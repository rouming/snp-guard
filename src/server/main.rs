use axum::extract::DefaultBodyLimit;
use axum::{
    middleware,
    routing::{get, post},
    Extension, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use rand::RngCore;
use rustls::crypto::ring::default_provider as ring_crypto_provider;
use sea_orm::Database;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

mod auth;
mod business_logic;
mod config;
mod master_password;
mod nonce;
mod rest_api;
mod service_core;
mod snpguest_wrapper;
mod web;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ensure rustls has a crypto provider (ring) installed
    ring_crypto_provider()
        .install_default()
        .expect("install ring crypto provider");

    let data_dir = std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".to_string());
    let paths = config::DataPaths::new(&data_dir)?;
    paths.ensure()?;

    // TLS setup: use existing cert/key or generate self-signed for dev
    let tls_cert = paths.tls_cert.clone();
    let tls_key = paths.tls_key.clone();
    if !tls_cert.exists() || !tls_key.exists() {
        generate_self_signed_cert(&tls_cert, &tls_key, &paths.ca_cert)?;
    }

    // Database URL derived from DATA_DIR
    let db_url = format!(
        "sqlite://{}?mode=rwc",
        paths.db_file.to_string_lossy().replace('\\', "/")
    );

    // 1. DB
    let conn = Database::connect(db_url).await?;

    // 2. Attestation state (shared between endpoints)
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);

    let attestation_state = Arc::new(service_core::AttestationState {
        db: conn.clone(),
        secret,
    });

    // 3. Service core state (shared)
    let data_paths = Arc::new(paths);
    let service_state = Arc::new(service_core::ServiceState {
        db: conn.clone(),
        attestation_state: attestation_state.clone(),
        data_paths: data_paths.clone(),
    });

    // Master password (web management)
    let master_auth = Arc::new(master_password::load_or_create_master_password(
        &data_paths.master_password_hash,
    )?);

    // REST API router
    let rest_router = rest_api::router(service_state.clone(), master_auth.clone());

    // 4. Web UI (Management)
    let management_app = Router::new()
        .route("/", get(web::index))
        .route("/login", get(web::login_form).post(web::login_submit))
        .route("/create", get(web::create_form).post(web::create_action))
        .route("/view/:id", get(web::view_record).post(web::update_action))
        .route("/delete/:id", get(web::delete_action))
        .route("/download/:id/:file", get(web::download_artifact))
        .route("/toggle/:id", post(web::toggle_enabled))
        .route("/tokens", get(web::tokens_page).post(web::create_token))
        .route("/tokens/:id/revoke", post(web::revoke_token))
        .nest_service("/static", ServeDir::new("ui/static"))
        .layer(Extension(service_state.clone()))
        .layer(Extension(master_auth.clone()))
        .layer(middleware::from_fn(auth::master_auth_middleware))
        .layer(DefaultBodyLimit::max(200 * 1024 * 1024)) // allow large multipart uploads
        .layer(TraceLayer::new_for_http());

    // 5. Combined app (REST API + web UI)
    let app = Router::new()
        .merge(management_app)
        .nest("/v1", rest_router)
        .layer(Extension(master_auth.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    println!("Management UI listening on https://{}", addr);
    println!("REST API listening on https://{}/v1", addr);

    let config = RustlsConfig::from_pem_file(tls_cert, tls_key).await?;
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

fn generate_self_signed_cert(
    cert_path: &PathBuf,
    key_path: &PathBuf,
    ca_path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    use rcgen::generate_simple_self_signed;

    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names)?;
    let cert_pem = cert.serialize_pem()?;
    let key_pem = cert.serialize_private_key_pem();

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }

    fs::write(cert_path, &cert_pem)?;
    fs::write(key_path, &key_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(cert_path, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
    }

    if let Some(parent) = ca_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(ca_path, &cert_pem)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(ca_path, fs::Permissions::from_mode(0o644))?;
    }

    println!(
        "Generated self-signed TLS cert and key at {}",
        cert_path.display()
    );
    Ok(())
}
