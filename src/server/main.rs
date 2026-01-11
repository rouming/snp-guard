use axum::{
    routing::{get, post},
    Router, Extension,
    middleware,
};
use axum_server::tls_rustls::RustlsConfig;
use sea_orm::Database;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tower_http::services::ServeDir;
use std::sync::Arc;
use rand::RngCore;

mod attestation;
mod web;
mod snpguest_wrapper;
mod auth;
mod service_core;
mod business_logic;
mod master_password;
mod nonce;
mod rest_api;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. DB
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let conn = Database::connect(db_url).await?;

    // 2. Attestation state (shared between endpoints)
    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);

    let attestation_state = Arc::new(attestation::AttestationState {
        db: conn.clone(),
        secret,
    });

    // 3. Service core state (shared)
    let service_state = Arc::new(service_core::ServiceState {
        db: conn.clone(),
        attestation_state: attestation_state.clone(),
    });

    // Master password (web management)
    let master_auth = Arc::new(master_password::load_or_create_master_password()?);
    
    // REST API router
    let rest_router = rest_api::router(service_state.clone(), master_auth.clone());

    // 4. Web UI (Management)
    let management_app = Router::new()
        .route("/", get(web::index))
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
        .layer(TraceLayer::new_for_http());

    // 5. Attestation API (HTTPS/TLS with protobuf)
    let attestation_app = Router::new()
        .route("/attestation/nonce", post(attestation::get_nonce_handler))
        .layer(Extension(attestation_state))
        .layer(TraceLayer::new_for_http());

    // 6. Combined app
    let app = Router::new()
        .merge(management_app)
        .merge(attestation_app)
        .nest("/v1", rest_router);

    // 7. TLS Configuration
    // 7. TLS Configuration - HTTPS only
    let tls_cert = std::env::var("TLS_CERT").expect("TLS_CERT must be set (path to PEM certificate)");
    let tls_key = std::env::var("TLS_KEY").expect("TLS_KEY must be set (path to PEM private key)");
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    println!("Management UI listening on https://{}", addr);
    println!("REST API listening on https://{}/v1", addr);

    let config = RustlsConfig::from_pem_file(tls_cert, tls_key).await?;
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
