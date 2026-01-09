use axum::{
    routing::{get, post},
    Router, Extension,
};
use sea_orm::Database;
use std::net::SocketAddr;
use tower_http::{trace::TraceLayer, validate_request::ValidateRequestHeaderLayer};
use tower_http::services::ServeDir;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

mod attestation;
mod web;
mod snpguest_wrapper;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. DB
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let conn = Database::connect(db_url).await?;

    // 2. Attestation state (shared between endpoints)
    let attestation_state = Arc::new(attestation::AttestationState {
        db: conn.clone(),
        nonces: Arc::new(Mutex::new(HashMap::new())),
    });

    // 3. Web UI (Management)
    let auth_username = std::env::var("SNPGUARD_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let auth_password = std::env::var("SNPGUARD_PASSWORD").unwrap_or_else(|_| "secret".to_string());
    let auth_layer = ValidateRequestHeaderLayer::basic(&auth_username, &auth_password);
    
    let management_app = Router::new()
        .route("/", get(web::index))
        .route("/create", get(web::create_form).post(web::create_action))
        .route("/view/:id", get(web::view_record).post(web::update_action))
        .route("/delete/:id", get(web::delete_action))
        .route("/download/:id/:file", get(web::download_artifact))
        .route("/toggle/:id", post(web::toggle_enabled))
        .route_layer(auth_layer)
        .nest_service("/static", ServeDir::new("ui/static"))
        .layer(Extension(conn.clone()))
        .layer(TraceLayer::new_for_http());

    // 4. Attestation API (HTTPS/TLS with protobuf)
    let attestation_app = Router::new()
        .route("/attestation/nonce", post(attestation::get_nonce))
        .route("/attestation/verify", post(attestation::verify_report))
        .layer(Extension(attestation_state))
        .layer(TraceLayer::new_for_http());

    // 5. Combined app
    let app = Router::new()
        .merge(management_app)
        .merge(attestation_app);

    // 6. TLS Configuration
    let tls_cert = std::env::var("TLS_CERT").ok();
    let tls_key = std::env::var("TLS_KEY").ok();
    
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    
    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        // HTTPS mode
        println!("Management UI and Attestation API listening on https://{}", addr);
        println!("Attestation endpoints: POST /attestation/nonce, POST /attestation/verify");
        
        use axum_server::tls_rustls::RustlsConfig;
        use axum_server::Server;
        
        let config = RustlsConfig::from_pem_file(&cert_path, &key_path)?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        Server::from_tcp_rustls(listener, config)?
            .serve(app.into_make_service())
            .await?;
    } else {
        // HTTP mode (for development)
        println!("WARNING: Running in HTTP mode (no TLS). Set TLS_CERT and TLS_KEY for production.");
        println!("Management UI listening on http://{}", addr);
        println!("Attestation endpoints: POST /attestation/nonce, POST /attestation/verify");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }
    
    Ok(())
}
