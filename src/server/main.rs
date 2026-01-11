use axum::{
    routing::{get, post},
    Router, Extension,
    middleware,
};
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
mod grpc_service;
mod business_logic;
mod grpc_client;
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

    // 3. gRPC Service (for both attestation and management)
    let grpc_state = Arc::new(grpc_service::GrpcServiceState {
        db: conn.clone(),
        attestation_state: attestation_state.clone(),
    });

    // Master password (web management)
    let master_auth = Arc::new(master_password::load_or_create_master_password()?);
    
    // REST API router
    let rest_router = rest_api::router(grpc_state.clone(), master_auth.clone());

    // 4. Web UI (Management)
    let management_app = Router::new()
        .route("/", get(web::index))
        .route("/create", get(web::create_form).post(web::create_action))
        .route("/view/:id", get(web::view_record).post(web::update_action))
        .route("/delete/:id", get(web::delete_action))
        .route("/download/:id/:file", get(web::download_artifact))
        .route("/toggle/:id", post(web::toggle_enabled))
        .nest_service("/static", ServeDir::new("ui/static"))
        .layer(Extension(grpc_state.clone()))
        .layer(Extension(master_auth.clone()))
        .layer(middleware::from_fn(auth::master_auth_middleware))
        .layer(TraceLayer::new_for_http());

    // 5. Attestation API (HTTPS/TLS with protobuf) - calls gRPC internally
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
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    println!("WARNING: Running in HTTP mode. Place behind TLS-terminating proxy for production.");
    println!("Management UI listening on http://{}", addr);
    println!("REST API listening on http://{}/v1", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
