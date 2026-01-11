use axum::{
    routing::{get, post},
    Router, Extension,
};
use sea_orm::Database;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tower_http::services::ServeDir;
use axum::middleware;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

mod attestation;
mod web;
mod snpguest_wrapper;
mod auth;
mod grpc_service;
mod business_logic;
mod grpc_client;
mod master_password;

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

    // 3. gRPC Service (for both attestation and management)
    let grpc_state = Arc::new(grpc_service::GrpcServiceState {
        db: conn.clone(),
        attestation_state: attestation_state.clone(),
    });

    // Master password (web management)
    let master_auth = Arc::new(master_password::load_or_create_master_password()?);
    
    // Start gRPC server
    let grpc_state_clone = grpc_state.clone();
    let grpc_addr = "[::]:50051".parse().unwrap();
    tokio::spawn(async move {
        use tonic::transport::Server;
        use grpc_service::{AttestationServiceImpl, ManagementServiceImpl};
        use common::snpguard::{
            attestation_service_server::AttestationServiceServer,
            management_service_server::ManagementServiceServer,
        };
        
        let attestation_svc = AttestationServiceImpl { state: grpc_state_clone.clone() };
        let management_svc = ManagementServiceImpl { state: grpc_state_clone };
        
        Server::builder()
            .add_service(AttestationServiceServer::new(attestation_svc))
            .add_service(ManagementServiceServer::new(management_svc))
            .serve(grpc_addr)
            .await
            .unwrap();
    });
    println!("gRPC Service listening on {}", grpc_addr);
    
    // 4. Web UI (Management) - calls gRPC internally
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
        .merge(attestation_app);

    // 7. TLS Configuration
    let tls_cert = std::env::var("TLS_CERT").ok();
    let tls_key = std::env::var("TLS_KEY").ok();
    
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    
    if let (Some(_cert_path), Some(_key_path)) = (tls_cert, tls_key) {
        // HTTPS mode - simplified, for production use proper TLS termination (nginx, etc.)
        println!("WARNING: Direct TLS in axum is complex. Consider using a reverse proxy for production.");
        println!("For now, falling back to HTTP. Set up nginx/caddy for TLS termination.");
        println!("Management UI listening on http://{}", addr);
                println!("Attestation endpoints: POST /attestation/nonce (verify via gRPC)");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    } else {
        // HTTP mode (for development)
        println!("WARNING: Running in HTTP mode (no TLS). Set TLS_CERT and TLS_KEY for production.");
        println!("Management UI listening on http://{}", addr);
                println!("Attestation endpoints: POST /attestation/nonce (verify via gRPC)");
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(listener, app).await?;
    }
    
    Ok(())
}
