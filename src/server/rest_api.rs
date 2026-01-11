use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderValue, StatusCode},
    response::Response,
    routing::{get, post},
    Router,
};
use prost::Message;
use base64::Engine;

use crate::service_core::ServiceState;
use crate::nonce;
use crate::master_password::MasterAuth;
use common::snpguard::{
    AttestationRequest, NonceRequest, NonceResponse,
    ListRecordsResponse, GetRecordResponse,
    CreateRecordRequest, CreateRecordResponse, UpdateRecordRequest, UpdateRecordResponse,
    DeleteRecordResponse, ToggleEnabledRequest, ToggleEnabledResponse,
};
use argon2::{Argon2, password_hash::PasswordHash, password_hash::PasswordVerifier};

const PROTO_CT: &str = "application/x-protobuf";

pub fn router(state: Arc<ServiceState>, master: Arc<MasterAuth>) -> Router {
    let auth_ctx = AuthCtx { state: state.clone(), master };
    let public = Router::new()
        .route("/health", get(health))
        .route("/attest/nonce", post(attest_nonce))
        .route("/attest/report", post(attest_report))
        .with_state(state.clone());

    let management = Router::new()
        .route("/records", get(list_records).post(create_record))
        .route("/records/:id", get(get_record).patch(update_record).delete(delete_record))
        .route("/records/:id/enable", post(enable_record))
        .route("/records/:id/disable", post(disable_record))
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/:id/revoke", post(revoke_token))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(auth_ctx, management_auth));

    public.merge(management)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

fn proto_response<M: Message>(msg: M) -> Response {
    let mut buf = Vec::new();
    msg.encode(&mut buf).expect("encode");
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", HeaderValue::from_static(PROTO_CT))
        .body(Body::from(buf))
        .unwrap()
}

fn proto_error(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Body::from(msg.to_string()))
        .unwrap()
}

// --- Token helpers (management API auth) ---
fn auth_header_token(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn verify_master(headers: &axum::http::HeaderMap, master: &crate::master_password::MasterAuth) -> bool {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    if let Some(auth) = auth_header {
        if auth.starts_with("Basic ") {
            let encoded = &auth[6..];
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                if let Ok(credentials) = String::from_utf8(decoded) {
                    let parts: Vec<&str> = credentials.splitn(2, ':').collect();
                    let supplied_password = if parts.len() == 2 { parts[1] } else { "" };
                    if let Ok(parsed_hash) = PasswordHash::new(&master.hash) {
                        return Argon2::default()
                            .verify_password(supplied_password.as_bytes(), &parsed_hash)
                            .is_ok();
                    }
                }
            }
        }
    }
    false
}

#[derive(Clone)]
struct AuthCtx {
    state: Arc<ServiceState>,
    master: Arc<MasterAuth>,
}

async fn management_auth(
    State(ctx): State<AuthCtx>,
    req: axum::http::Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_string();
    let headers = req.headers();

    // Tokens endpoints require master password only
    let tokens_route = path.contains("/tokens");

    // Try bearer token for non-token routes
    if !tokens_route {
        if let Some(token) = auth_header_token(headers) {
            match crate::service_core::auth_token_valid(&ctx.state, &token).await {
                Ok(true) => return next.run(req).await,
                Ok(false) | Err(_) => {}
            }
        }
    }

    // Fallback to master password
    if verify_master(headers, &ctx.master) {
        return next.run(req).await;
    }

    let mut resp = proto_error(StatusCode::UNAUTHORIZED, "Unauthorized");
    resp.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"SnpGuard Management\""),
    );
    resp
}

async fn attest_nonce(
    State(state): State<Arc<ServiceState>>,
    body: Bytes,
) -> Response {
    let req = match NonceRequest::decode(&body[..]) {
        Ok(r) => r,
        Err(_) => return proto_error(StatusCode::BAD_REQUEST, "Failed to decode NonceRequest"),
    };
    let _ = req; // vm_id unused for stateless nonce
    let nonce_bytes = nonce::generate_nonce(&state.attestation_state.secret);
    proto_response(NonceResponse { nonce: nonce_bytes.to_vec() })
}

async fn attest_report(
    State(state): State<Arc<ServiceState>>,
    body: Bytes,
) -> Response {
    let req = match AttestationRequest::decode(&body[..]) {
        Ok(r) => r,
        Err(_) => return proto_error(StatusCode::BAD_REQUEST, "Failed to decode AttestationRequest"),
    };

    let resp = crate::service_core::verify_report_core(state.clone(), req).await;
    proto_response(resp)
}

async fn list_records(
    State(state): State<Arc<ServiceState>>,
) -> Response {
    let records = match crate::service_core::list_records_core(&state).await {
        Ok(r) => r,
        Err(e) => return proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    proto_response(ListRecordsResponse { records })
}

async fn get_record(
    State(state): State<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> Response {
    match crate::service_core::get_record_core(&state, id).await {
        Ok(opt) => proto_response(GetRecordResponse { record: opt }),
        Err(e) => proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn create_record(
    State(state): State<Arc<ServiceState>>,
    body: Bytes,
) -> Response {
    let req = match CreateRecordRequest::decode(&body[..]) {
        Ok(r) => r,
        Err(_) => return proto_error(StatusCode::BAD_REQUEST, "Failed to decode CreateRecordRequest"),
    };
    match crate::service_core::create_record_core(&state, req).await {
        Ok(id) => proto_response(CreateRecordResponse { id, error_message: None }),
        Err(e) => proto_response(CreateRecordResponse { id: String::new(), error_message: Some(e) }),
    }
}

async fn update_record(
    State(state): State<Arc<ServiceState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let mut req = match UpdateRecordRequest::decode(&body[..]) {
        Ok(r) => r,
        Err(_) => return proto_error(StatusCode::BAD_REQUEST, "Failed to decode UpdateRecordRequest"),
    };
    req.id = id;
    match crate::service_core::update_record_core(&state, req).await {
        Ok(_) => proto_response(UpdateRecordResponse { success: true, error_message: None }),
        Err(e) => proto_response(UpdateRecordResponse { success: false, error_message: Some(e) }),
    }
}

async fn delete_record(
    State(state): State<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> Response {
    match crate::service_core::delete_record_core(&state, id).await {
        Ok(_) => proto_response(DeleteRecordResponse { success: true, error_message: None }),
        Err(e) => proto_response(DeleteRecordResponse { success: false, error_message: Some(e) }),
    }
}

async fn enable_record(
    State(state): State<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> Response {
    toggle_record(state, id, true).await
}

async fn disable_record(
    State(state): State<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> Response {
    toggle_record(state, id, false).await
}

async fn toggle_record(
    state: Arc<ServiceState>,
    id: String,
    enabled: bool,
) -> Response {
    let req = ToggleEnabledRequest { id };
    match crate::service_core::toggle_enabled_core(&state, req, enabled).await {
        Ok(enabled) => proto_response(ToggleEnabledResponse { enabled, error_message: None }),
        Err(e) => proto_response(ToggleEnabledResponse { enabled: !enabled, error_message: Some(e) }),
    }
}

async fn list_tokens(
    State(state): State<Arc<ServiceState>>,
) -> Response {
    match crate::service_core::list_tokens(&state).await {
        Ok(tokens) => {
            // encode as protobuf? We don't have Token list message; return text for now
            let body = serde_json::to_vec(&tokens).unwrap_or_default();
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }
        Err(e) => proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn create_token(
    State(state): State<Arc<ServiceState>>,
    body: Bytes,
) -> Response {
    // body: expected: label (string) and optional expires_at seconds since epoch in plain text? For simplicity JSON
    #[derive(serde::Deserialize)]
    struct CreateReq { label: String, expires_at: Option<i64> }
    let req: CreateReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return proto_error(StatusCode::BAD_REQUEST, "Invalid token create payload (json)"),
    };
    let expires_at = req.expires_at.and_then(|ts| chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0).map(|dt| dt.naive_utc()));
    match crate::service_core::generate_token(&state, req.label, expires_at).await {
        Ok((token_plain, info)) => {
            let resp = serde_json::json!({
                "token": token_plain,
                "id": info.id,
                "label": info.label,
                "created_at": info.created_at,
                "expires_at": info.expires_at,
                "revoked": info.revoked,
            });
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(Body::from(resp.to_string()))
                .unwrap()
        }
        Err(e) => proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn revoke_token(
    State(state): State<Arc<ServiceState>>,
    Path(id): Path<String>,
) -> Response {
    match crate::service_core::revoke_token(&state, id).await {
        Ok(_) => proto_error(StatusCode::OK, "revoked"),
        Err(e) => proto_error(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}
