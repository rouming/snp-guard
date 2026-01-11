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

use crate::auth::master_auth_middleware;
use crate::service_core::ServiceState;
use crate::nonce;
use crate::master_password::MasterAuth;
use common::snpguard::{
    AttestationRequest, NonceRequest, NonceResponse,
    ListRecordsResponse, GetRecordResponse,
    CreateRecordRequest, CreateRecordResponse, UpdateRecordRequest, UpdateRecordResponse,
    DeleteRecordResponse, ToggleEnabledRequest, ToggleEnabledResponse,
};

const PROTO_CT: &str = "application/x-protobuf";

pub fn router(state: Arc<ServiceState>, master: Arc<MasterAuth>) -> Router {
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
        .route("/tokens", post(tokens_stub))
        .with_state(state)
        .layer(axum::Extension(master))
        .layer(axum::middleware::from_fn(master_auth_middleware));

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

async fn tokens_stub() -> Response {
    proto_error(StatusCode::NOT_IMPLEMENTED, "Token issuance not implemented")
}
