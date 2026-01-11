use axum::body::to_bytes;
use axum::{
    async_trait,
    body::Body,
    extract::{Extension, FromRequest, Request},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use entity::vm;
use prost::Message;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tempfile::NamedTempFile;

use crate::nonce;
use crate::snpguest_wrapper;
use common::snpguard::{AttestationRequest, AttestationResponse, NonceRequest, NonceResponse};

pub struct AttestationState {
    #[allow(unused)]
    pub db: DatabaseConnection,
    pub secret: [u8; 32],
}

/// Custom extractor for raw request body bytes
pub struct RawBody(pub bytes::Bytes);

#[async_trait]
impl<S> FromRequest<S, Body> for RawBody
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request(req: Request<Body>, _state: &S) -> Result<Self, Self::Rejection> {
        let body = req.into_body();
        match to_bytes(body, usize::MAX).await {
            Ok(bytes) => Ok(RawBody(bytes)),
            Err(_) => Err(StatusCode::BAD_REQUEST),
        }
    }
}

/// Extract CPU family from attestation report
/// Based on CPUID_FAM_ID (offset 0x188, 8 bits) and CPUID_MOD_ID (offset 0x189, 8 bits)
#[allow(unused)]
pub fn detect_cpu_family(report_data: &[u8]) -> Result<String, String> {
    if report_data.len() < 0x18A {
        return Err("Report too short".to_string());
    }

    let family_id = report_data[0x188];
    let model_id = report_data[0x189];

    // From AMD: "turin" with Family 1Ah and Models 90h-AFh and Models C0h-CFh
    // "genoa" with Family 1Ah Models 00h-1Fh
    // "milan" with family 19h Models 00h-0Fh
    match (family_id, model_id) {
        (0x1A, 0x00..=0x1F) => Ok("genoa".to_string()),
        (0x1A, 0x90..=0xAF) | (0x1A, 0xC0..=0xCF) => Ok("turin".to_string()),
        (0x19, 0x00..=0x0F) => Ok("milan".to_string()),
        _ => {
            // Fallback: try to detect from family/model ranges
            if family_id == 0x1A {
                if (model_id >= 0x90 && model_id <= 0xAF) || (model_id >= 0xC0 && model_id <= 0xCF)
                {
                    Ok("turin".to_string())
                } else {
                    Ok("genoa".to_string())
                }
            } else if family_id == 0x19 {
                Ok("milan".to_string())
            } else {
                Ok("genoa".to_string())
            }
        }
    }
}

/// Handler for /attestation/nonce - Get a random 64-byte nonce
pub async fn get_nonce_handler(
    Extension(state): Extension<Arc<AttestationState>>,
    RawBody(body_bytes): RawBody,
) -> impl IntoResponse {
    let _req = match NonceRequest::decode(&body_bytes[..]) {
        Ok(r) => r,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("Failed to decode request"))
                .unwrap()
        }
    };

    // Stateless nonce generation
    let nonce_bytes = nonce::generate_nonce(&state.secret);
    let response = NonceResponse {
        nonce: nonce_bytes.to_vec(),
    };
    let mut response_bytes = Vec::new();
    if response.encode(&mut response_bytes).is_err() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("Internal server error"))
            .unwrap();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(response_bytes))
        .unwrap()
}

/// Handler for /attestation/verify - Verify attestation report
#[allow(dead_code)]
pub async fn verify_report_handler(
    Extension(state): Extension<Arc<AttestationState>>,
    req: Request<Body>,
) -> Response<Body> {
    use axum::body::to_bytes;

    let (_parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(b) => b,
        Err(_) => {
            return encode_response(AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Failed to read request body".to_string(),
            })
        }
    };

    let req = match AttestationRequest::decode(&body_bytes[..]) {
        Ok(r) => r,
        Err(_) => {
            return encode_response(AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Failed to decode request".to_string(),
            })
        }
    };

    let report_data = req.report_data;

    // 1. Check report length
    if report_data.len() < 0x50 + 64 {
        let response = AttestationResponse {
            success: false,
            secret: vec![],
            error_message: "Report too short".to_string(),
        };
        return encode_response(response);
    }

    // 2. Extract and verify nonce (offset 0x50, 64 bytes)
    let report_nonce = &report_data[0x50..0x50 + crate::nonce::NONCE_SIZE];
    if let Err(e) = crate::nonce::verify_nonce(&state.secret, report_nonce) {
        let response = AttestationResponse {
            success: false,
            secret: vec![],
            error_message: format!("Invalid or expired nonce: {:?}", e),
        };
        return encode_response(response);
    }

    // 3. Detect CPU family from report
    let cpu_family = match detect_cpu_family(&report_data) {
        Ok(family) => {
            // Use hint if provided, otherwise use detected
            if !req.cpu_family_hint.is_empty() {
                req.cpu_family_hint.clone()
            } else {
                family
            }
        }
        Err(e) => {
            eprintln!("Failed to detect CPU family: {}", e);
            if !req.cpu_family_hint.is_empty() {
                req.cpu_family_hint.clone()
            } else {
                "genoa".to_string() // Default fallback
            }
        }
    };

    // 4. Dump report to disk for verification tools
    let mut temp_report = match NamedTempFile::new() {
        Ok(f) => f,
        Err(_) => {
            return encode_response(AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Failed to create temporary file".to_string(),
            })
        }
    };
    if temp_report.write_all(&report_data).is_err() {
        return encode_response(AttestationResponse {
            success: false,
            secret: vec![],
            error_message: "Failed to write report to temporary file".to_string(),
        });
    }
    let report_path = temp_report.path();

    // 5. Verify signature (uses temporary certs directory internally)
    if let Err(e) =
        snpguest_wrapper::verify_report_signature(report_path, Path::new(""), &cpu_family)
    {
        let response = AttestationResponse {
            success: false,
            secret: vec![],
            error_message: format!("Signature verification failed: {}", e),
        };
        return encode_response(response);
    }

    // 6. Extract key digests (0xE0 and 0x110, 48 bytes each)
    if report_data.len() < 0x110 + 48 {
        let response = AttestationResponse {
            success: false,
            secret: vec![],
            error_message: "Report too short for key digests".to_string(),
        };
        return encode_response(response);
    }

    let id_digest = &report_data[0xE0..0xE0 + 48];
    let auth_digest = &report_data[0x110..0x110 + 48];

    // 7. DB lookup
    let record = match vm::Entity::find()
        .filter(vm::Column::IdKeyDigest.eq(id_digest))
        .filter(vm::Column::AuthKeyDigest.eq(auth_digest))
        .one(&state.db)
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return encode_response(AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Database error".to_string(),
            })
        }
    };

    if let Some(vm) = record {
        if !vm.enabled {
            let response = AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Attestation record is disabled".to_string(),
            };
            return encode_response(response);
        }

        // Success! Update request count
        let mut active: vm::ActiveModel = vm.clone().into();
        active.request_count = Set(vm.request_count + 1);
        let _ = active.update(&state.db).await;

        let response = AttestationResponse {
            success: true,
            secret: vm.secret.into_bytes(),
            error_message: String::new(),
        };
        return encode_response(response);
    }

    let response = AttestationResponse {
        success: false,
        secret: vec![],
        error_message: "No matching attestation record found".to_string(),
    };
    encode_response(response)
}

#[allow(unused)]
fn encode_response(response: AttestationResponse) -> Response<Body> {
    let mut response_bytes = Vec::new();
    if response.encode(&mut response_bytes).is_err() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("Internal server error"))
            .unwrap();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(response_bytes))
        .unwrap()
}
