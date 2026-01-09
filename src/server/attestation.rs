use axum::{
    extract::Extension,
    response::Response,
    body::Body,
    http::{StatusCode, header},
};
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, ColumnTrait, Set, ActiveModelTrait};
use entity::vm;
use rand::RngCore;
use rand::rngs::OsRng;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;
use std::fs;
use std::io::Write;
use std::path::Path;
use prost::Message;

use common::snpguard::{NonceRequest, NonceResponse, AttestationRequest, AttestationResponse};
use crate::snpguest_wrapper;

#[derive(Clone)]
struct NonceEntry {
    nonce: Vec<u8>,
    created_at: u64, // Unix timestamp
}

pub struct AttestationState {
    pub db: DatabaseConnection,
    pub nonces: Arc<Mutex<HashMap<String, NonceEntry>>>,
}

const NONCE_EXPIRY_SECONDS: u64 = 300; // 5 minutes
const MAX_NONCES: usize = 10000; // Prevent memory exhaustion

/// Extract CPU family from attestation report
/// Based on CPUID_FAM_ID (offset 0x188, 8 bits) and CPUID_MOD_ID (offset 0x189, 8 bits)
fn detect_cpu_family(report_data: &[u8]) -> Result<String, String> {
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
            // Default to genoa if unknown
            eprintln!("Unknown CPU family: {:02x} model: {:02x}, defaulting to genoa", family_id, model_id);
            Ok("genoa".to_string())
        }
    }
}

/// POST /attestation/nonce - Get a random 64-byte nonce
pub async fn get_nonce(
    Extension(state): Extension<Arc<AttestationState>>,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let request = NonceRequest::decode(&body_bytes[..])
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    // Use cryptographically secure RNG
    let mut rng = OsRng;
    let mut nonce = vec![0u8; 64];
    rng.fill_bytes(&mut nonce);
    
    let vm_id = request.vm_id;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Clean up expired nonces and limit size
    let mut nonces = state.nonces.lock().unwrap();
    if nonces.len() >= MAX_NONCES {
        // Remove oldest entries (simple cleanup)
        let expired_keys: Vec<String> = nonces.iter()
            .filter(|(_, entry)| now.saturating_sub(entry.created_at) > NONCE_EXPIRY_SECONDS)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired_keys {
            nonces.remove(&key);
        }
        // If still too many, remove oldest
        if nonces.len() >= MAX_NONCES {
            let oldest_key = nonces.iter()
                .min_by_key(|(_, entry)| entry.created_at)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest_key {
                nonces.remove(&key);
            }
        }
    }
    
    nonces.insert(vm_id, NonceEntry {
        nonce: nonce.clone(),
        created_at: now,
    });
    
    let response = NonceResponse { nonce };
    let mut response_bytes = Vec::new();
    response.encode(&mut response_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(response_bytes))
        .unwrap())
}

/// POST /attestation/verify - Verify attestation report
pub async fn verify_report(
    Extension(state): Extension<Arc<AttestationState>>,
    body: Body,
) -> Result<Response<Body>, StatusCode> {
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let request = AttestationRequest::decode(&body_bytes[..])
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let report_data = request.report_data;
    
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
    let report_nonce = &report_data[0x50..0x50 + 64];
    
    // Verify nonce was issued by us and not expired
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let mut nonces = state.nonces.lock().unwrap();
    let mut nonce_found = false;
    
    // Find matching nonce
    nonces.retain(|_, entry| {
        if entry.nonce == report_nonce {
            let age = now.saturating_sub(entry.created_at);
            if age <= NONCE_EXPIRY_SECONDS {
                nonce_found = true;
                false // Remove after use (one-time nonce)
            } else {
                false // Expired, remove
            }
        } else {
            // Keep non-expired nonces
            now.saturating_sub(entry.created_at) <= NONCE_EXPIRY_SECONDS
        }
    });
    
    if !nonce_found {
        let response = AttestationResponse {
            success: false,
            secret: vec![],
            error_message: "Invalid or expired nonce".to_string(),
        };
        return encode_response(response);
    }
    
    // 3. Detect CPU family from report
    let cpu_family = match detect_cpu_family(&report_data) {
        Ok(family) => {
            // Use hint if provided, otherwise use detected
            if !request.cpu_family_hint.is_empty() {
                request.cpu_family_hint.clone()
            } else {
                family
            }
        }
        Err(e) => {
            eprintln!("Failed to detect CPU family: {}", e);
            if !request.cpu_family_hint.is_empty() {
                request.cpu_family_hint.clone()
            } else {
                "genoa".to_string() // Default fallback
            }
        }
    };
    
    // 4. Dump report to disk for verification tools
    let mut temp_report = NamedTempFile::new()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    temp_report.write_all(&report_data)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let report_path = temp_report.path();
    
    // 5. Verify signature
    let certs_dir = Path::new("./certs");
    if let Err(e) = snpguest_wrapper::verify_report_signature(report_path, certs_dir, &cpu_family) {
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
    let record = vm::Entity::find()
        .filter(vm::Column::IdKeyDigest.eq(id_digest))
        .filter(vm::Column::AuthKeyDigest.eq(auth_digest))
        .one(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
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

fn encode_response(response: AttestationResponse) -> Result<Response<Body>, StatusCode> {
    let mut response_bytes = Vec::new();
    response.encode(&mut response_bytes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from(response_bytes))
        .unwrap())
}
