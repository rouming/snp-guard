use std::collections::HashMap;
use std::sync::Arc;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};

use crate::config::DataPaths;
use crate::ingestion_key::IngestionKeys;
use common::snpguard::{
    AttestationRecord, AttestationRequest, AttestationResponse, CreateRecordRequest,
    ToggleEnabledRequest,
};
use entity::{token, vm, vm_registration};
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    Deserializable, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use sha2::{Digest, Sha512};

use crate::business_logic;
use crate::snpguest_wrapper;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::Engine;
use rand::RngCore;
use uuid::Uuid;

pub struct ServiceState {
    pub db: DatabaseConnection,
    pub attestation_state: Arc<AttestationState>,
    pub data_paths: Arc<DataPaths>,
    pub ingestion_keys: Arc<IngestionKeys>,
}

#[derive(Clone)]
pub struct AttestationState {
    pub db: DatabaseConnection,
    pub secret: [u8; 32],
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct TokenInfo {
    pub id: String,
    pub label: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked: bool,
}

fn fmt_ts(ts: chrono::NaiveDateTime) -> String {
    ts.format("%Y-%m-%d %H:%M UTC").to_string()
}

struct ParsedReport<'a> {
    report: AttestationReport,
    raw: &'a [u8],
}

fn parse_snp_report(report_data: &[u8]) -> Result<ParsedReport<'_>, String> {
    AttestationReport::from_bytes(report_data)
        .map(|r| ParsedReport {
            report: r,
            raw: report_data,
        })
        .map_err(|e| format!("Failed to parse attestation report: {e}"))
}

fn verify_binding_hash(
    server_nonce: &[u8],
    client_pub_bytes: &[u8],
    report_data: &[u8; 64],
) -> Result<(), String> {
    // Compute expected binding hash: SHA512(server_nonce || client_pub_bytes)
    let mut hasher = Sha512::new();
    hasher.update(server_nonce);
    hasher.update(client_pub_bytes);
    let expected_digest: [u8; 64] = hasher.finalize().into();

    // Verify report_data matches expected binding hash
    if report_data != &expected_digest {
        return Err("Security Alert: REPORT_DATA binding mismatch!".to_string());
    }

    Ok(())
}

/// Re-encrypt sealed blob (unseal VMK and reseal for client session)
fn reencrypt_sealed_blob(
    sealed_blob: &[u8],
    unsealing_priv_bytes: &[u8],
    client_pub_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    // Validate sealed blob length
    if sealed_blob.len() < 32 {
        return Err("Client blob corrupted (too short)".to_string());
    }

    // Split sealed blob into encapped key and ciphertext
    let (vmk_encapped_bytes, vmk_ciphertext) = sealed_blob.split_at(32);

    // Validate unsealing private key length (should be exactly 32 bytes)
    if unsealing_priv_bytes.len() != 32 {
        return Err(format!(
            "Invalid unsealing private key length: expected 32 bytes, got {}",
            unsealing_priv_bytes.len()
        ));
    }

    // Parse unsealing private key (raw 32 bytes, no PEM parsing needed)
    let priv_bytes: [u8; 32] = unsealing_priv_bytes
        .try_into()
        .map_err(|_| "Failed to convert to 32-byte array".to_string())?;

    let unsealing_priv = match <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(&priv_bytes) {
        Ok(k) => k,
        Err(e) => {
            return Err(format!("Invalid unsealing private key format: {}", e));
        }
    };

    // Parse VMK encapped key
    let vmk_encapped_key =
        match <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(vmk_encapped_bytes) {
            Ok(k) => k,
            Err(e) => {
                return Err(format!("Failed to create VMK encapped key: {}", e));
            }
        };

    // Unseal VMK using unsealing private key
    let mut unsealing_ctx = match hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &unsealing_priv,
        &vmk_encapped_key,
        &[],
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            return Err(format!("Failed to unseal VMK: {}", e));
        }
    };

    let vmk_plaintext = match unsealing_ctx.open(vmk_ciphertext, &[]) {
        Ok(pt) => pt,
        Err(e) => {
            return Err(format!("Failed to decrypt VMK blob: {}", e));
        }
    };

    // Reseal VMK for client session using client's ephemeral pub
    let client_pub = match <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(client_pub_bytes) {
        Ok(k) => k,
        Err(e) => {
            return Err(format!("Invalid client public key: {}", e));
        }
    };

    let mut rng = OsRng;
    let (encapped_key, mut sender_ctx) = match hpke::setup_sender::<
        AesGcm256,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &client_pub, &[], &mut rng)
    {
        Ok((enc, ctx)) => (enc, ctx),
        Err(e) => {
            return Err(format!("Failed to setup session encryption: {}", e));
        }
    };

    let ciphertext = match sender_ctx.seal(&vmk_plaintext, &[]) {
        Ok(ct) => ct,
        Err(e) => {
            return Err(format!("Failed to encrypt session response: {}", e));
        }
    };

    Ok((encapped_key.to_bytes().to_vec(), ciphertext))
}

pub async fn verify_report_core(
    state: Arc<ServiceState>,
    req: AttestationRequest,
) -> AttestationResponse {
    // Validate required fields
    if req.server_nonce.len() != 64 {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: format!("Invalid server_nonce length: {}", req.server_nonce.len()),
        };
    }
    if req.client_pub_bytes.len() != 32 {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: format!(
                "Invalid client_pub_bytes length: {}",
                req.client_pub_bytes.len()
            ),
        };
    }
    if req.sealed_blob.is_empty() {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: "sealed_blob is required".to_string(),
        };
    }

    // Parse report with sev call from bytes
    let parsed = match parse_snp_report(&req.report_data) {
        Ok(p) => p,
        Err(e) => {
            return AttestationResponse {
                success: false,
                encapped_key: vec![],
                ciphertext: vec![],
                error_message: e,
            }
        }
    };

    // Verify stateless nonce from the report.report_data. The nonce is
    // verified from req.server_nonce, and the binding hash ensures it
    // matches what's embedded in report.report_data
    if let Err(e) = crate::nonce::verify_nonce(&state.attestation_state.secret, &req.server_nonce) {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: format!("Invalid or expired nonce: {:?}", e),
        };
    }

    // Verify hash binding
    if let Err(e) = verify_binding_hash(
        &req.server_nonce,
        &req.client_pub_bytes,
        &parsed.report.report_data,
    ) {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: e,
        };
    }

    // Find attestation record by report.image_id, report.id_key_digest,
    // report.auth_key_digest
    let record = match vm::Entity::find()
        .filter(vm::Column::ImageId.eq(parsed.report.image_id.to_vec()))
        .filter(vm::Column::IdKeyDigest.eq(parsed.report.id_key_digest.to_vec()))
        .filter(vm::Column::AuthKeyDigest.eq(parsed.report.author_key_digest.to_vec()))
        .one(&state.db)
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return AttestationResponse {
                success: false,
                encapped_key: vec![],
                ciphertext: vec![],
                error_message: "Database error".to_string(),
            }
        }
    };

    let attestation_record = match record.ok_or("No matching attestation record found") {
        Ok(r) => r,
        Err(e) => {
            return AttestationResponse {
                success: false,
                encapped_key: vec![],
                ciphertext: vec![],
                error_message: e.to_string(),
            }
        }
    };

    // Load the parent registration to check enabled status and update request_count
    let registration =
        match vm_registration::Entity::find_by_id(&attestation_record.registration_id)
            .one(&state.db)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => {
                return AttestationResponse {
                    success: false,
                    encapped_key: vec![],
                    ciphertext: vec![],
                    error_message: "Registration not found for attestation record".to_string(),
                }
            }
            Err(_) => {
                return AttestationResponse {
                    success: false,
                    encapped_key: vec![],
                    ciphertext: vec![],
                    error_message: "Database error".to_string(),
                }
            }
        };

    // Check if registration is not disabled
    if !registration.enabled {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: "Attestation record is disabled".to_string(),
        };
    }

    // Check TCB
    let current_bootloader = parsed.report.current_tcb.bootloader;
    let current_tee = parsed.report.current_tcb.tee;
    let current_snp = parsed.report.current_tcb.snp;
    let current_microcode = parsed.report.current_tcb.microcode;

    if current_bootloader < attestation_record.min_tcb_bootloader as u8 {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: format!(
                "Bootloader TCB version {} below minimum requirement {}",
                current_bootloader, attestation_record.min_tcb_bootloader
            ),
        };
    }
    if current_tee < attestation_record.min_tcb_tee as u8 {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: format!(
                "TEE TCB version {} below minimum requirement {}",
                current_tee, attestation_record.min_tcb_tee
            ),
        };
    }
    if current_snp < attestation_record.min_tcb_snp as u8 {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: format!(
                "SNP TCB version {} below minimum requirement {}",
                current_snp, attestation_record.min_tcb_snp
            ),
        };
    }
    if current_microcode < attestation_record.min_tcb_microcode as u8 {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: format!(
                "Microcode TCB version {} below minimum requirement {}",
                current_microcode, attestation_record.min_tcb_microcode
            ),
        };
    }

    // Check VMPL
    if parsed.report.vmpl > 0 {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: format!(
                "Security Alert: Report generated from VMPL {} (expected 0)",
                parsed.report.vmpl
            ),
        };
    }

    // Verify report certs (verify report signature)
    let temp_dir = match tempfile::TempDir::new() {
        Ok(dir) => dir,
        Err(_) => {
            return AttestationResponse {
                success: false,
                encapped_key: vec![],
                ciphertext: vec![],
                error_message: "Failed to create temp dir".to_string(),
            };
        }
    };

    let report_path = temp_dir.path().join("report.bin");
    if std::fs::write(&report_path, parsed.raw).is_err() {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: "Failed to write report to temp file".to_string(),
        };
    }

    if let Err(e) = snpguest_wrapper::verify_report_signature(&report_path) {
        return AttestationResponse {
            success: false,
            encapped_key: vec![],
            ciphertext: vec![],
            error_message: format!("Signature verification failed: {}", e),
        };
    }

    // Decrypt unsealing private key from DB using ingestion key
    let unsealing_priv_bytes = match state
        .ingestion_keys
        .decrypt(&attestation_record.unsealing_private_key_encrypted)
    {
        Ok(decrypted) => decrypted,
        Err(e) => {
            return AttestationResponse {
                success: false,
                encapped_key: vec![],
                ciphertext: vec![],
                error_message: format!("Failed to decrypt unsealing key: {}", e),
            };
        }
    };

    let (encapped_key, ciphertext) = match reencrypt_sealed_blob(
        &req.sealed_blob,
        &unsealing_priv_bytes,
        &req.client_pub_bytes,
    ) {
        Ok(result) => result,
        Err(e) => {
            return AttestationResponse {
                success: false,
                encapped_key: vec![],
                ciphertext: vec![],
                error_message: e,
            };
        }
    };

    // Increment request count on the registration
    let new_count = registration.request_count + 1;
    let mut reg_active: vm_registration::ActiveModel = registration.into();
    reg_active.request_count = Set(new_count);
    let _ = reg_active.update(&state.db).await;

    // Success
    AttestationResponse {
        success: true,
        encapped_key,
        ciphertext,
        error_message: String::new(),
    }
}

/// Build an AttestationRecord proto from a registration + its current attestation record.
fn build_proto_record(reg: vm_registration::Model, rec: vm::Model) -> AttestationRecord {
    AttestationRecord {
        id: reg.id,
        os_name: reg.os_name,
        request_count: reg.request_count,
        vcpu_type: rec.vcpu_type,
        vcpus: rec.vcpus as u32,
        enabled: reg.enabled,
        created_at: reg.created_at.to_string(),
        kernel_params: rec.kernel_params.unwrap_or_default(),
        firmware_path: rec.firmware_path.unwrap_or_default(),
        kernel_path: rec.kernel_path.unwrap_or_default(),
        initrd_path: rec.initrd_path.unwrap_or_default(),
        image_id: rec.image_id,
        allowed_debug: rec.allowed_debug,
        allowed_migrate_ma: rec.allowed_migrate_ma,
        allowed_smt: rec.allowed_smt,
        min_tcb_bootloader: rec.min_tcb_bootloader as u32,
        min_tcb_tee: rec.min_tcb_tee as u32,
        min_tcb_snp: rec.min_tcb_snp as u32,
        min_tcb_microcode: rec.min_tcb_microcode as u32,
    }
}

pub async fn list_records_core(
    state: &Arc<ServiceState>,
) -> Result<Vec<AttestationRecord>, String> {
    let registrations = vm_registration::Entity::find()
        .order_by_asc(vm_registration::Column::OsName)
        .all(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    let record_ids: Vec<String> = registrations
        .iter()
        .map(|r| r.current_record_id.clone())
        .collect();

    let records = vm::Entity::find()
        .filter(vm::Column::Id.is_in(record_ids))
        .all(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    let record_map: HashMap<String, vm::Model> =
        records.into_iter().map(|r| (r.id.clone(), r)).collect();

    let proto_records = registrations
        .into_iter()
        .filter_map(|reg| {
            let rec = record_map.get(&reg.current_record_id)?.clone();
            Some(build_proto_record(reg, rec))
        })
        .collect();

    Ok(proto_records)
}

pub async fn get_record_core(
    state: &Arc<ServiceState>,
    id: String,
) -> Result<Option<AttestationRecord>, String> {
    // id is the VmRegistration ID
    let registration = vm_registration::Entity::find_by_id(&id)
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    let reg = match registration {
        Some(r) => r,
        None => return Ok(None),
    };

    let rec = vm::Entity::find_by_id(&reg.current_record_id)
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| {
            format!(
                "Attestation record {} not found for registration {}",
                reg.current_record_id, id
            )
        })?;

    Ok(Some(build_proto_record(reg, rec)))
}

pub async fn create_record_core(
    state: &Arc<ServiceState>,
    req: CreateRecordRequest,
) -> Result<String, String> {
    let create_req = business_logic::CreateRecordRequest {
        os_name: req.os_name,
        firmware_data: if req.firmware.is_empty() {
            None
        } else {
            Some(req.firmware)
        },
        kernel_data: if req.kernel.is_empty() {
            None
        } else {
            Some(req.kernel)
        },
        initrd_data: if req.initrd.is_empty() {
            None
        } else {
            Some(req.initrd)
        },
        kernel_params: req.kernel_params,
        vcpus: req.vcpus,
        vcpu_type: req.vcpu_type,
        unsealing_private_key_encrypted: req.unsealing_private_key_encrypted,
        allowed_debug: req.allowed_debug,
        allowed_migrate_ma: req.allowed_migrate_ma,
        allowed_smt: req.allowed_smt,
        min_tcb_bootloader: req.min_tcb_bootloader,
        min_tcb_tee: req.min_tcb_tee,
        min_tcb_snp: req.min_tcb_snp,
        min_tcb_microcode: req.min_tcb_microcode,
    };

    // Returns the VmRegistration ID
    let res = business_logic::create_record_logic(
        &state.attestation_state.db,
        &state.data_paths,
        state.ingestion_keys.clone(),
        create_req,
    )
    .await?;
    Ok(res)
}

pub async fn delete_record_core(state: &Arc<ServiceState>, id: String) -> Result<(), String> {
    // id is the VmRegistration ID
    let registration = vm_registration::Entity::find_by_id(&id)
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Registration not found".to_string())?;

    // Collect all attestation record IDs that belong to this registration
    let mut record_ids = vec![registration.current_record_id.clone()];
    if let Some(pending_id) = &registration.pending_record_id {
        record_ids.push(pending_id.clone());
    }

    // Delete attestation records before the registration (FK order)
    for record_id in &record_ids {
        vm::Entity::delete_by_id(record_id)
            .exec(&state.db)
            .await
            .map_err(|e| format!("Database error: {}", e))?;
    }

    // Delete the registration
    vm_registration::Entity::delete_by_id(&id)
        .exec(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    // Remove artifact directories (named after attestation_record IDs)
    for record_id in &record_ids {
        let artifact_dir = state.data_paths.attestations_dir.join(record_id);
        if artifact_dir.exists() {
            let safe_to_remove = state
                .data_paths
                .attestations_dir
                .canonicalize()
                .ok()
                .and_then(|base| {
                    artifact_dir
                        .canonicalize()
                        .ok()
                        .map(|p| p.starts_with(&base))
                })
                .unwrap_or(false);
            if safe_to_remove {
                if let Err(e) = std::fs::remove_dir_all(&artifact_dir) {
                    eprintln!(
                        "Warning: failed to remove artifacts for {}: {}",
                        record_id, e
                    );
                }
            }
        }
    }

    Ok(())
}

pub async fn toggle_enabled_core(
    state: &Arc<ServiceState>,
    req: ToggleEnabledRequest,
    enabled: bool,
) -> Result<bool, String> {
    // req.id is the VmRegistration ID
    let reg = vm_registration::Entity::find_by_id(req.id.clone())
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Registration not found".to_string())?;

    let mut active: vm_registration::ActiveModel = reg.into();
    active.enabled = Set(enabled);
    active
        .update(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;
    Ok(enabled)
}

/// Returns the artifact directory path for the current record of a registration.
/// Used by export and download endpoints which need the filesystem path.
pub async fn get_current_artifact_dir(
    state: &Arc<ServiceState>,
    registration_id: &str,
) -> Result<std::path::PathBuf, String> {
    let reg = vm_registration::Entity::find_by_id(registration_id)
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Registration not found".to_string())?;

    Ok(state
        .data_paths
        .attestations_dir
        .join(&reg.current_record_id))
}

fn hash_token(token: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map_err(|e| format!("Hash error: {e}"))
        .map(|h| h.to_string())
}

fn verify_token_hash(token: &str, hash: &str) -> bool {
    if let Ok(parsed) = PasswordHash::new(hash) {
        Argon2::default()
            .verify_password(token.as_bytes(), &parsed)
            .is_ok()
    } else {
        false
    }
}

pub async fn generate_token(
    state: &ServiceState,
    label: String,
    expires_at: Option<chrono::NaiveDateTime>,
) -> Result<(String, TokenInfo), String> {
    let token_plain = {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    };
    let token_hash = hash_token(&token_plain)?;
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().naive_utc();

    let model = token::ActiveModel {
        id: Set(id.clone()),
        label: Set(label.clone()),
        token_hash: Set(token_hash),
        created_at: Set(now),
        expires_at: Set(expires_at),
        revoked: Set(false),
    };

    model
        .insert(&state.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

    let info = TokenInfo {
        id,
        label,
        created_at: fmt_ts(now),
        expires_at: expires_at.map(fmt_ts).unwrap_or_default(),
        revoked: false,
    };

    Ok((token_plain, info))
}

pub async fn list_tokens(state: &ServiceState) -> Result<Vec<TokenInfo>, String> {
    let tokens = token::Entity::find()
        .order_by_desc(token::Column::CreatedAt)
        .all(&state.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

    Ok(tokens
        .into_iter()
        .map(|t| TokenInfo {
            id: t.id,
            label: t.label,
            created_at: fmt_ts(t.created_at),
            expires_at: t.expires_at.map(fmt_ts).unwrap_or_default(),
            revoked: t.revoked,
        })
        .collect())
}

pub async fn revoke_token(state: &ServiceState, id: String) -> Result<(), String> {
    let mut model = token::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| "Token not found".to_string())?;

    model.revoked = true;
    let mut active: token::ActiveModel = model.into();
    active.revoked = Set(true);
    active
        .update(&state.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
    Ok(())
}

pub async fn auth_token_valid(state: &ServiceState, token_plain: &str) -> Result<bool, String> {
    let now = chrono::Utc::now().naive_utc();
    let records = token::Entity::find()
        .filter(token::Column::Revoked.eq(false))
        .all(&state.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

    for rec in records {
        if let Some(exp) = rec.expires_at {
            if now > exp {
                continue;
            }
        }
        if verify_token_hash(token_plain, &rec.token_hash) {
            return Ok(true);
        }
    }
    Ok(false)
}
