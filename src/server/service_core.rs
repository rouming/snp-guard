use std::sync::Arc;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};

use common::snpguard::{
    AttestationRecord, AttestationRequest, AttestationResponse, CreateRecordRequest,
    ToggleEnabledRequest, UpdateRecordRequest,
};
use entity::{token, vm};
use sev::firmware::guest::AttestationReport;
use sev::firmware::guest::ReportVariant;
use sev::parser::ByteParser;
use sev::Generation;

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

struct ParsedReport<'a> {
    report: AttestationReport,
    raw: &'a [u8],
}

fn detect_cpu_family(parsed: &ParsedReport) -> Result<String, String> {
    let variant = ReportVariant::from_bytes(
        parsed
            .raw
            .get(0..4)
            .ok_or_else(|| "Report too short for variant".to_string())?,
    )
    .map_err(|e| format!("Failed to parse report variant: {e}"))?;

    if let ReportVariant::V2 = variant {
        return Err(
            "Unsupported attestation report variant V2 (older CPUs unsupported)".to_string(),
        );
    }

    let family = parsed
        .report
        .cpuid_fam_id
        .ok_or_else(|| "Report missing cpuid family id".to_string())?;
    let model = parsed
        .report
        .cpuid_mod_id
        .ok_or_else(|| "Report missing cpuid model id".to_string())?;

    let generation = Generation::identify_cpu(family, model)
        .map_err(|e| format!("Failed to identify CPU: {e}"))?;

    Ok(generation.titlecase().to_lowercase())
}

fn parse_snp_report(report_data: &[u8]) -> Result<ParsedReport<'_>, String> {
    AttestationReport::from_bytes(report_data)
        .map(|r| ParsedReport {
            report: r,
            raw: report_data,
        })
        .map_err(|e| format!("Failed to parse attestation report: {e}"))
}

fn verify_nonce_step(secret: &[u8], nonce_bytes: &[u8]) -> Result<(), String> {
    crate::nonce::verify_nonce(secret, nonce_bytes)
        .map_err(|e| format!("Invalid or expired nonce: {:?}", e))
}

pub async fn verify_report_core(
    state: Arc<ServiceState>,
    req: AttestationRequest,
) -> AttestationResponse {
    let report_data = req.report_data;

    let parsed = match parse_snp_report(&report_data) {
        Ok(p) => p,
        Err(e) => {
            return AttestationResponse {
                success: false,
                secret: vec![],
                error_message: e,
            }
        }
    };

    if let Err(e) = verify_nonce_step(&state.attestation_state.secret, &parsed.report.report_data) {
        return AttestationResponse {
            success: false,
            secret: vec![],
            error_message: e,
        };
    }

    let cpu_family = match detect_cpu_family(&parsed) {
        Ok(family) => family,
        Err(e) => {
            eprintln!("Failed to detect CPU family: {}", e);
            "genoa".to_string()
        }
    };

    let temp_dir = tempfile::TempDir::new();
    let report_path = match temp_dir {
        Ok(dir) => {
            let path = dir.path().join("report.bin");
            if std::fs::write(&path, parsed.raw).is_err() {
                return AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: "Failed to write report to temp file".to_string(),
                };
            }
            path
        }
        Err(_) => {
            return AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Failed to create temp dir".to_string(),
            }
        }
    };

    if let Err(e) = snpguest_wrapper::verify_report_signature(
        &report_path,
        std::path::Path::new(""),
        &cpu_family,
    ) {
        return AttestationResponse {
            success: false,
            secret: vec![],
            error_message: format!("Signature verification failed: {}", e),
        };
    }

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
                secret: vec![],
                error_message: "Database error".to_string(),
            }
        }
    };

    if let Some(vm) = record {
        let policy = parsed.report.policy;
        if policy.debug_allowed() && !vm.allowed_debug {
            return AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Debug mode not allowed by policy".to_string(),
            };
        }
        if policy.migrate_ma_allowed() && !vm.allowed_migrate_ma {
            return AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Migration with MA not allowed by policy".to_string(),
            };
        }
        if policy.smt_allowed() && !vm.allowed_smt {
            return AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Simultaneous Multithreading not allowed by policy".to_string(),
            };
        }

        let current_bootloader = parsed.report.current_tcb.bootloader;
        let current_tee = parsed.report.current_tcb.tee;
        let current_snp = parsed.report.current_tcb.snp;
        let current_microcode = parsed.report.current_tcb.microcode;

        if current_bootloader < vm.min_tcb_bootloader as u8 {
            return AttestationResponse {
                success: false,
                secret: vec![],
                error_message: format!(
                    "Bootloader TCB version {} below minimum requirement {}",
                    current_bootloader, vm.min_tcb_bootloader
                ),
            };
        }
        if current_tee < vm.min_tcb_tee as u8 {
            return AttestationResponse {
                success: false,
                secret: vec![],
                error_message: format!(
                    "TEE TCB version {} below minimum requirement {}",
                    current_tee, vm.min_tcb_tee
                ),
            };
        }
        if current_snp < vm.min_tcb_snp as u8 {
            return AttestationResponse {
                success: false,
                secret: vec![],
                error_message: format!(
                    "SNP TCB version {} below minimum requirement {}",
                    current_snp, vm.min_tcb_snp
                ),
            };
        }
        if current_microcode < vm.min_tcb_microcode as u8 {
            return AttestationResponse {
                success: false,
                secret: vec![],
                error_message: format!(
                    "Microcode TCB version {} below minimum requirement {}",
                    current_microcode, vm.min_tcb_microcode
                ),
            };
        }

        if !vm.enabled {
            return AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Attestation record is disabled".to_string(),
            };
        }

        let mut active: vm::ActiveModel = vm.clone().into();
        active.request_count = Set(vm.request_count + 1);
        let _ = active.update(&state.db).await;

        AttestationResponse {
            success: true,
            secret: vm.secret.into_bytes(),
            error_message: String::new(),
        }
    } else {
        AttestationResponse {
            success: false,
            secret: vec![],
            error_message: "No matching attestation record found".to_string(),
        }
    }
}

pub async fn list_records_core(
    state: &Arc<ServiceState>,
) -> Result<Vec<AttestationRecord>, String> {
    let records = vm::Entity::find()
        .order_by_asc(vm::Column::OsName)
        .all(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    let proto_records: Vec<AttestationRecord> = records
        .into_iter()
        .map(|vm| AttestationRecord {
            id: vm.id,
            os_name: vm.os_name,
            request_count: vm.request_count,
            secret: vm.secret,
            vcpu_type: vm.vcpu_type,
            enabled: vm.enabled,
            created_at: vm.created_at.to_string(),
            kernel_params: vm.kernel_params,
            firmware_path: vm.firmware_path,
            kernel_path: vm.kernel_path,
            initrd_path: vm.initrd_path,
            image_id: vm.image_id,
            allowed_debug: vm.allowed_debug,
            allowed_migrate_ma: vm.allowed_migrate_ma,
            allowed_smt: vm.allowed_smt,
            min_tcb_bootloader: vm.min_tcb_bootloader as u32,
            min_tcb_tee: vm.min_tcb_tee as u32,
            min_tcb_snp: vm.min_tcb_snp as u32,
            min_tcb_microcode: vm.min_tcb_microcode as u32,
        })
        .collect();

    Ok(proto_records)
}

pub async fn get_record_core(
    state: &Arc<ServiceState>,
    id: String,
) -> Result<Option<AttestationRecord>, String> {
    let record = vm::Entity::find_by_id(id)
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;

    Ok(record.map(|vm| AttestationRecord {
        id: vm.id,
        os_name: vm.os_name,
        request_count: vm.request_count,
        secret: vm.secret,
        vcpu_type: vm.vcpu_type,
        enabled: vm.enabled,
        created_at: vm.created_at.to_string(),
        kernel_params: vm.kernel_params,
        firmware_path: vm.firmware_path,
        kernel_path: vm.kernel_path,
        initrd_path: vm.initrd_path,
        image_id: vm.image_id,
        allowed_debug: vm.allowed_debug,
        allowed_migrate_ma: vm.allowed_migrate_ma,
        allowed_smt: vm.allowed_smt,
        min_tcb_bootloader: vm.min_tcb_bootloader as u32,
        min_tcb_tee: vm.min_tcb_tee as u32,
        min_tcb_snp: vm.min_tcb_snp as u32,
        min_tcb_microcode: vm.min_tcb_microcode as u32,
    }))
}

pub async fn create_record_core(
    state: &Arc<ServiceState>,
    req: CreateRecordRequest,
) -> Result<String, String> {
    let create_req = business_logic::CreateRecordRequest {
        os_name: req.os_name,
        id_key_pem: if req.id_key.is_empty() {
            None
        } else {
            Some(req.id_key)
        },
        auth_key_pem: if req.auth_key.is_empty() {
            None
        } else {
            Some(req.auth_key)
        },
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
        vcpus: req.vcpus as u32,
        vcpu_type: req.vcpu_type,
        service_url: req.service_url,
        secret: req.secret,
        allowed_debug: req.allowed_debug,
        allowed_migrate_ma: req.allowed_migrate_ma,
        allowed_smt: req.allowed_smt,
        min_tcb_bootloader: req.min_tcb_bootloader,
        min_tcb_tee: req.min_tcb_tee,
        min_tcb_snp: req.min_tcb_snp,
        min_tcb_microcode: req.min_tcb_microcode,
    };

    let res = business_logic::create_record_logic(&state.attestation_state.db, create_req).await?;
    Ok(res)
}

pub async fn update_record_core(
    state: &Arc<ServiceState>,
    req: UpdateRecordRequest,
) -> Result<(), String> {
    let update_req = business_logic::UpdateRecordRequest {
        id: req.id,
        os_name: req.os_name,
        id_key_pem: req.id_key,
        auth_key_pem: req.auth_key,
        firmware_data: req.firmware,
        kernel_data: req.kernel,
        initrd_data: req.initrd,
        kernel_params: req.kernel_params,
        vcpus: req.vcpus.map(|v| v as u32),
        vcpu_type: req.vcpu_type,
        service_url: req.service_url,
        secret: req.secret,
        enabled: req.enabled,
        allowed_debug: req.allowed_debug,
        allowed_migrate_ma: req.allowed_migrate_ma,
        allowed_smt: req.allowed_smt,
        min_tcb_bootloader: req.min_tcb_bootloader,
        min_tcb_tee: req.min_tcb_tee,
        min_tcb_snp: req.min_tcb_snp,
        min_tcb_microcode: req.min_tcb_microcode,
    };

    let res = business_logic::update_record_logic(&state.attestation_state.db, update_req).await?;
    if res.success {
        Ok(())
    } else {
        Err(res.error_message.unwrap_or_else(|| "update failed".into()))
    }
}

pub async fn delete_record_core(state: &Arc<ServiceState>, id: String) -> Result<(), String> {
    vm::Entity::delete_by_id(id)
        .exec(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;
    Ok(())
}

pub async fn toggle_enabled_core(
    state: &Arc<ServiceState>,
    req: ToggleEnabledRequest,
    enabled: bool,
) -> Result<bool, String> {
    let id = req.id;
    let mut vm_model = vm::Entity::find_by_id(id.clone())
        .one(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Record not found".to_string())?;

    vm_model.enabled = enabled;
    let mut active: vm::ActiveModel = vm_model.into();
    active.enabled = Set(enabled);
    active
        .update(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;
    Ok(enabled)
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
        created_at: now.to_string(),
        expires_at: expires_at.map(|e| e.to_string()).unwrap_or_default(),
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
            created_at: t.created_at.to_string(),
            expires_at: t.expires_at.map(|e| e.to_string()).unwrap_or_default(),
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
