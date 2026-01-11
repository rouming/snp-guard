use tonic::{Request, Response, Status};
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, Set, ActiveModelTrait, QueryOrder, ColumnTrait};
use entity::vm;
use std::sync::Arc;
use std::path::Path;
use std::fs;

// Import service definitions
use common::snpguard::{
    attestation_service_server::{AttestationService},
    management_service_server::{ManagementService},
    *,
};
use crate::attestation::AttestationState;
use crate::nonce;
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use crate::snpguest_wrapper;
use crate::business_logic;
// snpguest wrapper not used directly in gRPC service paths

struct ParsedReport<'a> {
    report: AttestationReport,
    raw: &'a [u8],
}

fn parse_snp_report(report_data: &[u8]) -> Result<ParsedReport<'_>, String> {
    AttestationReport::from_bytes(report_data)
        .map(|r| ParsedReport { report: r, raw: report_data })
        .map_err(|e| format!("Failed to parse attestation report: {e}"))
}

fn verify_nonce_step(secret: &[u8], nonce_bytes: &[u8]) -> Result<(), String> {
    crate::nonce::verify_nonce(secret, nonce_bytes)
        .map_err(|e| format!("Invalid or expired nonce: {:?}", e))
}


pub struct GrpcServiceState {
    pub db: DatabaseConnection,
    pub attestation_state: Arc<AttestationState>,
}

// Shared helpers for REST and (legacy) gRPC

pub async fn verify_report_core(
    state: Arc<GrpcServiceState>,
    req: AttestationRequest,
) -> AttestationResponse {
    let report_data = req.report_data;

    // 1) Parse SNP report
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

    // 2) Verify nonce
    if let Err(e) = verify_nonce_step(&state.attestation_state.secret, &parsed.report.report_data) {
        return AttestationResponse {
            success: false,
            secret: vec![],
            error_message: e,
        };
    }

    // 3) Detect CPU family
    let cpu_family = match crate::attestation::detect_cpu_family(parsed.raw) {
        Ok(family) => {
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
                "genoa".to_string()
            }
        }
    };

    // 4) Verify signature (re-use existing wrapper)
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

    if let Err(e) =
        snpguest_wrapper::verify_report_signature(&report_path, std::path::Path::new(""), &cpu_family)
    {
        return AttestationResponse {
            success: false,
            secret: vec![],
            error_message: format!("Signature verification failed: {}", e),
        };
    }

    // 5) DB lookup
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
        // Policy
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

        // TCB
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

        // Update request count (best-effort)
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

pub async fn list_records_core(state: &Arc<GrpcServiceState>) -> Result<Vec<AttestationRecord>, String> {
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

pub async fn get_record_core(state: &Arc<GrpcServiceState>, id: String) -> Result<Option<AttestationRecord>, String> {
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

pub async fn create_record_core(state: &Arc<GrpcServiceState>, req: CreateRecordRequest) -> Result<String, String> {
    let create_req = business_logic::CreateRecordRequest {
        os_name: req.os_name,
        id_key_pem: if req.id_key.is_empty() { None } else { Some(req.id_key) },
        auth_key_pem: if req.auth_key.is_empty() { None } else { Some(req.auth_key) },
        firmware_data: if req.firmware.is_empty() { None } else { Some(req.firmware) },
        kernel_data: if req.kernel.is_empty() { None } else { Some(req.kernel) },
        initrd_data: if req.initrd.is_empty() { None } else { Some(req.initrd) },
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
    Ok(res.id)
}

pub async fn update_record_core(state: &Arc<GrpcServiceState>, req: UpdateRecordRequest) -> Result<(), String> {
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
    if res.success { Ok(()) } else { Err(res.error_message.unwrap_or_else(|| "update failed".into())) }
}

pub async fn delete_record_core(state: &Arc<GrpcServiceState>, id: String) -> Result<(), String> {
    vm::Entity::delete_by_id(id)
        .exec(&state.db)
        .await
        .map_err(|e| format!("Database error: {}", e))?;
    Ok(())
}

pub async fn toggle_enabled_core(
    state: &Arc<GrpcServiceState>,
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
// Attestation Service Implementation
pub struct AttestationServiceImpl {
    pub state: Arc<GrpcServiceState>,
}

#[tonic::async_trait]
impl AttestationService for AttestationServiceImpl {
    async fn get_nonce(&self, request: Request<NonceRequest>) -> Result<Response<NonceResponse>, Status> {
        let _vm_id = request.into_inner().vm_id;
        let nonce = nonce::generate_nonce(&self.state.attestation_state.secret);
        Ok(Response::new(NonceResponse { nonce: nonce.to_vec() }))
    }

    async fn verify_report(&self, request: Request<AttestationRequest>) -> Result<Response<AttestationResponse>, Status> {

        use tempfile::NamedTempFile;
        use std::io::Write;
        use std::path::Path;

        let req = request.into_inner();
        let report_data = req.report_data;

        // 1) Parse SNP report (length checks + essential fields)
        let parsed = match parse_snp_report(&report_data) {
            Ok(p) => p,
            Err(e) => {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: e,
                };
                return Ok(Response::new(response));
            }
        };

        // 2) Verify nonce BEFORE crypto verification
        if let Err(e) = verify_nonce_step(&self.state.attestation_state.secret, &parsed.report.report_data) {
            let response = AttestationResponse {
                success: false,
                secret: vec![],
                error_message: e,
            };
            return Ok(Response::new(response));
        }

        // 3) Detect CPU family
        let cpu_family = match crate::attestation::detect_cpu_family(parsed.raw) {
            Ok(family) => {
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
                    "genoa".to_string()
                }
            }
        };

        // 4) Verify SNP signature / cert chain
        let mut temp_report = match NamedTempFile::new() {
            Ok(f) => f,
            Err(_) => return Ok(Response::new(AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Failed to create temporary file".to_string(),
            })),
        };
        if temp_report.write_all(parsed.raw).is_err() {
            return Ok(Response::new(AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Failed to write report to temporary file".to_string(),
            }));
        }
        let report_path = temp_report.path();

        if let Err(e) = snpguest_wrapper::verify_report_signature(report_path, Path::new(""), &cpu_family) {
            let response = AttestationResponse {
                success: false,
                secret: vec![],
                error_message: format!("Signature verification failed: {}", e),
            };
            return Ok(Response::new(response));
        }

        // 8. DB lookup by image_id and key digests
        let record = match vm::Entity::find()
            .filter(vm::Column::ImageId.eq(parsed.report.image_id.to_vec()))
            .filter(vm::Column::IdKeyDigest.eq(parsed.report.id_key_digest.to_vec()))
            .filter(vm::Column::AuthKeyDigest.eq(parsed.report.author_key_digest.to_vec()))
            .one(&self.state.attestation_state.db)
            .await
        {
            Ok(r) => r,
            Err(_) => return Ok(Response::new(AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Database error".to_string(),
            })),
        };

        if let Some(vm) = record {
            // 9. Verify policy flags
            let policy = parsed.report.policy;
            let report_debug = policy.debug_allowed();
            let report_migrate_ma = policy.migrate_ma_allowed();
            let report_smt = policy.smt_allowed();

            // Check policy flags against allowed settings
            if report_debug && !vm.allowed_debug {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: "Debug mode not allowed by policy".to_string(),
                };
                return Ok(Response::new(response));
            }
            if report_migrate_ma && !vm.allowed_migrate_ma {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: "Migration with MA not allowed by policy".to_string(),
                };
                return Ok(Response::new(response));
            }
            if report_smt && !vm.allowed_smt {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: "Simultaneous Multithreading not allowed by policy".to_string(),
                };
                return Ok(Response::new(response));
            }

            // 10. Verify TCB version requirements
            let current_bootloader = parsed.report.current_tcb.bootloader;
            let current_tee = parsed.report.current_tcb.tee;
            let current_snp = parsed.report.current_tcb.snp;
            let current_microcode = parsed.report.current_tcb.microcode;

            // Check minimum TCB requirements
            if current_bootloader < vm.min_tcb_bootloader as u8 {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: format!("Bootloader TCB version {} below minimum requirement {}", current_bootloader, vm.min_tcb_bootloader),
                };
                return Ok(Response::new(response));
            }
            if current_tee < vm.min_tcb_tee as u8 {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: format!("TEE TCB version {} below minimum requirement {}", current_tee, vm.min_tcb_tee),
                };
                return Ok(Response::new(response));
            }
            if current_snp < vm.min_tcb_snp as u8 {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: format!("SNP TCB version {} below minimum requirement {}", current_snp, vm.min_tcb_snp),
                };
                return Ok(Response::new(response));
            }
            if current_microcode < vm.min_tcb_microcode as u8 {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: format!("Microcode TCB version {} below minimum requirement {}", current_microcode, vm.min_tcb_microcode),
                };
                return Ok(Response::new(response));
            }

            if !vm.enabled {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: "Attestation record is disabled".to_string(),
                };
                return Ok(Response::new(response));
            }

            // Success! Update request count
            let mut active: vm::ActiveModel = vm.clone().into();
            active.request_count = Set(vm.request_count + 1);
            let _ = active.update(&self.state.attestation_state.db).await;

            let response = AttestationResponse {
                success: true,
                secret: vm.secret.into_bytes(),
                error_message: String::new(),
            };
            Ok(Response::new(response))
        } else {
            let response = AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "No matching attestation record found".to_string(),
            };
            Ok(Response::new(response))
        }
    }
}

// Management Service Implementation
pub struct ManagementServiceImpl {
    pub state: Arc<GrpcServiceState>,
}

#[tonic::async_trait]
impl ManagementService for ManagementServiceImpl {
    async fn list_records(&self, _request: Request<ListRecordsRequest>) -> Result<Response<ListRecordsResponse>, Status> {
        let records = vm::Entity::find()
            .order_by_asc(vm::Column::OsName)
            .all(&self.state.db)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?;
        
        let proto_records: Vec<AttestationRecord> = records.into_iter()
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
        
        Ok(Response::new(ListRecordsResponse { records: proto_records }))
    }

    async fn get_record(&self, request: Request<GetRecordRequest>) -> Result<Response<GetRecordResponse>, Status> {
        let id = request.into_inner().id;
        let record = vm::Entity::find_by_id(id)
            .one(&self.state.db)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?;
        
        let proto_record = record.map(|vm| AttestationRecord {
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
        });
        
        Ok(Response::new(GetRecordResponse { record: proto_record }))
    }

    async fn create_record(&self, request: Request<CreateRecordRequest>) -> Result<Response<CreateRecordResponse>, Status> {
        let req = request.into_inner();

        let create_req = business_logic::CreateRecordRequest {
            os_name: req.os_name,
            id_key_pem: if req.id_key.is_empty() { None } else { Some(req.id_key) },
            auth_key_pem: if req.auth_key.is_empty() { None } else { Some(req.auth_key) },
            firmware_data: if req.firmware.is_empty() { None } else { Some(req.firmware) },
            kernel_data: if req.kernel.is_empty() { None } else { Some(req.kernel) },
            initrd_data: if req.initrd.is_empty() { None } else { Some(req.initrd) },
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

        match business_logic::create_record_logic(&self.state.attestation_state.db, create_req).await {
            Ok(response) => Ok(Response::new(CreateRecordResponse {
                id: response.id,
                error_message: response.error_message,
            })),
            Err(e) => Ok(Response::new(CreateRecordResponse {
                id: String::new(),
                error_message: Some(e),
            })),
        }
    }

    async fn update_record(&self, request: Request<UpdateRecordRequest>) -> Result<Response<UpdateRecordResponse>, Status> {
        let req = request.into_inner();

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

        match business_logic::update_record_logic(&self.state.attestation_state.db, update_req).await {
            Ok(response) => Ok(Response::new(UpdateRecordResponse {
                success: response.success,
                error_message: response.error_message,
            })),
            Err(e) => Ok(Response::new(UpdateRecordResponse {
                success: false,
                error_message: Some(e),
            })),
        }
    }

    async fn delete_record(&self, request: Request<DeleteRecordRequest>) -> Result<Response<DeleteRecordResponse>, Status> {
        let id = request.into_inner().id;
        
        vm::Entity::delete_by_id(&id)
            .exec(&self.state.db)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?;
        
        // Clean up artifacts
        let _ = fs::remove_dir_all(Path::new("artifacts").join(&id));
        
        Ok(Response::new(DeleteRecordResponse {
            success: true,
            error_message: None,
        }))
    }

    async fn toggle_enabled(&self, request: Request<ToggleEnabledRequest>) -> Result<Response<ToggleEnabledResponse>, Status> {
        let id = request.into_inner().id;
        
        let record = vm::Entity::find_by_id(id.clone())
            .one(&self.state.db)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?
            .ok_or_else(|| Status::not_found("Record not found"))?;
        
        let current_enabled = record.enabled;
        let mut active: vm::ActiveModel = record.into();
        active.enabled = Set(!current_enabled);
        active.update(&self.state.db)
            .await
            .map_err(|e| Status::internal(format!("Database error: {}", e)))?;
        
        let enabled = !current_enabled;
        
        Ok(Response::new(ToggleEnabledResponse {
            enabled,
            error_message: None,
        }))
    }
}

// Services are created directly in main.rs using the server builder
