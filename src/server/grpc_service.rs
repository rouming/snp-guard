use tonic::{Request, Response, Status};
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, Set, ActiveModelTrait, QueryOrder, ColumnTrait};
use entity::vm;
use rand::RngCore;
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::path::Path;
use std::fs;

// Import service definitions
use common::snpguard::{
    attestation_service_server::{AttestationService},
    management_service_server::{ManagementService},
    *,
};
use crate::attestation::{AttestationState, NonceEntry};
use crate::snpguest_wrapper;
use crate::business_logic;
// snpguest wrapper not used directly in gRPC service paths

/// Decode TCB version from attestation report based on CPU family
/// Returns (microcode, snp, tee, bootloader) versions
fn decode_tcb_version(tcb_version: u64, cpu_family: &str) -> (u8, u8, u8, u8) {
    // Extract bytes from the 64-bit TCB version
    let microcode = ((tcb_version >> 56) & 0xFF) as u8;

    // Check CPU family to determine TCB structure
    if cpu_family.contains("genoa") || cpu_family.contains("milan") {
        // Table 4: Genoa and Milan structure
        // Bits: 63:56 MICROCODE, 55:48 SNP, 47:16 Reserved, 15:8 TEE, 7:0 BOOT_LOADER
        let snp = ((tcb_version >> 48) & 0xFF) as u8;
        let tee = ((tcb_version >> 8) & 0xFF) as u8;
        let bootloader = (tcb_version & 0xFF) as u8;
        (microcode, snp, tee, bootloader)
    } else if cpu_family.contains("turin") {
        // Table 3: Turin structure
        // Bits: 63:56 MICROCODE, 55:32 Reserved, 31:24 SNP, 23:16 TEE, 15:8 BOOT_LOADER, 7:0 FMC
        let snp = ((tcb_version >> 24) & 0xFF) as u8;
        let tee = ((tcb_version >> 16) & 0xFF) as u8;
        let bootloader = ((tcb_version >> 8) & 0xFF) as u8;
        (microcode, snp, tee, bootloader)
    } else {
        // Default to Genoa/Milan structure as fallback
        let snp = ((tcb_version >> 48) & 0xFF) as u8;
        let tee = ((tcb_version >> 8) & 0xFF) as u8;
        let bootloader = (tcb_version & 0xFF) as u8;
        (microcode, snp, tee, bootloader)
    }
}

pub struct GrpcServiceState {
    pub db: DatabaseConnection,
    pub attestation_state: Arc<AttestationState>,
}

// Attestation Service Implementation
pub struct AttestationServiceImpl {
    pub state: Arc<GrpcServiceState>,
}

#[tonic::async_trait]
impl AttestationService for AttestationServiceImpl {
    async fn get_nonce(&self, request: Request<NonceRequest>) -> Result<Response<NonceResponse>, Status> {
        let mut rng = OsRng;
        let mut nonce = vec![0u8; 64];
        rng.fill_bytes(&mut nonce);
        
        let vm_id = request.into_inner().vm_id;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut nonces = self.state.attestation_state.nonces.lock().unwrap();
        
        // Clean up expired nonces
        const MAX_NONCES: usize = 10000;
        const NONCE_EXPIRY_SECONDS: u64 = 300; // 5 minutes
        
        if nonces.len() >= MAX_NONCES {
            let expired_keys: Vec<String> = nonces.iter()
                .filter(|(_, entry)| now.saturating_sub(entry.created_at) > NONCE_EXPIRY_SECONDS)
                .map(|(k, _)| k.clone())
                .collect();
            for key in expired_keys {
                nonces.remove(&key);
            }
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
        
        Ok(Response::new(NonceResponse { nonce }))
    }

    async fn verify_report(&self, request: Request<AttestationRequest>) -> Result<Response<AttestationResponse>, Status> {

const NONCE_EXPIRY_SECONDS: u64 = 300; // 5 minutes
        use tempfile::NamedTempFile;
        use std::io::Write;
        use std::path::Path;

        let req = request.into_inner();
        let report_data = req.report_data;

        // 1. Check report length
        if report_data.len() < 0x50 + 64 {
            let response = AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Report too short".to_string(),
            };
            return Ok(Response::new(response));
        }

        // 2. Extract and verify nonce (offset 0x50, 64 bytes)
        let report_nonce = &report_data[0x50..0x50 + 64];

        // Verify nonce was issued by us and not expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        {
            let mut nonces = self.state.attestation_state.nonces.lock().unwrap();
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
                return Ok(Response::new(response));
            }
        }

        // 3. Detect CPU family from report
        let cpu_family = match crate::attestation::detect_cpu_family(&report_data) {
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
            Err(_) => return Ok(Response::new(AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Failed to create temporary file".to_string(),
            })),
        };
        if temp_report.write_all(&report_data).is_err() {
            return Ok(Response::new(AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Failed to write report to temporary file".to_string(),
            }));
        }
        let report_path = temp_report.path();

        // 5. Verify signature (uses temporary certs directory internally)
        if let Err(e) = snpguest_wrapper::verify_report_signature(report_path, Path::new(""), &cpu_family) {
            let response = AttestationResponse {
                success: false,
                secret: vec![],
                error_message: format!("Signature verification failed: {}", e),
            };
            return Ok(Response::new(response));
        }

        // 6. Extract image_id (0x20, 16 bytes)
        if report_data.len() < 0x20 + 16 {
            let response = AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Report too short for image_id".to_string(),
            };
            return Ok(Response::new(response));
        }

        let image_id: Vec<u8> = report_data[0x20..0x20 + 16].to_vec();

        // 7. Extract key digests (0xE0 and 0x110, 48 bytes each)
        if report_data.len() < 0x110 + 48 {
            let response = AttestationResponse {
                success: false,
                secret: vec![],
                error_message: "Report too short for key digests".to_string(),
            };
            return Ok(Response::new(response));
        }

        let id_digest = &report_data[0xE0..0xE0 + 48];
        let auth_digest = &report_data[0x110..0x110 + 48];

        // 8. DB lookup by image_id and key digests
        let record = match vm::Entity::find()
            .filter(vm::Column::ImageId.eq(image_id))
            .filter(vm::Column::IdKeyDigest.eq(id_digest))
            .filter(vm::Column::AuthKeyDigest.eq(auth_digest))
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
            // 9. Extract and verify policy flags
            if report_data.len() < 0x08 + 8 {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: "Report too short for policy".to_string(),
                };
                return Ok(Response::new(response));
            }

            let policy_bytes = &report_data[0x08..0x08 + 8];
            let policy = u64::from_le_bytes(policy_bytes.try_into().unwrap());

            // Extract policy bits (bit 19 = debug, bit 18 = migrate_ma, bit 16 = smt)
            let report_debug = (policy & (1 << 19)) != 0;
            let report_migrate_ma = (policy & (1 << 18)) != 0;
            let report_smt = (policy & (1 << 16)) != 0;

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

            // 10. Extract and verify TCB version requirements
            if report_data.len() < 0x38 + 8 {
                let response = AttestationResponse {
                    success: false,
                    secret: vec![],
                    error_message: "Report too short for TCB version".to_string(),
                };
                return Ok(Response::new(response));
            }

            let tcb_bytes = &report_data[0x38..0x38 + 8];
            let tcb_version = u64::from_le_bytes(tcb_bytes.try_into().unwrap());

            // Decode TCB version based on CPU family
            let (current_microcode, current_snp, current_tee, current_bootloader) = decode_tcb_version(tcb_version, &cpu_family);

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
