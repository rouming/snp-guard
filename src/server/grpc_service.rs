use tonic::{Request, Response, Status};
use sea_orm::{DatabaseConnection, EntityTrait, Set, ActiveModelTrait, QueryOrder};
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
// snpguest wrapper not used directly in gRPC service paths

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

    async fn verify_report(&self, _request: Request<AttestationRequest>) -> Result<Response<AttestationResponse>, Status> {
        // Delegate to HTTP handler's verify_report logic
        // The HTTP endpoint already implements full verification
        // For now, return unimplemented - HTTP endpoint should be used
        Err(Status::unimplemented("Use HTTP /attestation/verify endpoint. Full gRPC implementation coming soon."))
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
        });
        
        Ok(Response::new(GetRecordResponse { record: proto_record }))
    }

    async fn create_record(&self, _request: Request<CreateRecordRequest>) -> Result<Response<CreateRecordResponse>, Status> {
        let _req = _request.into_inner();
        
        // Implementation similar to web::create_action but via gRPC
        // This would need to handle file uploads, generate blocks, etc.
        
        Err(Status::unimplemented("CreateRecord via gRPC not yet implemented - use HTTP endpoint"))
    }

    async fn update_record(&self, _request: Request<UpdateRecordRequest>) -> Result<Response<UpdateRecordResponse>, Status> {
        let _req = _request.into_inner();
        let _id = _req.id.clone();
        
        // Implementation similar to web::update_action but via gRPC
        
        Err(Status::unimplemented("UpdateRecord via gRPC not yet implemented - use HTTP endpoint"))
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
