use crate::snpguest_wrapper;
use entity::vm;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug)]
pub struct CreateRecordRequest {
    pub os_name: String,
    pub id_key_pem: Option<Vec<u8>>,
    pub auth_key_pem: Option<Vec<u8>>,
    pub firmware_data: Option<Vec<u8>>,
    pub kernel_data: Option<Vec<u8>>,
    pub initrd_data: Option<Vec<u8>>,
    pub kernel_params: String,
    pub vcpus: u32,
    pub vcpu_type: String,
    pub service_url: String,
    pub secret: String,
    pub allowed_debug: bool,
    pub allowed_migrate_ma: bool,
    pub allowed_smt: bool,
    pub min_tcb_bootloader: u32,
    pub min_tcb_tee: u32,
    pub min_tcb_snp: u32,
    pub min_tcb_microcode: u32,
}

#[derive(Debug)]
pub struct UpdateRecordRequest {
    pub id: String,
    pub os_name: Option<String>,
    pub id_key_pem: Option<Vec<u8>>,
    pub auth_key_pem: Option<Vec<u8>>,
    pub firmware_data: Option<Vec<u8>>,
    pub kernel_data: Option<Vec<u8>>,
    pub initrd_data: Option<Vec<u8>>,
    pub kernel_params: Option<String>,
    pub vcpus: Option<u32>,
    pub vcpu_type: Option<String>,
    pub service_url: Option<String>,
    pub secret: Option<String>,
    pub enabled: Option<bool>,
    pub allowed_debug: Option<bool>,
    pub allowed_migrate_ma: Option<bool>,
    pub allowed_smt: Option<bool>,
    pub min_tcb_bootloader: Option<u32>,
    pub min_tcb_tee: Option<u32>,
    pub min_tcb_snp: Option<u32>,
    pub min_tcb_microcode: Option<u32>,
}

#[derive(Debug)]
pub struct UpdateRecordResponse {
    pub success: bool,
    pub error_message: Option<String>,
}

pub async fn create_record_logic(
    db: &DatabaseConnection,
    req: CreateRecordRequest,
) -> Result<String, String> {
    let new_id = Uuid::new_v4().to_string();

    // Generate unique image_id as UUID (16 bytes)
    let image_id = Uuid::new_v4();

    let artifact_dir = PathBuf::from("artifacts").join(&new_id);
    fs::create_dir_all(&artifact_dir)
        .map_err(|e| format!("Failed to create artifact directory: {}", e))?;

    // Save uploaded files
    if let Some(id_key) = req.id_key_pem {
        fs::write(artifact_dir.join("id-block-key.pem"), id_key)
            .map_err(|e| format!("Failed to save ID key: {}", e))?;
    }
    if let Some(auth_key) = req.auth_key_pem {
        fs::write(artifact_dir.join("id-auth-key.pem"), auth_key)
            .map_err(|e| format!("Failed to save auth key: {}", e))?;
    }
    if let Some(firmware) = req.firmware_data {
        fs::write(artifact_dir.join("firmware-code.fd"), firmware)
            .map_err(|e| format!("Failed to save firmware: {}", e))?;
    }
    if let Some(kernel) = req.kernel_data {
        fs::write(artifact_dir.join("vmlinuz"), kernel)
            .map_err(|e| format!("Failed to save kernel: {}", e))?;
    }
    if let Some(initrd) = req.initrd_data {
        fs::write(artifact_dir.join("initrd.img"), initrd)
            .map_err(|e| format!("Failed to save initrd: {}", e))?;
    }

    let full_params = format!("{} rd.attest.url={}", req.kernel_params, req.service_url);
    fs::write(artifact_dir.join("kernel-params.txt"), &full_params)
        .map_err(|e| format!("Failed to save kernel params: {}", e))?;

    // Convert UUID to hex string (32 characters, 16 bytes when decoded)
    let image_id_hex = hex::encode(image_id.as_bytes());

    // Generate Measurements and Blocks
    snpguest_wrapper::generate_measurement_and_block(
        &artifact_dir.join("firmware-code.fd"),
        &artifact_dir.join("vmlinuz"),
        &artifact_dir.join("initrd.img"),
        &full_params,
        req.vcpus,
        &req.vcpu_type,
        &artifact_dir.join("id-block-key.pem"),
        &artifact_dir.join("id-auth-key.pem"),
        &artifact_dir,
        image_id_hex,
    )
    .map_err(|e| format!("Failed to generate measurement and blocks: {}", e))?;

    // Get Digests
    let id_digest = snpguest_wrapper::get_key_digest(&artifact_dir.join("id-block-key.pem"))
        .map_err(|e| format!("Failed to get ID key digest: {}", e))?;
    let auth_digest = snpguest_wrapper::get_key_digest(&artifact_dir.join("id-auth-key.pem"))
        .map_err(|e| format!("Failed to get auth key digest: {}", e))?;

    // Save to DB
    let new_vm = vm::ActiveModel {
        id: Set(new_id.clone()),
        os_name: Set(req.os_name),
        secret: Set(req.secret),
        vcpus: Set(req.vcpus as i32),
        vcpu_type: Set(req.vcpu_type),
        id_key_digest: Set(id_digest),
        auth_key_digest: Set(auth_digest),
        created_at: Set(chrono::Utc::now().naive_utc()),
        enabled: Set(true),
        image_id: Set(image_id.as_bytes().to_vec()),
        allowed_debug: Set(req.allowed_debug),
        allowed_migrate_ma: Set(req.allowed_migrate_ma),
        allowed_smt: Set(req.allowed_smt),
        min_tcb_bootloader: Set(req.min_tcb_bootloader as i32),
        min_tcb_tee: Set(req.min_tcb_tee as i32),
        min_tcb_snp: Set(req.min_tcb_snp as i32),
        min_tcb_microcode: Set(req.min_tcb_microcode as i32),
        kernel_params: Set(full_params),
        request_count: Set(0),
        firmware_path: Set("firmware-code.fd".into()),
        kernel_path: Set("vmlinuz".into()),
        initrd_path: Set("initrd.img".into()),
    };

    new_vm
        .insert(db)
        .await
        .map_err(|e| format!("Failed to save record to database: {}", e))?;

    Ok(new_id)
}

pub async fn update_record_logic(
    db: &DatabaseConnection,
    req: UpdateRecordRequest,
) -> Result<UpdateRecordResponse, String> {
    let artifact_dir = PathBuf::from("artifacts").join(&req.id);
    fs::create_dir_all(&artifact_dir)
        .map_err(|e| format!("Failed to create artifact directory: {}", e))?;

    // Get current record first
    let mut vm_model = vm::Entity::find_by_id(req.id.clone())
        .one(db)
        .await
        .map_err(|e| format!("Database error: {}", e))?
        .ok_or_else(|| "Record not found".to_string())?;

    // Save any new uploaded files
    let id_key_present = req.id_key_pem.is_some();
    let auth_key_present = req.auth_key_pem.is_some();
    let firmware_present = req.firmware_data.is_some();
    let kernel_present = req.kernel_data.is_some();
    let initrd_present = req.initrd_data.is_some();

    if let Some(ref id_key) = req.id_key_pem {
        fs::write(artifact_dir.join("id-block-key.pem"), id_key)
            .map_err(|e| format!("Failed to save ID key: {}", e))?;
    }
    if let Some(ref auth_key) = req.auth_key_pem {
        fs::write(artifact_dir.join("id-auth-key.pem"), auth_key)
            .map_err(|e| format!("Failed to save auth key: {}", e))?;
    }
    if let Some(ref firmware) = req.firmware_data {
        fs::write(artifact_dir.join("firmware-code.fd"), firmware)
            .map_err(|e| format!("Failed to save firmware: {}", e))?;
    }
    if let Some(ref kernel) = req.kernel_data {
        fs::write(artifact_dir.join("vmlinuz"), kernel)
            .map_err(|e| format!("Failed to save kernel: {}", e))?;
    }
    if let Some(ref initrd) = req.initrd_data {
        fs::write(artifact_dir.join("initrd.img"), initrd)
            .map_err(|e| format!("Failed to save initrd: {}", e))?;
    }

    // Update kernel params if needed
    let mut full_params = vm_model.kernel_params.clone();
    let mut params_changed = false;

    if let Some(new_kernel_params) = req.kernel_params {
        full_params = new_kernel_params;
        params_changed = true;
    }
    if let Some(service_url) = req.service_url {
        full_params = format!(
            "{} rd.attest.url={}",
            full_params
                .split("rd.attest.url=")
                .next()
                .unwrap_or("")
                .trim(),
            service_url
        );
        params_changed = true;
    }

    // Check if we need to regenerate blocks
    let needs_regeneration = params_changed
        || id_key_present
        || auth_key_present
        || firmware_present
        || kernel_present
        || initrd_present
        || req.vcpus.is_some()
        || req.vcpu_type.is_some();

    if needs_regeneration {
        // Ensure all files exist
        let firmware_path = artifact_dir.join("firmware-code.fd");
        let kernel_path = artifact_dir.join("vmlinuz");
        let initrd_path = artifact_dir.join("initrd.img");
        let id_key_path = artifact_dir.join("id-block-key.pem");
        let auth_key_path = artifact_dir.join("id-auth-key.pem");

        let vcpus = req.vcpus.unwrap_or(vm_model.vcpus as u32);
        let vcpu_type = req
            .vcpu_type
            .as_ref()
            .unwrap_or(&vm_model.vcpu_type)
            .clone();

        // Convert image_id bytes to hex string (32 characters, 16 bytes when decoded)
        let image_id_hex = hex::encode(&vm_model.image_id);

        snpguest_wrapper::generate_measurement_and_block(
            &firmware_path,
            &kernel_path,
            &initrd_path,
            &full_params,
            vcpus,
            &vcpu_type,
            &id_key_path,
            &auth_key_path,
            &artifact_dir,
            image_id_hex,
        )
        .map_err(|e| format!("Failed to regenerate measurement and blocks: {}", e))?;

        // Update digests
        let id_digest = snpguest_wrapper::get_key_digest(&id_key_path)
            .map_err(|e| format!("Failed to get ID key digest: {}", e))?;
        let auth_digest = snpguest_wrapper::get_key_digest(&auth_key_path)
            .map_err(|e| format!("Failed to get auth key digest: {}", e))?;

        vm_model.id_key_digest = id_digest;
        vm_model.auth_key_digest = auth_digest;
    }

    // Update database record
    let mut active_model: vm::ActiveModel = vm_model.into();

    if let Some(ref os_name) = req.os_name {
        active_model.os_name = Set(os_name.clone());
    }
    if let Some(ref secret) = req.secret {
        active_model.secret = Set(secret.clone());
    }
    if let Some(vcpus) = req.vcpus {
        active_model.vcpus = Set(vcpus as i32);
    }
    if let Some(ref vcpu_type) = req.vcpu_type {
        active_model.vcpu_type = Set(vcpu_type.clone());
    }
    if let Some(enabled) = req.enabled {
        active_model.enabled = Set(enabled);
    } else if req.os_name.is_none()
        && req.secret.is_none()
        && req.vcpus.is_none()
        && req.vcpu_type.is_none()
        && !id_key_present
        && !auth_key_present
        && !firmware_present
        && !kernel_present
        && !initrd_present
        && req.allowed_debug.is_none()
        && req.allowed_migrate_ma.is_none()
        && req.allowed_smt.is_none()
        && req.min_tcb_bootloader.is_none()
        && req.min_tcb_tee.is_none()
        && req.min_tcb_snp.is_none()
        && req.min_tcb_microcode.is_none()
    {
        // If no other changes, default enabled to false for checkbox behavior
        active_model.enabled = Set(false);
    }

    if let Some(allowed_debug) = req.allowed_debug {
        active_model.allowed_debug = Set(allowed_debug);
    }
    if let Some(allowed_migrate_ma) = req.allowed_migrate_ma {
        active_model.allowed_migrate_ma = Set(allowed_migrate_ma);
    }
    if let Some(allowed_smt) = req.allowed_smt {
        active_model.allowed_smt = Set(allowed_smt);
    }
    if let Some(min_tcb_bootloader) = req.min_tcb_bootloader {
        active_model.min_tcb_bootloader = Set(min_tcb_bootloader as i32);
    }
    if let Some(min_tcb_tee) = req.min_tcb_tee {
        active_model.min_tcb_tee = Set(min_tcb_tee as i32);
    }
    if let Some(min_tcb_snp) = req.min_tcb_snp {
        active_model.min_tcb_snp = Set(min_tcb_snp as i32);
    }
    if let Some(min_tcb_microcode) = req.min_tcb_microcode {
        active_model.min_tcb_microcode = Set(min_tcb_microcode as i32);
    }

    if params_changed {
        active_model.kernel_params = Set(full_params.clone());
        fs::write(artifact_dir.join("kernel-params.txt"), &full_params)
            .map_err(|e| format!("Failed to update kernel params file: {}", e))?;
    }

    active_model
        .update(db)
        .await
        .map_err(|e| format!("Failed to update record in database: {}", e))?;

    Ok(UpdateRecordResponse {
        success: true,
        error_message: None,
    })
}
