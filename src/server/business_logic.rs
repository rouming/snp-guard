use crate::{config::DataPaths, ingestion_key, snpguest_wrapper};
use entity::vm;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use rand::{rngs::OsRng, RngCore};
use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};
use sev::firmware::guest::GuestPolicy;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

/// Guard to ensure artifact directory is cleaned up on error
struct ArtifactDirGuard {
    path: PathBuf,
    should_cleanup: bool,
}

impl ArtifactDirGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            should_cleanup: true,
        }
    }

    fn keep(&mut self) {
        self.should_cleanup = false;
    }
}

impl Drop for ArtifactDirGuard {
    fn drop(&mut self) {
        if self.should_cleanup && self.path.exists() {
            if let Err(e) = fs::remove_dir_all(&self.path) {
                eprintln!(
                    "Warning: Failed to cleanup artifact directory {:?}: {}",
                    self.path, e
                );
            }
        }
    }
}

#[derive(Debug)]
pub struct CreateRecordRequest {
    pub os_name: String,
    pub firmware_data: Option<Vec<u8>>,
    pub kernel_data: Option<Vec<u8>>,
    pub initrd_data: Option<Vec<u8>>,
    pub kernel_params: String,
    pub vcpus: u32,
    pub vcpu_type: String,
    pub unsealing_private_key_encrypted: Vec<u8>, // HPKE-encrypted unsealing private key
    pub allowed_debug: bool,
    pub allowed_migrate_ma: bool,
    pub allowed_smt: bool,
    pub min_tcb_bootloader: u32,
    pub min_tcb_tee: u32,
    pub min_tcb_snp: u32,
    pub min_tcb_microcode: u32,
}

/// Generate a secp384r1 EC private key in PEM format
fn generate_ec_key_pem() -> Result<Vec<u8>, String> {
    use openssl::pkey::PKey;

    let group = EcGroup::from_curve_name(Nid::SECP384R1)
        .map_err(|e| format!("Failed to create EC group: {}", e))?;
    let key = EcKey::generate(&group).map_err(|e| format!("Failed to generate EC key: {}", e))?;
    let pkey = PKey::from_ec_key(key).map_err(|e| format!("Failed to create PKey: {}", e))?;
    pkey.private_key_to_pem_pkcs8()
        .map_err(|e| format!("Failed to serialize key to PEM: {}", e))
}

/// Securely delete a file by overwriting its contents before removal.
/// This helps prevent recovery of sensitive data from disk.
fn secure_delete_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(()); // File doesn't exist, nothing to delete
    }

    // Get file size
    let metadata = fs::metadata(path).map_err(|e| format!("Failed to get file metadata: {}", e))?;
    let file_size = metadata.len() as usize;

    if file_size == 0 {
        // Empty file, just delete it
        fs::remove_file(path).map_err(|e| format!("Failed to delete empty file: {}", e))?;
        return Ok(());
    }

    // Open file for writing (truncate to overwrite)
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("Failed to open file for secure deletion: {}", e))?;

    // Overwrite with random data (single pass is sufficient for modern systems)
    let mut rng = OsRng;
    let mut buffer = vec![0u8; file_size.min(64 * 1024)]; // 64KB buffer
    let mut remaining = file_size;

    while remaining > 0 {
        let to_write = remaining.min(buffer.len());
        rng.fill_bytes(&mut buffer[..to_write]);
        file.write_all(&buffer[..to_write])
            .map_err(|e| format!("Failed to overwrite file content: {}", e))?;
        remaining -= to_write;
    }

    // Sync to ensure data is written to disk
    file.sync_all()
        .map_err(|e| format!("Failed to sync file: {}", e))?;

    // Close file before deletion
    drop(file);

    // Delete the file
    fs::remove_file(path).map_err(|e| format!("Failed to delete file after overwrite: {}", e))?;

    Ok(())
}

pub async fn create_record_logic(
    db: &DatabaseConnection,
    paths: &DataPaths,
    ingestion_keys: Arc<ingestion_key::IngestionKeys>,
    req: CreateRecordRequest,
) -> Result<String, String> {
    let new_id = Uuid::new_v4().to_string();
    let artifact_dir = paths.attestations_dir.join(&new_id);

    // Create cleanup guard to ensure directory is removed on any error
    // The guard will be dropped when this function returns, cleaning up on error
    let mut cleanup_guard = ArtifactDirGuard::new(artifact_dir.clone());

    // Generate unique image_id as UUID (16 bytes)
    let image_id = Uuid::new_v4();

    let result = async {
        fs::create_dir_all(&artifact_dir)
            .map_err(|e| format!("Failed to create artifact directory: {}", e))?;

        // Generate ID and Auth keys on server
        let id_key_pem =
            generate_ec_key_pem().map_err(|e| format!("Failed to generate ID key: {}", e))?;
        let auth_key_pem =
            generate_ec_key_pem().map_err(|e| format!("Failed to generate auth key: {}", e))?;

        // Save generated keys
        fs::write(artifact_dir.join("id-block-key.pem"), &id_key_pem)
            .map_err(|e| format!("Failed to save ID key: {}", e))?;
        fs::write(artifact_dir.join("id-auth-key.pem"), &auth_key_pem)
            .map_err(|e| format!("Failed to save auth key: {}", e))?;

        // Unsealing private key is already encrypted by client with ingestion public key
        // Just store it directly
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

        fs::write(artifact_dir.join("kernel-params.txt"), &req.kernel_params)
            .map_err(|e| format!("Failed to save kernel params: {}", e))?;

        let mut policy: GuestPolicy = Default::default();
        policy.set_debug_allowed(req.allowed_debug);
        policy.set_migrate_ma_allowed(req.allowed_migrate_ma);
        policy.set_smt_allowed(req.allowed_smt);

        // Generate Measurements and Blocks
        let _ = snpguest_wrapper::generate_measurement_and_block(
            &artifact_dir.join("firmware-code.fd"),
            &artifact_dir.join("vmlinuz"),
            &artifact_dir.join("initrd.img"),
            &req.kernel_params,
            req.vcpus,
            &req.vcpu_type,
            policy.into(),
            &artifact_dir.join("id-block-key.pem"),
            &artifact_dir.join("id-auth-key.pem"),
            &artifact_dir,
            image_id.as_bytes(),
        )
        .map_err(|e| format!("Failed to generate measurement and blocks: {}", e))?;

        // Get Digests
        let id_digest = snpguest_wrapper::get_key_digest(&artifact_dir.join("id-block-key.pem"))
            .map_err(|e| format!("Failed to get ID key digest: {}", e))?;
        let auth_digest = snpguest_wrapper::get_key_digest(&artifact_dir.join("id-auth-key.pem"))
            .map_err(|e| format!("Failed to get auth key digest: {}", e))?;

        // Encrypt ID and Auth keys with ingestion key
        let id_key_encrypted = ingestion_keys
            .encrypt(&id_key_pem)
            .map_err(|e| format!("Failed to encrypt ID key: {}", e))?;
        let auth_key_encrypted = ingestion_keys
            .encrypt(&auth_key_pem)
            .map_err(|e| format!("Failed to encrypt Auth key: {}", e))?;

        // Securely delete key files after encryption (they're no longer needed)
        secure_delete_file(&artifact_dir.join("id-block-key.pem"))
            .map_err(|e| format!("Failed to securely delete ID key file: {}", e))?;
        secure_delete_file(&artifact_dir.join("id-auth-key.pem"))
            .map_err(|e| format!("Failed to securely delete Auth key file: {}", e))?;

        // Save to DB
        let new_vm = vm::ActiveModel {
            id: Set(new_id.clone()),
            os_name: Set(req.os_name),
            unsealing_private_key_encrypted: Set(req.unsealing_private_key_encrypted),
            vcpus: Set(req.vcpus as i32),
            vcpu_type: Set(req.vcpu_type),
            id_key_digest: Set(id_digest),
            auth_key_digest: Set(auth_digest),
            id_key_encrypted: Set(Some(id_key_encrypted)),
            auth_key_encrypted: Set(Some(auth_key_encrypted)),
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
            kernel_params: Set(req.kernel_params),
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
    .await;

    // If successful, mark guard to keep the directory; otherwise it will be cleaned up on drop
    match &result {
        Ok(_) => cleanup_guard.keep(),
        Err(_) => {
            // Explicitly try cleanup (guard's Drop will also try, but this ensures it happens)
            let _ = fs::remove_dir_all(&artifact_dir);
        }
    }

    result
}
