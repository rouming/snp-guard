use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "attestation_records")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String, // UUID
    pub os_name: String,
    pub request_count: i32,
    pub secret: String,
    pub vcpus: i32,
    pub vcpu_type: String,
    pub enabled: bool, // Enable/Disable flag
    #[sea_orm(column_type = "Binary(16)")]
    pub image_id: Vec<u8>, // Image ID (UUID as 16 bytes) for attestation report matching

    // Policy flags
    pub allowed_debug: bool,      // Allow debug mode
    pub allowed_migrate_ma: bool, // Allow migration with MA
    pub allowed_smt: bool,        // Allow Simultaneous Multithreading

    // TCB minimum version requirements
    pub min_tcb_bootloader: i32, // Minimum PSP bootloader version
    pub min_tcb_tee: i32,        // Minimum SNP firmware version
    pub min_tcb_snp: i32,        // Minimum SNP implementation version
    pub min_tcb_microcode: i32,  // Minimum CPU microcode version

    #[sea_orm(column_type = "Binary(48)")]
    pub id_key_digest: Vec<u8>,

    #[sea_orm(column_type = "Binary(48)")]
    pub auth_key_digest: Vec<u8>,

    pub created_at: DateTime,
    pub kernel_params: String, // base params without rd.attest.url
    pub service_url: String,   // attestation service URL

    // Stored filenames relative to artifact dir
    pub firmware_path: String,
    pub kernel_path: String,
    pub initrd_path: String,
    pub measurement: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
