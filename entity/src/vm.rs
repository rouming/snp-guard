use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "attestation_records")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,              // UUID
    pub os_name: String,
    pub request_count: i32,
    pub secret: String,
    pub vcpus: i32,
    pub vcpu_type: String,
    pub enabled: bool,           // Enable/Disable flag

    #[sea_orm(column_type = "Binary(48)")]
    pub id_key_digest: Vec<u8>,
    
    #[sea_orm(column_type = "Binary(48)")]
    pub auth_key_digest: Vec<u8>,
    
    pub created_at: DateTime,
    pub kernel_params: String,
    
    // Stored filenames relative to artifact dir
    pub firmware_path: String,
    pub kernel_path: String,
    pub initrd_path: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
