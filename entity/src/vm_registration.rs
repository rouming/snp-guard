use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// Persistent VM identity across kernel/initrd renewals.
///
/// Holds the mutable state (enabled flag, request counter, OS name) and
/// references to the currently active attestation record and, when a renewal
/// is in flight, the pending attestation record.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "vm_registrations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String, // UUID
    pub os_name: String,
    pub enabled: bool,
    pub request_count: i32,
    /// ID of the currently active AttestationRecord.
    pub current_record_id: String,
    /// ID of the pending AttestationRecord created by a renewal, if any.
    pub pending_record_id: Option<String>,
    pub created_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
