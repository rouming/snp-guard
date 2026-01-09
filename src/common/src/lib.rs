// Re-export the generated code so client/server can use "common::snpguard::..."
pub mod snpguard {
    include!(concat!(env!("OUT_DIR"), "/snpguard.rs"));
}
