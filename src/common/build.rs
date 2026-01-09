fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compiles proto to OUT_DIR using prost
    prost_build::Config::new()
        .out_dir("src")
        .compile_protos(&["../../protos/attestation.proto"], &["../../protos"])?;
    Ok(())
}
