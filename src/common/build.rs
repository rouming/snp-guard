fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate prost messages only (no gRPC services emitted)
    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .out_dir(std::env::var("OUT_DIR")?)
        .compile_protos(&["../../protos/attestation.proto"], &["../../protos"])?;

    Ok(())
}
