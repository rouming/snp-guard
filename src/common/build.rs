fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate prost messages (no gRPC services emitted/used)
    tonic_build::configure()
        .build_server(true)
        .build_client(true)  // Generate both server and client code
        .out_dir(std::env::var("OUT_DIR")?)
        .compile_protos(&["../../protos/attestation.proto"], &["../../protos"])?;

    Ok(())
}
