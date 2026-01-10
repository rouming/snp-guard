fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate both prost messages and tonic gRPC services
    // tonic-build generates both the gRPC service traits and prost message types
    tonic_build::configure()
        .build_server(true)
        .build_client(true)  // Generate both server and client code
        .out_dir(std::env::var("OUT_DIR")?)
        .compile_protos(&["../../protos/attestation.proto"], &["../../protos"])?;

    Ok(())
}
