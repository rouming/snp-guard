use anyhow::{anyhow, Context, Result};
use base64::Engine;
use std::path::Path;
use std::process::Command;

/// Wraps 'snpguest generate measurement' then 'snpguest generate id-block'
pub fn generate_measurement_and_block(
    ovmf: &Path,
    kernel: &Path,
    initrd: &Path,
    params: &str,
    vcpus: u32,
    vcpu_type: &str,
    id_key: &Path,
    auth_key: &Path,
    output_dir: &Path,
    image_id_hex: String,
) -> Result<()> {
    // 1. Calculate Measurement
    let snpguest_path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow!("Cannot get executable directory"))?
        .join("../../snpguest/target/x86_64-unknown-linux-musl/release/snpguest");

    let output = Command::new(&snpguest_path)
        .arg("generate")
        .arg("measurement")
        .arg("--ovmf")
        .arg(ovmf)
        .arg("--kernel")
        .arg(kernel)
        .arg("--append")
        .arg(params)
        .arg("--initrd")
        .arg(initrd)
        .arg("--vcpus")
        .arg(vcpus.to_string())
        .arg("--vcpu-type")
        .arg(vcpu_type)
        .output()
        .context("Failed to execute snpguest generate measurement")?;

    if !output.status.success() {
        return Err(anyhow!(
            "snpguest measurement failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let measurement = String::from_utf8(output.stdout)?.trim().to_string();

    // Validate image_id_hex is exactly 32 characters (representing 16 bytes in hex)
    if image_id_hex.len() != 32 || !image_id_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "image_id must be a 32-character hex string (representing 16 bytes)"
        ));
    }

    // 2. Generate ID-Block and Auth-Block with image-id
    let status = Command::new(&snpguest_path)
        .arg("--quiet")
        .arg("generate")
        .arg("id-block")
        .arg(id_key)
        .arg(auth_key)
        .arg(measurement)
        .arg("--image-id")
        .arg(image_id_hex)
        .arg("--id-file")
        .arg(output_dir.join("id-block.bin"))
        .arg("--auth-file")
        .arg(output_dir.join("id-auth.bin"))
        .status()?;

    if !status.success() {
        return Err(anyhow!("Failed to generate id-block"));
    }

    // Decode Base64 outputs to binary
    decode_base64_file(&output_dir.join("id-block.bin"))?;
    decode_base64_file(&output_dir.join("id-auth.bin"))?;

    Ok(())
}

fn decode_base64_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let content = std::fs::read(path)?;
    let content_str = String::from_utf8(content)?.replace('\n', "");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&content_str)
        .context("Failed to decode base64 block")?;
    std::fs::write(path, decoded)?;
    Ok(())
}

pub fn get_key_digest(key_path: &Path) -> Result<Vec<u8>> {
    let snpguest_path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow!("Cannot get executable directory"))?
        .join("../../snpguest/target/x86_64-unknown-linux-musl/release/snpguest");

    let output = Command::new(&snpguest_path)
        .arg("generate")
        .arg("key-digest")
        .arg(key_path)
        .output()?;

    if !output.status.success() {
        return Err(anyhow!("Failed to get key digest"));
    }

    // Output is Hex. Convert to binary.
    let hex_str = String::from_utf8(output.stdout)?.trim().to_string();
    let bytes = hex::decode(hex_str)?;
    Ok(bytes)
}

pub fn verify_report_signature(
    report_path: &Path,
    _certs_dir: &Path,
    cpu_family: &str,
) -> Result<()> {
    let snpguest_path = std::env::current_exe()?
        .parent()
        .ok_or_else(|| anyhow!("Cannot get executable directory"))?
        .join("../../snpguest/target/x86_64-unknown-linux-musl/release/snpguest");

    // Create temporary directory for certificates
    let temp_dir = tempfile::TempDir::new().context("Failed to create temporary directory")?;
    let certs_dir = temp_dir.path();

    // Requires snpguest 0.4+
    // 1. Fetch CA
    let status = Command::new(&snpguest_path)
        .arg("fetch")
        .arg("ca")
        .arg("pem")
        .arg(cpu_family)
        .arg(certs_dir)
        .status()?;
    if !status.success() {
        return Err(anyhow!("Failed to fetch CA certificates"));
    }

    // 2. Fetch VCEK (Needs report to identify chip)
    let status = Command::new(&snpguest_path)
        .arg("fetch")
        .arg("vcek")
        .arg("pem")
        .arg(cpu_family)
        .arg(certs_dir)
        .arg(report_path)
        .status()?;
    if !status.success() {
        return Err(anyhow!("Failed to fetch VCEK certificate"));
    }

    // 3. Verify Certs
    let status = Command::new(&snpguest_path)
        .arg("verify")
        .arg("certs")
        .arg(certs_dir)
        .status()?;
    if !status.success() {
        return Err(anyhow!("Failed to verify certificate chain"));
    }

    // 4. Verify Attestation
    let status = Command::new(&snpguest_path)
        .arg("verify")
        .arg("attestation")
        .arg(certs_dir)
        .arg(report_path)
        .status()?;
    if !status.success() {
        return Err(anyhow!("Failed to verify attestation report signature"));
    }

    // Temp directory will be automatically cleaned up when dropped
    Ok(())
}
