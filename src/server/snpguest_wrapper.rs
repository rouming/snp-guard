use std::process::Command;
use std::path::Path;
use anyhow::{Context, Result, anyhow};

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
) -> Result<()> {
    
    // 1. Calculate Measurement
    let output = Command::new("snpguest")
        .arg("generate")
        .arg("measurement")
        .arg("--ovmf").arg(ovmf)
        .arg("--kernel").arg(kernel)
        .arg("--append").arg(params)
        .arg("--initrd").arg(initrd)
        .arg("--vcpus").arg(vcpus.to_string())
        .arg("--vcpu-type").arg(vcpu_type)
        .output()
        .context("Failed to execute snpguest generate measurement")?;

    if !output.status.success() {
        return Err(anyhow!("snpguest measurement failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let measurement = String::from_utf8(output.stdout)?.trim().to_string();

    // 2. Generate ID-Block and Auth-Block (without family-id and image-id)
    let status = Command::new("snpguest")
        .arg("--quiet")
        .arg("generate")
        .arg("id-block")
        .arg(id_key)
        .arg(auth_key)
        .arg(measurement)
        .arg("--id-file").arg(output_dir.join("id-block.bin"))
        .arg("--auth-file").arg(output_dir.join("id-auth.bin"))
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
    if !path.exists() { return Ok(()); }
    let content = std::fs::read(path)?;
    let content_str = String::from_utf8(content)?.replace('\n', "");
    let decoded = base64::decode(&content_str).context("Failed to decode base64 block")?;
    std::fs::write(path, decoded)?;
    Ok(())
}

pub fn get_key_digest(key_path: &Path) -> Result<Vec<u8>> {
    let output = Command::new("snpguest")
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

pub fn verify_report_signature(report_path: &Path, certs_dir: &Path, cpu_family: &str) -> Result<()> {
    // Requires snpguest 0.4+ 
    let _ = std::fs::create_dir_all(certs_dir);

    // 1. Fetch CA
    let status = Command::new("snpguest").arg("fetch").arg("ca").arg("pem").arg(cpu_family).arg(certs_dir).status()?;
    if !status.success() { return Err(anyhow!("Failed to fetch CA")); }

    // 2. Fetch VCEK (Needs report to identify chip)
    let status = Command::new("snpguest").arg("fetch").arg("vcek").arg("pem").arg(cpu_family).arg(certs_dir).arg(report_path).status()?;
    if !status.success() { return Err(anyhow!("Failed to fetch VCEK")); }

    // 3. Verify Certs
    let status = Command::new("snpguest").arg("verify").arg("certs").arg(certs_dir).status()?;
    if !status.success() { return Err(anyhow!("Failed to verify certs")); }

    // 4. Verify Attestation
    let status = Command::new("snpguest").arg("verify").arg("attestation").arg(certs_dir).arg(report_path).status()?;
    if !status.success() { return Err(anyhow!("Failed to verify attestation signature")); }

    Ok(())
}
