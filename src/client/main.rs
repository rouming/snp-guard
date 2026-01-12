use anyhow::{bail, Context, Result};
use clap::Parser;
use common::snpguard::{AttestationRequest, AttestationResponse, NonceRequest, NonceResponse};
use prost::Message;
use reqwest::Certificate;
use sev::firmware::guest::Firmware;
use std::fs;
use std::io::Write;

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    url: String,
}

const CA_CERT_PATH: &str = "/etc/snpguard/ca.pem";

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Parse URL and ensure it's HTTPS
    let url = if args.url.starts_with("http://") || args.url.starts_with("https://") {
        args.url.clone()
    } else {
        format!("https://{}", args.url)
    };

    if !url.starts_with("https://") {
        bail!("URL must use HTTPS for secure attestation");
    }

    // Load pinned CA certificate (or self-signed server cert) from initrd path
    let ca_pem = fs::read(CA_CERT_PATH)
        .with_context(|| format!("Failed to read pinned CA certificate at {}", CA_CERT_PATH))?;
    let ca_cert =
        Certificate::from_pem(&ca_pem).context("Pinned CA certificate is not valid PEM")?;

    // Create HTTP client with strict TLS using only the pinned CA
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca_cert)
        .build()
        .context("Failed to create HTTP client with pinned CA")?;

    // 1. Get Nonce
    let nonce_request = NonceRequest {};
    let mut request_bytes = Vec::new();
    nonce_request.encode(&mut request_bytes)?;

    let nonce_url = format!("{}/v1/attest/nonce", url);
    let response = client
        .post(&nonce_url)
        .header("Content-Type", "application/x-protobuf")
        .body(request_bytes)
        .send()
        .await
        .context("Failed to request nonce")?;

    if !response.status().is_success() {
        anyhow::bail!("Nonce request failed: {}", response.status());
    }

    let response_bytes = response.bytes().await?;
    let nonce_response =
        NonceResponse::decode(&response_bytes[..]).context("Failed to decode nonce response")?;
    let nonce = nonce_response.nonce;

    if nonce.len() != 64 {
        anyhow::bail!(
            "Invalid nonce length: expected 64 bytes, got {}",
            nonce.len()
        );
    }

    // 2. Generate Report using sev library directly
    let mut fw = Firmware::open().context(
        "Failed to open SEV firmware device (/dev/sev-guest). Ensure SEV-SNP is enabled.",
    )?;

    // Convert nonce to [u8; 64] array
    let mut nonce_array = [0u8; 64];
    nonce_array.copy_from_slice(&nonce[..64]);

    let report_data = fw
        .get_report(None, Some(nonce_array), Some(1))
        .context("Failed to get attestation report from SEV firmware")?;

    // 3. Verify Report
    let verify_request = AttestationRequest { report_data };

    let mut request_bytes = Vec::new();
    verify_request.encode(&mut request_bytes)?;

    let verify_url = format!("{}/v1/attest/report", url);
    let response = client
        .post(&verify_url)
        .header("Content-Type", "application/x-protobuf")
        .body(request_bytes)
        .send()
        .await
        .context("Failed to verify report")?;

    if !response.status().is_success() {
        anyhow::bail!("Verification request failed: {}", response.status());
    }

    let response_bytes = response.bytes().await?;
    let verify_response = AttestationResponse::decode(&response_bytes[..])
        .context("Failed to decode verification response")?;

    if verify_response.success {
        // Output secret to stdout (piped to cryptsetup or other tools)
        std::io::stdout().write_all(&verify_response.secret)?;
        std::io::stdout().flush()?;
    } else {
        eprintln!("Attestation Failed: {}", verify_response.error_message);
        std::process::exit(1);
    }

    Ok(())
}
