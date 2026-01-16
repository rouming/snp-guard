mod local_ops;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use common::snpguard::{
    AttestationRequest, AttestationResponse, CreateRecordRequest, CreateRecordResponse,
    DeleteRecordResponse, GetRecordResponse, ListRecordsResponse, NonceRequest, NonceResponse,
    ToggleEnabledResponse,
};
use dirs::config_dir;
use flate2::read::GzDecoder;
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    Deserializable, OpModeR, OpModeS, Serializable,
};
use prost::Message;
use rand::rngs::OsRng;
use reqwest::Certificate;
use sev::firmware::guest::Firmware;
use sha2::{Digest, Sha512};
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tar::Archive;

const DEFAULT_CA_CERT: &str = "/etc/snpguard/ca.pem";

#[derive(Parser, Debug)]
#[command(author, version, about = "SnpGuard client")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Perform attestation and output the released secret
    Attest {
        #[arg(long, value_name = "URL")]
        url: String,
        #[arg(long, value_name = "PATH", default_value = DEFAULT_CA_CERT)]
        ca_cert: String,
        #[arg(long, value_name = "PATH")]
        sealed_blob: Option<PathBuf>,
    },
    /// Generate a new Unsealing Keypair (Offline)
    Keygen {
        /// Output path for private key (e.g., unsealing.key)
        #[arg(long, default_value = "unsealing.key")]
        priv_out: PathBuf,
        /// Output path for public key (e.g., unsealing.pub)
        #[arg(long, default_value = "unsealing.pub")]
        pub_out: PathBuf,
    },
    /// Seal a file (e.g., VMK) for a specific Public Key (Offline)
    Seal {
        /// Path to the Unsealing Public Key
        #[arg(long)]
        pub_key: PathBuf,
        /// Path to the plaintext file to seal
        #[arg(long)]
        data: PathBuf,
        /// Output path for the sealed blob
        #[arg(long)]
        out: PathBuf,
    },
    /// Unseal a file (e.g., VMK) using a Private Key (Offline)
    Unseal {
        /// Path to the Unsealing Private Key
        #[arg(long)]
        priv_key: PathBuf,
        /// Path to the sealed blob to unseal
        #[arg(long)]
        sealed_data: PathBuf,
        /// Output path for the unsealed data
        #[arg(long)]
        out: PathBuf,
    },
    /// Management operations (requires stored token)
    Manage {
        #[arg(long, value_name = "URL")]
        url: Option<String>,
        #[arg(long, value_name = "PATH", default_value = DEFAULT_CA_CERT)]
        ca_cert: String,
        #[command(subcommand)]
        action: ManageCmd,
    },
    /// Configure stored management token
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    /// Store a management token
    Login {
        #[arg(long)]
        token: String,
        #[arg(long, value_name = "URL")]
        url: String,
        #[arg(long, value_name = "PATH")]
        ca_cert: String,
    },
    /// Remove stored token
    Logout,
}

#[derive(Subcommand, Debug)]
enum ManageCmd {
    List {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Show {
        id: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Enable {
        id: String,
    },
    Disable {
        id: String,
    },
    Delete {
        id: String,
    },
    Export {
        id: String,
        #[arg(long, value_parser = ["tar", "squash", "squashfs"], default_value = "tar")]
        format: String,
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
    },
    Create {
        #[arg(long)]
        os_name: String,
        #[arg(long)]
        service_url: String,
        #[arg(long, value_name = "PATH")]
        unsealing_private_key: PathBuf,
        #[arg(long, default_value = "4")]
        vcpus: u32,
        #[arg(long, default_value = "EPYC")]
        vcpu_type: String,
        #[arg(long, default_value_t = false)]
        allowed_debug: bool,
        #[arg(long, default_value_t = false)]
        allowed_migrate_ma: bool,
        #[arg(long, default_value_t = false)]
        allowed_smt: bool,
        #[arg(long, default_value = "0")]
        min_tcb_bootloader: u32,
        #[arg(long, default_value = "0")]
        min_tcb_tee: u32,
        #[arg(long, default_value = "0")]
        min_tcb_snp: u32,
        #[arg(long, default_value = "0")]
        min_tcb_microcode: u32,
        /// Optional artifacts bundle (.tar or .tar.gz)
        #[arg(long, value_name = "PATH")]
        artifacts_bundle: Option<PathBuf>,
        #[arg(long)]
        firmware: Option<PathBuf>,
        #[arg(long)]
        kernel: Option<PathBuf>,
        #[arg(long)]
        initrd: Option<PathBuf>,
        #[arg(long)]
        kernel_params: Option<String>,
        /// If set, disable the record after creation
        #[arg(long, default_value_t = false)]
        disable: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Attest {
            url,
            ca_cert,
            sealed_blob,
        } => run_attest(&url, &ca_cert, sealed_blob.as_deref()).await,
        Command::Manage {
            url,
            ca_cert,
            action,
        } => run_manage(url.as_deref(), &ca_cert, action).await,
        Command::Config { action } => run_config(action),
        Command::Keygen { priv_out, pub_out } => {
            local_ops::generate_keys(&priv_out, &pub_out)?;
            Ok(())
        }
        Command::Seal { pub_key, data, out } => {
            local_ops::seal_file(&pub_key, &data, &out)?;
            Ok(())
        }
        Command::Unseal {
            priv_key,
            sealed_data,
            out,
        } => {
            local_ops::unseal_file(&priv_key, &sealed_data, &out)?;
            Ok(())
        }
    }
}

fn token_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("config.json"))
}

fn ca_dest_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("ca.pem"))
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct StoredConfig {
    token: Option<String>,
    url: Option<String>,
    ca_cert: Option<String>, // stored filename under config dir (e.g., ca.pem)
}

fn load_config() -> Result<StoredConfig> {
    let path = token_path()?;
    if !path.exists() {
        return Ok(StoredConfig::default());
    }
    let data = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config at {}", path.display()))?;
    let cfg: StoredConfig = serde_json::from_str(&data)
        .with_context(|| format!("Config file at {} is invalid JSON", path.display()))?;
    Ok(cfg)
}

fn save_config(cfg: &StoredConfig) -> Result<()> {
    let path = token_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let data = serde_json::to_string(cfg)?;
    fs::write(&path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn delete_config() -> Result<()> {
    let path = token_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    let ca_path = ca_dest_path()?;
    if ca_path.exists() {
        fs::remove_file(ca_path)?;
    }
    Ok(())
}

fn build_client(ca_cert_path: &str) -> Result<reqwest::Client> {
    let ca_pem = fs::read(ca_cert_path)
        .with_context(|| format!("Failed to read pinned CA certificate at {}", ca_cert_path))?;
    build_client_from_bytes(&ca_pem)
}

fn build_client_from_bytes(ca_pem: &[u8]) -> Result<reqwest::Client> {
    let ca_cert =
        Certificate::from_pem(ca_pem).context("Pinned CA certificate is not valid PEM")?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca_cert)
        .build()
        .context("Failed to create HTTP client with pinned CA")?;
    Ok(client)
}

async fn run_attest(url: &str, ca_cert: &str, sealed_blob: Option<&Path>) -> Result<()> {
    let client = build_client(ca_cert)?;
    let base = normalize_https(url)?;
    let mut rng = OsRng;

    // 1. Get server nonce
    let mut buf = Vec::new();
    NonceRequest {}.encode(&mut buf)?;
    let resp = client
        .post(format!("{}/v1/attest/nonce", base))
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await
        .context("Failed to request nonce")?;
    let resp = ensure_success(resp, "nonce").await?;
    let bytes = resp.bytes().await?;
    let nonce_resp = NonceResponse::decode(&bytes[..]).context("Decode nonce response")?;
    if nonce_resp.nonce.len() != 64 {
        bail!("Invalid nonce length: {}", nonce_resp.nonce.len());
    }
    let server_nonce = nonce_resp.nonce;

    // 2. Generate ephemeral session key (X25519)
    let (client_secret, client_public) = <X25519HkdfSha256 as Kem>::gen_keypair(&mut rng);
    let client_pub_bytes = client_public.to_bytes().to_vec();

    // 3. Create binding hash: SHA512(server_nonce || client_pub_bytes)
    let mut hasher = Sha512::new();
    hasher.update(&server_nonce);
    hasher.update(&client_pub_bytes);
    let binding_digest: [u8; 64] = hasher.finalize().into();

    // 4. Get AMD SNP report with binding digest in report_data
    let mut fw = Firmware::open().context(
        "Failed to open SEV firmware device (/dev/sev-guest). Ensure SEV-SNP is enabled.",
    )?;
    let report_bytes = fw
        .get_report(None, Some(binding_digest), Some(0))
        .context("Failed to get attestation report from SEV firmware")?;

    // report_bytes is [u8; 1184], convert to Vec<u8>
    let report_data = report_bytes.to_vec();

    // 5. Read sealed blob (required)
    let sealed_blob_path =
        sealed_blob.ok_or_else(|| anyhow!("--sealed-blob is required for attestation"))?;
    let sealed_blob_data = fs::read(sealed_blob_path)
        .with_context(|| format!("Failed to read sealed blob from {:?}", sealed_blob_path))?;

    // 6. Send attestation request
    let mut req_bytes = Vec::new();
    AttestationRequest {
        report_data,
        server_nonce: server_nonce.clone(),
        client_pub_bytes: client_pub_bytes.clone(),
        sealed_blob: sealed_blob_data,
    }
    .encode(&mut req_bytes)?;

    let resp = client
        .post(format!("{}/v1/attest/report", base))
        .header("Content-Type", "application/x-protobuf")
        .body(req_bytes)
        .send()
        .await
        .context("Failed to verify report")?;
    let resp = ensure_success(resp, "verify").await?;
    let bytes = resp.bytes().await?;
    let verify_resp =
        AttestationResponse::decode(&bytes[..]).context("Decode verification response")?;

    if !verify_resp.success {
        bail!("Attestation failed: {}", verify_resp.error_message);
    }

    // 7. Decrypt session response (HPKE)
    // 7a. Parse server's encapped key
    let encapped = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&verify_resp.encapped_key)
        .map_err(|_| anyhow!("Invalid server encapped key"))?;

    // 7b. Setup HPKE receiver
    let mut receiver_ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &client_secret,
        &encapped,
        &[],
    )
    .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

    // 7c. Open ciphertext to get VMK
    let vmk = receiver_ctx
        .open(&verify_resp.ciphertext, &[])
        .map_err(|e| anyhow!("Session decryption failed: {}", e))?;

    // 8. Output VMK to stdout
    std::io::stdout().write_all(&vmk)?;
    std::io::stdout().flush()?;
    Ok(())
}

async fn run_manage(url: Option<&str>, ca_cert: &str, action: ManageCmd) -> Result<()> {
    let cfg = load_config()?;
    let token = cfg
        .token
        .clone()
        .ok_or_else(|| anyhow!("Token not found; run config login"))?;
    let base = if let Some(u) = url {
        normalize_https(u)?
    } else if let Some(u) = cfg.url {
        u
    } else {
        bail!("URL not provided and not stored; pass --url or login with a URL")
    };
    let ca_path = if let Some(stored) = cfg.ca_cert {
        config_dir()
            .unwrap_or_default()
            .join("snpguard")
            .join(stored)
            .to_string_lossy()
            .to_string()
    } else {
        ca_cert.to_string()
    };
    let client = build_client(&ca_path)?;
    match action {
        ManageCmd::List { json } => {
            let resp = client
                .get(format!("{}/v1/records", base))
                .bearer_auth(&token)
                .send()
                .await?;
            let resp = ensure_success(resp, "list").await?;
            let bytes = resp.bytes().await?;
            let list = ListRecordsResponse::decode(&bytes[..])?;
            print_list(list.records, json)?;
        }
        ManageCmd::Show { id, json } => {
            let resp = client
                .get(format!("{}/v1/records/{}", base, id))
                .bearer_auth(&token)
                .send()
                .await?;
            let resp = ensure_success(resp, "show").await?;
            let bytes = resp.bytes().await?;
            let rec = GetRecordResponse::decode(&bytes[..])?;
            if let Some(r) = rec.record {
                print_record(&r, json)?;
            } else {
                println!("Record not found");
            }
        }
        ManageCmd::Enable { id } => toggle(&client, &base, &token, &id, true).await?,
        ManageCmd::Disable { id } => toggle(&client, &base, &token, &id, false).await?,
        ManageCmd::Delete { id } => {
            let resp = client
                .delete(format!("{}/v1/records/{}", base, id))
                .bearer_auth(&token)
                .send()
                .await?;
            let resp = ensure_success(resp, "delete").await?;
            let bytes = resp.bytes().await?;
            let _ = DeleteRecordResponse::decode(&bytes[..])?;
        }
        ManageCmd::Export { id, format, out } => {
            let endpoint = match format.as_str() {
                "tar" => "export/tar",
                "squash" | "squashfs" => "export/squash",
                _ => unreachable!(),
            };
            let resp = client
                .get(format!("{}/v1/records/{}/{}", base, id, endpoint))
                .bearer_auth(&token)
                .send()
                .await?;
            let resp = ensure_success(resp, "export").await?;
            let bytes = resp.bytes().await?;
            fs::write(&out, &bytes)?;
        }
        ManageCmd::Create {
            os_name,
            service_url,
            unsealing_private_key,
            vcpus,
            vcpu_type,
            allowed_debug,
            allowed_migrate_ma,
            allowed_smt,
            min_tcb_bootloader,
            min_tcb_tee,
            min_tcb_snp,
            min_tcb_microcode,
            artifacts_bundle,
            firmware,
            kernel,
            initrd,
            kernel_params,
            disable,
        } => {
            let mut firmware_data = None;
            let mut kernel_data = None;
            let mut initrd_data = None;
            let mut params = None;

            if let Some(bundle_path) = artifacts_bundle {
                let (fw, k, i, p) = read_bundle(&bundle_path)?;
                firmware_data = fw;
                kernel_data = k;
                initrd_data = i;
                params = p;
            }
            if let Some(path) = firmware {
                firmware_data = Some(fs::read(path)?);
            }
            if let Some(path) = kernel {
                kernel_data = Some(fs::read(path)?);
            }
            if let Some(path) = initrd {
                initrd_data = Some(fs::read(path)?);
            }
            if let Some(p) = kernel_params {
                params = Some(p);
            }

            if firmware_data.is_none() || kernel_data.is_none() || initrd_data.is_none() {
                bail!("firmware, kernel, and initrd are required (either in artifacts bundle or as --firmware/--kernel/--initrd)");
            }

            let params = params.unwrap_or_else(|| "console=ttyS0".to_string());

            // Read and parse unsealing private key (non-standard PEM format - raw 32-byte key wrapped in PEM)
            let unsealing_key_pem_str =
                fs::read_to_string(&unsealing_private_key).with_context(|| {
                    format!(
                        "Failed to read unsealing private key from {:?}",
                        unsealing_private_key
                    )
                })?;

            let unsealing_key_pem = pem::parse(&unsealing_key_pem_str)
                .context("Failed to parse unsealing private key PEM")?;
            if unsealing_key_pem.tag() != "PRIVATE KEY" {
                bail!("Invalid unsealing private key PEM tag (expected PRIVATE KEY)");
            }
            let unsealing_key_bytes: [u8; 32] = unsealing_key_pem
                .contents()
                .try_into()
                .map_err(|_| anyhow!("Invalid unsealing private key length (expected 32 bytes)"))?;

            // Fetch ingestion public key and encrypt unsealing key (32 bytes only)
            let ingestion_pub_pem = client
                .get(format!("{}/v1/keys/ingestion/public", base))
                .send()
                .await
                .context("Failed to fetch ingestion public key")?;
            let ingestion_pub_pem = ensure_success(ingestion_pub_pem, "get ingestion key").await?;
            let ingestion_pub_pem = ingestion_pub_pem
                .text()
                .await
                .context("Failed to read ingestion public key")?;

            let pub_pem_parsed = pem::parse(&ingestion_pub_pem)
                .context("Failed to parse ingestion public key PEM")?;
            if pub_pem_parsed.tag() != "PUBLIC KEY" {
                bail!("Invalid ingestion public key PEM tag");
            }
            let public_bytes: [u8; 32] = pub_pem_parsed
                .contents()
                .try_into()
                .map_err(|_| anyhow!("Invalid public key length"))?;

            let server_pub = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&public_bytes)
                .map_err(|e| anyhow!("Failed to create public key: {}", e))?;

            let mut rng = OsRng;
            let (encapped_key, mut sender_ctx) =
                hpke::setup_sender::<AesGcm256, HkdfSha256, X25519HkdfSha256, _>(
                    &OpModeS::Base,
                    &server_pub,
                    &[],
                    &mut rng,
                )
                .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

            let ciphertext = sender_ctx
                .seal(&unsealing_key_bytes, &[])
                .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

            let encapped_bytes = encapped_key.to_bytes();
            let mut unsealing_key_encrypted =
                Vec::with_capacity(encapped_bytes.len() + ciphertext.len());
            unsealing_key_encrypted.extend_from_slice(&encapped_bytes);
            unsealing_key_encrypted.extend_from_slice(&ciphertext);

            let req = CreateRecordRequest {
                os_name,
                firmware: firmware_data.unwrap_or_default(),
                kernel: kernel_data.unwrap_or_default(),
                initrd: initrd_data.unwrap_or_default(),
                kernel_params: params,
                service_url,
                unsealing_private_key_encrypted: unsealing_key_encrypted,
                vcpus,
                vcpu_type,
                allowed_debug,
                allowed_migrate_ma,
                allowed_smt,
                min_tcb_bootloader,
                min_tcb_tee,
                min_tcb_snp,
                min_tcb_microcode,
            };

            let mut buf = Vec::new();
            req.encode(&mut buf)?;
            let resp = client
                .post(format!("{}/v1/records", base))
                .bearer_auth(&token)
                .header("Content-Type", "application/x-protobuf")
                .body(buf)
                .send()
                .await?;
            let resp = ensure_success(resp, "create").await?;
            let bytes = resp.bytes().await?;
            let created = CreateRecordResponse::decode(&bytes[..])?;
            if let Some(err) = created.error_message {
                bail!("create failed: {}", err);
            }
            let id = created.id;
            if id.is_empty() {
                bail!("create failed: empty id returned");
            }
            if disable {
                toggle(&client, &base, &token, &id, false).await?;
            }
            println!("{id}");
        }
    }
    Ok(())
}

type BundleContents = (
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
);

#[allow(clippy::type_complexity)]
fn read_bundle(path: &Path) -> Result<BundleContents> {
    let file = File::open(path)?;
    let is_gz = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.eq_ignore_ascii_case("gz"))
        .unwrap_or(false);
    let reader: Box<dyn Read> = if is_gz {
        Box::new(GzDecoder::new(file))
    } else {
        Box::new(file)
    };
    let mut archive = Archive::new(reader);

    let mut fw = None;
    let mut k = None;
    let mut i = None;
    let mut params = None;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = entry
            .path()?
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        match name.as_str() {
            "firmware-code.fd" => fw = Some(buf),
            "vmlinuz" => k = Some(buf),
            "initrd.img" => i = Some(buf),
            "kernel-params.txt" => {
                if let Ok(s) = String::from_utf8(buf) {
                    params = Some(s.trim().to_string());
                }
            }
            _ => {}
        }
    }

    Ok((fw, k, i, params))
}

fn run_config(action: ConfigCmd) -> Result<()> {
    match action {
        ConfigCmd::Login {
            token,
            url,
            ca_cert,
        } => {
            let mut cfg = load_config()?;
            let base = normalize_https(&url)?;
            let ca_dest = ca_dest_path()?;

            // Read CA from provided path
            let ca_bytes = fs::read(&ca_cert)
                .with_context(|| format!("Failed to read CA certificate from {}", ca_cert))?;

            // Validate token via health (management auth) using in-memory CA
            let client = build_client_from_bytes(&ca_bytes)?;
            let resp = futures::executor::block_on(
                client
                    .get(format!("{}/v1/health", base))
                    .bearer_auth(&token)
                    .send(),
            )
            .map_err(|e| anyhow!("Failed to contact server: {}", e))?;
            if resp.status().is_success() {
                // Only now persist CA to config dir with 0600 perms
                if let Some(parent) = ca_dest.parent() {
                    fs::create_dir_all(parent)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
                    }
                }
                fs::write(&ca_dest, &ca_bytes)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&ca_dest, fs::Permissions::from_mode(0o600))?;
                }

                cfg.token = Some(token);
                cfg.url = Some(base);
                cfg.ca_cert = Some("ca.pem".to_string());
                save_config(&cfg)?;
                println!("Successfully logged in, config stored");
            } else {
                println!("Failed to validate token: status {}", resp.status());
                std::process::exit(1);
            }
        }
        ConfigCmd::Logout => {
            delete_config()?;
            println!("Token removed");
        }
    }
    Ok(())
}

fn print_kv(key: &str, val: &str) {
    println!("{:<20}: {}", key, val);
}

fn print_record(r: &common::snpguard::AttestationRecord, json: bool) -> Result<()> {
    if json {
        #[derive(serde::Serialize)]
        struct JsonRecord<'a> {
            id: &'a str,
            os_name: &'a str,
            request_count: i32,
            enabled: bool,
            service_url: &'a str,
            kernel_params: &'a str,
            firmware_path: &'a str,
            kernel_path: &'a str,
            initrd_path: &'a str,
            vcpus: u32,
            vcpu_type: &'a str,
            allowed_debug: bool,
            allowed_migrate_ma: bool,
            allowed_smt: bool,
            min_tcb_bootloader: u32,
            min_tcb_tee: u32,
            min_tcb_snp: u32,
            min_tcb_microcode: u32,
            image_id: String,
            created_at: &'a str,
        }
        let jr = JsonRecord {
            id: &r.id,
            os_name: &r.os_name,
            request_count: r.request_count,
            enabled: r.enabled,
            service_url: &r.service_url,
            kernel_params: &r.kernel_params,
            firmware_path: &r.firmware_path,
            kernel_path: &r.kernel_path,
            initrd_path: &r.initrd_path,
            vcpus: r.vcpus,
            vcpu_type: &r.vcpu_type,
            allowed_debug: r.allowed_debug,
            allowed_migrate_ma: r.allowed_migrate_ma,
            allowed_smt: r.allowed_smt,
            min_tcb_bootloader: r.min_tcb_bootloader,
            min_tcb_tee: r.min_tcb_tee,
            min_tcb_snp: r.min_tcb_snp,
            min_tcb_microcode: r.min_tcb_microcode,
            image_id: hex::encode(&r.image_id),
            created_at: &r.created_at,
        };
        let val = serde_json::to_string_pretty(&jr)?;
        println!("{}", val);
    } else {
        print_kv("ID", &r.id);
        print_kv("OS Name", &r.os_name);
        print_kv("Requests", &r.request_count.to_string());
        print_kv("Status", if r.enabled { "enabled" } else { "disabled" });
        print_kv("Service URL", &r.service_url);
        print_kv("Kernel Params", &r.kernel_params);
        print_kv("Firmware Path", &r.firmware_path);
        print_kv("Kernel Path", &r.kernel_path);
        print_kv("Initrd Path", &r.initrd_path);
        print_kv("vCPUs", &r.vcpus.to_string());
        print_kv("vCPU Type", &r.vcpu_type);
        print_kv("Allowed Debug", &r.allowed_debug.to_string());
        print_kv("Allowed Migrate MA", &r.allowed_migrate_ma.to_string());
        print_kv("Allowed SMT", &r.allowed_smt.to_string());
        print_kv("Min TCB Bootloader", &r.min_tcb_bootloader.to_string());
        print_kv("Min TCB TEE", &r.min_tcb_tee.to_string());
        print_kv("Min TCB SNP", &r.min_tcb_snp.to_string());
        print_kv("Min TCB Microcode", &r.min_tcb_microcode.to_string());
        print_kv("Image ID", &hex::encode(&r.image_id));
        print_kv("Created At", &r.created_at);
    }
    Ok(())
}

fn print_list(records: Vec<common::snpguard::AttestationRecord>, json: bool) -> Result<()> {
    if json {
        #[derive(serde::Serialize)]
        struct JsonRec<'a> {
            id: &'a str,
            os_name: &'a str,
            request_count: i32,
            enabled: bool,
        }
        let out: Vec<JsonRec> = records
            .iter()
            .map(|r| JsonRec {
                id: &r.id,
                os_name: &r.os_name,
                request_count: r.request_count,
                enabled: r.enabled,
            })
            .collect();
        let val = serde_json::to_string_pretty(&out)?;
        println!("{}", val);
    } else {
        println!(
            "{:<36}  {:<24}  {:>8}  {:<8}",
            "ID", "OS NAME", "REQUESTS", "STATUS"
        );
        for r in records {
            let status = if r.enabled { "enabled" } else { "disabled" };
            println!(
                "{:<36}  {:<24}  {:>8}  {:<8}",
                r.id, r.os_name, r.request_count, status
            );
        }
    }
    Ok(())
}
async fn toggle(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    id: &str,
    enable: bool,
) -> Result<()> {
    let endpoint = if enable { "enable" } else { "disable" };
    let resp = client
        .post(format!("{}/v1/records/{}/{}", base, id, endpoint))
        .bearer_auth(token)
        .send()
        .await?;
    let resp = ensure_success(resp, "toggle").await?;
    let bytes = resp.bytes().await?;
    let _ = ToggleEnabledResponse::decode(&bytes[..])?;
    Ok(())
}

async fn ensure_success(resp: reqwest::Response, op: &str) -> Result<reqwest::Response> {
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("{} failed: {} {}", op, status, body);
    }
    Ok(resp)
}

fn normalize_https(url: &str) -> Result<String> {
    let u = if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };
    if !u.starts_with("https://") {
        bail!("URL must use HTTPS");
    }
    Ok(u.trim_end_matches('/').to_string())
}
