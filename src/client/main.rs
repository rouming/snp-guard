use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use common::snpguard::{
    AttestationRequest, AttestationResponse, CreateRecordRequest, CreateRecordResponse,
    DeleteRecordResponse, GetRecordResponse, ListRecordsResponse, NonceRequest, NonceResponse,
    ToggleEnabledResponse,
};
use dirs::config_dir;
use flate2::read::GzDecoder;
use prost::Message;
use reqwest::Certificate;
use sev::firmware::guest::Firmware;
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
enum Command {
    /// Perform attestation and output the released secret
    Attest {
        #[arg(long, value_name = "URL")]
        url: String,
        #[arg(long, value_name = "PATH", default_value = DEFAULT_CA_CERT)]
        ca_cert: String,
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
        #[arg(long)]
        secret: String,
        #[arg(long, default_value = "4")]
        vcpus: u32,
        #[arg(long, default_value = "EPYC")]
        vcpu_type: String,
        #[arg(long, value_name = "PATH")]
        id_key: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        auth_key: Option<PathBuf>,
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
        Command::Attest { url, ca_cert } => run_attest(&url, &ca_cert).await,
        Command::Manage {
            url,
            ca_cert,
            action,
        } => run_manage(url.as_deref(), &ca_cert, action).await,
        Command::Config { action } => run_config(action),
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

async fn run_attest(url: &str, ca_cert: &str) -> Result<()> {
    let client = build_client(ca_cert)?;
    let base = normalize_https(url)?;

    // 1. Get nonce
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

    // 2. Generate report
    let mut fw = Firmware::open().context(
        "Failed to open SEV firmware device (/dev/sev-guest). Ensure SEV-SNP is enabled.",
    )?;
    let mut nonce_arr = [0u8; 64];
    nonce_arr.copy_from_slice(&nonce_resp.nonce[..64]);
    let report_data = fw
        .get_report(None, Some(nonce_arr), Some(1))
        .context("Failed to get attestation report from SEV firmware")?;

    // 3. Verify
    let mut req_bytes = Vec::new();
    AttestationRequest { report_data }.encode(&mut req_bytes)?;
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
    if verify_resp.success {
        std::io::stdout().write_all(&verify_resp.secret)?;
        std::io::stdout().flush()?;
        Ok(())
    } else {
        bail!("Attestation failed: {}", verify_resp.error_message);
    }
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
            secret,
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
            id_key,
            auth_key,
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
            let mut id_key_data = None;
            let mut auth_key_data = None;

            if let Some(bundle_path) = artifacts_bundle {
                let (fw, k, i, p, idk, authk) = read_bundle(&bundle_path)?;
                firmware_data = fw;
                kernel_data = k;
                initrd_data = i;
                params = p;
                id_key_data = idk;
                auth_key_data = authk;
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
            if let Some(path) = id_key {
                id_key_data = Some(fs::read(path)?);
            }
            if let Some(path) = auth_key {
                auth_key_data = Some(fs::read(path)?);
            }

            if id_key_data.is_none() || auth_key_data.is_none() {
                bail!("id-key and auth-key are required (either in artifacts bundle or as --id-key/--auth-key)");
            }

            let params = params.unwrap_or_else(|| "console=ttyS0".to_string());

            let req = CreateRecordRequest {
                os_name,
                id_key: id_key_data.unwrap_or_default(),
                auth_key: auth_key_data.unwrap_or_default(),
                firmware: firmware_data.unwrap_or_default(),
                kernel: kernel_data.unwrap_or_default(),
                initrd: initrd_data.unwrap_or_default(),
                kernel_params: params,
                service_url,
                secret,
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

fn read_bundle(
    path: &Path,
) -> Result<(
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
)> {
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
    let mut idk = None;
    let mut authk = None;

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
            "id-block-key.pem" => idk = Some(buf),
            "id-auth-key.pem" => authk = Some(buf),
            _ => {}
        }
    }

    Ok((fw, k, i, params, idk, authk))
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
