mod local_ops;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use dirs::config_dir;
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    Deserializable, OpModeS, Serializable,
};
use pem::parse as pem_parse;
use rand::{rngs::OsRng, RngCore};
use scopeguard::defer;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(author, version, about = "SnpGuard image tool")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
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
    /// Convert a QCOW2 image: encrypt rootfs with LUKS2 and seal keys
    Convert {
        /// Input QCOW2 image path
        #[arg(long)]
        in_image: PathBuf,
        /// Output QCOW2 image path
        #[arg(long)]
        out_image: PathBuf,
        /// Staging directory for temporary files
        #[arg(long)]
        out_staging: PathBuf,
        /// Optional: Override attestation URL (uses config if not provided)
        #[arg(long)]
        attest_url: Option<String>,
        /// Optional: Override ingestion public key path (uses config if not provided)
        #[arg(long)]
        ingestion_public_key: Option<PathBuf>,
        /// Optional: Override CA certificate path (uses config if not provided)
        #[arg(long)]
        ca_cert: Option<PathBuf>,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct StoredConfig {
    url: Option<String>,
}

fn config_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("config.json"))
}

fn ca_cert_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("ca.pem"))
}

fn ingestion_key_path() -> Result<PathBuf> {
    let base = config_dir().ok_or_else(|| anyhow!("Cannot determine config dir"))?;
    Ok(base.join("snpguard").join("ingestion.pub"))
}

fn load_config() -> Result<StoredConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(StoredConfig::default());
    }
    let data = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config at {}", path.display()))?;
    let cfg: StoredConfig = serde_json::from_str(&data)
        .with_context(|| format!("Config file at {} is invalid JSON", path.display()))?;
    Ok(cfg)
}

/// Securely delete a file by overwriting with random data
fn secure_delete_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(path)
        .with_context(|| format!("Failed to get file metadata: {}", path.display()))?;
    let file_size = metadata.len() as usize;

    if file_size == 0 {
        fs::remove_file(path)
            .with_context(|| format!("Failed to delete empty file: {}", path.display()))?;
        return Ok(());
    }

    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("Failed to stat {}", path.display()))?
        .permissions();

    if perms.mode() & 0o200 == 0 {
        // Add owner write bit (u+w) if missing
        perms.set_mode(perms.mode() | 0o200);

        fs::set_permissions(path, perms)
            .with_context(|| format!("Failed to chmod +w {}", path.display()))?;
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| {
            format!(
                "Failed to open file for secure deletion: {}",
                path.display()
            )
        })?;

    let mut rng = OsRng;
    let mut buffer = vec![0u8; file_size.min(64 * 1024)];
    let mut remaining = file_size;

    while remaining > 0 {
        let to_write = remaining.min(buffer.len());
        rng.fill_bytes(&mut buffer[..to_write]);
        file.write_all(&buffer[..to_write])
            .with_context(|| format!("Failed to overwrite file content: {}", path.display()))?;
        remaining -= to_write;
    }

    file.sync_all()
        .with_context(|| format!("Failed to sync file: {}", path.display()))?;
    drop(file);

    fs::remove_file(path)
        .with_context(|| format!("Failed to delete file after overwrite: {}", path.display()))?;
    Ok(())
}

/// Guard to ensure staging directory is cleaned up on error
struct StagingGuard {
    path: PathBuf,
    should_cleanup: bool,
}

impl StagingGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            should_cleanup: true,
        }
    }

    fn keep(&mut self) {
        self.should_cleanup = false;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.should_cleanup && self.path.exists() {
            if let Err(e) = fs::remove_dir_all(&self.path) {
                eprintln!(
                    "Warning: Failed to cleanup staging directory {:?}: {}",
                    self.path, e
                );
            }
        }
    }
}

/// Creates a guestfs context with scratch, source, and target drives attached and launched.
/// Returns the handle and the source/target rootfs device paths.
fn create_guestfs_context(
    source_path: &Path,
    target_path: &Path,
) -> Result<(guestfs::Handle, String, String)> {
    use guestfs::{AddDriveOptArgs, AddDriveScratchOptArgs, Handle};

    let g = Handle::create().map_err(|e| anyhow!("Failed to create guestfs handle: {:?}", e))?;

    // Add scratch drive for rootfs, this provides the physical space
    // and writable rootfs
    g.add_drive_scratch(
        10 * 1024 * 1024,
        AddDriveScratchOptArgs {
            label: Some("rootfs"),
            ..Default::default()
        },
    )
    .map_err(|e| anyhow!("Failed to add scratch drive: {:?}", e))?;

    // Add the SOURCE drive (read-only)
    g.add_drive(
        &source_path.to_string_lossy(),
        AddDriveOptArgs {
            label: Some("source"),
            readonly: Some(true),
            format: Some("qcow2"),
            ..Default::default()
        },
    )
    .map_err(|e| anyhow!("Failed to add source drive: {:?}", e))?;

    // Add the TARGET drive (read-write)
    g.add_drive(
        &target_path.to_string_lossy(),
        AddDriveOptArgs {
            label: Some("target"),
            readonly: Some(false),
            format: Some("qcow2"),
            ..Default::default()
        },
    )
    .map_err(|e| anyhow!("Failed to add target drive: {:?}", e))?;

    // Launch the VM
    g.launch()
        .map_err(|e| anyhow!("Failed to launch guestfs: {:?}", e))?;

    // Inspect source and target and find rootfs
    let roots = g
        .inspect_os()
        .map_err(|e| anyhow!("Failed to inspect OS: {:?}", e))?;
    if roots.len() != 2 {
        bail!("Two root filesystems are expected: one from a source and one from a target.");
    }

    // Prepare the scratch disk to be our writable rootfs
    let scratch_dev = "/dev/disk/guestfs/rootfs";
    use guestfs::MkfsOptArgs;
    g.mkfs("ext4", scratch_dev, MkfsOptArgs::default())
        .map_err(|e| anyhow!("Failed to mkfs ext4 on /: {:?}", e))?;
    g.mount(scratch_dev, "/")
        .map_err(|e| anyhow!("Failed to mount /: {:?}", e))?;

    // Find source and target rootfs
    let mut source_rootfs: Option<String> = None;
    let mut target_rootfs: Option<String> = None;

    let labels = g
        .list_disk_labels()
        .map_err(|e| anyhow!("Failed to list disk labels: {:?}", e))?;

    for (label, disk) in labels {
        if roots.contains(&disk) {
            if label.starts_with("source") {
                source_rootfs = Some(disk);
            } else if label.starts_with("target") {
                target_rootfs = Some(disk);
            }
        }
    }
    let source_rootfs = source_rootfs.ok_or_else(|| anyhow!("Source rootfs not found"))?;
    let target_rootfs = target_rootfs.ok_or_else(|| anyhow!("Target rootfs not found"))?;

    Ok((g, source_rootfs, target_rootfs))
}

fn encrypt_and_copy_rootfs(
    g: &guestfs::Handle,
    source_rootfs: &str,
    target_rootfs: &str,
    vmk: &[u8],
) -> Result<()> {
    // SURGERY on target
    g.wipefs(target_rootfs)
        .map_err(|e| anyhow!("Failed to wipefs on target: {:?}", e))?;

    // Convert VMK to string for LUKS
    let luks_key = hex::encode(vmk);

    g.luks_format(target_rootfs, &luks_key, 0)
        .map_err(|e| anyhow!("Failed to format LUKS: {:?}", e))?;
    g.luks_open(target_rootfs, &luks_key, "crypt_target_root")
        .map_err(|e| anyhow!("Failed to open LUKS: {:?}", e))?;
    defer! {
        if let Err(e) = g.luks_close("/dev/mapper/crypt_target_root") {
            println!("WARN: Failed to close LUKS: {:?}", e);
        }
    }

    // Format the inner filesystem
    use guestfs::MkfsOptArgs;
    g.mkfs(
        "ext4",
        "/dev/mapper/crypt_target_root",
        MkfsOptArgs::default(),
    )
    .map_err(|e| anyhow!("Failed to mkfs ext4: {:?}", e))?;

    // Create target and source mountpoints
    let source_dir = "/source";
    let target_dir = "/target";
    g.mkdir(source_dir)
        .map_err(|e| anyhow!("Failed to create {}: {:?}", source_dir, e))?;
    defer! {
        if let Err(e) = g.rmdir(source_dir) {
            println!("WARN: Failed to rmdir {}: {:?}", source_dir, e);
        }
    }
    g.mkdir(target_dir)
        .map_err(|e| anyhow!("Failed to create {}: {:?}", target_dir, e))?;
    defer! {
        if let Err(e) = g.rmdir(target_dir) {
            println!("WARN: Failed to rmdir {}: {:?}", target_dir, e);
        }
    }

    // Mount source and target
    g.mount_ro(source_rootfs, source_dir)
        .map_err(|e| anyhow!("Failed to mount {}: {:?}", source_rootfs, e))?;
    use guestfs::UmountOptArgs;
    defer! {
        if let Err(e) = g.umount(source_dir, UmountOptArgs::default()) {
            println!("WARN: Failed to umount {}: {:?}", source_dir, e);
        }
    }
    g.mount("/dev/mapper/crypt_target_root", target_dir)
        .map_err(|e| anyhow!("Failed to mount /dev/mapper/crypt_target_root: {:?}", e))?;
    defer! {
        if let Err(e) = g.umount(target_dir, UmountOptArgs::default()) {
            println!("WARN: Failed to umount {}: {:?}", target_dir, e);
        }
    }

    // Copy files
    println!("Copying files from source to encrypted target...");
    g.cp_a(source_dir, target_dir)
        .map_err(|e| anyhow!("Failed to copy files: {:?}", e))?;

    Ok(())
}

fn run_convert(
    in_image: &Path,
    out_image: &Path,
    out_staging: &Path,
    attest_url: Option<String>,
    ingestion_public_key: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
) -> Result<()> {
    // Load config if available
    let config = load_config().ok();

    // Resolve attest_url
    let _url = attest_url
        .or_else(|| config.as_ref().and_then(|c| c.url.clone()))
        .ok_or_else(|| {
            anyhow!(
                "Attestation URL not provided. Please run 'snpguard-client config login' first or provide --attest-url"
            )
        })?;

    // Resolve ingestion public key path
    let ingestion_key_file = ingestion_public_key
        .or_else(|| ingestion_key_path().ok())
        .ok_or_else(|| {
            anyhow!(
                "Ingestion public key not provided. Please run 'snpguard-client config login' first or provide --ingestion-public-key"
            )
        })?;

    if !ingestion_key_file.exists() {
        bail!(
            "Ingestion public key not found at {:?}. Please run 'snpguard-client config login' first or provide --ingestion-public-key",
            ingestion_key_file
        );
    }

    // Resolve CA cert path
    let ca_cert_file = ca_cert
        .or_else(|| ca_cert_path().ok())
        .ok_or_else(|| {
            anyhow!(
                "CA certificate not provided. Please run 'snpguard-client config login' first or provide --ca-cert"
            )
        })?;

    if !ca_cert_file.exists() {
        bail!(
            "CA certificate not found at {:?}. Please run 'snpguard-client config login' first or provide --ca-cert",
            ca_cert_file
        );
    }

    // Create staging directory
    if out_staging.exists() {
        bail!("Staging directory already exists: {:?}", out_staging);
    }
    fs::create_dir_all(out_staging)?;
    let mut staging_guard = StagingGuard::new(out_staging.to_path_buf());

    // Step 1: Generate random 64-byte VMK
    println!("Generating Volume Master Key (VMK)...");
    let mut vmk = vec![0u8; 64];
    let mut rng = OsRng;
    rng.fill_bytes(&mut vmk);
    let vmk_path = out_staging.join("vmk.bin");
    fs::write(&vmk_path, &vmk)?;

    // Step 2: Copy source to target
    println!("Copying source image to target...");
    fs::copy(in_image, out_image).with_context(|| {
        format!(
            "Failed to copy {} to {}",
            in_image.display(),
            out_image.display()
        )
    })?;

    // Step 3: Encrypt rootfs with LUKS2
    println!("Encrypting root filesystem with LUKS2...");
    let (g, source_rootfs, target_rootfs) = create_guestfs_context(in_image, out_image)?;
    encrypt_and_copy_rootfs(&g, &source_rootfs, &target_rootfs, &vmk)?;

    // Step 4: Generate unsealing keys
    println!("Generating unsealing keypair...");
    let unsealing_priv_path = out_staging.join("unsealing.key");
    let unsealing_pub_path = out_staging.join("unsealing.pub");
    local_ops::generate_keys(&unsealing_priv_path, &unsealing_pub_path)?;

    // Step 5: Seal VMK with unsealing public key
    println!("Sealing VMK with unsealing public key...");
    let sealed_vmk_path = out_staging.join("vmk.sealed");
    let sealed_vmk_path_clone = sealed_vmk_path.clone();
    local_ops::seal_file(&unsealing_pub_path, &vmk_path, &sealed_vmk_path)?;

    // Remove unsealing public key (not needed after sealing)
    fs::remove_file(&unsealing_pub_path).context("Failed to remove unsealing public key")?;

    // Step 6: Seal unsealing private key with ingestion public key
    println!("Sealing unsealing private key with ingestion public key...");

    // Load ingestion public key
    let ingestion_pub_pem_str = fs::read_to_string(&ingestion_key_file).with_context(|| {
        format!(
            "Failed to read ingestion public key from {:?}",
            ingestion_key_file
        )
    })?;

    let ingestion_pub_pem =
        pem_parse(&ingestion_pub_pem_str).context("Failed to parse ingestion public key PEM")?;

    if ingestion_pub_pem.tag() != "PUBLIC KEY" {
        bail!("Invalid ingestion public key PEM tag (expected PUBLIC KEY)");
    }

    let ingestion_pub_bytes: [u8; 32] = ingestion_pub_pem
        .contents()
        .try_into()
        .map_err(|_| anyhow!("Invalid ingestion public key length (expected 32 bytes)"))?;

    let server_pub = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&ingestion_pub_bytes)
        .map_err(|e| anyhow!("Failed to create ingestion public key: {}", e))?;

    // Load unsealing private key
    let unsealing_priv_pem_str =
        fs::read_to_string(&unsealing_priv_path).context("Failed to read unsealing private key")?;

    let unsealing_priv_pem =
        pem_parse(&unsealing_priv_pem_str).context("Failed to parse unsealing private key PEM")?;

    if unsealing_priv_pem.tag() != "PRIVATE KEY" {
        bail!("Invalid unsealing private key PEM tag (expected PRIVATE KEY)");
    }

    let unsealing_priv_bytes: [u8; 32] = unsealing_priv_pem
        .contents()
        .try_into()
        .map_err(|_| anyhow!("Invalid unsealing private key length (expected 32 bytes)"))?;

    // Encrypt with HPKE
    let mut rng = OsRng;
    let (encapped_key, mut sender_ctx) = hpke::setup_sender::<
        AesGcm256,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &server_pub, &[], &mut rng)
    .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

    let ciphertext = sender_ctx
        .seal(&unsealing_priv_bytes, &[])
        .map_err(|e| anyhow!("HPKE seal failed: {}", e))?;

    let encapped_bytes = encapped_key.to_bytes();
    let mut unsealing_key_encrypted = Vec::with_capacity(encapped_bytes.len() + ciphertext.len());
    unsealing_key_encrypted.extend_from_slice(&encapped_bytes);
    unsealing_key_encrypted.extend_from_slice(&ciphertext);

    // Save sealed unsealing key
    let sealed_unsealing_key_path = out_staging.join("unsealing.key.sealed");
    let sealed_unsealing_key_path_clone = sealed_unsealing_key_path.clone();
    fs::write(&sealed_unsealing_key_path, &unsealing_key_encrypted)?;

    // Securely delete unencrypted unsealing private key
    println!("Securely deleting unencrypted unsealing private key...");
    secure_delete_file(&unsealing_priv_path)?;

    // Securely delete unencrypted VMK
    println!("Securely deleting unencrypted VMK...");
    secure_delete_file(&vmk_path)?;

    // Mark staging as kept (don't cleanup on success)
    staging_guard.keep();

    println!("Image conversion completed successfully!");
    println!("  Output image: {:?}", out_image);
    println!("  Staging directory: {:?}", out_staging);
    println!("  Sealed VMK: {:?}", sealed_vmk_path_clone);
    println!(
        "  Sealed unsealing key: {:?}",
        sealed_unsealing_key_path_clone
    );

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
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
        Command::Convert {
            in_image,
            out_image,
            out_staging,
            attest_url,
            ingestion_public_key,
            ca_cert,
        } => run_convert(
            &in_image,
            &out_image,
            &out_staging,
            attest_url,
            ingestion_public_key,
            ca_cert,
        ),
    }
}
