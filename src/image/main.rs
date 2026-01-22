mod grub_parser;
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
use std::cell::RefCell;
use std::fs;
use std::io::{self, Write};
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
        /// Firmware path (required)
        #[arg(long)]
        firmware: PathBuf,
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
/// Returns the handle and the scratch/source/target rootfs device paths.
fn create_guestfs_context(
    source_path: &Path,
    target_path: &Path,
) -> Result<(guestfs::Handle, String, String, String)> {
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

    // Enable network
    g.set_network(true)
        .map_err(|e| anyhow!("Failed to setup network: {:?}", e))?;

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
    let scratch_rootfs = "/dev/disk/guestfs/rootfs";
    use guestfs::MkfsOptArgs;
    g.mkfs("ext4", scratch_rootfs, MkfsOptArgs::default())
        .map_err(|e| anyhow!("Failed to mkfs ext4 on /: {:?}", e))?;

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

    Ok((g, scratch_rootfs.to_string(), source_rootfs, target_rootfs))
}

/// Extracts kernel, initrd, and kernel parameters from target image using GRUB parser.
/// Returns (kernel_data, initrd_data, kernel_params)
fn extract_boot_data(
    g: &guestfs::Handle,
    scratch_rootfs: &str,
    target_rootfs: &str,
    vmk: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, String)> {
    use grub_parser::{parse_grub_cfg_from_str, GrubEntry};
    use guestfs::UmountOptArgs;

    println!("  Scratch rootfs: {}", scratch_rootfs);
    println!("  Target rootfs: {}", target_rootfs);

    // Convert VMK to string for LUKS
    let luks_key = hex::encode(vmk);

    g.luks_open(target_rootfs, &luks_key, "root_crypt")
        .map_err(|e| anyhow!("Failed to open LUKS: {:?}", e))?;
    defer! {
        if let Err(e) = g.luks_close("/dev/mapper/root_crypt") {
            println!("WARN: Failed to close LUKS: {:?}", e);
        }
    }

    // Mount scratch rootfs
    g.mount(scratch_rootfs, "/")
        .map_err(|e| anyhow!("Failed to mount {}: {:?}", scratch_rootfs, e))?;
    defer! {
        if let Err(e) = g.umount("/", UmountOptArgs::default()) {
            println!("WARN: Failed to umount {}: {:?}", "/", e);
        }
    }

    // Create /target mountpoint
    let target_mount = "/target";
    g.mkdir(target_mount)
        .map_err(|e| anyhow!("Failed to create {}: {:?}", target_mount, e))?;
    defer! {
        if let Err(e) = g.rmdir(target_mount) {
            println!("WARN: Failed to rmdir {}: {:?}", target_mount, e);
        }
    }

    // Mount target as /target
    g.mount_ro("/dev/mapper/root_crypt", target_mount)
        .map_err(|e| anyhow!("Failed to mount /dev/mapper/root_crypt: {:?}", e))?;
    defer! {
        if let Err(e) = g.umount(target_mount, UmountOptArgs::default()) {
            println!("WARN: Failed to umount {}: {:?}", target_mount, e);
        }
    }

    println!("  Mounted target rootfs to {}", target_mount);

    // Check for /boot partition or use root filesystem
    let mut grub_cfg_path = format!("{}/boot/grub/grub.cfg", target_mount);
    let mut boot_mount: Option<String> = None;
    let _guards = RefCell::new(Vec::<Box<dyn FnOnce() + '_>>::new());
    defer! {
        let mut guards = _guards.borrow_mut();
        while let Some(cleanup) = guards.pop() {
            cleanup();
        }
    };

    // First, check if grub.cfg exists in root filesystem's /boot
    use guestfs::IsFileOptArgs;
    let root_grub_exists = g
        .is_file(&grub_cfg_path, IsFileOptArgs::default())
        .map_err(|e| anyhow!("Failed to check if grub.cfg exists: {:?}", e))?;

    if !root_grub_exists {
        println!("  /boot/grub/grub.cfg not found in root filesystem");
        println!("  Checking for separate /boot partition...");

        // Try to find separate /boot partition
        let partitions = g
            .list_partitions()
            .map_err(|e| anyhow!("Failed to list partitions: {:?}", e))?;

        // Create /boot_check mountpoint
        let bootcheck_dir = "/boot_check";
        g.mkdir(bootcheck_dir)
            .map_err(|e| anyhow!("Failed to create {}: {:?}", bootcheck_dir, e))?;
        _guards.borrow_mut().push(Box::new(move || {
            if let Err(e) = g.rmdir(bootcheck_dir) {
                println!("WARN: Failed to rmdir {}: {:?}", bootcheck_dir, e);
            }
        }));

        for part in partitions {
            // Skip the target rootfs partition
            if part == target_rootfs {
                continue;
            }

            // Try to mount this partition and check if it contains grub.cfg
            if let Ok(()) = g.mount_ro(&part, bootcheck_dir) {
                _guards.borrow_mut().push(Box::new(move || {
                    if let Err(e) = g.umount(bootcheck_dir, UmountOptArgs::default()) {
                        println!("WARN: Failed to umount {}: {:?}", bootcheck_dir, e);
                    }
                }));
                let boot_check_grub = format!("{bootcheck_dir}/grub/grub.cfg");
                if g.is_file(boot_check_grub.as_str(), IsFileOptArgs::default())
                    .map_err(|e| anyhow!("Failed to check if file exists: {:?}", e))?
                {
                    println!("  Found /boot partition at: {}", part);
                    grub_cfg_path = boot_check_grub.to_string();
                    boot_mount = Some(bootcheck_dir.to_string());
                    break;
                }
            }
        }
        if boot_mount.is_none() {
            println!("  No separate /boot partition found with grub.cfg");
        }
    } else {
        println!("  Found /boot/grub/grub.cfg in root filesystem");
    }

    // Final check if grub.cfg exists (should have been found above, but double-check)
    if !g
        .is_file(&grub_cfg_path, IsFileOptArgs::default())
        .map_err(|e| anyhow!("Failed to check if grub.cfg exists: {:?}", e))?
    {
        bail!(
            "GRUB configuration file not found at: {}. Please ensure the target image has a valid GRUB installation.",
            grub_cfg_path
        );
    }

    println!("  Reading GRUB configuration from: {}", grub_cfg_path);

    // Read grub.cfg file
    let grub_content = g
        .read_file(&grub_cfg_path)
        .map_err(|e| anyhow!("Failed to read grub.cfg: {:?}", e))?;
    let grub_str = String::from_utf8(grub_content)
        .map_err(|e| anyhow!("Failed to convert grub.cfg to UTF-8: {}", e))?;

    // Parse GRUB configuration
    let entries = parse_grub_cfg_from_str(&grub_str)
        .map_err(|e| anyhow!("Failed to parse grub.cfg: {}", e))?;

    if entries.is_empty() {
        bail!("No GRUB menu entries found in grub.cfg. The file may be empty or malformed.");
    }

    println!(
        "  Found {} GRUB menu entr{}",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );

    let selected_entry: &GrubEntry = if entries.len() == 1 {
        // Single entry - use it automatically
        let entry = &entries[0];
        println!("  Using single menu entry:");
        println!("    Kernel: {}", entry.kernel);
        if let Some(ref initrd) = entry.initrd {
            println!("    Initrd: {}", initrd);
        } else {
            println!("    Initrd: (none)");
        }
        println!("    Parameters: {}", entry.params);
        entry
    } else {
        // Multiple entries - ask user to select
        println!("\n  Multiple GRUB menu entries found. Please select one:");
        for (idx, entry) in entries.iter().enumerate() {
            let default_marker = if entry.is_default { " (default)" } else { "" };
            println!("  [{}] Kernel: {}{}", idx, entry.kernel, default_marker);
            if let Some(ref initrd) = entry.initrd {
                println!("       Initrd: {}", initrd);
            }
            println!("       Parameters: {}", entry.params);
        }

        print!("\n  Enter entry number (0-{}): ", entries.len() - 1);
        io::stdout()
            .flush()
            .map_err(|e| anyhow!("Failed to flush stdout: {}", e))?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| anyhow!("Failed to read user input: {}", e))?;

        let selected_idx: usize = input
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid entry number: {}", input.trim()))?;

        if selected_idx >= entries.len() {
            bail!(
                "Entry number {} is out of range (0-{})",
                selected_idx,
                entries.len() - 1
            );
        }

        let entry = &entries[selected_idx];
        println!("\n  Selected entry {}:", selected_idx);
        println!("    Kernel: {}", entry.kernel);
        if let Some(ref initrd) = entry.initrd {
            println!("    Initrd: {}", initrd);
        } else {
            println!("    Initrd: (none)");
        }
        println!("    Parameters: {}", entry.params);
        entry
    };

    // Convert paths relative to target mount or boot partition
    // GRUB paths in grub.cfg are typically relative to the partition where grub.cfg is located
    let kernel_path = if selected_entry.kernel.starts_with('/') {
        // Absolute path - resolve based on where grub.cfg was found
        if let Some(ref boot_mnt) = boot_mount {
            // If boot is separate, absolute paths are relative to boot partition
            format!("{}{}", boot_mnt, selected_entry.kernel)
        } else {
            // Absolute paths are relative to root
            format!("{}{}", target_mount, selected_entry.kernel)
        }
    } else {
        // Relative path - assume it's relative to the partition containing grub.cfg
        if let Some(ref boot_mnt) = boot_mount {
            format!("{}/{}", boot_mnt, selected_entry.kernel)
        } else {
            format!("{}/boot/{}", target_mount, selected_entry.kernel)
        }
    };

    let initrd_path = selected_entry.initrd.as_ref().map(|initrd| {
        if initrd.starts_with('/') {
            if let Some(ref boot_mnt) = boot_mount {
                format!("{}{}", boot_mnt, initrd)
            } else {
                format!("{}{}", target_mount, initrd)
            }
        } else if let Some(ref boot_mnt) = boot_mount {
            format!("{}/{}", boot_mnt, initrd)
        } else {
            format!("{}/boot/{}", target_mount, initrd)
        }
    });

    // Read initrd from target image
    let initrd_path =
        initrd_path.ok_or_else(|| anyhow!("No initrd found in boot configuration"))?;
    let initrd_data = g
        .read_file(&initrd_path)
        .map_err(|e| anyhow!("Failed to read initrd from {}: {:?}", initrd_path, e))?;

    // Read kernel from target image
    let kernel_data = g
        .read_file(&kernel_path)
        .map_err(|e| anyhow!("Failed to read kernel from {}: {:?}", kernel_path, e))?;

    Ok((kernel_data, initrd_data, selected_entry.params.clone()))
}

fn encrypt_and_copy_rootfs(
    g: &guestfs::Handle,
    scratch_rootfs: &str,
    source_rootfs: &str,
    target_rootfs: &str,
    vmk: &[u8],
) -> Result<()> {
    use guestfs::{MkfsOptArgs, UmountOptArgs};
    // SURGERY on target
    g.wipefs(target_rootfs)
        .map_err(|e| anyhow!("Failed to wipefs on target: {:?}", e))?;

    // Convert VMK to string for LUKS
    let luks_key = hex::encode(vmk);

    g.luks_format(target_rootfs, &luks_key, 0)
        .map_err(|e| anyhow!("Failed to format LUKS: {:?}", e))?;
    g.luks_open(target_rootfs, &luks_key, "root_crypt")
        .map_err(|e| anyhow!("Failed to open LUKS: {:?}", e))?;
    defer! {
        if let Err(e) = g.luks_close("/dev/mapper/root_crypt") {
            println!("WARN: Failed to close LUKS: {:?}", e);
        }
    }

    // Format the inner filesystem
    g.mkfs("ext4", "/dev/mapper/root_crypt", MkfsOptArgs::default())
        .map_err(|e| anyhow!("Failed to mkfs ext4: {:?}", e))?;

    // Mount scratch rootfs
    g.mount(scratch_rootfs, "/")
        .map_err(|e| anyhow!("Failed to mount {}: {:?}", "/", e))?;
    defer! {
        if let Err(e) = g.umount("/", UmountOptArgs::default()) {
            println!("WARN: Failed to umount {}: {:?}", "/", e);
        }
    }

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
    defer! {
        if let Err(e) = g.umount(source_dir, UmountOptArgs::default()) {
            println!("WARN: Failed to umount {}: {:?}", source_dir, e);
        }
    }
    g.mount("/dev/mapper/root_crypt", target_dir)
        .map_err(|e| anyhow!("Failed to mount /dev/mapper/root_crypt: {:?}", e))?;
    defer! {
        if let Err(e) = g.umount(target_dir, UmountOptArgs::default()) {
            println!("WARN: Failed to umount {}: {:?}", target_dir, e);
        }
    }

    // Copy files
    println!("Copying files from source to encrypted target...");
    for entry in g
        .ls(source_dir)
        .map_err(|e| anyhow!("Failed to `ls {}`: {:?}", source_dir, e))?
    {
        let src = format!("{}/{}", source_dir, entry);
        g.cp_a(&src, target_dir)
            .map_err(|e| anyhow!("Failed to copy {}: {:?}", src, e))?;
    }

    Ok(())
}

/// Upload snpguard files and scripts into a guest image rootfs
pub fn upload_snpguard_files(
    g: &guestfs::Handle,
    snpguard_client_path: &str,
    ca_pem_path: &str,
    vmk_sealed_path: &str,
    attest_url: &str,
    hook_path: &str,
    local_top_path: &str,
) -> Result<()> {
    // Create directories
    g.mkdir_p("/etc/snpguard")
        .map_err(|e| anyhow!("Failed to mkdir /etc/snpguard: {:?}", e))?;

    // Upload snpguard binary
    g.upload(snpguard_client_path, "/usr/bin/snpguard-client")
        .map_err(|e| anyhow!("Failed to upload /usr/bin/snpguard-client: {:?}", e))?;
    g.chmod(0o755, "/usr/bin/snpguard-client")
        .map_err(|e| anyhow!("Failed to chmod /usr/bin/snpguard-client: {:?}", e))?;

    // Upload config files
    g.upload(ca_pem_path, "/etc/snpguard/ca.pem")
        .map_err(|e| anyhow!("Failed to upload /etc/snpguard/ca.pem: {:?}", e))?;
    g.upload(vmk_sealed_path, "/etc/snpguard/vmk.sealed")
        .map_err(|e| anyhow!("Failed to upload /etc/snpguard/vmk.sealed: {:?}", e))?;
    g.write("/etc/snpguard/attest.url", attest_url.as_bytes())
        .map_err(|e| anyhow!("Failed to write /etc/snpguard/attest.url: {:?}", e))?;

    // Upload initramfs hook script
    g.upload(hook_path, "/etc/initramfs-tools/hooks/snpguard")
        .map_err(|e| {
            anyhow!(
                "Failed to upload /etc/initramfs-tools/hooks/snpguard: {:?}",
                e
            )
        })?;
    g.chmod(0o755, "/etc/initramfs-tools/hooks/snpguard")
        .map_err(|e| {
            anyhow!(
                "Failed to chmod /etc/initramfs-tools/hooks/snpguard: {:?}",
                e
            )
        })?;

    // Upload local-top attestation script
    g.upload(
        local_top_path,
        "/etc/initramfs-tools/scripts/local-top/snpguard-attest",
    )
    .map_err(|e| {
        anyhow!(
            "Failed to upload /etc/initramfs-tools/scripts/local-top/snpguard-attest: {:?}",
            e
        )
    })?;

    g.chmod(
        0o755,
        "/etc/initramfs-tools/scripts/local-top/snpguard-attest",
    )
    .map_err(|e| {
        anyhow!(
            "Failed to chmod /etc/initramfs-tools/scripts/local-top/snpguard-attest: {:?}",
            e
        )
    })?;

    Ok(())
}

fn install_cryptsetup_on_target(
    g: &guestfs::Handle,
    target_rootfs: &str,
    vmk: &[u8],
    snpguard_client_path: &str,
    ca_pem_path: &str,
    vmk_sealed_path: &str,
    attest_url: &str,
    hook_path: &str,
    local_top_path: &str,
) -> Result<()> {
    enum DistroFamily {
        Debian,
        RedHat,
    }

    // Convert VMK to string for LUKS
    let luks_key = hex::encode(vmk);

    g.luks_open(target_rootfs, &luks_key, "root_crypt")
        .map_err(|e| anyhow!("Failed to open LUKS: {:?}", e))?;
    defer! {
        if let Err(e) = g.luks_close("/dev/mapper/root_crypt") {
            println!("WARN: Failed to close LUKS: {:?}", e);
        }
    }

    // Get distribution
    let dist = g
        .inspect_get_distro(target_rootfs)
        .map_err(|e| anyhow!("Failed to inspect distro on {}: {:?}", target_rootfs, e))?;

    let dist_family = match dist.as_str() {
        "debian" | "ubuntu" => DistroFamily::Debian,
        "fedora" | "centos" | "rhel" => DistroFamily::RedHat,
        _ => bail!("Unsupported distribution {}", dist),
    };

    // Mount target as /
    g.mount("/dev/mapper/root_crypt", "/")
        .map_err(|e| anyhow!("Failed to mount /dev/mapper/root_crypt: {:?}", e))?;
    defer! {
        if let Err(e) = g.umount_all() {
            println!("WARN: Failed to umount all: {:?}", e);
        }
    }

    // Map the package name and command
    let (install_cmds, update_initramfs_cmd) = match dist_family {
        DistroFamily::Debian => (
            vec![
                "dhclient eth0",                       // bring the whole network up
                "apt update -y",                       // update packages
                "apt install -y cryptsetup-initramfs", // install cryptsetup
                "pkill -KILL dhclient", // kill running dhclient, otherwise it holds /dev
            ],
            vec![
                "update-initramfs -u -k all", // update initramfs
            ],
        ),
        DistroFamily::RedHat => bail!("RedHat distributions are not supported at the moment"),
    };

    // Run install commands
    let cmd = install_cmds.join(";");
    g.sh(&format!("{}", cmd))
        .map_err(|e| anyhow!("Failed to execute '{}': {:?}", cmd, e))?;

    // Upload required files
    upload_snpguard_files(
        g,
        snpguard_client_path,
        ca_pem_path,
        vmk_sealed_path,
        attest_url,
        hook_path,
        local_top_path,
    )?;

    // Run update initramfs commands
    let cmd = update_initramfs_cmd.join(";");
    g.sh(&format!("{}", cmd))
        .map_err(|e| anyhow!("Failed to execute '{}': {:?}", cmd, e))?;

    Ok(())
}

fn run_convert(
    in_image: &Path,
    out_image: &Path,
    out_staging: &Path,
    attest_url: Option<String>,
    ingestion_public_key: Option<PathBuf>,
    ca_cert: Option<PathBuf>,
    firmware: PathBuf,
) -> Result<()> {
    // Load config if available
    let config = load_config().ok();

    // Resolve attest_url
    let _url = attest_url
        .clone()
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

    // Generate random 64-byte VMK
    println!("Generating Volume Master Key (VMK)...");
    let mut vmk = vec![0u8; 64];
    let mut rng = OsRng;
    rng.fill_bytes(&mut vmk);
    let vmk_path = out_staging.join("vmk.bin");
    fs::write(&vmk_path, &vmk)?;

    println!("Generating unsealing keypair...");
    let unsealing_priv_path = out_staging.join("unsealing.key");
    let unsealing_pub_path = out_staging.join("unsealing.pub");
    local_ops::generate_keys(&unsealing_priv_path, &unsealing_pub_path)?;

    println!("Sealing VMK with unsealing public key...");
    let sealed_vmk_file = out_staging.join("vmk.sealed");
    local_ops::seal_file(&unsealing_pub_path, &vmk_path, &sealed_vmk_file)?;

    // Remove unsealing public key (not needed after sealing)
    fs::remove_file(&unsealing_pub_path).context("Failed to remove unsealing public key")?;

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
    fs::write(&sealed_unsealing_key_path, &unsealing_key_encrypted)?;

    // Securely delete unencrypted unsealing private key
    println!("Securely deleting unencrypted unsealing private key...");
    secure_delete_file(&unsealing_priv_path)?;

    // Securely delete unencrypted VMK
    println!("Securely deleting unencrypted VMK...");
    secure_delete_file(&vmk_path)?;

    // Prepare data
    let attest_url_str = attest_url
        .or_else(|| config.as_ref().and_then(|c| c.url.clone()))
        .ok_or_else(|| {
            anyhow!(
                "Attestation URL not provided. Please run 'snpguard-client config login' first or provide --attest-url"
            )
        })?;

    println!("Copying the whole source image to target image...");
    fs::copy(in_image, out_image).with_context(|| {
        format!(
            "Failed to copy {} to {}",
            in_image.display(),
            out_image.display()
        )
    })?;

    println!("Preparing Guestfs context, launch appliance VM...");
    let (g, scratch_rootfs, source_rootfs, target_rootfs) =
        create_guestfs_context(in_image, out_image)?;

    println!("Encrypting root filesystem with LUKS2...");
    encrypt_and_copy_rootfs(&g, &scratch_rootfs, &source_rootfs, &target_rootfs, &vmk)?;

    let ca_cert_path = ca_cert_file
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 path: {:?}", ca_cert_file))?;
    let sealed_vmk_path = sealed_vmk_file
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 path: {:?}", sealed_vmk_file))?;

    println!("Install cryptsetup on target and update initrd...");
    install_cryptsetup_on_target(
        &g,
        &target_rootfs,
        &vmk,
        "target/x86_64-unknown-linux-musl/release/snpguard-client",
        ca_cert_path,
        sealed_vmk_path,
        &attest_url_str,
        "scripts/initramfs-tools/hook.sh",
        "scripts/initramfs-tools/attest.sh",
    )?;

    println!("Extract boot artifacts (kernel, initrd, params) from target image");
    let (kernel_data, initrd_data, kernel_params) =
        extract_boot_data(&g, &scratch_rootfs, &target_rootfs, &vmk)?;

    // Write artifacts to staging directory
    // Copy firmware (required)
    let firmware_dest = out_staging.join("firmware-code.fd");
    fs::copy(&firmware, &firmware_dest).with_context(|| {
        format!(
            "Failed to copy firmware from {:?} to {:?}",
            firmware, firmware_dest
        )
    })?;
    println!("  Copied firmware to firmware-code.fd");

    // Write extracted repacked initrd
    let initrd_dest = out_staging.join("initrd.img");
    fs::write(&initrd_dest, &initrd_data).context("Failed to write repacked initrd")?;
    println!("Wrote repacked initrd to initrd.img");

    // Write extracted kernel
    let kernel_dest = out_staging.join("vmlinuz");
    fs::write(&kernel_dest, &kernel_data).context("Failed to write kernel")?;
    println!("Wrote kernel to vmlinuz");

    // Write kernel params
    let params_dest = out_staging.join("kernel-params.txt");
    fs::write(&params_dest, &kernel_params).context("Failed to write kernel params")?;
    println!("Wrote kernel params to kernel-params.txt");

    // Mark staging as kept (don't cleanup on success)
    staging_guard.keep();

    println!("Image conversion completed successfully!");
    println!("  Output image: {:?}", out_image);
    println!("  Staging directory: {:?}", out_staging);
    println!("  Sealed VMK: {:?}", sealed_vmk_path);
    println!("  Sealed unsealing key: {:?}", sealed_unsealing_key_path);

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
            firmware,
        } => run_convert(
            &in_image,
            &out_image,
            &out_staging,
            attest_url,
            ingestion_public_key,
            ca_cert,
            firmware,
        ),
    }
}
