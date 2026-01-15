use anyhow::{anyhow, Context, Result};
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{Kem, X25519HkdfSha256},
    Deserializable, OpModeS, Serializable,
};
use pem::{EncodeConfig, Pem};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

/// Generates an X25519 keypair and saves as standard PEM files.
pub fn generate_keys(priv_path: &Path, pub_path: &Path) -> Result<()> {
    let mut rng = OsRng;
    println!("Generating X25519 Unsealing Keypair...");

    // 1. Generate Keypair using HPKE's KEM
    let (priv_key, pub_key) = <X25519HkdfSha256 as Kem>::gen_keypair(&mut rng);

    // 2. Write Private Key (PEM format)
    let priv_bytes = priv_key.to_bytes();
    let priv_pem = Pem::new("PRIVATE KEY", priv_bytes.to_vec());
    let priv_pem_str = pem::encode_config(
        &priv_pem,
        EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    );

    fs::write(priv_path, priv_pem_str.as_bytes())
        .with_context(|| format!("Failed to write private key to {:?}", priv_path))?;

    // Set Permissions (Read-only for owner)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(priv_path)?.permissions();
        perms.set_mode(0o400);
        fs::set_permissions(priv_path, perms)?;
    }

    // 3. Write Public Key (PEM format)
    let pub_bytes = pub_key.to_bytes();
    let pub_pem = Pem::new("PUBLIC KEY", pub_bytes.to_vec());
    let pub_pem_str = pem::encode_config(
        &pub_pem,
        EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    );

    fs::write(pub_path, pub_pem_str.as_bytes())
        .with_context(|| format!("Failed to write public key to {:?}", pub_path))?;

    println!(
        "Keys generated:\n  Private: {:?}\n  Public:  {:?}",
        priv_path, pub_path
    );
    Ok(())
}

/// Seals a file using HPKE (X25519 + AES-GCM-256)
pub fn seal_file(pub_key_path: &Path, data_path: &Path, out_path: &Path) -> Result<()> {
    let mut rng = OsRng;

    // 1. Load Data
    let plaintext = fs::read(data_path)
        .with_context(|| format!("Failed to read data file: {:?}", data_path))?;

    let pub_pem_str = fs::read_to_string(pub_key_path)
        .with_context(|| format!("Failed to read public key: {:?}", pub_key_path))?;

    // 2. Parse Public Key (Standard PEM)
    let pub_pem = pem::parse(&pub_pem_str).map_err(|e| anyhow!("Invalid PEM format: {}", e))?;

    if pub_pem.tag() != "PUBLIC KEY" {
        return Err(anyhow!("Expected PUBLIC KEY, got {}", pub_pem.tag()));
    }

    let pub_bytes: [u8; 32] = pub_pem
        .contents()
        .try_into()
        .map_err(|_| anyhow!("Invalid public key length (expected 32 bytes)"))?;

    // Convert to HPKE-compatible key type
    let hpke_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(&pub_bytes)
        .map_err(|e| anyhow!("Key conversion failed: {}", e))?;

    // 3. Encrypt (HPKE Seal)
    let (encapped_key, mut sender_ctx) = hpke::setup_sender::<
        AesGcm256,
        HkdfSha256,
        X25519HkdfSha256,
        _,
    >(&OpModeS::Base, &hpke_key, &[], &mut rng)
    .map_err(|e| anyhow!("HPKE setup failed: {}", e))?;

    let ciphertext = sender_ctx
        .seal(&plaintext, &[])
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // 4. Serialize: [ Encapped_Key (32b) || Ciphertext ]
    let mut output = encapped_key.to_bytes().to_vec();
    output.extend_from_slice(&ciphertext);

    fs::write(out_path, &output)
        .with_context(|| format!("Failed to write output to {:?}", out_path))?;

    println!("Sealed {} bytes to {:?}", plaintext.len(), out_path);
    Ok(())
}
