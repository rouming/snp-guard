use rand::{rngs::OsRng, RngCore};
use ring::aead;
use std::fs;
use std::io::Write;
use std::path::Path;

const MASTER_KEY_SIZE: usize = 32; // AES-256

#[derive(Clone)]
pub struct MasterKey {
    key: [u8; MASTER_KEY_SIZE],
}

impl MasterKey {
    pub fn load_or_create(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if path.exists() {
            let key_bytes = fs::read(path)?;
            if key_bytes.len() != MASTER_KEY_SIZE {
                return Err(format!(
                    "Master key file has invalid size: expected {}, got {}",
                    MASTER_KEY_SIZE,
                    key_bytes.len()
                )
                .into());
            }
            let mut key = [0u8; MASTER_KEY_SIZE];
            key.copy_from_slice(&key_bytes);
            return Ok(MasterKey { key });
        }

        // Generate new master key
        let mut key = [0u8; MASTER_KEY_SIZE];
        OsRng.fill_bytes(&mut key);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }

        // Write key to file
        let mut file = fs::File::create(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
        }
        file.write_all(&key)?;
        file.sync_all()?;

        println!("Generated new master app key at: {}", path.display());
        println!("(This key is used to encrypt unsealing private keys)");

        Ok(MasterKey { key })
    }

    pub fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        // Generate a random nonce (12 bytes for AES-GCM)
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        // Create sealing key
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &self.key)
            .map_err(|e| format!("Failed to create encryption key: {:?}", e))?;
        let sealing_key = aead::LessSafeKey::new(unbound_key);

        // Encrypt
        let mut ciphertext = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut ciphertext)
            .map_err(|e| format!("Encryption failed: {:?}", e))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if nonce.len() != 12 {
            return Err("Nonce must be exactly 12 bytes".into());
        }

        let nonce = aead::Nonce::assume_unique_for_key(
            nonce.try_into().map_err(|_| "Invalid nonce length")?,
        );

        // Create opening key
        let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &self.key)
            .map_err(|e| format!("Failed to create decryption key: {:?}", e))?;
        let opening_key = aead::LessSafeKey::new(unbound_key);

        // Decrypt
        let mut plaintext = ciphertext.to_vec();
        let plaintext_len = opening_key
            .open_in_place(nonce, aead::Aad::empty(), &mut plaintext)
            .map_err(|e| format!("Decryption failed: {:?}", e))?
            .len();

        plaintext.truncate(plaintext_len);
        Ok(plaintext)
    }
}
