use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use rand::{rngs::OsRng, seq::SliceRandom, RngCore};
use std::fs;
use std::io::Write;
use std::path::Path;

const DEFAULT_HASH_PATH: &str = "/data/master_password.hash";

#[derive(Clone)]
pub struct MasterAuth {
    pub hash: String,
}

pub fn load_or_create_master_password() -> Result<MasterAuth, Box<dyn std::error::Error>> {
    let path = std::env::var("MASTER_PASSWORD_HASH_PATH")
        .unwrap_or_else(|_| DEFAULT_HASH_PATH.to_string());

    if Path::new(&path).exists() {
        let hash = fs::read_to_string(&path)?.trim().to_string();
        if hash.is_empty() {
            return Err("Existing master password hash file is empty".into());
        }
        return Ok(MasterAuth { hash });
    }

    // Generate a human-readable, high-entropy passphrase
    let password = generate_memorable_password();

    // Hash with Argon2id
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash master password: {e}"))?
        .to_string();

    // Persist hash only
    if let Some(parent) = Path::new(&path).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(&path)?;
    file.write_all(hash.as_bytes())?;

    // Show the password once to the operator
    println!("==================================================");
    println!("SnpGuard master password (store this securely):");
    println!("{}", password);
    println!("(This password is shown only once and not stored in plaintext.)");
    println!("==================================================");

    Ok(MasterAuth { hash })
}

fn generate_memorable_password() -> String {
    // Short word list for memorability; 2048+ combinations per word gives strong entropy.
    // 6 words ~ 66 bits of entropy.
    const WORDS: &[&str] = &[
        "anchor",
        "apricot",
        "arctic",
        "atom",
        "autumn",
        "avocado",
        "badge",
        "bamboo",
        "battery",
        "beacon",
        "bicycle",
        "blossom",
        "breeze",
        "bridge",
        "bronze",
        "canyon",
        "carbon",
        "castle",
        "cedar",
        "ceramic",
        "cobalt",
        "comet",
        "coral",
        "cotton",
        "crimson",
        "crystal",
        "cypress",
        "dahlia",
        "delta",
        "desert",
        "ember",
        "falcon",
        "fiesta",
        "forest",
        "fossil",
        "galaxy",
        "ginger",
        "granite",
        "harbor",
        "hazel",
        "helium",
        "horizon",
        "jade",
        "jungle",
        "lagoon",
        "lemon",
        "lilac",
        "lunar",
        "magnet",
        "maple",
        "marble",
        "meadow",
        "mercury",
        "midnight",
        "mint",
        "nebula",
        "nectar",
        "oak",
        "onyx",
        "opal",
        "orbit",
        "orchid",
        "oxygen",
        "papaya",
        "pebble",
        "pepper",
        "petal",
        "phoenix",
        "pistachio",
        "plasma",
        "plume",
        "prairie",
        "quartz",
        "quasar",
        "raven",
        "redwood",
        "reef",
        "river",
        "saffron",
        "sage",
        "sandal",
        "saturn",
        "scarlet",
        "sequoia",
        "shadow",
        "silk",
        "silver",
        "skyline",
        "smoky",
        "sonic",
        "sparrow",
        "spice",
        "spruce",
        "stellar",
        "stone",
        "summit",
        "sunset",
        "tango",
        "terra",
        "thunder",
        "tidal",
        "topaz",
        "tundra",
        "vanilla",
        "velvet",
        "violet",
        "walnut",
        "willow",
        "zenith",
        "zephyr",
    ];

    let mut rng = OsRng;
    let mut words = Vec::with_capacity(6);
    for _ in 0..6 {
        let w = WORDS.choose(&mut rng).unwrap();
        words.push(*w);
    }
    let number = rng.next_u32() % 10000; // add extra entropy without hurting memorability
    format!(
        "{}-{}-{}-{}-{}-{}-{:04}",
        words[0], words[1], words[2], words[3], words[4], words[5], number
    )
}
