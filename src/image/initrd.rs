use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use std::io::{Read, Write};
use std::path::PathBuf;
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

#[derive(Debug, Clone, Copy, PartialEq)]
enum CompressionFormat {
    Gzip,
    Zstd,
    Uncompressed,
}

fn detect_format(bytes: &[u8]) -> CompressionFormat {
    if bytes.len() >= 2 && bytes[0..2] == [0x1f, 0x8b] {
        CompressionFormat::Gzip
    } else if bytes.len() >= 4 && bytes[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        CompressionFormat::Zstd
    } else {
        CompressionFormat::Uncompressed
    }
}

/// Repacks initrd with snpguard-client and configuration files.
/// Returns the repacked initrd as Vec<u8>.
pub fn repack_initrd(
    original_bytes: &[u8],
    attest_url: &[u8],
    ca_pem: &[u8],
    sealed_vmk: &[u8],
) -> Result<Vec<u8>> {
    println!("Repacking initrd with SnpGuard components...");

    // 1. Detect Compression
    let format = detect_format(original_bytes);
    println!("  Detected initrd compression: {:?}", format);

    // 2. Decompress to raw CPIO bytes
    let mut decompressed_orig = Vec::new();
    match format {
        CompressionFormat::Gzip => {
            let mut decoder = GzDecoder::new(original_bytes);
            decoder
                .read_to_end(&mut decompressed_orig)
                .context("Failed to decompress Gzip")?;
        }
        CompressionFormat::Zstd => {
            let mut decoder =
                ZstdDecoder::new(original_bytes).context("Failed to create Zstd decoder")?;
            decoder
                .read_to_end(&mut decompressed_orig)
                .context("Failed to decompress Zstd")?;
        }
        CompressionFormat::Uncompressed => {
            decompressed_orig = original_bytes.to_vec();
        }
    }

    // 3. Load snpguard-client binary
    let client_bin_path = PathBuf::from("target/x86_64-unknown-linux-musl/release/snpguard-client");
    if !client_bin_path.exists() {
        anyhow::bail!(
            "snpguard-client binary not found at {:?}. Please build it first with: make build-client",
            client_bin_path
        );
    }
    let client_bin = std::fs::read(&client_bin_path)
        .with_context(|| format!("Failed to read client binary from {:?}", client_bin_path))?;

    // 4. Prepare the Output Buffer
    // We will write into this Vec via an Encoder
    let mut final_output_buffer = Vec::new();

    // 5. Create the specific Encoder based on format
    // We use a Box<dyn Write> so we can use the same logic for appending files regardless of compression
    {
        // Define the encoder wrapper
        let mut encoder: Box<dyn Write> = match format {
            CompressionFormat::Gzip => Box::new(GzEncoder::new(
                &mut final_output_buffer,
                GzCompression::default(),
            )),
            CompressionFormat::Zstd => {
                // Auto-level 0 is usually default. Explicit 3 is standard.
                Box::new(
                    ZstdEncoder::new(&mut final_output_buffer, 3)
                        .context("Failed to create Zstd encoder")?,
                )
            }
            CompressionFormat::Uncompressed => Box::new(&mut final_output_buffer),
        };

        // 6. Write the original CPIO content first
        // Note: This results in [Old Files][TRAILER!!!][New Files][TRAILER!!!]
        // The Linux Kernel happily accepts this "Concatenated CPIO" format.
        encoder
            .write_all(&decompressed_orig)
            .context("Failed to write original cpio")?;

        // 7. Append New Files using 'cpio' crate
        use cpio::newc::Builder;

        // Helper function to write a file to the CPIO archive
        use std::io::Write;
        let mut write_file = |name: &str, data: &[u8], mode: u32| -> Result<()> {
            let mut writer = Builder::new(name)
                .mode(mode)
                .write(&mut *encoder, data.len() as u32);
            writer
                .write_all(data)
                .context("Failed to write file data to CPIO")?;
            Ok(())
        };

        // Inject snpguard-client
        write_file("usr/bin/snpguard-client", &client_bin, 0o100755)
            .context("Failed to add snpguard-client")?;
        println!("    Added /usr/bin/snpguard-client");

        // Create /etc/snpguard directory structure
        // Note: cpio will create directories automatically when we write files in them

        // Inject sealed key
        write_file("etc/snpguard/vmk.sealed", sealed_vmk, 0o100644)
            .context("Failed to add sealed key")?;
        println!("    Added /etc/snpguard/vmk.sealed");

        // Inject CA
        write_file("etc/snpguard/ca.pem", ca_pem, 0o100644).context("Failed to add CA")?;
        println!("    Added /etc/snpguard/ca.pem");

        // Inject attestation URL
        write_file("etc/snpguard/attest.url", attest_url, 0o100644)
            .context("Failed to add attestation URL")?;
        println!("    Added /etc/snpguard/attest.url");

        // Write trailer (TRAILER!!! record)
        cpio::newc::trailer(&mut *encoder).context("Failed to write CPIO trailer")?;

        // Ensure the encoder finishes/flushes
        encoder.flush().context("Failed to flush encoder")?;

        // Specifically for Zstd/Gzip encoders, they usually need to finish/drop to write the footer.
        // Box<dyn Write> hides the specific `finish()` methods of encoders.
        // However, standard Drop implementations on the Encoders should handle finalization
        // when this block scope ends.
    }

    println!("  Repacked initrd successfully");
    Ok(final_output_buffer)
}
