use anyhow::{Context, Result};
use cpio::newc::ModeFileType;
use cpio::{write_cpio, NewcBuilder};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use std::io::{Cursor, Read, Write};
use std::path::PathBuf;
use zstd::stream::read::Decoder as ZstdDecoder;
use zstd::stream::write::Encoder as ZstdEncoder;

const STACK_DECOMPRESSED: bool = false;

#[derive(Debug, Clone, Copy, PartialEq)]
enum CompressionFormat {
    Gzip,
    Zstd,
}

fn detect_format(bytes: &[u8]) -> Result<CompressionFormat> {
    if bytes.len() >= 2 && bytes[0..2] == [0x1f, 0x8b] {
        Ok(CompressionFormat::Gzip)
    } else if bytes.len() >= 4 && bytes[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
        Ok(CompressionFormat::Zstd)
    } else {
        anyhow::bail!("Unknown compression format")
    }
}

/// Appends snpguard-client and configuration files to the original
/// initrd. Returns a concatenated buffer of both initrds (the
/// original and the new one) as a Vec<u8>.
pub fn repack_initrd(
    orig_initrd: &[u8],
    attest_url: &[u8],
    ca_pem: &[u8],
    sealed_vmk: &[u8],
) -> Result<Vec<u8>> {
    println!("Append SnpGuard components to initrd...");

    let mut format = CompressionFormat::Gzip;
    let (cpio_buffer, compressed_buffer) = if STACK_DECOMPRESSED {
        // Detect compression and decompress
        let mut decompressed = Vec::new();
        format = detect_format(orig_initrd)?;
        match format {
            CompressionFormat::Gzip => {
                let mut decoder = GzDecoder::new(orig_initrd);
                decoder
                    .read_to_end(&mut decompressed)
                    .context("Failed to decompress Gzip")?;
            }
            CompressionFormat::Zstd => {
                let mut decoder =
                    ZstdDecoder::new(orig_initrd).context("Failed to create Zstd decoder")?;
                decoder
                    .read_to_end(&mut decompressed)
                    .context("Failed to decompress Zstd")?;
            }
        }

        // Initial CPIO buffer includes original decompressed initrd,
        // compressed buffer is empty
        (decompressed, Vec::new())
    } else {
        // Initial CPIO buffer is empty, compressed buffer includes original initrd
        (Vec::new(), Vec::from(orig_initrd))
    };

    // Read snpguard-client binary
    let client_bin_path = PathBuf::from("target/x86_64-unknown-linux-musl/release/snpguard-client");
    if !client_bin_path.exists() {
        anyhow::bail!(
            "snpguard-client binary not found at {:?}. Please build it first with: make build-client",
            client_bin_path
        );
    }
    let client_bin = std::fs::read(&client_bin_path)
        .with_context(|| format!("Failed to read client binary from {:?}", client_bin_path))?;

    // Set up our input files
    let mut input = vec![
        (
            NewcBuilder::new("usr")
                .mode(0o000755)
                .set_mode_file_type(ModeFileType::Directory),
            Cursor::new(vec![]),
        ),
        (
            NewcBuilder::new("usr/bin")
                .mode(0o000755)
                .set_mode_file_type(ModeFileType::Directory),
            Cursor::new(vec![]),
        ),
        (
            NewcBuilder::new("etc")
                .mode(0o000755)
                .set_mode_file_type(ModeFileType::Directory),
            Cursor::new(vec![]),
        ),
        (
            NewcBuilder::new("etc/snpguard")
                .mode(0o000755)
                .set_mode_file_type(ModeFileType::Directory),
            Cursor::new(vec![]),
        ),
        (
            NewcBuilder::new("usr/bin/snpguard-client").mode(0o100755),
            Cursor::new(client_bin),
        ),
        (
            NewcBuilder::new("etc/snpguard/vmk.sealed").mode(0o100644),
            Cursor::new(Vec::from(sealed_vmk)),
        ),
        (
            NewcBuilder::new("etc/snpguard/ca.pem").mode(0o100644),
            Cursor::new(Vec::from(ca_pem)),
        ),
        (
            NewcBuilder::new("etc/snpguard/attest.url").mode(0o100644),
            Cursor::new(Vec::from(attest_url)),
        ),
    ];

    // Set up output buffer
    let cpio_buffer_len = cpio_buffer.len();
    let mut final_cpio = Cursor::new(cpio_buffer);
    final_cpio.set_position(cpio_buffer_len as u64);

    // Write out the CPIO archive
    write_cpio(input.drain(..), &mut final_cpio).context("Failed to build CPIO archive")?;

    final_cpio
        .flush()
        .context("Failed to flush the CPIO buffer")?;

    let final_initrd = match format {
        CompressionFormat::Gzip => {
            let mut encoder = GzEncoder::new(compressed_buffer, GzCompression::default());
            encoder
                .write_all(&final_cpio.into_inner())
                .context("Failed to encode new CPIO archive with Gz")?;
            encoder
                .finish()
                .context("Failed to complete encoding of the new CPIO archive with Gz")?
        }
        CompressionFormat::Zstd => {
            let mut encoder =
                ZstdEncoder::new(compressed_buffer, 0).context("Failed to create Zstd encoder")?;
            encoder
                .write_all(&final_cpio.into_inner())
                .context("Failed to encode new CPIO archive with Zlib")?;
            encoder
                .finish()
                .context("Failed to complete encoding of the new CPIO archive with Zlib")?
        }
    };

    println!("Appended files to initrd successfully");
    Ok(final_initrd)
}
