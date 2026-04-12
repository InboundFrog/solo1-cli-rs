/// Top-level commands: version, genkey, sign, mergehex, ls.
use std::path::{Path, PathBuf};

use crate::crypto::{generate_keypair, load_signing_key, sign_firmware};
use crate::device::list_solo_devices;
use crate::error::Result;
use crate::firmware::{
    create_firmware_json, firmware_bytes_to_sign, merge_hex_files, parse_hex_file,
};

/// Print the library version.
pub fn cmd_version() {
    println!("solo1-cli-rs {}", env!("CARGO_PKG_VERSION"));
}

/// Generate an ECDSA P-256 keypair.
/// Writes the private key to `output` (or stdout) and prints the public key.
pub fn cmd_genkey(output: Option<&Path>, entropy_file: Option<&Path>) -> Result<()> {
    // Optionally seed additional entropy (informational; ring/p256 use OS RNG)
    if let Some(entropy_path) = entropy_file {
        eprintln!(
            "Note: additional entropy from {:?} is not directly injectable into the OS RNG; \
             the OS RNG is used regardless.",
            entropy_path
        );
    }

    let (priv_pem, pub_pem) = generate_keypair()?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &priv_pem)?;
        eprintln!("Private key written to {:?}", out_path);
    } else {
        print!("{}", priv_pem);
    }

    eprintln!("Public key:\n{}", pub_pem);
    Ok(())
}

/// Sign a firmware hex file with the given key.
/// Outputs JSON {firmware, signature} to stdout.
pub fn cmd_sign(key_path: &Path, firmware_hex: &Path) -> Result<()> {
    let signing_key = load_signing_key(key_path)?;
    let firmware_bytes = firmware_bytes_to_sign(firmware_hex)?;
    let sig_bytes = sign_firmware(&signing_key, &firmware_bytes)?;

    // Read the full hex binary for the firmware field
    let (_, full_bytes) = parse_hex_file(firmware_hex)?;

    let fw_json = create_firmware_json(&full_bytes, &sig_bytes);
    println!("{}", fw_json.to_json()?);
    Ok(())
}

/// Merge Intel HEX files into a single output.
pub fn cmd_mergehex(
    inputs: &[PathBuf],
    output: &Path,
    attestation_key: Option<&Path>,
    attestation_cert: Option<&Path>,
) -> Result<()> {
    let input_refs: Vec<&Path> = inputs.iter().map(|p| p.as_path()).collect();
    merge_hex_files(&input_refs, output, attestation_key, attestation_cert)?;
    println!("Merged {} files into {:?}", inputs.len(), output);
    Ok(())
}

/// List connected Solo devices.
pub fn cmd_ls() -> Result<()> {
    let devices = list_solo_devices()?;
    if devices.is_empty() {
        println!("No Solo devices found.");
    } else {
        println!("Found {} Solo device(s):", devices.len());
        for dev in &devices {
            println!(
                "  Path: {}  Serial: {}  Product: {}",
                dev.path,
                dev.serial.as_deref().unwrap_or("(none)"),
                dev.product.as_deref().unwrap_or("(unknown)")
            );
        }
    }
    Ok(())
}
