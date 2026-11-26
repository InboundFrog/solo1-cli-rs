/// Top-level commands: version, genkey, sign, mergehex, ls.
use std::path::{Path, PathBuf};

use crate::error::Result;
use solo1::crypto::{generate_keypair, load_signing_key, sign_firmware};
use solo1::firmware::{create_firmware_json_versioned, firmware_bytes_to_sign_for_version, merge_hex_files};

/// Print the library version.
///
/// # Errors
/// Returns an error if serializing or writing the JSON output fails (JSON mode
/// only).
pub fn cmd_version(json: bool) -> Result<()> {
    if json {
        use crate::output::{CliVersionOutput, print_json};
        let out = CliVersionOutput {
            name: "solo1-cli-rs".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        };
        return print_json(&out);
    }
    println!("solo1-cli-rs {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}

/// Generate an ECDSA P-256 keypair.
/// Writes the private key to `output` (or stdout) and prints the public key.
///
/// # Errors
/// Returns an error if keypair generation fails, writing the private key file
/// fails, or JSON serialization fails.
pub fn cmd_genkey(output: Option<&Path>, json: bool) -> Result<()> {
    let (priv_pem, pub_pem) = generate_keypair()?;

    if json {
        use crate::output::{GenKeyOutput, print_json};
        let out = GenKeyOutput {
            private_key: priv_pem,
            public_key: pub_pem,
        };
        return print_json(&out);
    }

    if let Some(out_path) = output {
        write_private_key(out_path, &priv_pem)?;
        eprintln!("Private key written to {}", out_path.display());
    } else {
        print!("{priv_pem}");
    }

    eprintln!("Public key:\n{pub_pem}");
    Ok(())
}

/// Write the signing private key to a new file at `path` with mode 0o600.
///
/// An existing regular file or symbolic link at the path is removed first and
/// never written into, so a handle that another program opened earlier cannot
/// read the new key. Any other kind of existing path gives an error.
#[cfg(unix)]
fn write_private_key(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() || meta.file_type().is_symlink() => {
            // ponytail: the old file is removed before the new one is written, so a failed write loses the old key (truncating did too). Write a temporary file and rename it if the old key must survive.
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "output path exists and is not a regular file",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

/// Write the signing private key to `path` (non-Unix fallback).
#[cfg(not(unix))]
fn write_private_key(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// Sign a firmware hex file with the given key.
///
/// Generates two signatures for different bootloader versions (matching Python reference):
///   - v1: signed over region using `APPLICATION_END_PAGE=19` (bootloaders <=2.5.3)
///   - v2: signed over region using `APPLICATION_END_PAGE=20` (bootloaders >2.5.3)
///
/// The firmware field in the output JSON is the base64 of the HEX FILE TEXT,
/// not the binary, matching the Python reference implementation.
///
/// Outputs JSON {firmware, signature, versions} to stdout.
///
/// # Errors
/// Returns an error if the signing key cannot be loaded, the firmware hex
/// cannot be read or parsed, signing fails, or building or serializing the
/// output JSON fails.
pub fn cmd_sign(key_path: &Path, firmware_hex: &Path) -> Result<()> {
    let signing_key = load_signing_key(key_path)?;

    // Sign for v1 bootloaders (<=2.5.3) using app_end_page=19
    let bytes_v1 = firmware_bytes_to_sign_for_version(firmware_hex, 19)?;
    eprintln!("im_size (v1): {}", bytes_v1.len());
    let sig_v1 = sign_firmware(&signing_key, &bytes_v1)?;

    // Sign for v2 bootloaders (>2.5.3) using app_end_page=20
    let bytes_v2 = firmware_bytes_to_sign_for_version(firmware_hex, 20)?;
    eprintln!("im_size (v2): {}", bytes_v2.len());
    let sig_v2 = sign_firmware(&signing_key, &bytes_v2)?;

    let fw_json = create_firmware_json_versioned(firmware_hex, &sig_v1, &sig_v2)?;
    println!("{}", fw_json.to_json()?);
    Ok(())
}

/// Merge Intel HEX files into a single output.
///
/// # Errors
/// Returns an error if reading or parsing the input hex files, merging them,
/// or writing the output file fails.
pub fn cmd_mergehex(
    inputs: &[PathBuf],
    output: &Path,
    attestation_key: Option<&Path>,
    attestation_cert: Option<&Path>,
) -> Result<()> {
    let input_refs: Vec<&Path> = inputs.iter().map(std::path::PathBuf::as_path).collect();
    merge_hex_files(&input_refs, output, attestation_key, attestation_cert)?;
    println!("Merged {} files into {}", inputs.len(), output.display());
    Ok(())
}

/// List connected Solo devices of every supported model.
///
/// # Errors
/// Returns an error if enumerating HID devices fails or JSON serialization
/// fails.
pub fn cmd_ls(json: bool) -> Result<()> {
    use crate::output::{DeviceInfo, ListOutput, print_json};

    let devices = crate::device::list()?;

    if json {
        let out = ListOutput {
            devices: devices
                .iter()
                .map(|(model, d)| DeviceInfo {
                    model: model.name().into(),
                    path: d.path.clone(),
                    serial: d.serial.clone(),
                    product: d.product.clone(),
                    manufacturer: d.manufacturer.clone(),
                })
                .collect(),
        };
        return print_json(&out);
    }

    if devices.is_empty() {
        println!("No Solo devices found.");
    } else {
        println!("Found {} Solo device(s):", devices.len());
        for (model, dev) in &devices {
            println!(
                "  Model: {}  Path: {}  Serial: {}  Product: {}",
                model,
                dev.path,
                dev.serial.as_deref().unwrap_or("(none)"),
                dev.product.as_deref().unwrap_or("(unknown)")
            );
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::cast_possible_truncation
    )]
    use super::write_private_key;
    use std::os::unix::fs::PermissionsExt;

    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n";

    /// The private key file must be created with mode 0o600 so it is not
    /// readable by other local users.
    #[test]
    fn test_write_private_key_sets_owner_only_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.pem");

        write_private_key(&path, KEY_PEM).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), KEY_PEM);
    }

    /// An existing file with wider permissions must be restricted to 0o600.
    #[test]
    fn test_write_private_key_restricts_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.pem");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_private_key(&path, KEY_PEM).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), KEY_PEM);
    }

    /// Overwriting an existing key file truncates it, matching `fs::write`.
    #[test]
    fn test_write_private_key_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.pem");

        write_private_key(&path, "a much longer first key body").unwrap();
        write_private_key(&path, KEY_PEM).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), KEY_PEM);
    }

    /// A handle opened on the old file before the call must not read the new key.
    #[test]
    fn test_write_private_key_does_not_reach_open_handles() {
        use std::os::unix::fs::{FileExt, MetadataExt};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.pem");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let handle = std::fs::File::open(&path).unwrap();

        write_private_key(&path, KEY_PEM).unwrap();

        let mut buf = vec![0_u8; 4096];
        let n = handle.read_at(&mut buf, 0).unwrap();
        assert_eq!(&buf[..n], b"old");
        assert_ne!(
            handle.metadata().unwrap().ino(),
            std::fs::metadata(&path).unwrap().ino()
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), KEY_PEM);
    }

    /// A symbolic link at the path is replaced and its target is left alone.
    #[test]
    fn test_write_private_key_replaces_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let path = dir.path().join("signing-key.pem");
        std::fs::write(&target, "target").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        write_private_key(&path, KEY_PEM).unwrap();

        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), KEY_PEM);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "target");
    }

    /// A path that is a directory gives an error and is left untouched.
    #[test]
    fn test_write_private_key_rejects_non_regular_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.pem");
        std::fs::create_dir(&path).unwrap();

        let err = write_private_key(&path, KEY_PEM).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(path.is_dir());
    }
}
