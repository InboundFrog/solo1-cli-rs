/// Top-level commands: version, genkey, sign, mergehex, ls.
use std::path::{Path, PathBuf};

use crate::error::Result;
use solo1::crypto::{generate_keypair, load_signing_key, sign_firmware};
use solo1::firmware::{create_firmware_json_versioned, firmware_bytes_to_sign_for_version, merge_hex_text};

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

/// Write a file that holds a private key to a new file at `path`.
///
/// Used for the key from `genkey` and for the merged HEX from `mergehex` when
/// it holds a user's attestation key.
///
/// The key is written to a temporary file in the same directory, with mode
/// 0o600 (or less if the umask removes bits). The file is synced and then
/// renamed over `path`. If any step fails, the temporary file is removed and
/// an old file at `path` is left as it was. The new key is in a new file, so a
/// handle that another program opened on the old file cannot read it. A
/// symbolic link or any other kind of existing path gives an error and is left
/// untouched.
#[cfg(unix)]
fn write_private_key(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {}
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "output path exists and is not a regular file (symbolic links are not followed)",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "output path has no file name"))?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".{}.tmp", std::process::id()));
    let temp = path.with_file_name(temp_name);

    // If this fails, the name is not ours, so nothing is removed.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temp, path));
    if result.is_err() {
        // Best effort: the original error is the one to report.
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Write a file that holds a private key to `path` (non-Unix fallback).
#[cfg(not(unix))]
fn write_private_key(path: &Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// Sign a firmware hex file with the given key.
///
/// Makes two signatures, one for each bootloader generation (as the Python tool does):
///   - v1: signed over region using `APPLICATION_END_PAGE=19` (bootloaders <=2.5.3)
///   - v2: signed over region using `APPLICATION_END_PAGE=20` (bootloaders >2.5.3)
///
/// The `firmware` field in the output JSON is the base64 of the HEX FILE TEXT,
/// not of the binary. The Python tool does the same.
///
/// Prints JSON {firmware, signature, versions} to stdout.
///
/// # Errors
/// Returns an error if the signing key cannot be loaded, the firmware hex
/// cannot be read or parsed, signing fails, or building or serializing the
/// output JSON fails.
pub fn cmd_sign(key_path: &Path, firmware_hex: &Path) -> Result<()> {
    let signing_key = load_signing_key(key_path)?;

    // v1 bootloaders (<=2.5.3): app_end_page=19
    let bytes_v1 = firmware_bytes_to_sign_for_version(firmware_hex, 19)?;
    eprintln!("im_size (v1): {}", bytes_v1.len());
    let sig_v1 = sign_firmware(&signing_key, &bytes_v1)?;

    // v2 bootloaders (>2.5.3): app_end_page=20
    let bytes_v2 = firmware_bytes_to_sign_for_version(firmware_hex, 20)?;
    eprintln!("im_size (v2): {}", bytes_v2.len());
    let sig_v2 = sign_firmware(&signing_key, &bytes_v2)?;

    let fw_json = create_firmware_json_versioned(firmware_hex, &sig_v1, &sig_v2)?;
    println!("{}", fw_json.to_json()?);
    Ok(())
}

/// Merge Intel HEX files into a single output.
///
/// If `attestation_key` is given, the output holds that private key, so it is
/// written with `write_private_key`. Otherwise it is a plain write.
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
    let text = merge_hex_text(&input_refs, attestation_key, attestation_cert)?;
    if attestation_key.is_some() {
        write_private_key(output, &text)?;
    } else {
        std::fs::write(output, text)?;
    }
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

    /// A symbolic link at the path gives an error and its target is not changed.
    #[test]
    fn test_write_private_key_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let path = dir.path().join("signing-key.pem");
        std::fs::write(&target, "target").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let err = write_private_key(&path, KEY_PEM).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("not a regular file"));
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "target");
    }

    /// A dangling symbolic link gives an error and no file is made through it.
    #[test]
    fn test_write_private_key_rejects_dangling_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("missing");
        let path = dir.path().join("signing-key.pem");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        let err = write_private_key(&path, KEY_PEM).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("not a regular file"));
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        assert!(!target.exists());
    }

    /// If the temporary file cannot be created, the call fails and the old file is kept.
    #[test]
    fn test_write_private_key_keeps_old_file_when_temp_cannot_be_created() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        // Root ignores directory permissions, so this test cannot work as root.
        if std::fs::metadata(dir.path()).unwrap().uid() == 0 {
            return;
        }
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let path = sub.join("signing-key.pem");
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = write_private_key(&path, KEY_PEM);
        let content = std::fs::read_to_string(&path);
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(content.unwrap(), "old");
    }

    /// A file at the temporary name is not ours: the call fails and nothing is changed.
    #[test]
    fn test_write_private_key_does_not_touch_foreign_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.pem");
        let temp = dir.path().join(format!(".signing-key.pem.{}.tmp", std::process::id()));
        std::fs::write(&path, "old").unwrap();
        std::fs::write(&temp, "foreign").unwrap();

        let err = write_private_key(&path, KEY_PEM).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");
        assert_eq!(std::fs::read_to_string(&temp).unwrap(), "foreign");
    }

    /// After a good write only the key file is in the directory.
    #[test]
    fn test_write_private_key_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.pem");
        std::fs::write(&path, "old").unwrap();

        write_private_key(&path, KEY_PEM).unwrap();

        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("signing-key.pem")]);
    }

    /// If the rename fails, the temporary file is removed.
    #[test]
    fn test_write_private_key_removes_temp_file_when_rename_fails() {
        let dir = tempfile::tempdir().unwrap();
        // The trailing slash makes the rename fail after the temp file exists.
        let path = format!("{}/new.pem/", dir.path().display());

        let result = write_private_key(std::path::Path::new(&path), KEY_PEM);

        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// A path with no file name gives an error, not a panic.
    #[test]
    fn test_write_private_key_rejects_path_without_file_name() {
        let dir = tempfile::tempdir().unwrap();
        // The missing parent makes the first check say "not found".
        let path = dir.path().join("missing").join("..");

        let err = write_private_key(&path, KEY_PEM).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// A Unix socket at the path gives an error and is left untouched.
    #[test]
    fn test_write_private_key_rejects_socket_path() {
        use std::os::unix::fs::FileTypeExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

        let err = write_private_key(&path, KEY_PEM).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("not a regular file"));
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_socket());
    }

    /// A path that is a directory gives an error and is left untouched.
    #[test]
    fn test_write_private_key_rejects_non_regular_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing-key.pem");
        std::fs::create_dir(&path).unwrap();

        let err = write_private_key(&path, KEY_PEM).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(err.to_string().contains("not a regular file"));
        assert!(path.is_dir());
    }

    /// Small valid inputs for `cmd_mergehex`: a HEX file, a key and a cert.
    fn mergehex_inputs(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let hex = dir.join("in.hex");
        std::fs::write(&hex, ":020000040800F2\n:00000001FF\n").unwrap();
        let key = dir.join("att.key");
        std::fs::write(&key, "11".repeat(32)).unwrap();
        let cert = dir.join("att.cert");
        std::fs::write(&cert, [0x30u8; 120]).unwrap();
        (hex, key, cert)
    }

    /// With an attestation key the output has mode 0o600, also over an old
    /// file with a wider mode.
    #[test]
    fn test_mergehex_with_attestation_key_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let (hex, key, cert) = mergehex_inputs(dir.path());
        let out = dir.path().join("out.hex");
        std::fs::write(&out, "old").unwrap();
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644)).unwrap();

        super::cmd_mergehex(std::slice::from_ref(&hex), &out, Some(&key), Some(&cert)).unwrap();

        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        let expected = solo1::firmware::merge_hex_text(&[hex.as_path()], Some(&key), Some(&cert)).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), expected);
    }

    /// With an attestation key, a symbolic link at the output path is refused
    /// and its target is not changed.
    #[test]
    fn test_mergehex_with_attestation_key_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let (hex, key, cert) = mergehex_inputs(dir.path());
        let target = dir.path().join("target");
        std::fs::write(&target, "untouched").unwrap();
        let out = dir.path().join("out.hex");
        std::os::unix::fs::symlink(&target, &out).unwrap();

        let err = super::cmd_mergehex(&[hex], &out, Some(&key), Some(&cert)).unwrap_err();

        assert!(err.to_string().contains("not a regular file"), "{err}");
        assert!(std::fs::symlink_metadata(&out).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
    }

    /// Without an attestation key the output is a plain write: the mode of an
    /// old file is kept and a symbolic link is followed.
    #[test]
    fn test_mergehex_without_attestation_key_is_plain_write() {
        let dir = tempfile::tempdir().unwrap();
        let (hex, _, _) = mergehex_inputs(dir.path());
        let out = dir.path().join("out.hex");
        std::fs::write(&out, "old").unwrap();
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644)).unwrap();

        super::cmd_mergehex(std::slice::from_ref(&hex), &out, None, None).unwrap();

        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o644);
        let expected = solo1::firmware::merge_hex_text(&[hex.as_path()], None, None).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), expected);

        let target = dir.path().join("target");
        let link = dir.path().join("link.hex");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        super::cmd_mergehex(&[hex], &link, None, None).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), expected);
    }
}
