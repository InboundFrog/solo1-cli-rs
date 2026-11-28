#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! What the commands that need no device print: stdout, stderr and the exit code.
//!
//! Each test starts the built program, so a change of an output text, of the
//! JSON form or of an exit code fails here.

use std::path::Path;
use std::process::Command;

struct Run {
    stdout: String,
    stderr: String,
    code: Option<i32>,
}

fn solo(args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_solo")).args(args).output().unwrap();
    Run {
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
        code: out.status.code(),
    }
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A tiny firmware HEX file.
const HEX: &str = ":020000040800F2\n:1050000000000000000000000000000000000000A0\n:00000001FF\n";

#[test]
fn version_text() {
    let r = solo(&["version"]);
    assert_eq!(r.stdout, format!("solo1-cli-rs {}\n", env!("CARGO_PKG_VERSION")));
    assert_eq!(r.stderr, "");
    assert_eq!(r.code, Some(0));
}

#[test]
fn version_json() {
    let r = solo(&["version", "--json"]);
    let expected = format!(
        "{{\n  \"name\": \"solo1-cli-rs\",\n  \"version\": \"{}\"\n}}\n",
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(r.stdout, expected);
    assert_eq!(r.stderr, "");
    assert_eq!(r.code, Some(0));
}

#[test]
fn version_unknown_flag_is_a_usage_error() {
    let r = solo(&["version", "--bogus"]);
    assert_eq!(r.stdout, "");
    assert!(
        r.stderr.starts_with("error: unexpected argument '--bogus' found"),
        "{}",
        r.stderr
    );
    assert_eq!(r.code, Some(2));
}

#[test]
fn genkey_to_file_writes_the_key_and_prints_the_public_key_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.pem");
    let r = solo(&["genkey", "-o", path(&key)]);
    assert_eq!(r.stdout, "");
    assert_eq!(r.code, Some(0));
    let lines: Vec<&str> = r.stderr.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some(format!("Private key written to {}", key.display()).as_str())
    );
    assert_eq!(lines.get(1).copied(), Some("Public key:"));
    assert_eq!(lines.get(2).copied(), Some("-----BEGIN PUBLIC KEY-----"));
    assert!(r.stderr.ends_with("-----END PUBLIC KEY-----\n\n"), "{}", r.stderr);
    let pem = std::fs::read_to_string(&key).unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{pem}");
    assert!(pem.ends_with("-----END PRIVATE KEY-----\n"), "{pem}");
}

#[test]
fn genkey_to_stdout_prints_the_private_key_there() {
    let r = solo(&["genkey"]);
    assert!(r.stdout.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{}", r.stdout);
    assert!(r.stdout.ends_with("-----END PRIVATE KEY-----\n"), "{}", r.stdout);
    assert!(
        r.stderr.starts_with("Public key:\n-----BEGIN PUBLIC KEY-----\n"),
        "{}",
        r.stderr
    );
    assert_eq!(r.code, Some(0));
}

#[test]
fn genkey_json_has_both_keys() {
    let r = solo(&["genkey", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&r.stdout).unwrap();
    let private = v["private_key"].as_str().unwrap();
    let public = v["public_key"].as_str().unwrap();
    assert!(private.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(public.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert_eq!(r.stderr, "");
    assert_eq!(r.code, Some(0));
}

#[test]
fn genkey_into_a_missing_directory_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("missing").join("k.pem");
    let r = solo(&["genkey", "-o", path(&key)]);
    assert_eq!(r.stdout, "");
    assert_eq!(r.stderr, "Error: I/O error: No such file or directory (os error 2)\n");
    assert_eq!(r.code, Some(1));
}

/// Makes a key with `genkey` and a firmware file in `dir`.
fn key_and_hex(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let key = dir.join("k.pem");
    assert_eq!(solo(&["genkey", "-o", path(&key)]).code, Some(0));
    let hex = dir.join("fw.hex");
    std::fs::write(&hex, HEX).unwrap();
    (key, hex)
}

#[test]
fn sign_prints_the_firmware_json_and_the_sizes_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let (key, hex) = key_and_hex(dir.path());
    let r = solo(&["sign", path(&key), path(&hex)]);
    assert_eq!(r.stderr, "im_size (v1): 202744\nim_size (v2): 200696\n");
    assert_eq!(r.code, Some(0));
    let v: serde_json::Value = serde_json::from_str(&r.stdout).unwrap();
    let mut names: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["firmware", "signature", "versions"]);
    let mut versions: Vec<&str> = v["versions"].as_object().unwrap().keys().map(String::as_str).collect();
    versions.sort_unstable();
    assert_eq!(versions, ["<=2.5.3", ">2.5.3"]);
    // The default signature is the one for the newer bootloaders.
    assert_eq!(v["signature"], v["versions"][">2.5.3"]["signature"]);
    assert_ne!(
        v["versions"]["<=2.5.3"]["signature"],
        v["versions"][">2.5.3"]["signature"]
    );
    assert_eq!(
        v["firmware"],
        "OjAyMDAwMDA0MDgwMEYyCjoxMDUwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwQTAKOjAwMDAwMDAxRkYK"
    );
}

#[test]
fn sign_with_a_missing_key_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (_, hex) = key_and_hex(dir.path());
    let missing = dir.path().join("nokey.pem");
    let r = solo(&["sign", path(&missing), path(&hex)]);
    assert_eq!(r.stdout, "");
    assert_eq!(r.stderr, "Error: I/O error: No such file or directory (os error 2)\n");
    assert_eq!(r.code, Some(1));
}

#[test]
fn mergehex_writes_the_output_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let (_, hex) = key_and_hex(dir.path());
    let out = dir.path().join("merged.hex");
    let r = solo(&["mergehex", "-o", path(&out), path(&hex), path(&hex)]);
    assert_eq!(r.stdout, format!("Merged 2 files into {}\n", out.display()));
    assert_eq!(r.stderr, "");
    assert_eq!(r.code, Some(0));
    let merged = std::fs::read_to_string(&out).unwrap();
    assert!(merged.starts_with(":020000040800F2\n:1050000000000000000000000000000000000000A0\n"));
    assert!(merged.ends_with(":00000001FF\n"));
}

#[test]
fn mergehex_with_a_missing_input_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.hex");
    let out = dir.path().join("merged.hex");
    let r = solo(&["mergehex", "-o", path(&out), path(&missing)]);
    assert_eq!(r.stdout, "");
    assert_eq!(r.stderr, "Error: I/O error: No such file or directory (os error 2)\n");
    assert_eq!(r.code, Some(1));
    assert!(!out.exists());
}

/// Writes a signed file in `dir`, the way `key sign-file` does, and returns its path
/// and the path of the public key.
fn signed_file(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use p256::pkcs8::{EncodePublicKey, LineEnding};
    use sha2::{Digest, Sha256};

    let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let file = dir.join("data.bin");
    std::fs::write(&file, b"hello").unwrap();

    // rpIdHash, flags (user present and user verified), counter 7.
    let mut auth_data = Sha256::digest(solo_cli::commands::key::SIGN_FILE_RP_ID.as_bytes()).to_vec();
    auth_data.push(0x05);
    auth_data.extend_from_slice(&7u32.to_be_bytes());
    let message = [auth_data.as_slice(), Sha256::digest(b"hello").as_slice()].concat();
    let sig: Signature = key.sign(&message);

    std::fs::write(dir.join("data.bin.sig"), sig.to_der().as_bytes()).unwrap();
    std::fs::write(dir.join("data.bin.authdata"), &auth_data).unwrap();
    let pem = key.verifying_key().to_public_key_pem(LineEnding::LF).unwrap();
    let pub_path = dir.join("pub.pem");
    std::fs::write(&pub_path, pem).unwrap();
    (file, pub_path)
}

#[test]
fn verify_file_reports_a_good_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (file, public_key) = signed_file(dir.path());
    let r = solo(&["verify-file", "--public-key", path(&public_key), path(&file)]);
    assert_eq!(
        r.stdout,
        "The signature is good.\nrpId: solokeys.dev\nUser verified: yes\nSignature counter: 7\n"
    );
    assert_eq!(r.stderr, "");
    assert_eq!(r.code, Some(0));
}

#[test]
fn verify_file_rejects_a_changed_file() {
    let dir = tempfile::tempdir().unwrap();
    let (file, public_key) = signed_file(dir.path());
    std::fs::write(&file, b"hellp").unwrap();
    let r = solo(&["verify-file", "--public-key", path(&public_key), path(&file)]);
    assert_eq!(r.stdout, "");
    assert_eq!(
        r.stderr,
        "Error: Crypto error: The signature does not match: wrong public key, or the file or the authenticator data was changed\n"
    );
    assert_eq!(r.code, Some(1));
}
