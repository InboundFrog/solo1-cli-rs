/// Top-level commands: version, genkey, sign, verify-file, mergehex, ls.
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::commands::key::{sha256_file, with_suffix};
use crate::error::{Result, SoloError};
use crate::output::{VerifyFileOutput, write_json};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use solo_ctap2::authdata::{AuthenticatorData, FLAG_UP, FLAG_UV};
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

/// The checks of `verify-file` that are not about the files.
pub struct FileChecks<'a> {
    /// The rpId that the signature must be for.
    pub host: &'a str,
    /// Fail unless the signature counter is greater than this.
    pub counter_above: Option<u32>,
}

/// What `check_file_signature` found in a good signature.
#[derive(Debug, PartialEq, Eq)]
pub struct FileSignatureFacts {
    pub user_verified: bool,
    pub sign_count: u32,
}

/// Check a `sign-file` signature. All checks must pass, or this returns an error that names the check.
///
/// `file_hash` is the SHA-256 of the file. `host` is the rpId that the signature must be for. The key signs `auth_data || file_hash` with ES256 (ECDSA P-256, SHA-256).
///
/// # Errors
/// Returns `CryptoError` if the public key is not a P-256 PEM key, the authenticator data is too short
/// or malformed, its rpIdHash is not that of `host`, the user-present flag is not set,
/// the signature is not DER, or the signature does not verify.
pub fn check_file_signature(
    public_key_pem: &str,
    signature_der: &[u8],
    auth_data: &[u8],
    file_hash: &[u8; 32],
    host: &str,
) -> Result<FileSignatureFacts> {
    let key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| SoloError::CryptoError(format!("The public key is not a P-256 PEM public key: {e}")))?;

    let parsed = AuthenticatorData::parse(auth_data).map_err(|_| {
        SoloError::CryptoError("The authenticator data is shorter than 37 bytes or is not valid".into())
    })?;

    if parsed.rp_id_hash[..] != Sha256::digest(host.as_bytes())[..] {
        return Err(SoloError::CryptoError(format!(
            "The authenticator data is not for the rpId {host} (rpIdHash does not match)"
        )));
    }

    if parsed.flags & FLAG_UP == 0 {
        return Err(SoloError::CryptoError(
            "The user-present flag is not set in the authenticator data".into(),
        ));
    }

    let signature = Signature::from_der(signature_der)
        .map_err(|e| SoloError::CryptoError(format!("The signature is not a valid DER ECDSA signature: {e}")))?;

    let message = [auth_data, file_hash].concat();
    key.verify(&message, &signature).map_err(|_| {
        SoloError::CryptoError(
            "The signature does not match: wrong public key, or the file or the authenticator data was changed".into(),
        )
    })?;

    Ok(FileSignatureFacts {
        user_verified: parsed.flags & FLAG_UV != 0,
        sign_count: parsed.sign_count,
    })
}

/// Make the error of a failed read say which input it was.
fn input_error(what: &str, path: &Path, e: &std::io::Error) -> SoloError {
    SoloError::IoError(std::io::Error::new(
        e.kind(),
        format!("cannot read the {what} {}: {e}", path.display()),
    ))
}

/// Read a small input file. The error says which input it was.
fn read_input(what: &str, path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| input_error(what, path, &e))
}

/// The JSON object of `verify-file --json` for a good signature. Prints nothing.
fn verify_file_output(facts: &FileSignatureFacts, host: &str) -> VerifyFileOutput {
    VerifyFileOutput {
        rp_id: host.into(),
        user_verified: facts.user_verified,
        sign_count: facts.sign_count,
    }
}

/// Check the signature of `sign-file` offline and print the result.
///
/// The result goes to `out`. With `json`, a good signature prints one JSON object. A failed check
/// prints nothing to `out` and is an error, as without `json`.
///
/// `checks.host` is the rpId that the signature must be for. A signature for another rpId fails, and the error names it.
///
/// `signature` and `authdata` default to `<file>.sig` and `<file>.authdata`.
///
/// # Errors
/// Returns an error if an input file cannot be read, if any check of
/// `check_file_signature` fails, or if `checks.counter_above` is set and the signature counter is not
/// greater than it. A counter of 0 fails every `checks.counter_above`.
pub fn cmd_verify_file(
    public_key: &Path,
    signature: Option<&Path>,
    authdata: Option<&Path>,
    file: &Path,
    json: bool,
    checks: &FileChecks,
    out: &mut impl Write,
) -> Result<()> {
    let signature = signature.map_or_else(|| with_suffix(file, ".sig"), Path::to_path_buf);
    let authdata = authdata.map_or_else(|| with_suffix(file, ".authdata"), Path::to_path_buf);

    let key_bytes = read_input("public key file", public_key)?;
    let key_pem = String::from_utf8(key_bytes)
        .map_err(|_| SoloError::CryptoError("The public key file is not a P-256 PEM public key (not text)".into()))?;
    let facts = check_file_signature(
        &key_pem,
        &read_input("signature file", &signature)?,
        &read_input("authenticator data file", &authdata)?,
        &sha256_file(file).map_err(|e| input_error("input file", file, &e))?,
        checks.host,
    )?;

    // The facts exist only after every check of the signature passed.
    if let Some(n) = checks.counter_above
        && facts.sign_count <= n
    {
        return Err(SoloError::CryptoError(format!(
            "The signature counter {} is not above {n}",
            facts.sign_count
        )));
    }

    if json {
        return write_json(out, &verify_file_output(&facts, checks.host));
    }
    writeln!(out, "The signature is good.")?;
    writeln!(out, "rpId: {}", checks.host)?;
    writeln!(out, "User verified: {}", if facts.user_verified { "yes" } else { "no" })?;
    writeln!(out, "Signature counter: {}", facts.sign_count)?;
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

#[cfg(test)]
mod verify_file_tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::cast_possible_truncation
    )]
    use super::*;
    use crate::commands::key::SIGN_FILE_RP_ID;
    use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
    use p256::pkcs8::{EncodePublicKey, LineEnding};

    const FILE: &[u8] = b"hello file\n";

    fn key() -> SigningKey {
        SigningKey::from_slice(&[0x42; 32]).unwrap()
    }

    fn hash_of(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn pem(k: &SigningKey) -> String {
        k.verifying_key().to_public_key_pem(LineEnding::LF).unwrap()
    }

    fn auth_data(rp_id: &str, flags: u8, count: u32) -> Vec<u8> {
        let mut v = Sha256::digest(rp_id.as_bytes()).to_vec();
        v.push(flags);
        v.extend_from_slice(&count.to_be_bytes());
        v
    }

    fn sign(k: &SigningKey, auth: &[u8], file: &[u8]) -> Vec<u8> {
        let msg = [auth, Sha256::digest(file).as_slice()].concat();
        let sig: DerSignature = k.sign(&msg);
        sig.as_bytes().to_vec()
    }

    fn good() -> (String, Vec<u8>, Vec<u8>) {
        let k = key();
        let auth = auth_data(SIGN_FILE_RP_ID, FLAG_UP, 9);
        (pem(&k), sign(&k, &auth, FILE), auth)
    }

    fn err_text(r: Result<FileSignatureFacts>) -> String {
        match r.unwrap_err() {
            SoloError::CryptoError(m) => m,
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn host_must_match_the_rp_id_of_the_authenticator_data() {
        let k = key();
        let auth = auth_data("example.com", FLAG_UP, 1);
        let sig = sign(&k, &auth, FILE);
        let facts = check_file_signature(&pem(&k), &sig, &auth, &hash_of(FILE), "example.com").unwrap();
        assert_eq!(facts.sign_count, 1);
        let msg = err_text(check_file_signature(
            &pem(&k),
            &sig,
            &auth,
            &hash_of(FILE),
            SIGN_FILE_RP_ID,
        ));
        assert!(msg.contains("not for the rpId solokeys.dev"), "{msg}");
        // The other way round: a signature for the default host fails for another host, and the error names it.
        let (pem, sig, auth) = good();
        let msg = err_text(check_file_signature(&pem, &sig, &auth, &hash_of(FILE), "example.com"));
        assert!(msg.contains("not for the rpId example.com"), "{msg}");
    }

    #[test]
    fn command_uses_the_given_host_in_the_output() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_case(dir.path(), FILE); // signed for solokeys.dev
        let k = key();
        let auth = auth_data("example.com", FLAG_UP, 3);
        std::fs::write(dir.path().join("doc.txt.sig"), sign(&k, &auth, FILE)).unwrap();
        std::fs::write(dir.path().join("doc.txt.authdata"), &auth).unwrap();
        let pubkey = dir.path().join("pub.pem");
        let checks = |host| FileChecks {
            host,
            counter_above: None,
        };
        let mut out = Vec::new();
        cmd_verify_file(&pubkey, None, None, &file, true, &checks("example.com"), &mut out).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["rp_id"], "example.com");
        let mut out = Vec::new();
        cmd_verify_file(&pubkey, None, None, &file, false, &checks("example.com"), &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("rpId: example.com\n"));
        let err = cmd_verify_file(
            &pubkey,
            None,
            None,
            &file,
            false,
            &checks(SIGN_FILE_RP_ID),
            &mut Vec::new(),
        );
        assert!(err.unwrap_err().to_string().contains("not for the rpId solokeys.dev"));
    }

    #[test]
    fn good_signature_passes_and_reports_facts() {
        let (pem, sig, auth) = good();
        let facts = check_file_signature(&pem, &sig, &auth, &hash_of(FILE), SIGN_FILE_RP_ID).unwrap();
        assert_eq!(
            facts,
            FileSignatureFacts {
                user_verified: false,
                sign_count: 9
            }
        );

        let k = key();
        let auth = auth_data(SIGN_FILE_RP_ID, FLAG_UP | FLAG_UV, 0x0102_0304);
        let facts = check_file_signature(&pem, &sign(&k, &auth, FILE), &auth, &hash_of(FILE), SIGN_FILE_RP_ID).unwrap();
        assert!(facts.user_verified);
        assert_eq!(facts.sign_count, 0x0102_0304);
    }

    #[test]
    fn changed_file_fails() {
        let (pem, sig, auth) = good();
        let mut file = FILE.to_vec();
        file[0] ^= 1;
        assert!(
            err_text(check_file_signature(
                &pem,
                &sig,
                &auth,
                &hash_of(&file),
                SIGN_FILE_RP_ID
            ))
            .contains("does not match")
        );
    }

    #[test]
    fn changed_authdata_fails() {
        let (pem, sig, mut auth) = good();
        auth[36] ^= 1; // the signature counter
        assert!(
            err_text(check_file_signature(&pem, &sig, &auth, &hash_of(FILE), SIGN_FILE_RP_ID))
                .contains("does not match")
        );
    }

    #[test]
    fn authdata_with_trailing_bytes_is_signed_as_a_whole() {
        let k = key();
        let mut auth = auth_data(SIGN_FILE_RP_ID, FLAG_UP, 1);
        auth.extend_from_slice(&[0xA0]);
        let sig = sign(&k, &auth, FILE);
        check_file_signature(&pem(&k), &sig, &auth, &hash_of(FILE), SIGN_FILE_RP_ID).unwrap();
        // A signature over the 37-byte header only must not pass for the longer data.
        let short_sig = sign(&k, &auth[..37], FILE);
        assert!(check_file_signature(&pem(&k), &short_sig, &auth, &hash_of(FILE), SIGN_FILE_RP_ID).is_err());
    }

    #[test]
    fn wrong_public_key_fails() {
        let (_, sig, auth) = good();
        let other = pem(&SigningKey::from_slice(&[0x43; 32]).unwrap());
        assert!(
            err_text(check_file_signature(
                &other,
                &sig,
                &auth,
                &hash_of(FILE),
                SIGN_FILE_RP_ID
            ))
            .contains("does not match")
        );
    }

    #[test]
    fn other_rp_id_fails_only_the_rp_id_check() {
        let k = key();
        let auth = auth_data("example.com", FLAG_UP, 1);
        let sig = sign(&k, &auth, FILE);
        let msg = err_text(check_file_signature(
            &pem(&k),
            &sig,
            &auth,
            &hash_of(FILE),
            SIGN_FILE_RP_ID,
        ));
        assert!(msg.contains("rpIdHash"), "{msg}");
    }

    #[test]
    fn user_present_flag_clear_fails_only_that_check() {
        let k = key();
        let auth = auth_data(SIGN_FILE_RP_ID, FLAG_UV, 1);
        let sig = sign(&k, &auth, FILE);
        let msg = err_text(check_file_signature(
            &pem(&k),
            &sig,
            &auth,
            &hash_of(FILE),
            SIGN_FILE_RP_ID,
        ));
        assert!(msg.contains("user-present"), "{msg}");
    }

    #[test]
    fn short_authdata_fails() {
        let (pem, sig, auth) = good();
        for len in [0, 1, 32, 36] {
            let msg = err_text(check_file_signature(
                &pem,
                &sig,
                &auth[..len],
                &hash_of(FILE),
                SIGN_FILE_RP_ID,
            ));
            assert!(msg.contains("shorter than 37"), "len {len}: {msg}");
            assert!(!msg.contains("device"), "len {len}: {msg}");
        }
    }

    #[test]
    fn cut_short_attested_data_fails_without_mentioning_a_device() {
        let (pem, sig, _) = good();
        let auth = auth_data(SIGN_FILE_RP_ID, FLAG_UP | 0x40, 1); // AT flag, but no attested data
        let msg = err_text(check_file_signature(&pem, &sig, &auth, &hash_of(FILE), SIGN_FILE_RP_ID));
        assert!(msg.contains("shorter than 37 bytes or is not valid"), "{msg}");
        assert!(!msg.contains("device"), "{msg}");
    }

    #[test]
    fn empty_or_non_der_signature_fails() {
        let (pem, sig, auth) = good();
        let with_extra_byte = [sig.as_slice(), &[0]].concat();
        // The last case is DER-shaped, but r is 0.
        let zero_r = [0x30, 6, 2, 1, 0, 2, 1, 1];
        for bad in [
            &[][..],
            &[0u8; 64][..],
            &sig[..sig.len() - 1],
            b"not a signature",
            &with_extra_byte,
            &zero_r,
        ] {
            let msg = err_text(check_file_signature(&pem, bad, &auth, &hash_of(FILE), SIGN_FILE_RP_ID));
            assert!(msg.contains("not a valid DER ECDSA signature"), "{msg}");
        }
    }

    #[test]
    fn bad_public_key_text_fails() {
        let (pem, sig, auth) = good();
        for bad in [
            "",
            "not pem",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        ] {
            let msg = err_text(check_file_signature(bad, &sig, &auth, &hash_of(FILE), SIGN_FILE_RP_ID));
            assert!(msg.contains("P-256 PEM public key"), "{msg}");
        }
        // A good key body under the wrong PEM label.
        assert!(
            check_file_signature(
                &pem.replace("PUBLIC KEY", "CERTIFICATE"),
                &sig,
                &auth,
                &hash_of(FILE),
                SIGN_FILE_RP_ID
            )
            .is_err()
        );
    }

    /// A vector made with OpenSSL only (new P-256 key, `openssl dgst -sha256 -sign` over the
    /// authenticator data followed by the SHA-256 hash of the file), not with this code.
    /// It fixes the order and the form of the signed bytes.
    const VECTOR_FILE: &[u8] = b"solo verify-file test vector\n";
    const VECTOR_AUTH: &str = "1ac491d9d3712c63f7b8d6cfadf86d057d099d382246dbe9c87f133ed167881b0100000007";
    const VECTOR_SIG: &str = "304402206584ecd4939b08a672c1195e80c15ce6ea71b0d4f09814dc93b246f0ff041ff002203b2cbcca1e83af28132afa8d9dd542ad6c0c1423c4cbfaba9e4f703bd1b4e19d";
    const VECTOR_KEY: &str = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErjD0bM/TwXPizabv2IyXLRbhiI0j\n\
K1AvWLn046q1Ik2YKVlH6a1ub/59Px9p0EYH/EJ99cnrKYqvALq666Q+Vw==\n\
-----END PUBLIC KEY-----\n";

    #[test]
    fn openssl_vector_passes_and_a_cut_file_fails() {
        let sig = hex::decode(VECTOR_SIG).unwrap();
        let auth = hex::decode(VECTOR_AUTH).unwrap();
        let facts = check_file_signature(VECTOR_KEY, &sig, &auth, &hash_of(VECTOR_FILE), SIGN_FILE_RP_ID).unwrap();
        assert_eq!(
            facts,
            FileSignatureFacts {
                user_verified: false,
                sign_count: 7
            }
        );
        let cut = &VECTOR_FILE[..VECTOR_FILE.len() - 1];
        assert!(
            err_text(check_file_signature(
                VECTOR_KEY,
                &sig,
                &auth,
                &hash_of(cut),
                SIGN_FILE_RP_ID
            ))
            .contains("does not match")
        );
    }

    #[test]
    fn private_key_pem_is_refused_as_public_key() {
        use p256::pkcs8::EncodePrivateKey;
        let (_, sig, auth) = good();
        let private = p256::SecretKey::from_slice(&[0x42; 32])
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        let msg = err_text(check_file_signature(
            &private,
            &sig,
            &auth,
            &hash_of(FILE),
            SIGN_FILE_RP_ID,
        ));
        assert!(msg.contains("P-256 PEM public key"), "{msg}");
    }

    #[test]
    fn command_fails_for_missing_or_non_text_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_case(dir.path(), FILE);
        let err = cmd_verify_file(
            &dir.path().join("none.pem"),
            None,
            None,
            &file,
            false,
            &FileChecks {
                host: SIGN_FILE_RP_ID,
                counter_above: None,
            },
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, SoloError::IoError(_)));
        assert!(err.to_string().contains("public key file"));

        std::fs::write(dir.path().join("bin.pem"), [0xFF, 0xFE, 0x00]).unwrap();
        let err = cmd_verify_file(
            &dir.path().join("bin.pem"),
            None,
            None,
            &file,
            false,
            &FileChecks {
                host: SIGN_FILE_RP_ID,
                counter_above: None,
            },
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, SoloError::CryptoError(_)));
        assert!(err.to_string().contains("not text"));
    }

    fn write_case(dir: &Path, signed_file: &[u8]) -> PathBuf {
        let k = key();
        let auth = auth_data(SIGN_FILE_RP_ID, FLAG_UP, 3);
        let file = dir.join("doc.txt");
        std::fs::write(&file, signed_file).unwrap();
        std::fs::write(dir.join("doc.txt.sig"), sign(&k, &auth, FILE)).unwrap();
        std::fs::write(dir.join("doc.txt.authdata"), &auth).unwrap();
        std::fs::write(dir.join("pub.pem"), pem(&k)).unwrap();
        file
    }

    #[test]
    fn command_uses_default_sig_and_authdata_paths() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_case(dir.path(), FILE);
        cmd_verify_file(
            &dir.path().join("pub.pem"),
            None,
            None,
            &file,
            false,
            &FileChecks {
                host: SIGN_FILE_RP_ID,
                counter_above: None,
            },
            &mut Vec::new(),
        )
        .unwrap();

        // A changed file is an error; so is a missing default file.
        let file = write_case(dir.path(), b"other");
        assert!(
            cmd_verify_file(
                &dir.path().join("pub.pem"),
                None,
                None,
                &file,
                false,
                &FileChecks {
                    host: SIGN_FILE_RP_ID,
                    counter_above: None
                },
                &mut Vec::new()
            )
            .is_err()
        );
        std::fs::remove_file(dir.path().join("doc.txt.authdata")).unwrap();
        let err = cmd_verify_file(
            &dir.path().join("pub.pem"),
            None,
            None,
            &file,
            false,
            &FileChecks {
                host: SIGN_FILE_RP_ID,
                counter_above: None,
            },
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, SoloError::IoError(_)));
        assert!(err.to_string().contains("authenticator data file"));
    }

    #[test]
    fn json_value_has_the_facts() {
        let v = serde_json::to_value(verify_file_output(
            &FileSignatureFacts {
                user_verified: true,
                sign_count: 3,
            },
            SIGN_FILE_RP_ID,
        ))
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"rp_id": "solokeys.dev", "user_verified": true, "sign_count": 3})
        );
        let v = serde_json::to_value(verify_file_output(
            &FileSignatureFacts {
                user_verified: false,
                sign_count: 0,
            },
            SIGN_FILE_RP_ID,
        ))
        .unwrap();
        assert_eq!(v["user_verified"], false);
        assert_eq!(v["sign_count"], 0);
    }

    #[test]
    fn counter_above_passes_only_for_a_greater_count() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_case(dir.path(), FILE); // the count is 3
        let pubkey = dir.path().join("pub.pem");
        let run = |n: Option<u32>, json: bool| {
            let mut out = Vec::new();
            let r = cmd_verify_file(
                &pubkey,
                None,
                None,
                &file,
                json,
                &FileChecks {
                    host: SIGN_FILE_RP_ID,
                    counter_above: n,
                },
                &mut out,
            );
            (r, out)
        };
        for n in [None, Some(0), Some(2)] {
            let (r, out) = run(n, true);
            r.unwrap();
            assert_eq!(out.first(), Some(&b'{'));
        }
        for n in [3, 4, u32::MAX] {
            let (r, out) = run(Some(n), true);
            let msg = r.unwrap_err().to_string();
            assert!(
                msg.ends_with(&format!("The signature counter 3 is not above {n}")),
                "{msg}"
            );
            assert_eq!(out, Vec::<u8>::new());
        }
    }

    #[test]
    fn counter_above_fails_for_a_zero_count() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_case(dir.path(), FILE);
        let k = key();
        let auth = auth_data(SIGN_FILE_RP_ID, FLAG_UP, 0);
        std::fs::write(dir.path().join("doc.txt.sig"), sign(&k, &auth, FILE)).unwrap();
        std::fs::write(dir.path().join("doc.txt.authdata"), &auth).unwrap();
        let pubkey = dir.path().join("pub.pem");
        cmd_verify_file(
            &pubkey,
            None,
            None,
            &file,
            false,
            &FileChecks {
                host: SIGN_FILE_RP_ID,
                counter_above: None,
            },
            &mut Vec::new(),
        )
        .unwrap();
        let err = cmd_verify_file(
            &pubkey,
            None,
            None,
            &file,
            false,
            &FileChecks {
                host: SIGN_FILE_RP_ID,
                counter_above: Some(0),
            },
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("counter 0 is not above 0"));
    }

    #[test]
    fn bad_signature_still_gives_the_signature_error_with_counter_above() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_case(dir.path(), FILE);
        let mut auth = std::fs::read(dir.path().join("doc.txt.authdata")).unwrap();
        auth[36] ^= 1; // the count becomes 2
        std::fs::write(dir.path().join("doc.txt.authdata"), &auth).unwrap();
        let err = cmd_verify_file(
            &dir.path().join("pub.pem"),
            None,
            None,
            &file,
            false,
            &FileChecks {
                host: SIGN_FILE_RP_ID,
                counter_above: Some(1),
            },
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn json_mode_writes_exactly_one_json_object() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_case(dir.path(), FILE);
        let mut out = Vec::new();
        cmd_verify_file(
            &dir.path().join("pub.pem"),
            None,
            None,
            &file,
            true,
            &FileChecks {
                host: SIGN_FILE_RP_ID,
                counter_above: None,
            },
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"rp_id": "solokeys.dev", "user_verified": false, "sign_count": 3})
        );
    }

    #[test]
    fn text_mode_lines_are_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_case(dir.path(), FILE);
        let mut out = Vec::new();
        cmd_verify_file(
            &dir.path().join("pub.pem"),
            None,
            None,
            &file,
            false,
            &FileChecks {
                host: SIGN_FILE_RP_ID,
                counter_above: None,
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "The signature is good.\nrpId: solokeys.dev\nUser verified: no\nSignature counter: 3\n"
        );
    }

    #[test]
    fn failed_check_writes_nothing_to_out() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_case(dir.path(), b"other");
        for json in [true, false] {
            let mut out = Vec::new();
            let err = cmd_verify_file(
                &dir.path().join("pub.pem"),
                None,
                None,
                &file,
                json,
                &FileChecks {
                    host: SIGN_FILE_RP_ID,
                    counter_above: None,
                },
                &mut out,
            )
            .unwrap_err();
            assert!(matches!(err, SoloError::CryptoError(_)));
            assert_eq!(out, Vec::<u8>::new());
        }
    }

    #[test]
    fn command_accepts_explicit_paths() {
        let dir = tempfile::tempdir().unwrap();
        let file = write_case(dir.path(), FILE);
        let sig = dir.path().join("a.sig");
        let auth = dir.path().join("a.ad");
        std::fs::rename(dir.path().join("doc.txt.sig"), &sig).unwrap();
        std::fs::rename(dir.path().join("doc.txt.authdata"), &auth).unwrap();
        cmd_verify_file(
            &dir.path().join("pub.pem"),
            Some(&sig),
            Some(&auth),
            &file,
            false,
            &FileChecks {
                host: SIGN_FILE_RP_ID,
                counter_above: None,
            },
            &mut Vec::new(),
        )
        .unwrap();
    }
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
