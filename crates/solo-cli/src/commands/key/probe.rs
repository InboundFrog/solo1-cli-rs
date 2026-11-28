use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Result, SoloError};
use crate::output::{ProbeOutput, SignFileOutput, print_json};
use solo_ctaphid::HidDevice;
use solo1::protocol::CMD_PROBE;

/// Run a hash probe on the device.
///
/// Sends a CBOR-encoded command to `CMD_PROBE` (0x70):
///   {"subcommand": `hash_type_str`, "data": `file_bytes`}
///
/// Valid hash types (input is not case-sensitive; the canonical form is sent):
///   SHA256, SHA512, RSA2048, Ed25519
///
/// The file must be at most 6144 bytes.
///
/// # Errors
/// Returns an error if `hash_type` is not a recognised hash type, if the file
/// cannot be read, if the file exceeds 6144 bytes, or if the device request
/// fails.
///
/// With `json`, prints one JSON object (see [`ProbeOutput`]) instead of the text.
pub fn cmd_probe(hid: &impl HidDevice, hash_type: &str, filename: &Path, json: bool) -> Result<()> {
    use ciborium::value::Value;
    // Convert the hash type to the canonical form that the device expects.
    let hash_type_str = normalize_hash_type(hash_type).ok_or_else(|| {
        SoloError::DeviceError(format!(
            "Unknown hash type: {}. Valid: SHA256, SHA512, RSA2048, Ed25519",
            hash_type.to_lowercase()
        ))
    })?;

    let file_bytes = std::fs::read(filename)?;
    if file_bytes.len() > 6 * 1024 {
        return Err(SoloError::DeviceError(format!(
            "File too large: {} bytes (max 6144)",
            file_bytes.len()
        )));
    }

    // CBOR-encode: {"subcommand": hash_type_str, "data": file_bytes}
    let cbor_val = Value::Map(vec![
        (Value::Text("subcommand".into()), Value::Text(hash_type_str.into())),
        (Value::Text("data".into()), Value::Bytes(file_bytes)),
    ]);
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&cbor_val, &mut cbor_bytes)?;

    let response = hid.send_recv(CMD_PROBE, &cbor_bytes)?;
    let result_hex = hex::encode(&response);
    if json {
        return print_json(&probe_output(hash_type_str, &response));
    }
    println!("{result_hex}");

    if hash_type_str == "Ed25519" {
        // The first 64 bytes are the signature (128 hex characters). The rest is the content.
        if response.len() > 64 {
            let content = response
                .get(64..)
                .ok_or_else(|| SoloError::ProtocolError("Probe response too short".into()))?;
            println!("content: {content:?}");
            let sig_hex = result_hex
                .get(..128.min(result_hex.len()))
                .unwrap_or(result_hex.as_str());
            println!("signature: {sig_hex}");
        }
    }

    Ok(())
}

/// Build the JSON object for a probe response. Prints nothing.
fn probe_output(hash_type: &str, response: &[u8]) -> ProbeOutput {
    // For Ed25519 the first 64 bytes are the signature. The rest is the content.
    let (signature, content) = match response.split_at_checked(64) {
        Some((sig, content)) if hash_type == "Ed25519" && !content.is_empty() => {
            (Some(hex::encode(sig)), Some(hex::encode(content)))
        }
        _ => (None, None),
    };
    ProbeOutput {
        hash_type: hash_type.to_owned(),
        response: hex::encode(response),
        signature,
        content,
    }
}

/// Convert a probe hash type to the canonical form that the device expects.
///
/// Matching is not case-sensitive. Returns `None` for unknown hash types.
fn normalize_hash_type(hash_type: &str) -> Option<&'static str> {
    match hash_type.to_lowercase().as_str() {
        "sha256" => Some("SHA256"),
        "sha512" => Some("SHA512"),
        "rsa2048" => Some("RSA2048"),
        "ed25519" => Some("Ed25519"),
        _ => None,
    }
}

/// The relying party id that `sign-file` uses. `verify-file` checks the rpIdHash against it.
pub const SIGN_FILE_RP_ID: &str = "solokeys.dev";

/// Sign a file using CTAP2 getAssertion with the file's SHA-256 as clientDataHash.
///
/// Protocol:
///   1. SHA-256 the file contents → clientDataHash
///   2. getAssertion (0x02) with `rp_id`, clientDataHash, allowList[`credential_id`]
///   3. Extract authData (key 0x02) and signature (key 0x03) from the CBOR response
///   4. Save raw signature bytes to `{filename}.sig`
///   5. Save raw authData bytes to `{filename}.authdata`
///   6. Print signature hex to stdout (with `json`: one JSON object, see [`SignFileOutput`])
///
/// With `json`, stdout holds only the JSON object. The hash line, the button
/// prompt and the "Saving" lines go to stderr.
///
/// The key does not sign the file hash alone. It signs `authData || SHA-256(file)`
/// with ECDSA over P-256 and SHA-256 (ES256). To check a signature, a verifier
/// needs the file, both output files and the public key of the credential.
/// `credential create --public-key-out` saves that public key.
///
/// # Errors
/// Returns an error if `credential_id` is not valid hex, if the file cannot be
/// read, if the getAssertion request fails, if the response is missing the
/// authData or the signature (no file is written then), or if writing the
/// `.sig` or `.authdata` file fails.
pub fn cmd_sign_file(hid: &impl HidDevice, credential_id: &str, filename: &Path, json: bool) -> Result<()> {
    use ciborium::value::Value;

    // Decode the hex credential ID. `cmd_challenge_response` does the same.
    let cred_id_bytes = hex::decode(credential_id).map_err(SoloError::InvalidHex)?;

    // Read the file. Use its SHA-256 hash as the clientDataHash.
    let data = std::fs::read(filename)?;
    let file_hash: Vec<u8> = Sha256::digest(&data).to_vec();

    progress(json, &format!("{}  {}", hex::encode(&file_hash), filename.display()));
    progress(json, "Please press the button on your Solo key");

    // Build the CTAP2 getAssertion CBOR request map:
    //   0x01: rpId  (must be the same rp that made the credential)
    //   0x02: clientDataHash  (SHA-256 of file)
    //   0x03: allowList  [{type: "public-key", id: cred_id_bytes}]
    let rp_id = SIGN_FILE_RP_ID;
    let get_assertion_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Text(rp_id.into())),
        (Value::Integer(0x02u64.into()), Value::Bytes(file_hash.clone())),
        (
            Value::Integer(0x03u64.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("id".into()), Value::Bytes(cred_id_bytes)),
            ])]),
        ),
    ]);

    // CTAP2 getAssertion (0x02)
    let ga_response = solo_ctap2::ctap2_call(hid, 0x02, &get_assertion_cbor)?;
    check_ga_response(&ga_response, filename, &file_hash, json)
}

/// Return `path` with `suffix` added at the end of the file name (`file.bin` and `.sig` give `file.bin.sig`).
#[must_use]
pub fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(suffix);
    std::path::PathBuf::from(p)
}

/// Print `line` to stdout, or to stderr in JSON mode so that stdout holds only the JSON object.
fn progress(json: bool, line: &str) {
    if json {
        eprintln!("{line}");
    } else {
        println!("{line}");
    }
}

/// Build the JSON object for a signed file. Prints nothing.
fn sign_file_output(file_hash: &[u8], signature: &[u8], filename: &Path) -> SignFileOutput {
    SignFileOutput {
        file_hash: hex::encode(file_hash),
        signature: hex::encode(signature),
        signature_file: with_suffix(filename, ".sig").display().to_string(),
        authdata_file: with_suffix(filename, ".authdata").display().to_string(),
    }
}

fn check_ga_response(ga_response: &[u8], filename: &Path, file_hash: &[u8], json: bool) -> Result<()> {
    use ciborium::value::Value;
    use solo_ctap2::cbor::find_int_key;

    let ga_pairs = solo_ctap2::parse_cbor_map_response(ga_response, "getAssertion")?;

    // 0x02: authData bytes. The signature covers them, so a verifier needs them.
    let Some(Value::Bytes(auth_data)) = find_int_key(&ga_pairs, 0x02) else {
        return Err(SoloError::MalformedResponse(
            "getAssertion response missing authData (key 0x02)".into(),
        ));
    };

    // 0x03: signature bytes
    let signature = match find_int_key(&ga_pairs, 0x03) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => {
            return Err(SoloError::MalformedResponse(
                "getAssertion response missing signature (key 0x03)".into(),
            ));
        }
    };

    // Save raw signature to {filename}.sig
    let sig_path = with_suffix(filename, ".sig");
    progress(json, &format!("Saving signature to {}", sig_path.display()));
    std::fs::write(&sig_path, &signature)?;

    // Save raw authData to {filename}.authdata
    let authdata_path = with_suffix(filename, ".authdata");
    progress(
        json,
        &format!("Saving authenticator data to {}", authdata_path.display()),
    );
    std::fs::write(&authdata_path, auth_data)?;

    // Print hex signature (or the JSON object) to stdout
    if json {
        print_json(&sign_file_output(file_hash, &signature, filename))?;
    } else {
        println!("{}", hex::encode(&signature));
    }

    Ok(())
}

#[cfg(test)]
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
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_normalize_hash_type_known_types() {
        let cases: &[(&str, &str)] = &[
            ("sha256", "SHA256"),
            ("SHA256", "SHA256"),
            ("Sha256", "SHA256"),
            ("sha512", "SHA512"),
            ("SHA512", "SHA512"),
            ("rsa2048", "RSA2048"),
            ("RSA2048", "RSA2048"),
            ("ed25519", "Ed25519"),
            ("Ed25519", "Ed25519"),
            ("ED25519", "Ed25519"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                normalize_hash_type(input),
                Some(*expected),
                "hash type '{input}' should normalize to '{expected}'"
            );
        }
    }

    #[test]
    fn test_normalize_hash_type_unknown_types() {
        for input in ["md5", "sha1", "blake3", ""] {
            assert_eq!(
                normalize_hash_type(input),
                None,
                "hash type '{input}' should be rejected"
            );
        }
    }

    /// `cmd_probe` must reject an unknown hash type before touching the file or device.
    #[test]
    fn test_cmd_probe_rejects_unknown_hash_type() {
        use solo_ctaphid::mock::MockDevice;
        // Empty queue: any device call would return Timeout, not DeviceError.
        let device = MockDevice::new(vec![]);
        let err = cmd_probe(&device, "md5", Path::new("/nonexistent"), false).unwrap_err();
        assert!(matches!(err, SoloError::DeviceError(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("Unknown hash type"));
    }

    /// Build a getAssertion response (status 0x00) with the given optional fields.
    fn ga_response(auth_data: Option<&[u8]>, signature: Option<&[u8]>) -> Vec<u8> {
        use ciborium::value::Value;
        let mut pairs = Vec::new();
        if let Some(a) = auth_data {
            pairs.push((Value::Integer(0x02u64.into()), Value::Bytes(a.to_vec())));
        }
        if let Some(s) = signature {
            pairs.push((Value::Integer(0x03u64.into()), Value::Bytes(s.to_vec())));
        }
        let mut out = vec![0x00u8];
        ciborium::ser::into_writer(&Value::Map(pairs), &mut out).unwrap();
        out
    }

    #[test]
    fn test_check_ga_response_ok() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        std::fs::write(&path, b"test data\n").unwrap();

        let auth_data = [0x11u8; 37];
        let result = check_ga_response(
            &ga_response(Some(&auth_data), Some(&[0xAA, 0xBB])),
            &path,
            &[0; 32],
            false,
        );
        assert!(result.is_ok());

        assert_eq!(std::fs::read(with_suffix(&path, ".sig")).unwrap(), vec![0xAA, 0xBB]);
        assert_eq!(
            std::fs::read(with_suffix(&path, ".authdata")).unwrap(),
            auth_data.to_vec()
        );
    }

    #[test]
    fn test_check_ga_response_missing_authdata_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        let err = check_ga_response(&ga_response(None, Some(&[0xAA])), &path, &[0; 32], false).unwrap_err();
        assert!(
            matches!(err, SoloError::MalformedResponse(_)),
            "unexpected error: {err}"
        );
        assert!(!with_suffix(&path, ".sig").exists());
        assert!(!with_suffix(&path, ".authdata").exists());
    }

    #[test]
    fn test_check_ga_response_missing_signature_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        let err = check_ga_response(&ga_response(Some(&[0x11; 37]), None), &path, &[0; 32], false).unwrap_err();
        assert!(
            matches!(err, SoloError::MalformedResponse(_)),
            "unexpected error: {err}"
        );
        assert!(!with_suffix(&path, ".sig").exists());
        assert!(!with_suffix(&path, ".authdata").exists());
    }

    #[test]
    fn test_check_ga_response_error_status() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        let ga_response = vec![0x01u8]; // error status
        let result = check_ga_response(&ga_response, path, &[0; 32], false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SoloError::AuthenticatorError { code: 0x01, .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_sign_file_output_fields() {
        let out = sign_file_output(&[0x01, 0x02], &[0xAA, 0xBB], Path::new("dir/file.bin"));
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "file_hash": "0102",
                "signature": "aabb",
                "signature_file": "dir/file.bin.sig",
                "authdata_file": "dir/file.bin.authdata",
            })
        );
    }

    #[test]
    fn test_probe_output_ed25519_splits_signature_and_content() {
        let mut response = vec![0xAA; 64];
        response.extend_from_slice(b"hi");
        let v = serde_json::to_value(probe_output("Ed25519", &response)).unwrap();
        assert_eq!(v["hash_type"], "Ed25519");
        assert_eq!(v["response"], hex::encode(&response));
        assert_eq!(v["signature"], "aa".repeat(64));
        assert_eq!(v["content"], "6869");
    }

    #[test]
    fn test_probe_output_without_content_or_other_hash_has_only_response() {
        // Ed25519 with exactly 64 bytes: no content, so the text mode prints no signature line either.
        for (hash_type, response) in [("Ed25519", vec![0xAA; 64]), ("SHA256", vec![0xBB; 100])] {
            let v = serde_json::to_value(probe_output(hash_type, &response)).unwrap();
            assert_eq!(v["response"], hex::encode(&response));
            assert!(
                v.get("signature").is_none() && v.get("content").is_none(),
                "{hash_type}"
            );
        }
    }
}
