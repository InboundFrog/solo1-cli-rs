use std::io::Write;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Result, SoloError};
use crate::output::{ProbeOutput, SignFileOutput, write_json};
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
/// With `json`, writes one JSON object (see [`ProbeOutput`]) to `out` instead of the text.
///
/// # Errors
/// Returns an error if `hash_type` is not a recognised hash type, if the file
/// cannot be read, if the file exceeds 6144 bytes, if the device request
/// fails, or if writing to `out` fails.
pub fn cmd_probe(
    hid: &impl HidDevice,
    hash_type: &str,
    filename: &Path,
    json: bool,
    out: &mut impl Write,
) -> Result<()> {
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
        return write_json(out, &probe_output(hash_type_str, &response));
    }
    writeln!(out, "{result_hex}")?;

    if hash_type_str == "Ed25519" {
        // The first 64 bytes are the signature (128 hex characters). The rest is the content.
        if response.len() > 64 {
            let content = response
                .get(64..)
                .ok_or_else(|| SoloError::ProtocolError("Probe response too short".into()))?;
            writeln!(out, "content: {content:?}")?;
            let sig_hex = result_hex
                .get(..128.min(result_hex.len()))
                .unwrap_or(result_hex.as_str());
            writeln!(out, "signature: {sig_hex}")?;
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

/// The relying party id that `sign-file` and `verify-file` use when `--host` is not given.
pub const SIGN_FILE_RP_ID: &str = "solokeys.dev";

/// Sign a file using CTAP2 getAssertion with the file's SHA-256 as clientDataHash.
///
/// Protocol:
///   1. SHA-256 the file contents → clientDataHash
///   2. getAssertion (0x02) with `host` as the rpId, clientDataHash, allowList[`credential_id`]
///   3. Extract authData (key 0x02) and signature (key 0x03) from the CBOR response
///   4. Save raw signature bytes to `{filename}.sig`
///   5. Save raw authData bytes to `{filename}.authdata`
///   6. Print signature hex to stdout (with `json`: one JSON object, see [`SignFileOutput`])
///
/// The result goes to `out` (stdout in the program). With `json`, `out` holds only
/// the JSON object, and the hash line, the button prompt and the "Saving" lines go
/// to `err` (stderr in the program) instead.
///
/// The key does not sign the file hash alone. It signs `authData || SHA-256(file)`
/// with ECDSA over P-256 and SHA-256 (ES256). To check a signature, a verifier
/// needs the file, both output files and the public key of the credential.
/// `credential create --public-key-out` saves that public key.
///
/// `host` is the rpId. It must be the rpId that the credential was made with.
///
/// # Errors
/// Returns an error if `credential_id` is not valid hex, if the file cannot be
/// read, if the getAssertion request fails, if the response is missing the
/// authData or the signature (no file is written then), or if writing the
/// `.sig` or `.authdata` file fails.
pub fn cmd_sign_file(
    hid: &impl HidDevice,
    credential_id: &str,
    host: &str,
    filename: &Path,
    json: bool,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<()> {
    use ciborium::value::Value;

    // Decode the hex credential ID. `cmd_challenge_response` does the same.
    let cred_id_bytes = hex::decode(credential_id).map_err(SoloError::InvalidHex)?;

    // Read the file. Use its SHA-256 hash as the clientDataHash.
    let file_hash = sha256_file(filename)?.to_vec();

    let hash_line = format!("{}  {}", hex::encode(&file_hash), filename.display());
    progress(json, out, err, &hash_line)?;
    progress(json, out, err, "Please press the button on your Solo key")?;

    // Build the CTAP2 getAssertion CBOR request map:
    //   0x01: rpId  (must be the same rp that made the credential)
    //   0x02: clientDataHash  (SHA-256 of file)
    //   0x03: allowList  [{type: "public-key", id: cred_id_bytes}]
    let get_assertion_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Text(host.into())),
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
    check_ga_response(&ga_response, filename, &file_hash, json, out, err)
}

/// SHA-256 of a file, hashed in blocks so that the file is never held in memory.
///
/// # Errors
/// Returns the I/O error if the file cannot be opened or read.
pub fn sha256_file(path: &Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut block = [0_u8; 8 * 1024];
    loop {
        let n = match file.read(&mut block) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(block.get(..n).unwrap_or_default());
    }
    Ok(hasher.finalize().into())
}

/// Return `path` with `suffix` added at the end of the file name (`file.bin` and `.sig` give `file.bin.sig`).
#[must_use]
pub fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(suffix);
    std::path::PathBuf::from(p)
}

/// Write `line` to `out`, or to `err` in JSON mode so that `out` holds only the JSON object.
fn progress(json: bool, out: &mut impl Write, err: &mut impl Write, line: &str) -> Result<()> {
    if json {
        writeln!(err, "{line}")?;
    } else {
        writeln!(out, "{line}")?;
    }
    Ok(())
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

fn check_ga_response(
    ga_response: &[u8],
    filename: &Path,
    file_hash: &[u8],
    json: bool,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<()> {
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
    progress(json, out, err, &format!("Saving signature to {}", sig_path.display()))?;
    std::fs::write(&sig_path, &signature)?;

    // Save raw authData to {filename}.authdata
    let authdata_path = with_suffix(filename, ".authdata");
    progress(
        json,
        out,
        err,
        &format!("Saving authenticator data to {}", authdata_path.display()),
    )?;
    std::fs::write(&authdata_path, auth_data)?;

    // Print hex signature (or the JSON object) to stdout
    if json {
        write_json(out, &sign_file_output(file_hash, &signature, filename))?;
    } else {
        writeln!(out, "{}", hex::encode(&signature))?;
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
    fn sha256_file_matches_the_hash_of_the_bytes_for_a_file_larger_than_one_block() {
        // The file has many blocks and one partial block.
        let data: Vec<u8> = (0..(100 * 1024 + 123_u32)).map(|i| (i % 251) as u8).collect();
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(&data).unwrap();
        assert_eq!(
            sha256_file(f.path()).unwrap().as_slice(),
            Sha256::digest(&data).as_slice()
        );
    }

    #[test]
    fn sha256_file_of_a_missing_file_is_an_error() {
        assert!(sha256_file(Path::new("/nonexistent/solo-test-file")).is_err());
    }

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
        let err = cmd_probe(&device, "md5", Path::new("/nonexistent"), false, &mut Vec::new()).unwrap_err();
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
            &mut Vec::new(),
            &mut Vec::new(),
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
        let err = check_ga_response(
            &ga_response(None, Some(&[0xAA])),
            &path,
            &[0; 32],
            false,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
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
        let err = check_ga_response(
            &ga_response(Some(&[0x11; 37]), None),
            &path,
            &[0; 32],
            false,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
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
        let result = check_ga_response(&ga_response, path, &[0; 32], false, &mut Vec::new(), &mut Vec::new());
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

    /// Run `cmd_sign_file` against a mock key. Returns what went to stdout and to stderr.
    fn run_sign_file(json: bool, path: &Path) -> (String, String) {
        use solo_ctaphid::mock::MockDevice;
        let device = MockDevice::new(vec![Ok(ga_response(Some(&[0x11; 37]), Some(&[0xAA, 0xBB])))]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        cmd_sign_file(&device, "abcd", SIGN_FILE_RP_ID, path, json, &mut out, &mut err).unwrap();
        (String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    /// A device that keeps the data of the last request that it got.
    struct Recorder(std::cell::RefCell<Vec<u8>>, Vec<u8>);

    impl HidDevice for Recorder {
        fn send_recv(&self, _cmd: u8, data: &[u8]) -> solo_ctaphid::Result<Vec<u8>> {
            *self.0.borrow_mut() = data.to_vec();
            Ok(self.1.clone())
        }

        fn send(&self, _cmd: u8, _data: &[u8]) -> solo_ctaphid::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_sign_file_sends_the_given_host_as_rp_id() {
        use ciborium::value::Value;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        std::fs::write(&path, b"test data\n").unwrap();
        for host in ["example.com", SIGN_FILE_RP_ID] {
            let device = Recorder(
                std::cell::RefCell::default(),
                ga_response(Some(&[0x11; 37]), Some(&[0xAA])),
            );
            cmd_sign_file(&device, "abcd", host, &path, false, &mut Vec::new(), &mut Vec::new()).unwrap();
            let sent = device.0.borrow();
            // The first byte is the CTAP2 command number, the rest is the CBOR request.
            let request: Value = ciborium::de::from_reader(&sent[1..]).unwrap();
            let Value::Map(pairs) = request else {
                panic!("not a map")
            };
            let rp_id = pairs.iter().find(|(k, _)| *k == Value::Integer(1u64.into())).unwrap();
            assert_eq!(rp_id.1, Value::Text(host.into()));
        }
    }

    #[test]
    fn test_sign_file_json_stdout_is_one_object_and_progress_goes_to_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        std::fs::write(&path, b"test data\n").unwrap();
        let (out, err) = run_sign_file(true, &path);

        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["signature"], "aabb");
        assert_eq!(v["file_hash"], hex::encode(Sha256::digest(b"test data\n")));
        assert_eq!(v.as_object().unwrap().len(), 4);
        assert!(err.contains("Please press the button on your Solo key"), "{err}");
        assert!(err.contains("Saving signature to "), "{err}");
        assert!(err.contains("Saving authenticator data to "), "{err}");
    }

    #[test]
    fn test_sign_file_text_output_is_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        std::fs::write(&path, b"test data\n").unwrap();
        let (out, err) = run_sign_file(false, &path);

        let hash = hex::encode(Sha256::digest(b"test data\n"));
        let expected = format!(
            "{hash}  {p}\nPlease press the button on your Solo key\nSaving signature to {p}.sig\nSaving authenticator data to {p}.authdata\naabb\n",
            p = path.display()
        );
        assert_eq!(out, expected);
        assert_eq!(err, "");
    }

    #[test]
    fn test_probe_json_stdout_is_one_object() {
        use solo_ctaphid::mock::MockDevice;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("in.bin");
        std::fs::write(&path, b"x").unwrap();
        let mut response = vec![0xAA; 64];
        response.extend_from_slice(b"hi");
        let device = MockDevice::new(vec![Ok(response.clone())]);
        let mut out = Vec::new();
        cmd_probe(&device, "ed25519", &path, true, &mut out).unwrap();

        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["hash_type"], "Ed25519");
        assert_eq!(v["response"], hex::encode(&response));
        assert_eq!(v["content"], "6869");
    }

    #[test]
    fn test_probe_text_output_is_unchanged() {
        use solo_ctaphid::mock::MockDevice;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("in.bin");
        std::fs::write(&path, b"x").unwrap();
        let mut response = vec![0xAA; 64];
        response.extend_from_slice(b"hi");
        let device = MockDevice::new(vec![Ok(response.clone())]);
        let mut out = Vec::new();
        cmd_probe(&device, "ed25519", &path, false, &mut out).unwrap();

        let hex_all = hex::encode(&response);
        let expected = format!("{hex_all}\ncontent: [104, 105]\nsignature: {}\n", "aa".repeat(64));
        assert_eq!(String::from_utf8(out).unwrap(), expected);
    }
}
