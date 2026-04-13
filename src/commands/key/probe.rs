use std::path::Path;

use sha2::{Digest, Sha256};

use crate::device::{SoloHid, CMD_PROBE, CTAPHID_CBOR};
use crate::error::{Result, SoloError};

/// Run a hash probe on the device.
///
/// Sends a CBOR-encoded command to CMD_PROBE (0x70):
///   {"subcommand": hash_type_str, "data": file_bytes}
///
/// Valid hash types (case-insensitive input, sent as canonical form):
///   SHA256, SHA512, RSA2048, Ed25519
///
/// File must be <= 6144 bytes.
pub fn cmd_probe(hid: &SoloHid, hash_type: &str, filename: &Path) -> Result<()> {
    // Normalize hash type to the canonical form expected by the device
    let hash_type_str = match hash_type.to_lowercase().as_str() {
        "sha256" => "SHA256",
        "sha512" => "SHA512",
        "rsa2048" => "RSA2048",
        "ed25519" => "Ed25519",
        other => {
            return Err(SoloError::DeviceError(format!(
                "Unknown hash type: {}. Valid: SHA256, SHA512, RSA2048, Ed25519",
                other
            )))
        }
    };

    let file_bytes = std::fs::read(filename)?;
    if file_bytes.len() > 6 * 1024 {
        return Err(SoloError::DeviceError(format!(
            "File too large: {} bytes (max 6144)",
            file_bytes.len()
        )));
    }

    // CBOR-encode: {"subcommand": hash_type_str, "data": file_bytes}
    use ciborium::value::Value;
    let cbor_val = Value::Map(vec![
        (
            Value::Text("subcommand".into()),
            Value::Text(hash_type_str.into()),
        ),
        (Value::Text("data".into()), Value::Bytes(file_bytes)),
    ]);
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&cbor_val, &mut cbor_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let response = hid.send_recv(CMD_PROBE, &cbor_bytes)?;
    let result_hex = hex::encode(&response);
    println!("{}", result_hex);

    if hash_type_str == "Ed25519" {
        // First 64 bytes = signature (128 hex chars), rest = content
        if response.len() > 64 {
            println!("content: {:?}", &response[64..]);
            println!("content from hex: {:?}", &response[64..]);
            println!("signature: {}", &result_hex[..128.min(result_hex.len())]);
        }
    }

    Ok(())
}

/// Sign a file using CTAP2 getAssertion with the file's SHA-256 as clientDataHash.
///
/// Protocol:
///   1. SHA-256 the file contents → clientDataHash
///   2. getAssertion (0x02) with rp_id, clientDataHash, allowList[credential_id]
///   3. Extract signature (key 0x03) from the CBOR response
///   4. Save raw signature bytes to `{filename}.sig`
///   5. Print signature hex to stdout
pub fn cmd_sign_file(hid: &SoloHid, credential_id: &str, filename: &Path) -> Result<()> {
    use ciborium::value::Value;

    // Decode hex credential ID (same convention as cmd_challenge_response)
    let cred_id_bytes = hex::decode(credential_id)
        .map_err(|e| SoloError::DeviceError(format!("Invalid credential_id hex: {}", e)))?;

    // Read file and compute SHA-256 → use directly as clientDataHash
    let data = std::fs::read(filename)?;
    let file_hash: Vec<u8> = Sha256::digest(&data).to_vec();

    println!("{}  {}", hex::encode(&file_hash), filename.display());
    println!("Please press the button on your Solo key");

    // Build CTAP2 getAssertion CBOR request map:
    //   0x01: rpId  (must match the rp used at credential creation)
    //   0x02: clientDataHash  (SHA-256 of file)
    //   0x03: allowList  [{type: "public-key", id: cred_id_bytes}]
    let rp_id = "solokeys.dev";
    let get_assertion_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Text(rp_id.into())),
        (Value::Integer(0x02u64.into()), Value::Bytes(file_hash)),
        (
            Value::Integer(0x03u64.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("id".into()), Value::Bytes(cred_id_bytes)),
            ])]),
        ),
    ]);

    let mut ga_bytes = vec![0x02u8]; // CTAP2 getAssertion command byte
    ciborium::ser::into_writer(&get_assertion_cbor, &mut ga_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let ga_response = hid.send_recv(CTAPHID_CBOR, &ga_bytes)?;

    if ga_response.is_empty() {
        return Err(SoloError::DeviceError(
            "Empty response from getAssertion".into(),
        ));
    }
    let ga_status = ga_response[0];
    if ga_status != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "getAssertion returned CTAP error 0x{:02X}",
            ga_status
        )));
    }

    // Parse CBOR response map
    let ga_val: Value = ciborium::de::from_reader(&ga_response[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;

    let ga_pairs = match ga_val {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "getAssertion response is not a map".into(),
            ))
        }
    };

    let get_ga_key = |key: u64| -> Option<&Value> {
        ga_pairs.iter().find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == key {
                    Some(v)
                } else {
                    None
                }
            } else {
                None
            }
        })
    };

    // 0x03: signature bytes
    let signature = match get_ga_key(0x03) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => {
            return Err(SoloError::DeviceError(
                "getAssertion response missing signature (key 0x03)".into(),
            ))
        }
    };

    // Save raw signature to {filename}.sig
    let sig_path = {
        let mut p = filename.as_os_str().to_owned();
        p.push(".sig");
        std::path::PathBuf::from(p)
    };
    println!("Saving signature to {}", sig_path.display());
    std::fs::write(&sig_path, &signature)?;

    // Print hex signature to stdout
    println!("{}", hex::encode(&signature));

    Ok(())
}
