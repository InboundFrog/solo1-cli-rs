use crate::cbor::{cbor_bytes, cbor_int, cbor_text, find_int_key, int_map};
use crate::ctap2::{parse_cbor_map_response, prompt_and_get_pin_token};
use crate::device::{SoloHid, CTAPHID_CBOR};
use crate::error::{Result, SoloError};
use sha2::{Digest, Sha256};

/// Verify key authenticity via attestation certificate.
///
/// Sends a CTAP2 makeCredential (0x01) request via CTAPHID_CBOR, extracts the
/// DER-encoded attestation certificate from attStmt.x5c[0], SHA-256 fingerprints
/// it, and compares against known fingerprints in crypto.rs.
pub fn cmd_verify(hid: &SoloHid) -> Result<()> {
    use crate::crypto::{check_attestation_fingerprint, sha256_hex};
    use ciborium::value::Value;
    use hmac::{Hmac, KeyInit as _, Mac as _};

    // clientDataHash: fixed 32-byte value (Solo does not verify it for attestation)
    let client_data_hash: Vec<u8> = Sha256::digest(b"solokeys_verify_test").to_vec();

    // If a PIN is set, acquire a PIN token and compute pinUvAuthParam.
    let pin_uv_auth: Option<Vec<u8>> = if crate::ctap2::get_info_client_pin_set(hid)? {
        let pin_token = prompt_and_get_pin_token(hid)?;

        // pinUvAuthParam = HMAC-SHA-256(pinToken, clientDataHash)[0..16]
        let mut mac = Hmac::<Sha256>::new_from_slice(&pin_token)
            .map_err(|e| SoloError::DeviceError(format!("HMAC key error: {}", e)))?;
        mac.update(&client_data_hash);
        let hmac_result = mac.finalize().into_bytes();
        Some(hmac_result[..16].to_vec())
    } else {
        None
    };

    println!("Please press the button on your Solo key");

    // Build CTAP2 makeCredential CBOR request map (integer keys per CTAP2 spec):
    //   0x01: clientDataHash
    //   0x02: rp  {"id": "solokeys.com", "name": "solokeys.com"}
    //   0x03: user {"id": b"verify", "name": "verify", "displayName": "verify"}
    //   0x04: pubKeyCredParams [{"alg": -7, "type": "public-key"}]
    //   0x08: pinUvAuthParam (if PIN is set)
    //   0x09: pinUvAuthProtocol = 1 (if PIN is set)
    let mut cbor_entries: Vec<(i64, Value)> = vec![
        (0x01, cbor_bytes(client_data_hash)),
        (
            0x02,
            Value::Map(vec![
                (cbor_text("id"), cbor_text("solokeys.com")),
                (cbor_text("name"), cbor_text("solokeys.com")),
            ]),
        ),
        (
            0x03,
            Value::Map(vec![
                (cbor_text("id"), cbor_bytes(b"verify".to_vec())),
                (cbor_text("name"), cbor_text("verify")),
                (cbor_text("displayName"), cbor_text("verify")),
            ]),
        ),
        (
            0x04,
            Value::Array(vec![Value::Map(vec![
                (cbor_text("alg"), cbor_int(-7)),
                (cbor_text("type"), cbor_text("public-key")),
            ])]),
        ),
    ];
    if let Some(auth_param) = pin_uv_auth {
        cbor_entries.push((0x08, cbor_bytes(auth_param)));
        cbor_entries.push((0x09, cbor_int(1)));
    }
    let cbor_request = int_map(cbor_entries);

    // Prepend CTAP2 command byte 0x01 (makeCredential) before the CBOR payload
    let mut request_bytes = vec![0x01u8];
    ciborium::ser::into_writer(&cbor_request, &mut request_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let response = hid.send_recv(CTAPHID_CBOR, &request_bytes)?;

    // First byte is CTAP2 status code; 0x00 = success
    let pairs = parse_cbor_map_response(&response, "makeCredential")?;

    // 0x03: attStmt map — contains "x5c" array of DER-encoded certs
    let att_stmt = match find_int_key(&pairs, 0x03) {
        Some(Value::Map(m)) => m,
        _ => {
            return Err(SoloError::DeviceError(
                "makeCredential response missing attStmt (key 0x03)".into(),
            ))
        }
    };

    // Find "x5c" key inside attStmt
    let x5c = att_stmt.iter().find_map(|(k, v)| {
        if let Value::Text(s) = k {
            if s == "x5c" {
                return Some(v);
            }
        }
        None
    });

    let cert_der = match x5c {
        Some(Value::Array(certs)) if !certs.is_empty() => match &certs[0] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(SoloError::DeviceError("x5c[0] is not bytes".into())),
        },
        _ => return Err(SoloError::DeviceError("attStmt missing x5c array".into())),
    };

    let fingerprint = sha256_hex(&cert_der);
    println!("Attestation certificate SHA-256: {}", fingerprint);

    use crate::crypto::AttestationResult;
    match check_attestation_fingerprint(&cert_der) {
        AttestationResult::GenuineConsumer(name) => {
            println!("OK: Genuine SoloKeys device: {}", name);
        }
        AttestationResult::DeveloperDevice(name) => {
            println!(
                "WARNING: Developer/non-production device: {}. Not a genuine consumer key.",
                name
            );
        }
        AttestationResult::Unknown => {
            println!(
                "FAILED: Could not verify device authenticity. Certificate fingerprint not recognised."
            );
        }
    }

    Ok(())
}
