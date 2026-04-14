use crate::ctap2::{find_cbor_response_by_key, get_pin_token, parse_cbor_map_response};
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
        let pin = rpassword::prompt_password("PIN: ").map_err(|e| SoloError::IoError(e))?;
        if pin.len() < 4 {
            return Err(SoloError::DeviceError(
                "PIN must be at least 4 characters".into(),
            ));
        }

        let pin_token = get_pin_token(hid, &pin)?;

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
    let mut cbor_pairs = vec![
        (
            Value::Integer(0x01u64.into()),
            Value::Bytes(client_data_hash),
        ),
        (
            Value::Integer(0x02u64.into()),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Text("solokeys.com".into())),
                (
                    Value::Text("name".into()),
                    Value::Text("solokeys.com".into()),
                ),
            ]),
        ),
        (
            Value::Integer(0x03u64.into()),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Bytes(b"verify".to_vec())),
                (Value::Text("name".into()), Value::Text("verify".into())),
                (
                    Value::Text("displayName".into()),
                    Value::Text("verify".into()),
                ),
            ]),
        ),
        (
            Value::Integer(0x04u64.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer((-7i64).into())),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ])]),
        ),
    ];
    if let Some(auth_param) = pin_uv_auth {
        cbor_pairs.push((Value::Integer(0x08u64.into()), Value::Bytes(auth_param)));
        cbor_pairs.push((Value::Integer(0x09u64.into()), Value::Integer(1u64.into())));
    }
    let cbor_request = Value::Map(cbor_pairs);

    // Prepend CTAP2 command byte 0x01 (makeCredential) before the CBOR payload
    let mut request_bytes = vec![0x01u8];
    ciborium::ser::into_writer(&cbor_request, &mut request_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let response = hid.send_recv(CTAPHID_CBOR, &request_bytes)?;

    // First byte is CTAP2 status code; 0x00 = success
    let pairs = parse_cbor_map_response(&response, "makeCredential")?;

    // 0x03: attStmt map — contains "x5c" array of DER-encoded certs
    let att_stmt = match find_cbor_response_by_key(&pairs, 0x03) {
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

    match check_attestation_fingerprint(&cert_der) {
        Some(msg) => {
            println!("Valid Solo key: {}", msg);
        }
        None => {
            println!("Unknown fingerprint — this key may not be genuine SoloKeys hardware.");
        }
    }

    Ok(())
}
