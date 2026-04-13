use sha2::{Digest, Sha256};

use crate::device::{SoloHid, CTAPHID_CBOR};
use crate::error::{Result, SoloError};

/// Verify key authenticity via attestation certificate.
///
/// Sends a CTAP2 makeCredential (0x01) request via CTAPHID_CBOR, extracts the
/// DER-encoded attestation certificate from attStmt.x5c[0], SHA-256 fingerprints
/// it, and compares against known fingerprints in crypto.rs.
pub fn cmd_verify(hid: &SoloHid) -> Result<()> {
    use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    use ciborium::value::Value;
    use crate::crypto::{check_attestation_fingerprint, sha256_hex};
    use hmac::{Hmac, Mac};
    use p256::ecdh::EphemeralSecret;
    use p256::EncodedPoint;
    use rand::rngs::OsRng;

    // clientDataHash: fixed 32-byte value (Solo does not verify it for attestation)
    let client_data_hash: Vec<u8> = Sha256::digest(b"solokeys_verify_test").to_vec();

    // If a PIN is set, acquire a PIN token and compute pinUvAuthParam.
    let pin_uv_auth: Option<Vec<u8>> = if super::credential::get_info_client_pin_set(hid)? {
        let pin = rpassword::prompt_password("PIN: ")
            .map_err(|e| SoloError::IoError(e))?;
        if pin.len() < 4 {
            return Err(SoloError::DeviceError("PIN must be at least 4 characters".into()));
        }

        // getKeyAgreement (clientPIN 0x06, subcommand 0x02)
        let get_ka_cbor = Value::Map(vec![
            (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())),
            (Value::Integer(0x02u64.into()), Value::Integer(2u64.into())),
        ]);
        let mut ka_req = vec![0x06u8];
        ciborium::ser::into_writer(&get_ka_cbor, &mut ka_req)
            .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;
        let ka_resp = hid.send_recv(CTAPHID_CBOR, &ka_req)?;
        if ka_resp.is_empty() || ka_resp[0] != 0x00 {
            return Err(SoloError::DeviceError(format!(
                "getKeyAgreement failed: 0x{:02X}", ka_resp.first().copied().unwrap_or(0xFF)
            )));
        }
        let ka_val: Value = ciborium::de::from_reader(&ka_resp[1..])
            .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;
        let ka_pairs = match ka_val {
            Value::Map(p) => p,
            _ => return Err(SoloError::DeviceError("getKeyAgreement response is not a map".into())),
        };
        let key_agreement = ka_pairs
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(i) = k {
                    let ki: u64 = (*i).try_into().ok()?;
                    if ki == 0x01 { Some(v) } else { None }
                } else { None }
            })
            .ok_or_else(|| SoloError::DeviceError("keyAgreement missing from response".into()))?;
        let cose_pairs = match key_agreement {
            Value::Map(p) => p,
            _ => return Err(SoloError::DeviceError("keyAgreement is not a CBOR map".into())),
        };
        let get_coord = |key: i64| -> Result<Vec<u8>> {
            cose_pairs
                .iter()
                .find_map(|(k, v)| {
                    if let Value::Integer(i) = k {
                        let ki: i64 = (*i).try_into().ok()?;
                        if ki == key {
                            if let Value::Bytes(b) = v { Some(b.clone()) } else { None }
                        } else { None }
                    } else { None }
                })
                .ok_or_else(|| SoloError::DeviceError(format!("COSE key missing coordinate {}", key)))
        };
        let dev_x = get_coord(-2)?;
        let dev_y = get_coord(-3)?;
        if dev_x.len() != 32 || dev_y.len() != 32 {
            return Err(SoloError::DeviceError("Device COSE key coordinates are not 32 bytes".into()));
        }
        let mut uncompressed = vec![0x04u8];
        uncompressed.extend_from_slice(&dev_x);
        uncompressed.extend_from_slice(&dev_y);
        let dev_pub_key = p256::PublicKey::from_sec1_bytes(&uncompressed)
            .map_err(|e| SoloError::DeviceError(format!("Invalid device public key: {}", e)))?;

        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let ephemeral_pub = p256::PublicKey::from(&ephemeral_secret);
        let ephemeral_point = EncodedPoint::from(&ephemeral_pub);
        let shared_secret_point = ephemeral_secret.diffie_hellman(&dev_pub_key);
        let shared_secret: [u8; 32] = Sha256::digest(shared_secret_point.raw_secret_bytes()).into();

        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

        // pinHashEnc = AES-256-CBC(shared_secret, IV=0, SHA-256(pin)[0..16])
        let pin_hash_full = Sha256::digest(pin.as_bytes());
        let pin_hash: [u8; 16] = pin_hash_full[..16].try_into().unwrap();
        let mut pin_hash_enc = [0u8; 16];
        #[allow(deprecated)]
        {
            use aes::cipher::generic_array::GenericArray;
            type Block16 = GenericArray<u8, aes::cipher::typenum::U16>;
            let iv = [0u8; 16];
            let src: &[Block16] = unsafe {
                std::slice::from_raw_parts(pin_hash.as_ptr() as *const Block16, 1)
            };
            let dst: &mut [Block16] = unsafe {
                std::slice::from_raw_parts_mut(pin_hash_enc.as_mut_ptr() as *mut Block16, 1)
            };
            let _ = Aes256CbcEnc::new(&shared_secret.into(), &iv.into())
                .encrypt_blocks_b2b_mut(src, dst);
        }

        let eph_x = ephemeral_point.x()
            .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing x".into()))?.to_vec();
        let eph_y = ephemeral_point.y()
            .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing y".into()))?.to_vec();
        let eph_cose = Value::Map(vec![
            (Value::Integer(1i64.into()),    Value::Integer(2i64.into())),
            (Value::Integer(3i64.into()),    Value::Integer((-7i64).into())),
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            (Value::Integer((-2i64).into()), Value::Bytes(eph_x)),
            (Value::Integer((-3i64).into()), Value::Bytes(eph_y)),
        ]);

        let get_pin_token_cbor = Value::Map(vec![
            (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())),
            (Value::Integer(0x02u64.into()), Value::Integer(5u64.into())),
            (Value::Integer(0x03u64.into()), eph_cose),
            (Value::Integer(0x06u64.into()), Value::Bytes(pin_hash_enc.to_vec())),
        ]);
        let mut gpt_req = vec![0x06u8];
        ciborium::ser::into_writer(&get_pin_token_cbor, &mut gpt_req)
            .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;
        let gpt_resp = hid.send_recv(CTAPHID_CBOR, &gpt_req)?;
        if gpt_resp.is_empty() || gpt_resp[0] != 0x00 {
            let code = gpt_resp.first().copied().unwrap_or(0xFF);
            let hint = match code {
                0x31 => " (PIN_INVALID — wrong PIN)",
                0x32 => " (PIN_BLOCKED — too many attempts; reset required)",
                0x34 => " (PIN_AUTH_BLOCKED — power-cycle the key and retry)",
                _ => "",
            };
            return Err(SoloError::DeviceError(format!(
                "getPINToken returned CTAP error 0x{:02X}{}", code, hint
            )));
        }
        let gpt_val: Value = ciborium::de::from_reader(&gpt_resp[1..])
            .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;
        let gpt_pairs = match gpt_val {
            Value::Map(p) => p,
            _ => return Err(SoloError::DeviceError("getPINToken response is not a map".into())),
        };
        let pin_token_enc = gpt_pairs
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(i) = k {
                    let ki: u64 = (*i).try_into().ok()?;
                    if ki == 0x02 {
                        if let Value::Bytes(b) = v { Some(b.clone()) } else { None }
                    } else { None }
                } else { None }
            })
            .ok_or_else(|| SoloError::DeviceError("pinTokenEnc missing from getPINToken response".into()))?;
        if pin_token_enc.is_empty() || pin_token_enc.len() % 16 != 0 {
            return Err(SoloError::DeviceError(format!(
                "pinTokenEnc has unexpected length: {}", pin_token_enc.len()
            )));
        }
        let n_token_blocks = pin_token_enc.len() / 16;
        let mut pin_token = pin_token_enc.clone();
        #[allow(deprecated)]
        {
            use aes::cipher::generic_array::GenericArray;
            type Block16 = GenericArray<u8, aes::cipher::typenum::U16>;
            let iv = [0u8; 16];
            let src: &[Block16] = unsafe {
                std::slice::from_raw_parts(pin_token_enc.as_ptr() as *const Block16, n_token_blocks)
            };
            let dst: &mut [Block16] = unsafe {
                std::slice::from_raw_parts_mut(pin_token.as_mut_ptr() as *mut Block16, n_token_blocks)
            };
            let _ = Aes256CbcDec::new(&shared_secret.into(), &iv.into())
                .decrypt_blocks_b2b_mut(src, dst);
        }
        let pin_token = &pin_token[..pin_token_enc.len()];

        // pinUvAuthParam = HMAC-SHA-256(pinToken, clientDataHash)[0..16]
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pin_token)
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
                (Value::Text("name".into()), Value::Text("solokeys.com".into())),
            ]),
        ),
        (
            Value::Integer(0x03u64.into()),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Bytes(b"verify".to_vec())),
                (Value::Text("name".into()), Value::Text("verify".into())),
                (Value::Text("displayName".into()), Value::Text("verify".into())),
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
    if response.is_empty() {
        return Err(SoloError::DeviceError("Empty response from device".into()));
    }
    let status = response[0];
    if status != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "makeCredential returned CTAP error 0x{:02X}",
            status
        )));
    }

    // Parse the CBOR response map
    let cbor_bytes = &response[1..];
    let resp_val: Value = ciborium::de::from_reader(cbor_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;

    let pairs = match resp_val {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "makeCredential response is not a CBOR map".into(),
            ))
        }
    };

    // Helper to look up an integer key in the map
    let get_key = |key: u64| -> Option<&Value> {
        pairs.iter().find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == key {
                    return Some(v);
                }
            }
            None
        })
    };

    // 0x03: attStmt map — contains "x5c" array of DER-encoded certs
    let att_stmt = match get_key(0x03) {
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
        Some(Value::Array(certs)) if !certs.is_empty() => {
            match &certs[0] {
                Value::Bytes(b) => b.clone(),
                _ => {
                    return Err(SoloError::DeviceError(
                        "x5c[0] is not bytes".into(),
                    ))
                }
            }
        }
        _ => {
            return Err(SoloError::DeviceError(
                "attStmt missing x5c array".into(),
            ))
        }
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
