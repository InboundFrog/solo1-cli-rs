use crate::commands::key::ctap2;
use crate::commands::key::ctap2::{find_cbor_response_by_key, find_key_agreement_response};
use crate::device::{SoloHid, CTAPHID_CBOR};
use crate::error::{Result, SoloError};
use sha2::{Digest, Sha256};

/// Create a FIDO2 credential with hmac-secret extension.
///
/// Sends a CTAP2 makeCredential (0x01) request via CTAPHID_CBOR with:
///   - clientDataHash: SHA-256 of 32 random bytes
///   - rp: {"id": host, "name": host}
///   - user: {"id": user bytes, "name": user, "displayName": user}
///   - pubKeyCredParams: [{"alg": -7, "type": "public-key"}] (ES256)
///   - extensions: {"hmac-secret": true}
///   - options: {"rk": true}  (resident key)
///
/// Parses the authData from the response to extract the credential ID,
/// then prints it as hex for use with `challenge-response` and `sign-file`.
pub fn cmd_make_credential(hid: &SoloHid, host: &str, user: &str, prompt: &str) -> Result<()> {
    use ciborium::value::Value;
    use rand::RngCore;

    if !prompt.is_empty() {
        println!("{}", prompt);
    }

    // Generate random challenge and hash it as clientDataHash
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    let client_data_hash: Vec<u8> = Sha256::digest(&challenge).to_vec();

    // Build CTAP2 makeCredential CBOR request map (integer keys per CTAP2 spec):
    //   0x01: clientDataHash
    //   0x02: rp  {"id": host, "name": host}
    //   0x03: user {"id": user bytes, "name": user, "displayName": user}
    //   0x04: pubKeyCredParams [{"alg": -7, "type": "public-key"}]
    //   0x06: extensions {"hmac-secret": true}
    //   0x07: options {"rk": true}
    let cbor_request = Value::Map(vec![
        (
            Value::Integer(0x01u64.into()),
            Value::Bytes(client_data_hash),
        ),
        (
            Value::Integer(0x02u64.into()),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Text(host.into())),
                (Value::Text("name".into()), Value::Text(host.into())),
            ]),
        ),
        (
            Value::Integer(0x03u64.into()),
            Value::Map(vec![
                (
                    Value::Text("id".into()),
                    Value::Bytes(user.as_bytes().to_vec()),
                ),
                (Value::Text("name".into()), Value::Text(user.into())),
                (Value::Text("displayName".into()), Value::Text(user.into())),
            ]),
        ),
        (
            Value::Integer(0x04u64.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer((-7i64).into())),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ])]),
        ),
        (
            Value::Integer(0x06u64.into()),
            Value::Map(vec![(Value::Text("hmac-secret".into()), Value::Bool(true))]),
        ),
        (
            Value::Integer(0x07u64.into()),
            Value::Map(vec![(Value::Text("rk".into()), Value::Bool(true))]),
        ),
    ]);

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

    // 0x02: authData bytes — contains rpIdHash, flags, signCount, AAGUID, credentialId
    let auth_data = match find_cbor_response_by_key(&pairs, 0x02) {
        Some(Value::Bytes(b)) => b,
        _ => {
            return Err(SoloError::DeviceError(
                "makeCredential response missing authData (key 0x02)".into(),
            ))
        }
    };

    // authData layout (CTAP2 spec):
    //   [0..32]   rpIdHash (32 bytes)
    //   [32]      flags byte (bit 6 = AT: attested credential data present)
    //   [33..37]  signCount (u32 BE)
    //   [37..53]  AAGUID (16 bytes)          — only if AT bit set
    //   [53..55]  credentialIdLength (u16 BE) — only if AT bit set
    //   [55..]    credentialId               — only if AT bit set
    if auth_data.len() < 37 {
        return Err(SoloError::DeviceError(
            "authData too short to contain credential info".into(),
        ));
    }

    let flags = auth_data[32];
    let at_flag = (flags & 0x40) != 0; // bit 6 = attested credential data present

    if !at_flag {
        return Err(SoloError::DeviceError(
            "authData AT flag not set — no credential data present".into(),
        ));
    }

    if auth_data.len() < 55 {
        return Err(SoloError::DeviceError(
            "authData too short to read credentialIdLength".into(),
        ));
    }

    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_id_start = 55;
    let cred_id_end = cred_id_start + cred_id_len;

    if auth_data.len() < cred_id_end {
        return Err(SoloError::DeviceError(format!(
            "authData too short: need {} bytes for credential ID, have {}",
            cred_id_end,
            auth_data.len()
        )));
    }

    let credential_id = &auth_data[cred_id_start..cred_id_end];
    println!("{}", hex::encode(credential_id));

    Ok(())
}

/// HMAC-secret challenge-response using CTAP2 getAssertion with hmac-secret extension.
///
/// Protocol (per CTAP2 spec and fido2 hmac-secret extension):
///   1. salt = SHA-256(challenge)  — 32-byte salt for hmac-secret
///   2. getKeyAgreement (clientPIN subcommand 0x02) → device COSE P-256 public key
///   3. Generate ephemeral P-256 keypair
///   4. ECDH + SHA-256(x-coord) → shared_secret (32 bytes)
///   5. saltEnc = AES-256-CBC(key=shared_secret, IV=0x00*16, data=salt)  — 32 bytes
///   6. saltAuth = HMAC-SHA-256(shared_secret, saltEnc)[0..16]  — 16-byte MAC
///   7. Send getAssertion (0x02) CBOR with:
///        rpId, clientDataHash, allowList[credentialId],
///        extensions: {"hmac-secret": {1: ephemeralPub, 2: saltEnc, 3: saltAuth}}
///   8. Parse authData from response; if ED flag set, decrypt the hmac-secret output:
///        output = AES-256-CBC-decrypt(shared_secret, IV=0x00*16, encrypted_output)
///   9. Print output as hex
pub fn cmd_challenge_response(
    hid: &SoloHid,
    credential_id: &str,
    challenge: &str,
    host: &str,
) -> Result<()> {
    use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
    use ciborium::value::Value;
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use p256::ecdh::EphemeralSecret;
    use p256::EncodedPoint;
    use rand::rngs::OsRng;
    use sha2::{Digest as _, Sha256};

    // Decode hex credential ID
    let cred_id_bytes = hex::decode(credential_id)
        .map_err(|e| SoloError::DeviceError(format!("Invalid credential_id hex: {}", e)))?;

    // ── Step 1: salt = SHA-256(challenge) ───────────────────────────────────
    let salt: [u8; 32] = Sha256::digest(challenge.as_bytes()).into();

    // ── Step 2: getKeyAgreement (subcommand 0x02) ────────────────────────────
    let get_ka_cbor = ctap2::create_key_agreement_cbor();
    let mut request_bytes = vec![0x06u8]; // authenticatorClientPIN command byte
    ciborium::ser::into_writer(&get_ka_cbor, &mut request_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let response = hid.send_recv(CTAPHID_CBOR, &request_bytes)?;

    if response.is_empty() {
        return Err(SoloError::DeviceError("Empty response from device".into()));
    }
    let status = response[0];
    if status != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "getKeyAgreement returned CTAP error 0x{:02X}",
            status
        )));
    }

    let resp_val: Value = ciborium::de::from_reader(&response[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;

    let resp_pairs = match resp_val {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "getKeyAgreement response is not a map".into(),
            ))
        }
    };

    let key_agreement = find_key_agreement_response(&resp_pairs)?;
    let cose_pairs = match key_agreement {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "keyAgreement is not a CBOR map".into(),
            ))
        }
    };

    let get_cose_bytes = |key: i64| -> Result<Vec<u8>> {
        cose_pairs
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(i) = k {
                    let ki: i64 = (*i).try_into().ok()?;
                    if ki == key {
                        if let Value::Bytes(b) = v {
                            Some(b.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or_else(|| SoloError::DeviceError(format!("COSE key missing coordinate {}", key)))
    };

    let dev_x = get_cose_bytes(-2)?;
    let dev_y = get_cose_bytes(-3)?;

    if dev_x.len() != 32 || dev_y.len() != 32 {
        return Err(SoloError::DeviceError(
            "Device COSE key coordinates are not 32 bytes".into(),
        ));
    }

    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&dev_x);
    uncompressed.extend_from_slice(&dev_y);
    let dev_pub_key = p256::PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| SoloError::DeviceError(format!("Invalid device public key: {}", e)))?;

    // ── Step 3: Generate ephemeral P-256 keypair ─────────────────────────────
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pub = p256::PublicKey::from(&ephemeral_secret);
    let ephemeral_point = EncodedPoint::from(&ephemeral_pub);

    // ── Step 4: ECDH + SHA-256 → shared_secret ──────────────────────────────
    let shared_secret_point = ephemeral_secret.diffie_hellman(&dev_pub_key);
    let raw_x = shared_secret_point.raw_secret_bytes();
    let shared_secret: [u8; 32] = Sha256::digest(raw_x).into();

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    // ── Step 5: saltEnc = AES-256-CBC(shared_secret, IV=0, salt) ────────────
    // salt is 32 bytes = 2 × 16-byte AES blocks, no padding needed
    let mut salt_enc = [0u8; 32];
    #[allow(deprecated)]
    {
        use hybrid_array::Array as HybridArray;
        type Block16 = HybridArray<u8, aes::cipher::typenum::U16>;
        let iv = [0u8; 16];
        let src_blocks: &[Block16] =
            unsafe { std::slice::from_raw_parts(salt.as_ptr() as *const Block16, 2) };
        let dst_blocks: &mut [Block16] =
            unsafe { std::slice::from_raw_parts_mut(salt_enc.as_mut_ptr() as *mut Block16, 2) };
        let _ = Aes256CbcEnc::new(&shared_secret.into(), &iv.into())
            .encrypt_blocks_b2b(src_blocks, dst_blocks);
    }

    // ── Step 6: saltAuth = HMAC-SHA-256(shared_secret, saltEnc)[0..16] ──────
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret.as_slice())
        .map_err(|e| SoloError::DeviceError(format!("HMAC init error: {}", e)))?;
    mac.update(&salt_enc);
    let mac_result = mac.finalize().into_bytes();
    let salt_auth = &mac_result[..16];

    // ── Step 7: Build ephemeral COSE key for hmac-secret extension ───────────
    let eph_x = ephemeral_point
        .x()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing x coordinate".into()))?
        .to_vec();
    let eph_y = ephemeral_point
        .y()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing y coordinate".into()))?
        .to_vec();

    let ephemeral_cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty = EC2
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())), // alg = ES256
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv = P-256
        (Value::Integer((-2i64).into()), Value::Bytes(eph_x)),      // x
        (Value::Integer((-3i64).into()), Value::Bytes(eph_y)),      // y
    ]);

    // hmac-secret extension input map: {1: keyAgreement, 2: saltEnc, 3: saltAuth}
    let hmac_secret_ext = Value::Map(vec![
        (Value::Integer(1i64.into()), ephemeral_cose_key),
        (Value::Integer(2i64.into()), Value::Bytes(salt_enc.to_vec())),
        (
            Value::Integer(3i64.into()),
            Value::Bytes(salt_auth.to_vec()),
        ),
    ]);

    // clientDataHash: fixed bytes (device does not verify for hmac-secret use)
    let client_data_hash: Vec<u8> = Sha256::digest(b"solo1_challenge_response").to_vec();

    // getAssertion CBOR map:
    //   0x01: rpId
    //   0x02: clientDataHash
    //   0x03: allowList  [{type: "public-key", id: cred_id_bytes}]
    //   0x04: extensions {"hmac-secret": hmac_secret_ext}
    let get_assertion_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Text(host.into())),
        (
            Value::Integer(0x02u64.into()),
            Value::Bytes(client_data_hash),
        ),
        (
            Value::Integer(0x03u64.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("id".into()), Value::Bytes(cred_id_bytes)),
            ])]),
        ),
        (
            Value::Integer(0x04u64.into()),
            Value::Map(vec![(Value::Text("hmac-secret".into()), hmac_secret_ext)]),
        ),
    ]);

    println!("Touch your authenticator to generate a response...");

    let mut ga_bytes = vec![0x02u8]; // CTAP2 getAssertion command
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

    // ── Step 8: Parse authData from getAssertion response ────────────────────
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

    // authData is at key 0x02 in the getAssertion response
    let auth_data = match get_ga_key(0x02) {
        Some(Value::Bytes(b)) => b,
        _ => {
            return Err(SoloError::DeviceError(
                "getAssertion response missing authData (key 0x02)".into(),
            ))
        }
    };

    // authData layout:
    //   [0..32]  rpIdHash
    //   [32]     flags byte — bit 7 (0x80) = ED: extensions data present
    //   [33..37] signCount (u32 BE)
    //   [37..]   extensions CBOR (if ED flag set)
    if auth_data.len() < 37 {
        return Err(SoloError::DeviceError("authData too short".into()));
    }

    let flags = auth_data[32];
    let ed_flag = (flags & 0x80) != 0; // bit 7 = extensions data present

    if !ed_flag {
        return Err(SoloError::DeviceError(
            "authData ED flag not set — no extensions data in response".into(),
        ));
    }

    // Parse extensions CBOR starting at byte 37
    let ext_cbor_bytes = &auth_data[37..];
    let ext_val: Value = ciborium::de::from_reader(ext_cbor_bytes)
        .map_err(|e| SoloError::DeviceError(format!("Extensions CBOR parse error: {}", e)))?;

    let ext_pairs = match ext_val {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "Extensions is not a CBOR map".into(),
            ))
        }
    };

    // Find "hmac-secret" key in extensions
    let hmac_secret_enc = ext_pairs
        .iter()
        .find_map(|(k, v)| {
            if let Value::Text(s) = k {
                if s == "hmac-secret" {
                    if let Value::Bytes(b) = v {
                        Some(b.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        })
        .ok_or_else(|| {
            SoloError::DeviceError("hmac-secret missing from authData extensions".into())
        })?;

    // The hmac-secret output is AES-256-CBC encrypted with shared_secret, IV=0x00*16
    // Decrypt it to get the final HMAC output
    if hmac_secret_enc.len() != 32 && hmac_secret_enc.len() != 64 {
        return Err(SoloError::DeviceError(format!(
            "hmac-secret encrypted output has unexpected length: {}",
            hmac_secret_enc.len()
        )));
    }

    let n_blocks = hmac_secret_enc.len() / 16;
    let mut hmac_output = hmac_secret_enc.clone();
    #[allow(deprecated)]
    {
        use hybrid_array::Array as HybridArray;
        type Block16 = HybridArray<u8, aes::cipher::typenum::U16>;
        let iv = [0u8; 16];
        let src_blocks: &[Block16] = unsafe {
            std::slice::from_raw_parts(hmac_secret_enc.as_ptr() as *const Block16, n_blocks)
        };
        let dst_blocks: &mut [Block16] = unsafe {
            std::slice::from_raw_parts_mut(hmac_output.as_mut_ptr() as *mut Block16, n_blocks)
        };
        let _ = Aes256CbcDec::new(&shared_secret.into(), &iv.into())
            .decrypt_blocks_b2b(src_blocks, dst_blocks);
    }

    // ── Step 9: Print the HMAC output as hex ────────────────────────────────
    println!("{}", hex::encode(&hmac_output[..32]));

    Ok(())
}
