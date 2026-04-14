use crate::cbor::{cbor_bytes, cbor_int, cbor_text, expect_map, find_int_key, int_map};
use crate::ctap2::{
    extract_cose_coord, find_key_agreement_response,
    parse_cbor_map_response, CTAP2_AES_IV,
};
use crate::device::{HidDevice, CTAPHID_CBOR};
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
pub fn cmd_make_credential(hid: &impl HidDevice, host: &str, user: &str, prompt: &str) -> Result<()> {
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
    let cbor_request = int_map([
        (0x01, cbor_bytes(client_data_hash)),
        (
            0x02,
            Value::Map(vec![
                (cbor_text("id"), cbor_text(host)),
                (cbor_text("name"), cbor_text(host)),
            ]),
        ),
        (
            0x03,
            Value::Map(vec![
                (cbor_text("id"), cbor_bytes(user.as_bytes().to_vec())),
                (cbor_text("name"), cbor_text(user)),
                (cbor_text("displayName"), cbor_text(user)),
            ]),
        ),
        (
            0x04,
            Value::Array(vec![Value::Map(vec![
                (cbor_text("alg"), cbor_int(-7)),
                (cbor_text("type"), cbor_text("public-key")),
            ])]),
        ),
        (
            0x06,
            Value::Map(vec![(cbor_text("hmac-secret"), Value::Bool(true))]),
        ),
        (
            0x07,
            Value::Map(vec![(cbor_text("rk"), Value::Bool(true))]),
        ),
    ]);

    // Prepend CTAP2 command byte 0x01 (makeCredential) before the CBOR payload
    let mut request_bytes = vec![0x01u8];
    ciborium::ser::into_writer(&cbor_request, &mut request_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let response = hid.send_recv(CTAPHID_CBOR, &request_bytes)?;

    // First byte is CTAP2 status code; 0x00 = success
    let pairs = parse_cbor_map_response(&response, "makeCredential")?;

    // 0x02: authData bytes — contains rpIdHash, flags, signCount, AAGUID, credentialId
    let auth_data = match find_int_key(&pairs, 0x02) {
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

/// Perform ECDH key agreement with the device's COSE P-256 public key.
///
/// Extracts the x and y coordinates from `dev_pub_key_cbor_pairs` (a COSE key
/// map), generates an ephemeral P-256 keypair, and computes the shared secret
/// as SHA-256 of the ECDH x-coordinate. Returns the 32-byte shared secret and
/// the ephemeral public key as a CBOR `Value` (COSE_Key map) suitable for use
/// as `keyAgreement` in the hmac-secret extension input.
fn derive_shared_secret(
    dev_pub_key_cbor_pairs: &[(ciborium::value::Value, ciborium::value::Value)],
) -> Result<([u8; 32], ciborium::value::Value)> {
    use p256::ecdh::EphemeralSecret;
    use p256::EncodedPoint;
    use rand::rngs::OsRng;

    let dev_x = extract_cose_coord(dev_pub_key_cbor_pairs, -2)?;
    let dev_y = extract_cose_coord(dev_pub_key_cbor_pairs, -3)?;

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

    // Generate ephemeral P-256 keypair
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pub = p256::PublicKey::from(&ephemeral_secret);
    let ephemeral_point = EncodedPoint::from(&ephemeral_pub);

    // ECDH + SHA-256 → shared_secret
    let shared_secret_point = ephemeral_secret.diffie_hellman(&dev_pub_key);
    let raw_x = shared_secret_point.raw_secret_bytes();
    let shared_secret: [u8; 32] = Sha256::digest(raw_x).into();

    let eph_x = ephemeral_point
        .x()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing x coordinate".into()))?
        .to_vec();
    let eph_y = ephemeral_point
        .y()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing y coordinate".into()))?
        .to_vec();

    let ephemeral_cose_key = int_map([
        (1,  cbor_int(2)),           // kty = EC2
        (3,  cbor_int(-7)),          // alg = ES256
        (-1, cbor_int(1)),           // crv = P-256
        (-2, cbor_bytes(eph_x)),     // x
        (-3, cbor_bytes(eph_y)),     // y
    ]);

    Ok((shared_secret, ephemeral_cose_key))
}

/// Decrypt the hmac-secret extension output returned by the authenticator.
///
/// The authenticator encrypts the HMAC output with AES-256-CBC using the
/// shared secret and a zero IV. `encrypted` must be 32 or 64 bytes (one or
/// two HMAC-SHA-256 outputs). Returns the decrypted bytes.
fn decrypt_hmac_secret(shared_secret: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{BlockModeDecrypt, KeyIvInit};

    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    if encrypted.len() != 32 && encrypted.len() != 64 {
        return Err(SoloError::DeviceError(format!(
            "hmac-secret encrypted output has unexpected length: {}",
            encrypted.len()
        )));
    }

    let n_blocks = encrypted.len() / 16;
    let mut output = encrypted.to_vec();
    {
        let mut blocks = vec![aes::Block::default(); n_blocks];
        for (i, chunk) in encrypted.chunks_exact(16).enumerate() {
            blocks[i] = (*chunk).try_into().unwrap();
        }
        Aes256CbcDec::new(&(*shared_secret).into(), &CTAP2_AES_IV.into())
            .decrypt_blocks(&mut blocks);
        for (i, block) in blocks.iter().enumerate() {
            output[i * 16..(i + 1) * 16].copy_from_slice(block.as_slice());
        }
    }
    Ok(output)
}

/// Build the hmac-secret extension input for a getAssertion request.
///
/// Performs steps 1–6 of the hmac-secret protocol:
///   1. Compute salt = SHA-256(challenge)
///   2–4. ECDH with device key → shared_secret + ephemeral COSE public key
///   5. saltEnc = AES-256-CBC(key=shared_secret, IV=0x00×16, data=salt)
///   6. saltAuth = HMAC-SHA-256(shared_secret, saltEnc)[0..16]
///
/// Returns the hmac-secret extension map `{1: keyAgreement, 2: saltEnc, 3: saltAuth}`
/// and the shared_secret needed to decrypt the authenticator's response.
fn prepare_hmac_secret_input(
    cose_pairs: &[(ciborium::value::Value, ciborium::value::Value)],
    challenge: &str,
) -> Result<(ciborium::value::Value, [u8; 32])> {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};
    use hmac::{Hmac, KeyInit as _, Mac as _};

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let salt: [u8; 32] = Sha256::digest(challenge.as_bytes()).into();

    let (shared_secret, ephemeral_cose_key) = derive_shared_secret(cose_pairs)?;

    // saltEnc = AES-256-CBC(shared_secret, IV=0, salt) — 32 bytes (2 AES blocks)
    let mut salt_enc = [0u8; 32];
    {
        let mut blocks = [aes::Block::default(); 2];
        for (i, chunk) in salt.chunks_exact(16).enumerate() {
            blocks[i] = (*chunk).try_into().unwrap();
        }
        Aes256CbcEnc::new(&shared_secret.into(), &CTAP2_AES_IV.into())
            .encrypt_blocks(&mut blocks);
        for (i, block) in blocks.iter().enumerate() {
            salt_enc[i * 16..(i + 1) * 16].copy_from_slice(block.as_slice());
        }
    }

    // saltAuth = HMAC-SHA-256(shared_secret, saltEnc)[0..16]
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret.as_slice())
        .map_err(|e| SoloError::DeviceError(format!("HMAC init error: {}", e)))?;
    mac.update(&salt_enc);
    let mac_result = mac.finalize().into_bytes();
    let salt_auth = &mac_result[..16];

    // hmac-secret extension input: {1: keyAgreement, 2: saltEnc, 3: saltAuth}
    let hmac_secret_ext = int_map([
        (1, ephemeral_cose_key),
        (2, cbor_bytes(salt_enc.to_vec())),
        (3, cbor_bytes(salt_auth.to_vec())),
    ]);

    Ok((hmac_secret_ext, shared_secret))
}

/// HMAC-secret challenge-response using CTAP2 getAssertion with hmac-secret extension.
///
/// Protocol (per CTAP2 spec and fido2 hmac-secret extension):
///   1–6. Handled by `prepare_hmac_secret_input`: salt derivation, ECDH, encrypt+auth
///   7. Send getAssertion (0x02) CBOR with:
///        rpId, clientDataHash, allowList[credentialId],
///        extensions: {"hmac-secret": {1: ephemeralPub, 2: saltEnc, 3: saltAuth}}
///   8. Parse authData from response; if ED flag set, decrypt the hmac-secret output:
///        output = AES-256-CBC-decrypt(shared_secret, IV=0x00*16, encrypted_output)
///   9. Print output as hex
pub fn cmd_challenge_response(
    hid: &impl HidDevice,
    credential_id: &str,
    challenge: &str,
    host: &str,
) -> Result<()> {
    use ciborium::value::Value;
    use sha2::Digest as _;

    // Decode hex credential ID
    let cred_id_bytes = hex::decode(credential_id)
        .map_err(|e| SoloError::DeviceError(format!("Invalid credential_id hex: {}", e)))?;

    // ── Steps 1–6: getKeyAgreement → prepare hmac-secret extension input ─────
    let get_ka_cbor = crate::ctap2::create_key_agreement_cbor();
    let mut request_bytes = vec![0x06u8]; // authenticatorClientPIN command byte
    ciborium::ser::into_writer(&get_ka_cbor, &mut request_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let response = hid.send_recv(CTAPHID_CBOR, &request_bytes)?;
    let resp_pairs = parse_cbor_map_response(&response, "getKeyAgreement")?;

    let key_agreement = find_key_agreement_response(&resp_pairs)?;
    let cose_pairs = match key_agreement {
        Value::Map(p) => p,
        _ => return Err(SoloError::DeviceError("keyAgreement is not a CBOR map".into())),
    };

    let (hmac_secret_ext, shared_secret) = prepare_hmac_secret_input(&cose_pairs, challenge)?;

    // ── Step 7: Build and send getAssertion request ───────────────────────────
    // clientDataHash: fixed bytes (device does not verify for hmac-secret use)
    let client_data_hash: Vec<u8> = Sha256::digest(b"solo1_challenge_response").to_vec();

    // getAssertion CBOR map:
    //   0x01: rpId
    //   0x02: clientDataHash
    //   0x03: allowList  [{type: "public-key", id: cred_id_bytes}]
    //   0x04: extensions {"hmac-secret": hmac_secret_ext}
    let get_assertion_cbor = int_map([
        (0x01, cbor_text(host)),
        (0x02, cbor_bytes(client_data_hash)),
        (
            0x03,
            Value::Array(vec![Value::Map(vec![
                (cbor_text("type"), cbor_text("public-key")),
                (cbor_text("id"), cbor_bytes(cred_id_bytes)),
            ])]),
        ),
        (
            0x04,
            Value::Map(vec![(cbor_text("hmac-secret"), hmac_secret_ext)]),
        ),
    ]);

    println!("Touch your authenticator to generate a response...");

    let mut ga_bytes = vec![0x02u8]; // CTAP2 getAssertion command
    ciborium::ser::into_writer(&get_assertion_cbor, &mut ga_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let ga_response = hid.send_recv(CTAPHID_CBOR, &ga_bytes)?;

    // ── Step 8: Parse authData from getAssertion response ────────────────────
    let ga_pairs = parse_cbor_map_response(&ga_response, "getAssertion")?;

    // authData is at key 0x02 in the getAssertion response
    let auth_data = match find_int_key(&ga_pairs, 0x02) {
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

    let ext_pairs = expect_map(ext_val, "getAssertion extensions")?;

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

    // ── Step 8 (cont): Decrypt the hmac-secret output ────────────────────────
    let hmac_output = decrypt_hmac_secret(&shared_secret, &hmac_secret_enc)?;

    // ── Step 9: Print the HMAC output as hex ────────────────────────────────
    println!("{}", hex::encode(&hmac_output[..32]));

    Ok(())
}
