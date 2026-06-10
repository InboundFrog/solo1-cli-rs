use crate::cbor::{
    cbor_bytes, cbor_int, cbor_text, expect_map, find_int_key, find_text_key, int_map,
};
use crate::ctap2::{
    aes256_cbc_decrypt, aes256_cbc_encrypt, ecdh_shared_secret, parse_cbor_map_response,
    prompt_and_get_pin_token,
};
use crate::device::HidDevice;
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
pub fn cmd_make_credential(
    hid: &impl HidDevice,
    host: &str,
    user: &str,
    prompt: &str,
    json: bool,
) -> Result<()> {
    use ciborium::value::Value;
    use rand::RngCore;

    // Generate random challenge and hash it as clientDataHash
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    let client_data_hash: Vec<u8> = Sha256::digest(challenge).to_vec();

    // If a PIN is set, acquire a PIN token and compute pinUvAuthParam.
    // PIN prompt comes first; the touch prompt is printed after PIN entry.
    let pin_uv_auth: Option<Vec<u8>> = if crate::ctap2::get_info_client_pin_set(hid)? {
        let pin_token = prompt_and_get_pin_token(hid)?;
        // pinUvAuthParam = HMAC-SHA-256(pinToken, clientDataHash)[0..16]
        Some(crate::ctap2::pin_uv_auth(&pin_token, &client_data_hash)?)
    } else {
        None
    };

    // Build CTAP2 makeCredential CBOR request map (integer keys per CTAP2 spec):
    //   0x01: clientDataHash
    //   0x02: rp  {"id": host, "name": host}
    //   0x03: user {"id": user bytes, "name": user, "displayName": user}
    //   0x04: pubKeyCredParams [{"alg": -7, "type": "public-key"}]
    //   0x06: extensions {"hmac-secret": true}
    //   0x07: options {"rk": true}
    //   0x08: pinUvAuthParam (if PIN is set)
    //   0x09: pinUvAuthProtocol = 1 (if PIN is set)
    let mut cbor_entries: Vec<(i64, Value)> = vec![
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
        (0x07, Value::Map(vec![(cbor_text("rk"), Value::Bool(true))])),
    ];
    if let Some(auth_param) = pin_uv_auth {
        cbor_entries.push((0x08, cbor_bytes(auth_param)));
        cbor_entries.push((0x09, cbor_int(1)));
    }
    let cbor_request = int_map(cbor_entries);

    if !prompt.is_empty() {
        eprintln!("{}", prompt);
    }

    // CTAP2 makeCredential (0x01)
    let response = crate::ctap2::ctap2_call(hid, 0x01, &cbor_request)?;

    // First byte is CTAP2 status code; 0x00 = success
    let pairs = parse_cbor_map_response(&response, "makeCredential")?;

    // 0x02: authData bytes — contains rpIdHash, flags, signCount, AAGUID, credentialId
    let auth_data = match find_int_key(&pairs, 0x02) {
        Some(Value::Bytes(b)) => b,
        _ => {
            return Err(SoloError::MalformedResponse(
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
        return Err(SoloError::MalformedResponse(
            "authData too short to contain credential info".into(),
        ));
    }

    let flags = auth_data[32];
    let at_flag = (flags & 0x40) != 0; // bit 6 = attested credential data present

    if !at_flag {
        return Err(SoloError::MalformedResponse(
            "authData AT flag not set — no credential data present".into(),
        ));
    }

    if auth_data.len() < 55 {
        return Err(SoloError::MalformedResponse(
            "authData too short to read credentialIdLength".into(),
        ));
    }

    let cred_id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let cred_id_start = 55;
    let cred_id_end = cred_id_start + cred_id_len;

    if auth_data.len() < cred_id_end {
        return Err(SoloError::MalformedResponse(format!(
            "authData too short: need {} bytes for credential ID, have {}",
            cred_id_end,
            auth_data.len()
        )));
    }

    let credential_id = &auth_data[cred_id_start..cred_id_end];

    if json {
        use crate::output::{print_json, MakeCredentialOutput};
        return print_json(&MakeCredentialOutput {
            credential_id: hex::encode(credential_id),
        });
    }
    println!("{}", hex::encode(credential_id));

    Ok(())
}

/// Decrypt the hmac-secret extension output returned by the authenticator.
///
/// The authenticator encrypts the HMAC output with AES-256-CBC using the
/// shared secret and a zero IV. `encrypted` must be 32 or 64 bytes (one or
/// two HMAC-SHA-256 outputs). Returns the decrypted bytes.
fn decrypt_hmac_secret(shared_secret: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() != 32 && encrypted.len() != 64 {
        return Err(SoloError::MalformedResponse(format!(
            "hmac-secret encrypted output has unexpected length: {}",
            encrypted.len()
        )));
    }

    aes256_cbc_decrypt(shared_secret, encrypted)
}

// TODO Cleanup doc - need to talk to Claude
#[allow(clippy::doc_lazy_continuation)]
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
    dev_pub_key: &p256::PublicKey,
    challenge: &str,
) -> Result<(ciborium::value::Value, [u8; 32])> {
    use rand::rngs::OsRng;
    let platform_scalar = p256::NonZeroScalar::random(&mut OsRng);
    prepare_hmac_secret_input_with_scalar(dev_pub_key, challenge, &platform_scalar)
}

/// Scalar-parameterized implementation of [`prepare_hmac_secret_input`];
/// tests call this directly with a fixed scalar.
fn prepare_hmac_secret_input_with_scalar(
    dev_pub_key: &p256::PublicKey,
    challenge: &str,
    platform_scalar: &p256::NonZeroScalar,
) -> Result<(ciborium::value::Value, [u8; 32])> {
    let salt: [u8; 32] = Sha256::digest(challenge.as_bytes()).into();

    let (shared_secret, ephemeral_cose_key) = ecdh_shared_secret(dev_pub_key, platform_scalar);

    // saltEnc = AES-256-CBC(shared_secret, IV=0, salt) — 32 bytes (2 AES blocks)
    let salt_enc = aes256_cbc_encrypt(&shared_secret, &salt)?;

    // saltAuth = HMAC-SHA-256(shared_secret, saltEnc)[0..16]
    let salt_auth = crate::ctap2::pin_uv_auth(&shared_secret, &salt_enc)?;

    // hmac-secret extension input: {1: keyAgreement, 2: saltEnc, 3: saltAuth}
    let hmac_secret_ext = int_map([
        (1, ephemeral_cose_key),
        (2, cbor_bytes(salt_enc)),
        (3, cbor_bytes(salt_auth)),
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
    json: bool,
) -> Result<()> {
    use ciborium::value::Value;
    use sha2::Digest as _;

    // Decode hex credential ID
    let cred_id_bytes = hex::decode(credential_id).map_err(SoloError::InvalidHex)?;

    // ── Steps 1–6: getKeyAgreement → prepare hmac-secret extension input ─────
    let dev_pub_key = crate::ctap2::get_key_agreement(hid)?;
    let (hmac_secret_ext, shared_secret) = prepare_hmac_secret_input(&dev_pub_key, challenge)?;

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

    eprintln!("Touch your authenticator to generate a response...");

    // CTAP2 getAssertion (0x02)
    let ga_response = crate::ctap2::ctap2_call(hid, 0x02, &get_assertion_cbor)?;

    // ── Step 8: Parse authData from getAssertion response ────────────────────
    let ga_pairs = parse_cbor_map_response(&ga_response, "getAssertion")?;

    // authData is at key 0x02 in the getAssertion response
    let auth_data = match find_int_key(&ga_pairs, 0x02) {
        Some(Value::Bytes(b)) => b,
        _ => {
            return Err(SoloError::MalformedResponse(
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
        return Err(SoloError::MalformedResponse("authData too short".into()));
    }

    let flags = auth_data[32];
    let ed_flag = (flags & 0x80) != 0; // bit 7 = extensions data present

    if !ed_flag {
        return Err(SoloError::MalformedResponse(
            "authData ED flag not set — no extensions data in response".into(),
        ));
    }

    // Parse extensions CBOR starting at byte 37
    let ext_cbor_bytes = &auth_data[37..];
    let ext_val: Value = ciborium::de::from_reader(ext_cbor_bytes)?;

    let ext_pairs = expect_map(ext_val, "getAssertion extensions")?;

    // Find "hmac-secret" key in extensions
    let hmac_secret_enc = match find_text_key(&ext_pairs, "hmac-secret") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => {
            return Err(SoloError::MalformedResponse(
                "hmac-secret missing from authData extensions".into(),
            ))
        }
    };

    // ── Step 8 (cont): Decrypt the hmac-secret output ────────────────────────
    let hmac_output = decrypt_hmac_secret(&shared_secret, &hmac_secret_enc)?;

    // ── Step 9: Print the HMAC output as hex ────────────────────────────────
    if json {
        use crate::output::{print_json, ChallengeResponseOutput};
        return print_json(&ChallengeResponseOutput {
            hmac_output: hex::encode(&hmac_output[..32]),
        });
    }
    println!("{}", hex::encode(&hmac_output[..32]));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctap2::cose_to_public_key;
    use ciborium::value::Value;

    /// Build a COSE key map (integer-keyed) from a `p256::PublicKey`.
    fn cose_pairs_from_pub(pub_key: &p256::PublicKey) -> Vec<(Value, Value)> {
        use p256::EncodedPoint;
        let point = EncodedPoint::from(pub_key);
        let x = point.x().unwrap().to_vec();
        let y = point.y().unwrap().to_vec();
        vec![
            (Value::Integer((-2i64).into()), Value::Bytes(x)),
            (Value::Integer((-3i64).into()), Value::Bytes(y)),
        ]
    }

    /// Extract a `Value::Bytes` payload from the CBOR extension map by integer key.
    fn find_bytes_by_int_key(pairs: &[(Value, Value)], key: i64) -> Option<Vec<u8>> {
        pairs.iter().find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: i64 = (*i).try_into().ok()?;
                if ki == key {
                    if let Value::Bytes(b) = v {
                        return Some(b.clone());
                    }
                }
            }
            None
        })
    }

    /// Verify that both sides of the ECDH exchange derive the same shared secret.
    ///
    /// The "device" side owns `dev_secret_key`; the "platform" side owns
    /// `platform_scalar`.  Both compute the x-coordinate of the DH shared point
    /// and SHA-256 it; the test asserts that the resulting 32-byte secrets match.
    #[test]
    fn ecdh_key_agreement_both_sides_agree() {
        use rand::rngs::OsRng;

        // Generate deterministic-within-test keys using p256::SecretKey::random
        let dev_secret = p256::SecretKey::random(&mut OsRng);
        let dev_pub = dev_secret.public_key();
        let platform_secret = p256::SecretKey::random(&mut OsRng);
        let platform_scalar = platform_secret.to_nonzero_scalar();
        let platform_pub = platform_secret.public_key();

        // Platform → device: platform computes DH with dev_pub, going through
        // the COSE-key parse the production code performs on device responses.
        let dev_cose_pairs = cose_pairs_from_pub(&dev_pub);
        let parsed_dev_pub = cose_to_public_key(&dev_cose_pairs).expect("COSE parse failed");
        assert_eq!(
            parsed_dev_pub, dev_pub,
            "COSE round-trip must preserve the key"
        );
        let (platform_shared, _cose_key) = ecdh_shared_secret(&parsed_dev_pub, &platform_scalar);

        // Device → platform: device computes DH with platform_pub
        let dev_scalar = dev_secret.to_nonzero_scalar();
        let dev_shared_point = p256::ecdh::diffie_hellman(&dev_scalar, platform_pub.as_affine());
        let dev_shared: [u8; 32] = Sha256::digest(dev_shared_point.raw_secret_bytes()).into();

        assert_eq!(
            platform_shared, dev_shared,
            "Platform and device must derive the same shared secret"
        );
    }

    /// Verify the COSE key embedded in the ECDH output is a valid P-256 public key
    /// and that its coordinates correspond to the platform scalar used.
    #[test]
    fn ecdh_key_agreement_cose_key_is_correct() {
        use p256::EncodedPoint;
        use rand::rngs::OsRng;

        let dev_secret = p256::SecretKey::random(&mut OsRng);
        let dev_pub = dev_secret.public_key();
        let platform_secret = p256::SecretKey::random(&mut OsRng);
        let platform_scalar = platform_secret.to_nonzero_scalar();

        let expected_platform_pub = platform_secret.public_key();
        let expected_point = EncodedPoint::from(&expected_platform_pub);
        let expected_x = expected_point.x().unwrap().to_vec();
        let expected_y = expected_point.y().unwrap().to_vec();

        let dev_cose_pairs = cose_pairs_from_pub(&dev_pub);
        let parsed_dev_pub = cose_to_public_key(&dev_cose_pairs).expect("COSE parse failed");
        let (_shared, cose_key) = ecdh_shared_secret(&parsed_dev_pub, &platform_scalar);

        let cose_pairs = match cose_key {
            Value::Map(p) => p,
            _ => panic!("COSE key is not a CBOR map"),
        };

        // kty = 2 (EC2)
        let kty = find_bytes_by_int_key(&cose_pairs, 1);
        assert!(kty.is_none(), "kty should be an integer, not bytes");
        let kty_val = cose_pairs.iter().find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: i64 = (*i).try_into().ok()?;
                if ki == 1 {
                    Some(v.clone())
                } else {
                    None
                }
            } else {
                None
            }
        });
        assert_eq!(
            kty_val,
            Some(Value::Integer(2i64.into())),
            "kty must be 2 (EC2)"
        );

        // x coordinate
        let got_x = find_bytes_by_int_key(&cose_pairs, -2).expect("COSE key missing x (-2)");
        assert_eq!(got_x, expected_x, "COSE key x coordinate mismatch");

        // y coordinate
        let got_y = find_bytes_by_int_key(&cose_pairs, -3).expect("COSE key missing y (-3)");
        assert_eq!(got_y, expected_y, "COSE key y coordinate mismatch");
    }

    /// Verify that `prepare_hmac_secret_input` produces correctly structured output:
    /// - The map has integer keys 1, 2, 3
    /// - saltEnc is 32 bytes
    /// - saltAuth is 16 bytes
    /// - saltEnc decrypts to SHA-256(challenge) using the shared secret
    /// - saltAuth equals HMAC-SHA-256(shared_secret, saltEnc)[0..16]
    #[test]
    fn prepare_hmac_secret_input_output_is_correct() {
        use hmac::{Hmac, KeyInit as _, Mac as _};
        use rand::rngs::OsRng;

        let challenge = "test-challenge";
        let expected_salt: [u8; 32] = Sha256::digest(challenge.as_bytes()).into();

        let dev_secret = p256::SecretKey::random(&mut OsRng);
        let dev_pub = dev_secret.public_key();
        let platform_secret = p256::SecretKey::random(&mut OsRng);
        let platform_scalar = platform_secret.to_nonzero_scalar();

        let (hmac_ext, shared_secret) =
            prepare_hmac_secret_input_with_scalar(&dev_pub, challenge, &platform_scalar)
                .expect("prepare_hmac_secret_input_with_scalar failed");

        // The result must be a CBOR map
        let ext_pairs = match hmac_ext {
            Value::Map(p) => p,
            _ => panic!("hmac-secret extension is not a CBOR map"),
        };

        // Keys 1, 2, 3 must be present
        let has_key = |k: i64| {
            ext_pairs.iter().any(|(ek, _)| {
                if let Value::Integer(i) = ek {
                    let ki: i64 = (*i).try_into().unwrap_or(i64::MIN);
                    ki == k
                } else {
                    false
                }
            })
        };
        assert!(has_key(1), "hmac-secret map missing key 1 (keyAgreement)");
        assert!(has_key(2), "hmac-secret map missing key 2 (saltEnc)");
        assert!(has_key(3), "hmac-secret map missing key 3 (saltAuth)");

        // saltEnc must be 32 bytes
        let salt_enc = find_bytes_by_int_key(&ext_pairs, 2).expect("saltEnc (key 2) missing");
        assert_eq!(salt_enc.len(), 32, "saltEnc must be 32 bytes");

        // saltAuth must be 16 bytes
        let salt_auth = find_bytes_by_int_key(&ext_pairs, 3).expect("saltAuth (key 3) missing");
        assert_eq!(salt_auth.len(), 16, "saltAuth must be 16 bytes");

        // Decrypt saltEnc and verify it equals SHA-256(challenge)
        let decrypted = aes256_cbc_decrypt(&shared_secret, &salt_enc).expect("decrypt failed");
        assert_eq!(
            decrypted.as_slice(),
            expected_salt,
            "Decrypted saltEnc must equal SHA-256(challenge)"
        );

        // Recompute saltAuth and verify it matches
        let mut mac =
            Hmac::<Sha256>::new_from_slice(shared_secret.as_slice()).expect("HMAC init failed");
        mac.update(&salt_enc);
        let mac_result = mac.finalize().into_bytes();
        let expected_salt_auth = &mac_result[..16];
        assert_eq!(
            salt_auth.as_slice(),
            expected_salt_auth,
            "saltAuth must equal HMAC-SHA-256(shared_secret, saltEnc)[0..16]"
        );
    }

    /// Verify that the shared secret computed by `prepare_hmac_secret_input_with_scalar`
    /// matches the shared secret the device side would compute.
    #[test]
    fn prepare_hmac_secret_input_shared_secret_matches_device() {
        use rand::rngs::OsRng;

        let challenge = "another-test-challenge";
        let dev_secret = p256::SecretKey::random(&mut OsRng);
        let dev_pub = dev_secret.public_key();
        let platform_secret = p256::SecretKey::random(&mut OsRng);
        let platform_scalar = platform_secret.to_nonzero_scalar();
        let platform_pub = platform_secret.public_key();

        let (_hmac_ext, platform_shared) =
            prepare_hmac_secret_input_with_scalar(&dev_pub, challenge, &platform_scalar)
                .expect("prepare_hmac_secret_input_with_scalar failed");

        // Device computes the same shared secret from the platform's public key
        let dev_scalar = dev_secret.to_nonzero_scalar();
        let dev_shared_point = p256::ecdh::diffie_hellman(&dev_scalar, platform_pub.as_affine());
        let device_shared: [u8; 32] = Sha256::digest(dev_shared_point.raw_secret_bytes()).into();

        assert_eq!(
            platform_shared, device_shared,
            "Shared secret from prepare_hmac_secret_input must match device-side computation"
        );
    }
}
