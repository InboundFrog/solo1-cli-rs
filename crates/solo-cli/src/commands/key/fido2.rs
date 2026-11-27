use crate::error::{Result, SoloError};
use p256::elliptic_curve::Generate;
use sha2::{Digest, Sha256};
use solo_ctap2::authdata::{AuthenticatorData, FLAG_AT, FLAG_ED};
use solo_ctap2::cbor::{cbor_bytes, cbor_text, expect_map, find_int_key, find_text_key, int_map};
use solo_ctap2::{aes256_cbc_decrypt, aes256_cbc_encrypt, ecdh_shared_secret, parse_cbor_map_response};
use solo_ctaphid::HidDevice;
use std::path::Path;

/// Create a FIDO2 credential with hmac-secret extension.
///
/// Sends a CTAP2 makeCredential (0x01) request via `CTAPHID_CBOR` with:
///   - clientDataHash: SHA-256 of 32 random bytes
///   - rp: {"id": host, "name": host}
///   - user: {"id": user bytes, "name": user, "displayName": user}
///   - pubKeyCredParams: [{"alg": -7, "type": "public-key"}] (ES256)
///   - extensions: {"hmac-secret": true}
///   - options: {"rk": true}  (resident key)
///
/// Reads the credential ID from the authData in the response. Prints it as
/// hex. You can use it with `challenge-response` and `sign-file`.
///
/// With `json`, the JSON object also holds the credential public key as PEM.
/// With `public_key_out`, the PEM is written to that file. This is the key
/// that checks the `sign-file` signatures. In plain mode without
/// `public_key_out`, the public key is not read at all.
///
/// The credential id (or the JSON) is printed first. The public key file is
/// written after it, so a write error does not hide the credential id.
///
/// # Errors
/// Returns an error if acquiring a PIN token fails, if the makeCredential
/// request fails, or if the response is malformed (missing authData, the
/// attested-credential-data flag is unset, or the authData is too short to
/// contain the credential ID). With `json` or `public_key_out`, it also fails
/// if the credential public key is missing or invalid. It fails if the public
/// key file cannot be written.
pub fn cmd_make_credential(
    hid: &impl HidDevice,
    host: &str,
    user: &str,
    prompt: &str,
    json: bool,
    public_key_out: Option<&Path>,
) -> Result<()> {
    use ciborium::value::Value;
    use rand::Rng;

    // Make a random challenge. Its SHA-256 hash is the clientDataHash.
    let mut challenge = [0u8; 32];
    rand::rng().fill_bytes(&mut challenge);
    let client_data_hash: Vec<u8> = Sha256::digest(challenge).to_vec();

    // If a PIN is set, get a PIN token and compute pinUvAuthParam.
    // The PIN prompt comes first. The touch prompt prints after the PIN entry.
    let pin_uv_auth = solo_ctap2::maybe_pin_uv_auth(hid, &client_data_hash, crate::commands::key::common::prompt_pin)?;

    // Build the makeCredential request. Add the extensions {"hmac-secret": true}
    // (0x06) and the options {"rk": true} (0x07) to the shared request.
    let cbor_request = solo_ctap2::build_make_credential(
        host,
        user,
        &client_data_hash,
        pin_uv_auth,
        [
            (0x06, Value::Map(vec![(cbor_text("hmac-secret"), Value::Bool(true))])),
            (0x07, Value::Map(vec![(cbor_text("rk"), Value::Bool(true))])),
        ],
    );

    if !prompt.is_empty() {
        eprintln!("{prompt}");
    }

    // CTAP2 makeCredential (0x01)
    let response = solo_ctap2::ctap2_call(hid, 0x01, &cbor_request)?;
    finish_make_credential(&response, json, public_key_out)
}

/// Read the makeCredential response. Returns the credential id as hex and, when
/// `want_key` is set, the credential public key as PEM. It prints nothing.
///
/// The credential already exists on the key at this point. So if the public key
/// is wanted and cannot be read, the error text holds the credential id.
fn read_make_credential(response: &[u8], want_key: bool) -> Result<(String, Option<String>)> {
    use ciborium::value::Value;

    // First byte is CTAP2 status code; 0x00 = success
    let pairs = parse_cbor_map_response(response, "makeCredential")?;

    // 0x02: authData bytes — contains rpIdHash, flags, signCount, AAGUID, credentialId
    let Some(Value::Bytes(auth_data)) = find_int_key(&pairs, 0x02) else {
        return Err(SoloError::MalformedResponse(
            "makeCredential response missing authData (key 0x02)".into(),
        ));
    };

    let parsed = AuthenticatorData::parse(auth_data)?;

    if parsed.flags & FLAG_AT == 0 {
        return Err(SoloError::MalformedResponse(
            "authData AT flag not set — no credential data present".into(),
        ));
    }

    let credential_id = hex::encode(
        parsed
            .credential_id
            .ok_or_else(|| SoloError::MalformedResponse("authData missing credential ID".into()))?,
    );

    // The key is only read when it is needed, so plain mode works as before.
    if !want_key {
        return Ok((credential_id, None));
    }
    match solo_ctap2::cose_key_pem_from_trailing(parsed.trailing) {
        Ok(pem) => Ok((credential_id, Some(pem))),
        Err(e) => {
            // Use the inner text, so the message has only one "Malformed response" prefix.
            let detail = match e {
                solo_ctap2::Error::MalformedResponse(m)
                | solo_ctap2::Error::Protocol(m)
                | solo_ctap2::Error::Crypto(m) => m,
                other => other.to_string(),
            };
            Err(SoloError::MalformedResponse(format!(
                "the credential was created (credential id {credential_id}), but its public key could not be read: {detail}"
            )))
        }
    }
}

/// Print the credential id (or the JSON), then write the public key file.
fn finish_make_credential(response: &[u8], json: bool, public_key_out: Option<&Path>) -> Result<()> {
    let (credential_id, public_key_pem) = read_make_credential(response, json || public_key_out.is_some())?;

    if json {
        use crate::output::{MakeCredentialOutput, print_json};
        print_json(&MakeCredentialOutput {
            credential_id,
            // The PEM is always there with `json`.
            public_key_pem: public_key_pem.clone().unwrap_or_default(),
        })?;
    } else {
        println!("{credential_id}");
    }

    if let (Some(path), Some(pem)) = (public_key_out, public_key_pem) {
        std::fs::write(path, &pem).map_err(|e| {
            SoloError::IoError(std::io::Error::new(
                e.kind(),
                format!("cannot write public key to {}: {e}", path.display()),
            ))
        })?;
    }

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

    Ok(aes256_cbc_decrypt(shared_secret, encrypted)?)
}

/// Build the hmac-secret extension input for a getAssertion request.
///
/// This performs steps 1 to 6 of the hmac-secret protocol:
///
/// - Step 1: compute salt = SHA-256(challenge).
/// - Steps 2 to 4: run ECDH with the device key. This gives the
///   `shared_secret` and the ephemeral COSE public key.
/// - Step 5: compute saltEnc = AES-256-CBC(key=`shared_secret`, IV=0x00 repeated 16 times, data=salt).
/// - Step 6: compute saltAuth = HMAC-SHA-256(`shared_secret`, saltEnc), truncated to the first 16 bytes.
///
/// Returns the hmac-secret extension map `{1: keyAgreement, 2: saltEnc, 3: saltAuth}`
/// and the `shared_secret` needed to decrypt the authenticator's response.
fn prepare_hmac_secret_input(
    dev_pub_key: &p256::PublicKey,
    challenge: &str,
) -> Result<(ciborium::value::Value, [u8; 32])> {
    let platform_scalar = p256::NonZeroScalar::generate_from_rng(&mut rand::rng());
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

    let (shared_secret, ephemeral_cose_key) = ecdh_shared_secret(dev_pub_key, platform_scalar)?;

    // saltEnc = AES-256-CBC(shared_secret, IV=0, salt) — 32 bytes (2 AES blocks)
    let salt_enc = aes256_cbc_encrypt(&shared_secret, &salt)?;

    // saltAuth = HMAC-SHA-256(shared_secret, saltEnc)[0..16]
    let salt_auth = solo_ctap2::pin_uv_auth(&shared_secret, &salt_enc)?;

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
///        output = AES-256-CBC-decrypt(shared_secret, IV=0x00*16, `encrypted_output`)
///   9. Print output as hex
///
/// # Errors
/// Returns an error if `credential_id` is not valid hex, if key agreement or
/// the getAssertion request fails, if the response is malformed (missing or
/// short authData, the extensions-data flag is unset, or the hmac-secret
/// output is missing or too short), or if decrypting the hmac-secret output
/// fails.
pub fn cmd_challenge_response(
    hid: &impl HidDevice,
    credential_id: &str,
    challenge: &str,
    host: &str,
    json: bool,
) -> Result<()> {
    use ciborium::value::Value;
    use sha2::Digest as _;

    // Decode the hex credential ID.
    let cred_id_bytes = hex::decode(credential_id).map_err(SoloError::InvalidHex)?;

    // ── Steps 1–6: getKeyAgreement → prepare hmac-secret extension input ─────
    let dev_pub_key = solo_ctap2::get_key_agreement(hid)?;
    let (hmac_secret_ext, shared_secret) = prepare_hmac_secret_input(&dev_pub_key, challenge)?;

    // ── Step 7: Build and send getAssertion request ───────────────────────────
    // clientDataHash is a fixed value. The device does not check it for hmac-secret.
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
        (0x04, Value::Map(vec![(cbor_text("hmac-secret"), hmac_secret_ext)])),
    ]);

    eprintln!("Touch your authenticator to generate a response...");

    // CTAP2 getAssertion (0x02)
    let ga_response = solo_ctap2::ctap2_call(hid, 0x02, &get_assertion_cbor)?;

    // ── Step 8: Parse authData from getAssertion response ────────────────────
    let ga_pairs = parse_cbor_map_response(&ga_response, "getAssertion")?;

    // authData is at key 0x02 in the getAssertion response
    let Some(Value::Bytes(auth_data)) = find_int_key(&ga_pairs, 0x02) else {
        return Err(SoloError::MalformedResponse(
            "getAssertion response missing authData (key 0x02)".into(),
        ));
    };

    let parsed = AuthenticatorData::parse(auth_data)?;

    if parsed.flags & FLAG_ED == 0 {
        return Err(SoloError::MalformedResponse(
            "authData ED flag not set — no extensions data in response".into(),
        ));
    }

    // The extensions CBOR follows the fixed header
    let ext_cbor_bytes = parsed.trailing;
    let ext_val: Value = ciborium::de::from_reader(ext_cbor_bytes)?;

    let ext_pairs = expect_map(ext_val, "getAssertion extensions")?;

    // Find the "hmac-secret" key in the extensions.
    let hmac_secret_enc = match find_text_key(&ext_pairs, "hmac-secret") {
        Some(Value::Bytes(b)) => b.clone(),
        _ => {
            return Err(SoloError::MalformedResponse(
                "hmac-secret missing from authData extensions".into(),
            ));
        }
    };

    // ── Step 8 (cont): Decrypt the hmac-secret output ────────────────────────
    let hmac_output = decrypt_hmac_secret(&shared_secret, &hmac_secret_enc)?;

    // ── Step 9: Print the HMAC output as hex ────────────────────────────────
    let hmac_output_hex = hex::encode(
        hmac_output
            .get(..32)
            .ok_or_else(|| SoloError::MalformedResponse("hmac-secret output too short".into()))?,
    );
    if json {
        use crate::output::{ChallengeResponseOutput, print_json};
        return print_json(&ChallengeResponseOutput {
            hmac_output: hmac_output_hex,
        });
    }
    println!("{hmac_output_hex}");

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
    use ciborium::value::Value;
    use solo_ctap2::cose_to_public_key;

    /// Build a COSE key map (integer-keyed) from a `p256::PublicKey`.
    fn cose_pairs_from_pub(pub_key: &p256::PublicKey) -> Vec<(Value, Value)> {
        use p256::Sec1Point as EncodedPoint;
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
                if ki == key
                    && let Value::Bytes(b) = v
                {
                    return Some(b.clone());
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
        // Generate deterministic-within-test keys using p256::SecretKey::random
        let dev_secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let dev_pub = dev_secret.public_key();
        let platform_secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let platform_scalar = platform_secret.to_nonzero_scalar();
        let platform_pub = platform_secret.public_key();

        // Platform → device: platform computes DH with dev_pub, going through
        // the COSE-key parse the production code performs on device responses.
        let dev_cose_pairs = cose_pairs_from_pub(&dev_pub);
        let parsed_dev_pub = cose_to_public_key(&dev_cose_pairs).expect("COSE parse failed");
        assert_eq!(parsed_dev_pub, dev_pub, "COSE round-trip must preserve the key");
        let (platform_shared, _cose_key) = ecdh_shared_secret(&parsed_dev_pub, &platform_scalar).unwrap();

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
        use p256::Sec1Point as EncodedPoint;

        let dev_secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let dev_pub = dev_secret.public_key();
        let platform_secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let platform_scalar = platform_secret.to_nonzero_scalar();

        let expected_platform_pub = platform_secret.public_key();
        let expected_point = EncodedPoint::from(&expected_platform_pub);
        let expected_x = expected_point.x().unwrap().to_vec();
        let expected_y = expected_point.y().unwrap().to_vec();

        let dev_cose_pairs = cose_pairs_from_pub(&dev_pub);
        let parsed_dev_pub = cose_to_public_key(&dev_cose_pairs).expect("COSE parse failed");
        let (_shared, cose_key) = ecdh_shared_secret(&parsed_dev_pub, &platform_scalar).unwrap();

        let Value::Map(cose_pairs) = cose_key else {
            panic!("COSE key is not a CBOR map")
        };

        // kty = 2 (EC2)
        let kty = find_bytes_by_int_key(&cose_pairs, 1);
        assert!(kty.is_none(), "kty should be an integer, not bytes");
        let kty_val = cose_pairs.iter().find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: i64 = (*i).try_into().ok()?;
                if ki == 1 { Some(v.clone()) } else { None }
            } else {
                None
            }
        });
        assert_eq!(kty_val, Some(Value::Integer(2i64.into())), "kty must be 2 (EC2)");

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

        let challenge = "test-challenge";
        let expected_salt: [u8; 32] = Sha256::digest(challenge.as_bytes()).into();

        let dev_secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let dev_pub = dev_secret.public_key();
        let platform_secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let platform_scalar = platform_secret.to_nonzero_scalar();

        let (hmac_ext, shared_secret) = prepare_hmac_secret_input_with_scalar(&dev_pub, challenge, &platform_scalar)
            .expect("prepare_hmac_secret_input_with_scalar failed");

        // The result must be a CBOR map
        let Value::Map(ext_pairs) = hmac_ext else {
            panic!("hmac-secret extension is not a CBOR map")
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
        let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret.as_slice()).expect("HMAC init failed");
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
        let challenge = "another-test-challenge";
        let dev_secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let dev_pub = dev_secret.public_key();
        let platform_secret = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let platform_scalar = platform_secret.to_nonzero_scalar();
        let platform_pub = platform_secret.public_key();

        let (_hmac_ext, platform_shared) = prepare_hmac_secret_input_with_scalar(&dev_pub, challenge, &platform_scalar)
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

    /// Build a makeCredential response: status 0x00, then `{0x02: authData}`.
    /// The authData holds the given COSE key bytes, then an extensions map.
    fn make_credential_response(cose_bytes: &[u8]) -> Vec<u8> {
        let mut auth_data = vec![0x11u8; 32];
        auth_data.push(0xC1); // UP, AT, ED
        auth_data.extend_from_slice(&[0, 0, 0, 1]);
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(&[0, 2, 0xAB, 0xCD]); // credential id
        auth_data.extend_from_slice(cose_bytes);
        let ext = Value::Map(vec![(Value::Text("hmac-secret".into()), Value::Bool(true))]);
        ciborium::ser::into_writer(&ext, &mut auth_data).unwrap();
        let mut response = vec![0x00u8];
        let map = Value::Map(vec![(Value::Integer(2u64.into()), Value::Bytes(auth_data))]);
        ciborium::ser::into_writer(&map, &mut response).unwrap();
        response
    }

    fn cose_bytes(pub_key: &p256::PublicKey) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Value::Map(cose_pairs_from_pub(pub_key)), &mut out).unwrap();
        out
    }

    #[test]
    fn test_finish_make_credential_writes_public_key_file() {
        use p256::pkcs8::DecodePublicKey;
        let pub_key = p256::SecretKey::from_slice(&[0x42; 32]).unwrap().public_key();
        let response = make_credential_response(&cose_bytes(&pub_key));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pub.pem");

        finish_make_credential(&response, false, Some(&path)).unwrap();

        let pem = std::fs::read_to_string(&path).unwrap();
        assert_eq!(p256::PublicKey::from_public_key_pem(&pem).unwrap(), pub_key);
    }

    #[test]
    fn test_read_make_credential_returns_id_and_key() {
        use p256::pkcs8::DecodePublicKey;
        let pub_key = p256::SecretKey::from_slice(&[0x42; 32]).unwrap().public_key();
        let response = make_credential_response(&cose_bytes(&pub_key));

        let (id, pem) = read_make_credential(&response, true).unwrap();
        assert_eq!(id, "abcd");
        assert_eq!(p256::PublicKey::from_public_key_pem(&pem.unwrap()).unwrap(), pub_key);

        // Without `want_key` the key is not read.
        let (id, pem) = read_make_credential(&response, false).unwrap();
        assert_eq!(id, "abcd");
        assert_eq!(pem, None);
    }

    /// Plain mode without the option does not look at the public key.
    #[test]
    fn test_finish_make_credential_plain_ignores_bad_cose_key() {
        let response = make_credential_response(&[0xF6]); // CBOR null
        finish_make_credential(&response, false, None).unwrap();
        assert_eq!(read_make_credential(&response, false).unwrap().0, "abcd");
    }

    #[test]
    fn test_finish_make_credential_bad_cose_key_is_error_with_json_or_file() {
        let response = make_credential_response(&[0xF6]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pub.pem");

        let err = finish_make_credential(&response, true, None).unwrap_err();
        assert!(
            matches!(err, SoloError::MalformedResponse(_)),
            "unexpected error: {err}"
        );

        let err = finish_make_credential(&response, false, Some(&path)).unwrap_err();
        assert!(
            matches!(err, SoloError::MalformedResponse(_)),
            "unexpected error: {err}"
        );
        assert!(!path.exists());
    }

    #[test]
    fn test_finish_make_credential_unwritable_file_is_error() {
        let pub_key = p256::SecretKey::from_slice(&[0x42; 32]).unwrap().public_key();
        let response = make_credential_response(&cose_bytes(&pub_key));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing-dir").join("pub.pem");

        let err = finish_make_credential(&response, false, Some(&path)).unwrap_err();
        assert!(matches!(err, SoloError::IoError(_)), "unexpected error: {err}");
        assert!(err.to_string().contains("cannot write public key"));
    }
}
