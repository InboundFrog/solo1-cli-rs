use crate::cbor::{cbor_bytes, cbor_int, cbor_text, find_int_key, find_text_key, int_map};
use crate::ctap2::{parse_cbor_map_response, prompt_and_get_pin_token};
use crate::device::HidDevice;
use crate::error::{Result, SoloError};
use sha2::{Digest, Sha256};

/// Attestation data extracted from a makeCredential response.
///
/// `cert_der` is always present (extraction fails without it).  `auth_data`
/// and `sig` are optional so that a response missing them can be reported as
/// a signature-verification failure rather than a transport error: a device
/// that presents a certificate but cannot produce the matching signature is
/// exactly the counterfeit case this command exists to catch.
#[derive(Debug)]
struct AttestationData {
    /// DER-encoded leaf attestation certificate (`attStmt.x5c[0]`).
    cert_der: Vec<u8>,
    /// Raw authenticator data bytes (response key 0x02), if present.
    auth_data: Option<Vec<u8>>,
    /// DER-encoded ECDSA signature (`attStmt.sig`), if present.
    sig: Option<Vec<u8>>,
}

/// Parse a raw makeCredential CTAP2 response and extract the packed
/// attestation: certificate (`attStmt.x5c[0]`), authenticator data (key
/// 0x02), and signature (`attStmt.sig`).
///
/// The response must start with a 0x00 status byte followed by a CBOR map.
/// Key 0x03 of that map is `attStmt`, which must contain an `x5c` array
/// whose first element is the leaf certificate as a byte string.
///
/// Per WebAuthn §8.2 the packed attestation `alg` must be -7 (ES256); any
/// other algorithm is an error because Solo keys only attest with ES256 and
/// this code cannot verify anything else.
fn extract_attestation(response: &[u8]) -> Result<AttestationData> {
    use ciborium::value::Value;

    let pairs = parse_cbor_map_response(response, "makeCredential")?;

    // 0x02: authData — raw authenticator data bytes signed by the attestation key
    let auth_data = match find_int_key(&pairs, 0x02) {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };

    // 0x03: attStmt map — contains "alg", "sig", and "x5c" array of DER certs
    let att_stmt = match find_int_key(&pairs, 0x03) {
        Some(Value::Map(m)) => m,
        _ => {
            return Err(SoloError::MalformedResponse(
                "makeCredential response missing attStmt (key 0x03)".into(),
            ))
        }
    };

    // "alg" must be -7 (ES256) if present; reject anything else outright.
    if let Some(Value::Integer(i)) = find_text_key(att_stmt, "alg") {
        let alg: i64 = (*i)
            .try_into()
            .map_err(|_| SoloError::MalformedResponse("attStmt alg out of i64 range".into()))?;
        if alg != -7 {
            return Err(SoloError::MalformedResponse(format!(
                "unsupported attestation algorithm {} (expected -7 / ES256)",
                alg
            )));
        }
    } else {
        return Err(SoloError::MalformedResponse(
            "attStmt missing alg (expected -7 / ES256)".into(),
        ));
    }

    // "sig" — DER-encoded ECDSA signature over authData || clientDataHash
    let sig = match find_text_key(att_stmt, "sig") {
        Some(Value::Bytes(b)) => Some(b.clone()),
        _ => None,
    };

    let cert_der = match find_text_key(att_stmt, "x5c") {
        Some(Value::Array(certs)) if !certs.is_empty() => match &certs[0] {
            Value::Bytes(b) => b.clone(),
            _ => return Err(SoloError::MalformedResponse("x5c[0] is not bytes".into())),
        },
        _ => {
            return Err(SoloError::MalformedResponse(
                "attStmt missing x5c array".into(),
            ))
        }
    };

    Ok(AttestationData {
        cert_der,
        auth_data,
        sig,
    })
}

/// Check the attestation signature for an extracted [`AttestationData`].
///
/// Returns `true` only when both `authData` and `attStmt.sig` are present and
/// the signature verifies over `auth_data || client_data_hash` with the
/// public key in the attestation certificate.  A missing signature or
/// authData is treated as a verification failure, never a pass.
fn attestation_signature_valid(att: &AttestationData, client_data_hash: &[u8]) -> bool {
    match (&att.auth_data, &att.sig) {
        (Some(auth_data), Some(sig)) => crate::crypto::verify_attestation_signature(
            &att.cert_der,
            auth_data,
            client_data_hash,
            sig,
        )
        .is_ok(),
        _ => false,
    }
}

/// Verify key authenticity via attestation certificate and signature.
///
/// Sends a CTAP2 makeCredential (0x01) request via CTAPHID_CBOR, extracts the
/// DER-encoded attestation certificate from attStmt.x5c[0], SHA-256 fingerprints
/// it, and compares against known fingerprints in crypto.rs.
///
/// The certificate fingerprint alone is not sufficient: a counterfeit device
/// can replay a copied genuine certificate.  The packed attestation signature
/// (`attStmt.sig` over `authData || clientDataHash`, WebAuthn §8.2) is
/// therefore verified against the certificate's public key, proving the
/// device actually possesses the attestation private key.  If the signature
/// is missing or invalid, the device is reported as failed regardless of the
/// fingerprint.
pub fn cmd_verify(hid: &impl HidDevice, json: bool) -> Result<()> {
    use crate::crypto::{check_attestation_fingerprint, check_cert_validity, sha256_hex};
    use ciborium::value::Value;

    // clientDataHash: fixed 32-byte value (Solo does not verify it for attestation)
    let client_data_hash: Vec<u8> = Sha256::digest(b"solokeys_verify_test").to_vec();

    // If a PIN is set, acquire a PIN token and compute pinUvAuthParam.
    let pin_uv_auth: Option<Vec<u8>> = if crate::ctap2::get_info_client_pin_set(hid)? {
        let pin_token = prompt_and_get_pin_token(hid)?;
        // pinUvAuthParam = HMAC-SHA-256(pinToken, clientDataHash)[0..16]
        Some(crate::ctap2::pin_uv_auth(&pin_token, &client_data_hash)?)
    } else {
        None
    };

    eprintln!("Please press the button on your Solo key");

    // Build CTAP2 makeCredential CBOR request map (integer keys per CTAP2 spec):
    //   0x01: clientDataHash
    //   0x02: rp  {"id": "solokeys.com", "name": "solokeys.com"}
    //   0x03: user {"id": b"verify", "name": "verify", "displayName": "verify"}
    //   0x04: pubKeyCredParams [{"alg": -7, "type": "public-key"}]
    //   0x08: pinUvAuthParam (if PIN is set)
    //   0x09: pinUvAuthProtocol = 1 (if PIN is set)
    let mut cbor_entries: Vec<(i64, Value)> = vec![
        (0x01, cbor_bytes(client_data_hash.clone())),
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

    // CTAP2 makeCredential (0x01)
    let response = crate::ctap2::ctap2_call(hid, 0x01, &cbor_request)?;

    // Extract the attestation: certificate, authData, and signature
    let att = extract_attestation(&response)?;
    let cert_der = &att.cert_der;

    // Verify the packed attestation signature (authData || clientDataHash)
    // against the certificate's public key.  Without this, a counterfeit
    // device replaying a copied genuine certificate would pass.
    let signature_valid = attestation_signature_valid(&att, &client_data_hash);

    let fingerprint = sha256_hex(cert_der);
    let spki_fingerprint = crate::crypto::extract_spki_fingerprint(cert_der)
        .unwrap_or_else(|_| "(could not extract)".into());

    use crate::crypto::AttestationResult;
    let result = check_attestation_fingerprint(cert_der);

    // Check certificate validity dates independently.  An expired cert on a
    // genuine device is still informative — we warn rather than fail, because
    // the fingerprint match is the primary authentication signal.
    let cert_expired = check_cert_validity(cert_der).is_err();

    if json {
        use crate::output::{print_json, VerifyOutput};
        let (device_type, device_name) = if !signature_valid {
            // The fingerprint result is meaningless without a valid signature:
            // the certificate may simply have been copied from a genuine key.
            ("invalid", None)
        } else {
            match &result {
                AttestationResult::GenuineConsumer(n) => ("genuine", Some(n.to_string())),
                AttestationResult::DeveloperDevice(n) => ("developer", Some(n.to_string())),
                AttestationResult::Unknown => ("unknown", None),
            }
        };
        return print_json(&VerifyOutput {
            device_type: device_type.to_string(),
            device_name,
            fingerprint: fingerprint.clone(),
            spki_fingerprint: spki_fingerprint.clone(),
            cert_expired,
            signature_valid,
        });
    }

    println!("Attestation certificate SHA-256: {}", fingerprint);
    println!("Attestation certificate SPKI:    {}", spki_fingerprint);
    if cert_expired {
        println!(
            "WARNING: Attestation certificate has expired. \
             The device may still be genuine but the certificate is no longer valid."
        );
    }
    if !signature_valid {
        println!(
            "FAILED: Attestation signature is invalid. The device did not prove \
             possession of the attestation key matching its certificate; \
             it may be counterfeit."
        );
        return Ok(());
    }
    match result {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::mock::MockDevice;
    use ciborium::value::Value;

    /// Build a raw makeCredential response: status 0x00 + CBOR map with
    /// fmt (0x01), authData (0x02), and attStmt (0x03).
    ///
    /// `auth_data`, `alg`, `sig` are optional so tests can omit fields.
    fn build_make_credential_response(
        auth_data: Option<&[u8]>,
        alg: Option<i64>,
        sig: Option<&[u8]>,
        cert_der: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut att_stmt: Vec<(Value, Value)> = Vec::new();
        if let Some(a) = alg {
            att_stmt.push((cbor_text("alg"), cbor_int(a)));
        }
        if let Some(s) = sig {
            att_stmt.push((cbor_text("sig"), cbor_bytes(s.to_vec())));
        }
        if let Some(c) = cert_der {
            att_stmt.push((cbor_text("x5c"), Value::Array(vec![cbor_bytes(c.to_vec())])));
        }

        let mut entries: Vec<(i64, Value)> = vec![(0x01, cbor_text("packed"))];
        if let Some(ad) = auth_data {
            entries.push((0x02, cbor_bytes(ad.to_vec())));
        }
        entries.push((0x03, Value::Map(att_stmt)));

        let mut out = vec![0x00u8]; // CTAP2 success status
        ciborium::ser::into_writer(&int_map(entries), &mut out).unwrap();
        out
    }

    /// Generate a self-signed P-256 cert and a valid attestation signature
    /// over `auth_data || client_data_hash` with the certified key.
    ///
    /// Returns `(cert_der, auth_data, sig_der)`.
    fn make_signed_attestation(client_data_hash: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
        use p256::pkcs8::DecodePrivateKey;
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate().expect("key gen failed");
        let cert = CertificateParams::default()
            .self_signed(&key_pair)
            .expect("self_signed failed");
        let signing_key =
            SigningKey::from_pkcs8_pem(&key_pair.serialize_pem()).expect("key load failed");

        let auth_data: Vec<u8> = (0u8..37).collect();
        let mut message = auth_data.clone();
        message.extend_from_slice(client_data_hash);
        let sig: DerSignature = signing_key.sign(&message);

        (cert.der().to_vec(), auth_data, sig.as_bytes().to_vec())
    }

    /// The fixed clientDataHash cmd_verify uses.
    fn verify_client_data_hash() -> Vec<u8> {
        Sha256::digest(b"solokeys_verify_test").to_vec()
    }

    // ── extract_attestation ──────────────────────────────────────────────

    #[test]
    fn extract_attestation_full_response() {
        let hash = verify_client_data_hash();
        let (cert_der, auth_data, sig) = make_signed_attestation(&hash);
        let resp =
            build_make_credential_response(Some(&auth_data), Some(-7), Some(&sig), Some(&cert_der));

        let att = extract_attestation(&resp).expect("extraction should succeed");
        assert_eq!(att.cert_der, cert_der);
        assert_eq!(att.auth_data.as_deref(), Some(auth_data.as_slice()));
        assert_eq!(att.sig.as_deref(), Some(sig.as_slice()));
    }

    #[test]
    fn extract_attestation_rejects_wrong_alg() {
        let resp = build_make_credential_response(
            Some(b"authdata"),
            Some(-257), // RS256, not ES256
            Some(b"sig"),
            Some(b"cert"),
        );
        let err = extract_attestation(&resp).unwrap_err();
        assert!(
            err.to_string().contains("-257"),
            "error should name the unsupported algorithm: {}",
            err
        );
    }

    #[test]
    fn extract_attestation_rejects_missing_alg() {
        let resp =
            build_make_credential_response(Some(b"authdata"), None, Some(b"sig"), Some(b"cert"));
        assert!(extract_attestation(&resp).is_err());
    }

    #[test]
    fn extract_attestation_rejects_missing_x5c() {
        let resp = build_make_credential_response(Some(b"authdata"), Some(-7), Some(b"sig"), None);
        assert!(extract_attestation(&resp).is_err());
    }

    #[test]
    fn extract_attestation_tolerates_missing_sig_and_auth_data() {
        // Missing sig/authData is reported via signature_valid=false, not an
        // extraction error, so the certificate fingerprint can still be shown.
        let resp = build_make_credential_response(None, Some(-7), None, Some(b"cert"));
        let att = extract_attestation(&resp).expect("extraction should succeed");
        assert_eq!(att.cert_der, b"cert");
        assert!(att.auth_data.is_none());
        assert!(att.sig.is_none());
    }

    // ── attestation_signature_valid ──────────────────────────────────────

    #[test]
    fn signature_valid_accepts_genuine_attestation() {
        let hash = verify_client_data_hash();
        let (cert_der, auth_data, sig) = make_signed_attestation(&hash);
        let att = AttestationData {
            cert_der,
            auth_data: Some(auth_data),
            sig: Some(sig),
        };
        assert!(attestation_signature_valid(&att, &hash));
    }

    #[test]
    fn signature_valid_rejects_tampered_sig() {
        let hash = verify_client_data_hash();
        let (cert_der, auth_data, mut sig) = make_signed_attestation(&hash);
        *sig.last_mut().unwrap() ^= 0x01;
        let att = AttestationData {
            cert_der,
            auth_data: Some(auth_data),
            sig: Some(sig),
        };
        assert!(!attestation_signature_valid(&att, &hash));
    }

    #[test]
    fn signature_valid_rejects_replayed_cert() {
        // Counterfeit scenario: genuine cert, but the signature was made by a
        // different (attacker) key because the attacker lacks the genuine
        // attestation private key.
        let hash = verify_client_data_hash();
        let (genuine_cert, _, _) = make_signed_attestation(&hash);
        let (_, auth_data, attacker_sig) = make_signed_attestation(&hash);
        let att = AttestationData {
            cert_der: genuine_cert,
            auth_data: Some(auth_data),
            sig: Some(attacker_sig),
        };
        assert!(!attestation_signature_valid(&att, &hash));
    }

    #[test]
    fn signature_valid_rejects_missing_sig() {
        let hash = verify_client_data_hash();
        let (cert_der, auth_data, _) = make_signed_attestation(&hash);
        let att = AttestationData {
            cert_der,
            auth_data: Some(auth_data),
            sig: None,
        };
        assert!(!attestation_signature_valid(&att, &hash));
    }

    #[test]
    fn signature_valid_rejects_missing_auth_data() {
        let hash = verify_client_data_hash();
        let (cert_der, _, sig) = make_signed_attestation(&hash);
        let att = AttestationData {
            cert_der,
            auth_data: None,
            sig: Some(sig),
        };
        assert!(!attestation_signature_valid(&att, &hash));
    }

    // ── cmd_verify end-to-end with MockDevice ────────────────────────────

    /// getInfo response: status 0x00 + empty CBOR map (no clientPin option,
    /// so cmd_verify skips the PIN flow).
    fn get_info_response() -> Vec<u8> {
        vec![0x00, 0xA0]
    }

    #[test]
    fn cmd_verify_succeeds_with_valid_attestation() {
        let hash = verify_client_data_hash();
        let (cert_der, auth_data, sig) = make_signed_attestation(&hash);
        let mc_resp =
            build_make_credential_response(Some(&auth_data), Some(-7), Some(&sig), Some(&cert_der));
        let device = MockDevice::new(vec![Ok(get_info_response()), Ok(mc_resp)]);
        assert!(cmd_verify(&device, true).is_ok());
    }

    #[test]
    fn cmd_verify_succeeds_with_invalid_signature() {
        // Tampered signature: the command reports FAILED but does not error —
        // consistent with the existing unknown-fingerprint behaviour.
        let hash = verify_client_data_hash();
        let (cert_der, auth_data, mut sig) = make_signed_attestation(&hash);
        *sig.last_mut().unwrap() ^= 0x01;
        let mc_resp =
            build_make_credential_response(Some(&auth_data), Some(-7), Some(&sig), Some(&cert_der));
        let device = MockDevice::new(vec![Ok(get_info_response()), Ok(mc_resp)]);
        assert!(cmd_verify(&device, true).is_ok());
    }

    #[test]
    fn cmd_verify_errors_on_unsupported_alg() {
        let hash = verify_client_data_hash();
        let (cert_der, auth_data, sig) = make_signed_attestation(&hash);
        let mc_resp = build_make_credential_response(
            Some(&auth_data),
            Some(-8), // EdDSA, unsupported
            Some(&sig),
            Some(&cert_der),
        );
        let device = MockDevice::new(vec![Ok(get_info_response()), Ok(mc_resp)]);
        assert!(cmd_verify(&device, true).is_err());
    }
}
