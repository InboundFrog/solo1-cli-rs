/// Cryptographic utilities: key generation, signing, verification, and
/// attestation fingerprint checking.
use std::path::Path;

use x509_cert::der::{Decode, Encode};
use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    SecretKey,
};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

use crate::error::{Result, SoloError};

/// Known attestation certificate fingerprints (SHA-256 of DER cert bytes).
/// These match the fingerprints checked in the Python reference (key.py verify command).
pub const SOLO_V3_FINGERPRINT: &str =
    "72d5833126acfce9a8e8266018e6414934c8be4ab8685f91b0992113bbd43295";
pub const SOLO_HACKER_FINGERPRINT: &str =
    "d06d6ccbda7de56a1627c2a7899c35a2a316c851b36ad8ed7ed78479bb787ef7";
pub const SOLO_EMULATION_FINGERPRINT: &str =
    "0592e1b2ba8e610d629a9bc015197e4adadc3136e0a0a176d9b57d17a6b80b38";
pub const SOLO_TAP_FINGERPRINT: &str =
    "b36b03211164db1d60413ec0f8d827e0eec204be29065300940ed9c59b90533f";
pub const SOMU_FINGERPRINT: &str =
    "8dde12db98e87c90c9d6231a9cd8fe3f54df82b73d732e8e72ec9f98f8b5c6c1";
pub const SOLO_FINGERPRINT: &str =
    "327585e49e496cffdebc4b280608183134e7cbf4c01670679476291cd9b98104";

pub const KNOWN_FINGERPRINTS: &[(&str, &str)] = &[
    (
        SOLO_V3_FINGERPRINT,
        "Valid Solo (<=3.0.0) firmware from SoloKeys.",
    ),
    (SOLO_HACKER_FINGERPRINT, "Solo Hacker firmware."),
    (SOLO_EMULATION_FINGERPRINT, "Local software emulation."),
    (
        SOLO_TAP_FINGERPRINT,
        "Valid Solo Tap with firmware from SoloKeys.",
    ),
    (SOMU_FINGERPRINT, "Valid Somu with firmware from SoloKeys."),
    (SOLO_FINGERPRINT, "Valid Solo with firmware from SoloKeys."),
];

/// Generate a new ECDSA P-256 key pair.
/// Returns (private_key_pem, public_key_pem).
pub fn generate_keypair() -> Result<(String, String)> {
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let secret_key = SecretKey::from(signing_key.as_nonzero_scalar().clone());
    let private_pem = secret_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| SoloError::CryptoError(format!("PEM encode error: {}", e)))?;
    let verifying_key = VerifyingKey::from(&signing_key);
    let public_pem = verifying_key
        .to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| SoloError::CryptoError(format!("Public key PEM encode error: {}", e)))?;
    Ok((private_pem.to_string(), public_pem))
}

/// Load a signing key from a PEM file path.
pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let pem = std::fs::read_to_string(path)?;
    SigningKey::from_pkcs8_pem(&pem)
        .map_err(|e| SoloError::CryptoError(format!("Failed to load key: {}", e)))
}

/// Sign the firmware bytes with the given key.
/// Returns the DER-encoded signature bytes.
pub fn sign_firmware(key: &SigningKey, firmware_bytes: &[u8]) -> Result<Vec<u8>> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{DerSignature, Signature};
    let hash = Sha256::digest(firmware_bytes);
    let sig: Signature = key.sign(&hash);
    let der_sig: DerSignature = sig.to_der();
    Ok(der_sig.as_bytes().to_vec())
}

/// Compute SHA-256 of the given bytes, returning hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

/// Compute SHA-256 of a file.
pub fn sha256_file(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    Ok(Sha256::digest(&data).to_vec())
}

/// The result of checking an attestation certificate fingerprint.
///
/// Variants carry the device name as a `&'static str`.
#[derive(Debug, PartialEq)]
pub enum AttestationResult {
    /// The certificate fingerprint matched a known genuine consumer device.
    GenuineConsumer(&'static str),
    /// The certificate fingerprint matched a developer or non-production device.
    /// These devices are real SoloKeys builds but are not genuine consumer hardware.
    /// This variant is included for developer convenience and does **not** indicate
    /// that the device is a genuine end-user product.
    DeveloperDevice(&'static str),
    /// The certificate fingerprint did not match any known fingerprint.
    Unknown,
}

/// Check whether a DER-encoded attestation certificate matches a known SoloKeys fingerprint.
///
/// ## What this check does
///
/// Computes `SHA-256(cert_der)` and compares it against a hardcoded list of
/// known-good fingerprints.  If a match is found the function returns the
/// device category (`GenuineConsumer` or `DeveloperDevice`) together with the
/// device name string.  If no match is found it returns `Unknown`.
///
/// ## What this check does NOT prove
///
/// - **No certificate chain validation.** The attestation certificate is not
///   verified against a trusted root CA.  Chain validation is a FIDO requirement
///   for full attestation verification (see CTAP2 §8.1 and WebAuthn §6.5.3).
/// - **No validity date check.** An expired attestation certificate will still
///   match if its full DER bytes are identical to the known fingerprint.
/// - **No revocation check.** There is no CRL or OCSP query.
/// - **Fingerprints cover the full certificate DER, not just the public key.**
///   Any change to the certificate — e.g., updated validity dates or extensions —
///   will cause a mismatch even for a device with a genuine SoloKeys attestation
///   key.  Newer firmware builds may produce certificates whose fingerprints are
///   not yet listed here.
///
/// ## Developer device fingerprints
///
/// `SOLO_HACKER_FINGERPRINT` and `SOLO_EMULATION_FINGERPRINT` match developer /
/// non-production builds.  They are included here for developer convenience but
/// are returned as `DeveloperDevice`, not `GenuineConsumer`.  A
/// `DeveloperDevice` result does **not** indicate genuine consumer hardware.
pub fn check_attestation_fingerprint(cert_der: &[u8]) -> AttestationResult {
    let fp = sha256_hex(cert_der);
    match fp.as_str() {
        f if f == SOLO_V3_FINGERPRINT => AttestationResult::GenuineConsumer("Solo v3"),
        f if f == SOLO_TAP_FINGERPRINT => AttestationResult::GenuineConsumer("Solo Tap"),
        f if f == SOMU_FINGERPRINT => AttestationResult::GenuineConsumer("Solo Mu"),
        f if f == SOLO_FINGERPRINT => AttestationResult::GenuineConsumer("Solo 1"),
        f if f == SOLO_HACKER_FINGERPRINT => AttestationResult::DeveloperDevice("Solo Hacker"),
        f if f == SOLO_EMULATION_FINGERPRINT => {
            AttestationResult::DeveloperDevice("Solo Emulation")
        }
        _ => AttestationResult::Unknown,
    }
}

// ---------------------------------------------------------------------------
// SPKI fingerprint constants
// ---------------------------------------------------------------------------
//
// TODO(0003): The SPKI fingerprint constants below are placeholders.  They
// cannot be populated without running the tool against real hardware and
// extracting the attestation certificate DER bytes, then computing:
//
//   `sha256_hex(&cert.tbs_certificate.subject_public_key_info.to_der()?)`
//
// See docs/reviews/20260414_0001/0003-attestation_chain_validation.md for
// the full migration plan.  Until these constants are populated, SPKI-based
// matching is NOT used for verification; the existing DER-fingerprint path
// in `check_attestation_fingerprint` remains the authoritative check.
//
// NOT implemented (scope boundary):
// - CRL or OCSP checking (requires network access)
// - Full certificate chain validation (no root CA cert is stored in this repo)
//
// These are also documented in the issue referenced above.

pub const SOLO_V3_SPKI_FINGERPRINT: &str = "";       // TODO(0003): populate from hardware
pub const SOMU_SPKI_FINGERPRINT: &str = "";           // TODO(0003): populate from hardware
pub const SOLO_SPKI_FINGERPRINT: &str = "";           // TODO(0003): populate from hardware
pub const SOLO_TAP_SPKI_FINGERPRINT: &str = "6b50560fef4c768b6e9a7a7749415a7c01d39842be3e4f7b8e859ba2a4be7049";
pub const SOLO_HACKER_SPKI_FINGERPRINT: &str = "";    // TODO(0003): populate from hardware
pub const SOLO_EMULATION_SPKI_FINGERPRINT: &str = ""; // TODO(0003): populate from hardware

// ---------------------------------------------------------------------------
// New certificate utility functions
// ---------------------------------------------------------------------------

/// Extract the SHA-256 fingerprint of the Subject Public Key Info (SPKI)
/// from a DER-encoded X.509 certificate.
///
/// Unlike `sha256_hex(cert_der)` (which fingerprints the entire certificate),
/// this function fingerprints only the `SubjectPublicKeyInfo` structure inside
/// the TBSCertificate.  Two certificates for the same attestation key but with
/// different validity dates or extensions will produce the **same** SPKI
/// fingerprint and **different** full-DER fingerprints.
///
/// This is the building block for future SPKI pinning (see TODO(0003) above).
pub fn extract_spki_fingerprint(cert_der: &[u8]) -> Result<String> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| SoloError::CryptoError(format!("Certificate parse error: {}", e)))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| SoloError::CryptoError(format!("SPKI encode error: {}", e)))?;
    Ok(sha256_hex(&spki_der))
}

/// Check whether the current system time falls within the certificate's
/// `notBefore`..=`notAfter` validity window.
///
/// Returns `Ok(())` if the certificate is currently valid.
/// Returns `Err(SoloError::CryptoError(...))` if:
/// - The certificate has expired (now > notAfter).
/// - The certificate is not yet valid (now < notBefore).
/// - The certificate cannot be parsed.
///
/// This check uses the local system clock and does not contact any external
/// time service.  Clock skew on the host may produce false positives.
pub fn check_cert_validity(cert_der: &[u8]) -> Result<()> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| SoloError::CryptoError(format!("Certificate parse error: {}", e)))?;

    let validity = cert.tbs_certificate.validity;
    let now = std::time::SystemTime::now();
    let not_before = validity.not_before.to_system_time();
    let not_after = validity.not_after.to_system_time();

    if now < not_before {
        return Err(SoloError::CryptoError(format!(
            "Certificate is not yet valid (notBefore: {})",
            validity.not_before
        )));
    }
    if now > not_after {
        return Err(SoloError::CryptoError(format!(
            "Certificate has expired (notAfter: {})",
            validity.not_after
        )));
    }
    Ok(())
}

/// Websafe base64 encoding (RFC 4648 URL-safe, no padding).
pub fn websafe_b64_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

/// Websafe base64 decoding.
pub fn websafe_b64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| SoloError::FirmwareError(format!("Base64 decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websafe_b64_roundtrip() {
        let data = b"Hello, SoloKey! \x00\x01\x02\xff";
        let encoded = websafe_b64_encode(data);
        // Should not contain + or / or =
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
        let decoded = websafe_b64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_websafe_b64_known() {
        // "Man" in standard base64 is "TWFu"; URL-safe no pad is same
        let encoded = websafe_b64_encode(b"Man");
        assert_eq!(encoded, "TWFu");
        let decoded = websafe_b64_decode("TWFu").unwrap();
        assert_eq!(decoded, b"Man");
    }

    #[test]
    fn test_websafe_b64_with_special_chars() {
        // bytes that would produce + and / in standard base64
        // 0xFB 0xFF -> standard "+/" equivalent area
        let data = vec![0xfb, 0xff, 0xfe];
        let encoded = websafe_b64_encode(&data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        let decoded = websafe_b64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_generate_keypair() {
        let (priv_pem, pub_pem) = generate_keypair().unwrap();
        assert!(priv_pem.contains("PRIVATE KEY"));
        assert!(pub_pem.contains("PUBLIC KEY"));
    }

    #[test]
    fn test_sign_and_verify_firmware() {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let firmware = b"fake firmware data for testing";
        let sig_der = sign_firmware(&signing_key, firmware).unwrap();
        assert!(!sig_der.is_empty());

        // Verify using p256
        use p256::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};
        let vk = VerifyingKey::from(&signing_key);
        let hash = Sha256::digest(firmware);
        let sig = DerSignature::try_from(sig_der.as_slice()).unwrap();
        assert!(vk.verify(&hash, &sig).is_ok());
    }

    #[test]
    fn test_sha256_hex() {
        // SHA-256 of empty string
        let result = sha256_hex(b"");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_attestation_fingerprint_no_match() {
        let data = b"not a real certificate";
        let result = check_attestation_fingerprint(data);
        assert_eq!(result, AttestationResult::Unknown);
    }

    #[test]
    fn test_attestation_fingerprint_constants_valid_hex() {
        // Verify all fingerprint constants are valid 32-byte hex strings
        for (fp, _name) in KNOWN_FINGERPRINTS {
            let bytes = hex::decode(fp).expect("fingerprint should be valid hex");
            assert_eq!(bytes.len(), 32, "fingerprint should be 32 bytes: {}", fp);
        }
    }

    #[test]
    fn test_attestation_fingerprint_match() {
        // Verify that fingerprint constants are valid hex
        let fp_bytes = hex::decode(SOLO_V3_FINGERPRINT).unwrap();
        assert_eq!(fp_bytes.len(), 32);
        // Just verify all fingerprint constants are valid hex
        assert!(hex::decode(SOLO_HACKER_FINGERPRINT).is_ok());
        assert!(hex::decode(SOMU_FINGERPRINT).is_ok());
        assert!(hex::decode(SOLO_TAP_FINGERPRINT).is_ok());
        assert!(hex::decode(SOLO_EMULATION_FINGERPRINT).is_ok());
        assert!(hex::decode(SOLO_FINGERPRINT).is_ok());
        assert_eq!(KNOWN_FINGERPRINTS.len(), 6);
    }

    // -----------------------------------------------------------------------
    // Helpers and tests for extract_spki_fingerprint / check_cert_validity
    // -----------------------------------------------------------------------

    /// Generate a self-signed DER certificate with the given validity window,
    /// using a freshly generated key pair.
    ///
    /// Returns `(der_bytes, key_pem)` so callers can reuse the same key.
    #[cfg(test)]
    fn make_test_cert_with_key(
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> (Vec<u8>, String) {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::generate().expect("key gen failed");
        let key_pem = key_pair.serialize_pem();
        let mut params = CertificateParams::default();
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params.self_signed(&key_pair).expect("self_signed failed");
        (cert.der().to_vec(), key_pem)
    }

    /// Generate a self-signed DER certificate with a given validity window,
    /// reusing a specific PEM-encoded key pair.
    #[cfg(test)]
    fn make_test_cert_from_key(
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
        key_pem: &str,
    ) -> Vec<u8> {
        use rcgen::{CertificateParams, KeyPair};

        let key_pair = KeyPair::from_pem(key_pem).expect("key load failed");
        let mut params = CertificateParams::default();
        params.not_before = not_before;
        params.not_after = not_after;
        let cert = params.self_signed(&key_pair).expect("self_signed failed");
        cert.der().to_vec()
    }

    #[test]
    fn extract_spki_fingerprint_is_stable() {
        // Two certs with the SAME key but DIFFERENT validity windows should
        // have the same SPKI fingerprint but different full-DER fingerprints.
        let now = time::OffsetDateTime::now_utc();
        let past = now - time::Duration::days(365);
        let future = now + time::Duration::days(365);
        let far_future = now + time::Duration::days(730);

        let (der1, key_pem) = make_test_cert_with_key(past, future);
        let der2 = make_test_cert_from_key(past - time::Duration::days(10), far_future, &key_pem);

        let spki_fp1 = extract_spki_fingerprint(&der1).expect("spki extract failed");
        let spki_fp2 = extract_spki_fingerprint(&der2).expect("spki extract failed");

        // Same key → same SPKI fingerprint
        assert_eq!(spki_fp1, spki_fp2, "SPKI fingerprint should be key-stable");

        // Different validity window → different full-DER fingerprint
        let der_fp1 = sha256_hex(&der1);
        let der_fp2 = sha256_hex(&der2);
        assert_ne!(
            der_fp1, der_fp2,
            "Full DER fingerprint should differ between re-issued certs"
        );
    }

    #[test]
    fn check_cert_validity_valid() {
        let now = time::OffsetDateTime::now_utc();
        let (der, _) = make_test_cert_with_key(
            now - time::Duration::days(1),
            now + time::Duration::days(365),
        );
        assert!(
            check_cert_validity(&der).is_ok(),
            "Currently-valid cert should pass"
        );
    }

    #[test]
    fn check_cert_validity_expired() {
        let now = time::OffsetDateTime::now_utc();
        let (der, _) = make_test_cert_with_key(
            now - time::Duration::days(730),
            now - time::Duration::days(365),
        );
        let err = check_cert_validity(&der).expect_err("Expired cert should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("expired") || msg.contains("Expired"),
            "Error should mention expiry, got: {}",
            msg
        );
    }

    #[test]
    fn check_cert_validity_not_yet_valid() {
        let now = time::OffsetDateTime::now_utc();
        let (der, _) = make_test_cert_with_key(
            now + time::Duration::days(1),
            now + time::Duration::days(366),
        );
        let err = check_cert_validity(&der).expect_err("Not-yet-valid cert should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("not yet valid") || msg.contains("Not yet valid"),
            "Error should mention not-yet-valid, got: {}",
            msg
        );
    }

    #[test]
    fn spki_fingerprint_differs_from_der_fingerprint() {
        let now = time::OffsetDateTime::now_utc();
        let (der, _) = make_test_cert_with_key(
            now - time::Duration::days(1),
            now + time::Duration::days(365),
        );
        let spki_fp = extract_spki_fingerprint(&der).expect("spki extract failed");
        let der_fp = sha256_hex(&der);
        assert_ne!(
            spki_fp, der_fp,
            "SPKI fingerprint must differ from full-DER fingerprint"
        );
    }

    #[test]
    fn extract_spki_fingerprint_rejects_garbage() {
        let result = extract_spki_fingerprint(b"not a certificate at all");
        assert!(result.is_err(), "Garbage input should return Err");
    }

    #[test]
    fn check_cert_validity_rejects_garbage() {
        let result = check_cert_validity(b"not a certificate at all");
        assert!(result.is_err(), "Garbage input should return Err");
    }
}
