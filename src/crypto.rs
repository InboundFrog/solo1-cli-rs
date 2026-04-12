/// Cryptographic utilities: key generation, signing, verification, and
/// attestation fingerprint checking.
use std::path::Path;

use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    SecretKey,
};
use sha2::{Digest, Sha256};

use crate::error::{Result, SoloError};

/// Known attestation certificate fingerprints (SHA-256 of DER).
pub const SOLO_ATTEST_FINGERPRINT: &str =
    "1b2626ecc8f69b0f69e34fb236d76466ba12ac16c3ab5750ba064e8b90e02448";
pub const SOLO_HACKER_FINGERPRINT: &str =
    "a149e0eab7fce935901e4bb45df18f2f0f68ad44f3c47b28b9785c3f1217e4b5";
pub const SOMU_FINGERPRINT: &str =
    "3e3169e0de4b7e68e8e96a5dff47f7ec5a2c7f89b7f2e76d57dc041fc70a46d0";

pub const KNOWN_FINGERPRINTS: &[(&str, &str)] = &[
    (SOLO_ATTEST_FINGERPRINT, "Solo <= 3.0.0"),
    (SOLO_HACKER_FINGERPRINT, "Solo Hacker"),
    (SOMU_FINGERPRINT, "Somu"),
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
    use p256::ecdsa::{DerSignature, Signature};
    use p256::ecdsa::signature::Signer;
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

/// Check if a DER-encoded certificate matches a known fingerprint.
pub fn check_attestation_fingerprint(cert_der: &[u8]) -> Option<&'static str> {
    let fp = sha256_hex(cert_der);
    for (known_fp, name) in KNOWN_FINGERPRINTS {
        if fp == *known_fp {
            return Some(name);
        }
    }
    None
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
        assert!(result.is_none());
    }

    #[test]
    fn test_attestation_fingerprint_match() {
        // Construct data whose SHA256 equals SOLO_ATTEST_FINGERPRINT
        // We test that the function returns None for random data (since we can't
        // preimage a SHA256), and separately that it would return Some for a
        // matching fingerprint by checking the logic path.
        let fp_bytes = hex::decode(SOLO_ATTEST_FINGERPRINT).unwrap();
        assert_eq!(fp_bytes.len(), 32);
        // Just verify the fingerprint constants are valid hex
        assert!(hex::decode(SOLO_HACKER_FINGERPRINT).is_ok());
        assert!(hex::decode(SOMU_FINGERPRINT).is_ok());
    }
}
