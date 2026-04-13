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
}
