use serde::Serialize;
use crate::error::Result;

#[derive(Serialize)]
pub struct MakeCredentialOutput {
    pub credential_id: String,   // hex
}

#[derive(Serialize)]
pub struct ChallengeResponseOutput {
    pub hmac_output: String,     // hex, 32 bytes
}

#[derive(Serialize)]
pub struct CredentialEntry {
    pub rp_id: String,
    pub user_name: String,
    pub credential_id: String,   // base64, matching the human display
}

#[derive(Serialize)]
pub struct CredentialListOutput {
    pub credentials: Vec<CredentialEntry>,
}

#[derive(Serialize)]
pub struct DeviceInfo {
    pub path: String,
    pub serial: Option<String>,
    pub product: Option<String>,
    pub manufacturer: Option<String>,
}

#[derive(Serialize)]
pub struct ListOutput {
    pub devices: Vec<DeviceInfo>,
}

#[derive(Serialize)]
pub struct VerifyOutput {
    /// "genuine", "developer", or "unknown"
    pub device_type: String,
    pub device_name: Option<String>,
    /// SHA-256 of the full certificate DER bytes.
    pub fingerprint: String,
    /// SHA-256 of the SubjectPublicKeyInfo (SPKI) only — stable across certificate re-issuance.
    pub spki_fingerprint: String,
    /// Whether the attestation certificate's validity period has expired.
    /// A genuine device may still have an expired cert; expiry is reported as
    /// a warning rather than an authentication failure.
    pub cert_expired: bool,
}

#[derive(Serialize)]
pub struct VersionOutput {
    pub firmware_version: String,
}

#[derive(Serialize)]
pub struct CliVersionOutput {
    pub name: String,
    pub version: String,
}

/// Serialize `value` to pretty JSON and print to stdout.
pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)
        .map_err(crate::error::SoloError::JsonError)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_credential_output_serializes() {
        let out = MakeCredentialOutput { credential_id: "deadbeef".into() };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["credential_id"], "deadbeef");
    }

    #[test]
    fn credential_list_output_serializes() {
        let out = CredentialListOutput {
            credentials: vec![CredentialEntry {
                rp_id: "example.com".into(),
                user_name: "alice".into(),
                credential_id: "abc123==".into(),
            }],
        };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["credentials"][0]["rp_id"], "example.com");
    }

    #[test]
    fn verify_output_genuine_serializes() {
        let out = VerifyOutput {
            device_type: "genuine".into(),
            device_name: Some("Solo v3".into()),
            fingerprint: "aabbcc".into(),
            spki_fingerprint: "ddeeff".into(),
            cert_expired: false,
        };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["device_type"], "genuine");
        assert_eq!(v["device_name"], "Solo v3");
        assert_eq!(v["cert_expired"], false);
    }

    #[test]
    fn verify_output_expired_cert_serializes() {
        let out = VerifyOutput {
            device_type: "genuine".into(),
            device_name: Some("Solo v3".into()),
            fingerprint: "aabbcc".into(),
            spki_fingerprint: "ddeeff".into(),
            cert_expired: true,
        };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["cert_expired"], true);
    }

    #[test]
    fn list_output_empty_serializes() {
        let out = ListOutput { devices: vec![] };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["devices"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn challenge_response_output_serializes() {
        let out = ChallengeResponseOutput {
            hmac_output: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".into(),
        };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["hmac_output"], "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    }

    #[test]
    fn version_output_serializes() {
        let out = VersionOutput { firmware_version: "4.1.2".into() };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["firmware_version"], "4.1.2");
    }

    #[test]
    fn list_output_non_empty_serializes() {
        let out = ListOutput {
            devices: vec![DeviceInfo {
                path: "/dev/hid123".into(),
                serial: Some("ABC-123".into()),
                product: Some("SoloKeys Solo".into()),
                manufacturer: Some("SoloKeys".into()),
            }],
        };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["devices"][0]["path"], "/dev/hid123");
        assert_eq!(v["devices"][0]["serial"], "ABC-123");
        assert_eq!(v["devices"][0]["product"], "SoloKeys Solo");
        assert_eq!(v["devices"][0]["manufacturer"], "SoloKeys");
    }

    #[test]
    fn cli_version_output_serializes() {
        let out = CliVersionOutput {
            name: "solo1-cli-rs".into(),
            version: "1.2.3".into(),
        };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["name"], "solo1-cli-rs");
        assert_eq!(v["version"], "1.2.3");
    }
}
