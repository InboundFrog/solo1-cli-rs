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
    pub fingerprint: String,
}

#[derive(Serialize)]
pub struct VersionOutput {
    pub firmware_version: String,
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
        };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["device_type"], "genuine");
        assert_eq!(v["device_name"], "Solo v3");
    }

    #[test]
    fn list_output_empty_serializes() {
        let out = ListOutput { devices: vec![] };
        let json = serde_json::to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["devices"].as_array().unwrap().len(), 0);
    }
}
