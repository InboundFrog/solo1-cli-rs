/// Firmware file handling: Intel HEX parsing, merging, signing, and the
/// firmware JSON format used by the Solo bootloader.
use std::collections::HashMap;
use std::path::Path;

use ihex::Record;
use serde::{Deserialize, Serialize};

use crate::crypto::{websafe_b64_decode, websafe_b64_encode};
use crate::error::{Result, SoloError};

/// The firmware JSON format used by the Solo 1 bootloader.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirmwareJson {
    pub firmware: String,
    pub signature: String,
    #[serde(default)]
    pub versions: HashMap<String, VersionedSignature>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VersionedSignature {
    pub signature: String,
}

impl FirmwareJson {
    /// Load from a JSON file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    /// Decode the firmware binary from the websafe base64 field.
    pub fn firmware_bytes(&self) -> Result<Vec<u8>> {
        websafe_b64_decode(&self.firmware)
    }

    /// Decode the signature from the websafe base64 field.
    pub fn signature_bytes(&self) -> Result<Vec<u8>> {
        websafe_b64_decode(&self.signature)
    }

    /// Select the appropriate signature based on firmware version.
    /// Version constraint format: "<=2.5.3" or ">2.5.3"
    pub fn signature_for_version(&self, version: &FirmwareVersion) -> Result<Vec<u8>> {
        if self.versions.is_empty() {
            return self.signature_bytes();
        }
        for (constraint, sig) in &self.versions {
            if version_matches_constraint(version, constraint)? {
                return websafe_b64_decode(&sig.signature);
            }
        }
        self.signature_bytes()
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// A semantic version (major.minor.patch).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirmwareVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl FirmwareVersion {
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        FirmwareVersion { major, minor, patch }
    }

    pub fn parse(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.trim_start_matches('v').split('.').collect();
        if parts.len() != 3 {
            return Err(SoloError::FirmwareError(format!(
                "Invalid version string: {}",
                s
            )));
        }
        let major = parts[0]
            .parse()
            .map_err(|_| SoloError::FirmwareError(format!("Invalid major: {}", parts[0])))?;
        let minor = parts[1]
            .parse()
            .map_err(|_| SoloError::FirmwareError(format!("Invalid minor: {}", parts[1])))?;
        let patch = parts[2]
            .parse()
            .map_err(|_| SoloError::FirmwareError(format!("Invalid patch: {}", parts[2])))?;
        Ok(FirmwareVersion { major, minor, patch })
    }
}

impl std::fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Check if a version matches a constraint like "<=2.5.3" or ">2.5.3".
pub fn version_matches_constraint(
    version: &FirmwareVersion,
    constraint: &str,
) -> Result<bool> {
    if let Some(rest) = constraint.strip_prefix("<=") {
        let bound = FirmwareVersion::parse(rest)?;
        Ok(*version <= bound)
    } else if let Some(rest) = constraint.strip_prefix(">=") {
        let bound = FirmwareVersion::parse(rest)?;
        Ok(*version >= bound)
    } else if let Some(rest) = constraint.strip_prefix('<') {
        let bound = FirmwareVersion::parse(rest)?;
        Ok(*version < bound)
    } else if let Some(rest) = constraint.strip_prefix('>') {
        let bound = FirmwareVersion::parse(rest)?;
        Ok(*version > bound)
    } else if let Some(rest) = constraint.strip_prefix('=') {
        let bound = FirmwareVersion::parse(rest)?;
        Ok(*version == bound)
    } else {
        Err(SoloError::FirmwareError(format!(
            "Unknown version constraint: {}",
            constraint
        )))
    }
}

/// Parse an Intel HEX file into a flat binary buffer.
/// Returns (base_address, bytes).
pub fn parse_hex_file(path: &Path) -> Result<(u32, Vec<u8>)> {
    let content = std::fs::read_to_string(path)?;
    parse_hex_string(&content)
}

/// Parse Intel HEX content from a string.
pub fn parse_hex_string(content: &str) -> Result<(u32, Vec<u8>)> {
    let reader = ihex::Reader::new(content);
    let mut records: Vec<Record> = Vec::new();
    for record in reader {
        let r = record.map_err(|e| {
            SoloError::FirmwareError(format!("Intel HEX parse error: {:?}", e))
        })?;
        records.push(r);
    }
    hex_records_to_binary(&records)
}

/// Convert Intel HEX records to a flat binary.
/// Returns (base_address, bytes).
pub fn hex_records_to_binary(records: &[Record]) -> Result<(u32, Vec<u8>)> {
    let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut base_addr: u32 = 0;
    let mut upper_linear: u32 = 0;

    for record in records {
        match record {
            Record::Data { offset, value } => {
                let addr = upper_linear + (*offset as u32) + base_addr;
                segments.push((addr, value.clone()));
            }
            Record::ExtendedLinearAddress(upper) => {
                upper_linear = (*upper as u32) << 16;
                base_addr = 0;
            }
            Record::ExtendedSegmentAddress(seg) => {
                base_addr = (*seg as u32) << 4;
                upper_linear = 0;
            }
            Record::StartLinearAddress(_) | Record::StartSegmentAddress { .. } => {}
            Record::EndOfFile => break,
        }
    }

    if segments.is_empty() {
        return Err(SoloError::FirmwareError(
            "No data records in HEX file".into(),
        ));
    }

    // Sort by address
    segments.sort_by_key(|(addr, _)| *addr);

    let min_addr = segments[0].0;
    let max_addr = segments
        .iter()
        .map(|(addr, data)| addr + data.len() as u32)
        .max()
        .unwrap();

    let size = (max_addr - min_addr) as usize;
    let mut binary = vec![0xFFu8; size];

    for (addr, data) in &segments {
        let offset = (addr - min_addr) as usize;
        binary[offset..offset + data.len()].copy_from_slice(data);
    }

    Ok((min_addr, binary))
}

/// Merge multiple Intel HEX files into one output HEX file.
/// Optionally inject attestation key and certificate.
pub fn merge_hex_files(
    inputs: &[&Path],
    output: &Path,
    attestation_key: Option<&Path>,
    attestation_cert: Option<&Path>,
) -> Result<()> {
    let mut all_segments: Vec<(u32, Vec<u8>)> = Vec::new();

    for input_path in inputs {
        let content = std::fs::read_to_string(input_path)?;
        let reader = ihex::Reader::new(&content);
        let mut upper_linear: u32 = 0;
        let mut base_addr: u32 = 0;
        for record in reader {
            let r = record.map_err(|e| {
                SoloError::FirmwareError(format!("HEX parse error in {:?}: {:?}", input_path, e))
            })?;
            match r {
                Record::Data { offset, value } => {
                    let addr = upper_linear + (offset as u32) + base_addr;
                    all_segments.push((addr, value));
                }
                Record::ExtendedLinearAddress(upper) => {
                    upper_linear = (upper as u32) << 16;
                    base_addr = 0;
                }
                Record::ExtendedSegmentAddress(seg) => {
                    base_addr = (seg as u32) << 4;
                    upper_linear = 0;
                }
                _ => {}
            }
        }
    }

    // Inject attestation data at page 113 (address = 0x08000000 + 113 * 2048)
    const ATTEST_PAGE: u32 = 113;
    const PAGE_SIZE: u32 = 2048;
    const BASE_ADDR: u32 = 0x08000000;
    let attest_addr = BASE_ADDR + ATTEST_PAGE * PAGE_SIZE;

    if let Some(key_path) = attestation_key {
        let key_bytes = std::fs::read(key_path)?;
        // Write key at attestation page offset 0
        let trimmed = if key_bytes.len() > PAGE_SIZE as usize {
            key_bytes[..PAGE_SIZE as usize].to_vec()
        } else {
            key_bytes
        };
        all_segments.push((attest_addr, trimmed));
    }

    if let Some(cert_path) = attestation_cert {
        let cert_bytes = std::fs::read(cert_path)?;
        // Write cert at attestation page + 64 bytes offset (typical layout)
        let cert_addr = attest_addr + 64;
        let trimmed = if cert_bytes.len() > (PAGE_SIZE as usize - 64) {
            cert_bytes[..PAGE_SIZE as usize - 64].to_vec()
        } else {
            cert_bytes
        };
        all_segments.push((cert_addr, trimmed));
    }

    // Sort and write output HEX
    all_segments.sort_by_key(|(addr, _)| *addr);
    write_hex_file(output, &all_segments)
}

/// Write segments as an Intel HEX file.
fn write_hex_file(path: &Path, segments: &[(u32, Vec<u8>)]) -> Result<()> {
    use std::fmt::Write as FmtWrite;
    let mut output = String::new();
    let mut current_upper: u32 = 0xFFFF_FFFF;

    for (addr, data) in segments {
        let upper = addr >> 16;
        if upper != current_upper {
            // Emit Extended Linear Address record
            let upper16 = upper as u16;
            let record_data = [(upper16 >> 8) as u8, upper16 as u8];
            let checksum = ihex_checksum(0x02, 0x0000, 0x04, &record_data);
            writeln!(
                output,
                ":02000004{:04X}{:02X}",
                upper16, checksum
            )
            .unwrap();
            current_upper = upper;
        }

        // Write data in chunks of 16 bytes
        let offset_base = (*addr & 0xFFFF) as u16;
        let mut pos = 0;
        while pos < data.len() {
            let chunk_size = (data.len() - pos).min(16);
            let chunk = &data[pos..pos + chunk_size];
            let offset = offset_base + pos as u16;
            let checksum = ihex_checksum(chunk_size as u8, offset, 0x00, chunk);
            write!(
                output,
                ":{:02X}{:04X}00",
                chunk_size, offset
            )
            .unwrap();
            for b in chunk {
                write!(output, "{:02X}", b).unwrap();
            }
            writeln!(output, "{:02X}", checksum).unwrap();
            pos += chunk_size;
        }
    }

    // EOF record
    writeln!(output, ":00000001FF").unwrap();
    std::fs::write(path, output)?;
    Ok(())
}

fn ihex_checksum(byte_count: u8, offset: u16, record_type: u8, data: &[u8]) -> u8 {
    let mut sum: u32 = 0;
    sum += byte_count as u32;
    sum += (offset >> 8) as u32;
    sum += (offset & 0xFF) as u32;
    sum += record_type as u32;
    for b in data {
        sum += *b as u32;
    }
    (0x100 - (sum & 0xFF)) as u8
}

/// Extract the firmware binary from an Intel HEX file, stripping the last 8 bytes.
/// This is what is signed.
pub fn firmware_bytes_to_sign(hex_path: &Path) -> Result<Vec<u8>> {
    let (_, mut bytes) = parse_hex_file(hex_path)?;
    if bytes.len() < 8 {
        return Err(SoloError::FirmwareError(
            "Firmware too small to sign".into(),
        ));
    }
    let len = bytes.len() - 8;
    bytes.truncate(len);
    Ok(bytes)
}

/// Create a FirmwareJson from firmware bytes and a signature.
pub fn create_firmware_json(firmware: &[u8], signature: &[u8]) -> FirmwareJson {
    FirmwareJson {
        firmware: websafe_b64_encode(firmware),
        signature: websafe_b64_encode(signature),
        versions: HashMap::new(),
    }
}

/// GitHub release API response (simplified).
#[derive(Debug, Deserialize)]
pub struct GithubRelease {
    pub tag_name: String,
    pub assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
pub struct GithubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

impl GithubRelease {
    /// Find the firmware JSON asset.
    pub fn find_firmware_asset(&self) -> Option<&GithubAsset> {
        self.assets.iter().find(|a| a.name.ends_with(".json"))
    }
}

/// Fetch the latest release info from GitHub.
pub fn fetch_latest_release() -> Result<GithubRelease> {
    let url = "https://api.github.com/repos/solokeys/solo1/releases/latest";
    let client = reqwest::blocking::Client::builder()
        .user_agent("solo1-cli-rs")
        .build()
        .map_err(|e| SoloError::NetworkError(e.to_string()))?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| SoloError::NetworkError(e.to_string()))?;
    let release: GithubRelease = resp
        .json()
        .map_err(|e| SoloError::NetworkError(format!("Failed to parse release JSON: {}", e)))?;
    Ok(release)
}

/// Download a URL to bytes.
pub fn download_url(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("solo1-cli-rs")
        .build()
        .map_err(|e| SoloError::NetworkError(e.to_string()))?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| SoloError::NetworkError(e.to_string()))?;
    let bytes = resp
        .bytes()
        .map_err(|e| SoloError::NetworkError(e.to_string()))?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firmware_version_parse() {
        let v = FirmwareVersion::parse("2.5.3").unwrap();
        assert_eq!(v, FirmwareVersion::new(2, 5, 3));
    }

    #[test]
    fn test_firmware_version_parse_v_prefix() {
        let v = FirmwareVersion::parse("v3.1.0").unwrap();
        assert_eq!(v, FirmwareVersion::new(3, 1, 0));
    }

    #[test]
    fn test_firmware_version_ordering() {
        let v253 = FirmwareVersion::new(2, 5, 3);
        let v300 = FirmwareVersion::new(3, 0, 0);
        let v253b = FirmwareVersion::new(2, 5, 3);
        assert!(v253 < v300);
        assert!(v300 > v253);
        assert_eq!(v253, v253b);
    }

    #[test]
    fn test_version_constraint_lte() {
        let v = FirmwareVersion::new(2, 5, 3);
        assert!(version_matches_constraint(&v, "<=2.5.3").unwrap());
        assert!(version_matches_constraint(&v, "<=3.0.0").unwrap());
        assert!(!version_matches_constraint(&v, "<=2.5.2").unwrap());
    }

    #[test]
    fn test_version_constraint_gt() {
        let v = FirmwareVersion::new(3, 0, 0);
        assert!(version_matches_constraint(&v, ">2.5.3").unwrap());
        assert!(!version_matches_constraint(&v, ">3.0.0").unwrap());
    }

    #[test]
    fn test_firmware_json_parse() {
        let json = r#"{
            "firmware": "SGVsbG8",
            "signature": "d29ybGQ",
            "versions": {
                "<=2.5.3": {"signature": "YWJj"},
                ">2.5.3": {"signature": "eHl6"}
            }
        }"#;
        let fw: FirmwareJson = serde_json::from_str(json).unwrap();
        assert_eq!(fw.firmware, "SGVsbG8");
        assert_eq!(fw.signature, "d29ybGQ");
        assert_eq!(fw.versions.len(), 2);

        let fw_bytes = fw.firmware_bytes().unwrap();
        assert_eq!(fw_bytes, b"Hello");

        let sig_bytes = fw.signature_bytes().unwrap();
        assert_eq!(sig_bytes, b"world");
    }

    #[test]
    fn test_firmware_json_version_selection() {
        let json = r#"{
            "firmware": "SGVsbG8",
            "signature": "ZGVmYXVsdA",
            "versions": {
                "<=2.5.3": {"signature": "b2xk"},
                ">2.5.3": {"signature": "bmV3"}
            }
        }"#;
        let fw: FirmwareJson = serde_json::from_str(json).unwrap();

        let old_version = FirmwareVersion::new(2, 5, 3);
        let sig = fw.signature_for_version(&old_version).unwrap();
        assert_eq!(sig, b"old");

        let new_version = FirmwareVersion::new(3, 0, 0);
        let sig = fw.signature_for_version(&new_version).unwrap();
        assert_eq!(sig, b"new");
    }

    #[test]
    fn test_hex_records_to_binary() {
        let records = vec![
            Record::ExtendedLinearAddress(0x0800),
            Record::Data {
                offset: 0x0000,
                value: vec![0x01, 0x02, 0x03, 0x04],
            },
            Record::Data {
                offset: 0x0004,
                value: vec![0x05, 0x06],
            },
            Record::EndOfFile,
        ];
        let (base, bytes) = hex_records_to_binary(&records).unwrap();
        assert_eq!(base, 0x08000000);
        assert_eq!(bytes, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn test_create_firmware_json() {
        let firmware = b"test firmware";
        let signature = b"test signature";
        let fw = create_firmware_json(firmware, signature);
        assert!(!fw.firmware.is_empty());
        assert!(!fw.signature.is_empty());
        assert_eq!(fw.firmware_bytes().unwrap(), firmware);
        assert_eq!(fw.signature_bytes().unwrap(), signature);
    }
}
