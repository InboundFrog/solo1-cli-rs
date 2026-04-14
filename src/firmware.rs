/// Firmware file handling: Intel HEX parsing, merging, signing, and the
/// firmware JSON format used by the Solo bootloader.
use std::collections::HashMap;
use std::path::Path;

use ihex::Record;
use serde::{Deserialize, Serialize};

use crate::crypto::{websafe_b64_decode, websafe_b64_encode};
use crate::device::{SoloHid, CMD_VERSION};
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

    /// Decode the raw bytes from the firmware field (may be Intel HEX text or binary).
    pub fn firmware_bytes(&self) -> Result<Vec<u8>> {
        websafe_b64_decode(&self.firmware)
    }

    /// Decode firmware to a flat binary with its base flash address.
    ///
    /// The official SoloKeys firmware JSONs store Intel HEX text in the `firmware`
    /// field (base64-encoded). This method detects that and parses it correctly.
    /// Raw binary (from our own `cmd_sign`) is also handled.
    ///
    /// Returns `(base_address, binary_bytes)`.
    pub fn firmware_binary(&self) -> Result<(u32, Vec<u8>)> {
        let bytes = websafe_b64_decode(&self.firmware)?;
        // Intel HEX files always start with ':'
        if bytes.first() == Some(&b':') {
            let hex_str = String::from_utf8(bytes).map_err(|e| {
                SoloError::FirmwareError(format!("Firmware HEX UTF-8 error: {}", e))
            })?;
            parse_hex_string(&hex_str)
        } else {
            // Raw binary — use the Solo 1 application start address
            Ok((0x08005000, bytes))
        }
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

/// Query the bootloader version from a connected device and select the
/// appropriate firmware signature for that bootloader version.
///
/// Bootloaders <= 2.5.3 use the v1 signing region; later ones use v2.
/// If the version query fails or returns no data, falls back to the default
/// (latest) signature rather than incorrectly matching "<=2.5.3".
pub fn select_signature(hid: &SoloHid, fw: &FirmwareJson) -> Result<Vec<u8>> {
    match hid.send_bootloader_cmd(CMD_VERSION, 0, &[]) {
        Ok(resp) if resp.len() >= 3 => {
            let v = FirmwareVersion::new(resp[0] as u32, resp[1] as u32, resp[2] as u32);
            println!("Bootloader version: {}", v);
            fw.signature_for_version(&v)
        }
        Ok(resp) if !resp.is_empty() => {
            let v = FirmwareVersion::new(0, 0, resp[0] as u32);
            println!("Bootloader version: {}", v);
            fw.signature_for_version(&v)
        }
        _ => {
            println!("Could not read bootloader version; using default signature.");
            fw.signature_bytes()
        }
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
        FirmwareVersion {
            major,
            minor,
            patch,
        }
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
        Ok(FirmwareVersion {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Check if a version matches a constraint like "<=2.5.3" or ">2.5.3".
pub fn version_matches_constraint(version: &FirmwareVersion, constraint: &str) -> Result<bool> {
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
        let r = record
            .map_err(|e| SoloError::FirmwareError(format!("Intel HEX parse error: {:?}", e)))?;
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

/// Default Solo Hacker attestation key (32-byte raw secret, hex-encoded).
/// From operations.py: "1b2626ecc8f69b0f69e34fb236d76466ba12ac16c3ab5750ba064e8b90e02448"
pub const HACKER_ATTESTATION_KEY_HEX: &str =
    "1b2626ecc8f69b0f69e34fb236d76466ba12ac16c3ab5750ba064e8b90e02448";

/// Default Solo Hacker attestation certificate (DER bytes).
/// From operations.py hacker_attestation_cert.
pub const HACKER_ATTESTATION_CERT: &[u8] = &[
    0x30, 0x82, 0x02, 0xe9, 0x30, 0x82, 0x02, 0x8e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x81, 0x82, 0x31,
    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f,
    0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x08, 0x4d, 0x61, 0x72, 0x79, 0x6c, 0x61, 0x6e, 0x64, 0x31,
    0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x53, 0x4f, 0x4c, 0x4f, 0x20, 0x48,
    0x41, 0x43, 0x4b, 0x45, 0x52, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x07,
    0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0c, 0x73, 0x6f, 0x6c, 0x6f, 0x6b, 0x65, 0x79, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x21,
    0x30, 0x1f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x12, 0x68,
    0x65, 0x6c, 0x6c, 0x6f, 0x40, 0x73, 0x6f, 0x6c, 0x6f, 0x6b, 0x65, 0x79, 0x73, 0x2e, 0x63, 0x6f,
    0x6d, 0x30, 0x20, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x32, 0x31, 0x31, 0x30, 0x32, 0x32, 0x30, 0x31,
    0x32, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x36, 0x38, 0x31, 0x31, 0x32, 0x38, 0x30, 0x32, 0x32, 0x30,
    0x31, 0x32, 0x5a, 0x30, 0x81, 0x94, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x08, 0x4d, 0x61,
    0x72, 0x79, 0x6c, 0x61, 0x6e, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x0b, 0x53, 0x4f, 0x4c, 0x4f, 0x20, 0x48, 0x41, 0x43, 0x4b, 0x45, 0x52, 0x31, 0x22, 0x30, 0x20,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x19, 0x41, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63,
    0x61, 0x74, 0x6f, 0x72, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
    0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x73, 0x6f, 0x6c, 0x6f, 0x6b,
    0x65, 0x79, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x12, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x40, 0x73, 0x6f,
    0x6c, 0x6f, 0x6b, 0x65, 0x79, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
    0x07, 0x03, 0x42, 0x00, 0x04, 0x7d, 0x78, 0xf6, 0xbe, 0xca, 0x40, 0x76, 0x3b, 0xc7, 0x5c, 0xe3,
    0xac, 0xf4, 0x27, 0x12, 0xc3, 0x94, 0x98, 0x13, 0x37, 0xa6, 0x41, 0x0e, 0x92, 0xf6, 0x9a, 0x3b,
    0x15, 0x47, 0x8d, 0xb6, 0xce, 0xd9, 0xd3, 0x4f, 0x39, 0x13, 0xed, 0x12, 0x7b, 0x81, 0x14, 0x3b,
    0xe8, 0xf9, 0x4c, 0x96, 0x38, 0xfe, 0xe3, 0xd6, 0xcb, 0x1b, 0x53, 0x93, 0xa2, 0x74, 0xf7, 0x13,
    0x9a, 0x0f, 0x9d, 0x5e, 0xa6, 0xa3, 0x81, 0xde, 0x30, 0x81, 0xdb, 0x30, 0x1d, 0x06, 0x03, 0x55,
    0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x9a, 0xfb, 0xa2, 0x21, 0x09, 0x23, 0xb5, 0xe4, 0x7a, 0x2a,
    0x1d, 0x7a, 0x6c, 0x4e, 0x03, 0x89, 0x92, 0xa3, 0x0e, 0xc2, 0x30, 0x81, 0xa1, 0x06, 0x03, 0x55,
    0x1d, 0x23, 0x04, 0x81, 0x99, 0x30, 0x81, 0x96, 0xa1, 0x81, 0x88, 0xa4, 0x81, 0x85, 0x30, 0x81,
    0x82, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11,
    0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x08, 0x4d, 0x61, 0x72, 0x79, 0x6c, 0x61, 0x6e,
    0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x53, 0x4f, 0x4c, 0x4f,
    0x20, 0x48, 0x41, 0x43, 0x4b, 0x45, 0x52, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b,
    0x0c, 0x07, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x0c, 0x73, 0x6f, 0x6c, 0x6f, 0x6b, 0x65, 0x79, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
    0x31, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16,
    0x12, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x40, 0x73, 0x6f, 0x6c, 0x6f, 0x6b, 0x65, 0x79, 0x73, 0x2e,
    0x63, 0x6f, 0x6d, 0x82, 0x09, 0x00, 0xeb, 0xd4, 0x84, 0x50, 0x14, 0xab, 0xd1, 0x57, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f,
    0x04, 0x04, 0x03, 0x02, 0x04, 0xf0, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
    0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xa1, 0x7b, 0x2a, 0x1d, 0x4e, 0x42,
    0xa8, 0x68, 0x6d, 0x65, 0x61, 0x1e, 0xf5, 0xfe, 0x6d, 0xc6, 0x99, 0xae, 0x7c, 0x20, 0x83, 0x16,
    0xba, 0xd6, 0xe5, 0x0f, 0xd7, 0x0d, 0x7e, 0x05, 0xda, 0xc9, 0x02, 0x21, 0x00, 0x92, 0x49, 0xf3,
    0x0b, 0x57, 0xd1, 0x19, 0x72, 0xf2, 0x75, 0x5a, 0xa2, 0xe0, 0xb6, 0xbd, 0x0f, 0x07, 0x38, 0xd0,
    0xe5, 0xa2, 0x4f, 0xa0, 0xf3, 0x87, 0x61, 0x82, 0xd8, 0xcd, 0x48, 0xfc, 0x57,
];

/// Write the boot-authorisation bytes into the byte map.
///
/// Sets the two-byte marker at `flash_addr(application_end_page - 1)` to
/// `0x41 0x41` ('A' 'A'), then writes the 8-byte AUTH_WORD at `auth_word_addr`:
/// bytes 0–3 are `0x00` (authorise boot) and bytes 4–7 are `0xFF` (enable
/// bootloader).
fn patch_auth_word(
    byte_map: &mut HashMap<u32, u8>,
    app_end_page_start: u32,
    auth_word_addr: u32,
) {
    // Boot marker: flash_addr(APPLICATION_END_PAGE - 1) = 'A' 'A'
    byte_map.insert(app_end_page_start, 0x41);
    byte_map.insert(app_end_page_start + 1, 0x41);

    // AUTH_WORD[0..3] = 0 (authorise boot)
    for i in 0..4u32 {
        byte_map.insert(auth_word_addr + i, 0x00);
    }
    // AUTH_WORD[4..7] = 0xFF (enable bootloader)
    for i in 4..8u32 {
        byte_map.insert(auth_word_addr + i, 0xFF);
    }
}

/// Write the attestation region into the byte map starting at `attest_addr`.
///
/// Layout at `attest_addr`:
///   [+0]:  32 bytes attestation key (first 32 bytes of `key`)
///   [+32]:  8 bytes device settings (little-endian u64: `0xAA551E7900000000`)
///   [+40]:  8 bytes cert size (little-endian u64)
///   [+48]:  N bytes certificate
fn patch_attestation(
    byte_map: &mut HashMap<u32, u8>,
    attest_addr: u32,
    key: &[u8],
    cert: &[u8],
) {
    // Attestation key at ATTEST_ADDR+0 (32 bytes)
    for (i, &b) in key.iter().take(32).enumerate() {
        byte_map.insert(attest_addr + i as u32, b);
    }

    // Device settings at ATTEST_ADDR+32 (8 bytes little-endian u64)
    // 0xAA551E7900000000 | lock_byte (lock_byte=0 since no --lock flag)
    let device_settings: u64 = 0xAA551E7900000000u64;
    let ds_bytes = device_settings.to_le_bytes();
    for (i, &b) in ds_bytes.iter().enumerate() {
        byte_map.insert(attest_addr + 32 + i as u32, b);
    }

    // Cert size at ATTEST_ADDR+40 (8 bytes little-endian u64)
    let cert_size: u64 = cert.len() as u64;
    let cs_bytes = cert_size.to_le_bytes();
    for (i, &b) in cs_bytes.iter().enumerate() {
        byte_map.insert(attest_addr + 40 + i as u32, b);
    }

    // Certificate at ATTEST_ADDR+48
    for (i, &b) in cert.iter().enumerate() {
        byte_map.insert(attest_addr + 48 + i as u32, b);
    }
}

/// Merge multiple Intel HEX files into one output HEX file.
///
/// Matches the Python reference (operations.py mergehex) which:
/// 1. Merges all input HEX files (later ones override earlier on overlap)
/// 2. Sets boot authorization bytes at AUTH_WORD_ADDR
/// 3. Patches attestation key, device settings, cert size, and cert at ATTEST_ADDR
///
/// If no attestation_key/cert files are provided, uses the default hacker
/// attestation key and cert. Both must be provided or both must be None.
///
/// Layout constants (APPLICATION_END_PAGE_COUNT=20, default for new bootloaders):
///   APPLICATION_END_PAGE = 128 - 20 = 108
///   AUTH_WORD_ADDR = flash_addr(108) - 8 = 0x080367F8
///   ATTEST_ADDR = flash_addr(128 - 15) = flash_addr(113) = 0x08038800
///
/// Attestation layout at ATTEST_ADDR:
///   [+0]:  32 bytes attestation key
///   [+32]:  8 bytes device settings (little-endian u64: 0xAA551E7900000000 | lock_byte)
///   [+40]:  8 bytes cert size (little-endian u64)
///   [+48]:  N bytes certificate
pub fn merge_hex_files(
    inputs: &[&Path],
    output: &Path,
    attestation_key: Option<&Path>,
    attestation_cert: Option<&Path>,
) -> Result<()> {
    // Validate that key and cert are either both provided or both None
    match (attestation_key, attestation_cert) {
        (Some(_), None) => {
            return Err(SoloError::FirmwareError(
                "Need to provide certificate with attestation_key".into(),
            ))
        }
        (None, Some(_)) => {
            return Err(SoloError::FirmwareError(
                "Need to provide certificate with attestation_key".into(),
            ))
        }
        _ => {}
    }

    // Read attestation key bytes (32 bytes raw)
    let key_bytes: Vec<u8> = if let Some(key_path) = attestation_key {
        let raw = std::fs::read(key_path)?;
        if raw.len() == 64 || raw.len() == 65 {
            // Hex-encoded key file
            hex::decode(std::str::from_utf8(&raw).unwrap_or("").trim()).map_err(|e| {
                SoloError::FirmwareError(format!("Invalid attestation key hex: {}", e))
            })?
        } else {
            raw
        }
    } else {
        hex::decode(HACKER_ATTESTATION_KEY_HEX).unwrap()
    };

    let cert_bytes: Vec<u8> = if let Some(cert_path) = attestation_cert {
        let data = std::fs::read(cert_path)?;
        if data.len() < 100 {
            return Err(SoloError::FirmwareError(
                "Attestation certificate is invalid (too short)".into(),
            ));
        }
        data
    } else {
        HACKER_ATTESTATION_CERT.to_vec()
    };

    // APPLICATION_END_PAGE_COUNT = 20 (default, for new bootloader)
    const APPLICATION_END_PAGE_COUNT: u32 = 20;
    let application_end_page = FLASH_PAGES - APPLICATION_END_PAGE_COUNT; // = 108

    eprintln!("app end page: {}", application_end_page);

    let auth_word_addr = flash_addr(application_end_page) - 8;
    // ATTEST_ADDR = flash_addr(PAGES - 15) = flash_addr(113)
    let attest_addr = flash_addr(FLASH_PAGES - 15);

    // Build a flat address-indexed byte map to allow overlap replacement
    // (later files override earlier, matching Python IntelHex merge with overlap="replace")
    let mut byte_map: HashMap<u32, u8> = HashMap::new();

    for input_path in inputs {
        let content = std::fs::read_to_string(input_path)?;
        let reader = ihex::Reader::new(&content);
        let mut upper_linear: u32 = 0;

        for record in reader {
            let r = record.map_err(|e| {
                SoloError::FirmwareError(format!("HEX parse error in {:?}: {:?}", input_path, e))
            })?;
            match r {
                Record::Data { offset, value } => {
                    let base = upper_linear + (offset as u32);
                    for (i, &b) in value.iter().enumerate() {
                        byte_map.insert(base + i as u32, b);
                    }
                }
                Record::ExtendedLinearAddress(upper) => {
                    upper_linear = (upper as u32) << 16;
                }
                Record::EndOfFile => break,
                _ => {}
            }
        }
    }

    // Patch boot authorization bytes and attestation region
    let app_end_page_start = flash_addr(application_end_page - 1);
    patch_auth_word(&mut byte_map, app_end_page_start, auth_word_addr);
    patch_attestation(&mut byte_map, attest_addr, &key_bytes, &cert_bytes);

    // Convert byte_map back to sorted segments for HEX output
    let mut addrs: Vec<u32> = byte_map.keys().cloned().collect();
    addrs.sort();

    let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut i = 0;
    while i < addrs.len() {
        let start = addrs[i];
        let mut data = vec![byte_map[&start]];
        while i + 1 < addrs.len() && addrs[i + 1] == addrs[i] + 1 {
            i += 1;
            data.push(byte_map[&addrs[i]]);
        }
        segments.push((start, data));
        i += 1;
    }

    write_hex_file(output, &segments)
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
            writeln!(output, ":02000004{:04X}{:02X}", upper16, checksum).unwrap();
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
            write!(output, ":{:02X}{:04X}00", chunk_size, offset).unwrap();
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

/// Flash base address for STM32L4.
pub const FLASH_BASE: u32 = 0x08000000;
/// Total number of flash pages.
pub const FLASH_PAGES: u32 = 128;
/// Flash page size in bytes.
pub const FLASH_PAGE_SIZE: u32 = 2048;

/// Compute the flash address for a given page number.
pub fn flash_addr(page: u32) -> u32 {
    FLASH_BASE + page * FLASH_PAGE_SIZE
}

/// Extract the firmware bytes to sign for a specific APPLICATION_END_PAGE value.
///
/// The signing region is:
///   START = first address in the hex file
///   END = flash_addr(FLASH_PAGES - app_end_page) - 8
///   bytes = hex_data[START .. END]  (padded with 0xFF for gaps)
///
/// Two versions exist:
///   app_end_page=19: for bootloaders <=2.5.3 (APPLICATION_END_PAGE_COUNT=19)
///   app_end_page=20: for bootloaders >2.5.3  (APPLICATION_END_PAGE_COUNT=20)
pub fn firmware_bytes_to_sign_for_version(hex_path: &Path, app_end_page: u32) -> Result<Vec<u8>> {
    let content = std::fs::read_to_string(hex_path)?;
    let reader = ihex::Reader::new(&content);
    let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut upper_linear: u32 = 0;

    for record in reader {
        let r = record
            .map_err(|e| SoloError::FirmwareError(format!("Intel HEX parse error: {:?}", e)))?;
        match r {
            Record::Data { offset, value } => {
                let addr = upper_linear + (offset as u32);
                segments.push((addr, value));
            }
            Record::ExtendedLinearAddress(upper) => {
                upper_linear = (upper as u32) << 16;
            }
            Record::EndOfFile => break,
            _ => {}
        }
    }

    if segments.is_empty() {
        return Err(SoloError::FirmwareError("No data in HEX file".into()));
    }

    segments.sort_by_key(|(addr, _)| *addr);
    let start = segments[0].0;

    // END = flash_addr(PAGES - app_end_page) - 8
    let end = flash_addr(FLASH_PAGES - app_end_page) - 8;

    if end <= start {
        return Err(SoloError::FirmwareError(format!(
            "Signing region is empty: start=0x{:08X} end=0x{:08X}",
            start, end
        )));
    }

    let size = (end - start) as usize;
    let mut binary = vec![0xFFu8; size];

    for (addr, data) in &segments {
        if *addr >= end {
            continue;
        }
        let offset = (addr - start) as usize;
        let copy_len = data.len().min(size.saturating_sub(offset));
        if copy_len > 0 {
            binary[offset..offset + copy_len].copy_from_slice(&data[..copy_len]);
        }
    }

    Ok(binary)
}

/// Extract the firmware binary from an Intel HEX file, stripping the last 8 bytes.
/// This uses the default app_end_page=20 (for bootloaders >2.5.3).
pub fn firmware_bytes_to_sign(hex_path: &Path) -> Result<Vec<u8>> {
    firmware_bytes_to_sign_for_version(hex_path, 20)
}

/// Create a FirmwareJson from the hex file text and both versioned signatures.
///
/// The firmware field contains the base64 of the HEX FILE TEXT (not binary),
/// matching the Python reference which does:
///   fw = base64.b64encode(open(hex_file, "r").read().encode())
pub fn create_firmware_json_versioned(
    hex_path: &Path,
    sig_v1: &[u8],
    sig_v2: &[u8],
) -> Result<FirmwareJson> {
    // Read the hex file as text and base64-encode it (matching Python reference)
    let hex_text = std::fs::read_to_string(hex_path)?;
    let firmware_b64 = websafe_b64_encode(hex_text.as_bytes());

    let mut versions = HashMap::new();
    versions.insert(
        "<=2.5.3".to_string(),
        VersionedSignature {
            signature: websafe_b64_encode(sig_v1),
        },
    );
    versions.insert(
        ">2.5.3".to_string(),
        VersionedSignature {
            signature: websafe_b64_encode(sig_v2),
        },
    );

    Ok(FirmwareJson {
        firmware: firmware_b64,
        signature: websafe_b64_encode(sig_v2), // default is v2 (new bootloaders)
        versions,
    })
}

/// Create a FirmwareJson from firmware bytes and a signature (legacy single-version form).
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

    #[test]
    fn test_flash_addr() {
        assert_eq!(flash_addr(0), 0x08000000);
        assert_eq!(flash_addr(1), 0x08000800);
        assert_eq!(flash_addr(108), 0x08036000);
        assert_eq!(flash_addr(113), 0x08038800);
    }

    #[test]
    fn test_firmware_bytes_to_sign_for_version_sizes_differ() {
        // v1 (app_end_page=19) should produce a larger signing region than v2 (app_end_page=20)
        // end_v1 = flash_addr(128-19) - 8 = flash_addr(109) - 8
        // end_v2 = flash_addr(128-20) - 8 = flash_addr(108) - 8
        let end_v1 = flash_addr(FLASH_PAGES - 19) - 8;
        let end_v2 = flash_addr(FLASH_PAGES - 20) - 8;
        // v1 region is one page larger
        assert_eq!(end_v1 - end_v2, FLASH_PAGE_SIZE);
    }

    #[test]
    fn test_auth_word_addr() {
        // Python: APPLICATION_END_PAGE = 128 - 20 = 108
        // AUTH_WORD_ADDR = flash_addr(108) - 8 = 0x08036000 - 8 = 0x08035FF8
        let app_end_page = FLASH_PAGES - 20; // 108
        let auth_word_addr = flash_addr(app_end_page) - 8;
        assert_eq!(auth_word_addr, 0x08035FF8);
    }

    #[test]
    fn test_hacker_attestation_key_is_valid() {
        use super::HACKER_ATTESTATION_KEY_HEX;
        let bytes = hex::decode(HACKER_ATTESTATION_KEY_HEX).expect("key should be valid hex");
        assert_eq!(bytes.len(), 32, "attestation key should be 32 bytes");
        assert_eq!(
            HACKER_ATTESTATION_KEY_HEX,
            "1b2626ecc8f69b0f69e34fb236d76466ba12ac16c3ab5750ba064e8b90e02448"
        );
    }

    #[test]
    fn test_hacker_attestation_cert_is_valid() {
        use super::HACKER_ATTESTATION_CERT;
        assert_eq!(HACKER_ATTESTATION_CERT.len(), 749);
        // DER SEQUENCE tag
        assert_eq!(HACKER_ATTESTATION_CERT[0], 0x30);
    }

    #[test]
    fn test_version_constraint_equals() {
        let v = FirmwareVersion::new(2, 5, 3);
        assert!(version_matches_constraint(&v, "=2.5.3").unwrap());
        assert!(!version_matches_constraint(&v, "=2.5.4").unwrap());
    }

    #[test]
    fn test_version_constraint_all_operators() {
        let v253 = FirmwareVersion::new(2, 5, 3);
        let v300 = FirmwareVersion::new(3, 0, 0);

        assert!(version_matches_constraint(&v253, "<=2.5.3").unwrap());
        assert!(version_matches_constraint(&v253, "<3.0.0").unwrap());
        assert!(version_matches_constraint(&v300, ">2.5.3").unwrap());
        assert!(version_matches_constraint(&v300, ">=3.0.0").unwrap());
        assert!(version_matches_constraint(&v253, "=2.5.3").unwrap());

        assert!(!version_matches_constraint(&v300, "<=2.5.3").unwrap());
        assert!(!version_matches_constraint(&v253, ">2.5.3").unwrap());
    }
}
