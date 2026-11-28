//! Firmware file handling: Intel HEX parsing, merging, signing, and the
//! firmware JSON format used by the Solo bootloader.

use std::collections::BTreeMap;
use std::path::Path;

use ihex::Record;
use serde::{Deserialize, Serialize};

use crate::bootloader::bootloader_cmd;
use crate::crypto::{websafe_b64_decode, websafe_b64_encode};
use crate::error::{Error, Result};
use crate::protocol::CMD_VERSION;
use solo_ctaphid::HidDevice;

/// The firmware JSON format used by the Solo 1 bootloader.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FirmwareJson {
    pub firmware: String,
    pub signature: String,
    #[serde(default)]
    pub versions: BTreeMap<String, VersionedSignature>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VersionedSignature {
    pub signature: String,
}

/// Start address of the application in flash on a Solo 1 key.
const APP_START_ADDRESS: u32 = 0x0800_5000;

impl FirmwareJson {
    /// Load from a JSON file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, or its contents are not
    /// valid `FirmwareJson` JSON.
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    /// Decode the bytes of the firmware field. They are Intel HEX text or raw binary.
    ///
    /// # Errors
    /// Returns [`Error::Firmware`] if the `firmware` field is not valid
    /// websafe base64.
    pub fn firmware_bytes(&self) -> Result<Vec<u8>> {
        websafe_b64_decode(&self.firmware)
    }

    /// Decode firmware to a flat binary with its base flash address.
    ///
    /// The official `SoloKeys` firmware JSON files store Intel HEX text in the
    /// `firmware` field, base64-encoded. This method detects the HEX text and
    /// parses it. It also accepts raw binary (from our own `cmd_sign`).
    ///
    /// Returns `(base_address, binary_bytes)`.
    ///
    /// # Errors
    /// Returns [`Error::Firmware`] if the `firmware` field is not valid
    /// websafe base64, the embedded Intel HEX text is not valid UTF-8, or the
    /// HEX cannot be parsed (malformed record, 32-bit address overflow, or an
    /// address span exceeding [`MAX_FIRMWARE_SPAN`]).
    pub fn firmware_binary(&self) -> Result<(u32, Vec<u8>)> {
        let bytes = websafe_b64_decode(&self.firmware)?;
        // Intel HEX files always start with ':'
        if bytes.first() == Some(&b':') {
            let hex_str =
                String::from_utf8(bytes).map_err(|e| Error::Firmware(format!("Firmware HEX UTF-8 error: {e}")))?;
            parse_hex_string(&hex_str)
        } else {
            // Raw binary — use the Solo 1 application start address
            Ok((APP_START_ADDRESS, bytes))
        }
    }

    /// Decode the signature from the websafe base64 field.
    ///
    /// # Errors
    /// Returns [`Error::Firmware`] if the `signature` field is not valid
    /// websafe base64.
    pub fn signature_bytes(&self) -> Result<Vec<u8>> {
        websafe_b64_decode(&self.signature)
    }

    /// Select the signature for a bootloader of the given version, or the
    /// default signature when the version is unknown.
    ///
    /// Bootloaders <= 2.5.3 use the v1 signing region; later ones use v2.
    ///
    /// # Errors
    /// Returns [`Error::Firmware`] if a version constraint string is
    /// malformed, or the selected signature is not valid websafe base64.
    pub fn signature_for_bootloader(&self, version: Option<&FirmwareVersion>) -> Result<Vec<u8>> {
        version.map_or_else(|| self.signature_bytes(), |v| self.signature_for_version(v))
    }

    /// Select the signature whose version constraint matches `version`.
    /// A constraint looks like "<=2.5.3" or ">2.5.3".
    ///
    /// # Errors
    /// Returns [`Error::Firmware`] if a version constraint string is
    /// malformed, or the selected signature is not valid websafe base64.
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
    ///
    /// # Errors
    /// Returns an error if the value cannot be serialized to JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// Read the Solo bootloader version from a device in bootloader mode.
///
/// Returns `None` if the query fails or the device returns no data. Callers
/// then use the default (latest) signature. This avoids a wrong match with
/// "<=2.5.3". A reply of one or two bytes is read as `0.0.<first byte>`.
pub fn read_bootloader_version(hid: &impl HidDevice) -> Option<FirmwareVersion> {
    match bootloader_cmd(hid, CMD_VERSION, 0, &[]) {
        Ok(resp) => match resp.as_slice() {
            [major, minor, patch, ..] => Some(FirmwareVersion::new(
                u32::from(*major),
                u32::from(*minor),
                u32::from(*patch),
            )),
            [patch, ..] => Some(FirmwareVersion::new(0, 0, u32::from(*patch))),
            [] => None,
        },
        Err(e) => {
            log::debug!("bootloader version query failed: {e}");
            None
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
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }

    /// Parse a version string of the form `major.minor.patch` (an optional
    /// leading `v` is stripped).
    ///
    /// # Errors
    /// Returns [`Error::Firmware`] if the string does not have exactly
    /// three dot-separated components, or any component is not a valid `u32`.
    pub fn parse(s: &str) -> Result<Self> {
        let mut parts = s.trim_start_matches('v').split('.');
        let (Some(major), Some(minor), Some(patch), None) = (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::Firmware(format!("Invalid version string: {s}")));
        };
        let component = |name: &str, text: &str| {
            text.parse()
                .map_err(|_| Error::Firmware(format!("Invalid {name}: {text}")))
        };
        Ok(Self {
            major: component("major", major)?,
            minor: component("minor", minor)?,
            patch: component("patch", patch)?,
        })
    }
}

impl std::fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Check whether a version matches a constraint like "<=2.5.3" or ">2.5.3".
///
/// # Errors
/// Returns [`Error::Firmware`] if `constraint` has no recognised
/// comparison prefix (`<=`, `>=`, `<`, `>`, `=`), or the version it contains
/// cannot be parsed.
pub fn version_matches_constraint(version: &FirmwareVersion, constraint: &str) -> Result<bool> {
    use std::cmp::Ordering;

    // Two-character prefixes come first, so "<=" is not read as "<".
    type Holds = fn(Ordering) -> bool;
    let table: [(&str, Holds); 5] = [
        ("<=", Ordering::is_le),
        (">=", Ordering::is_ge),
        ("<", Ordering::is_lt),
        (">", Ordering::is_gt),
        ("=", Ordering::is_eq),
    ];
    for (prefix, holds) in table {
        if let Some(rest) = constraint.strip_prefix(prefix) {
            return Ok(holds(version.cmp(&FirmwareVersion::parse(rest)?)));
        }
    }
    Err(Error::Firmware(format!("Unknown version constraint: {constraint}")))
}

/// Parse an Intel HEX file into a flat binary buffer.
/// Returns (`base_address`, bytes).
///
/// # Errors
/// Returns an error if the file cannot be read, or its Intel HEX content cannot
/// be parsed (see [`parse_hex_string`]).
pub fn parse_hex_file(path: &Path) -> Result<(u32, Vec<u8>)> {
    let content = std::fs::read_to_string(path)?;
    parse_hex_string(&content)
}

/// Parse Intel HEX content from a string.
///
/// # Errors
/// Returns [`Error::Firmware`] if the Intel HEX is malformed, contains
/// no data records, has an address that overflows 32 bits, or spans more than
/// [`MAX_FIRMWARE_SPAN`] bytes.
pub fn parse_hex_string(content: &str) -> Result<(u32, Vec<u8>)> {
    let reader = ihex::Reader::new(content);
    let mut records: Vec<Record> = Vec::new();
    for record in reader {
        let r = record.map_err(|e| Error::Firmware(format!("Intel HEX parse error: {e:?}")))?;
        records.push(r);
    }
    hex_records_to_binary(&records)
}

/// Maximum allowed address span (highest end address minus lowest start
/// address) of parsed Intel HEX content.
///
/// HEX content can come from the network (the firmware JSON that `update`
/// downloads). The span sets the allocation size when the HEX is flattened to
/// a binary. Solo flash is only 256 KiB, so 16 MiB is plenty. It still stops a
/// crafted `ExtendedLinearAddress` record from forcing an allocation of many
/// gigabytes.
const MAX_FIRMWARE_SPAN: u32 = 16 * 1024 * 1024;

/// Walk Intel HEX records and accumulate `(absolute_address, data)` segments.
///
/// Handles `Data`, `ExtendedLinearAddress` and `ExtendedSegmentAddress`
/// records and stops at the first `EndOfFile` record. Start-address records
/// are ignored. Segments are returned in record order (not sorted).
///
/// Rejects records whose absolute address overflows `u32`. Also rejects
/// content whose total address span is more than [`MAX_FIRMWARE_SPAN`]. So
/// untrusted HEX input cannot cause huge allocations or address wrap-around.
fn hex_records_to_segments(records: &[Record]) -> Result<Vec<(u32, Vec<u8>)>> {
    let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut base_addr: u32 = 0;
    let mut upper_linear: u32 = 0;
    let mut min_addr: u32 = u32::MAX;
    let mut max_end: u32 = 0;

    for record in records {
        match record {
            Record::Data { offset, value } => {
                let addr = upper_linear
                    .checked_add(u32::from(*offset))
                    .and_then(|a| a.checked_add(base_addr))
                    .ok_or_else(|| {
                        Error::Firmware(format!(
                            "HEX record address overflows 32 bits: \
                             upper=0x{upper_linear:08X} offset=0x{offset:04X} base=0x{base_addr:08X}"
                        ))
                    })?;
                let value_len = u32::try_from(value.len()).map_err(|_| {
                    Error::Firmware(format!(
                        "HEX record at 0x{addr:08X} has too many bytes for a 32-bit address space"
                    ))
                })?;
                let end = addr.checked_add(value_len).ok_or_else(|| {
                    Error::Firmware(format!(
                        "HEX record at 0x{:08X} ({} bytes) overflows the 32-bit address space",
                        addr,
                        value.len()
                    ))
                })?;
                min_addr = min_addr.min(addr);
                max_end = max_end.max(end);
                segments.push((addr, value.clone()));
            }
            Record::ExtendedLinearAddress(upper) => {
                upper_linear = u32::from(*upper) << 16;
                base_addr = 0;
            }
            Record::ExtendedSegmentAddress(seg) => {
                base_addr = u32::from(*seg) << 4;
                upper_linear = 0;
            }
            Record::StartLinearAddress(_) | Record::StartSegmentAddress { .. } => {}
            Record::EndOfFile => break,
        }
    }

    // max_end >= min_addr whenever there is at least one segment.
    if !segments.is_empty()
        && max_end
            .checked_sub(min_addr)
            .ok_or_else(|| Error::Firmware("HEX address span underflow".into()))?
            > MAX_FIRMWARE_SPAN
    {
        return Err(Error::Firmware(format!(
            "HEX address span too large: 0x{min_addr:08X}..0x{max_end:08X} exceeds {MAX_FIRMWARE_SPAN} bytes"
        )));
    }

    Ok(segments)
}

/// Convert Intel HEX records to a flat binary.
/// Returns (`base_address`, bytes).
///
/// # Errors
/// Returns [`Error::Firmware`] if the records contain no data, an
/// absolute address overflows 32 bits, or the address span exceeds
/// [`MAX_FIRMWARE_SPAN`] bytes.
pub fn hex_records_to_binary(records: &[Record]) -> Result<(u32, Vec<u8>)> {
    let mut segments = hex_records_to_segments(records)?;

    if segments.is_empty() {
        return Err(Error::Firmware("No data records in HEX file".into()));
    }

    // Sort by address
    segments.sort_by_key(|(addr, _)| *addr);

    let min_addr = segments
        .first()
        .ok_or_else(|| Error::Firmware("No data records in HEX file".into()))?
        .0;
    // `hex_records_to_segments` already checks overflow and `MAX_FIRMWARE_SPAN`.
    // Keep the checked arithmetic as a second safety layer.
    let mut max_addr = min_addr;
    for (addr, data) in &segments {
        let data_len = u32::try_from(data.len()).map_err(|_| {
            Error::Firmware(format!(
                "HEX record at 0x{addr:08X} has too many bytes for a 32-bit address space"
            ))
        })?;
        let end = addr
            .checked_add(data_len)
            .ok_or_else(|| Error::Firmware(format!("HEX record at 0x{addr:08X} overflows the 32-bit address space")))?;
        max_addr = max_addr.max(end);
    }

    // `max_addr >= min_addr` by construction, and the span has a limit, so
    // this allocation is at most `MAX_FIRMWARE_SPAN`.
    let size = usize::try_from(
        max_addr
            .checked_sub(min_addr)
            .ok_or_else(|| Error::Firmware("HEX address span underflow".into()))?,
    )
    .map_err(|_| Error::Firmware("HEX binary size too large".into()))?;
    let mut binary = vec![0xFFu8; size];

    for (addr, data) in &segments {
        let offset = usize::try_from(
            addr.checked_sub(min_addr)
                .ok_or_else(|| Error::Firmware("HEX address underflow".into()))?,
        )
        .map_err(|_| Error::Firmware("HEX offset too large".into()))?;
        let end = offset
            .checked_add(data.len())
            .ok_or_else(|| Error::Firmware("HEX offset overflow".into()))?;
        binary
            .get_mut(offset..end)
            .ok_or_else(|| Error::Firmware("HEX data out of range".into()))?
            .copy_from_slice(data);
    }

    Ok((min_addr, binary))
}

/// Default Solo Hacker attestation key (32-byte raw secret, hex-encoded).
/// From operations.py: "1b2626ecc8f69b0f69e34fb236d76466ba12ac16c3ab5750ba064e8b90e02448"
pub const HACKER_ATTESTATION_KEY_HEX: &str = "1b2626ecc8f69b0f69e34fb236d76466ba12ac16c3ab5750ba064e8b90e02448";

/// Default Solo Hacker attestation certificate (DER bytes).
/// From operations.py `hacker_attestation_cert`.
pub const HACKER_ATTESTATION_CERT: &[u8] = &[
    0x30, 0x82, 0x02, 0xe9, 0x30, 0x82, 0x02, 0x8e, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0a, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x81, 0x82, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x08, 0x4d, 0x61,
    0x72, 0x79, 0x6c, 0x61, 0x6e, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x53, 0x4f,
    0x4c, 0x4f, 0x20, 0x48, 0x41, 0x43, 0x4b, 0x45, 0x52, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c,
    0x07, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c,
    0x73, 0x6f, 0x6c, 0x6f, 0x6b, 0x65, 0x79, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x12, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x40, 0x73, 0x6f, 0x6c,
    0x6f, 0x6b, 0x65, 0x79, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x20, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x32, 0x31, 0x31,
    0x30, 0x32, 0x32, 0x30, 0x31, 0x32, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x36, 0x38, 0x31, 0x31, 0x32, 0x38, 0x30, 0x32,
    0x32, 0x30, 0x31, 0x32, 0x5a, 0x30, 0x81, 0x94, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
    0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x08, 0x4d, 0x61, 0x72, 0x79, 0x6c, 0x61,
    0x6e, 0x64, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x53, 0x4f, 0x4c, 0x4f, 0x20, 0x48,
    0x41, 0x43, 0x4b, 0x45, 0x52, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x19, 0x41, 0x75, 0x74,
    0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x6f, 0x72, 0x20, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x73, 0x6f, 0x6c, 0x6f, 0x6b,
    0x65, 0x79, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x09, 0x01, 0x16, 0x12, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x40, 0x73, 0x6f, 0x6c, 0x6f, 0x6b, 0x65, 0x79, 0x73,
    0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x7d, 0x78, 0xf6, 0xbe, 0xca, 0x40, 0x76,
    0x3b, 0xc7, 0x5c, 0xe3, 0xac, 0xf4, 0x27, 0x12, 0xc3, 0x94, 0x98, 0x13, 0x37, 0xa6, 0x41, 0x0e, 0x92, 0xf6, 0x9a,
    0x3b, 0x15, 0x47, 0x8d, 0xb6, 0xce, 0xd9, 0xd3, 0x4f, 0x39, 0x13, 0xed, 0x12, 0x7b, 0x81, 0x14, 0x3b, 0xe8, 0xf9,
    0x4c, 0x96, 0x38, 0xfe, 0xe3, 0xd6, 0xcb, 0x1b, 0x53, 0x93, 0xa2, 0x74, 0xf7, 0x13, 0x9a, 0x0f, 0x9d, 0x5e, 0xa6,
    0xa3, 0x81, 0xde, 0x30, 0x81, 0xdb, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x9a, 0xfb,
    0xa2, 0x21, 0x09, 0x23, 0xb5, 0xe4, 0x7a, 0x2a, 0x1d, 0x7a, 0x6c, 0x4e, 0x03, 0x89, 0x92, 0xa3, 0x0e, 0xc2, 0x30,
    0x81, 0xa1, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x81, 0x99, 0x30, 0x81, 0x96, 0xa1, 0x81, 0x88, 0xa4, 0x81, 0x85,
    0x30, 0x81, 0x82, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30,
    0x0f, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x08, 0x4d, 0x61, 0x72, 0x79, 0x6c, 0x61, 0x6e, 0x64, 0x31, 0x14, 0x30,
    0x12, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x53, 0x4f, 0x4c, 0x4f, 0x20, 0x48, 0x41, 0x43, 0x4b, 0x45, 0x52,
    0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x07, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x43, 0x41, 0x31,
    0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0c, 0x73, 0x6f, 0x6c, 0x6f, 0x6b, 0x65, 0x79, 0x73, 0x2e,
    0x63, 0x6f, 0x6d, 0x31, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16,
    0x12, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x40, 0x73, 0x6f, 0x6c, 0x6f, 0x6b, 0x65, 0x79, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
    0x82, 0x09, 0x00, 0xeb, 0xd4, 0x84, 0x50, 0x14, 0xab, 0xd1, 0x57, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04,
    0x02, 0x30, 0x00, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x04, 0xf0, 0x30, 0x0a, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xa1, 0x7b,
    0x2a, 0x1d, 0x4e, 0x42, 0xa8, 0x68, 0x6d, 0x65, 0x61, 0x1e, 0xf5, 0xfe, 0x6d, 0xc6, 0x99, 0xae, 0x7c, 0x20, 0x83,
    0x16, 0xba, 0xd6, 0xe5, 0x0f, 0xd7, 0x0d, 0x7e, 0x05, 0xda, 0xc9, 0x02, 0x21, 0x00, 0x92, 0x49, 0xf3, 0x0b, 0x57,
    0xd1, 0x19, 0x72, 0xf2, 0x75, 0x5a, 0xa2, 0xe0, 0xb6, 0xbd, 0x0f, 0x07, 0x38, 0xd0, 0xe5, 0xa2, 0x4f, 0xa0, 0xf3,
    0x87, 0x61, 0x82, 0xd8, 0xcd, 0x48, 0xfc, 0x57,
];

/// Number of addresses in one page of a [`FlashImage`].
const IMAGE_PAGE_LEN: usize = 256;

/// A sparse flash image: bytes at 32-bit addresses.
///
/// The address space is cut into pages of 256 addresses. A page is created
/// the first time a byte is written into it, and each address in a page is
/// either empty or holds one byte. Addresses that were never written stay
/// empty (holes); holes are never filled in.
///
/// A later write to the same address replaces the earlier byte. This matches
/// the Python `IntelHex` merge with `overlap="replace"`.
///
/// Cost: about 2 bytes of memory per address of each touched page, and the
/// same time per byte whatever order the writes come in.
#[derive(Default)]
struct FlashImage {
    /// Page number (address / 256) -> one slot per address in that page.
    /// A slot is `None` until a byte is written to it.
    pages: BTreeMap<u32, Box<[Option<u8>; IMAGE_PAGE_LEN]>>,
}

impl FlashImage {
    /// Write `data` at `addr`, replacing any bytes already there.
    ///
    /// If the write fails, the image is not changed.
    ///
    /// # Errors
    /// Returns [`Error::Firmware`] if an address in the range overflows 32 bits.
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        // Check the last address first, so a failed write changes nothing.
        let overflow = || Error::Firmware("flash address overflow".into());
        let extra = u32::try_from(data.len().saturating_sub(1)).map_err(|_| overflow())?;
        addr.checked_add(extra).ok_or_else(overflow)?;
        let mut a = addr;
        for &b in data {
            let page = self
                .pages
                .entry(a >> 8)
                .or_insert_with(|| Box::new([None; IMAGE_PAGE_LEN]));
            let [low, ..] = a.to_le_bytes();
            if let Some(slot) = page.get_mut(usize::from(low)) {
                *slot = Some(b);
            }
            // The last step may wrap; that value is not used.
            a = a.wrapping_add(1);
        }
        Ok(())
    }

    /// Join runs of consecutive addresses into `(start, bytes)` segments, sorted by address.
    fn segments(&self) -> Vec<(u32, Vec<u8>)> {
        let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut prev: Option<u32> = None;
        for (&page, slots) in &self.pages {
            for (low, slot) in (0..=u8::MAX).zip(slots.iter()) {
                let Some(b) = *slot else { continue };
                let addr = (page << 8) | u32::from(low);
                let joins = prev.and_then(|p| p.checked_add(1)) == Some(addr);
                match segments.last_mut() {
                    Some((_, data)) if joins => data.push(b),
                    _ => segments.push((addr, vec![b])),
                }
                prev = Some(addr);
            }
        }
        segments
    }
}

/// Write the boot-authorisation bytes into the image.
///
/// Sets the two-byte marker at `flash_addr(application_end_page - 1)` to
/// `0x41 0x41` ('A' 'A'), then writes the 8-byte `AUTH_WORD` at `auth_word_addr`:
/// bytes 0–3 are `0x00` (authorise boot) and bytes 4–7 are `0xFF` (enable
/// bootloader).
fn patch_auth_word(image: &mut FlashImage, app_end_page_start: u32, auth_word_addr: u32) -> Result<()> {
    // Boot marker: flash_addr(APPLICATION_END_PAGE - 1) = 'A' 'A'
    image.write(app_end_page_start, &[0x41, 0x41])?;
    // AUTH_WORD[0..3] = 0 (authorise boot), AUTH_WORD[4..7] = 0xFF (enable bootloader)
    image.write(auth_word_addr, &[0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF])
}

/// Write the attestation region into the image starting at `attest_addr`.
///
/// Layout at `attest_addr`:
///   [+0]:  32 bytes attestation key (first 32 bytes of `key`)
///   [+32]:  8 bytes device settings (little-endian u64: `0xAA551E7900000000`)
///   [+40]:  8 bytes cert size (little-endian u64)
///   [+48]:  N bytes certificate
fn patch_attestation(image: &mut FlashImage, attest_addr: u32, key: &[u8], cert: &[u8]) -> Result<()> {
    let overflow = || Error::Firmware("attestation address overflow".into());
    let at = |offset: u32| attest_addr.checked_add(offset).ok_or_else(overflow);

    // Attestation key at ATTEST_ADDR+0 (32 bytes)
    image.write(attest_addr, key.get(..32).unwrap_or(key))?;

    // Device settings at ATTEST_ADDR+32 (8 bytes little-endian u64)
    // 0xAA551E7900000000 | lock_byte (lock_byte=0 since no --lock flag)
    let device_settings: u64 = 0xAA55_1E79_0000_0000_u64;
    image.write(at(32)?, &device_settings.to_le_bytes())?;

    // Cert size at ATTEST_ADDR+40 (8 bytes little-endian u64)
    let cert_size: u64 = u64::try_from(cert.len()).map_err(|_| Error::Firmware("cert too large".into()))?;
    image.write(at(40)?, &cert_size.to_le_bytes())?;

    // Certificate at ATTEST_ADDR+48
    image.write(at(48)?, cert)
}

/// Returns the 32 attestation key bytes from the contents of a key file.
///
/// The format is chosen from the content, never from the file length:
/// 1. One UTF-8 byte order mark at the start is ignored when deciding if the
///    file is text. If every other byte is printable ASCII or white space,
///    the file is text.
/// 2. A text file must hold exactly 64 hex digits. White space anywhere in it
///    is ignored. Anything else (such as a `0x` prefix) is an error.
/// 3. Any other file is binary and must be exactly 32 bytes, which are the
///    key. The byte order mark is not removed here.
///
/// A limit remains: a 32-byte file with any byte that is not printable ASCII
/// or white space is taken as a raw key, because a raw key can be any 32
/// bytes and cannot be told apart from such a file.
///
/// Error messages never quote the file, because it holds a secret key.
fn parse_attestation_key(raw: &[u8]) -> Result<Vec<u8>> {
    let body = raw.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(raw);
    let is_text = body.iter().all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace());
    if !is_text {
        if raw.len() != 32 {
            return Err(Error::Firmware(format!(
                "Attestation key file is not plain ASCII text, so it is read as a raw key \
                 and must be exactly 32 bytes, got {}",
                raw.len()
            )));
        }
        return Ok(raw.to_vec());
    }
    let digits: Vec<u8> = body.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Firmware(
            "Attestation key file is text, so it must hold exactly 64 hex digits, \
             but it has a character that is not a hex digit"
                .into(),
        ));
    }
    if digits.len() != 64 {
        return Err(Error::Firmware(format!(
            "Attestation key file is text, so it must hold exactly 64 hex digits, got {}",
            digits.len()
        )));
    }
    hex::decode(&digits).map_err(|_| Error::Firmware("Attestation key file has invalid hex".into()))
}

/// Merge multiple Intel HEX files into one output HEX file.
///
/// Matches the Python reference (operations.py mergehex) which:
/// 1. Merges all input HEX files (later ones override earlier on overlap)
/// 2. Sets boot authorization bytes at `AUTH_WORD_ADDR`
/// 3. Patches attestation key, device settings, cert size, and cert at `ATTEST_ADDR`
///
/// If you pass no attestation key and cert files, it uses the default hacker
/// attestation key and cert. Pass both files or neither.
///
/// Layout constants (`APPLICATION_END_PAGE_COUNT=20`, default for new bootloaders):
///   `APPLICATION_END_PAGE` = 128 - 20 = 108
///   `AUTH_WORD_ADDR` = `flash_addr(108)` - 8 = 0x08035FF8
///   `ATTEST_ADDR` = `flash_addr(128` - 15) = `flash_addr(113)` = 0x08038800
///
/// Attestation layout at `ATTEST_ADDR`:
///   [+0]:  32 bytes attestation key
///   [+32]:  8 bytes device settings (little-endian u64: 0xAA551E7900000000 | `lock_byte`)
///   [+40]:  8 bytes cert size (little-endian u64)
///   [+48]:  N bytes certificate
///
/// # Errors
/// Returns [`Error::Firmware`] if only one of `attestation_key` and
/// `attestation_cert` is provided, an attestation key or certificate file
/// cannot be read or is invalid (malformed hex key, or a certificate shorter
/// than 100 bytes), an input HEX file cannot be read or parsed, an address
/// overflows 32 bits, or the output file cannot be written.
pub fn merge_hex_files(
    inputs: &[&Path],
    output: &Path,
    attestation_key: Option<&Path>,
    attestation_cert: Option<&Path>,
) -> Result<()> {
    let text = merge_hex_text(inputs, attestation_key, attestation_cert)?;
    std::fs::write(output, text)?;
    Ok(())
}

/// Merge Intel HEX files and return the merged HEX text without writing it.
///
/// This does the same work as [`merge_hex_files`], so the caller can choose
/// how to write the text. That matters when an attestation key was given,
/// because the text then holds the private key.
///
/// # Errors
/// Returns the same errors as [`merge_hex_files`], except those for writing
/// the output file.
pub fn merge_hex_text(
    inputs: &[&Path],
    attestation_key: Option<&Path>,
    attestation_cert: Option<&Path>,
) -> Result<String> {
    // APPLICATION_END_PAGE_COUNT = 20 (default, for new bootloader)
    const APPLICATION_END_PAGE_COUNT: u32 = 20;

    // Pass both the key and the cert, or neither.
    if attestation_key.is_some() != attestation_cert.is_some() {
        return Err(Error::Firmware(
            "Need to provide certificate with attestation_key".into(),
        ));
    }

    // Read attestation key bytes (32 raw bytes, or 64 hex digits as text)
    let key_bytes: Vec<u8> = if let Some(key_path) = attestation_key {
        parse_attestation_key(&std::fs::read(key_path)?)?
    } else {
        hex::decode(HACKER_ATTESTATION_KEY_HEX)?
    };

    let cert_bytes: Vec<u8> = if let Some(cert_path) = attestation_cert {
        let data = std::fs::read(cert_path)?;
        if data.len() < 100 {
            return Err(Error::Firmware("Attestation certificate is invalid (too short)".into()));
        }
        data
    } else {
        HACKER_ATTESTATION_CERT.to_vec()
    };

    let application_end_page = FLASH_PAGES - APPLICATION_END_PAGE_COUNT; // = 108

    log::debug!("app end page: {application_end_page}");

    let auth_word_addr = flash_addr(application_end_page)
        .checked_sub(8)
        .ok_or_else(|| Error::Firmware("auth word address underflow".into()))?;
    // ATTEST_ADDR = flash_addr(PAGES - 15) = flash_addr(113)
    let attest_addr = flash_addr(FLASH_PAGES - 15);

    // Later files override earlier ones on overlap.
    let mut image = FlashImage::default();

    for input_path in inputs {
        let content = std::fs::read_to_string(input_path)?;
        let records: Vec<Record> = ihex::Reader::new(&content)
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| Error::Firmware(format!("HEX parse error in {}: {e:?}", input_path.display())))?;

        for (addr, data) in hex_records_to_segments(&records)? {
            image.write(addr, &data)?;
        }
    }

    // Patch boot authorization bytes and attestation region
    let app_end_page_start = flash_addr(application_end_page - 1);
    patch_auth_word(&mut image, app_end_page_start, auth_word_addr)?;
    patch_attestation(&mut image, attest_addr, &key_bytes, &cert_bytes)?;

    // Join consecutive addresses into segments for HEX output
    let segments = image.segments();
    hex_text(&segments)
}

/// Return segments as Intel HEX text.
///
/// Data records hold at most 16 bytes and never cross a 64 KiB boundary.
/// An Extended Linear Address record is written whenever the upper 16 address
/// bits change.
fn hex_text(segments: &[(u32, Vec<u8>)]) -> Result<String> {
    let overflow = || Error::Firmware("HEX address overflow".into());
    let mut records: Vec<Record> = Vec::new();
    let mut current_upper: Option<u16> = None;

    for (start, data) in segments {
        let mut pos: usize = 0;
        for chunk in data.chunks(16) {
            let addr = u32::try_from(pos)
                .ok()
                .and_then(|p| start.checked_add(p))
                .ok_or_else(overflow)?;
            // The last byte of the chunk must stay in the same 64 KiB block.
            let last = u32::try_from(chunk.len().saturating_sub(1))
                .ok()
                .and_then(|n| addr.checked_add(n))
                .ok_or_else(overflow)?;
            let upper = u16::try_from(addr >> 16).map_err(|_| overflow())?;
            if current_upper != Some(upper) {
                records.push(Record::ExtendedLinearAddress(upper));
                current_upper = Some(upper);
            }
            let offset = u16::try_from(addr & 0xFFFF).map_err(|_| overflow())?;
            if last >> 16 == addr >> 16 {
                records.push(Record::Data {
                    offset,
                    value: chunk.to_vec(),
                });
            } else {
                // Split the chunk at the boundary. The tail goes after a new ELA record.
                let head_len =
                    usize::try_from(0x1_0000_u32.saturating_sub(u32::from(offset))).map_err(|_| overflow())?;
                let (head, tail) = chunk.split_at_checked(head_len).ok_or_else(overflow)?;
                records.push(Record::Data {
                    offset,
                    value: head.to_vec(),
                });
                let next_upper = upper.checked_add(1).ok_or_else(overflow)?;
                records.push(Record::ExtendedLinearAddress(next_upper));
                current_upper = Some(next_upper);
                records.push(Record::Data {
                    offset: 0,
                    value: tail.to_vec(),
                });
            }
            pos = pos.checked_add(chunk.len()).ok_or_else(overflow)?;
        }
    }

    records.push(Record::EndOfFile);
    ihex::create_object_file_representation(&records).map_err(|e| Error::Firmware(format!("HEX write error: {e}")))
}

/// Flash base address for STM32L4.
pub const FLASH_BASE: u32 = 0x0800_0000;
/// Total number of flash pages.
pub const FLASH_PAGES: u32 = 128;
/// Flash page size in bytes.
pub const FLASH_PAGE_SIZE: u32 = 2048;

/// Compute the flash address for a given page number.
#[must_use]
pub const fn flash_addr(page: u32) -> u32 {
    // Saturating math works in a `const fn`. It never saturates for valid page
    // numbers, so the result equals `FLASH_BASE + page * FLASH_PAGE_SIZE`.
    FLASH_BASE.saturating_add(page.saturating_mul(FLASH_PAGE_SIZE))
}

/// Extract the firmware bytes to sign for a specific `APPLICATION_END_PAGE` value.
///
/// The signing region is:
///   START = first address in the hex file
///   END = `flash_addr(FLASH_PAGES` - `app_end_page`) - 8
///   bytes = `hex_data`[START .. END]  (padded with 0xFF for gaps)
///
/// Two versions exist:
///   `app_end_page=19`: for bootloaders <=2.5.3 (`APPLICATION_END_PAGE_COUNT=19`)
///   `app_end_page=20`: for bootloaders >2.5.3  (`APPLICATION_END_PAGE_COUNT=20`)
///
/// # Errors
/// Returns [`Error::Firmware`] if the HEX file cannot be read or
/// parsed, contains no data, `app_end_page` is larger than [`FLASH_PAGES`], the
/// computed signing region is empty, or an address computation overflows.
pub fn firmware_bytes_to_sign_for_version(hex_path: &Path, app_end_page: u32) -> Result<Vec<u8>> {
    let content = std::fs::read_to_string(hex_path)?;
    let records: Vec<Record> = ihex::Reader::new(&content)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::Firmware(format!("Intel HEX parse error: {e:?}")))?;
    let mut segments = hex_records_to_segments(&records)?;

    if segments.is_empty() {
        return Err(Error::Firmware("No data in HEX file".into()));
    }

    segments.sort_by_key(|(addr, _)| *addr);
    let start = segments
        .first()
        .ok_or_else(|| Error::Firmware("No data in HEX file".into()))?
        .0;

    // END = flash_addr(PAGES - app_end_page) - 8
    let pages = FLASH_PAGES
        .checked_sub(app_end_page)
        .ok_or_else(|| Error::Firmware("application end page too large".into()))?;
    let end = flash_addr(pages)
        .checked_sub(8)
        .ok_or_else(|| Error::Firmware("signing region end underflow".into()))?;

    if end <= start {
        return Err(Error::Firmware(format!(
            "Signing region is empty: start=0x{start:08X} end=0x{end:08X}"
        )));
    }

    let size = usize::try_from(
        end.checked_sub(start)
            .ok_or_else(|| Error::Firmware("signing region size underflow".into()))?,
    )
    .map_err(|_| Error::Firmware("signing region too large".into()))?;
    let mut binary = vec![0xFFu8; size];

    for (addr, data) in &segments {
        if *addr >= end {
            continue;
        }
        let offset = usize::try_from(
            addr.checked_sub(start)
                .ok_or_else(|| Error::Firmware("signing region offset underflow".into()))?,
        )
        .map_err(|_| Error::Firmware("signing region offset too large".into()))?;
        let copy_len = data.len().min(size.saturating_sub(offset));
        if copy_len > 0 {
            let copy_end = offset
                .checked_add(copy_len)
                .ok_or_else(|| Error::Firmware("signing region copy overflow".into()))?;
            binary
                .get_mut(offset..copy_end)
                .ok_or_else(|| Error::Firmware("signing region out of range".into()))?
                .copy_from_slice(
                    data.get(..copy_len)
                        .ok_or_else(|| Error::Firmware("signing region source out of range".into()))?,
                );
        }
    }

    Ok(binary)
}

/// Create a `FirmwareJson` from the hex file text and both versioned signatures.
///
/// The firmware field holds the base64 of the HEX FILE TEXT, not of the binary.
/// The Python reference does the same:
///   fw = `base64.b64encode(open(hex_file`, "`r").read().encode()`)
///
/// # Errors
/// Returns an error if the HEX file cannot be read.
pub fn create_firmware_json_versioned(hex_path: &Path, sig_v1: &[u8], sig_v2: &[u8]) -> Result<FirmwareJson> {
    // Read the HEX file as text and base64-encode it, as the Python reference does.
    let hex_text = std::fs::read_to_string(hex_path)?;
    let firmware_b64 = websafe_b64_encode(hex_text.as_bytes());

    let mut versions = BTreeMap::new();
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
        signature: websafe_b64_encode(sig_v2), // The default is v2 (new bootloaders).
        versions,
    })
}

/// Create a `FirmwareJson` from firmware bytes and a signature (legacy single-version form).
#[must_use]
pub fn create_firmware_json(firmware: &[u8], signature: &[u8]) -> FirmwareJson {
    FirmwareJson {
        firmware: websafe_b64_encode(firmware),
        signature: websafe_b64_encode(signature),
        versions: BTreeMap::new(),
    }
}

/// GitHub repository (`owner/name`) that publishes Solo 1 firmware releases.
pub const FIRMWARE_RELEASES_REPO: &str = "solokeys/solo1";

/// Whether a release asset name is a Solo 1 firmware JSON file.
#[must_use]
pub fn is_firmware_asset(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
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
    fn test_firmware_version_parse_rejects_bad_input() {
        for bad in [
            "", "1.2", "1.2.3.4", "1..3", "a.2.3", "1.b.3", "1.2.c", "1.2.-3", "1.2.3 ",
        ] {
            assert!(FirmwareVersion::parse(bad).is_err(), "{bad:?} should be rejected");
        }
        // Every leading `v` is stripped.
        assert_eq!(
            FirmwareVersion::parse("vv1.2.3").unwrap(),
            FirmwareVersion::new(1, 2, 3)
        );
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
    fn test_firmware_json_parse_padded() {
        let json = r#"{
            "firmware": "SGVsbG8=",
            "signature": "d29ybGQ=",
            "versions": {">2.5.3": {"signature": "TQ=="}}
        }"#;
        let fw: FirmwareJson = serde_json::from_str(json).unwrap();
        assert_eq!(fw.firmware_bytes().unwrap(), b"Hello");
        assert_eq!(fw.signature_bytes().unwrap(), b"world");
        let sig = fw.signature_for_version(&FirmwareVersion::new(4, 0, 0)).unwrap();
        assert_eq!(sig, b"M");
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

        // Unknown bootloader version falls back to the default signature.
        let sig = fw.signature_for_bootloader(None).unwrap();
        assert_eq!(sig, b"default");
        let sig = fw.signature_for_bootloader(Some(&old_version)).unwrap();
        assert_eq!(sig, b"old");
    }

    #[test]
    fn test_firmware_json_to_json_sorted_and_stable() {
        let fw = create_firmware_json_versioned_for_test();
        let first = fw.to_json().unwrap();
        for _ in 0..20 {
            assert_eq!(fw.to_json().unwrap(), first);
        }
        let lt = first.find("\"<=2.5.3\"").unwrap();
        let gt = first.find("\">2.5.3\"").unwrap();
        assert!(lt < gt);
    }

    fn create_firmware_json_versioned_for_test() -> FirmwareJson {
        let mut versions = BTreeMap::new();
        versions.insert(
            ">2.5.3".to_string(),
            VersionedSignature {
                signature: "bmV3".into(),
            },
        );
        versions.insert(
            "<=2.5.3".to_string(),
            VersionedSignature {
                signature: "b2xk".into(),
            },
        );
        FirmwareJson {
            firmware: "SGVsbG8".into(),
            signature: "ZGVmYXVsdA".into(),
            versions,
        }
    }

    #[test]
    fn test_firmware_json_overlapping_constraints_pick_first_sorted() {
        let json = r#"{
            "firmware": "SGVsbG8",
            "signature": "ZGVmYXVsdA",
            "versions": {
                ">2.0.0": {"signature": "bmV3"},
                "<=3.0.0": {"signature": "b2xk"}
            }
        }"#;
        let fw: FirmwareJson = serde_json::from_str(json).unwrap();
        let v = FirmwareVersion::new(2, 5, 0);
        for _ in 0..20 {
            assert_eq!(fw.signature_for_version(&v).unwrap(), b"old");
        }
    }

    // ── read_bootloader_version ─────────────────────────────────────────────

    #[test]
    fn test_read_bootloader_version_three_bytes() {
        use solo_ctaphid::mock::MockDevice;
        // Bootloader responses start with a 0x00 status byte.
        let device = MockDevice::new(vec![Ok(vec![0x00, 2, 5, 3])]);
        assert_eq!(read_bootloader_version(&device), Some(FirmwareVersion::new(2, 5, 3)));
    }

    #[test]
    fn test_read_bootloader_version_one_byte() {
        use solo_ctaphid::mock::MockDevice;
        let device = MockDevice::new(vec![Ok(vec![0x00, 7])]);
        assert_eq!(read_bootloader_version(&device), Some(FirmwareVersion::new(0, 0, 7)));
    }

    #[test]
    fn test_read_bootloader_version_empty_or_error_is_none() {
        use solo_ctaphid::mock::MockDevice;
        let device = MockDevice::new(vec![Ok(vec![0x00])]);
        assert_eq!(read_bootloader_version(&device), None);
        let device = MockDevice::new(vec![Ok(vec![0x01])]);
        assert_eq!(read_bootloader_version(&device), None);
        let device = MockDevice::new(vec![]);
        assert_eq!(read_bootloader_version(&device), None);
    }

    #[test]
    fn test_is_firmware_asset() {
        assert!(is_firmware_asset("firmware-4.1.5.json"));
        assert!(is_firmware_asset("FIRMWARE.JSON"));
        assert!(!is_firmware_asset("firmware-4.1.5.hex"));
        assert!(!is_firmware_asset("json"));
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
        assert_eq!(base, 0x0800_0000);
        assert_eq!(bytes, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn test_flash_image_later_write_replaces() {
        let mut img = FlashImage::default();
        img.write(0x100, &[1, 2, 3, 4]).unwrap();
        img.write(0x102, &[9, 9]).unwrap();
        assert_eq!(img.segments(), vec![(0x100, vec![1, 2, 9, 9])]);
    }

    #[test]
    fn test_flash_image_gap_splits_segments() {
        let mut img = FlashImage::default();
        img.write(0x200, &[3]).unwrap();
        img.write(0x100, &[1, 2]).unwrap();
        assert_eq!(img.segments(), vec![(0x100, vec![1, 2]), (0x200, vec![3])]);
    }

    #[test]
    fn test_flash_image_touching_ranges_join() {
        let mut img = FlashImage::default();
        img.write(0x102, &[3, 4]).unwrap();
        img.write(0x100, &[1, 2]).unwrap();
        assert_eq!(img.segments(), vec![(0x100, vec![1, 2, 3, 4])]);
    }

    #[test]
    fn test_flash_image_address_overflow_is_error() {
        let mut img = FlashImage::default();
        assert!(img.write(u32::MAX, &[1, 2]).is_err());
        // The last address itself is valid.
        let mut img = FlashImage::default();
        img.write(u32::MAX, &[1]).unwrap();
        assert_eq!(img.segments(), vec![(u32::MAX, vec![1])]);
    }

    type Segs = Vec<(u32, Vec<u8>)>;

    /// Image with ranges `[10..14)`, `[20..24)` and `[30..34)`, filled with 1, 2 and 3.
    fn three_ranges() -> FlashImage {
        let mut img = FlashImage::default();
        img.write(10, &[1; 4]).unwrap();
        img.write(20, &[2; 4]).unwrap();
        img.write(30, &[3; 4]).unwrap();
        img
    }

    #[test]
    fn test_flash_image_write_inside_keeps_both_sides() {
        let mut img = FlashImage::default();
        img.write(10, &[1; 6]).unwrap();
        img.write(12, &[9, 9]).unwrap();
        assert_eq!(img.segments(), vec![(10, vec![1, 1, 9, 9, 1, 1])]);
    }

    #[test]
    fn test_flash_image_write_overlaps_start() {
        let mut img = FlashImage::default();
        img.write(10, &[1; 4]).unwrap();
        img.write(8, &[9; 4]).unwrap();
        assert_eq!(img.segments(), vec![(8, vec![9, 9, 9, 9, 1, 1])]);
    }

    #[test]
    fn test_flash_image_write_overlaps_end() {
        let mut img = FlashImage::default();
        img.write(10, &[1; 4]).unwrap();
        img.write(12, &[9; 4]).unwrap();
        assert_eq!(img.segments(), vec![(10, vec![1, 1, 9, 9, 9, 9])]);
    }

    #[test]
    fn test_flash_image_write_exactly_covers() {
        let mut img = FlashImage::default();
        img.write(10, &[1; 4]).unwrap();
        img.write(10, &[9; 4]).unwrap();
        assert_eq!(img.segments(), vec![(10, vec![9; 4])]);
    }

    #[test]
    fn test_flash_image_write_bridges_three_ranges_and_holes() {
        let mut img = three_ranges();
        img.write(12, &[9; 20]).unwrap();
        let mut want = vec![1, 1];
        want.extend([9; 20]);
        want.extend([3, 3]);
        assert_eq!(img.segments(), vec![(10, want)]);
    }

    #[test]
    fn test_flash_image_touching_front_joins() {
        let mut img = FlashImage::default();
        img.write(10, &[1, 2]).unwrap();
        img.write(8, &[7, 8]).unwrap();
        assert_eq!(img.segments(), vec![(8, vec![7, 8, 1, 2])]);
    }

    #[test]
    fn test_flash_image_touching_back_joins() {
        let mut img = FlashImage::default();
        img.write(10, &[1, 2]).unwrap();
        img.write(12, &[7, 8]).unwrap();
        assert_eq!(img.segments(), vec![(10, vec![1, 2, 7, 8])]);
    }

    #[test]
    fn test_flash_image_empty_write_is_noop() {
        let mut img = FlashImage::default();
        img.write(5, &[]).unwrap();
        img.write(u32::MAX, &[]).unwrap();
        assert_eq!(img.segments(), Segs::new());
        let mut img = three_ranges();
        let before = img.segments();
        img.write(12, &[]).unwrap();
        img.write(u32::MAX, &[]).unwrap();
        assert_eq!(img.segments(), before);
    }

    #[test]
    fn test_flash_image_two_bytes_ending_at_u32_max_is_valid() {
        let mut img = FlashImage::default();
        img.write(u32::MAX - 1, &[1, 2]).unwrap();
        assert_eq!(img.segments(), vec![(u32::MAX - 1, vec![1, 2])]);
    }

    #[test]
    fn test_flash_image_failed_overflow_write_leaves_image_unchanged() {
        let mut img = three_ranges();
        let before = img.segments();
        assert!(img.write(u32::MAX - 1, &[1, 2, 3]).is_err());
        assert_eq!(img.segments(), before);
    }

    #[test]
    fn test_flash_image_write_crossing_page_boundary_is_one_segment() {
        let mut img = FlashImage::default();
        img.write(0x0000_00FE, &[1, 2, 3, 4]).unwrap();
        assert_eq!(img.segments(), vec![(0xFE, vec![1, 2, 3, 4])]);
    }

    #[test]
    fn test_flash_image_write_longer_than_two_pages_round_trips() {
        let data: Vec<u8> = (0..600_u32).map(|i| (i % 251) as u8).collect();
        let mut img = FlashImage::default();
        img.write(0x1080, &data).unwrap();
        assert_eq!(img.segments(), vec![(0x1080, data)]);
    }

    #[test]
    fn test_flash_image_last_slot_and_first_slot_of_next_page_join() {
        let mut img = FlashImage::default();
        img.write(0x1FF, &[1]).unwrap();
        img.write(0x200, &[2]).unwrap();
        assert_eq!(img.segments(), vec![(0x1FF, vec![1, 2])]);
    }

    #[test]
    fn test_flash_image_hole_inside_page_splits() {
        let mut img = FlashImage::default();
        img.write(0x110, &[1]).unwrap();
        img.write(0x112, &[2]).unwrap();
        assert_eq!(img.segments(), vec![(0x110, vec![1]), (0x112, vec![2])]);
    }

    #[test]
    fn test_flash_image_hole_of_missing_pages_splits() {
        let mut img = FlashImage::default();
        img.write(0x0FF, &[1]).unwrap();
        img.write(0x500, &[2]).unwrap();
        assert_eq!(img.segments(), vec![(0x0FF, vec![1]), (0x500, vec![2])]);
    }

    #[test]
    fn test_flash_image_last_page_of_address_space() {
        let mut img = FlashImage::default();
        img.write(u32::MAX, &[7]).unwrap();
        img.write(u32::MAX - 3, &[1, 2]).unwrap();
        assert_eq!(img.segments(), vec![(u32::MAX - 3, vec![1, 2]), (u32::MAX, vec![7])]);
    }

    #[test]
    fn test_flash_image_matches_per_byte_model() {
        // Reference model: one map entry per byte (the old implementation).
        fn model_segments(model: &BTreeMap<u32, u8>) -> Segs {
            let mut out: Segs = Vec::new();
            for (&a, &b) in model {
                match out.last_mut() {
                    Some((s, d)) if u64::from(*s) + d.len() as u64 == u64::from(a) => d.push(b),
                    _ => out.push((a, vec![b])),
                }
            }
            out
        }
        // (first address, window width): at 0, mid-page, across a page
        // boundary, about 600 wide, and ending at u32::MAX.
        let windows: [(u32, u32); 5] = [
            (0, 64),
            (0x0000_0840, 24),
            (0x0000_00F0, 0x20),
            (0x0000_1000, 600),
            (u32::MAX - 299, 300),
        ];
        let mut total = 0_u32;
        let mut failures = 0_u32;
        for seed in 1..=10_u64 {
            for &(base, width) in &windows {
                let mut img = FlashImage::default();
                let mut model: BTreeMap<u32, u8> = BTreeMap::new();
                let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ u64::from(base);
                let mut next = move || {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    (state >> 33) as u32
                };
                for i in 0..120_u32 {
                    // Start a little before the window, and sometimes past its end.
                    let start = u64::from(base) + u64::from(next() % (width + 8));
                    let addr = u32::try_from(start.saturating_sub(4)).unwrap_or(u32::MAX);
                    let len = match next() % 4 {
                        0 => 0,
                        1 => next() % 4,
                        2 => next() % (width + 1),
                        _ => width + next() % 40, // longer than the window
                    };
                    let data: Vec<u8> = (0..len).map(|j| (i as u8).wrapping_add(j as u8) | 1).collect();
                    let before = img.segments();
                    let fits = u64::from(addr) + u64::from(len) <= 1 << 32;
                    let res = img.write(addr, &data);
                    assert_eq!(res.is_ok(), fits, "seed {seed} base {base:#x} write {i}");
                    total += 1;
                    if fits {
                        for (j, &b) in data.iter().enumerate() {
                            model.insert(addr + j as u32, b);
                        }
                    } else {
                        failures += 1;
                        assert_eq!(img.segments(), before, "failed write changed image");
                    }
                    let segs = img.segments();
                    assert_eq!(segs, model_segments(&model), "seed {seed} base {base:#x} write {i}");
                    assert!(segs.iter().all(|(_, d)| !d.is_empty()));
                    for w in segs.windows(2) {
                        assert!(u64::from(w[0].0) + (w[0].1.len() as u64) < u64::from(w[1].0));
                    }
                }
            }
        }
        assert!(total >= 6000);
        assert!(failures > 0, "the sequences must include overflowing writes");
    }

    #[test]
    fn test_hex_records_address_overflow_rejected() {
        // upper_linear = 0xFFFF0000, offset = 0xFFF8 => addr = 0xFFFFFFF8;
        // addr + 16 bytes overflows u32 and must be rejected, not wrap.
        let records = vec![
            Record::ExtendedLinearAddress(0xFFFF),
            Record::Data {
                offset: 0xFFF8,
                value: vec![0xAA; 16],
            },
            Record::EndOfFile,
        ];
        let result = hex_records_to_binary(&records);
        assert!(matches!(result, Err(Error::Firmware(_))));
        assert!(result.unwrap_err().to_string().contains("overflows"));
    }

    #[test]
    fn test_hex_records_span_cap_rejected() {
        // Records at 0x00000000 and 0x08000000 span 128 MiB, far above
        // MAX_FIRMWARE_SPAN (16 MiB); reject instead of allocating the span.
        let records = vec![
            Record::Data {
                offset: 0x0000,
                value: vec![0x01, 0x02],
            },
            Record::ExtendedLinearAddress(0x0800),
            Record::Data {
                offset: 0x0000,
                value: vec![0x03, 0x04],
            },
            Record::EndOfFile,
        ];
        let result = hex_records_to_binary(&records);
        assert!(matches!(result, Err(Error::Firmware(_))));
        assert!(result.unwrap_err().to_string().contains("span too large"));
    }

    #[test]
    fn test_hex_small_file_still_parses() {
        // A normal small HEX file is unaffected by the overflow/span checks.
        let hex = ":020000040800F2\n:0400000001020304F2\n:00000001FF\n";
        let (base, bytes) = parse_hex_string(hex).unwrap();
        assert_eq!(base, 0x0800_0000);
        assert_eq!(bytes, vec![0x01, 0x02, 0x03, 0x04]);
    }

    /// Write one segment, read it back with the parser.
    fn hex_round_trip(addr: u32, data: &[u8]) -> (u32, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.hex");
        std::fs::write(&path, hex_text(&[(addr, data.to_vec())]).unwrap()).unwrap();
        parse_hex_file(&path).unwrap()
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    #[test]
    fn test_write_hex_crossing_64k_boundary() {
        // Starts 0x20 bytes before a 64 KiB boundary and runs past it.
        let data = pattern(0x1_0000 + 0x57);
        let (base, bytes) = hex_round_trip(0x0800_FFE0, &data);
        assert_eq!(base, 0x0800_FFE0);
        assert_eq!(bytes, data);
    }

    #[test]
    fn test_write_hex_ending_on_64k_boundary() {
        let data = pattern(0x40);
        let (base, bytes) = hex_round_trip(0x0800_FFC0, &data);
        assert_eq!(base, 0x0800_FFC0);
        assert_eq!(bytes, data);
    }

    #[test]
    fn test_write_hex_small_segment_output_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.hex");
        std::fs::write(&path, hex_text(&[(0x0800_0000, vec![1, 2, 3, 4])]).unwrap()).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            ":020000040800F2\n:0400000001020304F2\n:00000001FF\n"
        );
    }

    #[test]
    fn test_write_hex_address_overflow_is_error() {
        let result = hex_text(&[(0xFFFF_FFFE, vec![0; 4])]);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_firmware_json() {
        let firmware = b"test firmware";
        let signature = b"test signature";
        let fw = create_firmware_json(firmware, signature);
        assert_ne!(fw.firmware, "");
        assert_ne!(fw.signature, "");
        assert_eq!(fw.firmware_bytes().unwrap(), firmware);
        assert_eq!(fw.signature_bytes().unwrap(), signature);
    }

    #[test]
    fn test_flash_addr() {
        assert_eq!(flash_addr(0), 0x0800_0000);
        assert_eq!(flash_addr(1), 0x0800_0800);
        assert_eq!(flash_addr(108), 0x0803_6000);
        assert_eq!(flash_addr(113), 0x0803_8800);
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
        assert_eq!(auth_word_addr, 0x0803_5FF8);
    }

    fn key_err(raw: &[u8]) -> String {
        parse_attestation_key(raw).unwrap_err().to_string()
    }

    #[test]
    fn test_parse_attestation_key_formats() {
        let key = [0xabu8; 32];
        let hex_key = "ab".repeat(32);
        let mut one_unprintable = [b'a'; 32];
        one_unprintable[0] = 0;
        let spaced = "ab ".repeat(32);
        let xxd = format!("{}\n{}\n", "ab".repeat(30), "ab".repeat(2));
        let ok = |raw: &[u8]| parse_attestation_key(raw).unwrap();

        assert_eq!(ok(&key), key);
        assert_eq!(ok(&one_unprintable), one_unprintable);
        assert_eq!(ok(hex_key.as_bytes()), key);
        assert_eq!(ok(format!("{hex_key}\n").as_bytes()), key);
        assert_eq!(ok(format!("{hex_key}\r\n").as_bytes()), key);
        assert_eq!(ok(format!(" \t{hex_key} \t").as_bytes()), key);
        assert_eq!(ok("AB".repeat(32).as_bytes()), key);
        assert_eq!(ok(xxd.as_bytes()), key);
        assert_eq!(ok(spaced.as_bytes()), key);
    }

    #[test]
    fn test_parse_attestation_key_rejects_text_that_is_not_64_hex_digits() {
        let hex64 = "ab".repeat(32);
        let bad: Vec<Vec<u8>> = vec![
            "ab".repeat(16).into_bytes(),                 // 32 bytes of hex text
            format!("{}\n", "a".repeat(31)).into_bytes(), // 32 bytes with LF
            b"this is a 32 byte note, no key.".to_vec(),  // 32 bytes of other text
            format!("0x{hex64}").into_bytes(),
            "a".repeat(63).into_bytes(),
            "a".repeat(65).into_bytes(),
            "a".repeat(66).into_bytes(),
            "a".repeat(128).into_bytes(),
            "zz".repeat(32).into_bytes(),
            b"abcd".to_vec(),
            Vec::new(),
            b" \t\r\n".to_vec(),
        ];
        for raw in &bad {
            assert!(parse_attestation_key(raw).is_err(), "accepted {} bytes", raw.len());
        }
    }

    #[test]
    fn test_parse_attestation_key_rejects_bad_binary_lengths() {
        for len in [31, 33, 64, 65] {
            assert!(parse_attestation_key(&vec![0xffu8; len]).is_err(), "len {len}");
            assert!(parse_attestation_key(&vec![0x01u8; len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn test_parse_attestation_key_bom_only_applies_to_text() {
        let key = [0xabu8; 32];
        let hex_key = "ab".repeat(32);
        let bom = b"\xEF\xBB\xBF";
        let with_bom = |tail: &str| [bom.as_slice(), tail.as_bytes()].concat();

        assert_eq!(
            parse_attestation_key(&with_bom(&format!("{hex_key}\r\n"))).unwrap(),
            key
        );
        assert_eq!(parse_attestation_key(&with_bom(&hex_key)).unwrap(), key);
        assert!(key_err(&with_bom(&"ab".repeat(16))).contains("text"));
        assert!(key_err(bom).contains("text"));

        // A raw key may start with the same three bytes: it is returned unchanged.
        let raw_key = [bom.as_slice(), &[0xffu8; 29]].concat();
        assert_eq!(raw_key.len(), 32);
        assert_eq!(parse_attestation_key(&raw_key).unwrap(), raw_key);

        // The BOM is not removed on the binary path, so 35 bytes is an error.
        let too_long = [bom.as_slice(), &[0xffu8; 32]].concat();
        let err = key_err(&too_long);
        assert!(err.contains("raw key") && err.contains("got 35"));
    }

    #[test]
    fn test_parse_attestation_key_rejects_utf16_text() {
        let utf16: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain("ab".repeat(32).bytes().flat_map(|b| [b, 0]))
            .collect();
        assert!(key_err(&utf16).contains("not plain ASCII text"));
    }

    #[test]
    fn test_parse_attestation_key_errors_name_format_and_hide_content() {
        // Each input uses characters that cannot appear in any of our messages.
        let bad_char = key_err(format!("{}#", "a".repeat(63)).as_bytes());
        assert!(bad_char.contains("text") && bad_char.contains("not a hex digit"));
        assert!(!bad_char.contains('#') && !bad_char.contains('\''));
        assert!(bad_char.is_ascii());

        let count = key_err("7".repeat(32).as_bytes());
        assert!(count.contains("text") && count.contains("64 hex digits") && count.contains("got 32"));
        assert!(!count.contains('7'));
        assert!(count.is_ascii());

        let err = parse_attestation_key(&[0xc3u8; 33]).unwrap_err();
        assert!(err.to_string().contains("raw key") && err.to_string().contains("got 33"));
        for text in [format!("{err}"), format!("{err:?}")] {
            assert!(!text.contains("c3") && !text.contains("C3") && !text.contains("195"));
            assert!(text.is_ascii(), "message is not plain ASCII");
        }
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
