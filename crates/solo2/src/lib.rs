//! Solo 2 device support: USB identifiers and the admin app's vendor
//! commands.
//!
//! Solo 2 runs Trussed firmware on an NXP LPC55S69. Generic CTAP2 operations
//! (PINs, credentials, hmac-secret) work through `solo-ctap2` unchanged; this
//! crate only holds what is specific to Solo 2. Firmware updates (the LPC55
//! ROM bootloader and SB2 images) are not implemented yet.

pub mod error;
pub mod protocol;

pub use error::{Error, Result};

use std::fmt;
use std::time::Duration;

use solo_ctaphid::{DeviceFilter, HidDevice, HidDeviceInfo, HidTransport, list_devices};

use protocol::{CMD_LOCKED, CMD_RNG, CMD_UUID, CMD_VERSION, SOLO2_PID, SOLO2_VID};

/// Matches the FIDO interface of a Solo 2 running firmware.
pub const DEVICE_FILTER: DeviceFilter = DeviceFilter::AllOf(&[
    DeviceFilter::UsbId {
        vendor_id: SOLO2_VID,
        product_id: SOLO2_PID,
    },
    DeviceFilter::Fido,
]);

/// Whether a USB vendor/product ID pair is a Solo 2 running firmware.
#[must_use]
pub const fn is_solo2(vendor_id: u16, product_id: u16) -> bool {
    vendor_id == SOLO2_VID && product_id == SOLO2_PID
}

/// List all connected Solo 2 devices.
///
/// # Errors
/// Returns an error if the HID API cannot be initialized.
pub fn list_solo2_devices() -> Result<Vec<HidDeviceInfo>> {
    Ok(list_devices(DEVICE_FILTER)?)
}

/// Open a Solo 2 by serial number (or the only one present if `None`).
///
/// # Errors
/// See [`HidTransport::open`].
pub fn open(serial: Option<&str>, timeout: Duration) -> Result<HidTransport> {
    Ok(HidTransport::open(DEVICE_FILTER, serial, timeout)?)
}

/// Solo 2 firmware version.
///
/// The firmware packs it into a `u32` as `major << 22 | minor << 6 | patch`
/// (10, 16 and 6 bits). Solo 2 releases use the minor field for the number
/// of days since 2020-01-01, so versions read like `2.964.0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u8,
}

impl Version {
    /// Unpack a version from its `u32` encoding.
    #[must_use]
    pub fn from_u32(v: u32) -> Self {
        // Each field is masked to its bit width first, so the conversions
        // cannot fail.
        Self {
            major: u16::try_from(v >> 22).unwrap_or(u16::MAX),
            minor: u16::try_from((v >> 6) & 0xFFFF).unwrap_or(u16::MAX),
            patch: u8::try_from(v & 0x3F).unwrap_or(u8::MAX),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Read the firmware version.
///
/// # Errors
/// Returns an error if the command fails, or the response is not exactly
/// 4 bytes.
pub fn version(hid: &impl HidDevice) -> Result<Version> {
    let resp = hid.send_recv(CMD_VERSION, &[])?;
    let bytes: [u8; 4] = resp
        .as_slice()
        .try_into()
        .map_err(|_| Error::MalformedResponse(format!("version response should be 4 bytes, got {}", resp.len())))?;
    Ok(Version::from_u32(u32::from_be_bytes(bytes)))
}

/// Read the device UUID as 32 lowercase hex digits.
///
/// Early Solo 2 firmware does not implement this over CTAPHID; there the
/// HID serial number carries the same value.
///
/// # Errors
/// Returns an error if the command fails, or the response is not 16 bytes.
pub fn uuid(hid: &impl HidDevice) -> Result<String> {
    let resp = hid.send_recv(CMD_UUID, &[])?;
    if resp.len() != 16 {
        return Err(Error::MalformedResponse(format!(
            "uuid response should be 16 bytes, got {}",
            resp.len()
        )));
    }
    Ok(hex::encode(resp))
}

/// Whether the device is locked (production firmware that refuses
/// unsigned updates and debug access).
///
/// # Errors
/// Returns an error if the command fails or the response is empty.
pub fn locked(hid: &impl HidDevice) -> Result<bool> {
    let resp = hid.send_recv(CMD_LOCKED, &[])?;
    let first = resp
        .first()
        .ok_or_else(|| Error::MalformedResponse("empty locked response".into()))?;
    Ok(*first == 1)
}

/// Read one batch of random bytes (57 per call on current firmware).
///
/// # Errors
/// Returns an error if the command fails.
pub fn random_bytes(hid: &impl HidDevice) -> Result<Vec<u8>> {
    Ok(hid.send_recv(CMD_RNG, &[])?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use solo_ctaphid::mock::MockDevice;

    #[test]
    fn test_version_unpacks_fields() {
        let packed: u32 = (2 << 22) | (964 << 6) | 3;
        let v = Version::from_u32(packed);
        assert_eq!(
            v,
            Version {
                major: 2,
                minor: 964,
                patch: 3
            }
        );
        assert_eq!(v.to_string(), "2.964.3");
    }

    #[test]
    fn test_version_field_limits() {
        let v = Version::from_u32(u32::MAX);
        assert_eq!((v.major, v.minor, v.patch), (1023, 0xFFFF, 63));
    }

    #[test]
    fn test_version_reads_big_endian() {
        let packed: u32 = (2 << 22) | (964 << 6);
        let device = MockDevice::new(vec![Ok(packed.to_be_bytes().to_vec())]);
        assert_eq!(version(&device).unwrap().to_string(), "2.964.0");
    }

    #[test]
    fn test_version_rejects_wrong_length() {
        let device = MockDevice::new(vec![Ok(vec![4, 1, 2])]);
        assert!(matches!(version(&device).unwrap_err(), Error::MalformedResponse(_)));
    }

    #[test]
    fn test_uuid_hex() {
        let device = MockDevice::new(vec![Ok((0u8..16).collect())]);
        assert_eq!(uuid(&device).unwrap(), "000102030405060708090a0b0c0d0e0f");
        let device = MockDevice::new(vec![Ok(vec![0; 8])]);
        assert!(uuid(&device).is_err());
    }

    #[test]
    fn test_locked() {
        let device = MockDevice::new(vec![Ok(vec![1])]);
        assert!(locked(&device).unwrap());
        let device = MockDevice::new(vec![Ok(vec![0])]);
        assert!(!locked(&device).unwrap());
        let device = MockDevice::new(vec![Ok(vec![])]);
        assert!(locked(&device).is_err());
    }

    #[test]
    fn test_is_solo2() {
        assert!(is_solo2(0x1209, 0xBEEE));
        assert!(!is_solo2(0x1209, 0xB000)); // bootloader
        assert!(!is_solo2(0x0483, 0xA2CA)); // Solo 1
    }
}
