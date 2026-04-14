use std::time::Instant;

use crate::commands::key::common;
use crate::device::{HidDevice, CMD_GET_VERSION, CTAPHID_CBOR, CTAPHID_PING, CTAPHID_WINK};
use crate::error::{Result, SoloError};
use crate::firmware::FirmwareVersion;

/// Get firmware version from the device.
pub fn cmd_key_version(hid: &impl HidDevice) -> Result<FirmwareVersion> {
    get_device_version(hid)
}

pub(super) fn get_device_version(hid: &impl HidDevice) -> Result<FirmwareVersion> {
    let response = hid.send_recv(CMD_GET_VERSION, &[])?;
    if response.len() < 3 {
        return Err(SoloError::ProtocolError(
            "Version response too short".into(),
        ));
    }
    Ok(FirmwareVersion::new(
        response[0] as u32,
        response[1] as u32,
        response[2] as u32,
    ))
}

/// Blink the LED on the device.
pub fn cmd_wink(hid: &impl HidDevice) -> Result<()> {
    hid.send_recv(CTAPHID_WINK, &[])?;
    println!("Winked!");
    Ok(())
}

/// Send ping(s) and measure round-trip time.
pub fn cmd_ping(hid: &impl HidDevice, count: u32, data: &[u8]) -> Result<()> {
    for i in 0..count {
        let start = Instant::now();
        let response = hid.send_recv(CTAPHID_PING, data)?;
        let elapsed = start.elapsed();

        if response != data {
            return Err(SoloError::ProtocolError("Ping response data mismatch".into()));
        }
        println!(
            "Ping {}: {} bytes, RTT = {:.3}ms",
            i + 1,
            data.len(),
            elapsed.as_secs_f64() * 1000.0
        );
    }
    Ok(())
}

/// Program a keyboard sequence (HID keyboard emulation).
pub fn cmd_keyboard(hid: &impl HidDevice, data: &[u8]) -> Result<()> {
    if data.len() > 64 {
        return Err(SoloError::ProtocolError(
            "Keyboard data too long (max 64 bytes)".into(),
        ));
    }
    // Use a vendor command for keyboard programming
    // This uses CTAPHID_VENDOR_FIRST + offset
    let cmd = 0x53u8; // vendor keyboard command
    hid.send_recv(cmd, data)?;
    println!("Keyboard sequence programmed ({} bytes)", data.len());
    Ok(())
}

/// Factory reset the device.
pub fn cmd_reset(hid: &impl HidDevice) -> Result<()> {
    if !common::confirm(
        "Warning: Your credentials will be lost!!! Type 'yes' to confirm:",
    )? {
        println!("Aborted.");
        return Ok(());
    }
    println!("Press the button to confirm -- again, your credentials will be lost!!!");
    // CTAP2 authenticatorReset = 0x07
    // Send via CTAPHID_CBOR
    let cbor_reset = vec![0x07u8];
    hid.send_recv(CTAPHID_CBOR, &cbor_reset)?;
    println!("....aaaand they're gone");
    Ok(())
}

/// Permanently disable firmware updates on the device.
pub fn cmd_disable_updates(hid: &impl HidDevice) -> Result<()> {
    use crate::device::CMD_DISABLE_BOOTLOADER;
    if !common::confirm(
        "WARNING: This will permanently disable firmware updates on this device!\nThis action cannot be undone. Type 'yes' to confirm:",
    )? {
        println!("Aborted.");
        return Ok(());
    }
    hid.send_bootloader_cmd(CMD_DISABLE_BOOTLOADER, 0, &[])?;
    println!("Firmware updates have been permanently disabled.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::mock::MockDevice;
    use crate::error::SoloError;

    // ── cmd_ping ────────────────────────────────────────────────────────────

    /// The device echoes back the same payload: cmd_ping must succeed.
    #[test]
    fn test_cmd_ping_success_echo() {
        let data = vec![0x01u8, 0x02, 0x03, 0x04];
        let device = MockDevice::new(vec![Ok(data.clone())]);
        let result = cmd_ping(&device, 1, &data);
        assert!(result.is_ok());
    }

    /// The device echoes back different bytes: cmd_ping must return an error.
    #[test]
    fn test_cmd_ping_data_mismatch() {
        let sent = vec![0x01u8, 0x02, 0x03];
        let received = vec![0xFF, 0xFE, 0xFD];
        let device = MockDevice::new(vec![Ok(received)]);
        let result = cmd_ping(&device, 1, &sent);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("mismatch") || msg.contains("Protocol error"), "unexpected error: {}", msg);
    }

    /// When the mock queue is empty, send_recv returns Timeout: cmd_ping must propagate it.
    #[test]
    fn test_cmd_ping_timeout() {
        let device = MockDevice::new(vec![]);
        let result = cmd_ping(&device, 1, &[0xAA]);
        assert!(matches!(result.unwrap_err(), SoloError::Timeout));
    }

    /// cmd_ping with count=0 performs no sends and must succeed immediately.
    #[test]
    fn test_cmd_ping_count_zero() {
        // No responses queued — if any send_recv is called, it would return Timeout.
        let device = MockDevice::new(vec![]);
        let result = cmd_ping(&device, 0, &[0x01, 0x02]);
        assert!(result.is_ok());
    }

    // ── cmd_wink ────────────────────────────────────────────────────────────

    /// A successful wink: device returns any non-error response.
    #[test]
    fn test_cmd_wink_success() {
        let device = MockDevice::new(vec![Ok(vec![])]);
        let result = cmd_wink(&device);
        assert!(result.is_ok());
    }

    /// If the device times out during wink, the error is propagated.
    #[test]
    fn test_cmd_wink_timeout() {
        let device = MockDevice::new(vec![]);
        let result = cmd_wink(&device);
        assert!(matches!(result.unwrap_err(), SoloError::Timeout));
    }

    // ── cmd_key_version ────────────────────────────────────────────────────

    /// Device returns three version bytes [major, minor, patch].
    #[test]
    fn test_cmd_key_version_parses_bytes() {
        let device = MockDevice::new(vec![Ok(vec![4, 1, 2])]);
        let version = cmd_key_version(&device).unwrap();
        assert_eq!(version, crate::firmware::FirmwareVersion::new(4, 1, 2));
    }

    /// Version 0.0.0 is a valid response.
    #[test]
    fn test_cmd_key_version_zero() {
        let device = MockDevice::new(vec![Ok(vec![0, 0, 0])]);
        let version = cmd_key_version(&device).unwrap();
        assert_eq!(version, crate::firmware::FirmwareVersion::new(0, 0, 0));
    }

    /// Extra bytes beyond the first three must be ignored.
    #[test]
    fn test_cmd_key_version_extra_bytes_ignored() {
        let device = MockDevice::new(vec![Ok(vec![2, 5, 3, 99, 42])]);
        let version = cmd_key_version(&device).unwrap();
        assert_eq!(version, crate::firmware::FirmwareVersion::new(2, 5, 3));
    }

    /// Fewer than 3 bytes must produce a ProtocolError.
    #[test]
    fn test_cmd_key_version_too_short() {
        let device = MockDevice::new(vec![Ok(vec![1, 0])]);
        let err = cmd_key_version(&device).unwrap_err();
        assert!(matches!(err, SoloError::ProtocolError(_)));
    }

    /// Timeout propagates as an error.
    #[test]
    fn test_cmd_key_version_timeout() {
        let device = MockDevice::new(vec![]);
        let err = cmd_key_version(&device).unwrap_err();
        assert!(matches!(err, SoloError::Timeout));
    }
}
