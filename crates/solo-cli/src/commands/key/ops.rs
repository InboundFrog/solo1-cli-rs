use std::time::Instant;

use crate::commands::key::common;
use crate::error::{Result, SoloError};
use crate::output::{PingOutput, Solo1VersionOutput, print_json};
use solo_ctaphid::{CTAPHID_CBOR, CTAPHID_PING, CTAPHID_WINK, HidDevice};
use solo1::firmware::FirmwareVersion;
use solo1::protocol::{CMD_GET_VERSION, CMD_KEYBOARD};

/// Print the firmware version of the device.
///
/// `product` is the USB product name. A key in the bootloader answers the
/// version query with the version of the bootloader, so it is reported as such.
///
/// # Errors
/// Returns an error if the version query fails (device/transport error or
/// timeout), the response is too short, or JSON serialization fails.
pub fn cmd_key_version(hid: &impl HidDevice, product: Option<&str>, json: bool) -> Result<()> {
    let out = key_version_output(hid, product)?;
    if json {
        return print_json(&out);
    }
    println!("{}", key_version_text(&out));
    Ok(())
}

fn key_version_output(hid: &impl HidDevice, product: Option<&str>) -> Result<Solo1VersionOutput> {
    let (version, locked) = query_version(hid)?;
    let version = version.to_string();
    Ok(if common::is_bootloader(product) {
        // The bootloader build compiles the same ctaphid.c (tag 4.1.5), so it also sends the
        // locked byte. This code does not show it in bootloader mode.
        Solo1VersionOutput::Bootloader {
            bootloader_version: version,
        }
    } else {
        Solo1VersionOutput::Normal {
            firmware_version: version,
            locked,
        }
    })
}

fn key_version_text(out: &Solo1VersionOutput) -> String {
    match out {
        Solo1VersionOutput::Bootloader { bootloader_version: v } => {
            format!("Bootloader version: {v}\nThe key is in bootloader mode.")
        }
        Solo1VersionOutput::Normal {
            firmware_version: v,
            locked,
        } => {
            let line = locked.map(|l| format!("\nLocked: {}", if l { "yes" } else { "no" }));
            format!("Firmware version: {v}{}", line.unwrap_or_default())
        }
    }
}

/// Print the firmware version of a Solo 2.
///
/// # Errors
/// Returns an error if the version query fails (device/transport error or
/// timeout), the response is not 4 bytes, or JSON serialization fails.
pub fn cmd_key_version_solo2(hid: &impl HidDevice, json: bool) -> Result<()> {
    use crate::output::VersionOutput;

    let version = solo2::version(hid)?;
    if json {
        return print_json(&VersionOutput {
            firmware_version: version.to_string(),
        });
    }
    println!("Firmware version: {version}");
    Ok(())
}

pub(super) fn get_device_version(hid: &impl HidDevice) -> Result<FirmwareVersion> {
    query_version(hid).map(|(version, _)| version)
}

/// Ask for the version. The second value is the "locked" flag, the fourth byte of the answer.
///
/// The firmware (tag 4.1.5) sends 0 or 1 there. A three-byte answer has no flag, and
/// any other value is not read as a flag, so both give `None`.
fn query_version(hid: &impl HidDevice) -> Result<(FirmwareVersion, Option<bool>)> {
    let response = hid.send_recv(CMD_GET_VERSION, &[])?;
    let [major, minor, patch, rest @ ..] = response.as_slice() else {
        return Err(SoloError::ProtocolError("Version response too short".into()));
    };
    let locked = match rest.first() {
        Some(0) => Some(false),
        Some(1) => Some(true),
        _ => None,
    };
    Ok((
        FirmwareVersion::new(u32::from(*major), u32::from(*minor), u32::from(*patch)),
        locked,
    ))
}

/// Blink the LED on the device.
///
/// # Errors
/// Returns an error if the wink command fails (device/transport error or
/// timeout).
pub fn cmd_wink(hid: &impl HidDevice) -> Result<()> {
    hid.send_recv(CTAPHID_WINK, &[])?;
    println!("Winked!");
    Ok(())
}

/// Send ping(s) and measure round-trip time.
///
/// # Errors
/// Returns an error if a ping cannot be sent or received (device/transport
/// error or timeout), the echoed data does not match what was sent, the ping
/// index overflows, or JSON serialization fails.
pub fn cmd_ping(hid: &impl HidDevice, count: u32, data: &[u8], json: bool) -> Result<()> {
    for i in 0..count {
        let start = Instant::now();
        let response = hid.send_recv(CTAPHID_PING, data)?;
        let elapsed = start.elapsed();

        if response != data {
            return Err(SoloError::ProtocolError("Ping response data mismatch".into()));
        }

        let index = i
            .checked_add(1)
            .ok_or_else(|| SoloError::ProtocolError("Ping index overflow".into()))?;

        if json {
            // One compact object per line (JSON Lines), printed as each ping answers.
            println!(
                "{}",
                serde_json::to_string(&PingOutput {
                    index,
                    data_len: data.len(),
                    duration_ms: elapsed.as_secs_f64() * 1000.0,
                })?
            );
        } else {
            println!(
                "Ping {}: {} bytes, RTT = {:.3}ms",
                index,
                data.len(),
                elapsed.as_secs_f64() * 1000.0
            );
        }
    }
    Ok(())
}

/// Program a keyboard sequence (HID keyboard emulation).
///
/// # Errors
/// Returns an error if the data exceeds 64 bytes or the keyboard command fails
/// (device/transport error or timeout).
pub fn cmd_keyboard(hid: &impl HidDevice, data: &[u8]) -> Result<()> {
    if data.len() > 64 {
        return Err(SoloError::ProtocolError("Keyboard data too long (max 64 bytes)".into()));
    }
    hid.send_recv(CMD_KEYBOARD, data)?;
    println!("Keyboard sequence programmed ({} bytes)", data.len());
    Ok(())
}

/// Factory reset the device.
///
/// # Errors
/// Returns an error if reading the confirmation from stdin fails or the reset
/// command fails (device/transport error or timeout).
pub fn cmd_reset(hid: &impl HidDevice) -> Result<()> {
    if !common::confirm("Warning: Your credentials will be lost!!! Type 'yes' to confirm:")? {
        println!("Aborted.");
        return Ok(());
    }
    println!("Press the button to confirm -- again, your credentials will be lost!!!");
    send_reset(hid)?;
    println!("....aaaand they're gone");
    Ok(())
}

/// Send CTAP2 authenticatorReset (0x07) and check the status byte.
///
/// Some keys refuse with 0x30 (not allowed) when the reset comes too late
/// after power-up; a Solo 1 (firmware 4.1.5) has no such limit. When nobody
/// touched the key, a Solo 1 answers 0x3A (action timeout); other keys may
/// answer 0x2F.
fn send_reset(hid: &impl HidDevice) -> Result<()> {
    let response = hid.send_recv(CTAPHID_CBOR, &[0x07u8])?;
    solo_ctap2::check_ctap_status(&response, "authenticatorReset")?;
    Ok(())
}

/// Permanently disable firmware updates on the device.
///
/// # Errors
/// Returns an error if reading the confirmation from stdin fails or the
/// disable-bootloader command fails (device/transport error or a non-zero
/// bootloader status).
pub fn cmd_disable_updates(hid: &impl HidDevice) -> Result<()> {
    use solo1::{bootloader::bootloader_cmd, protocol::CMD_DISABLE_BOOTLOADER};
    if !common::confirm(
        "WARNING: This will permanently disable firmware updates on this device!\nThis action cannot be undone. Type 'yes' to confirm:",
    )? {
        println!("Aborted.");
        return Ok(());
    }
    bootloader_cmd(hid, CMD_DISABLE_BOOTLOADER, 0, &[])?;
    println!("Firmware updates have been permanently disabled.");
    Ok(())
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
    use crate::error::SoloError;
    use solo_ctaphid::mock::MockDevice;

    // ── cmd_ping ────────────────────────────────────────────────────────────

    /// The device echoes back the same payload: `cmd_ping` must succeed.
    #[test]
    fn test_cmd_ping_success_echo() {
        let data = vec![0x01u8, 0x02, 0x03, 0x04];
        let device = MockDevice::new(vec![Ok(data.clone())]);
        let result = cmd_ping(&device, 1, &data, false);
        assert!(result.is_ok());
    }

    /// JSON mode with two pings: both echo back, so `cmd_ping` must succeed.
    #[test]
    fn test_cmd_ping_json_two_pings() {
        let data = vec![0x01u8, 0x02, 0x03, 0x04];
        let device = MockDevice::new(vec![Ok(data.clone()), Ok(data.clone())]);
        let result = cmd_ping(&device, 2, &data, true);
        assert!(result.is_ok());
    }

    /// The device echoes back different bytes: `cmd_ping` must return an error.
    #[test]
    fn test_cmd_ping_data_mismatch() {
        let sent = vec![0x01u8, 0x02, 0x03];
        let received = vec![0xFF, 0xFE, 0xFD];
        let device = MockDevice::new(vec![Ok(received)]);
        let result = cmd_ping(&device, 1, &sent, false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("mismatch") || msg.contains("Protocol error"),
            "unexpected error: {msg}"
        );
    }

    /// When the mock queue is empty, `send_recv` returns Timeout: `cmd_ping` must propagate it.
    #[test]
    fn test_cmd_ping_timeout() {
        let device = MockDevice::new(vec![]);
        let result = cmd_ping(&device, 1, &[0xAA], false);
        assert!(matches!(result.unwrap_err(), SoloError::Timeout));
    }

    /// `cmd_ping` with count=0 performs no sends and must succeed immediately.
    #[test]
    fn test_cmd_ping_count_zero() {
        // No responses queued — if any send_recv is called, it would return Timeout.
        let device = MockDevice::new(vec![]);
        let result = cmd_ping(&device, 0, &[0x01, 0x02], false);
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

    // ── send_reset ──────────────────────────────────────────────────────────

    /// A refused reset (status 0x30, not allowed) must be an error.
    #[test]
    fn test_send_reset_refused() {
        let device = MockDevice::new(vec![Ok(vec![0x30])]);
        let err = send_reset(&device).unwrap_err();
        assert!(matches!(err, SoloError::AuthenticatorError { code: 0x30, .. }), "{err}");
    }

    /// Status 0x00 means the key accepted the reset.
    #[test]
    fn test_send_reset_ok() {
        let device = MockDevice::new(vec![Ok(vec![0x00])]);
        assert!(send_reset(&device).is_ok());
    }

    // ── cmd_key_version ────────────────────────────────────────────────────

    /// Device returns three version bytes [major, minor, patch].
    #[test]
    fn test_cmd_key_version_parses_bytes() {
        let device = MockDevice::new(vec![Ok(vec![4, 1, 2])]);
        let version = get_device_version(&device).unwrap();
        assert_eq!(version, FirmwareVersion::new(4, 1, 2));
    }

    /// Version 0.0.0 is a valid response.
    #[test]
    fn test_cmd_key_version_zero() {
        let device = MockDevice::new(vec![Ok(vec![0, 0, 0])]);
        let version = get_device_version(&device).unwrap();
        assert_eq!(version, FirmwareVersion::new(0, 0, 0));
    }

    /// Extra bytes beyond the first three do not change the version.
    #[test]
    fn test_cmd_key_version_extra_bytes_ignored() {
        let device = MockDevice::new(vec![Ok(vec![2, 5, 3, 99, 42])]);
        let version = get_device_version(&device).unwrap();
        assert_eq!(version, FirmwareVersion::new(2, 5, 3));
    }

    /// Fewer than 3 bytes must produce a `ProtocolError`.
    #[test]
    fn test_cmd_key_version_too_short() {
        let device = MockDevice::new(vec![Ok(vec![1, 0])]);
        let err = cmd_key_version(&device, None, false).unwrap_err();
        assert!(matches!(err, SoloError::ProtocolError(_)));
    }

    /// Timeout propagates as an error.
    #[test]
    fn test_cmd_key_version_timeout() {
        let device = MockDevice::new(vec![]);
        let err = cmd_key_version(&device, None, false).unwrap_err();
        assert!(matches!(err, SoloError::Timeout));
    }

    /// Normal key: text and JSON report the firmware version.
    #[test]
    fn test_key_version_normal_mode() {
        let device = MockDevice::new(vec![Ok(vec![4, 1, 5])]);
        let out = key_version_output(&device, Some("Solo 4.1.5")).unwrap();
        assert_eq!(key_version_text(&out), "Firmware version: 4.1.5");
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v, serde_json::json!({"mode": "normal", "firmware_version": "4.1.5"}));
    }

    /// Bootloader: the version is called the bootloader version, and the mode is said.
    #[test]
    fn test_key_version_bootloader_mode() {
        let device = MockDevice::new(vec![Ok(vec![3, 0, 0])]);
        let out = key_version_output(&device, Some("Solo Bootloader 3.0.0")).unwrap();
        let text = key_version_text(&out);
        assert!(text.contains("Bootloader version: 3.0.0"), "{text}");
        assert!(text.contains("bootloader mode"), "{text}");
        assert!(!text.contains("Firmware"), "{text}");
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"mode": "bootloader", "bootloader_version": "3.0.0"})
        );
    }

    fn normal_with(bytes: Vec<u8>) -> (String, serde_json::Value) {
        let device = MockDevice::new(vec![Ok(bytes)]);
        let out = key_version_output(&device, Some("Solo 4.1.5")).unwrap();
        (key_version_text(&out), serde_json::to_value(&out).unwrap())
    }

    /// Fourth byte 1: locked.
    #[test]
    fn test_key_version_locked_yes() {
        let (text, v) = normal_with(vec![4, 1, 5, 1]);
        assert_eq!(text, "Firmware version: 4.1.5\nLocked: yes");
        assert_eq!(
            v,
            serde_json::json!({"mode": "normal", "firmware_version": "4.1.5", "locked": true})
        );
    }

    /// Fourth byte 0: not locked.
    #[test]
    fn test_key_version_locked_no() {
        let (text, v) = normal_with(vec![4, 1, 5, 0]);
        assert_eq!(text, "Firmware version: 4.1.5\nLocked: no");
        assert_eq!(v["locked"], serde_json::json!(false));
    }

    /// Any other fourth byte is not a flag: no line, no field.
    #[test]
    fn test_key_version_locked_other_byte() {
        let (text, v) = normal_with(vec![4, 1, 5, 2]);
        assert_eq!(text, "Firmware version: 4.1.5");
        assert!(v.get("locked").is_none(), "{v}");
    }

    /// Bootloader mode does not show the byte.
    #[test]
    fn test_key_version_bootloader_ignores_fourth_byte() {
        let device = MockDevice::new(vec![Ok(vec![3, 0, 0, 1])]);
        let out = key_version_output(&device, Some("Solo Bootloader 3.0.0")).unwrap();
        assert!(!key_version_text(&out).contains("Locked"));
        assert!(serde_json::to_value(&out).unwrap().get("locked").is_none());
    }
}
