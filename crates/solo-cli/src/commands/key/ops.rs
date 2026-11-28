use std::time::Instant;

use crate::commands::key::common;
use crate::error::{Result, SoloError};
use crate::output::{PingOutput, write_json};
use solo_ctaphid::{CTAPHID_CBOR, CTAPHID_PING, CTAPHID_WINK, HidDevice};
use solo1::firmware::FirmwareVersion;
use solo1::protocol::{CMD_GET_VERSION, CMD_KEYBOARD};
use std::io::Write;

/// Print the firmware version of the device.
///
/// # Errors
/// Returns an error if the version query fails (device/transport error or
/// timeout), the response is too short, or JSON serialization fails.
pub fn cmd_key_version(hid: &impl HidDevice, json: bool, mut out: impl Write) -> Result<()> {
    use crate::output::VersionOutput;

    let version = get_device_version(hid)?;
    if json {
        return write_json(
            out,
            &VersionOutput {
                firmware_version: version.to_string(),
            },
        );
    }
    outln!(out, "Firmware version: {version}");
    Ok(())
}

/// Print the firmware version of a Solo 2.
///
/// # Errors
/// Returns an error if the version query fails (device/transport error or
/// timeout), the response is not 4 bytes, or JSON serialization fails.
pub fn cmd_key_version_solo2(hid: &impl HidDevice, json: bool, mut out: impl Write) -> Result<()> {
    use crate::output::VersionOutput;

    let version = solo2::version(hid)?;
    if json {
        return write_json(
            out,
            &VersionOutput {
                firmware_version: version.to_string(),
            },
        );
    }
    outln!(out, "Firmware version: {version}");
    Ok(())
}

pub(super) fn get_device_version(hid: &impl HidDevice) -> Result<FirmwareVersion> {
    let response = hid.send_recv(CMD_GET_VERSION, &[])?;
    let [major, minor, patch, ..] = response.as_slice() else {
        return Err(SoloError::ProtocolError("Version response too short".into()));
    };
    Ok(FirmwareVersion::new(
        u32::from(*major),
        u32::from(*minor),
        u32::from(*patch),
    ))
}

/// Blink the LED on the device.
///
/// # Errors
/// Returns an error if the wink command fails (device/transport error or
/// timeout).
pub fn cmd_wink(hid: &impl HidDevice) -> Result<()> {
    hid.send_recv(CTAPHID_WINK, &[])?;
    outln!("Winked!");
    Ok(())
}

/// Send ping(s) and measure round-trip time.
///
/// # Errors
/// Returns an error if a ping cannot be sent or received (device/transport
/// error or timeout), the echoed data does not match what was sent, the ping
/// index overflows, or JSON serialization fails.
pub fn cmd_ping(hid: &impl HidDevice, count: u32, data: &[u8], json: bool, mut out: impl Write) -> Result<()> {
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
            outln!(
                out,
                "{}",
                serde_json::to_string(&PingOutput {
                    index,
                    data_len: data.len(),
                    duration_ms: elapsed.as_secs_f64() * 1000.0,
                })?
            );
        } else {
            outln!(
                out,
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
    outln!("Keyboard sequence programmed ({} bytes)", data.len());
    Ok(())
}

/// Factory reset the device.
///
/// # Errors
/// Returns an error if reading the confirmation from stdin fails or the reset
/// command fails (device/transport error or timeout).
pub fn cmd_reset(hid: &impl HidDevice) -> Result<()> {
    if !common::confirm("Warning: Your credentials will be lost!!! Type 'yes' to confirm:")? {
        outln!("Aborted.");
        return Ok(());
    }
    outln!("Press the button to confirm -- again, your credentials will be lost!!!");
    send_reset(hid)?;
    outln!("....aaaand they're gone");
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
        outln!("Aborted.");
        return Ok(());
    }
    bootloader_cmd(hid, CMD_DISABLE_BOOTLOADER, 0, &[])?;
    outln!("Firmware updates have been permanently disabled.");
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
        let result = cmd_ping(&device, 1, &data, false, std::io::sink());
        assert!(result.is_ok());
    }

    /// JSON mode with two pings: both echo back, so `cmd_ping` must succeed.
    #[test]
    fn test_cmd_ping_json_two_pings() {
        let data = vec![0x01u8, 0x02, 0x03, 0x04];
        let device = MockDevice::new(vec![Ok(data.clone()), Ok(data.clone())]);
        let result = cmd_ping(&device, 2, &data, true, std::io::sink());
        assert!(result.is_ok());
    }

    /// The device echoes back different bytes: `cmd_ping` must return an error.
    #[test]
    fn test_cmd_ping_data_mismatch() {
        let sent = vec![0x01u8, 0x02, 0x03];
        let received = vec![0xFF, 0xFE, 0xFD];
        let device = MockDevice::new(vec![Ok(received)]);
        let result = cmd_ping(&device, 1, &sent, false, std::io::sink());
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
        let result = cmd_ping(&device, 1, &[0xAA], false, std::io::sink());
        assert!(matches!(result.unwrap_err(), SoloError::Timeout));
    }

    /// `cmd_ping` with count=0 performs no sends and must succeed immediately.
    #[test]
    fn test_cmd_ping_count_zero() {
        // No responses queued — if any send_recv is called, it would return Timeout.
        let device = MockDevice::new(vec![]);
        let result = cmd_ping(&device, 0, &[0x01, 0x02], false, std::io::sink());
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

    /// Extra bytes beyond the first three must be ignored.
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
        let err = cmd_key_version(&device, false, std::io::sink()).unwrap_err();
        assert!(matches!(err, SoloError::ProtocolError(_)));
    }

    /// Timeout propagates as an error.
    #[test]
    fn test_cmd_key_version_timeout() {
        let device = MockDevice::new(vec![]);
        let err = cmd_key_version(&device, false, std::io::sink()).unwrap_err();
        assert!(matches!(err, SoloError::Timeout));
    }

    // ── what the commands write ─────────────────────────────────────────────

    /// A writer that always fails, like a closed stdout.
    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Text mode prints one line per ping: index, size and round-trip time.
    #[test]
    fn test_cmd_ping_text_lines() {
        let data = vec![1u8, 2, 3, 4];
        let device = MockDevice::new(vec![Ok(data.clone()), Ok(data.clone())]);
        let mut out = Vec::new();
        cmd_ping(&device, 2, &data, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        for (line, index) in lines.iter().zip(1..) {
            let rest = line.strip_prefix(&format!("Ping {index}: 4 bytes, RTT = ")).unwrap();
            let ms = rest.strip_suffix("ms").unwrap();
            // Three digits after the point.
            assert_eq!(ms.split_once('.').unwrap().1.len(), 3, "{line}");
            assert!(ms.parse::<f64>().is_ok(), "{line}");
        }
    }

    /// JSON mode prints one compact object per line, with the three fields in this order.
    #[test]
    fn test_cmd_ping_json_lines() {
        let data = vec![1u8, 2, 3];
        let device = MockDevice::new(vec![Ok(data.clone()), Ok(data.clone())]);
        let mut out = Vec::new();
        cmd_ping(&device, 2, &data, true, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        for (line, index) in lines.iter().zip(1..) {
            assert!(
                line.starts_with(&format!("{{\"index\":{index},\"data_len\":3,\"duration_ms\":")),
                "{line}"
            );
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v["duration_ms"].is_f64(), "{line}");
        }
    }

    /// A failed write is a `SoloError::Stdout`, so `main` can end quietly on a closed stdout.
    #[test]
    fn test_cmd_ping_write_error_is_stdout_error() {
        let device = MockDevice::new(vec![Ok(vec![9])]);
        let err = cmd_ping(&device, 1, &[9], false, FailingWriter).unwrap_err();
        assert!(matches!(err, SoloError::Stdout(_)), "unexpected error: {err}");
        let device = MockDevice::new(vec![Ok(vec![9])]);
        let err = cmd_ping(&device, 1, &[9], true, FailingWriter).unwrap_err();
        assert!(matches!(err, SoloError::Stdout(_)), "unexpected error: {err}");
    }

    #[test]
    fn test_cmd_key_version_text_and_json() {
        let device = MockDevice::new(vec![Ok(vec![2, 5, 3])]);
        let mut out = Vec::new();
        cmd_key_version(&device, false, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "Firmware version: 2.5.3\n");

        let device = MockDevice::new(vec![Ok(vec![2, 5, 3])]);
        let mut out = Vec::new();
        cmd_key_version(&device, true, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "{\n  \"firmware_version\": \"2.5.3\"\n}\n"
        );

        let device = MockDevice::new(vec![Ok(vec![2, 5, 3])]);
        let err = cmd_key_version(&device, true, FailingWriter).unwrap_err();
        assert!(matches!(err, SoloError::Stdout(_)), "unexpected error: {err}");
    }
}
