use crate::error::Result;
/// `program aux` subcommands: bootloader mode switching, reboot, DFU mode.
use solo_ctaphid::HidDevice;
use solo1::bootloader::bootloader_cmd;
use solo1::dfu::DfuDevice;
use solo1::protocol::{CMD_ENTER_BOOT, CMD_ENTER_ST_BOOT, CMD_REBOOT, CMD_VERSION};

/// Enter bootloader mode (from firmware).
/// Sends command 0x51 directly, without the bootloader wrapper, because the
/// firmware handles it. The device reboots at once, so there is no reply to wait for.
///
/// # Errors
/// This function does not return an error; the send result is intentionally
/// ignored because the device reboots without replying.
pub fn cmd_enter_bootloader(hid: &impl HidDevice) -> Result<()> {
    let _ = hid.send(CMD_ENTER_BOOT, &[]);
    outln!("Entering bootloader mode...");
    Ok(())
}

/// Leave bootloader mode (boot to firmware) by issuing a reboot from bootloader.
///
/// # Errors
/// This function does not return an error; the reboot command's result is
/// intentionally ignored because the device reboots without replying.
pub fn cmd_leave_bootloader(hid: &impl HidDevice) -> Result<()> {
    let _ = bootloader_cmd(hid, CMD_REBOOT, 0, &[]);
    outln!("Booting to firmware...");
    Ok(())
}

/// Enter ST DFU mode (from firmware).
/// Sends command 0x52 directly, because the firmware handles it. The device then reboots.
///
/// # Errors
/// This function does not return an error; the send result is intentionally
/// ignored because the device reboots without replying.
pub fn cmd_enter_dfu(hid: &impl HidDevice) -> Result<()> {
    let _ = hid.send(CMD_ENTER_ST_BOOT, &[]);
    outln!("Entering ST DFU mode...");
    Ok(())
}

/// Leave ST DFU mode. Finds the ST DFU device over USB (it is not a HID
/// device), sets the boot options and detaches, as the reference tool does.
/// The options only take effect after a power cycle.
///
/// # Errors
/// Returns an error if no ST DFU device is found, or reading the option bytes
/// or the DFU transfers fail.
pub fn cmd_leave_dfu() -> Result<()> {
    outln!("Leaving ST DFU mode...");
    DfuDevice::open()?.leave_dfu()?;
    outln!("Please powercycle the device (pull out, plug in again)");
    Ok(())
}

/// Reboot the device.
///
/// # Errors
/// Returns an error if the reboot command cannot be sent to the device.
pub fn cmd_reboot(hid: &impl HidDevice) -> Result<()> {
    bootloader_cmd(hid, CMD_REBOOT, 0, &[])?;
    outln!("Rebooting device...");
    Ok(())
}

/// Get bootloader version string.
///
/// # Errors
/// Returns an error if the version query cannot be sent or the bootloader
/// returns an error status.
pub fn cmd_bootloader_version(hid: &impl HidDevice) -> Result<()> {
    let response = bootloader_cmd(hid, CMD_VERSION, 0, &[])?;
    let version_str = format_bootloader_version(&response);
    outln!("Bootloader version: {version_str}");
    Ok(())
}

/// Format raw version response bytes into a human-readable version string.
///
/// With at least 3 bytes, the result is "major.minor.patch". Otherwise it is
/// the raw bytes as hex.
#[must_use]
pub fn format_bootloader_version(response: &[u8]) -> String {
    if let [major, minor, patch, ..] = response {
        format!("{major}.{minor}.{patch}")
    } else {
        hex::encode(response)
    }
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

    // The other aux functions (cmd_enter_bootloader, cmd_leave_bootloader,
    // cmd_enter_dfu, cmd_leave_dfu, cmd_reboot) only pass one command to the
    // HID layer. There is nothing to test without a real device.

    #[test]
    fn test_format_bootloader_version_three_bytes() {
        let response = vec![2u8, 5, 3];
        assert_eq!(format_bootloader_version(&response), "2.5.3");
    }

    #[test]
    fn test_format_bootloader_version_three_bytes_new() {
        // Bootloader version just above the 2.5.3 boundary
        let response = vec![2u8, 5, 4];
        assert_eq!(format_bootloader_version(&response), "2.5.4");
    }

    #[test]
    fn test_format_bootloader_version_zero_fields() {
        let response = vec![0u8, 0, 0];
        assert_eq!(format_bootloader_version(&response), "0.0.0");
    }

    #[test]
    fn test_format_bootloader_version_large_values() {
        // Byte values are u8, so max per field is 255
        let response = vec![255u8, 255, 255];
        assert_eq!(format_bootloader_version(&response), "255.255.255");
    }

    #[test]
    fn test_format_bootloader_version_extra_bytes_ignored() {
        // Extra bytes beyond the first three must be silently ignored
        let response = vec![3u8, 1, 0, 99, 42];
        assert_eq!(format_bootloader_version(&response), "3.1.0");
    }

    #[test]
    fn test_format_bootloader_version_two_bytes_falls_back_to_hex() {
        let response = vec![0x02u8, 0x05];
        assert_eq!(format_bootloader_version(&response), "0205");
    }

    #[test]
    fn test_format_bootloader_version_one_byte_falls_back_to_hex() {
        let response = vec![0xABu8];
        assert_eq!(format_bootloader_version(&response), "ab");
    }

    #[test]
    fn test_format_bootloader_version_empty_falls_back_to_hex() {
        let response: Vec<u8> = vec![];
        assert_eq!(format_bootloader_version(&response), "");
    }
}
