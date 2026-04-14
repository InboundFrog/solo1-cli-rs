/// `program aux` subcommands: bootloader mode switching, reboot, DFU mode.
use crate::device::{SoloHid, CMD_ENTER_BOOT, CMD_ENTER_ST_BOOT, CMD_REBOOT, CMD_VERSION};
use crate::error::Result;

/// Enter bootloader mode (from firmware).
/// Sends command 0x51 directly — no bootloader wrapper — as the firmware handles it.
/// The device reboots immediately so we don't wait for a response.
pub fn cmd_enter_bootloader(hid: &SoloHid) -> Result<()> {
    let _ = hid.send(CMD_ENTER_BOOT, &[]);
    println!("Entering bootloader mode...");
    Ok(())
}

/// Leave bootloader mode (boot to firmware) by issuing a reboot from bootloader.
pub fn cmd_leave_bootloader(hid: &SoloHid) -> Result<()> {
    let _ = hid.send_bootloader_cmd(CMD_REBOOT, 0, &[]);
    println!("Booting to firmware...");
    Ok(())
}

/// Enter ST DFU mode (from firmware).
/// Sends command 0x52 directly — the firmware handles it, device reboots.
pub fn cmd_enter_dfu(hid: &SoloHid) -> Result<()> {
    let _ = hid.send(CMD_ENTER_ST_BOOT, &[]);
    println!("Entering ST DFU mode...");
    Ok(())
}

/// Leave ST DFU mode (re-enter Solo bootloader) by issuing a reboot from bootloader.
pub fn cmd_leave_dfu(hid: &SoloHid) -> Result<()> {
    let _ = hid.send_bootloader_cmd(CMD_REBOOT, 0, &[]);
    println!("Leaving ST DFU mode...");
    Ok(())
}

/// Reboot the device.
pub fn cmd_reboot(hid: &SoloHid) -> Result<()> {
    hid.send_bootloader_cmd(CMD_REBOOT, 0, &[])?;
    println!("Rebooting device...");
    Ok(())
}

/// Get bootloader version string.
pub fn cmd_bootloader_version(hid: &SoloHid) -> Result<()> {
    let response = hid.send_bootloader_cmd(CMD_VERSION, 0, &[])?;
    let version_str = format_bootloader_version(&response);
    println!("Bootloader version: {}", version_str);
    Ok(())
}

/// Format raw version response bytes into a human-readable version string.
///
/// If the response contains at least 3 bytes, formats as "major.minor.patch".
/// Otherwise falls back to hex encoding of the raw bytes.
pub fn format_bootloader_version(response: &[u8]) -> String {
    if response.len() >= 3 {
        format!("{}.{}.{}", response[0], response[1], response[2])
    } else {
        hex::encode(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // All aux command functions (cmd_enter_bootloader, cmd_leave_bootloader,
    // cmd_enter_dfu, cmd_leave_dfu, cmd_reboot) are single-line device calls
    // with no logic beyond forwarding to the HID layer. There is nothing to
    // test without a real device.

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
