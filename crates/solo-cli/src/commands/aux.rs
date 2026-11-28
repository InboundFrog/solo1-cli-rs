use crate::error::Result;
/// `program aux` subcommands: bootloader mode switching, reboot, DFU mode.
use solo_ctaphid::HidDevice;
use solo1::bootloader::{bootloader_cmd, build_bootloader_packet};
use solo1::dfu::DfuDevice;
use solo1::protocol::{CMD_BOOT, CMD_ENTER_BOOT, CMD_ENTER_DFU, CMD_ENTER_ST_BOOT, CMD_REBOOT, CMD_VERSION};

/// Enter bootloader mode (from firmware).
/// Sends command 0x51 directly, without the bootloader wrapper, because the
/// firmware handles it. The device reboots at once, so there is no reply to wait for.
///
/// # Errors
/// This function does not return an error; the send result is intentionally
/// ignored because the device reboots without replying.
pub fn cmd_enter_bootloader(hid: &impl HidDevice) -> Result<()> {
    let _ = hid.send(CMD_ENTER_BOOT, &[]);
    println!("Entering bootloader mode...");
    Ok(())
}

/// Leave bootloader mode (boot to firmware) by issuing a reboot from bootloader.
///
/// # Errors
/// This function does not return an error; the reboot command's result is
/// intentionally ignored because the device reboots without replying.
pub fn cmd_leave_bootloader(hid: &impl HidDevice) -> Result<()> {
    let _ = bootloader_cmd(hid, CMD_REBOOT, 0, &[]);
    println!("Booting to firmware...");
    Ok(())
}

/// Enter ST DFU mode.
///
/// Like the reference tool (`enter_st_dfu` in `solo/devices/solo_v1.py`), this first asks the
/// key for the bootloader version. If the key answers, it runs the Solo bootloader, and the
/// `CMD_ENTER_DFU` (0x46) operation is sent inside a `CMD_BOOT` packet. Otherwise it runs the
/// normal firmware, and `CMD_ENTER_ST_BOOT` (0x52) is sent. The value 0x46 is `st_dfu` in
/// `solo/commands.py` (line 29) of solokeys/solo1-cli and `BootBootloader` in
/// `targets/stm32l432/bootloader/bootloader.c` (line 39) of solokeys/solo at tag 4.1.5.
/// That firmware handles it only in development ("hacker") builds (`SOLO_HACKER`, line 292).
/// Nothing here was tried on a key.
///
/// A key that jumps to ST DFU does not reply, so the send does not wait for a reply. The text
/// is printed when the send worked. It does not show that the key entered ST DFU mode:
/// firmware 4.1.5 does not handle 0x52 (only `fido2/ctaphid.h` line 29 defines it; tags 1.1.0
/// and 2.0.0 handled it in hacker builds), and a release-build bootloader answers 0x46 with an
/// error status. Neither reply is read.
///
/// # Errors
/// Returns an error if the command cannot be sent to the device.
pub fn cmd_enter_dfu(hid: &impl HidDevice) -> Result<()> {
    match bootloader_cmd(hid, CMD_VERSION, 0, &[]) {
        Ok(_) => hid.send(CMD_BOOT, &build_bootloader_packet(CMD_ENTER_DFU, 0, &[])?)?,
        Err(e) => {
            log::debug!("bootloader version query failed, so the key runs normal firmware: {e}");
            hid.send(CMD_ENTER_ST_BOOT, &[])?;
        }
    }
    println!("Entering ST DFU mode...");
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
    println!("Leaving ST DFU mode...");
    DfuDevice::open()?.leave_dfu()?;
    println!("Please powercycle the device (pull out, plug in again)");
    Ok(())
}

/// Reboot the device.
///
/// # Errors
/// Returns an error if the reboot command cannot be sent to the device.
pub fn cmd_reboot(hid: &impl HidDevice) -> Result<()> {
    bootloader_cmd(hid, CMD_REBOOT, 0, &[])?;
    println!("Rebooting device...");
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
    println!("Bootloader version: {version_str}");
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
    // cmd_leave_dfu, cmd_reboot) only pass one command to the HID layer.
    // There is nothing to test without a real device.

    use std::cell::RefCell;

    /// Records every `send`. `send_recv` answers the version query with `version`.
    struct Recorder {
        version: Option<Vec<u8>>,
        send_fails: bool,
        sent: RefCell<Vec<(u8, Vec<u8>)>>,
        queried: RefCell<Vec<(u8, Vec<u8>)>>,
    }

    impl HidDevice for Recorder {
        fn send_recv(&self, cmd: u8, data: &[u8]) -> solo_ctaphid::Result<Vec<u8>> {
            self.queried.borrow_mut().push((cmd, data.to_vec()));
            // A 4.1.5 firmware key answers the query with CTAPHID error 01 (invalid command).
            self.version
                .clone()
                .ok_or_else(|| solo_ctaphid::Error::Protocol("CTAPHID error: 01".into()))
        }

        fn send(&self, cmd: u8, data: &[u8]) -> solo_ctaphid::Result<()> {
            self.sent.borrow_mut().push((cmd, data.to_vec()));
            if self.send_fails {
                Err(solo_ctaphid::Error::Device("send failed".into()))
            } else {
                Ok(())
            }
        }
    }

    fn recorder(bootloader: bool, send_fails: bool) -> Recorder {
        Recorder {
            version: bootloader.then(|| vec![0, 2, 5, 3]),
            send_fails,
            sent: RefCell::new(Vec::new()),
            queried: RefCell::new(Vec::new()),
        }
    }

    #[test]
    fn enter_dfu_send_failure_is_returned() {
        assert!(cmd_enter_dfu(&recorder(false, true)).is_err());
        assert!(cmd_enter_dfu(&recorder(true, true)).is_err());
    }

    #[test]
    fn enter_dfu_normal_mode_sends_0x52() {
        let dev = recorder(false, false);
        cmd_enter_dfu(&dev).unwrap();
        assert_eq!(
            *dev.queried.borrow(),
            vec![(CMD_BOOT, build_bootloader_packet(CMD_VERSION, 0, &[]).unwrap())]
        );
        assert_eq!(*dev.sent.borrow(), vec![(CMD_ENTER_ST_BOOT, vec![])]);
    }

    #[test]
    fn enter_dfu_bootloader_mode_sends_0x46_inside_boot_packet() {
        let dev = recorder(true, false);
        cmd_enter_dfu(&dev).unwrap();
        assert_eq!(
            *dev.queried.borrow(),
            vec![(CMD_BOOT, build_bootloader_packet(CMD_VERSION, 0, &[]).unwrap())]
        );
        let packet = build_bootloader_packet(CMD_ENTER_DFU, 0, &[]).unwrap();
        assert_eq!(*dev.sent.borrow(), vec![(CMD_BOOT, packet)]);
    }

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
