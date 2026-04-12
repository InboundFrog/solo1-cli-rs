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
    let version_str = if response.len() >= 3 {
        format!("{}.{}.{}", response[0], response[1], response[2])
    } else {
        hex::encode(&response)
    };
    println!("Bootloader version: {}", version_str);
    Ok(())
}
