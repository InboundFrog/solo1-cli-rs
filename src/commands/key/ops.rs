use std::time::Instant;

use crate::commands::key::common;
use crate::device::{SoloHid, CMD_GET_VERSION, CTAPHID_CBOR, CTAPHID_PING, CTAPHID_WINK};
use crate::error::{Result, SoloError};
use crate::firmware::FirmwareVersion;

/// Get firmware version from the device.
pub fn cmd_key_version(hid: &SoloHid) -> Result<FirmwareVersion> {
    get_device_version(hid)
}

pub(super) fn get_device_version(hid: &SoloHid) -> Result<FirmwareVersion> {
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
pub fn cmd_wink(hid: &SoloHid) -> Result<()> {
    hid.send_recv(CTAPHID_WINK, &[])?;
    println!("Winked!");
    Ok(())
}

/// Send ping(s) and measure round-trip time.
pub fn cmd_ping(hid: &SoloHid, count: u32, data: &[u8]) -> Result<()> {
    for i in 0..count {
        let start = Instant::now();
        let response = hid.send_recv(CTAPHID_PING, data)?;
        let elapsed = start.elapsed();

        if response != data {
            return Err(SoloError::DeviceError("Ping response data mismatch".into()));
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
pub fn cmd_keyboard(hid: &SoloHid, data: &[u8]) -> Result<()> {
    if data.len() > 64 {
        return Err(SoloError::DeviceError(
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
pub fn cmd_reset(hid: &SoloHid) -> Result<()> {
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
pub fn cmd_disable_updates(hid: &SoloHid) -> Result<()> {
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
