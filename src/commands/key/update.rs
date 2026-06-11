use std::path::Path;

use crate::device::{HidDevice, SoloHid};
use crate::error::{Result, SoloError};
use crate::firmware;
use crate::vlog;

/// Update the device firmware.
pub fn cmd_update(hid: &impl HidDevice, firmware_file: Option<&Path>) -> Result<()> {
    use crate::commands::program::write_firmware;
    use crate::crypto::sha256_hex;
    use crate::device::CMD_ENTER_BOOT;
    use crate::firmware::{download_url, fetch_latest_release, FirmwareJson};

    let fw_json = if let Some(path) = firmware_file {
        println!("Loading firmware from {:?}", path);
        FirmwareJson::from_file(path)?
    } else {
        println!("Fetching latest firmware from GitHub...");
        let release = fetch_latest_release()?;
        println!("Latest release: {}", release.tag_name);
        let asset = release
            .find_firmware_asset()
            .ok_or_else(|| SoloError::FirmwareError("No firmware JSON in release".into()))?;
        println!("Downloading: {}", asset.name);
        let bytes = download_url(&asset.browser_download_url)?;
        let json_str = String::from_utf8(bytes)
            .map_err(|e| SoloError::FirmwareError(format!("Firmware JSON UTF-8 error: {}", e)))?;
        serde_json::from_str(&json_str)?
    };

    let (flash_start, firmware_bytes) = fw_json.firmware_binary()?;
    println!("Firmware size: {} bytes", firmware_bytes.len());
    println!("Flash start:   0x{:08X}", flash_start);
    println!("Firmware SHA-256: {}", sha256_hex(&firmware_bytes));

    // Enter bootloader mode. CMD_ENTER_BOOT (0x51) is a direct firmware vendor command —
    // not wrapped in CMD_BOOT. Device reboots immediately so no response is expected.
    println!("Entering bootloader mode...");
    let _ = hid.send(CMD_ENTER_BOOT, &[]);

    // Delay for device to re-enumerate in bootloader mode
    std::thread::sleep(std::time::Duration::from_millis(1500));

    // Reconnect in bootloader mode
    println!("Reconnecting...");
    let bl_hid = SoloHid::open(None, std::time::Duration::from_secs(30))?;

    // Query bootloader version to select the correct signature.
    let signature = firmware::select_signature(&bl_hid, &fw_json)?;
    vlog!(
        "Using signature ({} bytes): {}",
        signature.len(),
        hex::encode(&signature)
    );

    // Write firmware in 256-byte chunks, then verify via CMD_DONE
    write_firmware(
        &bl_hid,
        flash_start,
        &firmware_bytes,
        &signature,
        "Verifying and finalizing...",
    )?;

    println!("Firmware update complete!");
    Ok(())
}
