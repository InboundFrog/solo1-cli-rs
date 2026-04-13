use std::path::Path;

use crate::device::SoloHid;
use crate::error::{Result, SoloError};
use crate::firmware::FirmwareVersion;
use crate::vlog;

/// Update the device firmware.
pub fn cmd_update(hid: &SoloHid, firmware_file: Option<&Path>) -> Result<()> {
    use crate::crypto::sha256_hex;
    use crate::device::{CMD_DONE, CMD_ENTER_BOOT, CMD_VERSION, CMD_WRITE};
    use crate::firmware::{download_url, fetch_latest_release, FirmwareJson};
    use indicatif::{ProgressBar, ProgressStyle};

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
    let bl_hid = SoloHid::open_bootloader(None)?;

    // Query bootloader version to select the correct signature.
    // If CMD_VERSION fails, use the default (latest) signature directly rather than
    // falling back to version 0.0.0 which would incorrectly match "<=2.5.3".
    let signature = match bl_hid.send_bootloader_cmd(CMD_VERSION, 0, &[]) {
        Ok(resp) if resp.len() >= 3 => {
            let v = FirmwareVersion::new(resp[0] as u32, resp[1] as u32, resp[2] as u32);
            println!("Bootloader version: {}", v);
            fw_json.signature_for_version(&v)?
        }
        Ok(resp) if !resp.is_empty() => {
            let v = FirmwareVersion::new(0, 0, resp[0] as u32);
            println!("Bootloader version: {}", v);
            fw_json.signature_for_version(&v)?
        }
        _ => {
            println!("Could not read bootloader version; using default signature.");
            fw_json.signature_bytes()?
        }
    };
    vlog!(
        "Using signature ({} bytes): {}",
        signature.len(),
        hex::encode(&signature)
    );

    // Write firmware in 256-byte chunks
    const CHUNK_SIZE: usize = 256;

    let pb = ProgressBar::new(firmware_bytes.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes}")
            .unwrap()
            .progress_chars("##-"),
    );

    let mut offset = 0usize;
    let mut addr = flash_start;
    while offset < firmware_bytes.len() {
        let end = (offset + CHUNK_SIZE).min(firmware_bytes.len());
        let chunk = &firmware_bytes[offset..end];
        bl_hid.send_bootloader_cmd(CMD_WRITE, addr, chunk)?;
        pb.inc(chunk.len() as u64);
        offset = end;
        addr += CHUNK_SIZE as u32;
    }
    pb.finish_with_message("Written");

    // CMD_DONE sends the ECDSA signature; bootloader verifies it and reboots on success
    println!("Verifying and finalizing...");
    bl_hid.send_bootloader_cmd(CMD_DONE, 0, &signature)?;

    println!("Firmware update complete!");
    Ok(())
}
