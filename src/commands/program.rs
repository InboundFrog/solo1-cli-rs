/// `program` subcommand: bootloader, DFU.
use std::path::Path;

use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

use crate::device::HidDevice;
use crate::dfu::DfuDevice;
use crate::error::{Result, SoloError};
use crate::firmware::{self, FirmwareJson};
use crate::solo1::bootloader;
use crate::vlog;

/// Write `firmware` to the device starting at `base_addr` with a progress bar,
/// then send `CMD_DONE` with `signature` so the bootloader verifies and reboots.
///
/// The device must already be in bootloader mode. `finalize_msg` is printed
/// between the write loop and `CMD_DONE` (callers use different wording).
///
/// # Errors
/// Returns an error if the progress-bar template is invalid, or if any
/// bootloader write or the final `CMD_DONE` command fails.
pub fn write_firmware(
    hid: &impl HidDevice,
    base_addr: u32,
    firmware: &[u8],
    signature: &[u8],
    finalize_msg: &str,
) -> Result<()> {
    let pb = ProgressBar::new(0);
    let style = ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} {msg}")
        .map_err(|e| SoloError::ProtocolError(format!("progress template: {e}")))?
        .progress_chars("##-");
    pb.set_style(style);

    bootloader::write_firmware_chunks(hid, base_addr, firmware, |done, total| {
        pb.set_length(u64::try_from(total).unwrap_or(u64::MAX));
        pb.set_position(u64::try_from(done).unwrap_or(u64::MAX));
    })?;
    pb.finish_with_message("written");

    println!("{finalize_msg}");
    bootloader::finish_firmware(hid, signature)?;
    Ok(())
}

/// Read the bootloader version, report it, and pick the matching signature.
///
/// # Errors
/// Returns an error if signature selection fails (a malformed version
/// constraint, or a signature that is not valid websafe base64).
pub fn select_signature(hid: &impl HidDevice, fw: &FirmwareJson) -> Result<Vec<u8>> {
    let version = firmware::read_bootloader_version(hid);
    match &version {
        Some(v) => println!("Bootloader version: {v}"),
        None => println!("Could not read bootloader version; using default signature."),
    }
    fw.signature_for_bootloader(version.as_ref())
}

/// Program via the Solo bootloader (firmware.json format).
/// The device must already be in bootloader mode when this is called.
///
/// # Errors
/// Returns an error if the firmware JSON cannot be loaded or parsed, if
/// selecting the signature fails, or if writing the firmware fails.
pub fn cmd_program_bootloader(hid: &impl HidDevice, firmware_json: &Path) -> Result<()> {
    vlog!("Loading firmware JSON: {:?}", firmware_json);
    let fw = FirmwareJson::from_file(firmware_json)?;
    let (flash_start, firmware_bytes) = fw.firmware_binary()?;

    println!("Firmware size: {} bytes", firmware_bytes.len());
    println!("Flash start:   0x{flash_start:08X}");
    vlog!("Firmware SHA256: {}", hex::encode(Sha256::digest(&firmware_bytes)));

    // Query bootloader version BEFORE writing to select the correct signature.
    // (The BootVersion command resets the internal has_erased flag; querying it
    // before writes avoids any state confusion and mirrors the Python tool's flow.)
    let signature = select_signature(hid, &fw)?;
    vlog!("Signature ({} bytes): {}", signature.len(), hex::encode(&signature));

    write_firmware(hid, flash_start, &firmware_bytes, &signature, "Finalizing firmware...")?;
    println!("Done.");
    Ok(())
}

/// Program via ST DFU (firmware.hex format).
///
/// # Errors
/// Returns an error if the HEX file cannot be parsed, if the DFU device cannot
/// be opened, or if DFU programming fails.
pub fn cmd_program_dfu(firmware_hex: &Path) -> Result<()> {
    use crate::firmware::parse_hex_file;

    println!("Parsing firmware HEX file: {}", firmware_hex.display());
    let (base_addr, firmware_bytes) = parse_hex_file(firmware_hex)?;
    println!(
        "Base address: 0x{:08X}, size: {} bytes",
        base_addr,
        firmware_bytes.len()
    );

    println!("Opening ST DFU device (VID=0x0483, PID=0xDF11)...");
    let mut dfu = DfuDevice::open()?;

    println!("Programming {} bytes via DFU...", firmware_bytes.len());
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} chunks")
            .map_err(|e| SoloError::FirmwareError(format!("Progress bar style error: {e}")))?
            .progress_chars("##-"),
    );
    dfu.program(&firmware_bytes, |done, total| {
        pb.set_length(u64::try_from(total).unwrap_or(u64::MAX));
        pb.set_position(u64::try_from(done).unwrap_or(u64::MAX));
    })?;
    pb.finish_with_message("Done");
    println!("DFU programming complete.");
    Ok(())
}
