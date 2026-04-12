/// `program` subcommand: bootloader, DFU.
use std::path::Path;

use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

use crate::device::{SoloHid, CMD_CHECK, CMD_DONE, CMD_VERSION, CMD_WRITE};
use crate::dfu::DfuDevice;
use crate::error::Result;
use crate::firmware::{FirmwareJson, FirmwareVersion};
use crate::vlog;

/// Program via the Solo bootloader (firmware.json format).
/// The device must already be in bootloader mode when this is called.
pub fn cmd_program_bootloader(hid: &SoloHid, firmware_json: &Path) -> Result<()> {
    vlog!("Loading firmware JSON: {:?}", firmware_json);
    let fw = FirmwareJson::from_file(firmware_json)?;
    let firmware_bytes = fw.firmware_bytes()?;

    println!("Firmware size: {} bytes", firmware_bytes.len());
    vlog!(
        "Firmware SHA256: {}",
        hex::encode(Sha256::digest(&firmware_bytes))
    );

    const CHUNK_SIZE: usize = 256;
    const FLASH_START: u32 = 0x08005000; // Skip bootloader

    vlog!(
        "Writing {} chunks of {} bytes starting at 0x{:08X}",
        (firmware_bytes.len() + CHUNK_SIZE - 1) / CHUNK_SIZE,
        CHUNK_SIZE,
        FLASH_START
    );

    let total = firmware_bytes.len();
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );

    let mut offset = 0usize;
    let mut addr = FLASH_START;
    let mut chunk_num = 0u32;

    while offset < firmware_bytes.len() {
        let end = (offset + CHUNK_SIZE).min(firmware_bytes.len());
        let chunk = &firmware_bytes[offset..end];
        vlog!(
            "chunk #{} addr=0x{:08X} len={}",
            chunk_num,
            addr,
            chunk.len()
        );
        let resp = hid.send_bootloader_cmd(CMD_WRITE, addr, chunk)?;
        if !resp.is_empty() {
            vlog!("  write response: {}", hex::encode(&resp));
        }
        pb.inc(chunk.len() as u64);
        offset = end;
        addr += CHUNK_SIZE as u32;
        chunk_num += 1;
    }
    pb.finish_with_message("written");

    // Query bootloader version to select the correct signature
    let version = match hid.send_bootloader_cmd(CMD_VERSION, 0, &[]) {
        Ok(resp) if resp.len() >= 3 => {
            FirmwareVersion::new(resp[0] as u32, resp[1] as u32, resp[2] as u32)
        }
        Ok(resp) if !resp.is_empty() => FirmwareVersion::new(0, 0, resp[0] as u32),
        _ => FirmwareVersion::new(0, 0, 0),
    };
    vlog!("Bootloader version: {}", version);

    let signature = fw.signature_for_version(&version)?;
    vlog!("Signature ({} bytes): {}", signature.len(), hex::encode(&signature));

    vlog!("Sending CMD_CHECK (liveness probe)");
    let check_resp = hid.send_bootloader_cmd(CMD_CHECK, 0, &[])?;
    vlog!("check response: {}", hex::encode(&check_resp));

    // CMD_DONE sends the ECDSA signature; bootloader verifies and reboots on success
    println!("Finalizing firmware...");
    vlog!("Sending CMD_DONE with {} byte signature", signature.len());
    let done_resp = hid.send_bootloader_cmd(CMD_DONE, 0, &signature)?;
    vlog!("done response: {}", hex::encode(&done_resp));
    println!("Done.");
    Ok(())
}

/// Program via ST DFU (firmware.hex format).
pub fn cmd_program_dfu(firmware_hex: &Path) -> Result<()> {
    use crate::firmware::parse_hex_file;

    println!("Parsing firmware HEX file: {:?}", firmware_hex);
    let (base_addr, firmware_bytes) = parse_hex_file(firmware_hex)?;
    println!(
        "Base address: 0x{:08X}, size: {} bytes",
        base_addr,
        firmware_bytes.len()
    );

    println!("Opening ST DFU device (VID=0x0483, PID=0xDF11)...");
    let mut dfu = DfuDevice::open()?;

    println!("Programming {} bytes via DFU...", firmware_bytes.len());
    dfu.program(&firmware_bytes)?;
    println!("DFU programming complete.");
    Ok(())
}
