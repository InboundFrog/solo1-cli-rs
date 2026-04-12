/// `program` subcommand: bootloader, DFU.
use std::path::Path;

use indicatif::{ProgressBar, ProgressStyle};

use crate::device::{SoloHid, CMD_DONE, CMD_WRITE};
use crate::dfu::DfuDevice;
use crate::error::Result;
use crate::firmware::FirmwareJson;

/// Program via the Solo bootloader (firmware.json format).
pub fn cmd_program_bootloader(hid: &SoloHid, firmware_json: &Path) -> Result<()> {
    let fw = FirmwareJson::from_file(firmware_json)?;
    let firmware_bytes = fw.firmware_bytes()?;

    println!("Firmware size: {} bytes", firmware_bytes.len());

    const CHUNK_SIZE: usize = 256;
    const FLASH_START: u32 = 0x08005000; // Skip bootloader

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

    while offset < firmware_bytes.len() {
        let end = (offset + CHUNK_SIZE).min(firmware_bytes.len());
        let chunk = &firmware_bytes[offset..end];
        hid.send_bootloader_cmd(CMD_WRITE, addr, chunk)?;
        pb.inc(chunk.len() as u64);
        offset = end;
        addr += CHUNK_SIZE as u32;
    }
    pb.finish_with_message("written");

    println!("Finalizing firmware...");
    hid.send_bootloader_cmd(CMD_DONE, 0, &[])?;
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
