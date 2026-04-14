/// `program` subcommand: bootloader, DFU.
use std::path::Path;

use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

use crate::device::{HidDevice, CMD_DONE, CMD_WRITE};
use crate::dfu::DfuDevice;
use crate::error::Result;
use crate::firmware::{self, FirmwareJson};
use crate::vlog;

/// Program via the Solo bootloader (firmware.json format).
/// The device must already be in bootloader mode when this is called.
pub fn cmd_program_bootloader(hid: &impl HidDevice, firmware_json: &Path) -> Result<()> {
    vlog!("Loading firmware JSON: {:?}", firmware_json);
    let fw = FirmwareJson::from_file(firmware_json)?;
    let (flash_start, firmware_bytes) = fw.firmware_binary()?;

    println!("Firmware size: {} bytes", firmware_bytes.len());
    println!("Flash start:   0x{:08X}", flash_start);
    vlog!(
        "Firmware SHA256: {}",
        hex::encode(Sha256::digest(&firmware_bytes))
    );

    // Query bootloader version BEFORE writing to select the correct signature.
    // (The BootVersion command resets the internal has_erased flag; querying it
    // before writes avoids any state confusion and mirrors the Python tool's flow.)
    let signature = firmware::select_signature(hid, &fw)?;
    vlog!(
        "Signature ({} bytes): {}",
        signature.len(),
        hex::encode(&signature)
    );

    const CHUNK_SIZE: usize = 256;

    vlog!(
        "Writing {} chunks of {} bytes starting at 0x{:08X}",
        (firmware_bytes.len() + CHUNK_SIZE - 1) / CHUNK_SIZE,
        CHUNK_SIZE,
        flash_start
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
    let mut addr = flash_start;
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

    // CMD_DONE sends the ECDSA signature; bootloader verifies and reboots on success
    println!("Finalizing firmware...");
    vlog!("Sending CMD_DONE with {} byte signature", signature.len());
    let done_resp = hid.send_bootloader_cmd(CMD_DONE, 0, &signature)?;
    vlog!("done response: {}", hex::encode(&done_resp));
    println!("Done.");
    Ok(())
}

/// Compute the number of 256-byte chunks needed to cover `firmware_len` bytes.
///
/// This mirrors the chunk-count calculation used in `cmd_program_bootloader`
/// for the progress display and loop termination.
pub fn firmware_chunk_count(firmware_len: usize) -> usize {
    const CHUNK_SIZE: usize = 256;
    (firmware_len + CHUNK_SIZE - 1) / CHUNK_SIZE
}

/// Simulate the address sequence produced by the write loop in
/// `cmd_program_bootloader` without touching any device.
///
/// Returns a `Vec` of `(flash_address, chunk_length)` pairs in the order
/// that the bootloader would receive them.
pub fn compute_chunk_addresses(flash_start: u32, firmware_len: usize) -> Vec<(u32, usize)> {
    const CHUNK_SIZE: usize = 256;
    let mut result = Vec::new();
    let mut offset = 0usize;
    let mut addr = flash_start;
    while offset < firmware_len {
        let end = (offset + CHUNK_SIZE).min(firmware_len);
        result.push((addr, end - offset));
        offset = end;
        addr += CHUNK_SIZE as u32;
    }
    result
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

#[cfg(test)]
mod tests {
    use super::*;

    // cmd_program_bootloader and cmd_program_dfu require a live device or DFU
    // interface and cannot be unit-tested. The logic they contain has been
    // extracted into firmware_chunk_count and compute_chunk_addresses so it
    // can be tested here without hardware.

    // ── firmware_chunk_count ─────────────────────────────────────────────────

    #[test]
    fn test_chunk_count_exact_multiple() {
        // 512 bytes = exactly 2 full chunks of 256
        assert_eq!(firmware_chunk_count(512), 2);
    }

    #[test]
    fn test_chunk_count_partial_last_chunk() {
        // 257 bytes = one full chunk + one 1-byte chunk
        assert_eq!(firmware_chunk_count(257), 2);
        // 300 bytes = one full chunk + one 44-byte chunk
        assert_eq!(firmware_chunk_count(300), 2);
        // 511 bytes = one full chunk + one 255-byte chunk
        assert_eq!(firmware_chunk_count(511), 2);
    }

    #[test]
    fn test_chunk_count_single_chunk() {
        assert_eq!(firmware_chunk_count(1), 1);
        assert_eq!(firmware_chunk_count(128), 1);
        assert_eq!(firmware_chunk_count(256), 1);
    }

    #[test]
    fn test_chunk_count_zero() {
        // Empty firmware → zero chunks, matching the write-loop guard
        assert_eq!(firmware_chunk_count(0), 0);
    }

    #[test]
    fn test_chunk_count_large() {
        // 200 KiB = 204800 bytes = 800 chunks of 256
        assert_eq!(firmware_chunk_count(200 * 1024), 800);
    }

    // ── compute_chunk_addresses ──────────────────────────────────────────────

    #[test]
    fn test_addresses_exact_two_chunks() {
        let start: u32 = 0x08005000;
        let chunks = compute_chunk_addresses(start, 512);
        assert_eq!(chunks.len(), 2);
        // First chunk: starts at flash_start, full 256 bytes
        assert_eq!(chunks[0], (0x08005000, 256));
        // Second chunk: address advances by 256, full 256 bytes
        assert_eq!(chunks[1], (0x08005100, 256));
    }

    #[test]
    fn test_addresses_partial_last_chunk() {
        // 300-byte firmware: first chunk full (256), second chunk partial (44)
        let start: u32 = 0x08005000;
        let chunks = compute_chunk_addresses(start, 300);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], (0x08005000, 256));
        // Address still advances by the full CHUNK_SIZE (256), not by 44
        assert_eq!(chunks[1], (0x08005100, 44));
    }

    #[test]
    fn test_addresses_single_byte_firmware() {
        // One byte of firmware → one chunk of length 1 at flash_start
        let start: u32 = 0x08005000;
        let chunks = compute_chunk_addresses(start, 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], (0x08005000, 1));
    }

    #[test]
    fn test_addresses_empty_firmware() {
        // No bytes → no chunks → write loop never executes
        let chunks = compute_chunk_addresses(0x08005000, 0);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_addresses_stride_is_always_256() {
        // Regardless of how many bytes the last chunk contains, the address
        // stride must always be 256 to match the bootloader's expectation.
        let start: u32 = 0x08000000;
        let chunks = compute_chunk_addresses(start, 600); // 256+256+88
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].0, 0x08000000);
        assert_eq!(chunks[1].0, 0x08000100); // +256
        assert_eq!(chunks[2].0, 0x08000200); // +256 again, even though chunk 2 was partial
        assert_eq!(chunks[2].1, 88);
    }

    #[test]
    fn test_addresses_coverage_sums_to_firmware_len() {
        // All chunk lengths must add up to the total firmware length.
        let firmware_len = 1000;
        let chunks = compute_chunk_addresses(0x08005000, firmware_len);
        let total: usize = chunks.iter().map(|(_, len)| len).sum();
        assert_eq!(total, firmware_len);
    }
}
