//! Solo 1 bootloader command packets, sent over CTAPHID as `CMD_BOOT`.

use crate::error::{Error, Result};
use crate::protocol::{CMD_BOOT, CMD_DONE, CMD_WRITE, SOLO_TAG};
use solo_ctaphid::HidDevice;

/// Build a bootloader command packet.
/// Address is encoded little-endian (lower 24 bits); firmware ORs 0x08000000 back in.
///
/// # Errors
/// Returns an error if `data` is longer than the 16-bit big-endian length
/// field can express (65535 bytes), which would otherwise be silently
/// truncated.
pub fn build_bootloader_packet(cmd: u8, addr: u32, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > usize::from(u16::MAX) {
        return Err(Error::Protocol(format!(
            "Bootloader packet data too large: {} bytes (max {})",
            data.len(),
            u16::MAX
        )));
    }
    let capacity = 10usize
        .checked_add(data.len())
        .ok_or_else(|| Error::Protocol("bootloader packet capacity overflow".into()))?;
    let mut packet = Vec::with_capacity(capacity);
    packet.push(cmd);
    let [addr0, addr1, addr2, _] = addr.to_le_bytes();
    packet.push(addr0);
    packet.push(addr1);
    packet.push(addr2);
    packet.extend_from_slice(&SOLO_TAG);
    let len = u16::try_from(data.len()).map_err(|_| Error::Protocol("bootloader packet length exceeds u16".into()))?;
    let [len_hi, len_lo] = len.to_be_bytes();
    packet.push(len_hi);
    packet.push(len_lo);
    packet.extend_from_slice(data);
    Ok(packet)
}

/// Send a bootloader command and return the response payload.
///
/// Packet format: [cmd(1)] [addr(3) LE] [TAG(4)] [`length_be(2)`] [data]
///
/// The bootloader responds with [status(1)] [payload...]. This function checks
/// the status byte and strips it, returning only the payload on success.
///
/// # Errors
/// Returns an error if the packet cannot be built (data too long), the
/// command cannot be sent or received (device/transport error or timeout),
/// or the bootloader returns a non-zero status.
pub fn bootloader_cmd(hid: &impl HidDevice, cmd: u8, addr: u32, data: &[u8]) -> Result<Vec<u8>> {
    log::debug!(
        "bootloader cmd=0x{:02X} addr=0x{:08X} data_len={}",
        cmd,
        addr,
        data.len()
    );
    let packet = build_bootloader_packet(cmd, addr, data)?;

    let resp = hid.send_recv(CMD_BOOT, &packet)?;

    // First byte of bootloader response is a status code (0x00 = success)
    let Some((&status, payload)) = resp.split_first() else {
        return Ok(resp);
    };
    if status != 0x00 {
        return Err(Error::Protocol(format!("Bootloader error status: 0x{status:02X}")));
    }
    Ok(payload.to_vec())
}

/// Size of each flash write sent to the bootloader.
pub const CHUNK_SIZE: usize = 256;

/// Flash-address stride between consecutive chunks, as a `u32`.
///
/// Kept as a dedicated `u32` constant (rather than casting `CHUNK_SIZE`) so
/// address arithmetic needs no `usize -> u32` conversion. Must equal
/// `CHUNK_SIZE`; the assertion below enforces that at compile time.
const CHUNK_STRIDE: u32 = 256;
const _: () = assert!(CHUNK_STRIDE == 256 && CHUNK_SIZE == 256);

/// Write `firmware` to flash in [`CHUNK_SIZE`] chunks starting at `base_addr`.
///
/// The device must already be in bootloader mode. After each chunk,
/// `on_progress(bytes_written, total_bytes)` is called. Follow with
/// [`finish_firmware`] to have the bootloader verify the image.
///
/// # Errors
/// Returns an error if chunk offsets overflow, or any bootloader write fails.
pub fn write_firmware_chunks(
    hid: &impl HidDevice,
    base_addr: u32,
    firmware: &[u8],
    mut on_progress: impl FnMut(usize, usize),
) -> Result<()> {
    log::debug!(
        "Writing {} chunks of {} bytes starting at 0x{:08X}",
        firmware_chunk_count(firmware.len()),
        CHUNK_SIZE,
        base_addr
    );

    let mut offset = 0usize;
    for (chunk_num, (addr, len)) in compute_chunk_addresses(base_addr, firmware.len())
        .into_iter()
        .enumerate()
    {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| Error::Protocol("chunk offset overflow".into()))?;
        let chunk = firmware
            .get(offset..end)
            .ok_or_else(|| Error::Protocol("chunk out of range".into()))?;
        log::debug!("chunk #{} addr=0x{:08X} len={}", chunk_num, addr, chunk.len());
        let resp = bootloader_cmd(hid, CMD_WRITE, addr, chunk)?;
        if !resp.is_empty() {
            log::debug!("  write response: {}", hex::encode(&resp));
        }
        offset = end;
        on_progress(offset, firmware.len());
    }
    Ok(())
}

/// Send `CMD_DONE` with the ECDSA `signature`; the bootloader verifies the
/// written image and reboots on success.
///
/// # Errors
/// Returns an error if the command fails or the bootloader rejects the
/// signature (non-zero status).
pub fn finish_firmware(hid: &impl HidDevice, signature: &[u8]) -> Result<()> {
    log::debug!("Sending CMD_DONE with {} byte signature", signature.len());
    let done_resp = bootloader_cmd(hid, CMD_DONE, 0, signature)?;
    log::debug!("done response: {}", hex::encode(&done_resp));
    Ok(())
}

/// Compute the number of 256-byte chunks needed to cover `firmware_len` bytes.
///
/// Used by [`write_firmware_chunks`] for the verbose chunk-count display.
#[must_use]
pub const fn firmware_chunk_count(firmware_len: usize) -> usize {
    firmware_len.div_ceil(CHUNK_SIZE)
}

/// Compute the address sequence for the firmware write loop.
///
/// Returns a `Vec` of `(flash_address, chunk_length)` pairs in the order
/// that the bootloader receives them. [`write_firmware_chunks`] iterates this
/// sequence directly, so the tests below exercise the shipped code path.
#[must_use]
pub fn compute_chunk_addresses(flash_start: u32, firmware_len: usize) -> Vec<(u32, usize)> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    let mut addr = flash_start;
    while offset < firmware_len {
        // `saturating_add` cannot change the result: it only differs from `+`
        // on overflow, and any overflowed value is >= `firmware_len`, so `.min`
        // clamps it back to `firmware_len` exactly as plain `+` would.
        let end = offset.saturating_add(CHUNK_SIZE).min(firmware_len);
        // `end > offset` on every iteration (loop guard + non-zero stride), so
        // `saturating_sub` yields the same value as `end - offset`.
        result.push((addr, end.saturating_sub(offset)));
        offset = end;
        addr = addr.saturating_add(CHUNK_STRIDE);
    }
    result
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
    use solo_ctaphid::mock::MockDevice;

    #[test]
    fn test_bootloader_packet() {
        // Address 0x08001000: firmware strips 0x08000000, leaving offset 0x001000.
        // Little-endian 3-byte encoding of 0x001000: [0x00, 0x10, 0x00]
        let pkt = build_bootloader_packet(0x40, 0x0800_1000, &[0xDE, 0xAD]).unwrap();
        assert_eq!(pkt[0], 0x40); // cmd
        assert_eq!(&pkt[1..4], &[0x00, 0x10, 0x00]); // addr little-endian (LSB first)
        assert_eq!(&pkt[4..8], &SOLO_TAG); // tag
        assert_eq!(pkt[8], 0x00); // len high
        assert_eq!(pkt[9], 0x02); // len low
        assert_eq!(&pkt[10..12], &[0xDE, 0xAD]); // data

        // Address where byte order matters: 0x08010000 → offset 0x010000
        // Little-endian: [0x00, 0x00, 0x01]  (NOT [0x01, 0x00, 0x00])
        let pkt2 = build_bootloader_packet(0x40, 0x0801_0000, &[]).unwrap();
        assert_eq!(&pkt2[1..4], &[0x00, 0x00, 0x01]);

        // 0x08012345 → offset 0x012345 → LE: [0x45, 0x23, 0x01]
        let pkt3 = build_bootloader_packet(0x40, 0x0801_2345, &[]).unwrap();
        assert_eq!(&pkt3[1..4], &[0x45, 0x23, 0x01]);
    }

    #[test]
    fn test_bootloader_packet_max_data_ok() {
        let data = vec![0xA5; u16::MAX as usize];
        let pkt = build_bootloader_packet(0x40, 0x0800_0000, &data).unwrap();
        assert_eq!(pkt[8], 0xFF); // len high
        assert_eq!(pkt[9], 0xFF); // len low
        assert_eq!(pkt.len(), 10 + u16::MAX as usize);
    }

    #[test]
    fn test_bootloader_packet_oversized_data_err() {
        let data = vec![0xA5; u16::MAX as usize + 1];
        let err = build_bootloader_packet(0x40, 0x0800_0000, &data).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    /// A zero status byte is stripped and the rest is returned.
    #[test]
    fn test_bootloader_cmd_strips_ok_status() {
        let device = MockDevice::new(vec![Ok(vec![0x00, 2, 5, 3])]);
        let payload = bootloader_cmd(&device, 0x44, 0, &[]).unwrap();
        assert_eq!(payload, vec![2, 5, 3]);
    }

    /// A non-zero status byte becomes a `ProtocolError`.
    #[test]
    fn test_bootloader_cmd_error_status() {
        let device = MockDevice::new(vec![Ok(vec![0x0A])]);
        let err = bootloader_cmd(&device, 0x44, 0, &[]).unwrap_err();
        assert!(matches!(err, Error::Protocol(m) if m.contains("0x0A")));
    }

    /// An empty response is passed through unchanged.
    #[test]
    fn test_bootloader_cmd_empty_response() {
        let device = MockDevice::new(vec![Ok(vec![])]);
        assert_eq!(bootloader_cmd(&device, 0x45, 0, &[]).unwrap(), [] as [u8; 0]);
    }

    /// Transport errors propagate.
    #[test]
    fn test_bootloader_cmd_timeout() {
        let device = MockDevice::new(vec![]);
        let err = bootloader_cmd(&device, 0x44, 0, &[]).unwrap_err();
        assert!(matches!(err, Error::Transport(solo_ctaphid::Error::Timeout)));
    }

    // compute_chunk_addresses is the sequence write_firmware_chunks iterates,
    // so these tests exercise the exact addresses sent to the bootloader.

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
        let start: u32 = 0x0800_5000;
        let chunks = compute_chunk_addresses(start, 512);
        assert_eq!(chunks.len(), 2);
        // First chunk: starts at flash_start, full 256 bytes
        assert_eq!(chunks[0], (0x0800_5000, 256));
        // Second chunk: address advances by 256, full 256 bytes
        assert_eq!(chunks[1], (0x0800_5100, 256));
    }

    #[test]
    fn test_addresses_partial_last_chunk() {
        // 300-byte firmware: first chunk full (256), second chunk partial (44)
        let start: u32 = 0x0800_5000;
        let chunks = compute_chunk_addresses(start, 300);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], (0x0800_5000, 256));
        // Address still advances by the full CHUNK_SIZE (256), not by 44
        assert_eq!(chunks[1], (0x0800_5100, 44));
    }

    #[test]
    fn test_addresses_single_byte_firmware() {
        // One byte of firmware → one chunk of length 1 at flash_start
        let start: u32 = 0x0800_5000;
        let chunks = compute_chunk_addresses(start, 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], (0x0800_5000, 1));
    }

    #[test]
    fn test_addresses_empty_firmware() {
        // No bytes → no chunks → write loop never executes
        let chunks = compute_chunk_addresses(0x0800_5000, 0);
        assert_eq!(chunks, [] as [(u32, usize); 0]);
    }

    #[test]
    fn test_addresses_stride_is_always_256() {
        // Regardless of how many bytes the last chunk contains, the address
        // stride must always be 256 to match the bootloader's expectation.
        let start: u32 = 0x0800_0000;
        let chunks = compute_chunk_addresses(start, 600); // 256+256+88
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].0, 0x0800_0000);
        assert_eq!(chunks[1].0, 0x0800_0100); // +256
        assert_eq!(chunks[2].0, 0x0800_0200); // +256 again, even though chunk 2 was partial
        assert_eq!(chunks[2].1, 88);
    }

    #[test]
    fn test_addresses_coverage_sums_to_firmware_len() {
        // All chunk lengths must add up to the total firmware length.
        let firmware_len = 1000;
        let chunks = compute_chunk_addresses(0x0800_5000, firmware_len);
        let total: usize = chunks.iter().map(|(_, len)| len).sum();
        assert_eq!(total, firmware_len);
    }
}
