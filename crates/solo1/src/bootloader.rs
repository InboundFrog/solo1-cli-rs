//! Solo 1 bootloader command packets, sent over CTAPHID as `CMD_BOOT`.

use crate::error::{Error, Result};
use crate::protocol::{CMD_BOOT, CMD_DONE, CMD_WRITE, SOLO_TAG};
use solo_ctaphid::HidDevice;

/// Build a bootloader command packet.
///
/// The packet holds the lower 24 bits of the address, little-endian. The
/// firmware adds 0x08000000 back.
///
/// # Errors
/// Returns an error if `data` is longer than 65535 bytes. The 16-bit
/// big-endian length field cannot hold more, and it would silently cut the
/// length.
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
/// The bootloader replies with [status(1)] [payload...]. This function checks
/// the status byte and removes it. On success it returns only the payload.
///
/// # Errors
/// Returns an error if the packet cannot be built (data too long), the
/// command cannot be sent or received (device or transport error, or
/// timeout), the reply is empty (no status byte), or the bootloader returns a
/// non-zero status.
pub fn bootloader_cmd(hid: &impl HidDevice, cmd: u8, addr: u32, data: &[u8]) -> Result<Vec<u8>> {
    log::debug!(
        "bootloader cmd=0x{:02X} addr=0x{:08X} data_len={}",
        cmd,
        addr,
        data.len()
    );
    let packet = build_bootloader_packet(cmd, addr, data)?;

    let resp = hid.send_recv(CMD_BOOT, &packet)?;

    // The first byte of the reply is the status code (0x00 means success).
    let Some((&status, payload)) = resp.split_first() else {
        return Err(Error::Protocol(format!(
            "Bootloader command 0x{cmd:02X} got an empty reply (no status byte)"
        )));
    };
    if status != 0x00 {
        return Err(Error::Protocol(format!("Bootloader error status: 0x{status:02X}")));
    }
    Ok(payload.to_vec())
}

/// Size of each flash write sent to the bootloader.
pub const CHUNK_SIZE: usize = 256;

/// Write `firmware` to flash in [`CHUNK_SIZE`] chunks starting at `base_addr`.
///
/// The device must already be in bootloader mode. After each chunk,
/// `on_progress(bytes_written, total_bytes)` is called. Follow with
/// [`finish_firmware`] to have the bootloader verify the image.
///
/// # Errors
/// Returns an error if the flash address overflows `u32`, or any bootloader
/// write fails.
pub fn write_firmware_chunks(
    hid: &impl HidDevice,
    base_addr: u32,
    firmware: &[u8],
    mut on_progress: impl FnMut(usize, usize),
) -> Result<()> {
    log::debug!(
        "Writing {} chunks of {} bytes starting at 0x{:08X}",
        firmware.len().div_ceil(CHUNK_SIZE),
        CHUNK_SIZE,
        base_addr
    );

    let mut addr = base_addr;
    let mut written = 0usize;
    for (chunk_num, chunk) in firmware.chunks(CHUNK_SIZE).enumerate() {
        log::debug!("chunk #{} addr=0x{:08X} len={}", chunk_num, addr, chunk.len());
        let resp = bootloader_cmd(hid, CMD_WRITE, addr, chunk)?;
        if !resp.is_empty() {
            log::debug!("  write response: {}", hex::encode(&resp));
        }
        let len = u32::try_from(chunk.len()).map_err(|_| Error::Protocol("chunk length overflow".into()))?;
        addr = addr
            .checked_add(len)
            .ok_or_else(|| Error::Protocol("flash address overflow".into()))?;
        written = written
            .checked_add(chunk.len())
            .ok_or_else(|| Error::Protocol("chunk offset overflow".into()))?;
        on_progress(written, firmware.len());
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

    /// An empty reply has no status byte. It is an error that names the command.
    #[test]
    fn test_bootloader_cmd_empty_response() {
        let device = MockDevice::new(vec![Ok(vec![])]);
        let err = bootloader_cmd(&device, 0x45, 0, &[]).unwrap_err();
        assert!(matches!(err, Error::Protocol(m) if m.contains("0x45") && m.contains("empty")));
    }

    /// A reply of only a zero status byte is success with an empty payload.
    #[test]
    fn test_bootloader_cmd_status_only_ok() {
        let device = MockDevice::new(vec![Ok(vec![0x00])]);
        assert_eq!(bootloader_cmd(&device, 0x45, 0, &[]).unwrap(), [] as [u8; 0]);
    }

    /// The final signature check must not pass on an empty reply.
    #[test]
    fn test_finish_firmware_empty_reply_errors() {
        let device = MockDevice::new(vec![Ok(vec![])]);
        let err = finish_firmware(&device, &[0u8; 64]).unwrap_err();
        assert!(matches!(err, Error::Protocol(m) if m.contains("0x41")));
    }

    /// A status-only reply to the final check is accepted.
    #[test]
    fn test_finish_firmware_status_only_ok() {
        let device = MockDevice::new(vec![Ok(vec![0x00])]);
        finish_firmware(&device, &[0u8; 64]).unwrap();
    }

    /// Transport errors propagate.
    #[test]
    fn test_bootloader_cmd_timeout() {
        let device = MockDevice::new(vec![]);
        let err = bootloader_cmd(&device, 0x44, 0, &[]).unwrap_err();
        assert!(matches!(err, Error::Transport(solo_ctaphid::Error::Timeout)));
    }

    /// Records the `(address, length)` of each `CMD_WRITE` packet it receives.
    struct RecordingDevice {
        writes: std::cell::RefCell<Vec<(u32, usize)>>,
    }

    impl solo_ctaphid::HidDevice for RecordingDevice {
        fn send_recv(&self, _cmd: u8, data: &[u8]) -> solo_ctaphid::Result<Vec<u8>> {
            let addr = u32::from_le_bytes([data[1], data[2], data[3], 0]) | 0x0800_0000;
            let len = usize::from(u16::from_be_bytes([data[8], data[9]]));
            self.writes.borrow_mut().push((addr, len));
            Ok(vec![0x00])
        }

        fn send(&self, _cmd: u8, _data: &[u8]) -> solo_ctaphid::Result<()> {
            Ok(())
        }
    }

    fn write_and_record(base: u32, len: usize) -> (Result<()>, Vec<(u32, usize)>) {
        let dev = RecordingDevice {
            writes: std::cell::RefCell::default(),
        };
        let res = write_firmware_chunks(&dev, base, &vec![0xAB; len], |_, _| {});
        (res, dev.writes.into_inner())
    }

    #[test]
    fn test_write_chunks_exact_multiple() {
        let (res, writes) = write_and_record(0x0800_5000, 512);
        res.unwrap();
        assert_eq!(writes, [(0x0800_5000, 256), (0x0800_5100, 256)]);
    }

    #[test]
    fn test_write_chunks_partial_last_chunk() {
        let (res, writes) = write_and_record(0x0800_5000, 600);
        res.unwrap();
        assert_eq!(writes, [(0x0800_5000, 256), (0x0800_5100, 256), (0x0800_5200, 88)]);
    }

    #[test]
    fn test_write_chunks_empty_firmware() {
        let (res, writes) = write_and_record(0x0800_5000, 0);
        res.unwrap();
        assert_eq!(writes, [] as [(u32, usize); 0]);
    }

    /// The address must fail, not saturate or wrap, when it overflows `u32`.
    #[test]
    fn test_write_chunks_address_overflow_errors() {
        let (res, writes) = write_and_record(u32::MAX - 100, 600);
        assert!(matches!(res, Err(Error::Protocol(m)) if m.contains("overflow")));
        assert_eq!(writes.len(), 1);
    }
}
