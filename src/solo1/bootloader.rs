/// Solo 1 bootloader command packets, sent over CTAPHID as `CMD_BOOT`.
use crate::device::HidDevice;
use crate::error::{Result, SoloError};
use crate::solo1::protocol::{CMD_BOOT, SOLO_TAG};
use crate::vlog;

/// Build a bootloader command packet.
/// Address is encoded little-endian (lower 24 bits); firmware ORs 0x08000000 back in.
///
/// # Errors
/// Returns an error if `data` is longer than the 16-bit big-endian length
/// field can express (65535 bytes), which would otherwise be silently
/// truncated.
pub fn build_bootloader_packet(cmd: u8, addr: u32, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > usize::from(u16::MAX) {
        return Err(SoloError::ProtocolError(format!(
            "Bootloader packet data too large: {} bytes (max {})",
            data.len(),
            u16::MAX
        )));
    }
    let capacity = 10usize
        .checked_add(data.len())
        .ok_or_else(|| SoloError::ProtocolError("bootloader packet capacity overflow".into()))?;
    let mut packet = Vec::with_capacity(capacity);
    packet.push(cmd);
    let [addr0, addr1, addr2, _] = addr.to_le_bytes();
    packet.push(addr0);
    packet.push(addr1);
    packet.push(addr2);
    packet.extend_from_slice(&SOLO_TAG);
    let len = u16::try_from(data.len())
        .map_err(|_| SoloError::ProtocolError("bootloader packet length exceeds u16".into()))?;
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
    vlog!(
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
        return Err(SoloError::ProtocolError(format!(
            "Bootloader error status: 0x{status:02X}"
        )));
    }
    Ok(payload.to_vec())
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
    use crate::device::mock::MockDevice;

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
        assert!(matches!(err, SoloError::ProtocolError(_)));
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
        assert!(matches!(err, SoloError::ProtocolError(m) if m.contains("0x0A")));
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
        assert!(matches!(err, SoloError::Timeout));
    }
}
