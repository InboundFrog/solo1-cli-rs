/// CTAP HID frame types, encoding/decoding, and message assembly.

use crate::error::{Result, SoloError};
use crate::device::protocol::SOLO_TAG;

/// A single 64-byte HID frame (init or continuation).
#[derive(Debug, Clone)]
pub struct CtapHidFrame {
    pub channel_id: [u8; 4],
    pub payload: FramePayload,
}

#[derive(Debug, Clone)]
pub enum FramePayload {
    Init { cmd: u8, bcnt: u16, data: Vec<u8> },
    Cont { seq: u8, data: Vec<u8> },
}

impl CtapHidFrame {
    /// Encode the frame into exactly 65 bytes (report ID 0 + 64 bytes).
    pub fn encode(&self) -> [u8; 65] {
        let mut buf = [0u8; 65];
        // byte 0 = report id (always 0)
        buf[1..5].copy_from_slice(&self.channel_id);
        match &self.payload {
            FramePayload::Init { cmd, bcnt, data } => {
                buf[5] = *cmd | 0x80; // set high bit for init frame
                buf[6] = (bcnt >> 8) as u8;
                buf[7] = *bcnt as u8;
                let n = data.len().min(57);
                buf[8..8 + n].copy_from_slice(&data[..n]);
            }
            FramePayload::Cont { seq, data } => {
                buf[5] = *seq & 0x7F; // clear high bit for cont frame
                let n = data.len().min(59);
                buf[6..6 + n].copy_from_slice(&data[..n]);
            }
        }
        buf
    }

    /// Parse a 64-byte raw HID report (no report ID byte).
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 7 {
            return Err(SoloError::ProtocolError("HID frame too short".into()));
        }
        let mut channel_id = [0u8; 4];
        channel_id.copy_from_slice(&raw[0..4]);
        let byte4 = raw[4];
        if byte4 & 0x80 != 0 {
            // Init frame
            let cmd = byte4 & 0x7F;
            let bcnt = ((raw[5] as u16) << 8) | raw[6] as u16;
            let data = raw[7..].to_vec();
            Ok(CtapHidFrame {
                channel_id,
                payload: FramePayload::Init { cmd, bcnt, data },
            })
        } else {
            // Continuation frame
            let seq = byte4 & 0x7F;
            let data = raw[5..].to_vec();
            Ok(CtapHidFrame {
                channel_id,
                payload: FramePayload::Cont { seq, data },
            })
        }
    }
}

/// Build the list of HID frames needed to send `data` with command `cmd`
/// on channel `cid`.
pub fn build_ctaphid_frames(cid: &[u8; 4], cmd: u8, data: &[u8]) -> Vec<CtapHidFrame> {
    let bcnt = data.len() as u16;
    let mut frames = Vec::new();

    // First (init) frame: up to 57 bytes of payload
    let first_data = if data.len() > 57 {
        data[..57].to_vec()
    } else {
        data.to_vec()
    };
    frames.push(CtapHidFrame {
        channel_id: *cid,
        payload: FramePayload::Init {
            cmd,
            bcnt,
            data: first_data,
        },
    });

    // Continuation frames: up to 59 bytes each
    if data.len() > 57 {
        let mut offset = 57;
        let mut seq: u8 = 0;
        while offset < data.len() {
            let end = (offset + 59).min(data.len());
            frames.push(CtapHidFrame {
                channel_id: *cid,
                payload: FramePayload::Cont {
                    seq,
                    data: data[offset..end].to_vec(),
                },
            });
            offset = end;
            seq += 1;
        }
    }

    frames
}

/// Reassemble received frames into a complete message payload.
pub fn reassemble_frames(frames: &[CtapHidFrame]) -> Result<(u8, Vec<u8>)> {
    if frames.is_empty() {
        return Err(SoloError::ProtocolError("No frames to reassemble".into()));
    }
    let (cmd, bcnt, first_data) = match &frames[0].payload {
        FramePayload::Init { cmd, bcnt, data } => (*cmd, *bcnt as usize, data.clone()),
        _ => {
            return Err(SoloError::ProtocolError(
                "First frame is not an init frame".into(),
            ))
        }
    };

    let mut payload = first_data;
    for frame in &frames[1..] {
        match &frame.payload {
            FramePayload::Cont { data, .. } => payload.extend_from_slice(data),
            FramePayload::Init { .. } => {
                return Err(SoloError::ProtocolError(
                    "Unexpected init frame in continuation".into(),
                ))
            }
        }
    }
    payload.truncate(bcnt);
    Ok((cmd, payload))
}

/// Build a bootloader command packet (for testing / manual use).
/// Address is encoded little-endian (lower 24 bits); firmware ORs 0x08000000 back in.
pub fn build_bootloader_packet(cmd: u8, addr: u32, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(10 + data.len());
    packet.push(cmd);
    packet.push((addr & 0xFF) as u8);
    packet.push(((addr >> 8) & 0xFF) as u8);
    packet.push(((addr >> 16) & 0xFF) as u8);
    packet.extend_from_slice(&SOLO_TAG);
    let len = data.len() as u16;
    packet.push((len >> 8) as u8);
    packet.push(len as u8);
    packet.extend_from_slice(data);
    packet
}

/// DFU block index from flash address.
/// block_index = (address - BASE_ADDR) / chunk_size + 2
pub const FLASH_BASE: u32 = 0x08000000;
pub const DFU_CHUNK_SIZE: u32 = 2048;

pub fn dfu_block_index(address: u32) -> u32 {
    (address - FLASH_BASE) / DFU_CHUNK_SIZE + 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctaphid_frame_init_encode_decode() {
        let cid = [0x01, 0x02, 0x03, 0x04];
        let data = vec![0xAA, 0xBB, 0xCC];
        let frame = CtapHidFrame {
            channel_id: cid,
            payload: FramePayload::Init {
                cmd: 0x06, // CTAPHID_INIT without high bit
                bcnt: 3,
                data: data.clone(),
            },
        };
        let encoded = frame.encode();
        assert_eq!(encoded[0], 0); // report ID
        assert_eq!(&encoded[1..5], &cid);
        assert_eq!(encoded[5], 0x06 | 0x80); // high bit set
        assert_eq!(encoded[6], 0x00); // bcnth
        assert_eq!(encoded[7], 0x03); // bcntl
        assert_eq!(&encoded[8..11], &[0xAA, 0xBB, 0xCC]);

        // Parse back (skip report ID byte)
        let parsed = CtapHidFrame::parse(&encoded[1..]).unwrap();
        assert_eq!(parsed.channel_id, cid);
        match parsed.payload {
            FramePayload::Init { cmd, bcnt, data: d } => {
                assert_eq!(cmd, 0x06);
                assert_eq!(bcnt, 3);
                assert_eq!(&d[..3], &[0xAA, 0xBB, 0xCC]);
            }
            _ => panic!("Expected init frame"),
        }
    }

    #[test]
    fn test_ctaphid_frame_cont_encode_decode() {
        let cid = [0xFF, 0xFF, 0xFF, 0xFF];
        let data = vec![0x01, 0x02, 0x03];
        let frame = CtapHidFrame {
            channel_id: cid,
            payload: FramePayload::Cont {
                seq: 2,
                data: data.clone(),
            },
        };
        let encoded = frame.encode();
        assert_eq!(encoded[5], 0x02); // seq, no high bit
        assert_eq!(&encoded[6..9], &[0x01, 0x02, 0x03]);

        let parsed = CtapHidFrame::parse(&encoded[1..]).unwrap();
        match parsed.payload {
            FramePayload::Cont { seq, data: d } => {
                assert_eq!(seq, 2);
                assert_eq!(&d[..3], &[0x01, 0x02, 0x03]);
            }
            _ => panic!("Expected cont frame"),
        }
    }

    #[test]
    fn test_build_frames_single() {
        let cid = [0x01, 0x02, 0x03, 0x04];
        let data = vec![0xDE; 10];
        let frames = build_ctaphid_frames(&cid, 0x81, &data);
        assert_eq!(frames.len(), 1);
        match &frames[0].payload {
            FramePayload::Init { bcnt, .. } => assert_eq!(*bcnt, 10),
            _ => panic!(),
        }
    }

    #[test]
    fn test_build_frames_multi() {
        let cid = [0x01, 0x02, 0x03, 0x04];
        let data = vec![0xAB; 120]; // 57 + 59 + 4 = 120
        let frames = build_ctaphid_frames(&cid, 0x81, &data);
        assert_eq!(frames.len(), 3);
        match &frames[0].payload {
            FramePayload::Init { bcnt, data: d, .. } => {
                assert_eq!(*bcnt, 120);
                assert_eq!(d.len(), 57);
            }
            _ => panic!(),
        }
        match &frames[1].payload {
            FramePayload::Cont { seq, data: d } => {
                assert_eq!(*seq, 0);
                assert_eq!(d.len(), 59);
            }
            _ => panic!(),
        }
        match &frames[2].payload {
            FramePayload::Cont { seq, data: d } => {
                assert_eq!(*seq, 1);
                assert_eq!(d.len(), 4);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_bootloader_packet() {
        // Address 0x08001000: firmware strips 0x08000000, leaving offset 0x001000.
        // Little-endian 3-byte encoding of 0x001000: [0x00, 0x10, 0x00]
        let pkt = build_bootloader_packet(0x40, 0x08001000, &[0xDE, 0xAD]);
        assert_eq!(pkt[0], 0x40); // cmd
        assert_eq!(&pkt[1..4], &[0x00, 0x10, 0x00]); // addr little-endian (LSB first)
        assert_eq!(&pkt[4..8], &SOLO_TAG); // tag
        assert_eq!(pkt[8], 0x00); // len high
        assert_eq!(pkt[9], 0x02); // len low
        assert_eq!(&pkt[10..12], &[0xDE, 0xAD]); // data

        // Address where byte order matters: 0x08010000 → offset 0x010000
        // Little-endian: [0x00, 0x00, 0x01]  (NOT [0x01, 0x00, 0x00])
        let pkt2 = build_bootloader_packet(0x40, 0x08010000, &[]);
        assert_eq!(&pkt2[1..4], &[0x00, 0x00, 0x01]);

        // 0x08012345 → offset 0x012345 → LE: [0x45, 0x23, 0x01]
        let pkt3 = build_bootloader_packet(0x40, 0x08012345, &[]);
        assert_eq!(&pkt3[1..4], &[0x45, 0x23, 0x01]);
    }

    #[test]
    fn test_dfu_block_index() {
        assert_eq!(dfu_block_index(0x08000000), 2);
        assert_eq!(dfu_block_index(0x08000800), 3); // + 2048
        assert_eq!(dfu_block_index(0x08001000), 4); // + 4096
    }
}
