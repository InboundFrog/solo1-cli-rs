//! CTAP HID frame types, encoding/decoding, and message assembly.

use crate::error::{Error, Result};

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
    ///
    /// # Errors
    /// Returns an error if the payload does not fit within a single HID frame.
    pub fn encode(&self) -> Result<[u8; 65]> {
        let mut buf = [0u8; 65];
        // byte 0 = report id (always 0)
        buf[1..5].copy_from_slice(&self.channel_id);
        match &self.payload {
            FramePayload::Init { cmd, bcnt, data } => {
                buf[5] = *cmd | 0x80; // set high bit for init frame
                let [bcnt_hi, bcnt_lo] = bcnt.to_be_bytes();
                buf[6] = bcnt_hi;
                buf[7] = bcnt_lo;
                let n = data.len().min(57);
                let end = 8usize
                    .checked_add(n)
                    .ok_or_else(|| Error::Protocol("frame length overflow".into()))?;
                let src = data
                    .get(..n)
                    .ok_or_else(|| Error::Protocol("frame data too short".into()))?;
                buf.get_mut(8..end)
                    .ok_or_else(|| Error::Protocol("frame buffer overflow".into()))?
                    .copy_from_slice(src);
            }
            FramePayload::Cont { seq, data } => {
                buf[5] = *seq & 0x7F; // clear high bit for cont frame
                let n = data.len().min(59);
                let end = 6usize
                    .checked_add(n)
                    .ok_or_else(|| Error::Protocol("frame length overflow".into()))?;
                let src = data
                    .get(..n)
                    .ok_or_else(|| Error::Protocol("frame data too short".into()))?;
                buf.get_mut(6..end)
                    .ok_or_else(|| Error::Protocol("frame buffer overflow".into()))?
                    .copy_from_slice(src);
            }
        }
        Ok(buf)
    }

    /// Parse a 64-byte raw HID report (no report ID byte).
    ///
    /// # Errors
    /// Returns an error if `raw` is shorter than the 7-byte frame header.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 7 {
            return Err(Error::Protocol("HID frame too short".into()));
        }
        let mut channel_id = [0u8; 4];
        channel_id.copy_from_slice(
            raw.get(..4)
                .ok_or_else(|| Error::Protocol("HID frame too short".into()))?,
        );
        let byte4 = *raw
            .get(4)
            .ok_or_else(|| Error::Protocol("HID frame too short".into()))?;
        if byte4 & 0x80 != 0 {
            // Init frame
            let cmd = byte4 & 0x7F;
            let bcnt_hi = *raw
                .get(5)
                .ok_or_else(|| Error::Protocol("HID frame too short".into()))?;
            let bcnt_lo = *raw
                .get(6)
                .ok_or_else(|| Error::Protocol("HID frame too short".into()))?;
            let bcnt = u16::from_be_bytes([bcnt_hi, bcnt_lo]);
            let data = raw
                .get(7..)
                .ok_or_else(|| Error::Protocol("HID frame too short".into()))?
                .to_vec();
            Ok(Self {
                channel_id,
                payload: FramePayload::Init { cmd, bcnt, data },
            })
        } else {
            // Continuation frame
            let seq = byte4 & 0x7F;
            let data = raw
                .get(5..)
                .ok_or_else(|| Error::Protocol("HID frame too short".into()))?
                .to_vec();
            Ok(Self {
                channel_id,
                payload: FramePayload::Cont { seq, data },
            })
        }
    }
}

/// Maximum CTAPHID message payload: 57 bytes in the init frame plus
/// 128 continuation frames (seq 0..=127) of 59 bytes each.
pub const CTAPHID_MAX_PAYLOAD: usize = 57 + 128 * 59;

/// Build the list of HID frames needed to send `data` with command `cmd`
/// on channel `cid`.
///
/// # Errors
/// Returns an error if `data` exceeds the CTAPHID maximum message size
/// (7609 bytes), which would otherwise silently truncate the 16-bit
/// `bcnt` field and overflow the 7-bit continuation sequence number.
pub fn build_ctaphid_frames(cid: &[u8; 4], cmd: u8, data: &[u8]) -> Result<Vec<CtapHidFrame>> {
    if data.len() > CTAPHID_MAX_PAYLOAD {
        return Err(Error::Protocol(format!(
            "CTAPHID payload too large: {} bytes (max {})",
            data.len(),
            CTAPHID_MAX_PAYLOAD
        )));
    }
    let bcnt = u16::try_from(data.len()).map_err(|_| Error::Protocol("CTAPHID payload length exceeds u16".into()))?;
    let mut frames = Vec::new();

    // First (init) frame: up to 57 bytes of payload
    let first_data = if data.len() > 57 {
        data.get(..57)
            .ok_or_else(|| Error::Protocol("CTAPHID payload too short".into()))?
            .to_vec()
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
            let end = offset
                .checked_add(59)
                .ok_or_else(|| Error::Protocol("CTAPHID offset overflow".into()))?
                .min(data.len());
            frames.push(CtapHidFrame {
                channel_id: *cid,
                payload: FramePayload::Cont {
                    seq,
                    data: data
                        .get(offset..end)
                        .ok_or_else(|| Error::Protocol("CTAPHID slice out of range".into()))?
                        .to_vec(),
                },
            });
            offset = end;
            seq = seq
                .checked_add(1)
                .ok_or_else(|| Error::Protocol("CTAPHID sequence overflow".into()))?;
        }
    }

    Ok(frames)
}

/// Reassemble received frames into a complete message payload.
///
/// # Errors
/// Returns an error if `frames` is empty, if the first frame is not an init
/// frame, or if a continuation position contains an init frame.
pub fn reassemble_frames(frames: &[CtapHidFrame]) -> Result<(u8, Vec<u8>)> {
    if frames.is_empty() {
        return Err(Error::Protocol("No frames to reassemble".into()));
    }
    let first = frames
        .first()
        .ok_or_else(|| Error::Protocol("No frames to reassemble".into()))?;
    let (cmd, bcnt, first_data) = match &first.payload {
        FramePayload::Init { cmd, bcnt, data } => (*cmd, usize::from(*bcnt), data.clone()),
        FramePayload::Cont { .. } => return Err(Error::Protocol("First frame is not an init frame".into())),
    };

    let mut payload = first_data;
    for frame in frames
        .get(1..)
        .ok_or_else(|| Error::Protocol("frame index out of range".into()))?
    {
        match &frame.payload {
            FramePayload::Cont { data, .. } => payload.extend_from_slice(data),
            FramePayload::Init { .. } => return Err(Error::Protocol("Unexpected init frame in continuation".into())),
        }
    }
    payload.truncate(bcnt);
    Ok((cmd, payload))
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

    #[test]
    fn test_ctaphid_frame_init_encode_decode() {
        let cid = [0x01, 0x02, 0x03, 0x04];
        let data = vec![0xAA, 0xBB, 0xCC];
        let frame = CtapHidFrame {
            channel_id: cid,
            payload: FramePayload::Init {
                cmd: 0x06, // CTAPHID_INIT without high bit
                bcnt: 3,
                data,
            },
        };
        let encoded = frame.encode().unwrap();
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
            FramePayload::Cont { .. } => panic!("Expected init frame"),
        }
    }

    #[test]
    fn test_ctaphid_frame_cont_encode_decode() {
        let cid = [0xFF, 0xFF, 0xFF, 0xFF];
        let data = vec![0x01, 0x02, 0x03];
        let frame = CtapHidFrame {
            channel_id: cid,
            payload: FramePayload::Cont { seq: 2, data },
        };
        let encoded = frame.encode().unwrap();
        assert_eq!(encoded[5], 0x02); // seq, no high bit
        assert_eq!(&encoded[6..9], &[0x01, 0x02, 0x03]);

        let parsed = CtapHidFrame::parse(&encoded[1..]).unwrap();
        match parsed.payload {
            FramePayload::Cont { seq, data: d } => {
                assert_eq!(seq, 2);
                assert_eq!(&d[..3], &[0x01, 0x02, 0x03]);
            }
            FramePayload::Init { .. } => panic!("Expected cont frame"),
        }
    }

    #[test]
    fn test_build_frames_single() {
        let cid = [0x01, 0x02, 0x03, 0x04];
        let data = vec![0xDE; 10];
        let frames = build_ctaphid_frames(&cid, 0x81, &data).unwrap();
        assert_eq!(frames.len(), 1);
        match &frames[0].payload {
            FramePayload::Init { bcnt, .. } => assert_eq!(*bcnt, 10),
            FramePayload::Cont { .. } => panic!(),
        }
    }

    #[test]
    fn test_build_frames_multi() {
        let cid = [0x01, 0x02, 0x03, 0x04];
        let data = vec![0xAB; 120]; // 57 + 59 + 4 = 120
        let frames = build_ctaphid_frames(&cid, 0x81, &data).unwrap();
        assert_eq!(frames.len(), 3);
        match &frames[0].payload {
            FramePayload::Init { bcnt, data: d, .. } => {
                assert_eq!(*bcnt, 120);
                assert_eq!(d.len(), 57);
            }
            FramePayload::Cont { .. } => panic!(),
        }
        match &frames[1].payload {
            FramePayload::Cont { seq, data: d } => {
                assert_eq!(*seq, 0);
                assert_eq!(d.len(), 59);
            }
            FramePayload::Init { .. } => panic!(),
        }
        match &frames[2].payload {
            FramePayload::Cont { seq, data: d } => {
                assert_eq!(*seq, 1);
                assert_eq!(d.len(), 4);
            }
            FramePayload::Init { .. } => panic!(),
        }
    }

    #[test]
    fn test_build_frames_max_payload_ok() {
        let cid = [0x01, 0x02, 0x03, 0x04];
        let data = vec![0x5A; CTAPHID_MAX_PAYLOAD]; // 7609 = 57 + 128 * 59
        let frames = build_ctaphid_frames(&cid, 0x81, &data).unwrap();
        assert_eq!(frames.len(), 1 + 128); // init + 128 full cont frames
        match &frames[0].payload {
            FramePayload::Init { bcnt, data: d, .. } => {
                assert_eq!(*bcnt, CTAPHID_MAX_PAYLOAD as u16);
                assert_eq!(d.len(), 57);
            }
            FramePayload::Cont { .. } => panic!("Expected init frame"),
        }
        match &frames[128].payload {
            FramePayload::Cont { seq, data: d } => {
                assert_eq!(*seq, 127);
                assert_eq!(d.len(), 59);
            }
            FramePayload::Init { .. } => panic!("Expected cont frame"),
        }
    }

    #[test]
    fn test_build_frames_oversized_payload_err() {
        let cid = [0x01, 0x02, 0x03, 0x04];
        let data = vec![0x5A; CTAPHID_MAX_PAYLOAD + 1];
        let err = build_ctaphid_frames(&cid, 0x81, &data).unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }
}
