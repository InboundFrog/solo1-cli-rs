/// USB HID communication layer for Solo 1 devices.
///
/// Implements the CTAP HID protocol framing and the Solo-specific
/// vendor commands on top of it.
use std::time::{Duration, Instant};

use hidapi::{HidApi, HidDevice};

use crate::error::{Result, SoloError};
use crate::vlog;

// USB identifiers
pub const SOLO_VID: u16 = 0x0483;
pub const SOLO_PID: u16 = 0xA2CA;
pub const SOLO_DFU_PID: u16 = 0xDF11;

// HID report size
pub const HID_REPORT_SIZE: usize = 64;

// CTAPHID commands
pub const CTAPHID_INIT: u8 = 0x86;
pub const CTAPHID_MSG: u8 = 0x83;
pub const CTAPHID_CBOR: u8 = 0x90;
pub const CTAPHID_PING: u8 = 0x81;
pub const CTAPHID_WINK: u8 = 0x88;
pub const CTAPHID_VENDOR_FIRST: u8 = 0x40;

// Solo vendor commands (offset from CTAPHID_VENDOR_FIRST or absolute)
pub const CMD_WRITE: u8 = 0x40;
pub const CMD_DONE: u8 = 0x41;
pub const CMD_CHECK: u8 = 0x42;
pub const CMD_ERASE: u8 = 0x43;
pub const CMD_VERSION: u8 = 0x44;
pub const CMD_REBOOT: u8 = 0x45;
pub const CMD_ENTER_DFU: u8 = 0x46;
pub const CMD_DISABLE_BOOTLOADER: u8 = 0x47;
pub const CMD_BOOT: u8 = 0x50;
pub const CMD_ENTER_BOOT: u8 = 0x51;
pub const CMD_ENTER_ST_BOOT: u8 = 0x52;

// Firmware-mode custom commands
pub const CMD_RNG: u8 = 0x60;
pub const CMD_GET_VERSION: u8 = 0x61;
pub const CMD_SET_VERSION: u8 = 0x62;
pub const CMD_PROBE: u8 = 0x70;

// Solo bootloader magic tag
pub const SOLO_TAG: [u8; 4] = [0x8C, 0x27, 0x90, 0xF6];

// Broadcast channel for CTAPHID_INIT
pub const CTAPHID_BROADCAST_CID: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

/// A single 64-byte HID frame (init or continuation).
#[derive(Debug, Clone)]
pub struct CtapHidFrame {
    pub channel_id: [u8; 4],
    pub payload: FramePayload,
}

#[derive(Debug, Clone)]
pub enum FramePayload {
    Init {
        cmd: u8,
        bcnt: u16,
        data: Vec<u8>,
    },
    Cont {
        seq: u8,
        data: Vec<u8>,
    },
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

/// Information about a connected Solo device.
#[derive(Debug, Clone)]
pub struct SoloDevice {
    pub path: String,
    pub serial: Option<String>,
    pub product: Option<String>,
    pub manufacturer: Option<String>,
}

/// List all connected Solo HID devices.
pub fn list_solo_devices() -> Result<Vec<SoloDevice>> {
    let api = HidApi::new()?;
    let devices: Vec<SoloDevice> = api
        .device_list()
        .filter(|d| d.vendor_id() == SOLO_VID && d.product_id() == SOLO_PID)
        .map(|d| SoloDevice {
            path: d.path().to_string_lossy().to_string(),
            serial: d.serial_number().map(|s| s.to_string()),
            product: d.product_string().map(|s| s.to_string()),
            manufacturer: d.manufacturer_string().map(|s| s.to_string()),
        })
        .collect();
    Ok(devices)
}

/// Open a Solo HID device, optionally filtered by serial number.
/// Returns the opened device and its assigned channel ID.
pub struct SoloHid {
    pub device: HidDevice,
    pub channel_id: [u8; 4],
}

impl SoloHid {
    /// Open a device by serial number (or the only device if None).
    pub fn open(serial: Option<&str>) -> Result<Self> {
        let api = HidApi::new()?;
        let devices: Vec<_> = api
            .device_list()
            .filter(|d| d.vendor_id() == SOLO_VID && d.product_id() == SOLO_PID)
            .collect();

        if devices.is_empty() {
            return Err(SoloError::NoSoloFound);
        }

        let info = if let Some(sn) = serial {
            let matched: Vec<_> = devices
                .iter()
                .filter(|d| d.serial_number().map(|s| s == sn).unwrap_or(false))
                .collect();
            if matched.is_empty() {
                return Err(SoloError::DeviceError(format!(
                    "No device with serial {}",
                    sn
                )));
            }
            matched[0]
        } else {
            if devices.len() > 1 {
                return Err(SoloError::NonUniqueDevice);
            }
            devices[0]
        };

        let device = info.open_device(&api)?;
        device.set_blocking_mode(true)?;

        let mut hid = SoloHid {
            device,
            channel_id: [0u8; 4],
        };
        hid.init()?;
        Ok(hid)
    }

    /// Open a device for bootloader use (may be in firmware or bootloader mode).
    pub fn open_bootloader(serial: Option<&str>) -> Result<Self> {
        // Try the normal firmware PID first; if that fails, same VID/PID for bootloader
        Self::open(serial)
    }

    /// Send a CTAPHID_INIT to get a channel ID.
    fn init(&mut self) -> Result<()> {
        // Generate a random nonce
        let nonce: [u8; 8] = rand::random();
        vlog!("CTAPHID_INIT: sending nonce {}", hex::encode(nonce));
        let frames = build_ctaphid_frames(&CTAPHID_BROADCAST_CID, CTAPHID_INIT, &nonce);
        for frame in &frames {
            let encoded = frame.encode();
            self.device.write(&encoded)?;
        }

        let response = self.recv_response(CTAPHID_INIT, Duration::from_secs(5))?;
        if response.len() < 12 {
            return Err(SoloError::ProtocolError(
                "CTAPHID_INIT response too short".into(),
            ));
        }
        // Response: nonce[8] | channel_id[4] | ...
        self.channel_id.copy_from_slice(&response[8..12]);
        vlog!(
            "CTAPHID_INIT: assigned channel_id {}",
            hex::encode(self.channel_id)
        );
        Ok(())
    }

    /// Send a command with payload, receive and return the response payload.
    pub fn send_recv(&self, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        self.send(cmd, data)?;
        self.recv_response(cmd, Duration::from_secs(10))
    }

    /// Send a command with payload.
    pub fn send(&self, cmd: u8, data: &[u8]) -> Result<()> {
        vlog!(
            "HID send: cmd=0x{:02X} len={} data={}",
            cmd,
            data.len(),
            if data.len() <= 64 {
                hex::encode(data)
            } else {
                format!("{}...", hex::encode(&data[..64]))
            }
        );
        let frames = build_ctaphid_frames(&self.channel_id, cmd, data);
        vlog!("HID send: {} frame(s)", frames.len());
        for frame in &frames {
            let encoded = frame.encode();
            self.device.write(&encoded)?;
        }
        Ok(())
    }

    /// Receive a response for a given command, with timeout.
    pub fn recv_response(&self, expected_cmd: u8, timeout: Duration) -> Result<Vec<u8>> {
        vlog!("HID recv: waiting for cmd=0x{:02X}", expected_cmd);
        let start = Instant::now();
        let mut frames: Vec<CtapHidFrame> = Vec::new();
        let mut total_bcnt: Option<usize> = None;
        let mut collected: usize = 0;

        loop {
            if start.elapsed() > timeout {
                return Err(SoloError::Timeout);
            }
            let mut buf = [0u8; 65];
            let n = self.device.read_timeout(&mut buf, 500).map_err(|e| {
                SoloError::DeviceError(format!("HID read error: {}", e))
            })?;

            if n == 0 {
                continue;
            }

            // The HID report may or may not include the report ID byte depending on platform.
            // hidapi on most platforms does NOT include the report ID byte in the read buffer.
            let raw = &buf[..n];
            // If first byte looks like a report ID (0x00), skip it
            let frame_bytes = if n >= 65 && raw[0] == 0 {
                &raw[1..65]
            } else if n >= 64 {
                &raw[..64]
            } else {
                // pad to 64
                &raw[..n]
            };

            let frame = CtapHidFrame::parse(frame_bytes)?;

            // Skip frames not for our channel (unless this is INIT response on broadcast)
            let for_us = frame.channel_id == self.channel_id
                || frame.channel_id == CTAPHID_BROADCAST_CID;
            if !for_us {
                vlog!(
                    "HID recv: ignoring frame for channel {}",
                    hex::encode(frame.channel_id)
                );
                continue;
            }

            match &frame.payload {
                FramePayload::Init { cmd, bcnt, data } => {
                    // Check for error
                    if *cmd == 0x3F {
                        // CTAPHID_ERROR
                        let code = data.first().copied().unwrap_or(0);
                        vlog!("HID recv: CTAPHID_ERROR code=0x{:02X}", code);
                        return Err(SoloError::ProtocolError(format!(
                            "CTAPHID error: {:02x}",
                            code
                        )));
                    }
                    vlog!(
                        "HID recv: init frame cmd=0x{:02X} bcnt={} first_data={}",
                        cmd,
                        bcnt,
                        hex::encode(&data[..data.len().min(16)])
                    );
                    if *cmd != (expected_cmd & 0x7F) {
                        vlog!(
                            "HID recv: unexpected cmd 0x{:02X} (want 0x{:02X}), skipping",
                            cmd,
                            expected_cmd & 0x7F
                        );
                        continue;
                    }
                    total_bcnt = Some(*bcnt as usize);
                    collected = data.len().min(*bcnt as usize);
                    frames.clear();
                    frames.push(frame);
                }
                FramePayload::Cont { seq, .. } => {
                    vlog!("HID recv: cont frame seq={}", seq);
                    if let Some(tb) = total_bcnt {
                        frames.push(frame.clone());
                        if let FramePayload::Cont { data, .. } = &frame.payload {
                            collected += data.len();
                        }
                        if collected >= tb {
                            break;
                        }
                    }
                }
            }

            if let Some(tb) = total_bcnt {
                if collected >= tb || frames.len() == 1 && tb <= 57 {
                    break;
                }
            }
        }

        let (_, payload) = reassemble_frames(&frames)?;
        vlog!(
            "HID recv: reassembled {} bytes: {}",
            payload.len(),
            if payload.len() <= 32 {
                hex::encode(&payload)
            } else {
                format!("{}...", hex::encode(&payload[..32]))
            }
        );
        Ok(payload)
    }

    /// Send a vendor (bootloader) command packet.
    /// Format: [cmd(1)] [addr(3)] [TAG(4)] [length_be(2)] [data]
    pub fn send_bootloader_cmd(&self, cmd: u8, addr: u32, data: &[u8]) -> Result<Vec<u8>> {
        vlog!(
            "bootloader cmd=0x{:02X} addr=0x{:08X} data_len={}",
            cmd,
            addr,
            data.len()
        );
        let mut packet = Vec::with_capacity(10 + data.len());
        packet.push(cmd);
        // 3-byte address (big-endian, lower 24 bits)
        packet.push(((addr >> 16) & 0xFF) as u8);
        packet.push(((addr >> 8) & 0xFF) as u8);
        packet.push((addr & 0xFF) as u8);
        packet.extend_from_slice(&SOLO_TAG);
        let len = data.len() as u16;
        packet.push((len >> 8) as u8);
        packet.push(len as u8);
        packet.extend_from_slice(data);

        self.send_recv(CMD_BOOT, &packet)
    }
}

/// Build a bootloader command packet (for testing / manual use).
pub fn build_bootloader_packet(cmd: u8, addr: u32, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(10 + data.len());
    packet.push(cmd);
    packet.push(((addr >> 16) & 0xFF) as u8);
    packet.push(((addr >> 8) & 0xFF) as u8);
    packet.push((addr & 0xFF) as u8);
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
            payload: FramePayload::Cont { seq: 2, data: data.clone() },
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
        // Address 0x08001000 in 3-byte big-endian: lower 24 bits = 0x001000
        // bytes: 0x00, 0x10, 0x00
        let pkt = build_bootloader_packet(0x40, 0x08001000, &[0xDE, 0xAD]);
        assert_eq!(pkt[0], 0x40); // cmd
        assert_eq!(&pkt[1..4], &[0x00, 0x10, 0x00]); // addr (lower 24 bits of 0x08001000)
        assert_eq!(&pkt[4..8], &SOLO_TAG); // tag
        assert_eq!(pkt[8], 0x00); // len high
        assert_eq!(pkt[9], 0x02); // len low
        assert_eq!(&pkt[10..12], &[0xDE, 0xAD]); // data

        // Verify with an address in the lower range
        let pkt2 = build_bootloader_packet(0x40, 0x00001234, &[]);
        assert_eq!(&pkt2[1..4], &[0x00, 0x12, 0x34]); // addr
    }

    #[test]
    fn test_dfu_block_index() {
        assert_eq!(dfu_block_index(0x08000000), 2);
        assert_eq!(dfu_block_index(0x08000800), 3); // + 2048
        assert_eq!(dfu_block_index(0x08001000), 4); // + 4096
    }
}
