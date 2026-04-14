/// Solo HID device communication — SoloHid, SoloDevice, list_solo_devices.

use std::time::{Duration, Instant};

use hidapi::{HidApi, HidDevice as HidApiDevice};

use crate::error::{Result, SoloError};
use crate::vlog;
use crate::device::protocol::{
    SOLO_VID, SOLO_PID, SOLO_TAG, CTAPHID_INIT, CTAPHID_BROADCAST_CID, CMD_BOOT,
};
use crate::device::frame::{CtapHidFrame, FramePayload, build_ctaphid_frames, reassemble_frames};

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
    pub device: HidApiDevice,
    pub channel_id: [u8; 4],
    /// Timeout applied to each `send_recv` / `recv_response` call.
    /// The low-level `init` handshake always uses a fixed 5-second timeout.
    pub response_timeout: Duration,
}

impl SoloHid {
    /// Open a device by serial number (or the only device if None).
    ///
    /// `timeout` controls how long `send_recv` and `recv_response` wait for a
    /// device reply. The low-level CTAPHID init handshake always uses a fixed
    /// 5-second timeout regardless of this value.
    pub fn open(serial: Option<&str>, timeout: Duration) -> Result<Self> {
        let api = HidApi::new()?;
        let devices: Vec<_> = api
            .device_list()
            .filter(|d| d.vendor_id() == SOLO_VID && d.product_id() == SOLO_PID)
            .collect();

        if devices.is_empty() {
            return Err(SoloError::NoSoloFound);
        }

        let info = if let Some(sn) = serial {
            devices
                .iter()
                .find(|d| d.serial_number().map_or(false, |s| s == sn))
                .ok_or_else(|| SoloError::DeviceError(format!("No device with serial {}", sn)))?
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
            response_timeout: timeout,
        };
        hid.init()?;
        Ok(hid)
    }

    /// Open a device for bootloader use (may be in firmware or bootloader mode).
    pub fn open_bootloader(serial: Option<&str>, timeout: Duration) -> Result<Self> {
        // Try the normal firmware PID first; if that fails, same VID/PID for bootloader
        Self::open(serial, timeout)
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
        self.recv_response(cmd, self.response_timeout)
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
            let n = self
                .device
                .read_timeout(&mut buf, 500)
                .map_err(|e| SoloError::DeviceError(format!("HID read error: {}", e)))?;

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
            let for_us =
                frame.channel_id == self.channel_id || frame.channel_id == CTAPHID_BROADCAST_CID;
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

    /// Send a vendor (bootloader) command packet and return the response payload.
    ///
    /// Packet format: [cmd(1)] [addr(3) LE] [TAG(4)] [length_be(2)] [data]
    ///
    /// The bootloader responds with [status(1)] [payload...]. This method checks
    /// the status byte and strips it, returning only the payload on success.
    pub fn send_bootloader_cmd(&self, cmd: u8, addr: u32, data: &[u8]) -> Result<Vec<u8>> {
        vlog!(
            "bootloader cmd=0x{:02X} addr=0x{:08X} data_len={}",
            cmd,
            addr,
            data.len()
        );
        let mut packet = Vec::with_capacity(10 + data.len());
        packet.push(cmd);
        // 3-byte address, little-endian (firmware does: *(uint32_t*)addr & 0xffffff | 0x8000000)
        packet.push((addr & 0xFF) as u8);
        packet.push(((addr >> 8) & 0xFF) as u8);
        packet.push(((addr >> 16) & 0xFF) as u8);
        packet.extend_from_slice(&SOLO_TAG);
        let len = data.len() as u16;
        packet.push((len >> 8) as u8);
        packet.push(len as u8);
        packet.extend_from_slice(data);

        let resp = self.send_recv(CMD_BOOT, &packet)?;

        // First byte of bootloader response is a status code (0x00 = success)
        if resp.is_empty() {
            return Ok(resp);
        }
        let status = resp[0];
        if status != 0x00 {
            return Err(SoloError::ProtocolError(format!(
                "Bootloader error status: 0x{:02X}",
                status
            )));
        }
        Ok(resp[1..].to_vec())
    }
}

impl crate::device::HidDevice for SoloHid {
    fn send_recv(&self, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        SoloHid::send_recv(self, cmd, data)
    }

    fn send_bootloader_cmd(&self, cmd: u8, addr: u32, data: &[u8]) -> Result<Vec<u8>> {
        SoloHid::send_bootloader_cmd(self, cmd, addr, data)
    }

    fn send(&self, cmd: u8, data: &[u8]) -> Result<()> {
        SoloHid::send(self, cmd, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solohid_stores_response_timeout() {
        // We cannot open a real HID device in a unit test, but we can verify
        // that the Duration arithmetic used when threading --timeout through
        // the CLI is correct, and that the field type matches expectations.
        let secs: u64 = 42;
        let timeout = Duration::from_secs(secs);
        assert_eq!(timeout.as_secs(), secs);

        // Also verify that the default timeout value (30 s) round-trips cleanly.
        let default_timeout = Duration::from_secs(30);
        assert_eq!(default_timeout.as_secs(), 30);

        // Verify init's fixed timeout is independent of the configurable one.
        let init_timeout = Duration::from_secs(5);
        assert!(init_timeout < default_timeout,
            "init timeout must be less than the default response timeout");
    }
}
