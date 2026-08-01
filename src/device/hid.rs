/// Solo HID device communication — `SoloHid`, `SoloDevice`, `list_solo_devices`.
use std::time::{Duration, Instant};

use hidapi::{HidApi, HidDevice as HidApiDevice};

use crate::device::frame::{
    build_bootloader_packet, build_ctaphid_frames, reassemble_frames, CtapHidFrame, FramePayload,
};
use crate::device::protocol::{CMD_BOOT, CTAPHID_BROADCAST_CID, CTAPHID_INIT, SOLO_PID, SOLO_VID};
use crate::error::{Result, SoloError};
use crate::vlog;

/// Information about a connected Solo device.
#[derive(Debug, Clone)]
pub struct SoloDevice {
    pub path: String,
    pub serial: Option<String>,
    pub product: Option<String>,
    pub manufacturer: Option<String>,
}

/// List all connected Solo HID devices.
///
/// # Errors
/// Returns an error if the HID API cannot be initialized.
pub fn list_solo_devices() -> Result<Vec<SoloDevice>> {
    let api = HidApi::new()?;
    let devices: Vec<SoloDevice> = api
        .device_list()
        .filter(|d| d.vendor_id() == SOLO_VID && d.product_id() == SOLO_PID)
        .map(|d| SoloDevice {
            path: d.path().to_string_lossy().to_string(),
            serial: d.serial_number().map(std::string::ToString::to_string),
            product: d.product_string().map(std::string::ToString::to_string),
            manufacturer: d
                .manufacturer_string()
                .map(std::string::ToString::to_string),
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
    ///
    /// # Errors
    /// Returns an error if the HID API cannot be initialized, no Solo device is
    /// found, the requested serial does not match any device, multiple devices
    /// are present when no serial is given, the device cannot be opened, or the
    /// CTAPHID init handshake fails.
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
                .find(|d| d.serial_number() == Some(sn))
                .ok_or_else(|| SoloError::DeviceError(format!("No device with serial {sn}")))?
        } else {
            if devices.len() > 1 {
                return Err(SoloError::NonUniqueDevice);
            }
            devices
                .first()
                .copied()
                .ok_or_else(|| SoloError::DeviceError("No device available".into()))?
        };

        let device = info.open_device(&api)?;
        device.set_blocking_mode(true)?;

        let mut hid = Self {
            device,
            channel_id: [0u8; 4],
            response_timeout: timeout,
        };
        hid.init()?;
        Ok(hid)
    }

    /// Send a `CTAPHID_INIT` to get a channel ID.
    fn init(&mut self) -> Result<()> {
        // Generate a random nonce
        let nonce: [u8; 8] = rand::random();
        vlog!("CTAPHID_INIT: sending nonce {}", hex::encode(nonce));
        let frames = build_ctaphid_frames(&CTAPHID_BROADCAST_CID, CTAPHID_INIT, &nonce)?;
        for frame in &frames {
            let encoded = frame.encode()?;
            self.device.write(&encoded)?;
        }

        let response = self.recv_response(CTAPHID_INIT, Duration::from_secs(5))?;
        if response.len() < 12 {
            return Err(SoloError::ProtocolError(
                "CTAPHID_INIT response too short".into(),
            ));
        }
        // Response: nonce[8] | channel_id[4] | ...
        self.channel_id.copy_from_slice(
            response.get(8..12).ok_or_else(|| {
                SoloError::ProtocolError("CTAPHID_INIT response too short".into())
            })?,
        );
        vlog!(
            "CTAPHID_INIT: assigned channel_id {}",
            hex::encode(self.channel_id)
        );
        Ok(())
    }

    /// Send a command with payload, receive and return the response payload.
    ///
    /// # Errors
    /// Returns an error if the command cannot be sent or no valid response is
    /// received before the timeout.
    pub fn send_recv(&self, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        self.send(cmd, data)?;
        self.recv_response(cmd, self.response_timeout)
    }

    /// Send a command with payload.
    ///
    /// # Errors
    /// Returns an error if the payload cannot be framed or encoded, or writing
    /// to the HID device fails.
    pub fn send(&self, cmd: u8, data: &[u8]) -> Result<()> {
        vlog!(
            "HID send: cmd=0x{:02X} len={} data={}",
            cmd,
            data.len(),
            if data.len() <= 64 {
                hex::encode(data)
            } else {
                format!("{}...", hex::encode(data.get(..64).unwrap_or(data)))
            }
        );
        let frames = build_ctaphid_frames(&self.channel_id, cmd, data)?;
        vlog!("HID send: {} frame(s)", frames.len());
        for frame in &frames {
            let encoded = frame.encode()?;
            self.device.write(&encoded)?;
        }
        Ok(())
    }

    /// Read a single HID frame from the device, stripping the platform report-ID
    /// byte when present. Returns `Ok(None)` when the read timed out with no data.
    fn read_frame(&self) -> Result<Option<CtapHidFrame>> {
        let mut buf = [0u8; 65];
        let n = self
            .device
            .read_timeout(&mut buf, 500)
            .map_err(|e| SoloError::DeviceError(format!("HID read error: {e}")))?;

        if n == 0 {
            return Ok(None);
        }

        // The HID report may or may not include the report ID byte depending on platform.
        // hidapi on most platforms does NOT include the report ID byte in the read buffer.
        let raw = buf
            .get(..n)
            .ok_or_else(|| SoloError::ProtocolError("HID read length invalid".into()))?;
        // If first byte looks like a report ID (0x00), skip it
        let frame_bytes = if n >= 65
            && *raw
                .first()
                .ok_or_else(|| SoloError::ProtocolError("HID read buffer empty".into()))?
                == 0
        {
            raw.get(1..65)
                .ok_or_else(|| SoloError::ProtocolError("HID read buffer too short".into()))?
        } else if n >= 64 {
            raw.get(..64)
                .ok_or_else(|| SoloError::ProtocolError("HID read buffer too short".into()))?
        } else {
            // pad to 64
            raw.get(..n)
                .ok_or_else(|| SoloError::ProtocolError("HID read length invalid".into()))?
        };

        Ok(Some(CtapHidFrame::parse(frame_bytes)?))
    }

    /// Receive a response for a given command, with timeout.
    ///
    /// # Errors
    /// Returns an error if no response arrives before the timeout, the device
    /// returns a CTAPHID error, a HID read fails, or the frames cannot be
    /// reassembled.
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
            let Some(frame) = self.read_frame()? else {
                continue;
            };

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
                            "CTAPHID error: {code:02x}"
                        )));
                    }
                    vlog!(
                        "HID recv: init frame cmd=0x{:02X} bcnt={} first_data={}",
                        cmd,
                        bcnt,
                        hex::encode(data.get(..data.len().min(16)).unwrap_or(data))
                    );
                    if *cmd != (expected_cmd & 0x7F) {
                        vlog!(
                            "HID recv: unexpected cmd 0x{:02X} (want 0x{:02X}), skipping",
                            cmd,
                            expected_cmd & 0x7F
                        );
                        continue;
                    }
                    total_bcnt = Some(usize::from(*bcnt));
                    collected = data.len().min(usize::from(*bcnt));
                    frames.clear();
                    frames.push(frame);
                }
                FramePayload::Cont { seq, .. } => {
                    vlog!("HID recv: cont frame seq={}", seq);
                    if let Some(tb) = total_bcnt {
                        frames.push(frame.clone());
                        if let FramePayload::Cont { data, .. } = &frame.payload {
                            collected = collected.checked_add(data.len()).ok_or_else(|| {
                                SoloError::ProtocolError("response length overflow".into())
                            })?;
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
                format!("{}...", hex::encode(payload.get(..32).unwrap_or(&payload)))
            }
        );
        Ok(payload)
    }

    /// Send a vendor (bootloader) command packet and return the response payload.
    ///
    /// Packet format: [cmd(1)] [addr(3) LE] [TAG(4)] [`length_be(2)`] [data]
    ///
    /// The bootloader responds with [status(1)] [payload...]. This method checks
    /// the status byte and strips it, returning only the payload on success.
    ///
    /// # Errors
    /// Returns an error if the packet cannot be built (data too long), the
    /// command cannot be sent or received (device/transport error or timeout),
    /// or the bootloader returns a non-zero status.
    pub fn send_bootloader_cmd(&self, cmd: u8, addr: u32, data: &[u8]) -> Result<Vec<u8>> {
        vlog!(
            "bootloader cmd=0x{:02X} addr=0x{:08X} data_len={}",
            cmd,
            addr,
            data.len()
        );
        // [cmd(1)] [addr(3) LE] [TAG(4)] [length_be(2)] [data]; errors if
        // data is longer than the 16-bit length field can express.
        let packet = build_bootloader_packet(cmd, addr, data)?;

        let resp = self.send_recv(CMD_BOOT, &packet)?;

        // First byte of bootloader response is a status code (0x00 = success)
        if resp.is_empty() {
            return Ok(resp);
        }
        let status = *resp
            .first()
            .ok_or_else(|| SoloError::ProtocolError("empty bootloader response".into()))?;
        if status != 0x00 {
            return Err(SoloError::ProtocolError(format!(
                "Bootloader error status: 0x{status:02X}"
            )));
        }
        Ok(resp
            .get(1..)
            .ok_or_else(|| SoloError::ProtocolError("bootloader response too short".into()))?
            .to_vec())
    }
}

impl crate::device::HidDevice for SoloHid {
    fn send_recv(&self, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        Self::send_recv(self, cmd, data)
    }

    fn send_bootloader_cmd(&self, cmd: u8, addr: u32, data: &[u8]) -> Result<Vec<u8>> {
        Self::send_bootloader_cmd(self, cmd, addr, data)
    }

    fn send(&self, cmd: u8, data: &[u8]) -> Result<()> {
        Self::send(self, cmd, data)
    }
}
