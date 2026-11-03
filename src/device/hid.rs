/// CTAPHID transport over USB HID — `HidTransport`, `HidDeviceInfo`, `list_devices`.
use std::time::{Duration, Instant};

use hidapi::{DeviceInfo, HidApi, HidDevice as HidApiDevice};

use crate::device::frame::{CtapHidFrame, FramePayload, build_ctaphid_frames, reassemble_frames};
use crate::device::protocol::{CTAPHID_BROADCAST_CID, CTAPHID_INIT};
use crate::error::{Result, SoloError};

/// Selects which HID devices [`list_devices`] and [`HidTransport::open`] consider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFilter {
    /// Match an exact USB vendor and product ID.
    UsbId { vendor_id: u16, product_id: u16 },
}

impl DeviceFilter {
    /// Whether the given hidapi device entry passes this filter.
    #[must_use]
    pub fn matches(&self, info: &DeviceInfo) -> bool {
        match *self {
            Self::UsbId { vendor_id, product_id } => info.vendor_id() == vendor_id && info.product_id() == product_id,
        }
    }
}

/// Information about a connected HID device.
#[derive(Debug, Clone)]
pub struct HidDeviceInfo {
    pub path: String,
    pub serial: Option<String>,
    pub product: Option<String>,
    pub manufacturer: Option<String>,
}

/// List connected HID devices that match `filter`.
///
/// # Errors
/// Returns an error if the HID API cannot be initialized.
pub fn list_devices(filter: DeviceFilter) -> Result<Vec<HidDeviceInfo>> {
    let api = HidApi::new()?;
    let devices: Vec<HidDeviceInfo> = api
        .device_list()
        .filter(|d| filter.matches(d))
        .map(|d| HidDeviceInfo {
            path: d.path().to_string_lossy().to_string(),
            serial: d.serial_number().map(std::string::ToString::to_string),
            product: d.product_string().map(std::string::ToString::to_string),
            manufacturer: d.manufacturer_string().map(std::string::ToString::to_string),
        })
        .collect();
    Ok(devices)
}

/// An open CTAPHID channel to a USB HID authenticator.
pub struct HidTransport {
    pub device: HidApiDevice,
    pub channel_id: [u8; 4],
    /// Timeout applied to each `send_recv` / `recv_response` call.
    /// The low-level `init` handshake always uses a fixed 5-second timeout.
    pub response_timeout: Duration,
}

impl HidTransport {
    /// Open a device matching `filter` by serial number (or the only matching
    /// device if `serial` is `None`).
    ///
    /// `timeout` controls how long `send_recv` and `recv_response` wait for a
    /// device reply. The low-level CTAPHID init handshake always uses a fixed
    /// 5-second timeout regardless of this value.
    ///
    /// # Errors
    /// Returns an error if the HID API cannot be initialized, no matching device
    /// is found, the requested serial does not match any device, multiple devices
    /// are present when no serial is given, the device cannot be opened, or the
    /// CTAPHID init handshake fails.
    pub fn open(filter: DeviceFilter, serial: Option<&str>, timeout: Duration) -> Result<Self> {
        let api = HidApi::new()?;
        let devices: Vec<_> = api.device_list().filter(|d| filter.matches(d)).collect();

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
        log::debug!("CTAPHID_INIT: sending nonce {}", hex::encode(nonce));
        let frames = build_ctaphid_frames(&CTAPHID_BROADCAST_CID, CTAPHID_INIT, &nonce)?;
        for frame in &frames {
            let encoded = frame.encode()?;
            self.device.write(&encoded)?;
        }

        let response = self.recv_response(CTAPHID_INIT, Duration::from_secs(5))?;
        if response.len() < 12 {
            return Err(SoloError::ProtocolError("CTAPHID_INIT response too short".into()));
        }
        // Response: nonce[8] | channel_id[4] | ...
        self.channel_id.copy_from_slice(
            response
                .get(8..12)
                .ok_or_else(|| SoloError::ProtocolError("CTAPHID_INIT response too short".into()))?,
        );
        log::debug!("CTAPHID_INIT: assigned channel_id {}", hex::encode(self.channel_id));
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
        log::debug!(
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
        log::debug!("HID send: {} frame(s)", frames.len());
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
        log::debug!("HID recv: waiting for cmd=0x{expected_cmd:02X}");
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
            let for_us = frame.channel_id == self.channel_id || frame.channel_id == CTAPHID_BROADCAST_CID;
            if !for_us {
                log::debug!("HID recv: ignoring frame for channel {}", hex::encode(frame.channel_id));
                continue;
            }

            match &frame.payload {
                FramePayload::Init { cmd, bcnt, data } => {
                    // Check for error
                    if *cmd == 0x3F {
                        // CTAPHID_ERROR
                        let code = data.first().copied().unwrap_or(0);
                        log::debug!("HID recv: CTAPHID_ERROR code=0x{code:02X}");
                        return Err(SoloError::ProtocolError(format!("CTAPHID error: {code:02x}")));
                    }
                    log::debug!(
                        "HID recv: init frame cmd=0x{:02X} bcnt={} first_data={}",
                        cmd,
                        bcnt,
                        hex::encode(data.get(..data.len().min(16)).unwrap_or(data))
                    );
                    if *cmd != (expected_cmd & 0x7F) {
                        log::debug!(
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
                    log::debug!("HID recv: cont frame seq={seq}");
                    if let Some(tb) = total_bcnt {
                        frames.push(frame.clone());
                        if let FramePayload::Cont { data, .. } = &frame.payload {
                            collected = collected
                                .checked_add(data.len())
                                .ok_or_else(|| SoloError::ProtocolError("response length overflow".into()))?;
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
        log::debug!(
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
}

impl crate::device::HidDevice for HidTransport {
    fn send_recv(&self, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        Self::send_recv(self, cmd, data)
    }

    fn send(&self, cmd: u8, data: &[u8]) -> Result<()> {
        Self::send(self, cmd, data)
    }
}
