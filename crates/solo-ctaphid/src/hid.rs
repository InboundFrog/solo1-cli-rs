//! CTAPHID transport over USB HID — `HidTransport`, `HidDeviceInfo`, `list_devices`.

use std::time::{Duration, Instant};

use hidapi::{DeviceInfo, HidApi, HidDevice as HidApiDevice};

use crate::error::{Error, Result};
use crate::frame::{CtapHidFrame, FramePayload, build_ctaphid_frames, reassemble_frames};
use crate::protocol::{CTAPHID_BROADCAST_CID, CTAPHID_ERROR, CTAPHID_INIT, FIDO_USAGE, FIDO_USAGE_PAGE};

/// Selects which HID devices [`list_devices`] and [`HidTransport::open`] consider.
///
/// Filters compose, so a device crate can say "this USB ID, FIDO interface
/// only", and the CLI can say "any supported device".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceFilter {
    /// Match an exact USB vendor and product ID.
    UsbId { vendor_id: u16, product_id: u16 },
    /// Match any HID interface whose report descriptor declares the FIDO
    /// usage page and CTAPHID usage.
    Fido,
    /// Match only if every filter matches.
    AllOf(&'static [Self]),
    /// Match if any filter matches.
    AnyOf(&'static [Self]),
}

/// The identifying fields of a HID interface that [`DeviceFilter`] looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidIds {
    pub vendor_id: u16,
    pub product_id: u16,
    pub usage_page: u16,
    pub usage: u16,
}

impl From<&DeviceInfo> for HidIds {
    fn from(info: &DeviceInfo) -> Self {
        Self {
            vendor_id: info.vendor_id(),
            product_id: info.product_id(),
            usage_page: info.usage_page(),
            usage: info.usage(),
        }
    }
}

impl DeviceFilter {
    /// Whether the given hidapi device entry passes this filter.
    #[must_use]
    pub fn matches(&self, info: &DeviceInfo) -> bool {
        self.matches_ids(&HidIds::from(info))
    }

    /// Whether a device with these identifiers passes this filter.
    #[must_use]
    pub fn matches_ids(&self, ids: &HidIds) -> bool {
        match *self {
            Self::UsbId { vendor_id, product_id } => ids.vendor_id == vendor_id && ids.product_id == product_id,
            Self::Fido => ids.usage_page == FIDO_USAGE_PAGE && ids.usage == FIDO_USAGE,
            Self::AllOf(filters) => filters.iter().all(|f| f.matches_ids(ids)),
            Self::AnyOf(filters) => filters.iter().any(|f| f.matches_ids(ids)),
        }
    }
}

/// Information about a connected HID device.
#[derive(Debug, Clone)]
pub struct HidDeviceInfo {
    pub path: String,
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial: Option<String>,
    pub product: Option<String>,
    pub manufacturer: Option<String>,
}

impl From<&DeviceInfo> for HidDeviceInfo {
    fn from(d: &DeviceInfo) -> Self {
        Self {
            path: d.path().to_string_lossy().to_string(),
            vendor_id: d.vendor_id(),
            product_id: d.product_id(),
            serial: d.serial_number().map(std::string::ToString::to_string),
            product: d.product_string().map(std::string::ToString::to_string),
            manufacturer: d.manufacturer_string().map(std::string::ToString::to_string),
        }
    }
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
        .map(HidDeviceInfo::from)
        .collect();
    Ok(devices)
}

/// An open CTAPHID channel to a USB HID authenticator.
pub struct HidTransport {
    device: HidApiDevice,
    /// The device that was opened, so callers can tell which model it is.
    info: HidDeviceInfo,
    channel_id: [u8; 4],
    /// Timeout applied to each `send_recv` / `recv_response` call.
    /// The low-level `init` handshake always uses a fixed 5-second timeout.
    response_timeout: Duration,
}

impl HidTransport {
    /// The device that was opened, so callers can tell which model it is.
    #[must_use]
    pub const fn info(&self) -> &HidDeviceInfo {
        &self.info
    }

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
            return Err(Error::NoDeviceFound);
        }

        let info = if let Some(sn) = serial {
            devices
                .iter()
                .find(|d| d.serial_number() == Some(sn))
                .ok_or_else(|| Error::Device(format!("No device with serial {sn}")))?
        } else {
            if devices.len() > 1 {
                return Err(Error::NonUniqueDevice);
            }
            devices
                .first()
                .copied()
                .ok_or_else(|| Error::Device("No device available".into()))?
        };

        let device = info.open_device(&api)?;
        device.set_blocking_mode(true)?;

        let mut hid = Self {
            device,
            info: HidDeviceInfo::from(info),
            channel_id: [0u8; 4],
            response_timeout: timeout,
        };
        hid.init()?;
        Ok(hid)
    }

    /// Send `CTAPHID_INIT` on the broadcast channel to get a channel ID.
    fn init(&mut self) -> Result<()> {
        let nonce: [u8; 8] = rand::random();
        log::debug!("CTAPHID_INIT: sending nonce {}", hex::encode(nonce));
        let frames = build_ctaphid_frames(&CTAPHID_BROADCAST_CID, CTAPHID_INIT, &nonce)?;
        for frame in &frames {
            let encoded = frame.encode()?;
            self.device.write(&encoded)?;
        }

        self.channel_id = wait_for_init_response(&mut || self.read_frame(), nonce, Duration::from_secs(5))?;
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
            .map_err(|e| Error::Device(format!("HID read error: {e}")))?;

        if n == 0 {
            return Ok(None);
        }

        // The HID report may or may not include the report ID byte depending on platform.
        // hidapi on most platforms does NOT include the report ID byte in the read buffer.
        let raw = buf
            .get(..n)
            .ok_or_else(|| Error::Protocol("HID read length invalid".into()))?;
        // If first byte looks like a report ID (0x00), skip it
        let frame_bytes = if n >= 65
            && *raw
                .first()
                .ok_or_else(|| Error::Protocol("HID read buffer empty".into()))?
                == 0
        {
            raw.get(1..65)
                .ok_or_else(|| Error::Protocol("HID read buffer too short".into()))?
        } else if n >= 64 {
            raw.get(..64)
                .ok_or_else(|| Error::Protocol("HID read buffer too short".into()))?
        } else {
            // Short report: use the bytes as they are.
            raw.get(..n)
                .ok_or_else(|| Error::Protocol("HID read length invalid".into()))?
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
        receive_message(&mut || self.read_frame(), self.channel_id, expected_cmd, timeout)
    }
}

/// Read frames from `read_frame` until one complete message for `channel_id`
/// with command `expected_cmd` has arrived.
fn receive_message(
    read_frame: &mut impl FnMut() -> Result<Option<CtapHidFrame>>,
    channel_id: [u8; 4],
    expected_cmd: u8,
    timeout: Duration,
) -> Result<Vec<u8>> {
    log::debug!("HID recv: waiting for cmd=0x{expected_cmd:02X}");
    let start = Instant::now();
    let mut frames: Vec<CtapHidFrame> = Vec::new();
    let mut total_bcnt: Option<usize> = None;
    let mut collected: usize = 0;

    loop {
        if start.elapsed() > timeout {
            return Err(Error::Timeout);
        }
        let Some(frame) = read_frame()? else {
            continue;
        };

        // Broadcast frames are only valid for the INIT response, where the caller
        // asks for the broadcast channel.
        if frame.channel_id != channel_id {
            log::debug!("HID recv: ignoring frame for channel {}", hex::encode(frame.channel_id));
            continue;
        }

        match &frame.payload {
            FramePayload::Init { cmd, bcnt, data } => {
                // Check for error
                if *cmd == CTAPHID_ERROR & 0x7F {
                    let code = data.first().copied().unwrap_or(0);
                    log::debug!("HID recv: CTAPHID_ERROR code=0x{code:02X}");
                    return Err(Error::Protocol(format!("CTAPHID error: {code:02x}")));
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
                    // Continuation frames must count 0, 1, 2 and so on.
                    let expected = frames.len().checked_sub(1).and_then(|n| u8::try_from(n).ok());
                    if Some(*seq) != expected {
                        return Err(Error::Protocol(format!(
                            "CTAPHID frame out of order: got sequence {seq}, expected {expected:?}"
                        )));
                    }
                    frames.push(frame.clone());
                    if let FramePayload::Cont { data, .. } = &frame.payload {
                        collected = collected
                            .checked_add(data.len())
                            .ok_or_else(|| Error::Protocol("response length overflow".into()))?;
                    }
                    if collected >= tb {
                        break;
                    }
                }
            }
        }

        if let Some(tb) = total_bcnt
            && collected >= tb
        {
            break;
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

/// Read frames until the `CTAPHID_INIT` response that echoes `nonce` arrives,
/// and return the channel id it assigns.
///
/// Responses for other nonces belong to other applications on the broadcast
/// channel. They are ignored.
fn wait_for_init_response(
    read_frame: &mut impl FnMut() -> Result<Option<CtapHidFrame>>,
    nonce: [u8; 8],
    timeout: Duration,
) -> Result<[u8; 4]> {
    let start = Instant::now();
    loop {
        let remaining = timeout.checked_sub(start.elapsed()).ok_or(Error::Timeout)?;
        let response = receive_message(read_frame, CTAPHID_BROADCAST_CID, CTAPHID_INIT, remaining)?;
        // Response: nonce[8] | channel_id[4] | ...
        if response.get(..8) != Some(nonce.as_slice()) {
            log::debug!("CTAPHID_INIT: ignoring response with a different nonce");
            continue;
        }
        return response
            .get(8..12)
            .and_then(|cid| <[u8; 4]>::try_from(cid).ok())
            .ok_or_else(|| Error::Protocol("CTAPHID_INIT response too short".into()));
    }
}

impl crate::HidDevice for HidTransport {
    fn send_recv(&self, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
        Self::send_recv(self, cmd, data)
    }

    fn send(&self, cmd: u8, data: &[u8]) -> Result<()> {
        Self::send(self, cmd, data)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use std::collections::VecDeque;

    use super::*;

    /// Frames as the device would send them: full 64-byte reports, parsed back.
    fn wire(cid: [u8; 4], cmd: u8, data: &[u8]) -> VecDeque<CtapHidFrame> {
        build_ctaphid_frames(&cid, cmd, data)
            .unwrap()
            .iter()
            .map(|f| CtapHidFrame::parse(f.encode().unwrap().get(1..).unwrap()).unwrap())
            .collect()
    }

    const SOLO_LIKE: DeviceFilter = DeviceFilter::UsbId {
        vendor_id: 0x1234,
        product_id: 0x5678,
    };
    const SOLO_LIKE_FIDO: DeviceFilter = DeviceFilter::AllOf(&[SOLO_LIKE, DeviceFilter::Fido]);
    const OTHER: DeviceFilter = DeviceFilter::UsbId {
        vendor_id: 0xAAAA,
        product_id: 0xBBBB,
    };

    fn ids(vendor_id: u16, product_id: u16, usage_page: u16, usage: u16) -> HidIds {
        HidIds {
            vendor_id,
            product_id,
            usage_page,
            usage,
        }
    }

    #[test]
    fn test_usb_id_filter() {
        assert!(SOLO_LIKE.matches_ids(&ids(0x1234, 0x5678, 0, 0)));
        assert!(!SOLO_LIKE.matches_ids(&ids(0x1234, 0x0000, 0, 0)));
    }

    #[test]
    fn test_fido_filter_needs_usage_page_and_usage() {
        assert!(DeviceFilter::Fido.matches_ids(&ids(1, 2, FIDO_USAGE_PAGE, FIDO_USAGE)));
        assert!(!DeviceFilter::Fido.matches_ids(&ids(1, 2, FIDO_USAGE_PAGE, 0x02)));
        // A keyboard interface on the same device must not match.
        assert!(!DeviceFilter::Fido.matches_ids(&ids(1, 2, 0x0001, 0x06)));
    }

    #[test]
    fn test_all_of_requires_every_filter() {
        assert!(SOLO_LIKE_FIDO.matches_ids(&ids(0x1234, 0x5678, FIDO_USAGE_PAGE, FIDO_USAGE)));
        assert!(!SOLO_LIKE_FIDO.matches_ids(&ids(0x1234, 0x5678, 0x0001, 0x06)));
        assert!(!SOLO_LIKE_FIDO.matches_ids(&ids(0xAAAA, 0xBBBB, FIDO_USAGE_PAGE, FIDO_USAGE)));
    }

    /// A nonce that differs from `nonce` in the first byte.
    fn other_nonce(mut nonce: [u8; 8]) -> [u8; 8] {
        nonce[0] ^= 0xFF;
        nonce
    }

    #[test]
    fn test_init_ignores_response_with_other_nonce() {
        let nonce = rand::random::<[u8; 8]>();
        let mut other = other_nonce(nonce).to_vec();
        other.extend_from_slice(&[0xAA; 4]);
        let mut ours = nonce.to_vec();
        ours.extend_from_slice(&[0xBB; 4]);
        let mut queue = wire(CTAPHID_BROADCAST_CID, CTAPHID_INIT, &other);
        queue.extend(wire(CTAPHID_BROADCAST_CID, CTAPHID_INIT, &ours));
        let cid = wait_for_init_response(&mut || Ok(queue.pop_front()), nonce, Duration::from_secs(1)).unwrap();
        assert_eq!(cid, [0xBB; 4]);
    }

    #[test]
    fn test_init_times_out_when_only_other_nonces_answer() {
        let nonce = rand::random::<[u8; 8]>();
        let mut other = other_nonce(nonce).to_vec();
        other.extend_from_slice(&[0xAA; 4]);
        let mut queue = wire(CTAPHID_BROADCAST_CID, CTAPHID_INIT, &other);
        let err = wait_for_init_response(&mut || Ok(queue.pop_front()), nonce, Duration::from_millis(50)).unwrap_err();
        assert!(matches!(err, Error::Timeout));
    }

    #[test]
    fn test_receive_ignores_broadcast_frames_on_own_channel() {
        let cid = [1, 2, 3, 4];
        let mut queue = wire(CTAPHID_BROADCAST_CID, crate::protocol::CTAPHID_PING, b"stray");
        queue.extend(wire(cid, crate::protocol::CTAPHID_PING, b"mine"));
        let got = receive_message(
            &mut || Ok(queue.pop_front()),
            cid,
            crate::protocol::CTAPHID_PING,
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(got, b"mine");
    }

    #[test]
    fn test_receive_rejects_out_of_order_continuation() {
        let cid = [1, 2, 3, 4];
        let mut queue = wire(cid, crate::protocol::CTAPHID_PING, &[0x42; 150]);
        // Drop the frame with sequence 0, so sequence 1 arrives first.
        queue.remove(1);
        let err = receive_message(
            &mut || Ok(queue.pop_front()),
            cid,
            crate::protocol::CTAPHID_PING,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn test_receive_does_not_return_short_message() {
        let cid = [1, 2, 3, 4];
        // The init frame announces 20 bytes but the report carries only 10.
        let mut raw = [0u8; 17];
        raw[..4].copy_from_slice(&cid);
        raw[4] = crate::protocol::CTAPHID_PING;
        raw[6] = 20;
        let mut queue = VecDeque::from([CtapHidFrame::parse(&raw).unwrap()]);
        let err = receive_message(
            &mut || Ok(queue.pop_front()),
            cid,
            crate::protocol::CTAPHID_PING,
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Timeout));
    }

    #[test]
    fn test_receive_reports_ctaphid_error() {
        let cid = [1, 2, 3, 4];
        let mut queue = wire(cid, CTAPHID_ERROR, &[0x06]);
        let err = receive_message(
            &mut || Ok(queue.pop_front()),
            cid,
            crate::protocol::CTAPHID_PING,
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(&err, Error::Protocol(m) if m.contains("06")));
    }

    #[test]
    fn test_any_of_accepts_either_filter() {
        const EITHER: DeviceFilter = DeviceFilter::AnyOf(&[SOLO_LIKE, OTHER]);
        assert!(EITHER.matches_ids(&ids(0x1234, 0x5678, 0, 0)));
        assert!(EITHER.matches_ids(&ids(0xAAAA, 0xBBBB, 0, 0)));
        assert!(!EITHER.matches_ids(&ids(0x1111, 0x2222, 0, 0)));
    }
}
