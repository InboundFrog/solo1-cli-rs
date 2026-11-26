//! ST DFU (Device Firmware Upgrade) protocol implementation via libusb.
//!
//! Implements USB DFU over control transfers for STM32 devices.

use std::time::{Duration, Instant};

use rusb::{Context, DeviceHandle, UsbContext};

use crate::error::{Error, Result};
use crate::protocol::{SOLO_DFU_PID, SOLO_VID};

/// DFU transfer chunk size in bytes.
pub const DFU_CHUNK_SIZE: u32 = 2048;

// DFU request codes
pub const DFU_DNLOAD: u8 = 0x01;
pub const DFU_UPLOAD: u8 = 0x02;
pub const DFU_GETSTATUS: u8 = 0x03;
pub const DFU_CLRSTATUS: u8 = 0x04;

// DFU states
pub const DFU_STATE_IDLE: u8 = 0x02;
pub const DFU_STATE_DOWNLOAD_IDLE: u8 = 0x05;
pub const DFU_STATE_BUSY: u8 = 0x04;
pub const DFU_STATE_DOWNLOAD_SYNC: u8 = 0x03;
pub const DFU_STATE_UPLOAD_IDLE: u8 = 0x09;
pub const DFU_STATE_ERROR: u8 = 0x0A;
pub const DFU_STATE_MANIFEST_SYNC: u8 = 0x06;
pub const DFU_STATE_MANIFEST: u8 = 0x07;

/// Longest single sleep between status polls. The device reports its own poll
/// time (up to 24 bits of milliseconds), so a bad value must not stall us.
pub const DFU_MAX_POLL_SLEEP: Duration = Duration::from_secs(1);

/// Longest total time to wait for the device to leave the busy state. A mass
/// erase can take several seconds.
pub const DFU_BUSY_DEADLINE: Duration = Duration::from_secs(30);

/// How often `get_status` retries after a pipe error (as in the reference).
const DFU_STATUS_RETRIES: u8 = 3;

/// Pause between `get_status` retries.
const DFU_STATUS_RETRY_PAUSE: Duration = Duration::from_millis(10);

pub const DFU_INTERFACE: u8 = 0;
/// Alternate setting of the DFU interface that the reference tool selects.
pub const DFU_ALT: u8 = 1;

/// First address of the main flash.
pub const FLASH_BASE: u32 = 0x0800_0000;

/// DFU status structure.
#[derive(Debug, Clone)]
pub struct DfuStatus {
    pub status: u8,
    pub poll_timeout_ms: u32,
    pub state: u8,
    pub istring: u8,
}

impl DfuStatus {
    /// Parse a 6-byte `DFU_GETSTATUS` response.
    ///
    /// # Errors
    /// Returns an error if the input is shorter than 6 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 6] = bytes
            .get(..6)
            .ok_or_else(|| Error::Protocol("DFU status response too short".into()))?
            .try_into()
            .map_err(|_| Error::Protocol("DFU status response too short".into()))?;
        Ok(Self {
            status: bytes[0],
            poll_timeout_ms: u32::from(bytes[1]) | (u32::from(bytes[2]) << 8) | (u32::from(bytes[3]) << 16),
            state: bytes[4],
            istring: bytes[5],
        })
    }

    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.status == 0x00
    }
}

/// How long to sleep for a device poll time, capped at `DFU_MAX_POLL_SLEEP`.
fn poll_sleep(poll_timeout_ms: u32) -> Duration {
    Duration::from_millis(u64::from(poll_timeout_ms)).min(DFU_MAX_POLL_SLEEP)
}

/// Open the DFU device via libusb.
///
/// # Errors
/// Returns an error if the libusb context cannot be created, the device list
/// cannot be read, opening the device fails, or no ST DFU device (PID 0xDF11)
/// is present. Devices whose descriptor cannot be read are skipped.
pub fn open_dfu_device() -> Result<DeviceHandle<Context>> {
    let context = Context::new()?;
    let devices = context.devices()?;
    for device in devices.iter() {
        // A device we cannot read is not ours. Skip it and keep scanning.
        let Ok(desc) = device.device_descriptor() else {
            continue;
        };
        if desc.vendor_id() == SOLO_VID && desc.product_id() == SOLO_DFU_PID {
            let handle = device.open()?;
            return Ok(handle);
        }
    }
    Err(Error::Device("No ST DFU device found (PID 0xDF11)".into()))
}

/// The USB control transfers the DFU logic needs. The real implementation
/// uses libusb; tests use a fake that records the transfers.
trait Transport {
    /// Send a class request to the DFU interface (host to device).
    fn control_out(&self, request: u8, value: u16, data: &[u8]) -> Result<()>;
    /// Read a class request from the DFU interface (device to host).
    fn control_in(&self, request: u8, value: u16, buf: &mut [u8]) -> Result<usize>;
}

/// libusb transport for an opened ST DFU device.
struct UsbTransport {
    handle: DeviceHandle<Context>,
}

impl Transport for UsbTransport {
    fn control_out(&self, request: u8, value: u16, data: &[u8]) -> Result<()> {
        self.handle
            .write_control(
                0x21, // bmRequestType: host->device, class, interface
                request,
                value,
                u16::from(DFU_INTERFACE),
                data,
                Duration::from_secs(5),
            )
            .map_err(Error::Usb)?;
        Ok(())
    }

    fn control_in(&self, request: u8, value: u16, buf: &mut [u8]) -> Result<usize> {
        self.handle
            .read_control(
                0xA1, // bmRequestType: device->host, class, interface
                request,
                value,
                u16::from(DFU_INTERFACE),
                buf,
                Duration::from_secs(5),
            )
            .map_err(Error::Usb)
    }
}

/// Map a flash address to the DFU block number: `(address - base) / page + 2`.
///
/// # Errors
/// Returns an error if the address is below the flash base, is not a multiple
/// of the page size above it, or gives a block number that does not fit in
/// 16 bits.
fn addr_to_block(address: u32) -> Result<u16> {
    let bad = || {
        Error::Protocol(format!(
            "DFU address 0x{address:08X} is not a page-aligned flash address"
        ))
    };
    let offset = address.checked_sub(FLASH_BASE).ok_or_else(bad)?;
    if offset.checked_rem(DFU_CHUNK_SIZE) != Some(0) {
        return Err(bad());
    }
    let page = offset.checked_div(DFU_CHUNK_SIZE).ok_or_else(bad)?;
    let block = page
        .checked_add(2)
        .ok_or_else(|| Error::Protocol("DFU block number overflow".into()))?;
    u16::try_from(block).map_err(|_| Error::Protocol(format!("DFU address 0x{address:08X} is beyond the block range")))
}

/// The DFU protocol steps, on top of a transport.
struct Dfu<T: Transport> {
    io: T,
    busy_deadline: Duration,
}

impl<T: Transport> Dfu<T> {
    const fn new(io: T) -> Self {
        Self {
            io,
            busy_deadline: DFU_BUSY_DEADLINE,
        }
    }

    /// Query the current DFU status via `DFU_GETSTATUS`. Retries a few times
    /// when the device stalls the transfer (pipe error), as the reference does.
    fn get_status(&self) -> Result<DfuStatus> {
        let mut buf = [0u8; 6];
        let mut retries = DFU_STATUS_RETRIES;
        loop {
            match self.io.control_in(DFU_GETSTATUS, 0, &mut buf) {
                Ok(_) => break,
                Err(Error::Usb(rusb::Error::Pipe)) if retries > 0 => {
                    retries = retries.saturating_sub(1);
                    std::thread::sleep(DFU_STATUS_RETRY_PAUSE);
                }
                Err(Error::Usb(rusb::Error::Pipe)) => {
                    return Err(Error::Device("Failed to get status from DFU".into()));
                }
                Err(e) => return Err(e),
            }
        }
        let status = DfuStatus::parse(&buf)?;
        log::debug!(
            "DFU_GETSTATUS: status=0x{:02X} state=0x{:02X} poll_ms={}",
            status.status,
            status.state,
            status.poll_timeout_ms
        );
        Ok(status)
    }

    fn clear_status(&self) -> Result<()> {
        self.io.control_out(DFU_CLRSTATUS, 0, &[])
    }

    /// Clear an error state left over from an earlier session.
    fn init(&self) -> Result<()> {
        if self.get_status()?.state == DFU_STATE_ERROR {
            self.clear_status()?;
        }
        Ok(())
    }

    /// Make sure the device is in one of `states`. If not, send `CLRSTATUS`
    /// twice and check again, as the reference does.
    fn ensure_state(&self, states: &[u8], what: &str) -> Result<()> {
        if states.contains(&self.get_status()?.state) {
            return Ok(());
        }
        self.clear_status()?;
        self.clear_status()?;
        if states.contains(&self.get_status()?.state) {
            return Ok(());
        }
        Err(Error::Device(format!("DFU device not in correct state for {what}")))
    }

    /// Poll while the device is in the download-busy state.
    fn wait_while_busy(&self) -> Result<DfuStatus> {
        let start = Instant::now();
        loop {
            let status = self.get_status()?;
            if !status.is_ok() {
                return Err(Error::Device(format!(
                    "DFU error status: 0x{:02x} state: 0x{:02x}",
                    status.status, status.state
                )));
            }
            if status.state != DFU_STATE_BUSY {
                return Ok(status);
            }
            if start.elapsed() >= self.busy_deadline {
                return Err(Error::Device("Timed out waiting for the DFU device to finish".into()));
            }
            std::thread::sleep(poll_sleep(status.poll_timeout_ms));
        }
    }

    /// Wait for the device to finish and check that it is back in download-idle.
    fn finish_download(&self) -> Result<()> {
        let status = self.wait_while_busy()?;
        if status.state != DFU_STATE_DOWNLOAD_IDLE {
            return Err(Error::Device(format!(
                "DFU device not idle after download, state: 0x{:02x}",
                status.state
            )));
        }
        Ok(())
    }

    /// Erase all flash: `DNLOAD` block 0 with the single byte 0x41.
    fn mass_erase(&self) -> Result<()> {
        self.io.control_out(DFU_DNLOAD, 0, &[0x41])?;
        self.finish_download()
    }

    /// Write one page to a DFU block.
    fn write_page(&self, block: u16, data: &[u8]) -> Result<()> {
        self.ensure_state(&[DFU_STATE_IDLE, DFU_STATE_DOWNLOAD_IDLE], "writing memory")?;
        self.io.control_out(DFU_DNLOAD, block, data)?;
        self.finish_download()
    }

    /// Erase the flash, then write `firmware` page by page, starting at
    /// `address`. After each page, `on_progress(done, total)` is called.
    fn program(&self, address: u32, firmware: &[u8], mut on_progress: impl FnMut(usize, usize)) -> Result<()> {
        let first_block = addr_to_block(address)?;
        let chunk_size =
            usize::try_from(DFU_CHUNK_SIZE).map_err(|_| Error::Protocol("DFU chunk size overflow".into()))?;
        let total_chunks = firmware.len().div_ceil(chunk_size);

        match self.mass_erase() {
            Ok(()) => {}
            Err(Error::Usb(_)) => {
                // The reference does a garbage write, which is sometimes
                // needed before the mass erase works, and tries once more.
                let filler = b"ZZFF".repeat(chunk_size.div_ceil(4));
                self.write_page(
                    addr_to_block(FLASH_BASE.saturating_add(DFU_CHUNK_SIZE.saturating_mul(10)))?,
                    &filler,
                )?;
                self.mass_erase()?;
            }
            Err(e) => return Err(e),
        }

        for (index, chunk) in firmware.chunks(chunk_size).enumerate() {
            let block = u16::try_from(index)
                .ok()
                .and_then(|i| first_block.checked_add(i))
                .ok_or_else(|| Error::Protocol("DFU block number overflow".into()))?;
            // Pad the last page with the erased-flash value.
            let mut page = chunk.to_vec();
            page.resize(chunk_size, 0xFF);
            self.write_page(block, &page)?;
            on_progress(index.saturating_add(1), total_chunks);
        }
        Ok(())
    }
}

/// DFU programmer for STM32.
pub struct DfuDevice {
    dfu: Dfu<UsbTransport>,
}

impl DfuDevice {
    /// Open the ST DFU device, claim its interface and select the alternate
    /// setting used for flash. Clears a leftover error state.
    ///
    /// # Errors
    /// Returns an error if no ST DFU device is found, the device cannot be
    /// opened, the DFU interface cannot be claimed, the alternate setting
    /// cannot be selected, or the status cannot be read.
    pub fn open() -> Result<Self> {
        let handle = open_dfu_device()?;
        handle.claim_interface(DFU_INTERFACE).map_err(Error::Usb)?;
        handle
            .set_alternate_setting(DFU_INTERFACE, DFU_ALT)
            .map_err(Error::Usb)?;
        let dfu = Dfu::new(UsbTransport { handle });
        dfu.init()?;
        Ok(Self { dfu })
    }

    /// Erase the flash and program a firmware binary at `address`.
    ///
    /// `address` must be in flash and a multiple of the page size. The device
    /// is not told to leave DFU mode. After each page,
    /// `on_progress(pages_written, total_pages)` is called.
    ///
    /// # Errors
    /// Returns an error if the address is not valid, a USB transfer fails, the
    /// device reports an error or stays busy too long, or the block number
    /// arithmetic overflows.
    pub fn program(&self, address: u32, firmware: &[u8], on_progress: impl FnMut(usize, usize)) -> Result<()> {
        self.dfu.program(address, firmware, on_progress)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unnecessary_wraps,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::cast_possible_truncation
    )]
    use super::*;

    #[test]
    fn test_dfu_status_parse() {
        let bytes = [0x00, 0x0A, 0x00, 0x00, 0x05, 0x00];
        let status = DfuStatus::parse(&bytes).unwrap();
        assert!(status.is_ok());
        assert_eq!(status.poll_timeout_ms, 10);
        assert_eq!(status.state, DFU_STATE_DOWNLOAD_IDLE);
        assert_eq!(status.istring, 0);
    }

    #[test]
    fn test_dfu_status_error() {
        let bytes = [0x05, 0x00, 0x00, 0x00, 0x0A, 0x00];
        let status = DfuStatus::parse(&bytes).unwrap();
        assert!(!status.is_ok());
        assert_eq!(status.state, DFU_STATE_ERROR);
    }

    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// One control transfer, as seen by the fake device.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Xfer {
        Out { request: u8, value: u16, data: Vec<u8> },
        In { request: u8, value: u16, len: usize },
    }

    /// Fake transport. It records every transfer and answers reads from a script.
    #[derive(Default)]
    struct Fake {
        log: RefCell<Vec<Xfer>>,
        ins: RefCell<VecDeque<Result<Vec<u8>>>>,
        outs: RefCell<VecDeque<Result<()>>>,
        /// Answer for reads once `ins` is empty. Without it, a read fails.
        default_in: Option<Vec<u8>>,
    }

    impl Fake {
        fn with_ins(ins: Vec<Result<Vec<u8>>>) -> Self {
            Self {
                ins: RefCell::new(ins.into()),
                ..Self::default()
            }
        }

        fn log(&self) -> Vec<Xfer> {
            self.log.borrow().clone()
        }
    }

    impl Transport for Fake {
        fn control_out(&self, request: u8, value: u16, data: &[u8]) -> Result<()> {
            self.log.borrow_mut().push(Xfer::Out {
                request,
                value,
                data: data.to_vec(),
            });
            self.outs.borrow_mut().pop_front().unwrap_or(Ok(()))
        }

        fn control_in(&self, request: u8, value: u16, buf: &mut [u8]) -> Result<usize> {
            self.log.borrow_mut().push(Xfer::In {
                request,
                value,
                len: buf.len(),
            });
            let reply = match self.ins.borrow_mut().pop_front() {
                Some(r) => r?,
                None => self
                    .default_in
                    .clone()
                    .ok_or_else(|| Error::Device("fake: no reply scripted".into()))?,
            };
            buf[..reply.len()].copy_from_slice(&reply);
            Ok(reply.len())
        }
    }

    /// A `GETSTATUS` reply with status OK, no poll time, and the given state.
    fn st(state: u8) -> Result<Vec<u8>> {
        Ok(vec![0, 0, 0, 0, state, 0])
    }

    fn get_status_xfer() -> Xfer {
        Xfer::In {
            request: DFU_GETSTATUS,
            value: 0,
            len: 6,
        }
    }

    fn dnload(value: u16, data: &[u8]) -> Xfer {
        Xfer::Out {
            request: DFU_DNLOAD,
            value,
            data: data.to_vec(),
        }
    }

    fn clrstatus() -> Xfer {
        Xfer::Out {
            request: DFU_CLRSTATUS,
            value: 0,
            data: vec![],
        }
    }

    #[test]
    fn test_addr_to_block() {
        assert_eq!(addr_to_block(0x0800_0000).unwrap(), 2);
        assert_eq!(addr_to_block(0x0800_0800).unwrap(), 3);
        assert_eq!(addr_to_block(0x0800_5000).unwrap(), 12);
        // The last block that fits in 16 bits.
        assert_eq!(addr_to_block(FLASH_BASE + 65_533 * DFU_CHUNK_SIZE).unwrap(), 65_535);
        assert!(addr_to_block(FLASH_BASE + 65_534 * DFU_CHUNK_SIZE).is_err());
        assert!(addr_to_block(0x07FF_F800).is_err());
        assert!(addr_to_block(0).is_err());
        assert!(addr_to_block(0x0800_0001).is_err());
        assert!(addr_to_block(0x0800_0400).is_err());
    }

    #[test]
    fn test_program_erases_then_writes_addressed_pages() {
        // 2049 bytes make two pages. Start at the second flash page (block 3).
        let fw = vec![0xAB; 2049];
        let fake = Fake::with_ins(vec![
            // mass erase: busy, then idle
            st(DFU_STATE_BUSY),
            st(DFU_STATE_DOWNLOAD_IDLE),
            // page 1: state check, busy, idle
            st(DFU_STATE_DOWNLOAD_IDLE),
            st(DFU_STATE_BUSY),
            st(DFU_STATE_DOWNLOAD_IDLE),
            // page 2
            st(DFU_STATE_DOWNLOAD_IDLE),
            st(DFU_STATE_BUSY),
            st(DFU_STATE_DOWNLOAD_IDLE),
        ]);
        let dfu = Dfu::new(fake);
        let mut progress = vec![];
        dfu.program(0x0800_0800, &fw, |d, t| progress.push((d, t))).unwrap();

        let page1 = vec![0xAB; 2048];
        let mut page2 = vec![0xFF; 2048];
        page2[0] = 0xAB;
        let gs = get_status_xfer;
        assert_eq!(
            dfu.io.log(),
            vec![
                dnload(0, &[0x41]),
                gs(),
                gs(),
                gs(),
                dnload(3, &page1),
                gs(),
                gs(),
                gs(),
                dnload(4, &page2),
                gs(),
                gs(),
            ]
        );
        // No zero-length download at the end.
        assert!(!dfu.io.log().contains(&dnload(5, &[])));
        assert_eq!(progress, vec![(1, 2), (2, 2)]);
    }

    #[test]
    fn test_program_rejects_bad_address_before_any_transfer() {
        let dfu = Dfu::new(Fake::default());
        assert!(dfu.program(0x0800_0001, &[1], |_, _| {}).is_err());
        assert!(dfu.program(0x0000_0000, &[1], |_, _| {}).is_err());
        assert_eq!(dfu.io.log(), vec![]);
    }

    #[test]
    fn test_program_retries_mass_erase_after_filler_write() {
        let fake = Fake::with_ins(vec![
            // filler page: state check, busy, idle
            st(DFU_STATE_IDLE),
            st(DFU_STATE_BUSY),
            st(DFU_STATE_DOWNLOAD_IDLE),
            // second mass erase
            st(DFU_STATE_BUSY),
            st(DFU_STATE_DOWNLOAD_IDLE),
        ]);
        fake.outs.borrow_mut().push_back(Err(Error::Usb(rusb::Error::Io)));
        let dfu = Dfu::new(fake);
        dfu.program(FLASH_BASE, &[], |_, _| {}).unwrap();
        let gs = get_status_xfer;
        let filler = b"ZZFF".repeat(512);
        assert_eq!(
            dfu.io.log(),
            vec![
                dnload(0, &[0x41]), // fails
                gs(),
                dnload(12, &filler),
                gs(),
                gs(),
                dnload(0, &[0x41]),
                gs(),
                gs(),
            ]
        );
    }

    #[test]
    fn test_write_page_clears_status_twice_when_not_idle() {
        let fake = Fake::with_ins(vec![
            st(DFU_STATE_ERROR),
            st(DFU_STATE_IDLE),
            st(DFU_STATE_BUSY),
            st(DFU_STATE_DOWNLOAD_IDLE),
        ]);
        let dfu = Dfu::new(fake);
        dfu.write_page(2, &[1, 2]).unwrap();
        let gs = get_status_xfer;
        assert_eq!(
            dfu.io.log(),
            vec![gs(), clrstatus(), clrstatus(), gs(), dnload(2, &[1, 2]), gs(), gs()]
        );
    }

    #[test]
    fn test_write_page_fails_when_state_stays_wrong() {
        let fake = Fake::with_ins(vec![st(DFU_STATE_ERROR), st(DFU_STATE_ERROR)]);
        let dfu = Dfu::new(fake);
        assert!(dfu.write_page(2, &[1]).is_err());
        assert!(!dfu.io.log().contains(&dnload(2, &[1])));
    }

    #[test]
    fn test_init_clears_error_state_only() {
        let dfu = Dfu::new(Fake::with_ins(vec![st(DFU_STATE_ERROR)]));
        dfu.init().unwrap();
        assert_eq!(dfu.io.log(), vec![get_status_xfer(), clrstatus()]);

        let dfu = Dfu::new(Fake::with_ins(vec![st(DFU_STATE_IDLE)]));
        dfu.init().unwrap();
        assert_eq!(dfu.io.log(), vec![get_status_xfer()]);
    }

    #[test]
    fn test_wait_while_busy_times_out() {
        let mut dfu = Dfu::new(Fake {
            default_in: Some(vec![0, 0, 0, 0, DFU_STATE_BUSY, 0]),
            ..Fake::default()
        });
        dfu.busy_deadline = Duration::from_millis(30);
        let err = dfu.wait_while_busy().unwrap_err();
        assert!(err.to_string().contains("Timed out"), "{err}");
    }

    #[test]
    fn test_wait_while_busy_reports_error_status() {
        let dfu = Dfu::new(Fake::with_ins(vec![Ok(vec![0x05, 0, 0, 0, DFU_STATE_ERROR, 0])]));
        assert!(dfu.wait_while_busy().is_err());
    }

    #[test]
    fn test_get_status_retries_pipe_errors() {
        let pipe = || Err(Error::Usb(rusb::Error::Pipe));
        let dfu = Dfu::new(Fake::with_ins(vec![pipe(), pipe(), pipe(), st(DFU_STATE_IDLE)]));
        assert_eq!(dfu.get_status().unwrap().state, DFU_STATE_IDLE);
        assert_eq!(dfu.io.log().len(), 4);

        let dfu = Dfu::new(Fake::with_ins(vec![pipe(), pipe(), pipe(), pipe(), st(DFU_STATE_IDLE)]));
        assert!(dfu.get_status().is_err());
        assert_eq!(dfu.io.log().len(), 4);
    }

    #[test]
    fn test_get_status_does_not_retry_other_errors() {
        let dfu = Dfu::new(Fake::with_ins(vec![
            Err(Error::Usb(rusb::Error::Io)),
            st(DFU_STATE_IDLE),
        ]));
        assert!(dfu.get_status().is_err());
        assert_eq!(dfu.io.log().len(), 1);
    }

    #[test]
    fn test_poll_sleep_is_capped() {
        assert_eq!(poll_sleep(0), Duration::ZERO);
        assert_eq!(poll_sleep(10), Duration::from_millis(10));
        // The largest 24-bit poll time (about 4.6 hours) is cut to the cap.
        assert_eq!(poll_sleep(0x00FF_FFFF), DFU_MAX_POLL_SLEEP);
    }

    #[test]
    fn test_dfu_status_parse_short() {
        let bytes = [0x00, 0x00];
        assert!(DfuStatus::parse(&bytes).is_err());
    }
}
