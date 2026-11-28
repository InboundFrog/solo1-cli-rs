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

// DFU states used by the code and its tests.
//
// All DFU 1.1 device states (`bState` in the `DFU_GETSTATUS` reply), kept as a
// record of the protocol:
//
// | Value | State                  |
// |-------|------------------------|
// | 0x00  | appIDLE                |
// | 0x01  | appDETACH              |
// | 0x02  | dfuIDLE                |
// | 0x03  | dfuDNLOAD-SYNC         |
// | 0x04  | dfuDNBUSY              |
// | 0x05  | dfuDNLOAD-IDLE         |
// | 0x06  | dfuMANIFEST-SYNC       |
// | 0x07  | dfuMANIFEST            |
// | 0x08  | dfuMANIFEST-WAIT-RESET |
// | 0x09  | dfuUPLOAD-IDLE         |
// | 0x0A  | dfuERROR               |
pub const DFU_STATE_IDLE: u8 = 0x02;
pub const DFU_STATE_BUSY: u8 = 0x04;
pub const DFU_STATE_DOWNLOAD_IDLE: u8 = 0x05;
pub const DFU_STATE_MANIFEST_SYNC: u8 = 0x06;
pub const DFU_STATE_UPLOAD_IDLE: u8 = 0x09;
pub const DFU_STATE_ERROR: u8 = 0x0A;

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

/// Address of the option bytes on the STM32L432.
const OPTION_BYTES_ADDR: u32 = 0x1FFF_7800;

/// Size of the option bytes block that the reference reads and writes.
const OPTION_BYTES_LEN: usize = 16;

/// Option word bit nBOOT0 (set: boot from flash, as set by the reference).
const OPT_NBOOT0: u32 = 1 << 27;

/// Option word bit nSWBOOT0 (cleared by the reference).
const OPT_NSWBOOT0: u32 = 1 << 26;

/// DFU block number that means "at the current address pointer". The
/// reference calls `read_mem(0, 16)` and `write_page(0, m)`. Its `addr2block`
/// then gives a negative number whose low 16 bits are 2, so both transfers
/// use block 2.
const BLOCK_AT_POINTER: u16 = 2;

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

/// Choose one device from `candidates`, a list of (device, USB serial number).
///
/// With `serial`, only a device with that serial number is chosen. Without it,
/// there must be exactly one device. A device whose serial could not be read
/// has the error and never matches a `serial`. The error is shown in the
/// messages, for example a missing permission.
///
/// # Errors
/// Returns an error if the list is empty, if no device has the requested
/// serial number, if several devices have it, or if there are several devices
/// and no `serial`.
fn select_device<T, E: std::fmt::Display>(
    candidates: Vec<(T, std::result::Result<String, E>)>,
    serial: Option<&str>,
) -> Result<T> {
    const NONE: &str = "No ST DFU device found (0483:df11)";
    let count = candidates.len();
    let listed = candidates
        .iter()
        .map(|(_, s)| {
            s.as_ref()
                .map_or_else(|e| format!("unknown serial ({e})"), Clone::clone)
        })
        .collect::<Vec<_>>()
        .join(", ");
    let Some(wanted) = serial else {
        let mut it = candidates.into_iter();
        return match (it.next(), it.next()) {
            (None, _) => Err(Error::Device(NONE.into())),
            (Some((device, _)), None) => Ok(device),
            (Some(_), Some(_)) => Err(Error::Device(format!(
                "{count} ST DFU devices found ({listed}). Use --serial <serial> to choose one."
            ))),
        };
    };
    let mut matching = candidates
        .into_iter()
        .filter(|(_, s)| s.as_deref().ok() == Some(wanted));
    match (matching.next(), matching.next()) {
        (Some((device, _)), None) => Ok(device),
        (Some(_), Some(_)) => Err(Error::Device(format!(
            "More than one ST DFU device has the serial {wanted}"
        ))),
        (None, _) if count == 0 => Err(Error::Device(NONE.into())),
        (None, _) => Err(Error::Device(format!(
            "No ST DFU device with serial {wanted} (found: {listed})"
        ))),
    }
}

/// Open the ST DFU device via libusb. Every USB device with the ids of the ST
/// ROM bootloader (0483:df11) is a candidate, not only a Solo key. See
/// `select_device` for how one is chosen.
///
/// The serial number of each candidate is read by opening it. If that fails
/// (for example no permission), the error is kept and shown in the messages.
///
/// # Errors
/// Returns an error if the libusb context cannot be created, the device list
/// cannot be read, no device is chosen (none, no match for `serial`, or
/// several without `serial`), or opening the chosen device fails. Devices
/// whose descriptor cannot be read are skipped.
pub fn open_dfu_device(serial: Option<&str>) -> Result<DeviceHandle<Context>> {
    let context = Context::new()?;
    let mut candidates = Vec::new();
    for device in context.devices()?.iter() {
        // A device we cannot read is not ours. Skip it and keep scanning.
        let Ok(desc) = device.device_descriptor() else {
            continue;
        };
        if desc.vendor_id() == SOLO_VID && desc.product_id() == SOLO_DFU_PID {
            let usb_serial = device.open().and_then(|h| h.read_serial_number_string_ascii(&desc));
            candidates.push((device, usb_serial));
        }
    }
    Ok(select_device(candidates, serial)?.open()?)
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

/// The DFU block of page number `index` when the first page is `first_block`.
fn page_block(first_block: u16, index: usize) -> Result<u16> {
    u16::try_from(index)
        .ok()
        .and_then(|i| first_block.checked_add(i))
        .ok_or_else(|| Error::Protocol("DFU block number overflow".into()))
}

/// Index of the first byte where `got` differs from `expected`. If `got` is a
/// shorter copy of `expected`, this is the index where `got` ends.
fn first_difference(expected: &[u8], got: &[u8]) -> Option<usize> {
    expected
        .iter()
        .zip(got)
        .position(|(a, b)| a != b)
        .or_else(|| (got.len() < expected.len()).then_some(got.len()))
}

/// Set the boot options that leave-dfu needs: nBOOT0 on, nSWBOOT0 off.
///
/// Only bits 26 and 27 of the first little-endian word can change. Byte 0
/// holds the read-protection level, so it must never change.
const fn detach_option_bytes(mut bytes: [u8; OPTION_BYTES_LEN]) -> [u8; OPTION_BYTES_LEN] {
    if let Some(head) = bytes.first_chunk_mut::<4>() {
        let word = u32::from_le_bytes(*head);
        *head = ((word | OPT_NBOOT0) & !OPT_NSWBOOT0).to_le_bytes();
    }
    bytes
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
            let block = page_block(first_block, index)?;
            // Pad the last page with the erased-flash value.
            let mut page = chunk.to_vec();
            page.resize(chunk_size, 0xFF);
            self.write_page(block, &page)?;
            on_progress(index.saturating_add(1), total_chunks);
        }
        Ok(())
    }

    /// Read the flash back, page by page from `address`, and compare it with
    /// `firmware`. Fails at the first byte that differs.
    ///
    /// The whole image is compared, also a last page that is only partly
    /// filled. Only the bytes of the image are compared. The 0xFF padding that
    /// `program` adds to the last page is not.
    fn verify(&self, address: u32, firmware: &[u8]) -> Result<()> {
        let first_block = addr_to_block(address)?;
        let chunk_size =
            usize::try_from(DFU_CHUNK_SIZE).map_err(|_| Error::Protocol("DFU chunk size overflow".into()))?;
        for (index, chunk) in firmware.chunks(chunk_size).enumerate() {
            let got = self.read_block(page_block(first_block, index)?, chunk_size)?;
            if let Some(pos) = first_difference(chunk, &got) {
                let bad_address = index
                    .checked_mul(chunk_size)
                    .and_then(|offset| offset.checked_add(pos))
                    .and_then(|offset| u32::try_from(offset).ok())
                    .and_then(|offset| address.checked_add(offset))
                    .ok_or_else(|| Error::Protocol("DFU address overflow".into()))?;
                let show = |b: Option<&u8>| b.map_or_else(|| "no data".to_string(), |b| format!("0x{b:02X}"));
                return Err(Error::Device(format!(
                    "Flash readback differs from the firmware at address 0x{bad_address:08X}: wrote {}, read {}",
                    show(chunk.get(pos)),
                    show(got.get(pos)),
                )));
            }
        }
        Ok(())
    }

    /// Set the address pointer: `DNLOAD` block 0 with 0x21 and the address.
    fn set_addr(&self, address: u32) -> Result<()> {
        let [a0, a1, a2, a3] = address.to_le_bytes();
        self.io.control_out(DFU_DNLOAD, 0, &[0x21, a0, a1, a2, a3])?;
        self.wait_while_busy()?;
        Ok(())
    }

    /// Read up to `len` bytes from a DFU block. The device may send fewer.
    fn read_block(&self, block: u16, len: usize) -> Result<Vec<u8>> {
        self.ensure_state(&[DFU_STATE_IDLE, DFU_STATE_UPLOAD_IDLE], "reading memory")?;
        let mut buf = vec![0u8; len];
        let n = self.io.control_in(DFU_UPLOAD, block, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Read `OPTION_BYTES_LEN` bytes at the current address pointer.
    fn read_at_pointer(&self) -> Result<Vec<u8>> {
        self.read_block(BLOCK_AT_POINTER, OPTION_BYTES_LEN)
    }

    /// Write 16 bytes at the current address pointer. The device may reset
    /// when option bytes are written, so a USB error is only a warning, as in
    /// the reference.
    fn write_at_pointer(&self, bytes: &[u8; OPTION_BYTES_LEN]) -> Result<()> {
        self.wait_while_busy()?;
        let result = self
            .write_page(BLOCK_AT_POINTER, bytes)
            .and_then(|()| self.wait_while_busy().map(|_| ()));
        match result {
            Err(Error::Usb(e)) => {
                log::warn!("USB error while writing option bytes: {e}");
                Ok(())
            }
            other => other,
        }
    }

    /// Set the boot options so that the key boots its firmware or the Solo
    /// bootloader after a power cycle. Follows the reference tool.
    fn prepare_options_bytes_detach(&self) -> Result<()> {
        // From the reference: read 16 bytes and write them back before the
        // option bytes are touched. Its comment says "Necessary to prevent
        // future errors". We write only when exactly 16 bytes came back.
        match <[u8; OPTION_BYTES_LEN]>::try_from(self.read_at_pointer()?.as_slice()) {
            Ok(bytes) => self.write_at_pointer(&bytes)?,
            Err(_) => log::warn!("Short read before the option bytes. Skipping the write-back."),
        }

        self.set_addr(OPTION_BYTES_ADDR)?;
        let old = <[u8; OPTION_BYTES_LEN]>::try_from(self.read_at_pointer()?.as_slice())
            .map_err(|_| Error::Device("Could not read all 16 option bytes. Nothing was written.".into()))?;
        let new = detach_option_bytes(old);
        if new != old {
            log::info!("Rewriting option bytes...");
            self.write_at_pointer(&new)?;
        }
        Ok(())
    }

    /// Ask the device to leave DFU mode: a zero-length `DNLOAD`, then a status
    /// read.
    fn detach(&self) -> Result<()> {
        self.ensure_state(&[DFU_STATE_IDLE, DFU_STATE_DOWNLOAD_IDLE], "detaching")?;
        self.io.control_out(DFU_DNLOAD, 0, &[])?;
        self.get_status()?;
        Ok(())
    }

    /// Fix the boot options, then detach. A USB error from the detach is
    /// ignored because the device resets.
    fn leave_dfu(&self) -> Result<()> {
        self.prepare_options_bytes_detach()?;
        match self.detach() {
            Err(Error::Usb(e)) => {
                log::debug!("USB error while detaching (the device resets): {e}");
                Ok(())
            }
            other => other,
        }
    }
}

/// DFU programmer for STM32.
pub struct DfuDevice {
    dfu: Dfu<UsbTransport>,
}

impl DfuDevice {
    /// Open the ST DFU device, claim its interface and select the alternate
    /// setting used for flash. Clears a leftover error state. With `serial`,
    /// only the device with that USB serial number is used. Without it, there
    /// must be exactly one ST DFU device.
    ///
    /// # Errors
    /// Returns an error if no ST DFU device is chosen (none found, no match
    /// for `serial`, or several found without `serial`), the device cannot be
    /// opened, the DFU interface cannot be claimed, the alternate setting
    /// cannot be selected, or the status cannot be read.
    pub fn open(serial: Option<&str>) -> Result<Self> {
        let handle = open_dfu_device(serial)?;
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

    /// Read the flash back from `address` and compare it with `firmware`. Call
    /// it after `program` with the same address and firmware.
    ///
    /// # Errors
    /// Returns an error naming the first address that differs, if a read
    /// returns fewer bytes than the firmware has there, if the address is not
    /// valid, a USB transfer fails, or the device is in the wrong state.
    pub fn verify(&self, address: u32, firmware: &[u8]) -> Result<()> {
        self.dfu.verify(address, firmware)
    }

    /// Set the boot options and make the device leave ST DFU mode, as the
    /// reference `leave-dfu` does. The options only take effect after a power
    /// cycle of the key.
    ///
    /// The option bytes are written only if exactly 16 bytes were read, and
    /// only if the boot bits need to change. A USB error while detaching is
    /// ignored because the device resets.
    ///
    /// # Errors
    /// Returns an error if the option bytes cannot be read in full, a USB
    /// transfer fails before the detach, or the device is in the wrong state
    /// or stays busy too long.
    pub fn leave_dfu(&self) -> Result<()> {
        self.dfu.leave_dfu()
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

    /// Script for `verify`: per page, a state check and the page read.
    fn verify_script(pages: &[Vec<u8>]) -> Vec<Result<Vec<u8>>> {
        pages.iter().flat_map(|p| [st(DFU_STATE_IDLE), Ok(p.clone())]).collect()
    }

    /// 2058 bytes: one full page and a last page with 10 bytes.
    fn two_page_image() -> Vec<u8> {
        (0..2058u32).map(|i| (i % 251) as u8).collect()
    }

    /// What a device returns for `image`: full pages, the last one padded with 0xFF.
    fn readback(image: &[u8]) -> Vec<Vec<u8>> {
        image
            .chunks(2048)
            .map(|c| {
                let mut p = c.to_vec();
                p.resize(2048, 0xFF);
                p
            })
            .collect()
    }

    #[test]
    fn test_verify_passes_on_a_good_readback_and_reads_each_page() {
        let image = two_page_image();
        let fake = Fake::with_ins(verify_script(&readback(&image)));
        let dfu = Dfu::new(fake);
        dfu.verify(FLASH_BASE, &image).unwrap();
        let reads: Vec<_> = dfu
            .io
            .log()
            .into_iter()
            .filter(|x| matches!(x, Xfer::In { request, .. } if *request == DFU_UPLOAD))
            .collect();
        let upload = |value| Xfer::In {
            request: DFU_UPLOAD,
            value,
            len: 2048,
        };
        assert_eq!(reads, [upload(2), upload(3)]);
    }

    #[test]
    fn test_verify_names_the_first_address_that_differs() {
        let image = two_page_image();
        let mut pages = readback(&image);
        pages[1][3] ^= 0x01; // address FLASH_BASE + 2048 + 3
        pages[0][5] ^= 0x01; // page 0 is read first, so this lower address is the one reported
        let err = Dfu::new(Fake::with_ins(verify_script(&pages)))
            .verify(FLASH_BASE, &image)
            .unwrap_err()
            .to_string();
        assert!(err.contains("0x08000005"), "{err}");

        let mut pages = readback(&image);
        pages[1][3] ^= 0x01;
        let err = Dfu::new(Fake::with_ins(verify_script(&pages)))
            .verify(FLASH_BASE, &image)
            .unwrap_err()
            .to_string();
        assert!(err.contains("0x08000803"), "{err}");
    }

    #[test]
    fn test_verify_starts_at_the_given_address() {
        let image = vec![0xAA; 16];
        let mut page = readback(&image);
        page[0][0] = 0x00;
        let err = Dfu::new(Fake::with_ins(verify_script(&page)))
            .verify(FLASH_BASE + 0x1000, &image)
            .unwrap_err()
            .to_string();
        assert!(err.contains("0x08001000"), "{err}");

        // A good readback from this address reads block 4, not block 2.
        let dfu = Dfu::new(Fake::with_ins(verify_script(&readback(&image))));
        dfu.verify(FLASH_BASE + 0x1000, &image).unwrap();
        assert!(dfu.io.log().contains(&Xfer::In {
            request: DFU_UPLOAD,
            value: 4,
            len: 2048
        }));
    }

    #[test]
    fn test_verify_after_program_clears_download_idle_first() {
        let image = vec![0xAA; 16];
        let mut ins = vec![st(DFU_STATE_DOWNLOAD_IDLE), st(DFU_STATE_IDLE)];
        ins.extend(readback(&image).into_iter().map(Ok));
        let dfu = Dfu::new(Fake::with_ins(ins));
        dfu.verify(FLASH_BASE, &image).unwrap();
        assert_eq!(
            dfu.io.log(),
            vec![
                get_status_xfer(),
                clrstatus(),
                clrstatus(),
                get_status_xfer(),
                Xfer::In {
                    request: DFU_UPLOAD,
                    value: 2,
                    len: 2048
                },
            ]
        );
    }

    #[test]
    fn test_verify_ignores_the_padding_of_the_last_page() {
        let image = two_page_image();
        let mut pages = readback(&image);
        pages[1][10] = 0x00; // first byte after the image
        Dfu::new(Fake::with_ins(verify_script(&pages)))
            .verify(FLASH_BASE, &image)
            .unwrap();
    }

    #[test]
    fn test_verify_fails_on_a_short_read() {
        let image = two_page_image();
        let mut pages = readback(&image);
        pages[1].truncate(4); // image needs 10 bytes here
        let err = Dfu::new(Fake::with_ins(verify_script(&pages)))
            .verify(FLASH_BASE, &image)
            .unwrap_err()
            .to_string();
        assert!(err.contains("0x08000804") && err.contains("no data"), "{err}");
    }

    #[test]
    fn test_verify_rejects_bad_address_before_any_transfer() {
        let dfu = Dfu::new(Fake::default());
        assert!(dfu.verify(FLASH_BASE + 1, &[1]).is_err());
        assert_eq!(dfu.io.log().len(), 0);
    }

    type Cand = (u8, std::result::Result<String, &'static str>);

    fn named(id: u8, serial: &str) -> Cand {
        (id, Ok(serial.into()))
    }

    fn unreadable(id: u8) -> Cand {
        (id, Err("no access"))
    }

    #[test]
    fn test_select_device_by_count_without_serial() {
        let none: Vec<Cand> = vec![];
        let msg = select_device(none, None).unwrap_err().to_string();
        assert!(msg.contains("No ST DFU device found"), "{msg}");
        assert_eq!(select_device(vec![named(7, "A")], None).unwrap(), 7);
        // One device whose serial cannot be read is still the only one.
        assert_eq!(select_device(vec![unreadable(7)], None).unwrap(), 7);
        let msg = select_device(vec![named(1, "A"), unreadable(2)], None)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("2 ST DFU devices") && msg.contains("--serial"), "{msg}");
        assert!(msg.contains('A') && msg.contains("unknown serial (no access)"), "{msg}");
    }

    #[test]
    fn test_select_device_with_serial() {
        assert_eq!(select_device(vec![named(1, "A"), named(2, "B")], Some("B")).unwrap(), 2);
        assert_eq!(select_device(vec![named(1, "A")], Some("A")).unwrap(), 1);
        // No match: an error, also when there is only one device.
        let msg = select_device(vec![named(1, "A")], Some("B")).unwrap_err().to_string();
        assert!(msg.contains("serial B") && msg.contains('A'), "{msg}");
        // A device whose serial cannot be read never matches, and its error is shown.
        let msg = select_device(vec![unreadable(1)], Some("A")).unwrap_err().to_string();
        assert!(msg.contains("unknown serial (no access)"), "{msg}");
        let none: Vec<Cand> = vec![];
        let msg = select_device(none, Some("A")).unwrap_err().to_string();
        assert!(msg.contains("No ST DFU device found"), "{msg}");
        // The same serial twice is not unique.
        let msg = select_device(vec![named(1, "A"), named(2, "A")], Some("A"))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("More than one"), "{msg}");
    }

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
    fn test_detach_option_bytes_sets_and_clears_boot_bits() {
        let mut input = [0u8; 16];
        input[3] = 0x04; // nSWBOOT0 set, nBOOT0 clear
        let out = detach_option_bytes(input);
        assert_eq!(out[3], 0x08);
        // Already correct: no change.
        input[3] = 0x08;
        assert_eq!(detach_option_bytes(input), input);
    }

    #[test]
    fn test_detach_option_bytes_changes_only_bits_26_and_27() {
        for b0 in 0..=255u8 {
            for b3 in 0..=255u8 {
                let mut input = [0xA5u8; 16];
                for (i, b) in input.iter_mut().enumerate().skip(4) {
                    *b = u8::try_from(i * 17).unwrap();
                }
                input[0] = b0;
                input[1] = !b0;
                input[2] = b0.rotate_left(3);
                input[3] = b3;
                let out = detach_option_bytes(input);
                // Byte 0 (read-protection level), 1 and 2 never change.
                assert_eq!(out[..3], input[..3]);
                // Bytes 4 to 15 never change.
                assert_eq!(out[4..], input[4..]);
                // In byte 3 only bits 2 and 3 (word bits 26 and 27) may change.
                assert_eq!(out[3] & !0x0C, b3 & !0x0C);
                assert_eq!(out[3] & 0x0C, 0x08);
            }
        }
    }

    /// Reply script for the steps before the detach: the write-back of the
    /// first 16 bytes, the address change, and the read of the option bytes.
    fn option_script(first: Vec<u8>, options: Vec<u8>) -> Vec<Result<Vec<u8>>> {
        vec![
            st(DFU_STATE_IDLE), // read at the pointer: state check
            Ok(first),
            st(DFU_STATE_DOWNLOAD_IDLE), // write back: wait, state check
            st(DFU_STATE_DOWNLOAD_IDLE),
            st(DFU_STATE_BUSY), // finish download
            st(DFU_STATE_DOWNLOAD_IDLE),
            st(DFU_STATE_DOWNLOAD_IDLE), // wait after the write
            st(DFU_STATE_BUSY),          // set_addr
            st(DFU_STATE_DOWNLOAD_IDLE),
            st(DFU_STATE_DOWNLOAD_IDLE), // read option bytes: state check fails,
            st(DFU_STATE_IDLE),          // two CLRSTATUS, then it is idle
            Ok(options),
        ]
    }

    fn upload() -> Xfer {
        Xfer::In {
            request: DFU_UPLOAD,
            value: 2,
            len: 16,
        }
    }

    #[test]
    fn test_leave_dfu_transfer_order_with_rewrite() {
        let first: Vec<u8> = (0..16).collect();
        let mut options = vec![0xAA, 0x01, 0x02, 0x04, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let mut ins = option_script(first.clone(), options.clone());
        ins.extend([
            st(DFU_STATE_IDLE), // rewrite: wait, state check
            st(DFU_STATE_IDLE),
            st(DFU_STATE_BUSY), // finish download
            st(DFU_STATE_DOWNLOAD_IDLE),
            st(DFU_STATE_DOWNLOAD_IDLE), // wait after the write
            st(DFU_STATE_DOWNLOAD_IDLE), // detach: state check, then status
            st(DFU_STATE_MANIFEST_SYNC),
        ]);
        let dfu = Dfu::new(Fake::with_ins(ins));
        dfu.leave_dfu().unwrap();

        options[3] = 0x08;
        let gs = get_status_xfer;
        assert_eq!(
            dfu.io.log(),
            vec![
                // write back the first 16 bytes (block 2, not an address block)
                gs(),
                upload(),
                gs(),
                gs(),
                dnload(2, &first),
                gs(),
                gs(),
                gs(),
                // set the address pointer to the option bytes
                dnload(0, &[0x21, 0x00, 0x78, 0xFF, 0x1F]),
                gs(),
                gs(),
                // read them
                gs(),
                clrstatus(),
                clrstatus(),
                gs(),
                upload(),
                // write them back with the boot bits fixed
                gs(),
                gs(),
                dnload(2, &options),
                gs(),
                gs(),
                gs(),
                // detach
                gs(),
                dnload(0, &[]),
                gs(),
            ]
        );
    }

    #[test]
    fn test_leave_dfu_skips_rewrite_when_unchanged_and_ignores_usb_error_on_detach() {
        let first = vec![0u8; 16];
        let mut options = vec![0u8; 16];
        options[3] = 0x08;
        let mut ins = option_script(first, options);
        ins.extend([st(DFU_STATE_DOWNLOAD_IDLE), Err(Error::Usb(rusb::Error::Io))]);
        let dfu = Dfu::new(Fake::with_ins(ins));
        dfu.leave_dfu().unwrap();

        let log = dfu.io.log();
        // Block 2 is written once (the first write-back), never for the options.
        assert_eq!(
            log.iter().filter(|x| matches!(x, Xfer::Out { value: 2, .. })).count(),
            1
        );
        assert_eq!(log.last(), Some(&get_status_xfer()));
        assert!(log.contains(&dnload(0, &[])));
    }

    #[test]
    fn test_leave_dfu_writes_no_option_bytes_after_a_short_read() {
        let first = vec![0u8; 16];
        let short = vec![0u8; 8];
        let dfu = Dfu::new(Fake::with_ins(option_script(first, short)));
        assert!(dfu.leave_dfu().is_err());

        let log = dfu.io.log();
        // Only the first write-back used block 2.
        assert_eq!(
            log.iter().filter(|x| matches!(x, Xfer::Out { value: 2, .. })).count(),
            1
        );
        assert!(!log.contains(&dnload(0, &[])));
    }

    #[test]
    fn test_leave_dfu_skips_first_write_back_after_a_short_read() {
        let dfu = Dfu::new(Fake::with_ins(vec![st(DFU_STATE_IDLE), Ok(vec![0u8; 4])]));
        // The second read has no scripted reply, so the run stops there.
        assert!(dfu.leave_dfu().is_err());
        assert!(!dfu.io.log().iter().any(|x| matches!(x, Xfer::Out { value: 2, .. })));
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
