/// ST DFU (Device Firmware Upgrade) protocol implementation via libusb.
///
/// Implements USB DFU over control transfers for STM32 devices.
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use rusb::{Context, DeviceHandle, UsbContext};

use crate::device::{DFU_CHUNK_SIZE, SOLO_DFU_PID, SOLO_VID};
use crate::error::{Result, SoloError};
use crate::vlog;

// DFU request codes
pub const DFU_DNLOAD: u8 = 0x01;
pub const DFU_GETSTATUS: u8 = 0x03;

// DFU states
pub const DFU_STATE_IDLE: u8 = 0x02;
pub const DFU_STATE_DOWNLOAD_IDLE: u8 = 0x05;
pub const DFU_STATE_BUSY: u8 = 0x04;
pub const DFU_STATE_DOWNLOAD_SYNC: u8 = 0x03;
pub const DFU_STATE_ERROR: u8 = 0x0A;
pub const DFU_STATE_MANIFEST_SYNC: u8 = 0x06;
pub const DFU_STATE_MANIFEST: u8 = 0x07;

pub const DFU_INTERFACE: u8 = 0;
pub const DFU_ALT: u8 = 0;

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
            .ok_or_else(|| SoloError::ProtocolError("DFU status response too short".into()))?
            .try_into()
            .map_err(|_| SoloError::ProtocolError("DFU status response too short".into()))?;
        Ok(Self {
            status: bytes[0],
            poll_timeout_ms: u32::from(bytes[1])
                | (u32::from(bytes[2]) << 8)
                | (u32::from(bytes[3]) << 16),
            state: bytes[4],
            istring: bytes[5],
        })
    }

    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.status == 0x00
    }
}

/// Open the DFU device via libusb.
///
/// # Errors
/// Returns an error if the libusb context cannot be created, the device list
/// or a device descriptor cannot be read, opening the device fails, or no ST
/// DFU device (PID 0xDF11) is present.
pub fn open_dfu_device() -> Result<DeviceHandle<Context>> {
    let context = Context::new()?;
    let devices = context.devices()?;
    for device in devices.iter() {
        let desc = device.device_descriptor()?;
        if desc.vendor_id() == SOLO_VID && desc.product_id() == SOLO_DFU_PID {
            let handle = device.open()?;
            return Ok(handle);
        }
    }
    Err(SoloError::DeviceError(
        "No ST DFU device found (PID 0xDF11)".into(),
    ))
}

/// DFU programmer for STM32.
pub struct DfuDevice {
    handle: DeviceHandle<Context>,
    transaction: u16,
}

impl DfuDevice {
    /// Open the ST DFU device and claim its interface.
    ///
    /// # Errors
    /// Returns an error if no ST DFU device is found, the device cannot be
    /// opened, or the DFU interface cannot be claimed.
    pub fn open() -> Result<Self> {
        let handle = open_dfu_device()?;
        handle
            .claim_interface(DFU_INTERFACE)
            .map_err(SoloError::UsbError)?;
        Ok(Self {
            handle,
            transaction: 0,
        })
    }

    fn control_out(&self, request: u8, value: u16, data: &[u8]) -> Result<usize> {
        let n = self
            .handle
            .write_control(
                0x21, // bmRequestType: host->device, class, interface
                request,
                value,
                u16::from(DFU_INTERFACE),
                data,
                Duration::from_secs(5),
            )
            .map_err(SoloError::UsbError)?;
        Ok(n)
    }

    fn control_in(&self, request: u8, value: u16, buf: &mut [u8]) -> Result<usize> {
        let n = self
            .handle
            .read_control(
                0xA1, // bmRequestType: device->host, class, interface
                request,
                value,
                u16::from(DFU_INTERFACE),
                buf,
                Duration::from_secs(5),
            )
            .map_err(SoloError::UsbError)?;
        Ok(n)
    }

    /// Query the current DFU status via `DFU_GETSTATUS`.
    ///
    /// # Errors
    /// Returns an error if the USB control transfer fails or the status
    /// response cannot be parsed.
    pub fn get_status(&self) -> Result<DfuStatus> {
        let mut buf = [0u8; 6];
        self.control_in(DFU_GETSTATUS, 0, &mut buf)?;
        let status = DfuStatus::parse(&buf)?;
        vlog!(
            "DFU_GETSTATUS: status=0x{:02X} state=0x{:02X} poll_ms={}",
            status.status,
            status.state,
            status.poll_timeout_ms
        );
        Ok(status)
    }

    /// Wait while device is in DNBUSY state.
    ///
    /// # Errors
    /// Returns an error if a status query fails or the device reports an error
    /// status.
    pub fn wait_while_busy(&self) -> Result<DfuStatus> {
        loop {
            let status = self.get_status()?;
            if !status.is_ok() {
                return Err(SoloError::DeviceError(format!(
                    "DFU error status: 0x{:02x} state: 0x{:02x}",
                    status.status, status.state
                )));
            }
            if status.state == DFU_STATE_BUSY {
                let ms = status.poll_timeout_ms;
                if ms > 0 {
                    std::thread::sleep(Duration::from_millis(u64::from(ms)));
                }
                continue;
            }
            return Ok(status);
        }
    }

    /// Download one chunk via `DFU_DNLOAD`.
    ///
    /// # Errors
    /// Returns an error if the USB control transfer fails, the transaction
    /// counter overflows, or the device reports an error while busy.
    pub fn dnload_chunk(&mut self, data: &[u8]) -> Result<()> {
        vlog!(
            "DFU_DNLOAD: transaction={} len={}",
            self.transaction,
            data.len()
        );
        self.control_out(DFU_DNLOAD, self.transaction, data)?;
        self.transaction = self
            .transaction
            .checked_add(1)
            .ok_or_else(|| SoloError::ProtocolError("DFU transaction counter overflow".into()))?;
        self.wait_while_busy()?;
        Ok(())
    }

    /// Program a firmware binary to the device.
    ///
    /// # Errors
    /// Returns an error if the chunk-size or offset arithmetic overflows, the
    /// progress bar style is invalid, or downloading a chunk to the device
    /// fails.
    pub fn program(&mut self, firmware: &[u8]) -> Result<()> {
        let chunk_size = usize::try_from(DFU_CHUNK_SIZE)
            .map_err(|_| SoloError::ProtocolError("DFU chunk size overflow".into()))?;
        let total_chunks = firmware.len().div_ceil(chunk_size);

        let pb = ProgressBar::new(
            u64::try_from(total_chunks)
                .map_err(|_| SoloError::ProtocolError("DFU chunk count overflow".into()))?,
        );
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} chunks")
                .map_err(|e| SoloError::FirmwareError(format!("Progress bar style error: {e}")))?
                .progress_chars("##-"),
        );

        // Reset transaction counter for address calculation
        // block_index = (address - BASE) / chunk_size + 2
        // We start at transaction = 2 to match DFU block offset
        self.transaction = 2;

        let mut offset = 0;
        while offset < firmware.len() {
            let end = offset
                .checked_add(chunk_size)
                .ok_or_else(|| SoloError::ProtocolError("DFU offset overflow".into()))?
                .min(firmware.len());
            let chunk = firmware
                .get(offset..end)
                .ok_or_else(|| SoloError::ProtocolError("DFU chunk range out of bounds".into()))?;

            // Pad chunk to chunk_size if needed
            let mut padded = chunk.to_vec();
            if padded.len() < chunk_size {
                padded.resize(chunk_size, 0xFF);
            }

            self.dnload_chunk(&padded)?;
            pb.inc(1);
            offset = offset
                .checked_add(chunk_size)
                .ok_or_else(|| SoloError::ProtocolError("DFU offset overflow".into()))?;
        }

        // Send zero-length download to signal end
        self.dnload_chunk(&[])?;

        pb.finish_with_message("Done");
        Ok(())
    }
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

    #[test]
    fn test_dfu_status_parse_short() {
        let bytes = [0x00, 0x00];
        assert!(DfuStatus::parse(&bytes).is_err());
    }
}
