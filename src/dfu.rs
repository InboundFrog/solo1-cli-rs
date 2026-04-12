/// ST DFU (Device Firmware Upgrade) protocol implementation via libusb.
///
/// Implements USB DFU over control transfers for STM32 devices.
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use rusb::{Context, DeviceHandle, UsbContext};

use crate::device::{FLASH_BASE, DFU_CHUNK_SIZE, SOLO_VID, SOLO_DFU_PID};
use crate::error::{Result, SoloError};

// DFU request codes
pub const DFU_DETACH: u8 = 0x00;
pub const DFU_DNLOAD: u8 = 0x01;
pub const DFU_UPLOAD: u8 = 0x02;
pub const DFU_GETSTATUS: u8 = 0x03;
pub const DFU_CLRSTATUS: u8 = 0x04;
pub const DFU_GETSTATE: u8 = 0x05;
pub const DFU_ABORT: u8 = 0x06;

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
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 6 {
            return Err(SoloError::ProtocolError(
                "DFU status response too short".into(),
            ));
        }
        Ok(DfuStatus {
            status: bytes[0],
            poll_timeout_ms: (bytes[1] as u32)
                | ((bytes[2] as u32) << 8)
                | ((bytes[3] as u32) << 16),
            state: bytes[4],
            istring: bytes[5],
        })
    }

    pub fn is_ok(&self) -> bool {
        self.status == 0x00
    }
}

/// Open the DFU device via libusb.
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
    pub fn open() -> Result<Self> {
        let handle = open_dfu_device()?;
        handle
            .claim_interface(DFU_INTERFACE)
            .map_err(|e| SoloError::UsbError(e))?;
        Ok(DfuDevice {
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
                DFU_INTERFACE as u16,
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
                DFU_INTERFACE as u16,
                buf,
                Duration::from_secs(5),
            )
            .map_err(SoloError::UsbError)?;
        Ok(n)
    }

    pub fn get_status(&self) -> Result<DfuStatus> {
        let mut buf = [0u8; 6];
        self.control_in(DFU_GETSTATUS, 0, &mut buf)?;
        DfuStatus::parse(&buf)
    }

    pub fn clear_status(&self) -> Result<()> {
        self.control_out(DFU_CLRSTATUS, 0, &[])?;
        Ok(())
    }

    pub fn abort(&self) -> Result<()> {
        self.control_out(DFU_ABORT, 0, &[])?;
        Ok(())
    }

    /// Wait while device is in DNBUSY state.
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
                    std::thread::sleep(Duration::from_millis(ms as u64));
                }
                continue;
            }
            return Ok(status);
        }
    }

    /// Download one chunk via DFU_DNLOAD.
    pub fn dnload_chunk(&mut self, data: &[u8]) -> Result<()> {
        self.control_out(DFU_DNLOAD, self.transaction, data)?;
        self.transaction += 1;
        self.wait_while_busy()?;
        Ok(())
    }

    /// Program a firmware binary to the device.
    pub fn program(&mut self, firmware: &[u8]) -> Result<()> {
        let chunk_size = DFU_CHUNK_SIZE as usize;
        let total_chunks = (firmware.len() + chunk_size - 1) / chunk_size;

        let pb = ProgressBar::new(total_chunks as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} chunks")
                .unwrap()
                .progress_chars("##-"),
        );

        // Reset transaction counter for address calculation
        // block_index = (address - BASE) / chunk_size + 2
        // We start at transaction = 2 to match DFU block offset
        self.transaction = 2;

        let mut offset = 0;
        while offset < firmware.len() {
            let end = (offset + chunk_size).min(firmware.len());
            let chunk = &firmware[offset..end];

            // Pad chunk to chunk_size if needed
            let mut padded = chunk.to_vec();
            if padded.len() < chunk_size {
                padded.resize(chunk_size, 0xFF);
            }

            self.dnload_chunk(&padded)?;
            pb.inc(1);
            offset += chunk_size;
        }

        // Send zero-length download to signal end
        self.dnload_chunk(&[])?;

        pb.finish_with_message("Done");
        Ok(())
    }
}

/// Calculate the DFU block index for a given flash address.
/// Exported here for use in tests and commands.
pub fn block_index_for_address(address: u32) -> u32 {
    (address - FLASH_BASE) / DFU_CHUNK_SIZE + 2
}

#[cfg(test)]
mod tests {
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
    fn test_dfu_block_index() {
        // Base address -> block 2
        assert_eq!(block_index_for_address(0x08000000), 2);
        // + 2048 -> block 3
        assert_eq!(block_index_for_address(0x08000800), 3);
        // + 4096 -> block 4
        assert_eq!(block_index_for_address(0x08001000), 4);
        // Page 113 = 113 * 2048 = 0x38800 offset
        let page113_addr = 0x08000000 + 113 * 2048;
        assert_eq!(block_index_for_address(page113_addr), 113 + 2);
    }

    #[test]
    fn test_dfu_status_parse_short() {
        let bytes = [0x00, 0x00];
        assert!(DfuStatus::parse(&bytes).is_err());
    }
}
