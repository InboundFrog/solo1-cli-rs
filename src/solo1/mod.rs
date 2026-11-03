/// Solo 1 device support: USB identifiers, vendor commands and bootloader.
pub mod bootloader;
pub mod protocol;

use std::time::Duration;

use crate::error::Result;
use solo_ctaphid::{DeviceFilter, HidDeviceInfo, HidTransport, list_devices};

/// Matches a Solo 1 running firmware or the Solo bootloader.
pub const DEVICE_FILTER: DeviceFilter = DeviceFilter::UsbId {
    vendor_id: protocol::SOLO_VID,
    product_id: protocol::SOLO_PID,
};

/// List all connected Solo 1 devices.
///
/// # Errors
/// Returns an error if the HID API cannot be initialized.
pub fn list_solo_devices() -> Result<Vec<HidDeviceInfo>> {
    Ok(list_devices(DEVICE_FILTER)?)
}

/// Open a Solo 1 by serial number (or the only one present if `None`).
///
/// # Errors
/// See [`HidTransport::open`].
pub fn open(serial: Option<&str>, timeout: Duration) -> Result<HidTransport> {
    Ok(HidTransport::open(DEVICE_FILTER, serial, timeout)?)
}
