use thiserror::Error;

/// Errors from CTAPHID framing and the USB HID transport.
#[derive(Debug, Error)]
pub enum Error {
    #[error("No matching device found")]
    NoDeviceFound,

    #[error("Multiple matching devices found; select one by serial number")]
    NonUniqueDevice,

    #[error("Device error: {0}")]
    Device(String),

    #[error("HID error: {0}")]
    Hid(#[from] hidapi::HidError),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Timeout waiting for device response")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, Error>;
