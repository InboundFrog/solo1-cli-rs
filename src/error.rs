use thiserror::Error;

#[derive(Debug, Error)]
pub enum SoloError {
    #[error("No Solo device found. On Linux, ensure udev rules are installed:\n  https://github.com/solokeys/solo1/blob/master/udev/70-solokeys-access.rules")]
    NoSoloFound,

    #[error("Multiple Solo devices found. Run `solo1 ls` to list serial numbers, then use `--serial <serial>`.")]
    NonUniqueDevice,

    #[error("Device error: {0}")]
    DeviceError(String),

    #[error("Invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("CBOR error: {0}")]
    CborError(String),

    #[error("Authenticator error (CTAP2 {code:#04x}): {message}")]
    AuthenticatorError { code: u8, message: &'static str },

    #[error("Malformed response from device: {0}")]
    MalformedResponse(String),

    #[error("Firmware error: {0}")]
    FirmwareError(String),

    #[error("This operation is not supported on this platform")]
    UnsupportedPlatform,

    #[error("HID error: {0}")]
    HidError(#[from] hidapi::HidError),

    #[error("USB error: {0}")]
    UsbError(#[from] rusb::Error),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Timeout waiting for device response")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, SoloError>;
