use thiserror::Error;

#[derive(Debug, Error)]
pub enum SoloError {
    #[error(
        "No Solo device found. On Linux, ensure udev rules are installed:\n  https://github.com/solokeys/solo1/blob/master/udev/70-solokeys-access.rules"
    )]
    NoSoloFound,

    #[error("Multiple Solo devices found. Run `solo1 ls` to list serial numbers, then use `--serial <serial>`.")]
    NonUniqueDevice,

    #[error("Device error: {0}")]
    DeviceError(String),

    #[error("Invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("CBOR serialization error: {0}")]
    CborSerError(#[from] ciborium::ser::Error<std::io::Error>),

    #[error("CBOR deserialization error: {0}")]
    CborDeError(#[from] ciborium::de::Error<std::io::Error>),

    #[error("Authenticator error (CTAP2 {code:#04x}): {message}")]
    AuthenticatorError { code: u8, message: &'static str },

    #[error("Malformed response from device: {0}")]
    MalformedResponse(String),

    #[error("Firmware error: {0}")]
    FirmwareError(String),

    #[error("This operation is not supported on this platform")]
    UnsupportedPlatform,

    /// Any other CTAPHID transport error.
    #[error(transparent)]
    Transport(solo_ctaphid::Error),

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

impl From<solo_ctaphid::Error> for SoloError {
    /// Device-selection errors map to variants whose messages carry CLI
    /// guidance (udev rules, `--serial`); timeouts stay matchable as
    /// [`SoloError::Timeout`]. Everything else is passed through unchanged.
    fn from(e: solo_ctaphid::Error) -> Self {
        match e {
            solo_ctaphid::Error::NoDeviceFound => Self::NoSoloFound,
            solo_ctaphid::Error::NonUniqueDevice => Self::NonUniqueDevice,
            solo_ctaphid::Error::Timeout => Self::Timeout,
            other => Self::Transport(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_device_selection_errors_keep_cli_guidance() {
        let e = SoloError::from(solo_ctaphid::Error::NoDeviceFound);
        assert!(matches!(e, SoloError::NoSoloFound));
        assert!(e.to_string().contains("udev"));

        let e = SoloError::from(solo_ctaphid::Error::NonUniqueDevice);
        assert!(matches!(e, SoloError::NonUniqueDevice));
        assert!(e.to_string().contains("--serial"));
    }

    #[test]
    fn test_transport_timeout_stays_matchable() {
        let e = SoloError::from(solo_ctaphid::Error::Timeout);
        assert!(matches!(e, SoloError::Timeout));
    }

    #[test]
    fn test_other_transport_errors_pass_through() {
        let e = SoloError::from(solo_ctaphid::Error::Protocol("bad frame".into()));
        assert!(matches!(e, SoloError::Transport(_)));
        assert_eq!(e.to_string(), "Protocol error: bad frame");
    }
}
