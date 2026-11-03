use thiserror::Error;

#[derive(Debug, Error)]
pub enum SoloError {
    #[error(
        "No Solo device found. On Linux, ensure udev rules are installed:\n  Solo 1: https://github.com/solokeys/solo1/blob/master/udev/70-solokeys-access.rules\n  Solo 2: https://github.com/solokeys/solo2-cli/blob/main/70-solo2.rules"
    )]
    NoSoloFound,

    #[error("Multiple Solo devices found. Run `solo ls` to list serial numbers, then use `--serial <serial>`.")]
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

    #[error("`{command}` is not supported on {model} yet")]
    Unsupported { command: &'static str, model: &'static str },
}

pub type Result<T> = std::result::Result<T, SoloError>;

impl From<solo2::Error> for SoloError {
    fn from(e: solo2::Error) -> Self {
        match e {
            solo2::Error::Transport(t) => t.into(),
            solo2::Error::MalformedResponse(m) => Self::MalformedResponse(m),
        }
    }
}

impl From<solo1::Error> for SoloError {
    /// Each Solo 1 error maps to the equivalent existing variant, so messages
    /// and `matches!` checks are unchanged.
    fn from(e: solo1::Error) -> Self {
        match e {
            solo1::Error::Transport(t) => t.into(),
            solo1::Error::Device(m) => Self::DeviceError(m),
            solo1::Error::InvalidHex(e) => Self::InvalidHex(e),
            solo1::Error::Firmware(m) => Self::FirmwareError(m),
            solo1::Error::Usb(e) => Self::UsbError(e),
            solo1::Error::Io(e) => Self::IoError(e),
            solo1::Error::Json(e) => Self::JsonError(e),
            solo1::Error::Crypto(m) => Self::CryptoError(m),
            solo1::Error::Protocol(m) => Self::ProtocolError(m),
        }
    }
}

impl From<solo_ctap2::Error> for SoloError {
    /// Each CTAP2 error maps to the equivalent existing variant, so messages
    /// and `matches!` checks are unchanged.
    fn from(e: solo_ctap2::Error) -> Self {
        match e {
            solo_ctap2::Error::Transport(t) => t.into(),
            solo_ctap2::Error::Authenticator { code, message } => Self::AuthenticatorError { code, message },
            solo_ctap2::Error::CborSer(e) => Self::CborSerError(e),
            solo_ctap2::Error::CborDe(e) => Self::CborDeError(e),
            solo_ctap2::Error::MalformedResponse(m) => Self::MalformedResponse(m),
            solo_ctap2::Error::Crypto(m) => Self::CryptoError(m),
            solo_ctap2::Error::Protocol(m) => Self::ProtocolError(m),
        }
    }
}

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
    fn test_ctap2_errors_map_to_existing_variants() {
        let e = SoloError::from(solo_ctap2::Error::Authenticator {
            code: 0x31,
            message: "PIN blocked",
        });
        assert!(matches!(e, SoloError::AuthenticatorError { code: 0x31, .. }));

        let e = SoloError::from(solo_ctap2::Error::Transport(solo_ctaphid::Error::Timeout));
        assert!(matches!(e, SoloError::Timeout));
    }

    #[test]
    fn test_solo1_errors_map_to_existing_variants() {
        let e = SoloError::from(solo1::Error::Firmware("bad image".into()));
        assert!(matches!(e, SoloError::FirmwareError(_)));
        assert_eq!(e.to_string(), "Firmware error: bad image");

        let e = SoloError::from(solo1::Error::Transport(solo_ctaphid::Error::NoDeviceFound));
        assert!(matches!(e, SoloError::NoSoloFound));
    }

    #[test]
    fn test_other_transport_errors_pass_through() {
        let e = SoloError::from(solo_ctaphid::Error::Protocol("bad frame".into()));
        assert!(matches!(e, SoloError::Transport(_)));
        assert_eq!(e.to_string(), "Protocol error: bad frame");
    }
}
