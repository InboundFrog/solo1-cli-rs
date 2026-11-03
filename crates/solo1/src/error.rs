use thiserror::Error;

/// Errors from Solo 1 vendor commands, firmware handling, DFU and attestation.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Transport(#[from] solo_ctaphid::Error),

    #[error("Device error: {0}")]
    Device(String),

    #[error("Invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("Firmware error: {0}")]
    Firmware(String),

    #[error("USB error: {0}")]
    Usb(#[from] rusb::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;
