use thiserror::Error;

/// Errors from CTAP2 requests and responses.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Transport(#[from] solo_ctaphid::Error),

    #[error("Authenticator error (CTAP2 {code:#04x}): {message}")]
    Authenticator { code: u8, message: &'static str },

    #[error("CBOR serialization error: {0}")]
    CborSer(#[from] ciborium::ser::Error<std::io::Error>),

    #[error("CBOR deserialization error: {0}")]
    CborDe(#[from] ciborium::de::Error<std::io::Error>),

    #[error("Malformed response from device: {0}")]
    MalformedResponse(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;
