use thiserror::Error;

/// Errors from Solo 2 admin-app commands.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Transport(#[from] solo_ctaphid::Error),

    #[error("Malformed response from device: {0}")]
    MalformedResponse(String),
}

pub type Result<T> = std::result::Result<T, Error>;
