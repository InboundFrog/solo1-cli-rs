/// Like `println!`, but writes to a locked stdout and returns the write error
/// with `?` instead of panicking. Use it in a function that returns
/// `Result<_, SoloError>`.
#[macro_export]
macro_rules! outln {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        writeln!(::std::io::stdout().lock(), $($arg)*).map_err($crate::error::SoloError::Stdout)?
    }};
}

/// Like `print!`, with the same error handling as [`outln!`].
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        write!(::std::io::stdout().lock(), $($arg)*).map_err($crate::error::SoloError::Stdout)?
    }};
}

pub mod cli;
pub mod commands;
pub mod device;
pub mod error;
pub mod github;
pub mod logger;
pub mod output;
