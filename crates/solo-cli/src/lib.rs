/// Like `println!`, but writes to a locked stdout and returns the write error
/// with `?` instead of panicking. Use it in a function that returns
/// `Result<_, SoloError>`.
///
/// `outln!(out, "...")` with a writer name first writes to that writer instead.
/// A write error is a `SoloError::Stdout` in both forms.
#[macro_export]
macro_rules! outln {
    ($out:ident, $($arg:tt)*) => {{
        writeln!($out, $($arg)*).map_err($crate::error::SoloError::Stdout)?
    }};
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        writeln!(::std::io::stdout().lock(), $($arg)*).map_err($crate::error::SoloError::Stdout)?
    }};
}

/// Like `print!`, with the same error handling as [`outln!`].
#[macro_export]
macro_rules! out {
    ($out:ident, $($arg:tt)*) => {{
        write!($out, $($arg)*).map_err($crate::error::SoloError::Stdout)?
    }};
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
