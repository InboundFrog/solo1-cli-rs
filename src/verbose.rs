/// Global verbose flag and logging macro.
use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Print to stderr when --verbose is active.
/// Usage: `vlog!("sent {} bytes", n);`
#[macro_export]
macro_rules! vlog {
    ($($arg:tt)*) => {
        if $crate::verbose::is_verbose() {
            eprintln!("[verbose] {}", format!($($arg)*));
        }
    };
}
