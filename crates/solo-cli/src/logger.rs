/// Minimal stderr logger behind the `log` facade.
///
/// Library modules log through `log::debug!` and friends; only the CLI decides
/// what reaches the terminal. With `--verbose`, debug records from this
/// project's crates are shown. Other crates (HTTP, USB, ...) only ever show
/// warnings and errors, so `--verbose` output stays about the device.
use log::{Level, LevelFilter, Log, Metadata, Record};

/// Crate-name prefix shared by every crate in this project.
const OWN_TARGET_PREFIX: &str = "solo";

struct StderrLogger {
    verbose: bool,
}

impl StderrLogger {
    fn max_level_for(&self, target: &str) -> LevelFilter {
        if self.verbose && is_own_target(target) {
            LevelFilter::Debug
        } else {
            LevelFilter::Warn
        }
    }
}

/// Whether a log target belongs to one of this project's crates.
fn is_own_target(target: &str) -> bool {
    target.starts_with(OWN_TARGET_PREFIX)
}

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= self.max_level_for(metadata.target())
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let label = match record.level() {
            Level::Error => "error",
            Level::Warn => "warning",
            Level::Info => "info",
            Level::Debug | Level::Trace => "verbose",
        };
        eprintln!("[{label}] {}", record.args());
    }

    fn flush(&self) {}
}

static QUIET: StderrLogger = StderrLogger { verbose: false };
static VERBOSE: StderrLogger = StderrLogger { verbose: true };

/// Install the stderr logger. Call once, at startup.
///
/// If a logger is already installed (e.g. by a test harness) this is a no-op.
pub fn init(verbose: bool) {
    let logger = if verbose { &VERBOSE } else { &QUIET };
    if log::set_logger(logger).is_ok() {
        log::set_max_level(if verbose { LevelFilter::Debug } else { LevelFilter::Warn });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_own_targets_get_debug_only_when_verbose() {
        let quiet = StderrLogger { verbose: false };
        let loud = StderrLogger { verbose: true };
        assert_eq!(quiet.max_level_for("solo_ctaphid::hid"), LevelFilter::Warn);
        assert_eq!(loud.max_level_for("solo_ctaphid::hid"), LevelFilter::Debug);
        assert_eq!(loud.max_level_for("solo_ctaphid"), LevelFilter::Debug);
    }

    #[test]
    fn test_other_crates_capped_at_warn() {
        let loud = StderrLogger { verbose: true };
        assert_eq!(loud.max_level_for("reqwest::connect"), LevelFilter::Warn);
        assert_eq!(loud.max_level_for("hidapi"), LevelFilter::Warn);
    }
}
