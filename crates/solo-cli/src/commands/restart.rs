//! Wait for the key to restart after a firmware write.

use std::time::{Duration, Instant};

use super::key::common::is_bootloader;
use super::key::get_device_version;
use crate::error::{Result, SoloError};
use solo1::firmware::FirmwareVersion;

/// Pause between attempts to reconnect to the key.
pub const RECONNECT_INTERVAL: Duration = Duration::from_millis(500);

/// I/O timeout for the version query in each attempt after a firmware write.
/// The init handshake in `open` has its own fixed 5 second limit.
const RESTART_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the retry loop runs before a failed try is shown at warn level.
/// Until then the messages are debug records, so a key that is only a little
/// slow to appear does not make a good run look like a problem.
const WARN_AFTER: Duration = Duration::from_secs(5);

/// Call `open` until it succeeds or `total` has passed.
///
/// Sleeps `interval` after each failed attempt. Tries at least once. One
/// attempt can run past `total` by however long that attempt takes.
///
/// Each failed attempt that will be tried again is passed to `report` as text,
/// with `Level::Debug` for the first `WARN_AFTER` and `Level::Warn` after that.
/// A message is passed at warn level only once, however often it comes back.
/// The error from the last attempt is not reported. It is returned.
///
/// # Errors
/// Returns the error of the last attempt when the time is up.
pub fn retry_open<T, E: std::fmt::Display>(
    interval: Duration,
    total: Duration,
    open: impl FnMut() -> std::result::Result<T, E>,
    report: impl FnMut(&str, log::Level),
) -> std::result::Result<T, E> {
    let start = Instant::now();
    retry_with_clock(|| start.elapsed(), std::thread::sleep, interval, total, open, report)
}

/// `retry_open` with the clock and the sleep passed in, so tests need no real time.
fn retry_with_clock<T, E: std::fmt::Display>(
    elapsed: impl Fn() -> Duration,
    mut sleep: impl FnMut(Duration),
    interval: Duration,
    total: Duration,
    mut open: impl FnMut() -> std::result::Result<T, E>,
    mut report: impl FnMut(&str, log::Level),
) -> std::result::Result<T, E> {
    let mut warned: Vec<String> = Vec::new();
    loop {
        match open() {
            Ok(v) => return Ok(v),
            Err(e) => {
                let now = elapsed();
                if now >= total {
                    return Err(e);
                }
                let message = e.to_string();
                if now < WARN_AFTER {
                    report(&message, log::Level::Debug);
                } else if !warned.contains(&message) {
                    report(&message, log::Level::Warn);
                    warned.push(message);
                }
                sleep(interval);
            }
        }
    }
}

/// Check that the key is a normal key and return the firmware version it reports.
///
/// A key whose USB product name contains `Bootloader` is still in the bootloader.
/// The bootloader also answers the version query, with its own version, so the
/// product name is the only way to tell, and `query` is not run then.
/// A missing product name counts as a normal key, so a good update never looks failed.
fn normal_key_version(
    product: Option<&str>,
    query: impl FnOnce() -> Result<FirmwareVersion>,
) -> Result<FirmwareVersion> {
    if is_bootloader(product) {
        return Err(SoloError::DeviceError("The key is still in the bootloader".into()));
    }
    query()
}

/// Wait until `try_once` shows a normal key again, for at most `total`.
///
/// A failed attempt is expected while the key restarts, so it is only logged at debug level.
///
/// # Errors
/// Returns an error that tells the user to unplug the key and plug it in again, if no
/// attempt succeeded in time.
fn wait_for_restart(
    interval: Duration,
    total: Duration,
    try_once: impl FnMut() -> Result<FirmwareVersion>,
) -> Result<FirmwareVersion> {
    retry_open(interval, total, try_once, |msg, _| {
        log::debug!("The key has not restarted yet: {msg}");
    })
    .map_err(|e| {
        SoloError::FirmwareError(format!(
            "The firmware was written and the bootloader accepted it, but the key did not answer \
             as a normal key within {} seconds. Unplug the key, plug it in again, and run \
             `solo key version`. (Last error: {e})",
            total.as_secs()
        ))
    })
}

/// Wait until the key at `serial` answers as a normal key again, and return its firmware version.
///
/// Opens the key again on every attempt. Use this after a firmware write.
///
/// # Errors
/// Returns an error that tells the user to unplug the key and plug it in again, if no
/// attempt succeeded within `timeout`.
pub fn wait_for_normal_key(serial: Option<&str>, timeout: Duration) -> Result<FirmwareVersion> {
    wait_for_restart(RECONNECT_INTERVAL, timeout, || {
        let key = solo1::open(serial, RESTART_ATTEMPT_TIMEOUT)?;
        normal_key_version(key.info().product.as_deref(), || get_device_version(&key))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const TICK: Duration = Duration::from_millis(1);

    fn v415() -> FirmwareVersion {
        FirmwareVersion::new(4, 1, 5)
    }

    #[test]
    fn wait_for_restart_succeeds_after_failures() {
        let mut calls = 0;
        let r = wait_for_restart(TICK, Duration::from_secs(5), || {
            calls += 1;
            if calls < 3 { Err(SoloError::Timeout) } else { Ok(v415()) }
        });
        assert_eq!(r.unwrap(), v415());
        assert_eq!(calls, 3);
    }

    #[test]
    fn wait_for_restart_gives_advice_when_key_never_returns() {
        let r = wait_for_restart(TICK, Duration::from_millis(20), || Err(SoloError::Timeout));
        let text = r.unwrap_err().to_string();
        assert!(text.contains("the bootloader accepted it"), "{text}");
        assert!(
            text.contains(&format!("(Last error: {})", SoloError::Timeout)),
            "{text}"
        );
        assert!(
            text.contains("did not answer as a normal key within 0 seconds"),
            "{text}"
        );
        assert!(
            text.contains("Unplug the key, plug it in again, and run `solo key version`"),
            "{text}"
        );
    }

    #[test]
    fn bootloader_is_not_a_normal_key() {
        let r = normal_key_version(Some("Solo Bootloader 3.0.0"), || {
            panic!("must not query the bootloader")
        });
        assert!(r.is_err());
    }

    #[test]
    fn normal_key_reports_version() {
        assert_eq!(normal_key_version(Some("Solo 4.1.5"), || Ok(v415())).unwrap(), v415());
        assert_eq!(normal_key_version(None, || Ok(v415())).unwrap(), v415());
        assert!(normal_key_version(Some("Solo 4.1.5"), || Err(SoloError::Timeout)).is_err());
    }

    #[test]
    fn wait_for_restart_keeps_waiting_while_bootloader() {
        let mut calls = 0;
        let r = wait_for_restart(TICK, Duration::from_secs(5), || {
            calls += 1;
            let product = if calls < 3 {
                "Solo Bootloader 3.0.0"
            } else {
                "Solo 4.1.5"
            };
            normal_key_version(Some(product), || Ok(v415()))
        });
        assert_eq!(r.unwrap(), v415());
        assert_eq!(calls, 3);
    }

    use log::Level::{Debug, Warn};
    use std::cell::Cell;

    /// Run `retry_with_clock` on a fake clock. Each sleep is one second.
    /// `errors` is the error of each try; the run ends when they are used up.
    fn run(
        total_secs: u64,
        errors: &[&'static str],
    ) -> (Vec<(String, log::Level)>, i32, std::result::Result<(), &'static str>) {
        let now = Cell::new(Duration::ZERO);
        let mut errors = errors.iter();
        let mut reports = Vec::new();
        let mut calls = 0;
        let result = retry_with_clock(
            || now.get(),
            |d| now.set(now.get().saturating_add(d)),
            Duration::from_secs(1),
            Duration::from_secs(total_secs),
            || {
                calls = i32::saturating_add(calls, 1);
                errors.next().map_or(Ok(()), |e| Err(*e))
            },
            |m, l| reports.push((m.to_owned(), l)),
        );
        (reports, calls, result)
    }

    #[test]
    fn failed_tries_are_debug_until_warn_after() {
        // Tries at 0..=4 s are quiet. The tries at 5 s and later are loud.
        let errors = ["e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8"];
        let (reports, ..) = run(100, &errors);
        let levels: Vec<_> = reports.iter().map(|r| r.1).collect();
        assert_eq!(levels, [Debug, Debug, Debug, Debug, Debug, Warn, Warn, Warn, Warn]);
    }

    #[test]
    fn a_good_run_within_warn_after_prints_no_warning() {
        let (reports, calls, _) = run(100, &["down", "down", "down"]);
        assert_eq!(calls, 4);
        assert!(reports.iter().all(|r| r.1 == Debug), "{reports:?}");
    }

    #[test]
    fn warn_messages_that_alternate_are_printed_once_each() {
        let errors = ["x"; 5]
            .into_iter()
            .chain(["A", "B", "A", "B", "A", "B", "C"])
            .collect::<Vec<_>>();
        let (reports, ..) = run(100, &errors);
        let warns: Vec<_> = reports.iter().filter(|r| r.1 == Warn).map(|r| r.0.as_str()).collect();
        assert_eq!(warns, ["A", "B", "C"]);
    }

    #[test]
    fn the_last_error_is_returned_and_not_reported() {
        // Tries run at 0 s, 1 s, 2 s and 3 s. The try at 3 s is the last.
        let (reports, calls, result) = run(3, &["a", "b", "c", "d", "e"]);
        assert_eq!(calls, 4);
        assert_eq!(result, Err("d"));
        let texts: Vec<_> = reports.iter().map(|r| r.0.as_str()).collect();
        assert_eq!(texts, ["a", "b", "c"]);
    }

    #[test]
    fn success_after_failures_returns_ok() {
        let (_, calls, result) = run(100, &["a", "b"]);
        assert_eq!(calls, 3);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn retry_open_immediate_success_reports_nothing() {
        let mut reports: Vec<String> = Vec::new();
        let r: std::result::Result<&str, &str> = retry_open(
            TICK,
            Duration::from_secs(5),
            || Ok("up"),
            |m, _| reports.push(m.to_owned()),
        );
        assert_eq!(r, Ok("up"));
        assert_eq!(reports, Vec::<String>::new());
    }
}
