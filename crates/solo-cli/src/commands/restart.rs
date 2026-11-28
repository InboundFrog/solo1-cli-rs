use std::time::{Duration, Instant};

use super::key::common::is_bootloader;
use super::key::get_device_version;
use crate::error::{Result, SoloError};
use solo1::firmware::FirmwareVersion;

/// Wait after entering the bootloader, so the old firmware is gone before the first open.
pub const RECONNECT_SETTLE: Duration = Duration::from_millis(1500);

/// Pause between attempts to reconnect after entering the bootloader.
pub const RECONNECT_INTERVAL: Duration = Duration::from_millis(500);

/// I/O timeout for the version query in each attempt after the update.
/// The init handshake in `open` has its own fixed 5 second limit.
const RESTART_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// Call `open` until it succeeds or `total` has passed.
///
/// Sleeps `interval` after each failed attempt. Tries at least once. One
/// attempt can run past `total` by however long that attempt takes.
///
/// Each failed attempt that will be tried again is passed to `report` as text.
/// A message that is the same as the one just before it is not reported again.
/// The error from the last attempt is not reported. It is returned.
///
/// # Errors
/// Returns the error of the last attempt when the time is up.
pub fn retry_open<T, E: std::fmt::Display>(
    interval: Duration,
    total: Duration,
    mut open: impl FnMut() -> std::result::Result<T, E>,
    mut report: impl FnMut(&str),
) -> std::result::Result<T, E> {
    let start = Instant::now();
    let mut last_reported = String::new();
    loop {
        match open() {
            Ok(v) => return Ok(v),
            Err(e) if start.elapsed() >= total => return Err(e),
            Err(e) => {
                let message = e.to_string();
                if message != last_reported {
                    report(&message);
                    last_reported = message;
                }
                std::thread::sleep(interval);
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
    retry_open(interval, total, try_once, |msg| {
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

    #[test]
    fn retry_open_succeeds_after_two_failures() {
        let mut calls = 0;
        let mut reports: Vec<String> = Vec::new();
        let r: std::result::Result<&str, &str> = retry_open(
            TICK,
            Duration::from_secs(5),
            || {
                calls += 1;
                if calls < 3 { Err("down") } else { Ok("up") }
            },
            |m| reports.push(m.to_owned()),
        );
        assert_eq!(r, Ok("up"));
        assert_eq!(calls, 3);
        assert_eq!(reports, ["down"]);
    }

    #[test]
    fn retry_open_returns_last_error_at_deadline() {
        let mut calls = 0;
        let mut reports: Vec<String> = Vec::new();
        let r: std::result::Result<(), i32> = retry_open(
            TICK,
            Duration::from_millis(20),
            || {
                calls += 1;
                Err(calls)
            },
            |m| reports.push(m.to_owned()),
        );
        assert_eq!(r, Err(calls));
        assert!(calls > 1);
        assert_eq!(reports, (1..calls).map(|n| n.to_string()).collect::<Vec<_>>());
    }

    #[test]
    fn retry_open_reports_changes_only() {
        let mut errors = ["a", "a", "b", "a"].into_iter();
        let mut reports: Vec<String> = Vec::new();
        let r: std::result::Result<&str, &str> = retry_open(
            TICK,
            Duration::from_secs(5),
            || errors.next().map_or(Ok("up"), Err),
            |m| reports.push(m.to_owned()),
        );
        assert_eq!(r, Ok("up"));
        assert_eq!(reports, ["a", "b", "a"]);
    }

    #[test]
    fn retry_open_immediate_success_reports_nothing() {
        let mut reports: Vec<String> = Vec::new();
        let r: std::result::Result<&str, &str> = retry_open(
            TICK,
            Duration::from_secs(5),
            || Ok("up"),
            |m| reports.push(m.to_owned()),
        );
        assert_eq!(r, Ok("up"));
        assert_eq!(reports, Vec::<String>::new());
    }
}
