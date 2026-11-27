use std::path::Path;
use std::time::{Duration, Instant};

use super::ops::get_device_version;
use crate::error::{Result, SoloError};
use solo_ctaphid::HidDevice;
use solo1::firmware::FirmwareVersion;

/// Wait after entering the bootloader, so the old firmware is gone before the first open.
const RECONNECT_SETTLE: Duration = Duration::from_millis(1500);

/// Pause between attempts to reconnect after entering the bootloader.
const RECONNECT_INTERVAL: Duration = Duration::from_millis(500);

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
fn retry_open<T, E: std::fmt::Display>(
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
    if product.is_some_and(|p| p.contains("Bootloader")) {
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

/// Update the device firmware.
///
/// After the key enters the bootloader, this reconnects to the same serial
/// number (if given) and keeps trying for up to `timeout`.
///
/// # Errors
/// Returns an error if the firmware cannot be loaded from the given file or
/// downloaded from GitHub, if the release contains no firmware asset, if the
/// firmware JSON is malformed, if reconnecting in bootloader mode fails, if
/// selecting the signature fails, if writing the firmware fails, or if the key
/// does not answer as a normal key again within `timeout` after the write.
pub fn cmd_update(
    hid: &impl HidDevice,
    firmware_file: Option<&Path>,
    serial: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    use crate::commands::program::{select_signature, write_firmware};
    use crate::github::{download_url, fetch_latest_release};
    use solo1::crypto::sha256_hex;
    use solo1::firmware::{FIRMWARE_RELEASES_REPO, FirmwareJson, is_firmware_asset};
    use solo1::protocol::CMD_ENTER_BOOT;

    let fw_json = if let Some(path) = firmware_file {
        println!("Loading firmware from {}", path.display());
        FirmwareJson::from_file(path)?
    } else {
        println!("Fetching latest firmware from GitHub...");
        let release = fetch_latest_release(FIRMWARE_RELEASES_REPO)?;
        println!("Latest release: {}", release.tag_name);
        let asset = release
            .find_asset(is_firmware_asset)
            .ok_or_else(|| SoloError::FirmwareError("No firmware JSON in release".into()))?;
        asset.check_size()?;
        println!("Downloading: {}", asset.name);
        let bytes = download_url(&asset.browser_download_url)?;
        let json_str = String::from_utf8(bytes)
            .map_err(|e| SoloError::FirmwareError(format!("Firmware JSON UTF-8 error: {e}")))?;
        serde_json::from_str(&json_str)?
    };

    let (flash_start, firmware_bytes) = fw_json.firmware_binary()?;
    println!("Firmware size: {} bytes", firmware_bytes.len());
    println!("Flash start:   0x{flash_start:08X}");
    println!("Firmware SHA-256: {}", sha256_hex(&firmware_bytes));

    // Enter bootloader mode. CMD_ENTER_BOOT (0x51) is a direct firmware vendor command —
    // not wrapped in CMD_BOOT. Device reboots immediately so no response is expected.
    println!("Entering bootloader mode...");
    let _ = hid.send(CMD_ENTER_BOOT, &[]);

    // Reconnect in bootloader mode. The device needs time to re-enumerate; the old firmware
    // has the same VID/PID, so wait before the first open.
    println!("Reconnecting...");
    std::thread::sleep(RECONNECT_SETTLE);
    let bl_hid = retry_open(
        RECONNECT_INTERVAL,
        timeout,
        || solo1::open(serial, timeout),
        |msg| log::warn!("Could not reconnect yet: {msg}. Trying again..."),
    )?;

    // Query bootloader version to select the correct signature.
    let signature = select_signature(&bl_hid, &fw_json)?;
    log::debug!(
        "Using signature ({} bytes): {}",
        signature.len(),
        hex::encode(&signature)
    );

    // Write firmware in 256-byte chunks, then verify via CMD_DONE
    write_firmware(
        &bl_hid,
        flash_start,
        &firmware_bytes,
        &signature,
        "Verifying and finalizing...",
    )?;

    // CMD_DONE only means the bootloader accepted the image. The key still has to restart.
    // The key is about to restart. An open handle to the old device is of no use and may
    // get in the way of the next open on some systems.
    drop(bl_hid);
    println!("Waiting for the key to restart...");
    let version = wait_for_restart(RECONNECT_INTERVAL, timeout, || {
        let key = solo1::open(serial, RESTART_ATTEMPT_TIMEOUT)?;
        normal_key_version(key.info().product.as_deref(), || get_device_version(&key))
    })?;
    println!("The key restarted with firmware {version}.");
    println!("Firmware update complete!");
    Ok(())
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
