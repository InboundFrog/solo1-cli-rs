use std::path::Path;
use std::time::Duration;

use crate::commands::restart::{RECONNECT_INTERVAL, retry_open, wait_for_normal_key};
use crate::error::{Result, SoloError};
use solo_ctaphid::HidDevice;
use solo1::firmware::{FirmwareJson, FirmwareVersion};

/// Wait after entering the bootloader, so the old firmware is gone before the first open.
const RECONNECT_SETTLE: Duration = Duration::from_millis(1500);

/// Compare the version the key reports after the restart with the release tag that was written.
///
/// The tag has the same form as the version (`4.1.5`, a leading `v` is allowed). A firmware file
/// from the user has no version, so `tag` is `None` and nothing is checked. A tag that is not a
/// version is logged and skipped.
///
/// # Errors
/// Returns an error that names both versions if they differ.
fn check_restart_version(tag: Option<&str>, reported: &FirmwareVersion) -> Result<()> {
    let Some(tag) = tag else { return Ok(()) };
    let expected = match FirmwareVersion::parse(tag) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Could not compare the firmware version: release tag {tag:?} is not a version ({e}).");
            return Ok(());
        }
    };
    if expected == *reported {
        return Ok(());
    }
    Err(SoloError::FirmwareError(format!(
        "The firmware was written and the key restarted, but it reports version {reported}, not {expected} \
         (release {tag}). Run `solo key version` and check the key."
    )))
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
/// selecting the signature fails, if writing the firmware fails, if the key
/// does not answer as a normal key again within `timeout` after the write, or
/// if the key restarts with another version than the downloaded release.
pub fn cmd_update(
    hid: &impl HidDevice,
    firmware_file: Option<&Path>,
    serial: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    use crate::github::{download_url, fetch_latest_release};
    use solo1::firmware::{FIRMWARE_RELEASES_REPO, is_firmware_asset};

    let mut release_tag = None;
    let fw_json = if let Some(path) = firmware_file {
        println!("Loading firmware from {}", path.display());
        FirmwareJson::from_file(path)?
    } else {
        println!("Fetching latest firmware from GitHub...");
        let release = fetch_latest_release(FIRMWARE_RELEASES_REPO)?;
        println!("Latest release: {}", release.tag_name);
        release_tag = Some(release.tag_name.clone());
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

    run_update(
        hid,
        &fw_json,
        release_tag.as_deref(),
        RECONNECT_SETTLE,
        timeout,
        || solo1::open(serial, timeout),
        || wait_for_normal_key(serial, timeout),
    )
}

/// The steps of the update after the firmware is loaded.
///
/// `open` opens the key in bootloader mode and `wait` waits for the restart. They are
/// arguments so that a test can pass fake devices. `settle` is the pause before the first `open`.
///
/// # Errors
/// The errors of [`cmd_update`] from the bootloader step on.
fn run_update<B: HidDevice, E: std::fmt::Display + Into<SoloError>>(
    hid: &impl HidDevice,
    fw_json: &FirmwareJson,
    release_tag: Option<&str>,
    settle: Duration,
    timeout: Duration,
    open: impl FnMut() -> std::result::Result<B, E>,
    wait: impl FnOnce() -> Result<FirmwareVersion>,
) -> Result<()> {
    use crate::commands::program::{select_signature, write_firmware};
    use solo1::crypto::sha256_hex;
    use solo1::protocol::CMD_ENTER_BOOT;

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
    std::thread::sleep(settle);
    let bl_hid = retry_open(RECONNECT_INTERVAL, timeout, open, |msg, level| {
        log::log!(level, "Could not reconnect yet: {msg}. Trying again...");
    })
    .map_err(Into::into)?;

    // Query bootloader version to select the correct signature.
    let signature = select_signature(&bl_hid, fw_json)?;
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
    let version = wait()?;
    println!("The key restarted with firmware {version}.");
    check_restart_version(release_tag, &version)?;
    println!("Firmware update complete!");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use solo_ctaphid::mock::MockDevice;
    use std::cell::RefCell;
    use std::rc::Rc;

    const V415: FirmwareVersion = FirmwareVersion::new(4, 1, 5);

    #[test]
    fn matching_tag_passes() {
        check_restart_version(Some("4.1.5"), &V415).unwrap();
        check_restart_version(Some("v4.1.5"), &V415).unwrap();
    }

    #[test]
    fn different_version_is_an_error_naming_both() {
        let text = check_restart_version(Some("4.1.5"), &FirmwareVersion::new(4, 1, 4))
            .unwrap_err()
            .to_string();
        assert!(text.contains("4.1.4") && text.contains("4.1.5"), "{text}");
        assert!(text.contains("was written"), "{text}");
    }

    #[test]
    fn unparseable_tag_is_skipped() {
        check_restart_version(Some("nightly"), &V415).unwrap();
    }

    #[test]
    fn user_file_is_not_checked() {
        check_restart_version(None, &V415).unwrap();
    }

    type Log = Rc<RefCell<Vec<&'static str>>>;

    /// A mock that writes the step of every call, and of its drop, into a shared log.
    struct Recorder {
        inner: MockDevice,
        log: Log,
        log_drop: bool,
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            if self.log_drop {
                self.log.borrow_mut().push("close");
            }
        }
    }

    impl HidDevice for Recorder {
        fn send_recv(&self, cmd: u8, data: &[u8]) -> solo_ctaphid::Result<Vec<u8>> {
            // The first byte of a bootloader packet is the bootloader command.
            let step = match (cmd, data.first()) {
                (solo1::protocol::CMD_BOOT, Some(&solo1::protocol::CMD_VERSION)) => "version",
                (solo1::protocol::CMD_BOOT, Some(&solo1::protocol::CMD_WRITE)) => "write",
                (solo1::protocol::CMD_BOOT, Some(&solo1::protocol::CMD_DONE)) => "done",
                _ => "other",
            };
            self.log.borrow_mut().push(step);
            self.inner.send_recv(cmd, data)
        }
        fn send(&self, cmd: u8, data: &[u8]) -> solo_ctaphid::Result<()> {
            if cmd == solo1::protocol::CMD_ENTER_BOOT {
                self.log.borrow_mut().push("enter_boot");
            }
            self.inner.send(cmd, data)
        }
    }

    fn recorder(log: &Log, replies: Vec<solo_ctaphid::Result<Vec<u8>>>, log_drop: bool) -> Recorder {
        Recorder {
            inner: MockDevice::new(replies),
            log: Rc::clone(log),
            log_drop,
        }
    }

    /// Replies for: bootloader version, one write, done. The first byte is the status.
    fn good_replies() -> Vec<solo_ctaphid::Result<Vec<u8>>> {
        vec![Ok(vec![0, 3, 0, 0]), Ok(vec![0]), Ok(vec![0])]
    }

    /// Run the flow with a 10 byte firmware (one write chunk) and no pause.
    fn run(
        log: &Log,
        tag: Option<&str>,
        open_ok: bool,
        replies: Vec<solo_ctaphid::Result<Vec<u8>>>,
        restarted: FirmwareVersion,
    ) -> Result<()> {
        let fw = solo1::firmware::create_firmware_json(&[0xAB; 10], &[0x01; 64]);
        let old_key = recorder(log, vec![], false);
        let mut bl = Some(recorder(log, replies, true));
        let open_log = Rc::clone(log);
        let wait_log = Rc::clone(log);
        run_update(
            &old_key,
            &fw,
            tag,
            Duration::ZERO,
            Duration::ZERO,
            move || {
                open_log.borrow_mut().push("open");
                match bl.take() {
                    Some(dev) if open_ok => Ok(dev),
                    _ => Err(SoloError::DeviceError("no key".into())),
                }
            },
            move || {
                wait_log.borrow_mut().push("wait");
                Ok(restarted)
            },
        )
    }

    #[test]
    fn steps_run_in_order_and_the_key_is_closed_before_the_wait() {
        let log = Log::default();
        run(&log, Some("4.1.5"), true, good_replies(), V415).unwrap();
        assert_eq!(
            *log.borrow(),
            ["enter_boot", "open", "version", "write", "done", "close", "wait"]
        );
    }

    #[test]
    fn restart_version_is_checked_after_the_wait() {
        let log = Log::default();
        let text = run(&log, Some("4.1.5"), true, good_replies(), FirmwareVersion::new(4, 1, 4))
            .unwrap_err()
            .to_string();
        assert!(text.contains("4.1.4") && text.contains("4.1.5"), "{text}");
        assert_eq!(log.borrow().last(), Some(&"wait"));
    }

    #[test]
    fn no_write_and_no_wait_when_the_key_does_not_open() {
        let log = Log::default();
        let err = run(&log, None, false, good_replies(), V415).unwrap_err();
        assert!(err.to_string().contains("no key"), "{err}");
        assert_eq!(log.borrow().first_chunk(), Some(&["enter_boot", "open"]));
        for step in ["version", "write", "done", "wait"] {
            assert!(!log.borrow().contains(&step), "{step} ran: {:?}", log.borrow());
        }
    }

    #[test]
    fn no_wait_when_the_write_fails() {
        let log = Log::default();
        // The write is answered with a bootloader error status.
        let replies = vec![Ok(vec![0, 3, 0, 0]), Ok(vec![1])];
        run(&log, None, true, replies, V415).unwrap_err();
        assert!(!log.borrow().contains(&"wait"), "{:?}", log.borrow());
    }
}
