use std::path::Path;
use std::time::Duration;

use crate::commands::restart::{RECONNECT_INTERVAL, retry_open, wait_for_normal_key};
use crate::error::{Result, SoloError};
use solo_ctaphid::HidDevice;
use solo1::firmware::FirmwareVersion;

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
    use crate::commands::program::{select_signature, write_firmware};
    use crate::github::{download_url, fetch_latest_release};
    use solo1::crypto::sha256_hex;
    use solo1::firmware::{FIRMWARE_RELEASES_REPO, FirmwareJson, is_firmware_asset};
    use solo1::protocol::CMD_ENTER_BOOT;

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
    let version = wait_for_normal_key(serial, timeout)?;
    println!("The key restarted with firmware {version}.");
    check_restart_version(release_tag.as_deref(), &version)?;
    println!("Firmware update complete!");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

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
}
