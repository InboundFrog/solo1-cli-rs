/// `program` subcommand: bootloader, DFU.
use std::path::Path;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};

use crate::commands::restart::wait_for_normal_key;
use crate::error::{Result, SoloError};
use solo_ctaphid::HidDevice;
use solo1::bootloader;
use solo1::dfu::DfuDevice;
use solo1::firmware::{self, FirmwareJson, FirmwareVersion};

/// Write `firmware` to the device starting at `base_addr` with a progress bar,
/// then send `CMD_DONE` with `signature` so the bootloader verifies and reboots.
///
/// The device must already be in bootloader mode. `finalize_msg` is printed
/// between the write loop and `CMD_DONE` (callers use different wording).
///
/// # Errors
/// Returns an error if the progress-bar template is invalid, or if any
/// bootloader write or the final `CMD_DONE` command fails.
pub fn write_firmware(
    hid: &impl HidDevice,
    base_addr: u32,
    firmware: &[u8],
    signature: &[u8],
    finalize_msg: &str,
) -> Result<()> {
    let pb = ProgressBar::new(0);
    let style = ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} {msg}")
        .map_err(|e| SoloError::ProtocolError(format!("progress template: {e}")))?
        .progress_chars("##-");
    pb.set_style(style);

    bootloader::write_firmware_chunks(hid, base_addr, firmware, |done, total| {
        pb.set_length(u64::try_from(total).unwrap_or(u64::MAX));
        pb.set_position(u64::try_from(done).unwrap_or(u64::MAX));
    })?;
    pb.finish_with_message("written");

    println!("{finalize_msg}");
    bootloader::finish_firmware(hid, signature)?;
    Ok(())
}

/// Read the bootloader version, report it, and pick the matching signature.
///
/// # Errors
/// Returns an error if signature selection fails (a malformed version
/// constraint, or a signature that is not valid websafe base64).
pub fn select_signature(hid: &impl HidDevice, fw: &FirmwareJson) -> Result<Vec<u8>> {
    let version = firmware::read_bootloader_version(hid);
    match &version {
        Some(v) => println!("Bootloader version: {v}"),
        None => println!("Could not read bootloader version; using default signature."),
    }
    Ok(fw.signature_for_bootloader(version.as_ref())?)
}

/// Program via the Solo bootloader (firmware.json format).
/// The device must already be in bootloader mode when this is called.
///
/// After the write, the key restarts. This waits until it answers as a normal key again,
/// for at most `timeout`, and prints its firmware version. `serial` selects the key to wait for.
///
/// # Errors
/// Returns an error if the firmware JSON cannot be loaded or parsed, if
/// selecting the signature fails, if writing the firmware fails, or if the key
/// does not answer as a normal key again within `timeout` after the write.
pub fn cmd_program_bootloader(
    hid: impl HidDevice,
    firmware_json: &Path,
    serial: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    program_bootloader_then(hid, firmware_json, || wait_for_normal_key(serial, timeout))
}

/// Write the firmware, close the device, then run `wait` and print the version it returns.
/// `wait` is not run if the write fails.
fn program_bootloader_then(
    hid: impl HidDevice,
    firmware_json: &Path,
    wait: impl FnOnce() -> Result<FirmwareVersion>,
) -> Result<()> {
    log::debug!("Loading firmware JSON: {}", firmware_json.display());
    let fw = FirmwareJson::from_file(firmware_json)?;
    let (flash_start, firmware_bytes) = fw.firmware_binary()?;

    println!("Firmware size: {} bytes", firmware_bytes.len());
    println!("Flash start:   0x{flash_start:08X}");
    log::debug!("Firmware SHA256: {}", hex::encode(Sha256::digest(&firmware_bytes)));

    // Read the bootloader version before writing. The version decides which
    // signature to use. The BootVersion command also clears the bootloader's
    // internal has_erased flag, so sending it after writes start would erase
    // the application again. The Python tool uses the same order.
    let signature = select_signature(&hid, &fw)?;
    log::debug!("Signature ({} bytes): {}", signature.len(), hex::encode(&signature));

    write_firmware(&hid, flash_start, &firmware_bytes, &signature, "Finalizing firmware...")?;

    // CMD_DONE only means the bootloader accepted the image. The key still has to restart.
    // An open handle to the old device is of no use and may get in the way of the next open.
    drop(hid);
    println!("Waiting for the key to restart...");
    let version = wait()?;
    println!("The key restarted with firmware {version}.");
    println!("Done.");
    Ok(())
}

/// Program via ST DFU (firmware.hex format).
///
/// # Errors
/// Returns an error if the HEX file cannot be parsed, if the DFU device cannot
/// be opened, or if DFU programming fails.
pub fn cmd_program_dfu(firmware_hex: &Path) -> Result<()> {
    use solo1::firmware::parse_hex_file;

    println!("Parsing firmware HEX file: {}", firmware_hex.display());
    let (base_addr, firmware_bytes) = parse_hex_file(firmware_hex)?;
    println!(
        "Base address: 0x{:08X}, size: {} bytes",
        base_addr,
        firmware_bytes.len()
    );

    println!("Opening ST DFU device (VID=0x0483, PID=0xDF11)...");
    let dfu = DfuDevice::open()?;

    println!("Programming {} bytes via DFU...", firmware_bytes.len());
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} chunks")
            .map_err(|e| SoloError::FirmwareError(format!("Progress bar style error: {e}")))?
            .progress_chars("##-"),
    );
    dfu.program(base_addr, &firmware_bytes, |done, total| {
        pb.set_length(u64::try_from(total).unwrap_or(u64::MAX));
        pb.set_position(u64::try_from(done).unwrap_or(u64::MAX));
    })?;
    pb.finish_with_message("Done");
    println!("DFU programming complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use solo_ctaphid::mock::MockDevice;
    use std::cell::Cell;
    use std::rc::Rc;

    /// A mock that records when it is dropped.
    struct DropFlag {
        inner: MockDevice,
        dropped: Rc<Cell<bool>>,
    }

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    impl HidDevice for DropFlag {
        fn send_recv(&self, cmd: u8, data: &[u8]) -> solo_ctaphid::Result<Vec<u8>> {
            self.inner.send_recv(cmd, data)
        }
        fn send(&self, cmd: u8, data: &[u8]) -> solo_ctaphid::Result<()> {
            self.inner.send(cmd, data)
        }
    }

    /// Firmware file with 10 bytes: one write chunk.
    fn firmware_file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        let json = solo1::firmware::create_firmware_json(&[0xAB; 10], &[0x01; 64]);
        let path = dir.path().join("fw.json");
        std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();
        path
    }

    /// Replies for: bootloader version, one write, done. The first byte is the status.
    fn good_replies() -> Vec<solo_ctaphid::Result<Vec<u8>>> {
        vec![Ok(vec![0, 3, 0, 0]), Ok(vec![0]), Ok(vec![0])]
    }

    fn device(replies: Vec<solo_ctaphid::Result<Vec<u8>>>) -> (DropFlag, Rc<Cell<bool>>) {
        let dropped = Rc::new(Cell::new(false));
        let dev = DropFlag {
            inner: MockDevice::new(replies),
            dropped: Rc::clone(&dropped),
        };
        (dev, dropped)
    }

    #[test]
    fn waits_after_write_with_device_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (dev, dropped) = device(good_replies());
        let mut waited = false;
        program_bootloader_then(dev, &firmware_file(&dir), || {
            waited = true;
            assert!(dropped.get(), "the device must be closed before the wait");
            Ok(FirmwareVersion::new(4, 1, 5))
        })
        .unwrap();
        assert!(waited);
    }

    #[test]
    fn wait_error_is_returned() {
        let dir = tempfile::tempdir().unwrap();
        let (dev, _) = device(good_replies());
        let r = program_bootloader_then(dev, &firmware_file(&dir), || {
            Err(SoloError::FirmwareError("did not restart".into()))
        });
        assert!(r.unwrap_err().to_string().contains("did not restart"));
    }

    #[test]
    fn no_wait_when_write_fails() {
        let dir = tempfile::tempdir().unwrap();
        // The write is answered with a bootloader error status.
        let (dev, _) = device(vec![Ok(vec![0, 3, 0, 0]), Ok(vec![1])]);
        let r = program_bootloader_then(dev, &firmware_file(&dir), || {
            panic!("must not wait after a failed write")
        });
        assert!(r.is_err());
    }
}
