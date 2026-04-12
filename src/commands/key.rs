/// Commands in the `key` subgroup: RNG, FIDO2, version, wink, ping, etc.
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::device::{
    SoloHid, CMD_GET_VERSION, CMD_PROBE, CMD_RNG, CTAPHID_CBOR, CTAPHID_PING, CTAPHID_WINK,
};
use crate::vlog;
use crate::error::{Result, SoloError};
use crate::firmware::FirmwareVersion;

/// Get N random bytes from the device, return as hex string.
pub fn cmd_rng_hexbytes(hid: &SoloHid, n: usize) -> Result<String> {
    let request = [n as u8];
    let response = hid.send_recv(CMD_RNG, &request)?;
    Ok(hex::encode(&response[..response.len().min(n)]))
}

/// Stream raw random bytes to stdout.
pub fn cmd_rng_raw(hid: &SoloHid) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    loop {
        let request = [64u8];
        let response = hid.send_recv(CMD_RNG, &request)?;
        out.write_all(&response)?;
        out.flush()?;
    }
}

/// Feed entropy to /dev/random (Linux only).
#[cfg(target_os = "linux")]
pub fn cmd_rng_feedkernel(hid: &SoloHid) -> Result<()> {
    use std::fs::OpenOptions;

    let mut dev_random = OpenOptions::new().write(true).open("/dev/random")?;

    println!("Feeding entropy to /dev/random. Press Ctrl+C to stop.");
    loop {
        let request = [64u8];
        let response = hid.send_recv(CMD_RNG, &request)?;
        dev_random.write_all(&response)?;
        dev_random.flush()?;
    }
}

#[cfg(not(target_os = "linux"))]
pub fn cmd_rng_feedkernel(_hid: &SoloHid) -> Result<()> {
    Err(SoloError::UnsupportedPlatform)
}

/// Create a FIDO2 credential with hmac-secret extension.
/// TODO: Implement full CTAP2 command sequence:
///   1. Send CTAPHID_CBOR with CTAP2 command 0x01 (makeCredential)
///   2. clientDataHash: SHA256 of client data
///   3. rp: {"id": rp_id, "name": rp_id}
///   4. user: {"id": random 32 bytes, "name": "user"}
///   5. pubKeyCredParams: [{"type": "public-key", "alg": -7}] (ES256)
///   6. extensions: {"hmac-secret": true}
///   7. options: {"rk": true}  (resident key)
///   8. Parse CBOR response to get credential ID and public key
pub fn cmd_make_credential(hid: &SoloHid, rp_id: &str) -> Result<()> {
    // Stub: connect to device and show it's reachable, then explain TODO
    let _version = get_device_version(hid)?;
    println!("Connected to device.");
    println!(
        "TODO: Full CTAP2 makeCredential for RP '{}' with hmac-secret extension not yet implemented.",
        rp_id
    );
    println!("The CTAP2 command sequence would:");
    println!("  1. Send CTAPHID_CBOR (0x90) with CBOR-encoded makeCredential (0x01) request");
    println!("  2. Include hmac-secret extension in the request");
    println!("  3. Return credential ID and public key from the response");
    Ok(())
}

/// HMAC-secret challenge-response.
/// TODO: Implement full CTAP2 sequence:
///   1. Generate a client assertion using hmac-secret extension
///   2. CTAP2 getAssertion (0x02) with allowList containing credential
///   3. salt = SHA256(secret || rp_id)
///   4. Return the HMAC output from the device
pub fn cmd_challenge_response(hid: &SoloHid, rp_id: &str, secret: &str) -> Result<()> {
    let _version = get_device_version(hid)?;
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(rp_id.as_bytes());
    let salt = hasher.finalize();
    println!("Connected to device.");
    println!("Salt (SHA256(secret || rp_id)): {}", hex::encode(salt));
    println!(
        "TODO: Full CTAP2 getAssertion with hmac-secret for RP '{}' not yet implemented.",
        rp_id
    );
    Ok(())
}

/// Verify key authenticity via attestation certificate.
/// TODO: Implement full CTAP2 sequence:
///   1. makeCredential with direct attestation request
///   2. Extract attestation certificate from response
///   3. Verify certificate chain
///   4. Check fingerprint against known values
pub fn cmd_verify(hid: &SoloHid) -> Result<()> {
    let _version = get_device_version(hid)?;
    println!("Connected to device.");
    println!("TODO: Full attestation verification not yet implemented.");
    println!("This would:");
    println!("  1. Request a new credential with direct attestation");
    println!("  2. Extract the attestation certificate DER");
    println!("  3. SHA-256 fingerprint the cert and compare to known values:");
    println!("     - Solo <= 3.0.0: 1b2626ec...");
    println!("     - Solo Hacker:   a149e0ea...");
    println!("     - Somu:          3e3169e0...");
    Ok(())
}

/// Get firmware version from the device.
pub fn cmd_key_version(hid: &SoloHid) -> Result<FirmwareVersion> {
    get_device_version(hid)
}

fn get_device_version(hid: &SoloHid) -> Result<FirmwareVersion> {
    let response = hid.send_recv(CMD_GET_VERSION, &[])?;
    if response.len() < 3 {
        return Err(SoloError::ProtocolError(
            "Version response too short".into(),
        ));
    }
    Ok(FirmwareVersion::new(
        response[0] as u32,
        response[1] as u32,
        response[2] as u32,
    ))
}

/// Blink the LED on the device.
pub fn cmd_wink(hid: &SoloHid) -> Result<()> {
    hid.send_recv(CTAPHID_WINK, &[])?;
    println!("Winked!");
    Ok(())
}

/// Send ping(s) and measure round-trip time.
pub fn cmd_ping(hid: &SoloHid, count: u32, data: &[u8]) -> Result<()> {
    for i in 0..count {
        let start = Instant::now();
        let response = hid.send_recv(CTAPHID_PING, data)?;
        let elapsed = start.elapsed();

        if response != data {
            return Err(SoloError::DeviceError(
                "Ping response data mismatch".into(),
            ));
        }
        println!(
            "Ping {}: {} bytes, RTT = {:.3}ms",
            i + 1,
            data.len(),
            elapsed.as_secs_f64() * 1000.0
        );
    }
    Ok(())
}

/// Program a keyboard sequence (HID keyboard emulation).
pub fn cmd_keyboard(hid: &SoloHid, data: &[u8]) -> Result<()> {
    if data.len() > 64 {
        return Err(SoloError::DeviceError(
            "Keyboard data too long (max 64 bytes)".into(),
        ));
    }
    // Use a vendor command for keyboard programming
    // This uses CTAPHID_VENDOR_FIRST + offset
    let cmd = 0x53u8; // vendor keyboard command
    hid.send_recv(cmd, data)?;
    println!("Keyboard sequence programmed ({} bytes)", data.len());
    Ok(())
}

/// Factory reset the device.
pub fn cmd_reset(hid: &SoloHid) -> Result<()> {
    // CTAP2 authenticatorReset = 0x07
    // Send via CTAPHID_CBOR
    let cbor_reset = vec![0x07u8];
    hid.send_recv(CTAPHID_CBOR, &cbor_reset)?;
    println!("Device reset successfully.");
    Ok(())
}

/// Change the existing PIN (prompts for old and new PIN).
/// TODO: Full CTAP2 clientPin sequence:
///   1. CTAP2 authenticatorClientPIN (0x06) subcommand getPINToken
///   2. Key agreement, PIN hash exchange (see CTAP2 spec section 6.5)
///   3. changePin subcommand with encrypted new PIN
pub fn cmd_change_pin(hid: &SoloHid) -> Result<()> {
    let _version = get_device_version(hid)?;
    let old_pin = rpassword::prompt_password("Current PIN: ")
        .map_err(|e| SoloError::IoError(e))?;
    let new_pin = rpassword::prompt_password("New PIN: ")
        .map_err(|e| SoloError::IoError(e))?;
    let confirm_pin = rpassword::prompt_password("Confirm new PIN: ")
        .map_err(|e| SoloError::IoError(e))?;

    if new_pin != confirm_pin {
        return Err(SoloError::DeviceError("PINs do not match".into()));
    }
    if new_pin.len() < 4 {
        return Err(SoloError::DeviceError("PIN must be at least 4 characters".into()));
    }

    println!("TODO: Full CTAP2 changePin command not yet implemented.");
    println!("Old PIN: {} chars, New PIN: {} chars", old_pin.len(), new_pin.len());
    println!("The CTAP2 sequence would use authenticatorClientPIN (0x06) changePin subcommand.");
    Ok(())
}

/// Set PIN on an unpinned key (prompts for new PIN).
/// TODO: Full CTAP2 clientPin sequence:
///   1. CTAP2 authenticatorClientPIN (0x06) subcommand setPin
///   2. Key agreement and PIN hash per CTAP2 spec
pub fn cmd_set_pin(hid: &SoloHid) -> Result<()> {
    let _version = get_device_version(hid)?;
    let new_pin = rpassword::prompt_password("New PIN: ")
        .map_err(|e| SoloError::IoError(e))?;
    let confirm_pin = rpassword::prompt_password("Confirm PIN: ")
        .map_err(|e| SoloError::IoError(e))?;

    if new_pin != confirm_pin {
        return Err(SoloError::DeviceError("PINs do not match".into()));
    }
    if new_pin.len() < 4 {
        return Err(SoloError::DeviceError("PIN must be at least 4 characters".into()));
    }

    println!("TODO: Full CTAP2 setPin command not yet implemented.");
    println!("New PIN: {} chars", new_pin.len());
    println!("The CTAP2 sequence would use authenticatorClientPIN (0x06) setPin subcommand.");
    Ok(())
}

/// Permanently disable firmware updates on the device.
pub fn cmd_disable_updates(hid: &SoloHid) -> Result<()> {
    use crate::device::CMD_DISABLE_BOOTLOADER;
    println!(
        "WARNING: This will permanently disable firmware updates on this device!"
    );
    println!("This action cannot be undone. Are you sure? (type 'yes' to confirm)");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "yes" {
        println!("Aborted.");
        return Ok(());
    }
    hid.send_bootloader_cmd(CMD_DISABLE_BOOTLOADER, 0, &[])?;
    println!("Firmware updates have been permanently disabled.");
    Ok(())
}

/// Run a hash probe on the device.
pub fn cmd_probe(hid: &SoloHid, hash_type: &str) -> Result<()> {
    let hash_code: u8 = match hash_type {
        "sha256" => 0x01,
        "sha512" => 0x02,
        "rsa2048" => 0x03,
        "ed25519" => 0x04,
        other => {
            return Err(SoloError::DeviceError(format!(
                "Unknown hash type: {}. Valid: sha256, sha512, rsa2048, ed25519",
                other
            )))
        }
    };
    let response = hid.send_recv(CMD_PROBE, &[hash_code])?;
    println!("Probe result ({}): {}", hash_type, hex::encode(&response));
    Ok(())
}

/// Sign a file with a resident credential.
/// TODO: Full CTAP2 getAssertion sequence:
///   1. Hash the file with SHA-256
///   2. Use as clientDataHash in getAssertion
///   3. No allowList (use resident key)
///   4. Return the assertion response including signature
pub fn cmd_sign_file(hid: &SoloHid, filename: &Path) -> Result<()> {
    let _version = get_device_version(hid)?;
    let data = std::fs::read(filename)?;
    let hash = sha2::Sha256::digest(&data);
    println!("File: {:?}", filename);
    println!("SHA-256: {}", hex::encode(hash));
    println!("TODO: Full CTAP2 getAssertion with resident key not yet implemented.");
    println!("The CTAP2 sequence would use the SHA-256 as clientDataHash in an assertion request.");
    Ok(())
}

/// Update the device firmware.
pub fn cmd_update(hid: &SoloHid, firmware_file: Option<&Path>) -> Result<()> {
    use crate::device::{CMD_ENTER_BOOT, CMD_WRITE, CMD_DONE, CMD_VERSION};
    use crate::firmware::{fetch_latest_release, download_url, FirmwareJson, FirmwareVersion};
    use crate::crypto::sha256_hex;
    use indicatif::{ProgressBar, ProgressStyle};

    let fw_json = if let Some(path) = firmware_file {
        println!("Loading firmware from {:?}", path);
        FirmwareJson::from_file(path)?
    } else {
        println!("Fetching latest firmware from GitHub...");
        let release = fetch_latest_release()?;
        println!("Latest release: {}", release.tag_name);
        let asset = release
            .find_firmware_asset()
            .ok_or_else(|| SoloError::FirmwareError("No firmware JSON in release".into()))?;
        println!("Downloading: {}", asset.name);
        let bytes = download_url(&asset.browser_download_url)?;
        let json_str = String::from_utf8(bytes)
            .map_err(|e| SoloError::FirmwareError(format!("Firmware JSON UTF-8 error: {}", e)))?;
        serde_json::from_str(&json_str)?
    };

    let (flash_start, firmware_bytes) = fw_json.firmware_binary()?;
    println!("Firmware size: {} bytes", firmware_bytes.len());
    println!("Flash start:   0x{:08X}", flash_start);
    println!("Firmware SHA-256: {}", sha256_hex(&firmware_bytes));

    // Enter bootloader mode. CMD_ENTER_BOOT (0x51) is a direct firmware vendor command —
    // not wrapped in CMD_BOOT. Device reboots immediately so no response is expected.
    println!("Entering bootloader mode...");
    let _ = hid.send(CMD_ENTER_BOOT, &[]);

    // Delay for device to re-enumerate in bootloader mode
    std::thread::sleep(std::time::Duration::from_millis(1500));

    // Reconnect in bootloader mode
    println!("Reconnecting...");
    let bl_hid = SoloHid::open_bootloader(None)?;

    // Query bootloader version to select the correct signature
    let version = match bl_hid.send_bootloader_cmd(CMD_VERSION, 0, &[]) {
        Ok(resp) if resp.len() >= 3 => {
            let v = FirmwareVersion::new(resp[0] as u32, resp[1] as u32, resp[2] as u32);
            println!("Bootloader version: {}", v);
            v
        }
        Ok(resp) if !resp.is_empty() => {
            let v = FirmwareVersion::new(0, 0, resp[0] as u32);
            println!("Bootloader version: {}", v);
            v
        }
        _ => {
            println!("Could not read bootloader version, using default signature.");
            FirmwareVersion::new(0, 0, 0)
        }
    };

    let signature = fw_json.signature_for_version(&version)?;
    vlog!("Using signature ({} bytes): {}", signature.len(), hex::encode(&signature));

    // Write firmware in 256-byte chunks
    const CHUNK_SIZE: usize = 256;

    let pb = ProgressBar::new(firmware_bytes.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes}")
            .unwrap()
            .progress_chars("##-"),
    );

    let mut offset = 0usize;
    let mut addr = flash_start;
    while offset < firmware_bytes.len() {
        let end = (offset + CHUNK_SIZE).min(firmware_bytes.len());
        let chunk = &firmware_bytes[offset..end];
        bl_hid.send_bootloader_cmd(CMD_WRITE, addr, chunk)?;
        pb.inc(chunk.len() as u64);
        offset = end;
        addr += CHUNK_SIZE as u32;
    }
    pb.finish_with_message("Written");

    // CMD_DONE sends the ECDSA signature; bootloader verifies it and reboots on success
    println!("Verifying and finalizing...");
    bl_hid.send_bootloader_cmd(CMD_DONE, 0, &signature)?;

    println!("Firmware update complete!");
    Ok(())
}

/// Credential management subcommands.
pub mod credential {
    use super::*;
    use crate::device::CTAPHID_CBOR;

    /// Get credential slot info.
    /// TODO: Full CTAP2 authenticatorGetInfo (0x04) to read credential capacity
    pub fn cmd_credential_info(hid: &SoloHid) -> Result<()> {
        let _version = get_device_version(hid)?;
        // CTAP2 getInfo
        let cbor_get_info = vec![0x04u8];
        let _response = hid.send_recv(CTAPHID_CBOR, &cbor_get_info)?;
        println!("TODO: Full CTAP2 getInfo parsing not yet implemented.");
        println!("The response would include 'maxCredentialCountInList' and 'remainingDiscoverableCredentials'.");
        Ok(())
    }

    /// List resident credentials.
    /// TODO: Full CTAP2 authenticatorCredentialManagement (0x0A) enumerateRPsBegin
    /// followed by enumerateCredentialsBegin/Next for each RP
    pub fn cmd_credential_ls(hid: &SoloHid) -> Result<()> {
        let _version = get_device_version(hid)?;
        println!("TODO: Full CTAP2 credential enumeration not yet implemented.");
        println!("The sequence would use authenticatorCredentialManagement (0x0A):");
        println!("  1. enumerateRPsBegin (subcommand 0x02) to get list of RPs");
        println!("  2. For each RP, enumerateCredentialsBegin (0x04) to list credentials");
        Ok(())
    }

    /// Remove a credential by ID.
    /// TODO: Full CTAP2 authenticatorCredentialManagement deleteCredential subcommand
    pub fn cmd_credential_rm(hid: &SoloHid, credential_id: &str) -> Result<()> {
        let _version = get_device_version(hid)?;
        let _cred_id_bytes = hex::decode(credential_id).map_err(|e| {
            SoloError::DeviceError(format!("Invalid credential ID hex: {}", e))
        })?;
        println!("TODO: Full CTAP2 deleteCredential not yet implemented.");
        println!("Credential ID: {}", credential_id);
        println!("The sequence would use authenticatorCredentialManagement (0x0A) deleteCredential (0x06).");
        Ok(())
    }
}
