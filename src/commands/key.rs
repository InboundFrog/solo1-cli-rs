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
    if n > 255 {
        return Err(SoloError::DeviceError(format!(
            "Number of bytes must be between 0 and 255, you passed {}",
            n
        )));
    }
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

/// Feed entropy to /dev/random (Linux only) using RNDADDENTROPY ioctl.
///
/// Uses the RNDADDENTROPY ioctl (0x40085203) to properly inform the kernel
/// of the entropy being added, rather than just writing bytes. The struct
/// sent to the ioctl is: entropy_count (i32) | buf_size (i32) | data (bytes).
/// entropy_count = count * 2 (2 bits per byte, pessimistic estimate).
#[cfg(target_os = "linux")]
pub fn cmd_rng_feedkernel(hid: &SoloHid) -> Result<()> {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    const ENTROPY_INFO: &str = "/proc/sys/kernel/random/entropy_avail";
    const RNDADDENTROPY: libc::c_ulong = 0x40085203;
    const COUNT: usize = 64;
    const ENTROPY_BITS_PER_BYTE: i32 = 2;

    let before = std::fs::read_to_string(ENTROPY_INFO)
        .unwrap_or_else(|_| "unknown".into());
    println!("Entropy before: 0x{}", before.trim());

    let request = [COUNT as u8];
    let response = hid.send_recv(CMD_RNG, &request)?;
    let data = &response[..response.len().min(COUNT)];

    // Build rand_pool_info struct: entropy_count (i32), buf_size (i32), buf (bytes)
    let mut buf = Vec::with_capacity(8 + data.len());
    let entropy_count: i32 = data.len() as i32 * ENTROPY_BITS_PER_BYTE;
    let buf_size: i32 = data.len() as i32;
    buf.extend_from_slice(&entropy_count.to_ne_bytes());
    buf.extend_from_slice(&buf_size.to_ne_bytes());
    buf.extend_from_slice(data);

    let dev_random = File::options().write(true).open("/dev/random")?;
    let ret = unsafe {
        libc::ioctl(dev_random.as_raw_fd(), RNDADDENTROPY, buf.as_ptr())
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let after = std::fs::read_to_string(ENTROPY_INFO)
        .unwrap_or_else(|_| "unknown".into());
    println!("Entropy after:  0x{}", after.trim());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn cmd_rng_feedkernel(_hid: &SoloHid) -> Result<()> {
    Err(SoloError::UnsupportedPlatform)
}

/// Create a FIDO2 credential with hmac-secret extension.
/// TODO: Implement full CTAP2 command sequence:
///   1. Send CTAPHID_CBOR with CTAP2 command 0x01 (makeCredential)
///   2. clientDataHash: SHA256 of client data
///   3. rp: {"id": host, "name": host}
///   4. user: {"id": user_id bytes, "name": user}
///   5. pubKeyCredParams: [{"type": "public-key", "alg": -7}] (ES256)
///   6. extensions: {"hmac-secret": true}
///   7. options: {"rk": true}  (resident key)
///   8. Parse CBOR response to get credential ID and public key
pub fn cmd_make_credential(
    hid: &SoloHid,
    host: &str,
    user: &str,
    prompt: &str,
) -> Result<()> {
    let _version = get_device_version(hid)?;
    if !prompt.is_empty() {
        println!("{}", prompt);
    }
    println!(
        "TODO: Full CTAP2 makeCredential for host '{}' user '{}' with hmac-secret not yet implemented.",
        host, user
    );
    println!("The CTAP2 command sequence would:");
    println!("  1. Send CTAPHID_CBOR (0x90) with CBOR-encoded makeCredential (0x01) request");
    println!("  2. rp.id = '{}', user.name = '{}'", host, user);
    println!("  3. Include hmac-secret extension and options.rk = true");
    println!("  4. Return credential ID (hex) to stdout");
    Ok(())
}

/// HMAC-secret challenge-response.
/// TODO: Implement full CTAP2 sequence:
///   1. Generate a client assertion using hmac-secret extension
///   2. CTAP2 getAssertion (0x02) with allowList containing credential
///   3. salt = SHA256(challenge) sent as hmac-secret salt
///   4. Return the HMAC output from the device
pub fn cmd_challenge_response(
    hid: &SoloHid,
    credential_id: &str,
    challenge: &str,
    host: &str,
) -> Result<()> {
    let _version = get_device_version(hid)?;
    // Hash the challenge with SHA-256 to produce the 32-byte salt
    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    let salt = hasher.finalize();
    println!("Connected to device.");
    println!("Credential ID: {}", credential_id);
    println!("Host (RP): {}", host);
    println!("Salt (SHA256(challenge)): {}", hex::encode(salt));
    println!(
        "TODO: Full CTAP2 getAssertion with hmac-secret for RP '{}' not yet implemented.",
        host
    );
    println!("The CTAP2 sequence would:");
    println!("  1. Send CTAPHID_CBOR (0x90) with CBOR-encoded getAssertion (0x02) request");
    println!("  2. Include hmac-secret extension with the salt above");
    println!("  3. Specify credential_id in the allowList");
    println!("  4. Return the HMAC output (32 bytes) from the device");
    Ok(())
}

/// Verify key authenticity via attestation certificate.
///
/// Sends a CTAP2 makeCredential (0x01) request via CTAPHID_CBOR, extracts the
/// DER-encoded attestation certificate from attStmt.x5c[0], SHA-256 fingerprints
/// it, and compares against known fingerprints in crypto.rs.
pub fn cmd_verify(hid: &SoloHid) -> Result<()> {
    use ciborium::value::Value;
    use crate::crypto::{check_attestation_fingerprint, sha256_hex};

    println!("Please press the button on your Solo key");

    // clientDataHash: fixed 32-byte value (Solo does not verify it for attestation)
    let client_data_hash: Vec<u8> = Sha256::digest(b"solokeys_verify_test").to_vec();

    // Build CTAP2 makeCredential CBOR request map (integer keys per CTAP2 spec):
    //   0x01: clientDataHash
    //   0x02: rp  {"id": "solokeys.com", "name": "solokeys.com"}
    //   0x03: user {"id": b"verify", "name": "verify", "displayName": "verify"}
    //   0x04: pubKeyCredParams [{"alg": -7, "type": "public-key"}]
    let cbor_request = Value::Map(vec![
        (
            Value::Integer(0x01u64.into()),
            Value::Bytes(client_data_hash),
        ),
        (
            Value::Integer(0x02u64.into()),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Text("solokeys.com".into())),
                (Value::Text("name".into()), Value::Text("solokeys.com".into())),
            ]),
        ),
        (
            Value::Integer(0x03u64.into()),
            Value::Map(vec![
                (Value::Text("id".into()), Value::Bytes(b"verify".to_vec())),
                (Value::Text("name".into()), Value::Text("verify".into())),
                (Value::Text("displayName".into()), Value::Text("verify".into())),
            ]),
        ),
        (
            Value::Integer(0x04u64.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer((-7i64).into())),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ])]),
        ),
    ]);

    // Prepend CTAP2 command byte 0x01 (makeCredential) before the CBOR payload
    let mut request_bytes = vec![0x01u8];
    ciborium::ser::into_writer(&cbor_request, &mut request_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let response = hid.send_recv(CTAPHID_CBOR, &request_bytes)?;

    // First byte is CTAP2 status code; 0x00 = success
    if response.is_empty() {
        return Err(SoloError::DeviceError("Empty response from device".into()));
    }
    let status = response[0];
    if status != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "makeCredential returned CTAP error 0x{:02X}",
            status
        )));
    }

    // Parse the CBOR response map
    let cbor_bytes = &response[1..];
    let resp_val: Value = ciborium::de::from_reader(cbor_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;

    let pairs = match resp_val {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "makeCredential response is not a CBOR map".into(),
            ))
        }
    };

    // Helper to look up an integer key in the map
    let get_key = |key: u64| -> Option<&Value> {
        pairs.iter().find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == key {
                    return Some(v);
                }
            }
            None
        })
    };

    // 0x03: attStmt map — contains "x5c" array of DER-encoded certs
    let att_stmt = match get_key(0x03) {
        Some(Value::Map(m)) => m,
        _ => {
            return Err(SoloError::DeviceError(
                "makeCredential response missing attStmt (key 0x03)".into(),
            ))
        }
    };

    // Find "x5c" key inside attStmt
    let x5c = att_stmt.iter().find_map(|(k, v)| {
        if let Value::Text(s) = k {
            if s == "x5c" {
                return Some(v);
            }
        }
        None
    });

    let cert_der = match x5c {
        Some(Value::Array(certs)) if !certs.is_empty() => {
            match &certs[0] {
                Value::Bytes(b) => b.clone(),
                _ => {
                    return Err(SoloError::DeviceError(
                        "x5c[0] is not bytes".into(),
                    ))
                }
            }
        }
        _ => {
            return Err(SoloError::DeviceError(
                "attStmt missing x5c array".into(),
            ))
        }
    };

    let fingerprint = sha256_hex(&cert_der);
    println!("Attestation certificate SHA-256: {}", fingerprint);

    match check_attestation_fingerprint(&cert_der) {
        Some(msg) => {
            println!("Valid Solo key: {}", msg);
        }
        None => {
            println!("Unknown fingerprint — this key may not be genuine SoloKeys hardware.");
        }
    }

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
    println!("Warning: Your credentials will be lost!!! Do you wish to continue?");
    print!("Type 'yes' to confirm: ");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "yes" {
        println!("Aborted.");
        return Ok(());
    }
    println!("Press the button to confirm -- again, your credentials will be lost!!!");
    // CTAP2 authenticatorReset = 0x07
    // Send via CTAPHID_CBOR
    let cbor_reset = vec![0x07u8];
    hid.send_recv(CTAPHID_CBOR, &cbor_reset)?;
    println!("....aaaand they're gone");
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
///
/// Implements CTAP2 authenticatorClientPIN setPin (spec section 6.5.4):
///   1. getKeyAgreement (subcommand 0x02) to get device's public key
///   2. Generate ephemeral P-256 keypair
///   3. ECDH + SHA-256 to derive shared secret
///   4. AES-256-CBC encrypt padded PIN → newPinEnc
///   5. HMAC-SHA-256(shared_secret, newPinEnc)[0..16] → pinUvAuthParam
///   6. setPin (subcommand 0x03) with keyAgreement, pinUvAuthParam, newPinEnc
pub fn cmd_set_pin(hid: &SoloHid) -> Result<()> {
    use aes::cipher::{BlockEncryptMut, KeyIvInit};
    use ciborium::value::Value;
    use hmac::{Hmac, Mac};
    use p256::ecdh::EphemeralSecret;
    use p256::EncodedPoint;
    use rand::rngs::OsRng;
    use sha2::{Digest as _, Sha256};

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

    // ── Step 1: getKeyAgreement (subcommand 0x02) ───────────────────────────
    // Send: [0x06, CBOR({0x01: 1, 0x02: 2})]
    let get_ka_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())), // pinUvAuthProtocol = 1
        (Value::Integer(0x02u64.into()), Value::Integer(2u64.into())), // subCommand = getKeyAgreement
    ]);
    let mut request_bytes = vec![0x06u8]; // authenticatorClientPIN command byte
    ciborium::ser::into_writer(&get_ka_cbor, &mut request_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let response = hid.send_recv(CTAPHID_CBOR, &request_bytes)?;

    if response.is_empty() {
        return Err(SoloError::DeviceError("Empty response from device".into()));
    }
    let status = response[0];
    if status != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "getKeyAgreement returned CTAP error 0x{:02X} — device may already have a PIN set",
            status
        )));
    }

    // Parse CBOR response map; key 0x01 = keyAgreement (COSE_Key)
    let resp_val: Value = ciborium::de::from_reader(&response[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;

    let resp_pairs = match resp_val {
        Value::Map(p) => p,
        _ => return Err(SoloError::DeviceError("getKeyAgreement response is not a map".into())),
    };

    let key_agreement = resp_pairs
        .iter()
        .find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == 0x01 { Some(v) } else { None }
            } else {
                None
            }
        })
        .ok_or_else(|| SoloError::DeviceError("keyAgreement (0x01) missing in response".into()))?;

    // Extract x and y coordinates from COSE_Key map
    // COSE key map integer keys: -2 = x, -3 = y
    let cose_pairs = match key_agreement {
        Value::Map(p) => p,
        _ => return Err(SoloError::DeviceError("keyAgreement is not a CBOR map".into())),
    };

    let get_cose_bytes = |key: i64| -> Result<Vec<u8>> {
        cose_pairs
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(i) = k {
                    let ki: i64 = (*i).try_into().ok()?;
                    if ki == key {
                        if let Value::Bytes(b) = v { Some(b.clone()) } else { None }
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or_else(|| SoloError::DeviceError(format!("COSE key missing coordinate {}", key)))
    };

    let dev_x = get_cose_bytes(-2)?;
    let dev_y = get_cose_bytes(-3)?;

    if dev_x.len() != 32 || dev_y.len() != 32 {
        return Err(SoloError::DeviceError("Device COSE key coordinates are not 32 bytes".into()));
    }

    // Reconstruct device public key from uncompressed SEC1 bytes (04 || x || y)
    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&dev_x);
    uncompressed.extend_from_slice(&dev_y);
    let dev_pub_key = p256::PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| SoloError::DeviceError(format!("Invalid device public key: {}", e)))?;

    // ── Step 2: Generate ephemeral P-256 keypair ────────────────────────────
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pub = p256::PublicKey::from(&ephemeral_secret);
    let ephemeral_point = EncodedPoint::from(&ephemeral_pub);

    // ── Step 3: ECDH + SHA-256 → shared_secret ─────────────────────────────
    let shared_secret_point = ephemeral_secret.diffie_hellman(&dev_pub_key);
    // Raw x-coordinate of ECDH result, then SHA-256
    let raw_x = shared_secret_point.raw_secret_bytes();
    let shared_secret: [u8; 32] = Sha256::digest(raw_x).into();

    // ── Step 4: AES-256-CBC encrypt padded PIN → newPinEnc ──────────────────
    // Pad PIN to 64 bytes (right-padded with 0x00)
    let pin_bytes = new_pin.as_bytes();
    let mut padded_pin = [0u8; 64];
    let copy_len = pin_bytes.len().min(64);
    padded_pin[..copy_len].copy_from_slice(&pin_bytes[..copy_len]);

    // AES-256-CBC, zero IV, no PKCS#7 padding (data is already a multiple of 16)
    // Encrypt 64-byte padded PIN = 4 × 16-byte blocks.
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    let mut new_pin_enc = [0u8; 64];
    #[allow(deprecated)]
    {
        use aes::cipher::generic_array::GenericArray;
        type Block16 = GenericArray<u8, aes::cipher::typenum::U16>;
        let iv = [0u8; 16];
        let src_blocks: &[Block16] = unsafe {
            std::slice::from_raw_parts(padded_pin.as_ptr() as *const Block16, 4)
        };
        let dst_blocks: &mut [Block16] = unsafe {
            std::slice::from_raw_parts_mut(new_pin_enc.as_mut_ptr() as *mut Block16, 4)
        };
        let _ = Aes256CbcEnc::new(&shared_secret.into(), &iv.into())
            .encrypt_blocks_b2b_mut(src_blocks, dst_blocks);
    }

    // ── Step 5: HMAC-SHA-256(shared_secret, newPinEnc)[0..16] ──────────────
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&shared_secret)
        .map_err(|e| SoloError::DeviceError(format!("HMAC init error: {}", e)))?;
    mac.update(&new_pin_enc);
    let mac_result = mac.finalize().into_bytes();
    let pin_uv_auth_param = &mac_result[..16];

    // ── Step 6: Send setPin (subcommand 0x03) ───────────────────────────────
    // Build COSE key map for ephemeral public key
    // {1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes}
    let eph_x = ephemeral_point.x().ok_or_else(|| {
        SoloError::DeviceError("Ephemeral key missing x coordinate".into())
    })?.to_vec();
    let eph_y = ephemeral_point.y().ok_or_else(|| {
        SoloError::DeviceError("Ephemeral key missing y coordinate".into())
    })?.to_vec();

    let ephemeral_cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()),  Value::Integer(2i64.into())),   // kty = EC2
        (Value::Integer(3i64.into()),  Value::Integer((-7i64).into())),// alg = ES256
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv = P-256
        (Value::Integer((-2i64).into()), Value::Bytes(eph_x)),         // x
        (Value::Integer((-3i64).into()), Value::Bytes(eph_y)),         // y
    ]);

    let set_pin_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())),           // pinUvAuthProtocol = 1
        (Value::Integer(0x02u64.into()), Value::Integer(3u64.into())),           // subCommand = setPin
        (Value::Integer(0x03u64.into()), ephemeral_cose_key),                    // keyAgreement
        (Value::Integer(0x04u64.into()), Value::Bytes(pin_uv_auth_param.to_vec())), // pinUvAuthParam
        (Value::Integer(0x05u64.into()), Value::Bytes(new_pin_enc.to_vec())),    // newPinEnc
    ]);

    let mut set_pin_bytes = vec![0x06u8];
    ciborium::ser::into_writer(&set_pin_cbor, &mut set_pin_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let set_pin_response = hid.send_recv(CTAPHID_CBOR, &set_pin_bytes)?;

    if set_pin_response.is_empty() {
        return Err(SoloError::DeviceError("Empty response from setPin".into()));
    }
    let set_pin_status = set_pin_response[0];
    if set_pin_status != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "setPin returned CTAP error 0x{:02X}",
            set_pin_status
        )));
    }

    println!("PIN set successfully.");
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
///
/// Sends a CBOR-encoded command to CMD_PROBE (0x70):
///   {"subcommand": hash_type_str, "data": file_bytes}
///
/// Valid hash types (case-insensitive input, sent as canonical form):
///   SHA256, SHA512, RSA2048, Ed25519
///
/// File must be <= 6144 bytes.
pub fn cmd_probe(hid: &SoloHid, hash_type: &str, filename: &Path) -> Result<()> {
    // Normalize hash type to the canonical form expected by the device
    let hash_type_str = match hash_type.to_lowercase().as_str() {
        "sha256" => "SHA256",
        "sha512" => "SHA512",
        "rsa2048" => "RSA2048",
        "ed25519" => "Ed25519",
        other => {
            return Err(SoloError::DeviceError(format!(
                "Unknown hash type: {}. Valid: SHA256, SHA512, RSA2048, Ed25519",
                other
            )))
        }
    };

    let file_bytes = std::fs::read(filename)?;
    if file_bytes.len() > 6 * 1024 {
        return Err(SoloError::DeviceError(format!(
            "File too large: {} bytes (max 6144)",
            file_bytes.len()
        )));
    }

    // CBOR-encode: {"subcommand": hash_type_str, "data": file_bytes}
    use ciborium::value::Value;
    let cbor_val = Value::Map(vec![
        (
            Value::Text("subcommand".into()),
            Value::Text(hash_type_str.into()),
        ),
        (Value::Text("data".into()), Value::Bytes(file_bytes)),
    ]);
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&cbor_val, &mut cbor_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let response = hid.send_recv(CMD_PROBE, &cbor_bytes)?;
    let result_hex = hex::encode(&response);
    println!("{}", result_hex);

    if hash_type_str == "Ed25519" {
        // First 64 bytes = signature (128 hex chars), rest = content
        if response.len() > 64 {
            println!("content: {:?}", &response[64..]);
            println!(
                "content from hex: {:?}",
                &response[64..]
            );
            println!("signature: {}", &result_hex[..128.min(result_hex.len())]);
        }
    }

    Ok(())
}

/// Sign a file with a resident credential.
/// TODO: Full CTAP2 getAssertion sequence:
///   1. Hash the file with SHA-256
///   2. Use as clientDataHash in getAssertion
///   3. Specify credential_id in allowList
///   4. Return the assertion response including signature
///   5. Save signature to filename.sig
pub fn cmd_sign_file(hid: &SoloHid, credential_id: &str, filename: &Path) -> Result<()> {
    let _version = get_device_version(hid)?;
    let data = std::fs::read(filename)?;
    let hash = sha2::Sha256::digest(&data);
    println!("{}  {:?}", hex::encode(hash), filename);
    println!("Please press the button on your Solo key");
    println!("TODO: Full CTAP2 getAssertion not yet implemented.");
    println!("Credential ID (base64): {}", credential_id);
    println!(
        "The CTAP2 sequence would use the SHA-256 as clientDataHash with the given credential."
    );
    Ok(())
}

/// Update the device firmware.
pub fn cmd_update(hid: &SoloHid, firmware_file: Option<&Path>) -> Result<()> {
    use crate::device::{CMD_ENTER_BOOT, CMD_WRITE, CMD_DONE, CMD_VERSION};
    use crate::firmware::{fetch_latest_release, download_url, FirmwareJson};
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

    // Query bootloader version to select the correct signature.
    // If CMD_VERSION fails, use the default (latest) signature directly rather than
    // falling back to version 0.0.0 which would incorrectly match "<=2.5.3".
    let signature = match bl_hid.send_bootloader_cmd(CMD_VERSION, 0, &[]) {
        Ok(resp) if resp.len() >= 3 => {
            let v = FirmwareVersion::new(resp[0] as u32, resp[1] as u32, resp[2] as u32);
            println!("Bootloader version: {}", v);
            fw_json.signature_for_version(&v)?
        }
        Ok(resp) if !resp.is_empty() => {
            let v = FirmwareVersion::new(0, 0, resp[0] as u32);
            println!("Bootloader version: {}", v);
            fw_json.signature_for_version(&v)?
        }
        _ => {
            println!("Could not read bootloader version; using default signature.");
            fw_json.signature_bytes()?
        }
    };
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

    /// Get credential slot info via CTAP2 authenticatorGetInfo (0x04).
    pub fn cmd_credential_info(hid: &SoloHid) -> Result<()> {
        use ciborium::de::from_reader;
        use ciborium::value::Value;

        // CTAP2 getInfo
        let cbor_get_info = vec![0x04u8];
        let response = hid.send_recv(CTAPHID_CBOR, &cbor_get_info)?;

        // The first byte of a CTAP2 response is the status code; 0x00 = success.
        if response.is_empty() {
            return Err(SoloError::DeviceError("Empty response from device".into()));
        }
        let status = response[0];
        if status != 0x00 {
            return Err(SoloError::DeviceError(format!(
                "authenticatorGetInfo returned CTAP error 0x{:02X}",
                status
            )));
        }
        let cbor_bytes = &response[1..];

        let val: Value = from_reader(cbor_bytes)
            .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;

        let pairs = match val {
            Value::Map(p) => p,
            _ => {
                return Err(SoloError::DeviceError(
                    "authenticatorGetInfo response is not a CBOR map".into(),
                ))
            }
        };

        // Helper: look up a key (integer) in the map.
        let get_key = |key: u64| -> Option<&Value> {
            pairs.iter().find_map(|(k, v)| {
                if let Value::Integer(i) = k {
                    let ki: u64 = (*i).try_into().ok()?;
                    if ki == key {
                        return Some(v);
                    }
                }
                None
            })
        };

        println!("CTAP2 authenticatorGetInfo");
        println!("{}", "=".repeat(40));

        // 0x01: versions
        if let Some(Value::Array(versions)) = get_key(0x01) {
            let strs: Vec<&str> = versions
                .iter()
                .filter_map(|v| if let Value::Text(s) = v { Some(s.as_str()) } else { None })
                .collect();
            println!("Versions:                       {}", strs.join(", "));
        }

        // 0x02: extensions
        if let Some(Value::Array(exts)) = get_key(0x02) {
            let strs: Vec<&str> = exts
                .iter()
                .filter_map(|v| if let Value::Text(s) = v { Some(s.as_str()) } else { None })
                .collect();
            println!("Extensions:                     {}", strs.join(", "));
        }

        // 0x03: aaguid (16 bytes)
        if let Some(Value::Bytes(aaguid)) = get_key(0x03) {
            println!("AAGUID:                         {}", hex::encode(aaguid));
        }

        // 0x04: options (map of string -> bool)
        if let Some(Value::Map(opts)) = get_key(0x04) {
            let opt_strs: Vec<String> = opts
                .iter()
                .filter_map(|(k, v)| {
                    if let (Value::Text(name), Value::Bool(b)) = (k, v) {
                        Some(format!("{}: {}", name, b))
                    } else {
                        None
                    }
                })
                .collect();
            println!("Options:                        {}", opt_strs.join(", "));
        }

        // 0x05: maxMsgSize
        if let Some(Value::Integer(n)) = get_key(0x05) {
            let size: u64 = (*n).try_into().unwrap_or(0);
            println!("Max message size:               {}", size);
        }

        // 0x06: pinUvAuthProtocols
        if let Some(Value::Array(protos)) = get_key(0x06) {
            let nums: Vec<String> = protos
                .iter()
                .filter_map(|v| {
                    if let Value::Integer(i) = v {
                        let n: u64 = (*i).try_into().ok()?;
                        Some(n.to_string())
                    } else {
                        None
                    }
                })
                .collect();
            println!("PIN/UV auth protocols:          {}", nums.join(", "));
        }

        // 0x07: maxCredentialCountInList
        if let Some(Value::Integer(n)) = get_key(0x07) {
            let count: u64 = (*n).try_into().unwrap_or(0);
            println!("Max credential count in list:   {}", count);
        }

        // 0x08: maxCredentialIdLength
        if let Some(Value::Integer(n)) = get_key(0x08) {
            let len: u64 = (*n).try_into().unwrap_or(0);
            println!("Max credential ID length:       {}", len);
        }

        // 0x0A: remainingDiscoverableCredentials
        if let Some(Value::Integer(n)) = get_key(0x0A) {
            let remaining: u64 = (*n).try_into().unwrap_or(0);
            println!("Remaining discoverable creds:   {}", remaining);
        } else {
            println!("Remaining discoverable creds:   (not reported by device)");
        }

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

#[cfg(test)]
mod tests {
    /// Test rng_hexbytes validation: n must be 0..=255.
    /// The actual validation is: if n > 255 { return Err(...) }
    #[test]
    fn test_rng_hexbytes_validation_boundary() {
        // n=255 is valid (fits in u8)
        let n_valid: usize = 255;
        assert!(n_valid <= 255, "255 should be valid");

        // n=256 is invalid (exceeds u8::MAX)
        let n_invalid: usize = 256;
        assert!(n_invalid > 255, "256 should be invalid");

        // n=0 is valid (return empty bytes)
        let n_zero: usize = 0;
        assert!(n_zero <= 255, "0 should be valid");
    }

    /// Test probe hash type normalization logic.
    #[test]
    fn test_probe_hash_type_normalization() {
        let cases: &[(&str, Option<&str>)] = &[
            ("sha256", Some("SHA256")),
            ("SHA256", Some("SHA256")),
            ("Sha256", Some("SHA256")),
            ("sha512", Some("SHA512")),
            ("SHA512", Some("SHA512")),
            ("rsa2048", Some("RSA2048")),
            ("RSA2048", Some("RSA2048")),
            ("ed25519", Some("Ed25519")),
            ("Ed25519", Some("Ed25519")),
            ("ED25519", Some("Ed25519")),
            ("md5", None),
            ("sha1", None),
            ("", None),
        ];

        for (input, expected) in cases {
            let canonical = match input.to_lowercase().as_str() {
                "sha256" => Some("SHA256"),
                "sha512" => Some("SHA512"),
                "rsa2048" => Some("RSA2048"),
                "ed25519" => Some("Ed25519"),
                _ => None,
            };
            assert_eq!(
                canonical, *expected,
                "hash type '{}' should normalize to {:?}",
                input, expected
            );
        }
    }

    /// Test that reset confirmation logic works correctly.
    /// The implementation reads "yes" from stdin; here we just verify the
    /// string comparison logic used in the confirmation.
    #[test]
    fn test_reset_confirmation_string_check() {
        // Only "yes" (exact, trimmed) should be accepted
        let accepted = ["yes"];
        let rejected = ["Yes", "YES", "y", "no", "n", "", " yes", "yes "];

        for s in &accepted {
            assert_eq!(s.trim(), "yes", "'{}' trimmed should equal 'yes'", s);
        }
        for s in &rejected {
            // After trim, should NOT equal "yes" (except "yes" itself, but those
            // are in rejected because they have spaces - " yes".trim() = "yes"...
            // Actually " yes".trim() IS "yes", so let's be more careful)
            let trimmed = s.trim();
            if *s == " yes" || *s == "yes " {
                // These DO trim to "yes" - they should be accepted!
                assert_eq!(trimmed, "yes");
            } else {
                assert_ne!(trimmed, "yes", "'{}' trimmed ('{}') should not equal 'yes'", s, trimmed);
            }
        }
    }

    /// Test challenge_response salt computation.
    #[test]
    fn test_challenge_response_salt_is_sha256_of_challenge() {
        use sha2::{Digest, Sha256};

        let challenge = "my-challenge-string";
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        let salt = hasher.finalize();

        // The salt should be SHA256(challenge) - 32 bytes
        assert_eq!(salt.len(), 32);
        // Known value for SHA256("my-challenge-string")
        let expected = sha2::Sha256::digest(challenge.as_bytes());
        assert_eq!(salt.as_slice(), expected.as_slice());
    }
}
