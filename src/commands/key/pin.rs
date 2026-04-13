use crate::device::{SoloHid, CTAPHID_CBOR};
use crate::error::{Result, SoloError};

/// Change the existing PIN (prompts for old and new PIN).
///
/// Implements CTAP2 authenticatorClientPIN changePin (spec section 6.5.5):
///   1. getKeyAgreement (subcommand 0x02) to get device's public key
///   2. Generate ephemeral P-256 keypair
///   3. ECDH + SHA-256 to derive shared secret
///   4. AES-256-CBC encrypt SHA-256(old_pin)[0..16] → pinHashEnc
///   5. AES-256-CBC encrypt padded new PIN → newPinEnc
///   6. HMAC-SHA-256(shared_secret, newPinEnc || pinHashEnc)[0..16] → pinUvAuthParam
///   7. changePin (subcommand 0x04) with keyAgreement, pinUvAuthParam, newPinEnc, pinHashEnc
pub fn cmd_change_pin(hid: &SoloHid) -> Result<()> {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};
    use ciborium::value::Value;
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use p256::ecdh::EphemeralSecret;
    use p256::EncodedPoint;
    use rand::rngs::OsRng;
    use sha2::{Digest as _, Sha256};

    let _version = super::ops::get_device_version(hid)?;
    let old_pin = rpassword::prompt_password("Current PIN: ").map_err(|e| SoloError::IoError(e))?;
    let new_pin = rpassword::prompt_password("New PIN: ").map_err(|e| SoloError::IoError(e))?;
    let confirm_pin =
        rpassword::prompt_password("Confirm new PIN: ").map_err(|e| SoloError::IoError(e))?;

    if new_pin != confirm_pin {
        return Err(SoloError::DeviceError("PINs do not match".into()));
    }
    if new_pin.len() < 4 {
        return Err(SoloError::DeviceError(
            "PIN must be at least 4 characters".into(),
        ));
    }
    if old_pin.len() < 4 {
        return Err(SoloError::DeviceError(
            "PIN must be at least 4 characters".into(),
        ));
    }

    // ── Step 1: getKeyAgreement (subcommand 0x02) ───────────────────────────
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
            "getKeyAgreement returned CTAP error 0x{:02X}",
            status
        )));
    }

    // Parse CBOR response map; key 0x01 = keyAgreement (COSE_Key)
    let resp_val: Value = ciborium::de::from_reader(&response[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;

    let resp_pairs = match resp_val {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "getKeyAgreement response is not a map".into(),
            ))
        }
    };

    let key_agreement = resp_pairs
        .iter()
        .find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == 0x01 {
                    Some(v)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .ok_or_else(|| SoloError::DeviceError("keyAgreement (0x01) missing in response".into()))?;

    // Extract x and y coordinates from COSE_Key map
    let cose_pairs = match key_agreement {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "keyAgreement is not a CBOR map".into(),
            ))
        }
    };

    let get_cose_bytes = |key: i64| -> Result<Vec<u8>> {
        cose_pairs
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(i) = k {
                    let ki: i64 = (*i).try_into().ok()?;
                    if ki == key {
                        if let Value::Bytes(b) = v {
                            Some(b.clone())
                        } else {
                            None
                        }
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
        return Err(SoloError::DeviceError(
            "Device COSE key coordinates are not 32 bytes".into(),
        ));
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
    let raw_x = shared_secret_point.raw_secret_bytes();
    let shared_secret: [u8; 32] = Sha256::digest(raw_x).into();

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    // ── Step 4: pinHashEnc — AES-256-CBC encrypt SHA-256(old_pin)[0..16] ───
    // pinHash = first 16 bytes of SHA-256(old_pin_utf8)
    let old_pin_hash_full = Sha256::digest(old_pin.as_bytes());
    let pin_hash: [u8; 16] = old_pin_hash_full[..16]
        .try_into()
        .map_err(|_| SoloError::DeviceError("Failed to slice pin hash".into()))?;

    let mut pin_hash_enc = [0u8; 16];
    #[allow(deprecated)]
    {
        use hybrid_array::Array as HybridArray;
        type Block16 = HybridArray<u8, aes::cipher::typenum::U16>;
        let iv = [0u8; 16];
        let src_blocks: &[Block16] =
            unsafe { std::slice::from_raw_parts(pin_hash.as_ptr() as *const Block16, 1) };
        let dst_blocks: &mut [Block16] =
            unsafe { std::slice::from_raw_parts_mut(pin_hash_enc.as_mut_ptr() as *mut Block16, 1) };
        let _ = Aes256CbcEnc::new(&shared_secret.into(), &iv.into())
            .encrypt_blocks_b2b(src_blocks, dst_blocks);
    }

    // ── Step 5: newPinEnc — AES-256-CBC encrypt padded new PIN (64 bytes) ──
    let pin_bytes = new_pin.as_bytes();
    let mut padded_pin = [0u8; 64];
    let copy_len = pin_bytes.len().min(64);
    padded_pin[..copy_len].copy_from_slice(&pin_bytes[..copy_len]);

    let mut new_pin_enc = [0u8; 64];
    #[allow(deprecated)]
    {
        use hybrid_array::Array as HybridArray;
        type Block16 = HybridArray<u8, aes::cipher::typenum::U16>;
        let iv = [0u8; 16];
        let src_blocks: &[Block16] =
            unsafe { std::slice::from_raw_parts(padded_pin.as_ptr() as *const Block16, 4) };
        let dst_blocks: &mut [Block16] =
            unsafe { std::slice::from_raw_parts_mut(new_pin_enc.as_mut_ptr() as *mut Block16, 4) };
        let _ = Aes256CbcEnc::new(&shared_secret.into(), &iv.into())
            .encrypt_blocks_b2b(src_blocks, dst_blocks);
    }

    // ── Step 6: HMAC-SHA-256(shared_secret, newPinEnc || pinHashEnc)[0..16] ─
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret.as_slice())
        .map_err(|e| SoloError::DeviceError(format!("HMAC init error: {}", e)))?;
    mac.update(&new_pin_enc);
    mac.update(&pin_hash_enc);
    let mac_result = mac.finalize().into_bytes();
    let pin_uv_auth_param = &mac_result[..16];

    // ── Step 7: Send changePin (subcommand 0x04) ────────────────────────────
    let eph_x = ephemeral_point
        .x()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing x coordinate".into()))?
        .to_vec();
    let eph_y = ephemeral_point
        .y()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing y coordinate".into()))?
        .to_vec();

    let ephemeral_cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty = EC2
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())), // alg = ES256
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv = P-256
        (Value::Integer((-2i64).into()), Value::Bytes(eph_x)),      // x
        (Value::Integer((-3i64).into()), Value::Bytes(eph_y)),      // y
    ]);

    let change_pin_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())), // pinUvAuthProtocol = 1
        (Value::Integer(0x02u64.into()), Value::Integer(4u64.into())), // subCommand = changePin (0x04)
        (Value::Integer(0x03u64.into()), ephemeral_cose_key),          // keyAgreement
        (
            Value::Integer(0x04u64.into()),
            Value::Bytes(pin_uv_auth_param.to_vec()),
        ), // pinUvAuthParam (16 bytes)
        (
            Value::Integer(0x05u64.into()),
            Value::Bytes(new_pin_enc.to_vec()),
        ), // newPinEnc (64 bytes)
        (
            Value::Integer(0x06u64.into()),
            Value::Bytes(pin_hash_enc.to_vec()),
        ), // pinHashEnc (16 bytes)
    ]);

    let mut change_pin_bytes = vec![0x06u8];
    ciborium::ser::into_writer(&change_pin_cbor, &mut change_pin_bytes)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let change_pin_response = hid.send_recv(CTAPHID_CBOR, &change_pin_bytes)?;

    if change_pin_response.is_empty() {
        return Err(SoloError::DeviceError(
            "Empty response from changePin".into(),
        ));
    }
    let change_pin_status = change_pin_response[0];
    if change_pin_status != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "changePin returned CTAP error 0x{:02X}",
            change_pin_status
        )));
    }

    println!("PIN changed successfully.");
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
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};
    use ciborium::value::Value;
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use p256::ecdh::EphemeralSecret;
    use p256::EncodedPoint;
    use rand::rngs::OsRng;
    use sha2::{Digest as _, Sha256};

    let _version = super::ops::get_device_version(hid)?;
    let new_pin = rpassword::prompt_password("New PIN: ").map_err(|e| SoloError::IoError(e))?;
    let confirm_pin =
        rpassword::prompt_password("Confirm PIN: ").map_err(|e| SoloError::IoError(e))?;

    if new_pin != confirm_pin {
        return Err(SoloError::DeviceError("PINs do not match".into()));
    }
    if new_pin.len() < 4 {
        return Err(SoloError::DeviceError(
            "PIN must be at least 4 characters".into(),
        ));
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
        _ => {
            return Err(SoloError::DeviceError(
                "getKeyAgreement response is not a map".into(),
            ))
        }
    };

    let key_agreement = resp_pairs
        .iter()
        .find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == 0x01 {
                    Some(v)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .ok_or_else(|| SoloError::DeviceError("keyAgreement (0x01) missing in response".into()))?;

    // Extract x and y coordinates from COSE_Key map
    // COSE key map integer keys: -2 = x, -3 = y
    let cose_pairs = match key_agreement {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "keyAgreement is not a CBOR map".into(),
            ))
        }
    };

    let get_cose_bytes = |key: i64| -> Result<Vec<u8>> {
        cose_pairs
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(i) = k {
                    let ki: i64 = (*i).try_into().ok()?;
                    if ki == key {
                        if let Value::Bytes(b) = v {
                            Some(b.clone())
                        } else {
                            None
                        }
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
        return Err(SoloError::DeviceError(
            "Device COSE key coordinates are not 32 bytes".into(),
        ));
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
        use hybrid_array::Array as HybridArray;
        type Block16 = HybridArray<u8, aes::cipher::typenum::U16>;
        let iv = [0u8; 16];
        let src_blocks: &[Block16] =
            unsafe { std::slice::from_raw_parts(padded_pin.as_ptr() as *const Block16, 4) };
        let dst_blocks: &mut [Block16] =
            unsafe { std::slice::from_raw_parts_mut(new_pin_enc.as_mut_ptr() as *mut Block16, 4) };
        let _ = Aes256CbcEnc::new(&shared_secret.into(), &iv.into())
            .encrypt_blocks_b2b(src_blocks, dst_blocks);
    }

    // ── Step 5: HMAC-SHA-256(shared_secret, newPinEnc)[0..16] ──────────────
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret.as_slice())
        .map_err(|e| SoloError::DeviceError(format!("HMAC init error: {}", e)))?;
    mac.update(&new_pin_enc);
    let mac_result = mac.finalize().into_bytes();
    let pin_uv_auth_param = &mac_result[..16];

    // ── Step 6: Send setPin (subcommand 0x03) ───────────────────────────────
    // Build COSE key map for ephemeral public key
    // {1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes}
    let eph_x = ephemeral_point
        .x()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing x coordinate".into()))?
        .to_vec();
    let eph_y = ephemeral_point
        .y()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing y coordinate".into()))?
        .to_vec();

    let ephemeral_cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty = EC2
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())), // alg = ES256
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv = P-256
        (Value::Integer((-2i64).into()), Value::Bytes(eph_x)),      // x
        (Value::Integer((-3i64).into()), Value::Bytes(eph_y)),      // y
    ]);

    let set_pin_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())), // pinUvAuthProtocol = 1
        (Value::Integer(0x02u64.into()), Value::Integer(3u64.into())), // subCommand = setPin
        (Value::Integer(0x03u64.into()), ephemeral_cose_key),          // keyAgreement
        (
            Value::Integer(0x04u64.into()),
            Value::Bytes(pin_uv_auth_param.to_vec()),
        ), // pinUvAuthParam
        (
            Value::Integer(0x05u64.into()),
            Value::Bytes(new_pin_enc.to_vec()),
        ), // newPinEnc
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
