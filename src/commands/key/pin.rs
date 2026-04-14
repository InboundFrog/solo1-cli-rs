use crate::cbor::{cbor_bytes, cbor_int, int_map};
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
    let _version = super::ops::get_device_version(hid)?;
    let old_pin = rpassword::prompt_password("Current PIN: ").map_err(|e| SoloError::IoError(e))?;
    let new_pin = rpassword::prompt_password("New PIN: ").map_err(|e| SoloError::IoError(e))?;
    let confirm_pin =
        rpassword::prompt_password("Confirm new PIN: ").map_err(|e| SoloError::IoError(e))?;

    if new_pin != confirm_pin {
        return Err(SoloError::DeviceError("PINs do not match".into()));
    }
    if new_pin.len() < 4 || old_pin.len() < 4 {
        return Err(SoloError::DeviceError(
            "PIN must be at least 4 characters".into(),
        ));
    }

    let dev_pub_key = crate::ctap2::get_key_agreement(hid)?;
    let session = crate::ctap2::ClientPinSession::new(&dev_pub_key);

    let pin_hash_enc = session.encrypt_pin_hash(&old_pin)?;
    let new_pin_enc = session.encrypt_pin(&new_pin)?;

    let mut auth_msg = new_pin_enc.clone();
    auth_msg.extend_from_slice(&pin_hash_enc);
    let pin_uv_auth_param = session.authenticate(&auth_msg)?;

    let change_pin_cbor = int_map([
        (0x01, cbor_int(1)),                                          // pinUvAuthProtocol = 1
        (0x02, cbor_int(4)),                                          // subCommand = changePin (0x04)
        (0x03, session.ephemeral_pub_key.clone()),                    // keyAgreement
        (0x04, cbor_bytes(pin_uv_auth_param)),                        // pinUvAuthParam (16 bytes)
        (0x05, cbor_bytes(new_pin_enc)),                              // newPinEnc (64 bytes)
        (0x06, cbor_bytes(pin_hash_enc.to_vec())),                    // pinHashEnc (16 bytes)
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

    let dev_pub_key = crate::ctap2::get_key_agreement(hid)?;
    let session = crate::ctap2::ClientPinSession::new(&dev_pub_key);

    let new_pin_enc = session.encrypt_pin(&new_pin)?;
    let pin_uv_auth_param = session.authenticate(&new_pin_enc)?;

    let set_pin_cbor = int_map([
        (0x01, cbor_int(1)),                                          // pinUvAuthProtocol = 1
        (0x02, cbor_int(3)),                                          // subCommand = setPin
        (0x03, session.ephemeral_pub_key.clone()),                    // keyAgreement
        (0x04, cbor_bytes(pin_uv_auth_param)),                        // pinUvAuthParam
        (0x05, cbor_bytes(new_pin_enc)),                              // newPinEnc
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
