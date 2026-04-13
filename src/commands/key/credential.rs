use crate::commands::key::ctap2::{
    extract_cbor_text_responses, find_cbor_response_by_key, get_pin_token,
    parse_cbor_map_response,
};
use crate::device::{SoloHid, CTAPHID_CBOR};
use crate::error::{Result, SoloError};

/// Query CTAP2 getInfo (0x04) and return whether a PIN has been set on the device.
///
/// Returns `Ok(true)` when `options.clientPin == true`, `Ok(false)` when it is
/// `false` or absent, and `Err(...)` on communication / parse failures.
pub fn get_info_client_pin_set(hid: &SoloHid) -> Result<bool> {
    super::ctap2::get_info_client_pin_set(hid)
}

/// Get credential slot info via CTAP2 authenticatorGetInfo (0x04).
pub fn cmd_credential_info(hid: &SoloHid) -> Result<()> {
    use ciborium::value::Value;

    // CTAP2 getInfo
    let cbor_get_info = vec![0x04u8];
    let response = hid.send_recv(CTAPHID_CBOR, &cbor_get_info)?;

    let pairs = parse_cbor_map_response(&response, "authenticatorGetInfo")?;

    println!("CTAP2 authenticatorGetInfo");
    println!("{}", "=".repeat(40));

    // 0x01: versions
    if let Some(Value::Array(versions)) = find_cbor_response_by_key(&pairs, 0x01) {
        let strs: Vec<&str> = extract_cbor_text_responses(&versions);
        println!("Versions:                       {}", strs.join(", "));
    }

    // 0x02: extensions
    if let Some(Value::Array(exts)) = find_cbor_response_by_key(&pairs, 0x02) {
        let strs: Vec<&str> = extract_cbor_text_responses(&exts);
        println!("Extensions:                     {}", strs.join(", "));
    }

    // 0x03: aaguid (16 bytes)
    if let Some(Value::Bytes(aaguid)) = find_cbor_response_by_key(&pairs, 0x03) {
        println!("AAGUID:                         {}", hex::encode(aaguid));
    }

    // 0x04: options (map of string -> bool)
    if let Some(Value::Map(opts)) = find_cbor_response_by_key(&pairs, 0x04) {
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
    if let Some(Value::Integer(n)) = find_cbor_response_by_key(&pairs, 0x05) {
        let size: u64 = (*n).try_into().unwrap_or(0);
        println!("Max message size:               {}", size);
    }

    // 0x06: pinUvAuthProtocols
    if let Some(Value::Array(protos)) = find_cbor_response_by_key(&pairs, 0x06) {
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
    if let Some(Value::Integer(n)) = find_cbor_response_by_key(&pairs, 0x07) {
        let count: u64 = (*n).try_into().unwrap_or(0);
        println!("Max credential count in list:   {}", count);
    }

    // 0x08: maxCredentialIdLength
    if let Some(Value::Integer(n)) = find_cbor_response_by_key(&pairs, 0x08) {
        let len: u64 = (*n).try_into().unwrap_or(0);
        println!("Max credential ID length:       {}", len);
    }

    // 0x0A: remainingDiscoverableCredentials
    if let Some(Value::Integer(n)) = find_cbor_response_by_key(&pairs, 0x0A) {
        let remaining: u64 = (*n).try_into().unwrap_or(0);
        println!("Remaining discoverable creds:   {}", remaining);
    } else {
        println!("Remaining discoverable creds:   (not reported by device)");
    }

    Ok(())
}

/// List resident credentials via CTAP2 authenticatorCredentialManagement (0x0A).
///
/// Protocol:
///   1. Prompt for PIN, derive PIN token via clientPIN (0x06):
///      a. getKeyAgreement (subcommand 0x02) → device COSE key
///      b. Generate ephemeral P-256 keypair, ECDH → shared_secret = SHA-256(x)
///      c. pinHashEnc = AES-256-CBC(shared_secret, IV=0, SHA-256(pin)[0..16])
///      d. getPINToken (subcommand 0x05) → decrypt response → pinToken (32 bytes)
///   2. enumerateRPsBegin (credMgmt 0x0A subcommand 0x02):
///      pinUvAuthParam = HMAC-SHA-256(pinToken, [0x02])[0..16]
///      Response: {0x03: rp, 0x04: rpIdHash, 0x05: totalRPs}
///   3. enumerateRPsGetNextRP (subcommand 0x03) for remaining RPs
///   4. For each RP, enumerateCredentialsBegin (subcommand 0x04):
///      pinUvAuthParam = HMAC-SHA-256(pinToken, [0x04] || CBOR({0x01: rpIdHash}))[0..16]
///      Response: {0x06: user, 0x07: credentialId, 0x08: publicKey, 0x09: totalCredentials}
///   5. enumerateCredentialsGetNextCredential (subcommand 0x05) for remaining
pub fn cmd_credential_ls(hid: &SoloHid) -> Result<()> {
    use base64::Engine as _;
    use ciborium::value::Value;
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;

    // ── Pre-check: ensure a PIN has been set on the device ──────────────
    if !get_info_client_pin_set(hid)? {
        return Err(SoloError::DeviceError(
            "Credential management requires a PIN. Please set a PIN first with 'solo1 key set-pin'.".into(),
        ));
    }

    // ── Step 0: get PIN token ────────────────────────────────────────────

    let pin = rpassword::prompt_password("PIN: ").map_err(|e| SoloError::IoError(e))?;
    if pin.len() < 4 {
        return Err(SoloError::DeviceError(
            "PIN must be at least 4 characters".into(),
        ));
    }

    let pin_token = get_pin_token(hid, &pin)?;
    let pin_token = pin_token.as_slice();

    // Helper: compute pinUvAuthParam = HMAC-SHA-256(pinToken, msg)[0..16]
    let pin_uv_auth = |msg: &[u8]| -> Result<Vec<u8>> {
        let mut mac = Hmac::<Sha256>::new_from_slice(pin_token)
            .map_err(|e| SoloError::DeviceError(format!("HMAC init error: {}", e)))?;
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        Ok(result[..16].to_vec())
    };

    // Helper: send a credMgmt (0x0A) subcommand with optional params and pinAuth
    let send_cred_mgmt =
        |subcommand: u8, params: Option<Value>, pin_uv: Vec<u8>| -> Result<Vec<u8>> {
            let mut map_entries = vec![
                (
                    Value::Integer(0x01u64.into()),
                    Value::Integer((subcommand as u64).into()),
                ), // subCommand
            ];
            if let Some(p) = params {
                map_entries.push((Value::Integer(0x02u64.into()), p)); // subCommandParams
            }
            map_entries.push((Value::Integer(0x03u64.into()), Value::Integer(1u64.into()))); // pinUvAuthProtocol = 1
            map_entries.push((Value::Integer(0x04u64.into()), Value::Bytes(pin_uv))); // pinUvAuthParam

            let cm_cbor = Value::Map(map_entries);
            let mut req = vec![0x0Au8]; // authenticatorCredentialManagement
            ciborium::ser::into_writer(&cm_cbor, &mut req)
                .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;
            hid.send_recv(CTAPHID_CBOR, &req)
        };

    // Helper: send a credMgmt subcommand with NO pinAuth (for *Next commands)
    let send_cred_mgmt_next = |subcommand: u8| -> Result<Vec<u8>> {
        let cm_cbor = Value::Map(vec![(
            Value::Integer(0x01u64.into()),
            Value::Integer((subcommand as u64).into()),
        )]);
        let mut req = vec![0x0Au8];
        ciborium::ser::into_writer(&cm_cbor, &mut req)
            .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;
        hid.send_recv(CTAPHID_CBOR, &req)
    };

    // Helper: parse a CBOR map response, check status byte
    let parse_cm_response = |resp: Vec<u8>, ctx: &str| -> Result<Vec<(Value, Value)>> {
        if resp.is_empty() {
            return Err(SoloError::DeviceError(format!(
                "Empty response from {}",
                ctx
            )));
        }
        let status = resp[0];
        if status == 0x2E {
            return Err(SoloError::DeviceError(
                "Authenticator does not support credential management (CTAP2_ERR_UNSUPPORTED_OPTION 0x2E)".into()
            ));
        }
        if status != 0x00 {
            return Err(SoloError::DeviceError(format!(
                "{} returned CTAP error 0x{:02X}",
                ctx, status
            )));
        }
        if resp.len() == 1 {
            return Ok(vec![]);
        }
        let val: Value = ciborium::de::from_reader(&resp[1..])
            .map_err(|e| SoloError::DeviceError(format!("CBOR parse error in {}: {}", ctx, e)))?;
        match val {
            Value::Map(p) => Ok(p),
            _ => Err(SoloError::DeviceError(format!(
                "{} response is not a CBOR map",
                ctx
            ))),
        }
    };

    // ── Step 1: enumerateRPsBegin (subcommand 0x02) ──────────────────────
    // pinUvAuthParam = HMAC-SHA-256(pinToken, [0x02])[0..16]
    let rp_begin_auth = pin_uv_auth(&[0x02u8])?;
    let rp_begin_resp = send_cred_mgmt(0x02, None, rp_begin_auth)?;
    let rp_begin_pairs = parse_cm_response(rp_begin_resp, "enumerateRPsBegin")?;

    if rp_begin_pairs.is_empty() {
        println!("No resident credentials on this device.");
        return Ok(());
    }

    // Extract totalRPs from response (key 0x05); may be absent if only 1 RP
    let total_rps: usize = find_cbor_response_by_key(&rp_begin_pairs, 0x05)
        .and_then(|v| {
            if let Value::Integer(i) = v {
                (*i).try_into().ok()
            } else {
                None
            }
        })
        .unwrap_or(1usize);

    // Collect all RP responses
    let mut rp_responses: Vec<Vec<(Value, Value)>> = vec![rp_begin_pairs];
    for _ in 1..total_rps {
        let next_resp = send_cred_mgmt_next(0x03)?;
        let next_pairs = parse_cm_response(next_resp, "enumerateRPsGetNextRP")?;
        rp_responses.push(next_pairs);
    }

    // ── Step 2: For each RP, enumerate credentials ───────────────────────
    println!(
        "{:<32} {:<24} {}",
        "Relying Party", "Username", "Credential ID (base64)"
    );
    println!("{}", "-".repeat(90));

    for rp_pairs in &rp_responses {
        // Extract rpId from key 0x03 (rp map with "id" field)
        let rp_id: String = find_cbor_response_by_key(rp_pairs, 0x03)
            .and_then(|v| {
                if let Value::Map(m) = v {
                    m.iter().find_map(|(k, val)| {
                        if let Value::Text(s) = k {
                            if s == "id" {
                                if let Value::Text(id) = val {
                                    Some(id.clone())
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
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "<unknown>".into());

        // Extract rpIdHash from key 0x04 (32 bytes)
        let rp_id_hash: Vec<u8> = find_cbor_response_by_key(rp_pairs, 0x04)
            .and_then(|v| {
                if let Value::Bytes(b) = v {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                SoloError::DeviceError(format!("rpIdHash (0x04) missing for RP '{}'", rp_id))
            })?;

        if rp_id_hash.len() != 32 {
            return Err(SoloError::DeviceError(format!(
                "rpIdHash for '{}' is {} bytes, expected 32",
                rp_id,
                rp_id_hash.len()
            )));
        }

        // enumerateCredentialsBegin (subcommand 0x04)
        // subCommandParams = CBOR({0x01: rpIdHash})
        // pinUvAuthParam = HMAC-SHA-256(pinToken, [0x04] || subCommandParamsCbor)[0..16]
        let rk_begin_params = Value::Map(vec![(
            Value::Integer(0x01u64.into()),
            Value::Bytes(rp_id_hash.clone()),
        )]);
        let mut rk_params_cbor: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(&rk_begin_params, &mut rk_params_cbor)
            .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

        let mut rk_auth_msg = vec![0x04u8];
        rk_auth_msg.extend_from_slice(&rk_params_cbor);
        let rk_begin_auth = pin_uv_auth(&rk_auth_msg)?;

        let rk_begin_resp = send_cred_mgmt(0x04, Some(rk_begin_params), rk_begin_auth)?;
        let rk_begin_pairs = parse_cm_response(rk_begin_resp, "enumerateCredentialsBegin")?;

        if rk_begin_pairs.is_empty() {
            continue;
        }

        let total_creds: usize = find_cbor_response_by_key(&rk_begin_pairs, 0x09)
            .and_then(|v| {
                if let Value::Integer(i) = v {
                    (*i).try_into().ok()
                } else {
                    None
                }
            })
            .unwrap_or(1usize);

        let mut cred_responses = vec![rk_begin_pairs];
        for _ in 1..total_creds {
            let next_resp = send_cred_mgmt_next(0x05)?;
            let next_pairs = parse_cm_response(next_resp, "enumerateCredentialsGetNextCredential")?;
            cred_responses.push(next_pairs);
        }

        for cred_pairs in &cred_responses {
            // user: key 0x06 → map with "name" or "displayName"
            let username: String = find_cbor_response_by_key(cred_pairs, 0x06)
                .and_then(|v| {
                    if let Value::Map(m) = v {
                        // prefer "name", fall back to "displayName", then "id" as hex
                        m.iter()
                            .find_map(|(k, val)| {
                                if let Value::Text(s) = k {
                                    if s == "name" || s == "displayName" {
                                        if let Value::Text(n) = val {
                                            Some(n.clone())
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
                            .or_else(|| {
                                m.iter().find_map(|(k, val)| {
                                    if let Value::Text(s) = k {
                                        if s == "id" {
                                            match val {
                                                Value::Text(t) => Some(t.clone()),
                                                Value::Bytes(b) => Some(hex::encode(b)),
                                                _ => None,
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                })
                            })
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "<unknown>".into());

            // credentialId: key 0x07 → map with "id" (bytes)
            let cred_id_b64: String = find_cbor_response_by_key(cred_pairs, 0x07)
                .and_then(|v| {
                    if let Value::Map(m) = v {
                        m.iter().find_map(|(k, val)| {
                            if let Value::Text(s) = k {
                                if s == "id" {
                                    if let Value::Bytes(b) = val {
                                        Some(base64::engine::general_purpose::STANDARD.encode(b))
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
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "<unknown>".into());

            println!("{:<32} {:<24} {}", rp_id, username, cred_id_b64);
        }
    }

    Ok(())
}

/// Remove a credential by ID.
/// Implements CTAP2 authenticatorCredentialManagement (0x0A) deleteCredential (subcommand 0x06).
pub fn cmd_credential_rm(hid: &SoloHid, credential_id: &str) -> Result<()> {
    use ciborium::value::Value;
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;

    let cred_id_bytes = hex::decode(credential_id)
        .map_err(|e| SoloError::DeviceError(format!("Invalid credential ID hex: {}", e)))?;

    // Confirmation prompt
    print!("Delete credential {}? (yes/N): ", credential_id);
    use std::io::Write as _;
    std::io::stdout()
        .flush()
        .map_err(|e| SoloError::IoError(e))?;
    let mut confirmation = String::new();
    std::io::stdin()
        .read_line(&mut confirmation)
        .map_err(|e| SoloError::IoError(e))?;
    if confirmation.trim() != "yes" {
        println!("Aborted.");
        return Ok(());
    }

    // ── Pre-check: ensure a PIN has been set on the device ──────────────
    if !get_info_client_pin_set(hid)? {
        return Err(SoloError::DeviceError(
            "Credential management requires a PIN. Please set a PIN first with 'solo1 key set-pin'.".into(),
        ));
    }

    // ── Step 0: get PIN token ────────────────────────────────────────────

    let pin = rpassword::prompt_password("PIN: ").map_err(|e| SoloError::IoError(e))?;
    if pin.len() < 4 {
        return Err(SoloError::DeviceError(
            "PIN must be at least 4 characters".into(),
        ));
    }

    let pin_token = get_pin_token(hid, &pin)?;
    let pin_token = pin_token.as_slice();

    // ── Step 1: deleteCredential (subcommand 0x06) ───────────────────────
    // subCommandParams = CBOR({0x01: credentialId bytes})
    let del_params = Value::Map(vec![(
        Value::Integer(0x01u64.into()),
        Value::Bytes(cred_id_bytes),
    )]);
    let mut del_params_cbor: Vec<u8> = Vec::new();
    ciborium::ser::into_writer(&del_params, &mut del_params_cbor)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    // pinUvAuthParam = HMAC-SHA-256(pinToken, [0x06] || subCommandParamsCbor)[0..16]
    let mut del_auth_msg = vec![0x06u8];
    del_auth_msg.extend_from_slice(&del_params_cbor);
    let del_pin_uv_auth: Vec<u8> = {
        let mut mac = Hmac::<Sha256>::new_from_slice(pin_token)
            .map_err(|e| SoloError::DeviceError(format!("HMAC init error: {}", e)))?;
        mac.update(&del_auth_msg);
        let result = mac.finalize().into_bytes();
        result[..16].to_vec()
    };

    // Send: authenticatorCredentialManagement CBOR =
    //   {0x01: 6, 0x02: {0x01: cred_id_bytes}, 0x03: 1, 0x04: pinUvAuthParam}
    let del_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(6u64.into())), // subCommand = deleteCredential
        (Value::Integer(0x02u64.into()), del_params),                  // subCommandParams
        (Value::Integer(0x03u64.into()), Value::Integer(1u64.into())), // pinUvAuthProtocol = 1
        (
            Value::Integer(0x04u64.into()),
            Value::Bytes(del_pin_uv_auth),
        ), // pinUvAuthParam
    ]);
    let mut del_req = vec![0x0Au8]; // authenticatorCredentialManagement
    ciborium::ser::into_writer(&del_cbor, &mut del_req)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let del_resp = hid.send_recv(CTAPHID_CBOR, &del_req)?;
    if del_resp.is_empty() {
        return Err(SoloError::DeviceError(
            "Empty response from deleteCredential".into(),
        ));
    }
    let status = del_resp[0];
    if status == 0x2E {
        return Err(SoloError::DeviceError(
            "Authenticator does not support credential management (CTAP2_ERR_UNSUPPORTED_OPTION 0x2E)".into()
        ));
    }
    if status != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "deleteCredential returned CTAP error 0x{:02X}",
            status
        )));
    }

    println!("Credential deleted.");
    Ok(())
}
