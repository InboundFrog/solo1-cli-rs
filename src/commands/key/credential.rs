use crate::cbor::{cbor_bytes, cbor_int, int_map};
use crate::commands::key::common;
use crate::ctap2::{
    extract_cbor_text_responses, find_cbor_response_by_key, parse_cbor_map_response,
    prompt_and_get_pin_token,
};
use crate::device::{HidDevice, CTAPHID_CBOR};
use crate::error::{Result, SoloError};

/// Query CTAP2 getInfo (0x04) and return whether a PIN has been set on the device.
///
/// Returns `Ok(true)` when `options.clientPin == true`, `Ok(false)` when it is
/// `false` or absent, and `Err(...)` on communication / parse failures.
pub fn get_info_client_pin_set(hid: &impl HidDevice) -> Result<bool> {
    crate::ctap2::get_info_client_pin_set(hid)
}

/// Get credential slot info via CTAP2 authenticatorGetInfo (0x04).
pub fn cmd_credential_info(hid: &impl HidDevice) -> Result<()> {
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

/// Compute `pinUvAuthParam = HMAC-SHA-256(pin_token, msg)[0..16]`.
fn pin_uv_auth(pin_token: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(pin_token)
        .map_err(|e| SoloError::CryptoError(format!("HMAC init error: {}", e)))?;
    mac.update(msg);
    let result = mac.finalize().into_bytes();
    Ok(result[..16].to_vec())
}

/// Send a credMgmt (0x0A) subcommand with optional params and pinUvAuthParam.
///
/// Encodes the request as a CBOR map with keys: subCommand (0x01),
/// optional subCommandParams (0x02), pinUvAuthProtocol (0x03), and
/// pinUvAuthParam (0x04), then forwards it over HID.
fn send_cred_mgmt(
    hid: &impl HidDevice,
    subcommand: u8,
    params: Option<ciborium::value::Value>,
    pin_uv: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut entries: Vec<(i64, ciborium::value::Value)> = vec![
        (0x01, cbor_int(subcommand as i64)), // subCommand
    ];
    if let Some(p) = params {
        entries.push((0x02, p)); // subCommandParams
    }
    entries.push((0x03, cbor_int(1)));        // pinUvAuthProtocol = 1
    entries.push((0x04, cbor_bytes(pin_uv))); // pinUvAuthParam

    let cm_cbor = int_map(entries);
    let mut req = vec![0x0Au8]; // authenticatorCredentialManagement
    ciborium::ser::into_writer(&cm_cbor, &mut req)
        .map_err(|e| SoloError::CborError(e.to_string()))?;
    hid.send_recv(CTAPHID_CBOR, &req)
}

/// Send a credMgmt (0x0A) subcommand with no authentication parameters.
///
/// Used for the *GetNext* subcommands (0x03 enumerateRPsGetNextRP,
/// 0x05 enumerateCredentialsGetNextCredential) which carry no pinUvAuthParam.
fn send_cred_mgmt_next(hid: &impl HidDevice, subcommand: u8) -> Result<Vec<u8>> {
    let cm_cbor = int_map([(0x01i64, cbor_int(subcommand as i64))]);
    let mut req = vec![0x0Au8];
    ciborium::ser::into_writer(&cm_cbor, &mut req)
        .map_err(|e| SoloError::CborError(e.to_string()))?;
    hid.send_recv(CTAPHID_CBOR, &req)
}

/// Parse a raw credMgmt HID response into a CBOR map, checking the status byte.
///
/// Returns an empty vec if the response contains only a success status byte
/// with no CBOR payload. Returns `Err` for any non-zero status byte or
/// malformed CBOR.
fn parse_cm_response(resp: Vec<u8>, ctx: &str) -> Result<Vec<(ciborium::value::Value, ciborium::value::Value)>> {
    use ciborium::value::Value;
    use crate::ctap2::ctap2_status_message;
    if resp.is_empty() {
        return Err(SoloError::MalformedResponse(format!(
            "Empty response from {}",
            ctx
        )));
    }
    let status = resp[0];
    if status != 0x00 {
        let message = ctap2_status_message(status);
        return Err(SoloError::AuthenticatorError { code: status, message });
    }
    if resp.len() == 1 {
        return Ok(vec![]);
    }
    let val: Value = ciborium::de::from_reader(&resp[1..])
        .map_err(|e| SoloError::CborError(e.to_string()))?;
    match val {
        Value::Map(p) => Ok(p),
        _ => Err(SoloError::MalformedResponse(format!(
            "{} response is not a CBOR map",
            ctx
        ))),
    }
}

/// Send enumerateRPsBegin (subcommand 0x02) then enumerateRPsGetNextRP
/// (subcommand 0x03) for all remaining RPs, returning `(rp_id, rp_id_hash)`
/// pairs for every relying party that has at least one resident credential.
fn enumerate_rps(hid: &impl HidDevice, pin_token: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    use ciborium::value::Value;

    // enumerateRPsBegin — pinUvAuthParam = HMAC-SHA-256(pinToken, [0x02])[0..16]
    let rp_begin_auth = pin_uv_auth(pin_token, &[0x02u8])?;
    let rp_begin_resp = send_cred_mgmt(hid, 0x02, None, rp_begin_auth)?;
    let rp_begin_pairs = parse_cm_response(rp_begin_resp, "enumerateRPsBegin")?;

    if rp_begin_pairs.is_empty() {
        return Ok(vec![]);
    }

    // totalRPs (key 0x05); may be absent when there is only one RP
    let total_rps: usize = find_cbor_response_by_key(&rp_begin_pairs, 0x05)
        .and_then(|v| {
            if let Value::Integer(i) = v {
                (*i).try_into().ok()
            } else {
                None
            }
        })
        .unwrap_or(1usize);

    let mut rp_responses: Vec<Vec<(Value, Value)>> = vec![rp_begin_pairs];
    for _ in 1..total_rps {
        let next_resp = send_cred_mgmt_next(hid, 0x03)?;
        let next_pairs = parse_cm_response(next_resp, "enumerateRPsGetNextRP")?;
        rp_responses.push(next_pairs);
    }

    let mut result = Vec::new();
    for rp_pairs in rp_responses {
        // rp map at key 0x03 — extract the "id" text field
        let rp_id: String = find_cbor_response_by_key(&rp_pairs, 0x03)
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

        // rpIdHash at key 0x04 (32 bytes)
        let rp_id_hash: Vec<u8> = find_cbor_response_by_key(&rp_pairs, 0x04)
            .and_then(|v| {
                if let Value::Bytes(b) = v {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                SoloError::MalformedResponse(format!("rpIdHash (0x04) missing for RP '{}'", rp_id))
            })?;

        if rp_id_hash.len() != 32 {
            return Err(SoloError::MalformedResponse(format!(
                "rpIdHash for '{}' is {} bytes, expected 32",
                rp_id,
                rp_id_hash.len()
            )));
        }

        result.push((rp_id, rp_id_hash));
    }

    Ok(result)
}

/// Send enumerateCredentialsBegin (subcommand 0x04) for the given RP hash,
/// then enumerateCredentialsGetNextCredential (subcommand 0x05) for all
/// remaining credentials, returning `(username, cred_id_base64)` pairs.
///
/// `pin_auth_protocol` is always 1 for the current implementation (CTAP 2.0).
fn enumerate_credentials_for_rp(
    hid: &impl HidDevice,
    pin_token: &[u8],
    rp_id_hash: &[u8],
    _pin_auth_protocol: u8,
) -> Result<Vec<(String, Vec<u8>)>> {
    use base64::Engine as _;
    use ciborium::value::Value;

    // subCommandParams = CBOR({0x01: rpIdHash})
    // pinUvAuthParam   = HMAC-SHA-256(pinToken, [0x04] || subCommandParamsCbor)[0..16]
    let rk_begin_params = int_map([(0x01i64, cbor_bytes(rp_id_hash.to_vec()))]);
    let mut rk_params_cbor: Vec<u8> = Vec::new();
    ciborium::ser::into_writer(&rk_begin_params, &mut rk_params_cbor)
        .map_err(|e| SoloError::CborError(e.to_string()))?;

    let mut rk_auth_msg = vec![0x04u8];
    rk_auth_msg.extend_from_slice(&rk_params_cbor);
    let rk_begin_auth = pin_uv_auth(pin_token, &rk_auth_msg)?;

    let rk_begin_resp = send_cred_mgmt(hid, 0x04, Some(rk_begin_params), rk_begin_auth)?;
    let rk_begin_pairs = parse_cm_response(rk_begin_resp, "enumerateCredentialsBegin")?;

    if rk_begin_pairs.is_empty() {
        return Ok(vec![]);
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
        let next_resp = send_cred_mgmt_next(hid, 0x05)?;
        let next_pairs =
            parse_cm_response(next_resp, "enumerateCredentialsGetNextCredential")?;
        cred_responses.push(next_pairs);
    }

    let mut result = Vec::new();
    for cred_pairs in cred_responses {
        // user: key 0x06 → map with "name" or "displayName"
        let username: String = find_cbor_response_by_key(&cred_pairs, 0x06)
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

        // credentialId: key 0x07 → map with "id" (bytes); store as base64
        let cred_id: Vec<u8> = find_cbor_response_by_key(&cred_pairs, 0x07)
            .and_then(|v| {
                if let Value::Map(m) = v {
                    m.iter().find_map(|(k, val)| {
                        if let Value::Text(s) = k {
                            if s == "id" {
                                if let Value::Bytes(b) = val {
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
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let cred_id_b64 = base64::engine::general_purpose::STANDARD.encode(&cred_id);
        result.push((username, cred_id_b64.into_bytes()));
    }

    Ok(result)
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
pub fn cmd_credential_ls(hid: &impl HidDevice, json: bool) -> Result<()> {
    use crate::output::{CredentialEntry, CredentialListOutput, print_json};

    // ── Pre-check: ensure a PIN has been set on the device ──────────────
    if !get_info_client_pin_set(hid)? {
        return Err(SoloError::ProtocolError(
            "Credential management requires a PIN. Please set a PIN first with 'solo1 key set-pin'.".into(),
        ));
    }

    // ── Step 0: get PIN token ────────────────────────────────────────────
    let pin_token = prompt_and_get_pin_token(hid)?;
    let pin_token = pin_token.as_slice();

    // ── Step 1: enumerate all relying parties ────────────────────────────
    let rps = enumerate_rps(hid, pin_token)?;

    if rps.is_empty() {
        if json {
            return print_json(&CredentialListOutput { credentials: vec![] });
        }
        println!("No resident credentials on this device.");
        return Ok(());
    }

    if json {
        let mut entries = Vec::new();
        for (rp_id, rp_id_hash) in &rps {
            let credentials = enumerate_credentials_for_rp(hid, pin_token, rp_id_hash, 1)?;
            for (username, cred_id_bytes) in credentials {
                let cred_id_b64 = String::from_utf8(cred_id_bytes).unwrap_or_default();
                entries.push(CredentialEntry {
                    rp_id: rp_id.clone(),
                    user_name: username,
                    credential_id: cred_id_b64,
                });
            }
        }
        return print_json(&CredentialListOutput { credentials: entries });
    }

    // ── Step 2: for each RP, enumerate credentials and print ─────────────
    println!(
        "{:<32} {:<24} {}",
        "Relying Party", "Username", "Credential ID (base64)"
    );
    println!("{}", "-".repeat(90));

    for (rp_id, rp_id_hash) in &rps {
        let credentials = enumerate_credentials_for_rp(hid, pin_token, rp_id_hash, 1)?;
        for (username, cred_id_bytes) in credentials {
            let cred_id_b64 = String::from_utf8(cred_id_bytes).unwrap_or_default();
            println!("{:<32} {:<24} {}", rp_id, username, cred_id_b64);
        }
    }

    Ok(())
}

/// Remove a credential by ID.
/// Implements CTAP2 authenticatorCredentialManagement (0x0A) deleteCredential (subcommand 0x06).
pub fn cmd_credential_rm(hid: &impl HidDevice, credential_id: &str) -> Result<()> {
    use base64::Engine as _;
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;

    let cred_id_bytes = base64::engine::general_purpose::STANDARD
        .decode(credential_id)
        .map_err(|e| SoloError::ProtocolError(format!("Invalid base64 credential ID: {}", e)))?;

    // Confirmation prompt
    if !common::confirm(&format!(
        "Delete credential {}? Type 'yes' to confirm:",
        credential_id
    ))? {
        println!("Aborted.");
        return Ok(());
    }

    // ── Pre-check: ensure a PIN has been set on the device ──────────────
    if !get_info_client_pin_set(hid)? {
        return Err(SoloError::ProtocolError(
            "Credential management requires a PIN. Please set a PIN first with 'solo1 key set-pin'.".into(),
        ));
    }

    // ── Step 0: get PIN token ────────────────────────────────────────────

    let pin_token = prompt_and_get_pin_token(hid)?;
    let pin_token = pin_token.as_slice();

    // ── Step 1: deleteCredential (subcommand 0x06) ───────────────────────
    // subCommandParams = CBOR({0x02: PublicKeyCredentialDescriptor})
    // Key 0x01 (CM_subCommandRpId) is for rpIdHash in enumerateCredentials.
    // Key 0x02 (CM_subCommandCred) is for the credential descriptor in deleteCredential.
    // PublicKeyCredentialDescriptor = {"type": "public-key", "id": <bytes>}
    let cred_descriptor = ciborium::value::Value::Map(vec![
        (ciborium::value::Value::Text("type".into()), ciborium::value::Value::Text("public-key".into())),
        (ciborium::value::Value::Text("id".into()), cbor_bytes(cred_id_bytes)),
    ]);
    let del_params = int_map([(0x02i64, cred_descriptor)]);
    let mut del_params_cbor: Vec<u8> = Vec::new();
    ciborium::ser::into_writer(&del_params, &mut del_params_cbor)
        .map_err(|e| SoloError::CborError(e.to_string()))?;

    // pinUvAuthParam = HMAC-SHA-256(pinToken, [0x06] || subCommandParamsCbor)[0..16]
    let mut del_auth_msg = vec![0x06u8];
    del_auth_msg.extend_from_slice(&del_params_cbor);
    let del_pin_uv_auth: Vec<u8> = {
        let mut mac = Hmac::<Sha256>::new_from_slice(pin_token)
            .map_err(|e| SoloError::CryptoError(format!("HMAC init error: {}", e)))?;
        mac.update(&del_auth_msg);
        let result = mac.finalize().into_bytes();
        result[..16].to_vec()
    };

    // Send: authenticatorCredentialManagement CBOR =
    //   {0x01: 6, 0x02: {0x01: cred_id_bytes}, 0x03: 1, 0x04: pinUvAuthParam}
    let del_cbor = int_map([
        (0x01, cbor_int(6)),                    // subCommand = deleteCredential
        (0x02, del_params),                     // subCommandParams
        (0x03, cbor_int(1)),                    // pinUvAuthProtocol = 1
        (0x04, cbor_bytes(del_pin_uv_auth)),    // pinUvAuthParam
    ]);
    let mut del_req = vec![0x0Au8]; // authenticatorCredentialManagement
    ciborium::ser::into_writer(&del_cbor, &mut del_req)
        .map_err(|e| SoloError::CborError(e.to_string()))?;

    let del_resp = hid.send_recv(CTAPHID_CBOR, &del_req)?;
    if del_resp.is_empty() {
        return Err(SoloError::MalformedResponse(
            "Empty response from deleteCredential".into(),
        ));
    }
    let status = del_resp[0];
    if status != 0x00 {
        let message = crate::ctap2::ctap2_status_message(status);
        return Err(SoloError::AuthenticatorError { code: status, message });
    }

    println!("Credential deleted.");
    Ok(())
}
