use crate::device::{SoloHid, CTAPHID_CBOR};
use crate::error::{Result, SoloError};

/// Query CTAP2 getInfo (0x04) and return whether a PIN has been set on the device.
///
/// Returns `Ok(true)` when `options.clientPin == true`, `Ok(false)` when it is
/// `false` or absent, and `Err(...)` on communication / parse failures.
pub fn get_info_client_pin_set(hid: &SoloHid) -> Result<bool> {
    use ciborium::value::Value;

    let get_info_req = vec![0x04u8];
    let info_resp = hid.send_recv(CTAPHID_CBOR, &get_info_req)?;
    if info_resp.is_empty() || info_resp[0] != 0x00 {
        return Err(SoloError::DeviceError("getInfo failed".into()));
    }
    let info_val: Value = ciborium::de::from_reader(&info_resp[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;
    let pairs = match info_val {
        Value::Map(p) => p,
        _ => return Err(SoloError::DeviceError("getInfo response is not a CBOR map".into())),
    };
    // Key 0x04 in getInfo response is the options map (text → bool)
    let client_pin_set = pairs
        .iter()
        .find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == 0x04 {
                    if let Value::Map(opts) = v {
                        return Some(opts.iter().find_map(|(ok, ov)| {
                            if let (Value::Text(name), Value::Bool(b)) = (ok, ov) {
                                if name == "clientPin" { Some(*b) } else { None }
                            } else {
                                None
                            }
                        }));
                    }
                }
            }
            None
        })
        .flatten()
        .unwrap_or(false);
    Ok(client_pin_set)
}

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
    use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    use base64::Engine as _;
    use ciborium::value::Value;
    use hmac::{Hmac, Mac};
    use p256::ecdh::EphemeralSecret;
    use p256::EncodedPoint;
    use rand::rngs::OsRng;
    use sha2::{Digest as _, Sha256};

    // ── Pre-check: ensure a PIN has been set on the device ──────────────
    if !get_info_client_pin_set(hid)? {
        return Err(SoloError::DeviceError(
            "Credential management requires a PIN. Please set a PIN first with 'solo1 key set-pin'.".into(),
        ));
    }

    // ── Step 0: get PIN token ────────────────────────────────────────────

    let pin = rpassword::prompt_password("PIN: ")
        .map_err(|e| SoloError::IoError(e))?;
    if pin.len() < 4 {
        return Err(SoloError::DeviceError("PIN must be at least 4 characters".into()));
    }

    // 0a. getKeyAgreement (clientPIN 0x06, subcommand 0x02)
    let get_ka_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())), // pinUvAuthProtocol = 1
        (Value::Integer(0x02u64.into()), Value::Integer(2u64.into())), // subCommand = getKeyAgreement
    ]);
    let mut ka_req = vec![0x06u8];
    ciborium::ser::into_writer(&get_ka_cbor, &mut ka_req)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let ka_resp = hid.send_recv(CTAPHID_CBOR, &ka_req)?;
    if ka_resp.is_empty() {
        return Err(SoloError::DeviceError("Empty response from getKeyAgreement".into()));
    }
    if ka_resp[0] != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "getKeyAgreement returned CTAP error 0x{:02X}", ka_resp[0]
        )));
    }

    let ka_val: Value = ciborium::de::from_reader(&ka_resp[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;
    let ka_pairs = match ka_val {
        Value::Map(p) => p,
        _ => return Err(SoloError::DeviceError("getKeyAgreement response is not a map".into())),
    };

    let key_agreement = ka_pairs
        .iter()
        .find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == 0x01 { Some(v) } else { None }
            } else { None }
        })
        .ok_or_else(|| SoloError::DeviceError("keyAgreement missing from response".into()))?;

    let cose_pairs = match key_agreement {
        Value::Map(p) => p,
        _ => return Err(SoloError::DeviceError("keyAgreement is not a CBOR map".into())),
    };

    let get_coord = |key: i64| -> Result<Vec<u8>> {
        cose_pairs
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(i) = k {
                    let ki: i64 = (*i).try_into().ok()?;
                    if ki == key {
                        if let Value::Bytes(b) = v { Some(b.clone()) } else { None }
                    } else { None }
                } else { None }
            })
            .ok_or_else(|| SoloError::DeviceError(format!("COSE key missing coordinate {}", key)))
    };

    let dev_x = get_coord(-2)?;
    let dev_y = get_coord(-3)?;
    if dev_x.len() != 32 || dev_y.len() != 32 {
        return Err(SoloError::DeviceError("Device COSE key coordinates are not 32 bytes".into()));
    }

    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&dev_x);
    uncompressed.extend_from_slice(&dev_y);
    let dev_pub_key = p256::PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| SoloError::DeviceError(format!("Invalid device public key: {}", e)))?;

    // 0b. Ephemeral keypair + ECDH → shared_secret
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pub = p256::PublicKey::from(&ephemeral_secret);
    let ephemeral_point = EncodedPoint::from(&ephemeral_pub);

    let shared_secret_point = ephemeral_secret.diffie_hellman(&dev_pub_key);
    let shared_secret: [u8; 32] = Sha256::digest(shared_secret_point.raw_secret_bytes()).into();

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    // 0c. pinHashEnc = AES-256-CBC(shared_secret, IV=0, SHA-256(pin)[0..16])
    let pin_hash_full = Sha256::digest(pin.as_bytes());
    let pin_hash: [u8; 16] = pin_hash_full[..16].try_into().unwrap();
    let mut pin_hash_enc = [0u8; 16];
    #[allow(deprecated)]
    {
        use aes::cipher::generic_array::GenericArray;
        type Block16 = GenericArray<u8, aes::cipher::typenum::U16>;
        let iv = [0u8; 16];
        let src: &[Block16] = unsafe {
            std::slice::from_raw_parts(pin_hash.as_ptr() as *const Block16, 1)
        };
        let dst: &mut [Block16] = unsafe {
            std::slice::from_raw_parts_mut(pin_hash_enc.as_mut_ptr() as *mut Block16, 1)
        };
        let _ = Aes256CbcEnc::new(&shared_secret.into(), &iv.into())
            .encrypt_blocks_b2b_mut(src, dst);
    }

    // 0d. getPINToken (subcommand 0x05)
    let eph_x = ephemeral_point.x()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing x".into()))?.to_vec();
    let eph_y = ephemeral_point.y()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing y".into()))?.to_vec();

    let eph_cose = Value::Map(vec![
        (Value::Integer(1i64.into()),    Value::Integer(2i64.into())),
        (Value::Integer(3i64.into()),    Value::Integer((-7i64).into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(eph_x)),
        (Value::Integer((-3i64).into()), Value::Bytes(eph_y)),
    ]);

    let get_pin_token_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())),             // pinUvAuthProtocol = 1
        (Value::Integer(0x02u64.into()), Value::Integer(5u64.into())),             // subCommand = getPINToken
        (Value::Integer(0x03u64.into()), eph_cose),                                // keyAgreement
        (Value::Integer(0x06u64.into()), Value::Bytes(pin_hash_enc.to_vec())),     // pinHashEnc
    ]);

    let mut gpt_req = vec![0x06u8];
    ciborium::ser::into_writer(&get_pin_token_cbor, &mut gpt_req)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let gpt_resp = hid.send_recv(CTAPHID_CBOR, &gpt_req)?;
    if gpt_resp.is_empty() {
        return Err(SoloError::DeviceError("Empty response from getPINToken".into()));
    }
    if gpt_resp[0] != 0x00 {
        let code = gpt_resp[0];
        let hint = match code {
            0x31 => " (PIN_INVALID — wrong PIN)",
            0x32 => " (PIN_BLOCKED — too many attempts; reset required)",
            0x34 => " (PIN_AUTH_BLOCKED — power-cycle the key and retry)",
            _ => "",
        };
        return Err(SoloError::DeviceError(format!(
            "getPINToken returned CTAP error 0x{:02X}{}", code, hint
        )));
    }

    let gpt_val: Value = ciborium::de::from_reader(&gpt_resp[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;
    let gpt_pairs = match gpt_val {
        Value::Map(p) => p,
        _ => return Err(SoloError::DeviceError("getPINToken response is not a map".into())),
    };

    let pin_token_enc = gpt_pairs
        .iter()
        .find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == 0x02 {
                    if let Value::Bytes(b) = v { Some(b.clone()) } else { None }
                } else { None }
            } else { None }
        })
        .ok_or_else(|| SoloError::DeviceError("pinTokenEnc (0x02) missing from getPINToken response".into()))?;

    if pin_token_enc.is_empty() || pin_token_enc.len() % 16 != 0 {
        return Err(SoloError::DeviceError(format!(
            "pinTokenEnc has unexpected length: {}", pin_token_enc.len()
        )));
    }

    // Decrypt pinToken: AES-256-CBC-decrypt(shared_secret, IV=0, pinTokenEnc)
    // Solo 1 uses PIN_TOKEN_SIZE=16, so pinTokenEnc is exactly 16 bytes.
    let n_token_blocks = pin_token_enc.len() / 16;
    let mut pin_token = pin_token_enc.clone();
    #[allow(deprecated)]
    {
        use aes::cipher::generic_array::GenericArray;
        type Block16 = GenericArray<u8, aes::cipher::typenum::U16>;
        let iv = [0u8; 16];
        let src: &[Block16] = unsafe {
            std::slice::from_raw_parts(pin_token_enc.as_ptr() as *const Block16, n_token_blocks)
        };
        let dst: &mut [Block16] = unsafe {
            std::slice::from_raw_parts_mut(pin_token.as_mut_ptr() as *mut Block16, n_token_blocks)
        };
        let _ = Aes256CbcDec::new(&shared_secret.into(), &iv.into())
            .decrypt_blocks_b2b_mut(src, dst);
    }
    // Use the full decrypted token (Solo 1: 16 bytes; larger tokens also supported)
    let pin_token = &pin_token[..pin_token_enc.len()];

    // Helper: compute pinUvAuthParam = HMAC-SHA-256(pinToken, msg)[0..16]
    let pin_uv_auth = |msg: &[u8]| -> Result<Vec<u8>> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pin_token)
            .map_err(|e| SoloError::DeviceError(format!("HMAC init error: {}", e)))?;
        mac.update(msg);
        let result = mac.finalize().into_bytes();
        Ok(result[..16].to_vec())
    };

    // Helper: send a credMgmt (0x0A) subcommand with optional params and pinAuth
    let send_cred_mgmt = |subcommand: u8, params: Option<Value>, pin_uv: Vec<u8>| -> Result<Vec<u8>> {
        let mut map_entries = vec![
            (Value::Integer(0x01u64.into()), Value::Integer((subcommand as u64).into())),  // subCommand
        ];
        if let Some(p) = params {
            map_entries.push((Value::Integer(0x02u64.into()), p));                // subCommandParams
        }
        map_entries.push((Value::Integer(0x03u64.into()), Value::Integer(1u64.into()))); // pinUvAuthProtocol = 1
        map_entries.push((Value::Integer(0x04u64.into()), Value::Bytes(pin_uv)));         // pinUvAuthParam

        let cm_cbor = Value::Map(map_entries);
        let mut req = vec![0x0Au8]; // authenticatorCredentialManagement
        ciborium::ser::into_writer(&cm_cbor, &mut req)
            .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;
        hid.send_recv(CTAPHID_CBOR, &req)
    };

    // Helper: send a credMgmt subcommand with NO pinAuth (for *Next commands)
    let send_cred_mgmt_next = |subcommand: u8| -> Result<Vec<u8>> {
        let cm_cbor = Value::Map(vec![
            (Value::Integer(0x01u64.into()), Value::Integer((subcommand as u64).into())),
        ]);
        let mut req = vec![0x0Au8];
        ciborium::ser::into_writer(&cm_cbor, &mut req)
            .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;
        hid.send_recv(CTAPHID_CBOR, &req)
    };

    // Helper: parse a CBOR map response, check status byte
    let parse_cm_response = |resp: Vec<u8>, ctx: &str| -> Result<Vec<(Value, Value)>> {
        if resp.is_empty() {
            return Err(SoloError::DeviceError(format!("Empty response from {}", ctx)));
        }
        let status = resp[0];
        if status == 0x2E {
            return Err(SoloError::DeviceError(
                "Authenticator does not support credential management (CTAP2_ERR_UNSUPPORTED_OPTION 0x2E)".into()
            ));
        }
        if status != 0x00 {
            return Err(SoloError::DeviceError(format!(
                "{} returned CTAP error 0x{:02X}", ctx, status
            )));
        }
        if resp.len() == 1 {
            return Ok(vec![]);
        }
        let val: Value = ciborium::de::from_reader(&resp[1..])
            .map_err(|e| SoloError::DeviceError(format!("CBOR parse error in {}: {}", ctx, e)))?;
        match val {
            Value::Map(p) => Ok(p),
            _ => Err(SoloError::DeviceError(format!("{} response is not a CBOR map", ctx))),
        }
    };

    // Helper: look up an integer key in a CBOR map
    fn find_int_key<'a>(pairs: &'a [(Value, Value)], key: u64) -> Option<&'a Value> {
        pairs.iter().find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == key { Some(v) } else { None }
            } else { None }
        })
    }

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
    let total_rps: usize = find_int_key(&rp_begin_pairs, 0x05)
        .and_then(|v| if let Value::Integer(i) = v { (*i).try_into().ok() } else { None })
        .unwrap_or(1usize);

    // Collect all RP responses
    let mut rp_responses: Vec<Vec<(Value, Value)>> = vec![rp_begin_pairs];
    for _ in 1..total_rps {
        let next_resp = send_cred_mgmt_next(0x03)?;
        let next_pairs = parse_cm_response(next_resp, "enumerateRPsGetNextRP")?;
        rp_responses.push(next_pairs);
    }

    // ── Step 2: For each RP, enumerate credentials ───────────────────────
    println!("{:<32} {:<24} {}", "Relying Party", "Username", "Credential ID (base64)");
    println!("{}", "-".repeat(90));

    for rp_pairs in &rp_responses {
        // Extract rpId from key 0x03 (rp map with "id" field)
        let rp_id: String = find_int_key(rp_pairs, 0x03)
            .and_then(|v| {
                if let Value::Map(m) = v {
                    m.iter().find_map(|(k, val)| {
                        if let Value::Text(s) = k {
                            if s == "id" {
                                if let Value::Text(id) = val { Some(id.clone()) } else { None }
                            } else { None }
                        } else { None }
                    })
                } else { None }
            })
            .unwrap_or_else(|| "<unknown>".into());

        // Extract rpIdHash from key 0x04 (32 bytes)
        let rp_id_hash: Vec<u8> = find_int_key(rp_pairs, 0x04)
            .and_then(|v| if let Value::Bytes(b) = v { Some(b.clone()) } else { None })
            .ok_or_else(|| SoloError::DeviceError(
                format!("rpIdHash (0x04) missing for RP '{}'", rp_id)
            ))?;

        if rp_id_hash.len() != 32 {
            return Err(SoloError::DeviceError(format!(
                "rpIdHash for '{}' is {} bytes, expected 32", rp_id, rp_id_hash.len()
            )));
        }

        // enumerateCredentialsBegin (subcommand 0x04)
        // subCommandParams = CBOR({0x01: rpIdHash})
        // pinUvAuthParam = HMAC-SHA-256(pinToken, [0x04] || subCommandParamsCbor)[0..16]
        let rk_begin_params = Value::Map(vec![
            (Value::Integer(0x01u64.into()), Value::Bytes(rp_id_hash.clone())),
        ]);
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

        let total_creds: usize = find_int_key(&rk_begin_pairs, 0x09)
            .and_then(|v| if let Value::Integer(i) = v { (*i).try_into().ok() } else { None })
            .unwrap_or(1usize);

        let mut cred_responses = vec![rk_begin_pairs];
        for _ in 1..total_creds {
            let next_resp = send_cred_mgmt_next(0x05)?;
            let next_pairs = parse_cm_response(next_resp, "enumerateCredentialsGetNextCredential")?;
            cred_responses.push(next_pairs);
        }

        for cred_pairs in &cred_responses {
            // user: key 0x06 → map with "name" or "displayName"
            let username: String = find_int_key(cred_pairs, 0x06)
                .and_then(|v| {
                    if let Value::Map(m) = v {
                        // prefer "name", fall back to "displayName", then "id" as hex
                        m.iter().find_map(|(k, val)| {
                            if let Value::Text(s) = k {
                                if s == "name" || s == "displayName" {
                                    if let Value::Text(n) = val { Some(n.clone()) } else { None }
                                } else { None }
                            } else { None }
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
                                    } else { None }
                                } else { None }
                            })
                        })
                    } else { None }
                })
                .unwrap_or_else(|| "<unknown>".into());

            // credentialId: key 0x07 → map with "id" (bytes)
            let cred_id_b64: String = find_int_key(cred_pairs, 0x07)
                .and_then(|v| {
                    if let Value::Map(m) = v {
                        m.iter().find_map(|(k, val)| {
                            if let Value::Text(s) = k {
                                if s == "id" {
                                    if let Value::Bytes(b) = val {
                                        Some(base64::engine::general_purpose::STANDARD.encode(b))
                                    } else { None }
                                } else { None }
                            } else { None }
                        })
                    } else { None }
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
    use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    use ciborium::value::Value;
    use hmac::{Hmac, Mac};
    use p256::ecdh::EphemeralSecret;
    use p256::EncodedPoint;
    use rand::rngs::OsRng;
    use sha2::{Digest as _, Sha256};

    let cred_id_bytes = hex::decode(credential_id).map_err(|e| {
        SoloError::DeviceError(format!("Invalid credential ID hex: {}", e))
    })?;

    // Confirmation prompt
    print!("Delete credential {}? (yes/N): ", credential_id);
    use std::io::Write as _;
    std::io::stdout().flush().map_err(|e| SoloError::IoError(e))?;
    let mut confirmation = String::new();
    std::io::stdin().read_line(&mut confirmation)
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

    let pin = rpassword::prompt_password("PIN: ")
        .map_err(|e| SoloError::IoError(e))?;
    if pin.len() < 4 {
        return Err(SoloError::DeviceError("PIN must be at least 4 characters".into()));
    }

    // 0a. getKeyAgreement (clientPIN 0x06, subcommand 0x02)
    let get_ka_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())), // pinUvAuthProtocol = 1
        (Value::Integer(0x02u64.into()), Value::Integer(2u64.into())), // subCommand = getKeyAgreement
    ]);
    let mut ka_req = vec![0x06u8];
    ciborium::ser::into_writer(&get_ka_cbor, &mut ka_req)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let ka_resp = hid.send_recv(CTAPHID_CBOR, &ka_req)?;
    if ka_resp.is_empty() {
        return Err(SoloError::DeviceError("Empty response from getKeyAgreement".into()));
    }
    if ka_resp[0] != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "getKeyAgreement returned CTAP error 0x{:02X}", ka_resp[0]
        )));
    }

    let ka_val: Value = ciborium::de::from_reader(&ka_resp[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;
    let ka_pairs = match ka_val {
        Value::Map(p) => p,
        _ => return Err(SoloError::DeviceError("getKeyAgreement response is not a map".into())),
    };

    let key_agreement = ka_pairs
        .iter()
        .find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == 0x01 { Some(v) } else { None }
            } else { None }
        })
        .ok_or_else(|| SoloError::DeviceError("keyAgreement missing from response".into()))?;

    let cose_pairs = match key_agreement {
        Value::Map(p) => p,
        _ => return Err(SoloError::DeviceError("keyAgreement is not a CBOR map".into())),
    };

    let get_coord = |key: i64| -> Result<Vec<u8>> {
        cose_pairs
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(i) = k {
                    let ki: i64 = (*i).try_into().ok()?;
                    if ki == key {
                        if let Value::Bytes(b) = v { Some(b.clone()) } else { None }
                    } else { None }
                } else { None }
            })
            .ok_or_else(|| SoloError::DeviceError(format!("COSE key missing coordinate {}", key)))
    };

    let dev_x = get_coord(-2)?;
    let dev_y = get_coord(-3)?;
    if dev_x.len() != 32 || dev_y.len() != 32 {
        return Err(SoloError::DeviceError("Device COSE key coordinates are not 32 bytes".into()));
    }

    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&dev_x);
    uncompressed.extend_from_slice(&dev_y);
    let dev_pub_key = p256::PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| SoloError::DeviceError(format!("Invalid device public key: {}", e)))?;

    // 0b. Ephemeral keypair + ECDH → shared_secret
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let ephemeral_pub = p256::PublicKey::from(&ephemeral_secret);
    let ephemeral_point = EncodedPoint::from(&ephemeral_pub);

    let shared_secret_point = ephemeral_secret.diffie_hellman(&dev_pub_key);
    let shared_secret: [u8; 32] = Sha256::digest(shared_secret_point.raw_secret_bytes()).into();

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    // 0c. pinHashEnc = AES-256-CBC(shared_secret, IV=0, SHA-256(pin)[0..16])
    let pin_hash_full = Sha256::digest(pin.as_bytes());
    let pin_hash: [u8; 16] = pin_hash_full[..16].try_into().unwrap();
    let mut pin_hash_enc = [0u8; 16];
    #[allow(deprecated)]
    {
        use aes::cipher::generic_array::GenericArray;
        type Block16 = GenericArray<u8, aes::cipher::typenum::U16>;
        let iv = [0u8; 16];
        let src: &[Block16] = unsafe {
            std::slice::from_raw_parts(pin_hash.as_ptr() as *const Block16, 1)
        };
        let dst: &mut [Block16] = unsafe {
            std::slice::from_raw_parts_mut(pin_hash_enc.as_mut_ptr() as *mut Block16, 1)
        };
        let _ = Aes256CbcEnc::new(&shared_secret.into(), &iv.into())
            .encrypt_blocks_b2b_mut(src, dst);
    }

    // 0d. getPINToken (subcommand 0x05)
    let eph_x = ephemeral_point.x()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing x".into()))?.to_vec();
    let eph_y = ephemeral_point.y()
        .ok_or_else(|| SoloError::DeviceError("Ephemeral key missing y".into()))?.to_vec();

    let eph_cose = Value::Map(vec![
        (Value::Integer(1i64.into()),    Value::Integer(2i64.into())),
        (Value::Integer(3i64.into()),    Value::Integer((-7i64).into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(eph_x)),
        (Value::Integer((-3i64).into()), Value::Bytes(eph_y)),
    ]);

    let get_pin_token_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())),             // pinUvAuthProtocol = 1
        (Value::Integer(0x02u64.into()), Value::Integer(5u64.into())),             // subCommand = getPINToken
        (Value::Integer(0x03u64.into()), eph_cose),                                // keyAgreement
        (Value::Integer(0x06u64.into()), Value::Bytes(pin_hash_enc.to_vec())),     // pinHashEnc
    ]);

    let mut gpt_req = vec![0x06u8];
    ciborium::ser::into_writer(&get_pin_token_cbor, &mut gpt_req)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let gpt_resp = hid.send_recv(CTAPHID_CBOR, &gpt_req)?;
    if gpt_resp.is_empty() {
        return Err(SoloError::DeviceError("Empty response from getPINToken".into()));
    }
    if gpt_resp[0] != 0x00 {
        let code = gpt_resp[0];
        let hint = match code {
            0x31 => " (PIN_INVALID — wrong PIN)",
            0x32 => " (PIN_BLOCKED — too many attempts; reset required)",
            0x34 => " (PIN_AUTH_BLOCKED — power-cycle the key and retry)",
            _ => "",
        };
        return Err(SoloError::DeviceError(format!(
            "getPINToken returned CTAP error 0x{:02X}{}", code, hint
        )));
    }

    let gpt_val: Value = ciborium::de::from_reader(&gpt_resp[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;
    let gpt_pairs = match gpt_val {
        Value::Map(p) => p,
        _ => return Err(SoloError::DeviceError("getPINToken response is not a map".into())),
    };

    let pin_token_enc = gpt_pairs
        .iter()
        .find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: u64 = (*i).try_into().ok()?;
                if ki == 0x02 {
                    if let Value::Bytes(b) = v { Some(b.clone()) } else { None }
                } else { None }
            } else { None }
        })
        .ok_or_else(|| SoloError::DeviceError("pinTokenEnc (0x02) missing from getPINToken response".into()))?;

    if pin_token_enc.is_empty() || pin_token_enc.len() % 16 != 0 {
        return Err(SoloError::DeviceError(format!(
            "pinTokenEnc has unexpected length: {}", pin_token_enc.len()
        )));
    }

    // Decrypt pinToken: AES-256-CBC-decrypt(shared_secret, IV=0, pinTokenEnc)
    // Solo 1 uses PIN_TOKEN_SIZE=16, so pinTokenEnc is exactly 16 bytes.
    let n_token_blocks = pin_token_enc.len() / 16;
    let mut pin_token = pin_token_enc.clone();
    #[allow(deprecated)]
    {
        use aes::cipher::generic_array::GenericArray;
        type Block16 = GenericArray<u8, aes::cipher::typenum::U16>;
        let iv = [0u8; 16];
        let src: &[Block16] = unsafe {
            std::slice::from_raw_parts(pin_token_enc.as_ptr() as *const Block16, n_token_blocks)
        };
        let dst: &mut [Block16] = unsafe {
            std::slice::from_raw_parts_mut(pin_token.as_mut_ptr() as *mut Block16, n_token_blocks)
        };
        let _ = Aes256CbcDec::new(&shared_secret.into(), &iv.into())
            .decrypt_blocks_b2b_mut(src, dst);
    }
    // Use the full decrypted token (Solo 1: 16 bytes; larger tokens also supported)
    let pin_token = &pin_token[..pin_token_enc.len()];

    // ── Step 1: deleteCredential (subcommand 0x06) ───────────────────────
    // subCommandParams = CBOR({0x01: credentialId bytes})
    let del_params = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Bytes(cred_id_bytes)),
    ]);
    let mut del_params_cbor: Vec<u8> = Vec::new();
    ciborium::ser::into_writer(&del_params, &mut del_params_cbor)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    // pinUvAuthParam = HMAC-SHA-256(pinToken, [0x06] || subCommandParamsCbor)[0..16]
    let mut del_auth_msg = vec![0x06u8];
    del_auth_msg.extend_from_slice(&del_params_cbor);
    let del_pin_uv_auth: Vec<u8> = {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(pin_token)
            .map_err(|e| SoloError::DeviceError(format!("HMAC init error: {}", e)))?;
        mac.update(&del_auth_msg);
        let result = mac.finalize().into_bytes();
        result[..16].to_vec()
    };

    // Send: authenticatorCredentialManagement CBOR =
    //   {0x01: 6, 0x02: {0x01: cred_id_bytes}, 0x03: 1, 0x04: pinUvAuthParam}
    let del_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(6u64.into())),          // subCommand = deleteCredential
        (Value::Integer(0x02u64.into()), del_params),                            // subCommandParams
        (Value::Integer(0x03u64.into()), Value::Integer(1u64.into())),          // pinUvAuthProtocol = 1
        (Value::Integer(0x04u64.into()), Value::Bytes(del_pin_uv_auth)),        // pinUvAuthParam
    ]);
    let mut del_req = vec![0x0Au8]; // authenticatorCredentialManagement
    ciborium::ser::into_writer(&del_cbor, &mut del_req)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let del_resp = hid.send_recv(CTAPHID_CBOR, &del_req)?;
    if del_resp.is_empty() {
        return Err(SoloError::DeviceError("Empty response from deleteCredential".into()));
    }
    let status = del_resp[0];
    if status == 0x2E {
        return Err(SoloError::DeviceError(
            "Authenticator does not support credential management (CTAP2_ERR_UNSUPPORTED_OPTION 0x2E)".into()
        ));
    }
    if status != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "deleteCredential returned CTAP error 0x{:02X}", status
        )));
    }

    println!("Credential deleted.");
    Ok(())
}
