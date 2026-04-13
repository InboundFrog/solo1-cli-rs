use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use ciborium::value::Value;
use hmac::{Hmac, KeyInit as _, Mac as _};
use p256::ecdh::EphemeralSecret;
use p256::EncodedPoint;
use rand::rngs::OsRng;
use sha2::{Digest as _, Sha256};

use crate::device::{SoloHid, CTAPHID_CBOR};
use crate::error::{Result, SoloError};

/// Query CTAP2 getInfo (0x04) and return whether a PIN has been set on the device.
pub fn get_info_client_pin_set(hid: &SoloHid) -> Result<bool> {
    let get_info_req = vec![0x04u8];
    let info_resp = hid.send_recv(CTAPHID_CBOR, &get_info_req)?;
    if info_resp.is_empty() || info_resp[0] != 0x00 {
        return Err(SoloError::DeviceError("getInfo failed".into()));
    }
    let info_val: Value = ciborium::de::from_reader(&info_resp[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;
    let pairs = match info_val {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "getInfo response is not a CBOR map".into(),
            ))
        }
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
                                if name == "clientPin" {
                                    Some(*b)
                                } else {
                                    None
                                }
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

#[inline]
pub fn create_key_agreement_cbor() -> Value {
    Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())), // pinUvAuthProtocol = 1
        (Value::Integer(0x02u64.into()), Value::Integer(2u64.into())), // subCommand = getKeyAgreement
    ])
}

#[inline]
pub fn find_cbor_response_by_key(response_pairs: &[(Value, Value)], key: u64) -> Option<&Value> {
    response_pairs.iter().find_map(|(k, v)| {
        if let Value::Integer(i) = k {
            let ki: u64 = (*i).try_into().ok()?;
            if ki == key {
                return Some(v);
            }
        }
        None
    })
}

#[inline]
pub fn extract_cbor_text_responses(response_values: &[Value]) -> Vec<&str> {
    response_values
        .iter()
        .filter_map(|v| {
            if let Value::Text(s) = v {
                Some(s.as_str())
            } else {
                None
            }
        })
        .collect()
}

#[inline]
pub fn find_key_agreement_response(
    response_pairs: &[(Value, Value)],
) -> core::result::Result<&Value, SoloError> {
    find_cbor_response_by_key(response_pairs, 0x01)
        .ok_or_else(|| SoloError::DeviceError("keyAgreement (0x01) missing in response".into()))
}

/// Extract a byte-valued coordinate from a COSE key map by its integer key.
#[inline]
pub fn extract_cose_coord(cose_pairs: &[(Value, Value)], key: i64) -> Result<Vec<u8>> {
    cose_pairs
        .iter()
        .find_map(|(k, v)| {
            if let Value::Integer(i) = k {
                let ki: i64 = (*i).try_into().ok()?;
                if ki == key {
                    if let Value::Bytes(b) = v {
                        return Some(b.clone());
                    }
                }
            }
            None
        })
        .ok_or_else(|| SoloError::DeviceError(format!("COSE key missing coordinate {}", key)))
}

/// Perform CTAP2 getKeyAgreement (0x06, subcommand 0x02) to get the device's public key.
pub fn get_key_agreement(hid: &SoloHid) -> Result<p256::PublicKey> {
    let get_ka_cbor = create_key_agreement_cbor();
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

    let key_agreement = find_key_agreement_response(&resp_pairs)?;
    let cose_pairs = match key_agreement {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "keyAgreement is not a CBOR map".into(),
            ))
        }
    };

    let dev_x = extract_cose_coord(cose_pairs, -2)?;
    let dev_y = extract_cose_coord(cose_pairs, -3)?;
    if dev_x.len() != 32 || dev_y.len() != 32 {
        return Err(SoloError::DeviceError(
            "Device COSE key coordinates are not 32 bytes".into(),
        ));
    }

    let mut uncompressed = vec![0x04u8];
    uncompressed.extend_from_slice(&dev_x);
    uncompressed.extend_from_slice(&dev_y);
    p256::PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|e| SoloError::DeviceError(format!("Invalid device public key: {}", e)))
}

/// Represents an established shared secret with a CTAP2 device.
pub struct ClientPinSession {
    shared_secret: [u8; 32],
    pub ephemeral_pub_key: Value,
}

impl ClientPinSession {
    /// Establish a session by performing ECDH with the device's public key.
    pub fn new(dev_pub_key: &p256::PublicKey) -> Self {
        let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
        let ephemeral_pub = p256::PublicKey::from(&ephemeral_secret);
        let ephemeral_point = EncodedPoint::from(&ephemeral_pub);

        let shared_secret_point = ephemeral_secret.diffie_hellman(dev_pub_key);
        let shared_secret: [u8; 32] = Sha256::digest(shared_secret_point.raw_secret_bytes()).into();

        // Wrap ephemeral public key in COSE_Key format for CTAP2
        let ephemeral_pub_key = Value::Map(vec![
            (Value::Integer(1u64.into()), Value::Integer(2u64.into())), // kty: EC2
            (Value::Integer(3u64.into()), Value::Integer((-7i64).into())), // alg: ES256
            (Value::Integer((-1i64).into()), Value::Integer(1u64.into())), // crv: P-256
            (
                Value::Integer((-2i64).into()),
                Value::Bytes(ephemeral_point.x().unwrap().to_vec()),
            ),
            (
                Value::Integer((-3i64).into()),
                Value::Bytes(ephemeral_point.y().unwrap().to_vec()),
            ),
        ]);

        Self {
            shared_secret,
            ephemeral_pub_key,
        }
    }

    /// Encrypt a PIN for setPin or changePin.
    pub fn encrypt_pin(&self, pin: &str) -> Result<Vec<u8>> {
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let pin_bytes = pin.as_bytes();
        let mut padded_pin = [0u8; 64];
        let copy_len = pin_bytes.len().min(64);
        padded_pin[..copy_len].copy_from_slice(&pin_bytes[..copy_len]);

        let mut encrypted = [0u8; 64];
        let iv = [0u8; 16];
        Aes256CbcEnc::new(&self.shared_secret.into(), &iv.into()).encrypt_blocks(unsafe {
            std::slice::from_raw_parts_mut(encrypted.as_mut_ptr() as *mut aes::Block, 4)
        });

        Ok(encrypted.to_vec())
    }

    /// Compute pinUvAuthParam for a message.
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;
        let mut hmac = HmacSha256::new_from_slice(&self.shared_secret).unwrap();
        hmac.update(message);
        hmac.finalize().into_bytes()[..16].to_vec()
    }

    /// Encrypt the PIN hash for getPinToken.
    pub fn encrypt_pin_hash(&self, pin: &str) -> Result<[u8; 16]> {
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        let pin_hash_full = Sha256::digest(pin.as_bytes());
        let pin_hash: [u8; 16] = pin_hash_full[..16].try_into().unwrap();

        let mut pin_hash_enc = pin_hash;
        let iv = [0u8; 16];
        Aes256CbcEnc::new(&self.shared_secret.into(), &iv.into()).encrypt_blocks(unsafe {
            std::slice::from_raw_parts_mut(&mut pin_hash_enc as *mut _ as *mut aes::Block, 1)
        });

        Ok(pin_hash_enc)
    }

    /// Decrypt a PIN token from the device.
    pub fn decrypt_pin_token(&self, pin_token_enc: &[u8]) -> Result<Vec<u8>> {
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

        if pin_token_enc.is_empty() || pin_token_enc.len() % 16 != 0 {
            return Err(SoloError::DeviceError(format!(
                "pinTokenEnc has unexpected length: {}",
                pin_token_enc.len()
            )));
        }

        let mut pin_token = pin_token_enc.to_vec();
        let iv = [0u8; 16];
        let n_blocks = pin_token.len() / 16;

        Aes256CbcDec::new(&self.shared_secret.into(), &iv.into()).decrypt_blocks(unsafe {
            std::slice::from_raw_parts_mut(pin_token.as_mut_ptr() as *mut aes::Block, n_blocks)
        });

        Ok(pin_token)
    }
}
