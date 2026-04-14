use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use ciborium::value::Value;
use hmac::{Hmac, KeyInit as _, Mac as _};
use p256::ecdh::EphemeralSecret;
use p256::EncodedPoint;
use rand::rngs::OsRng;
use sha2::{Digest as _, Sha256};

use crate::device::{SoloHid, CTAPHID_CBOR};
use crate::error::{Result, SoloError};

/// All-zero IV as mandated by the CTAP2 specification for clientPIN AES-256-CBC operations
/// (PIN/UV Auth Protocol One, §6.5.4).
///
/// This is safe because the AES key is derived from a fresh ephemeral ECDH exchange for each
/// session and is never reused across sessions, so the zero IV does not leak information about
/// the plaintext.
///
/// Reference: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto1>
pub const CTAP2_AES_IV: [u8; 16] = [0u8; 16];

/// Query CTAP2 getInfo (0x04) and return whether a PIN has been set on the device.
pub fn get_info_client_pin_set(hid: &SoloHid) -> Result<bool> {
    let get_info_req = vec![0x04u8];
    let info_resp = hid.send_recv(CTAPHID_CBOR, &get_info_req)?;
    let pairs = parse_cbor_map_response(&info_resp, "getInfo")?;
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

/// Validate a raw CTAP2 response: checks it is non-empty and the status byte is 0x00.
/// Returns `Ok(())` on success, `Err` with a context-tagged message otherwise.
pub fn check_ctap_status(response: &[u8], context: &str) -> Result<()> {
    if response.is_empty() {
        return Err(SoloError::DeviceError(format!(
            "Empty response from {}",
            context
        )));
    }
    if response[0] != 0x00 {
        return Err(SoloError::DeviceError(format!(
            "{} returned CTAP error 0x{:02X}",
            context, response[0]
        )));
    }
    Ok(())
}

/// Parse a raw CTAP2 response as a CBOR map: validates status, parses CBOR, checks it is a map.
/// Returns the map pairs on success.
pub fn parse_cbor_map_response(
    response: &[u8],
    context: &str,
) -> Result<Vec<(Value, Value)>> {
    check_ctap_status(response, context)?;
    let val: Value = ciborium::de::from_reader(&response[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;
    match val {
        Value::Map(p) => Ok(p),
        _ => Err(SoloError::DeviceError(format!(
            "{} response is not a CBOR map",
            context
        ))),
    }
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

    let resp_pairs = parse_cbor_map_response(&response, "getKeyAgreement")?;

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

/// Prompt the user for a PIN, validate it is non-empty, and acquire a PIN token from the device.
///
/// This is the single place to add retry logic, PIN caching, or minimum-length enforcement.
pub fn prompt_and_get_pin_token(hid: &SoloHid) -> Result<Vec<u8>> {
    let pin = rpassword::prompt_password("Enter PIN: ")
        .map_err(|e| SoloError::IoError(e))?;
    if pin.is_empty() {
        return Err(SoloError::ProtocolError("PIN is required".into()));
    }
    get_pin_token(hid, &pin)
}

/// Perform the full CTAP2 clientPIN getPINToken flow and return the decrypted PIN token.
///
/// Steps:
///   1. getKeyAgreement (subcommand 0x02) → device P-256 public key
///   2. Generate ephemeral P-256 keypair, ECDH → shared_secret
///   3. pinHashEnc = AES-256-CBC(shared_secret, IV=0, SHA-256(pin)[0..16])
///   4. getPINToken (subcommand 0x05) → decrypt response → pin token bytes
pub fn get_pin_token(hid: &SoloHid, pin: &str) -> Result<Vec<u8>> {
    let dev_pub_key = get_key_agreement(hid)?;
    let session = ClientPinSession::new(&dev_pub_key);
    let pin_hash_enc = session.encrypt_pin_hash(pin)?;

    let get_pin_token_cbor = Value::Map(vec![
        (Value::Integer(0x01u64.into()), Value::Integer(1u64.into())), // pinUvAuthProtocol = 1
        (Value::Integer(0x02u64.into()), Value::Integer(5u64.into())), // subCommand = getPINToken
        (Value::Integer(0x03u64.into()), session.ephemeral_pub_key.clone()), // keyAgreement
        (
            Value::Integer(0x06u64.into()),
            Value::Bytes(pin_hash_enc.to_vec()),
        ), // pinHashEnc
    ]);

    let mut gpt_req = vec![0x06u8]; // authenticatorClientPIN
    ciborium::ser::into_writer(&get_pin_token_cbor, &mut gpt_req)
        .map_err(|e| SoloError::DeviceError(format!("CBOR encode error: {}", e)))?;

    let gpt_resp = hid.send_recv(CTAPHID_CBOR, &gpt_req)?;
    if gpt_resp.is_empty() {
        return Err(SoloError::DeviceError(
            "Empty response from getPINToken".into(),
        ));
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
            "getPINToken returned CTAP error 0x{:02X}{}",
            code, hint
        )));
    }

    let gpt_val: Value = ciborium::de::from_reader(&gpt_resp[1..])
        .map_err(|e| SoloError::DeviceError(format!("CBOR parse error: {}", e)))?;
    let gpt_pairs = match gpt_val {
        Value::Map(p) => p,
        _ => {
            return Err(SoloError::DeviceError(
                "getPINToken response is not a CBOR map".into(),
            ))
        }
    };

    let pin_token_enc = match find_cbor_response_by_key(&gpt_pairs, 0x02) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => {
            return Err(SoloError::DeviceError(
                "pinTokenEnc (0x02) missing from getPINToken response".into(),
            ))
        }
    };

    session.decrypt_pin_token(&pin_token_enc)
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
        let mut blocks = [aes::Block::default(); 4];
        for (i, chunk) in padded_pin.chunks_exact(16).enumerate() {
            blocks[i] = (*chunk).try_into().unwrap();
        }
        
        Aes256CbcEnc::new(&self.shared_secret.into(), &CTAP2_AES_IV.into()).encrypt_blocks(&mut blocks);
        
        for (i, block) in blocks.iter().enumerate() {
            encrypted[i*16..(i+1)*16].copy_from_slice(block.as_slice());
        }

        Ok(encrypted.to_vec())
    }

    /// Compute pinUvAuthParam for a message.
    pub fn authenticate(&self, message: &[u8]) -> Result<Vec<u8>> {
        type HmacSha256 = Hmac<Sha256>;
        let mut hmac = HmacSha256::new_from_slice(&self.shared_secret)
            .map_err(|_| SoloError::CryptoError("HMAC key length invalid".into()))?;
        hmac.update(message);
        let full = hmac.finalize().into_bytes();
        let truncated: Vec<u8> = full[..16]
            .try_into()
            .map_err(|_| SoloError::CryptoError("HMAC output truncation failed".into()))?;
        Ok(truncated)
    }

    /// Encrypt the PIN hash for getPinToken.
    pub fn encrypt_pin_hash(&self, pin: &str) -> Result<[u8; 16]> {
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        let pin_hash_full = Sha256::digest(pin.as_bytes());
        let pin_hash: [u8; 16] = pin_hash_full[..16].try_into().unwrap();

        let mut pin_hash_enc = pin_hash;
        let mut block = aes::Block::from(pin_hash_enc);
        Aes256CbcEnc::new(&self.shared_secret.into(), &CTAP2_AES_IV.into()).encrypt_blocks(std::slice::from_mut(&mut block));
        pin_hash_enc.copy_from_slice(block.as_slice());

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
        let n_blocks = pin_token.len() / 16;
        let mut blocks = vec![aes::Block::default(); n_blocks];
        for (i, chunk) in pin_token.chunks_exact(16).enumerate() {
            blocks[i] = (*chunk).try_into().unwrap();
        }

        Aes256CbcDec::new(&self.shared_secret.into(), &CTAP2_AES_IV.into()).decrypt_blocks(&mut blocks);

        for (i, block) in blocks.iter().enumerate() {
            pin_token[i * 16..(i + 1) * 16].copy_from_slice(block.as_slice());
        }

        Ok(pin_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    #[test]
    fn test_check_ctap_status() {
        assert!(check_ctap_status(&[0x00, 0x01, 0x02], "test").is_ok());
        let err = check_ctap_status(&[0x01, 0x01, 0x02], "test").unwrap_err();
        assert!(err.to_string().contains("returned CTAP error 0x01"));
        let err_empty = check_ctap_status(&[], "test").unwrap_err();
        assert!(err_empty.to_string().contains("Empty response"));
    }

    #[test]
    fn test_find_cbor_response_by_key() {
        let pairs = vec![
            (Value::Integer(1u64.into()), Value::Text("one".into())),
            (Value::Integer(2u64.into()), Value::Bytes(vec![0x02])),
        ];
        assert_eq!(
            find_cbor_response_by_key(&pairs, 1),
            Some(&Value::Text("one".into()))
        );
        assert_eq!(
            find_cbor_response_by_key(&pairs, 2),
            Some(&Value::Bytes(vec![0x02]))
        );
        assert_eq!(find_cbor_response_by_key(&pairs, 3), None);
    }

    #[test]
    fn test_extract_cbor_text_responses() {
        let values = vec![
            Value::Text("first".into()),
            Value::Integer(123u64.into()),
            Value::Text("second".into()),
        ];
        let texts = extract_cbor_text_responses(&values);
        assert_eq!(texts, vec!["first", "second"]);
    }

    #[test]
    fn test_client_pin_session_crypto_roundtrip() {
        // We need a dummy public key to initialize the session.
        // P-256 public key is 65 bytes (0x04 || X || Y)
        let secret = p256::ecdh::EphemeralSecret::random(&mut OsRng);
        let pub_key = p256::PublicKey::from(&secret);

        let session = ClientPinSession::new(&pub_key);

        // Test encryption/decryption of a token (multi-block)
        let _encrypted = session.encrypt_pin_hash("123456").unwrap(); // 16 bytes
        // encrypt_pin_hash is one-way in practice (we don't have a decrypt_pin_hash)
        // but we can test decrypt_pin_token with any encrypted data.
        
        // Let's test encrypt_pin (64 bytes)
        let pin = "123456";
        let enc_pin = session.encrypt_pin(pin).unwrap();
        assert_eq!(enc_pin.len(), 64);
        
        let dec_pin = session.decrypt_pin_token(&enc_pin).unwrap();
        assert_eq!(dec_pin.len(), 64);
        assert_eq!(&dec_pin[..pin.len()], pin.as_bytes());
        assert_eq!(&dec_pin[pin.len()..], &[0u8; 64-6][..]);

        // Test authenticate (HMAC-SHA256 truncated to 16 bytes)
        let msg = b"hello world";
        let auth1 = session.authenticate(msg).unwrap();
        let auth2 = session.authenticate(msg).unwrap();
        assert_eq!(auth1, auth2);
        assert_eq!(auth1.len(), 16);
    }

    #[test]
    fn test_extract_cose_coord() {
        let cose_pairs = vec![
            (Value::Integer((-2i64).into()), Value::Bytes(vec![0xAA; 32])),
            (Value::Integer((-3i64).into()), Value::Bytes(vec![0xBB; 32])),
        ];
        let x = extract_cose_coord(&cose_pairs, -2).unwrap();
        assert_eq!(x, vec![0xAA; 32]);
        let y = extract_cose_coord(&cose_pairs, -3).unwrap();
        assert_eq!(y, vec![0xBB; 32]);
        assert!(extract_cose_coord(&cose_pairs, -1).is_err());
    }
}
