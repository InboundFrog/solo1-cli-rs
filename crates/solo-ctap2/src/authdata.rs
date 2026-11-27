//! Parser for the authenticator data returned by makeCredential and
//! getAssertion.
//!
//! Layout (`WebAuthn`, authenticator data):
//!
//! ```text
//! [0..32]   rpIdHash
//! [32]      flags
//! [33..37]  signCount (u32, big-endian)
//! [37..53]  AAGUID                 (only if AT is set)
//! [53..55]  credential id length   (only if AT is set, u16, big-endian)
//! [55..]    credential id, then the COSE public key (only if AT is set)
//! ```
//!
//! Only the fields that callers need are parsed.

use crate::{Error, Result};

/// Flag bit: user present.
pub const FLAG_UP: u8 = 0x01;
/// Flag bit: user verified.
pub const FLAG_UV: u8 = 0x04;
/// Flag bit: attested credential data is present.
pub const FLAG_AT: u8 = 0x40;
/// Flag bit: extension data is present.
pub const FLAG_ED: u8 = 0x80;

/// Size of the fixed header: rpIdHash, flags and signCount.
const HEADER_LEN: usize = 37;
/// Size of the AAGUID in the attested credential data.
const AAGUID_LEN: usize = 16;
/// Size of the credential id length field.
const ID_LEN_FIELD: usize = 2;

/// A parsed view of authenticator data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorData<'a> {
    /// The flags byte.
    pub flags: u8,
    /// The credential id, if the AT flag is set.
    pub credential_id: Option<&'a [u8]>,
    /// Everything after the fixed header, or after the credential id when the
    /// AT flag is set. With AT set, this starts with the COSE public key.
    pub trailing: &'a [u8],
}

impl<'a> AuthenticatorData<'a> {
    /// Parse authenticator data.
    ///
    /// # Errors
    /// Returns an error if the input is shorter than the fixed header, or if
    /// the AT flag is set and the attested credential data is cut short or
    /// its credential id length is larger than the remaining bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let too_short = || Error::MalformedResponse("authData too short".into());
        let mut rest = data.get(HEADER_LEN..).ok_or_else(too_short)?;
        let flags = *data.get(32).ok_or_else(too_short)?;

        let mut credential_id = None;
        if flags & FLAG_AT != 0 {
            let id_start = AAGUID_LEN.saturating_add(ID_LEN_FIELD);
            let len_bytes: [u8; 2] = rest
                .get(AAGUID_LEN..id_start)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| Error::MalformedResponse("authData too short to read credentialIdLength".into()))?;
            let id_len = usize::from(u16::from_be_bytes(len_bytes));
            let id_end = id_start.saturating_add(id_len);
            let id = rest.get(id_start..id_end).ok_or_else(|| {
                Error::MalformedResponse(format!(
                    "authData too short: need {id_len} bytes for credential ID, have {}",
                    rest.len().saturating_sub(id_start)
                ))
            })?;
            credential_id = Some(id);
            rest = rest.get(id_end..).unwrap_or_default();
        }

        Ok(Self {
            flags,
            credential_id,
            trailing: rest,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    fn header(flags: u8) -> Vec<u8> {
        let mut v = vec![0xAA; 32];
        v.push(flags);
        v.extend_from_slice(&[0, 0, 0, 7]);
        v
    }

    fn with_credential(id: &[u8]) -> Vec<u8> {
        let mut v = header(FLAG_AT | FLAG_UP);
        v.extend_from_slice(&[0; 16]);
        v.extend_from_slice(&u16::try_from(id.len()).unwrap().to_be_bytes());
        v.extend_from_slice(id);
        v
    }

    #[test]
    fn parses_minimal_header() {
        let data = header(FLAG_UP | FLAG_ED);
        let ad = AuthenticatorData::parse(&data).unwrap();
        assert_eq!(ad.flags, FLAG_UP | FLAG_ED);
        assert_eq!(ad.credential_id, None);
        assert_eq!(ad.trailing, []);
    }

    #[test]
    fn no_attested_data_keeps_trailing_bytes() {
        let mut data = header(FLAG_ED);
        data.extend_from_slice(&[0xA0]);
        let ad = AuthenticatorData::parse(&data).unwrap();
        assert_eq!(ad.trailing, &[0xA0]);
    }

    #[test]
    fn parses_attested_credential_data() {
        let mut data = with_credential(&[1, 2, 3]);
        data.extend_from_slice(&[0xA5, 0xA6]);
        let ad = AuthenticatorData::parse(&data).unwrap();
        assert_eq!(ad.credential_id, Some(&[1u8, 2, 3][..]));
        assert_eq!(ad.trailing, &[0xA5, 0xA6]);
    }

    #[test]
    fn short_input_is_an_error_at_each_boundary() {
        let plain = header(0);
        for len in [0, 32, 33, 36] {
            assert!(AuthenticatorData::parse(&plain[..len]).is_err(), "len {len}");
        }
        // AT set: cut inside the AAGUID, inside the length field, and inside the id.
        let data = with_credential(&[1, 2, 3]);
        for len in [37, 45, 53, 54, 55, 57] {
            assert!(AuthenticatorData::parse(&data[..len]).is_err(), "len {len}");
        }
        assert!(AuthenticatorData::parse(&data).is_ok());
    }

    #[test]
    fn credential_id_length_larger_than_rest_is_an_error() {
        let mut data = header(FLAG_AT);
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&0xFFFFu16.to_be_bytes());
        data.extend_from_slice(&[1, 2, 3]);
        assert!(AuthenticatorData::parse(&data).is_err());
    }
}
