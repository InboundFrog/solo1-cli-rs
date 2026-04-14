use ciborium::value::Value;

use crate::error::{Result, SoloError};

/// Extract a CBOR map's key-value pairs, or return an error with context.
pub fn expect_map(v: Value, ctx: &str) -> Result<Vec<(Value, Value)>> {
    match v {
        Value::Map(pairs) => Ok(pairs),
        _ => Err(SoloError::ProtocolError(format!(
            "{}: expected a CBOR map",
            ctx
        ))),
    }
}

/// Find a value in a CTAP2 integer-keyed map by key number.
///
/// Matches keys stored as either signed or unsigned `Value::Integer` whose
/// numeric value equals `key` when interpreted as `i64`.
pub fn find_int_key(pairs: &[(Value, Value)], key: i64) -> Option<&Value> {
    pairs.iter().find_map(|(k, v)| {
        if let Value::Integer(i) = k {
            let ki: i64 = (*i).try_into().ok()?;
            if ki == key {
                return Some(v);
            }
        }
        None
    })
}

/// Require a value by integer key; error with context if missing.
pub fn require_int_key<'a>(
    pairs: &'a [(Value, Value)],
    key: i64,
    ctx: &str,
) -> Result<&'a Value> {
    find_int_key(pairs, key).ok_or_else(|| {
        SoloError::ProtocolError(format!("{}: key {} missing in CBOR map", ctx, key))
    })
}

/// Extract bytes from a required integer-keyed entry.
///
/// Returns `Err` if the key is absent or if its value is not `Value::Bytes`.
pub fn require_bytes(pairs: &[(Value, Value)], key: i64, ctx: &str) -> Result<Vec<u8>> {
    match require_int_key(pairs, key, ctx)? {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(SoloError::ProtocolError(format!(
            "{}: key {} is not bytes",
            ctx, key
        ))),
    }
}

/// Build a CBOR map from `(i64, Value)` pairs.
pub fn int_map(entries: impl IntoIterator<Item = (i64, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k.into()), v))
            .collect(),
    )
}

/// Wrap a byte vec as a `Value::Bytes`.
pub fn cbor_bytes(b: impl Into<Vec<u8>>) -> Value {
    Value::Bytes(b.into())
}

/// Wrap an `i64` as a `Value::Integer`.
pub fn cbor_int(i: i64) -> Value {
    Value::Integer(i.into())
}

/// Wrap a string as a `Value::Text`.
pub fn cbor_text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pairs() -> Vec<(Value, Value)> {
        vec![
            (Value::Integer(1i64.into()), Value::Text("one".into())),
            (Value::Integer(2i64.into()), Value::Bytes(vec![0xAB])),
            (Value::Integer((-1i64).into()), Value::Integer(42i64.into())),
        ]
    }

    #[test]
    fn test_expect_map_ok() {
        let v = Value::Map(vec![]);
        assert!(expect_map(v, "test").is_ok());
    }

    #[test]
    fn test_expect_map_err() {
        let v = Value::Text("not a map".into());
        assert!(expect_map(v, "test").is_err());
    }

    #[test]
    fn test_find_int_key() {
        let pairs = sample_pairs();
        assert_eq!(find_int_key(&pairs, 1), Some(&Value::Text("one".into())));
        assert_eq!(find_int_key(&pairs, 2), Some(&Value::Bytes(vec![0xAB])));
        assert!(find_int_key(&pairs, -1).is_some());
        assert!(find_int_key(&pairs, 99).is_none());
    }

    #[test]
    fn test_require_int_key_ok() {
        let pairs = sample_pairs();
        assert!(require_int_key(&pairs, 1, "ctx").is_ok());
    }

    #[test]
    fn test_require_int_key_err() {
        let pairs = sample_pairs();
        let err = require_int_key(&pairs, 99, "ctx").unwrap_err();
        assert!(err.to_string().contains("99"));
        assert!(err.to_string().contains("ctx"));
    }

    #[test]
    fn test_require_bytes_ok() {
        let pairs = sample_pairs();
        assert_eq!(require_bytes(&pairs, 2, "ctx").unwrap(), vec![0xAB]);
    }

    #[test]
    fn test_require_bytes_wrong_type() {
        let pairs = sample_pairs();
        // key 1 is Text, not Bytes
        assert!(require_bytes(&pairs, 1, "ctx").is_err());
    }

    #[test]
    fn test_int_map_roundtrip() {
        let m = int_map([(1, cbor_int(99)), (2, cbor_bytes(vec![0xFF]))]);
        match m {
            Value::Map(pairs) => {
                assert_eq!(pairs.len(), 2);
                assert_eq!(pairs[0].0, Value::Integer(1i64.into()));
                assert_eq!(pairs[1].0, Value::Integer(2i64.into()));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn test_cbor_helpers() {
        assert_eq!(cbor_int(42), Value::Integer(42i64.into()));
        assert_eq!(cbor_bytes(vec![1u8, 2, 3]), Value::Bytes(vec![1, 2, 3]));
        assert_eq!(cbor_text("hi"), Value::Text("hi".into()));
    }
}
