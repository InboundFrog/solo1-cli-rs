---
name: CBOR Helpers Module
description: CBOR map construction and value extraction is repeated verbatim across 6+ command files — extract into a shared helpers module
type: project
---

# 0002 — CBOR Helpers Module

## Problem

Every command that speaks CTAP2 manually constructs `ciborium::Value::Map(vec![...])` inline and manually extracts values by scanning integer-keyed pairs. This pattern appears in:

- `src/commands/key/fido2.rs` (makeCredential, getAssertion — twice each)
- `src/commands/key/pin.rs` (setPin, changePin)
- `src/commands/key/verify.rs`
- `src/commands/key/credential.rs` (info, ls, rm — three times)
- `src/ctap2.rs` (get_key_agreement, get_pin_token)

### Repeated extraction pattern (appears ~10 times):

```rust
let pairs = match response_value {
    Value::Map(p) => p,
    _ => return Err(SoloError::ProtocolError("expected map".into())),
};
let foo = pairs.iter().find_map(|(k, v)| {
    if k == &Value::Integer(3.into()) { Some(v.clone()) } else { None }
});
```

### Repeated construction pattern:

```rust
Value::Map(vec![
    (Value::Integer(1.into()), Value::Integer(5.into())),
    (Value::Integer(2.into()), Value::Bytes(data.clone())),
    ...
])
```

## Why It Needs Changing

- Any fix or change to extraction logic must be made in 6+ places
- The verbosity makes the actual CTAP2 semantics hard to read
- Bugs can be silently inconsistent across commands (e.g., error messages differ, key types differ)

## Proposed Change

Add `src/cbor.rs` (or `src/ctap2/cbor.rs` if ctap2 is modularised) with:

```rust
/// Extract a CTAP2 integer-keyed CBOR map as a Vec of pairs, or error.
pub fn expect_map(v: Value, ctx: &str) -> Result<Vec<(Value, Value)>>

/// Find a value in a CTAP2 response map by integer key.
pub fn find_int_key(pairs: &[(Value, Value)], key: i64) -> Option<&Value>

/// Require a value by integer key; error with context if missing.
pub fn require_int_key(pairs: &[(Value, Value)], key: i64, ctx: &str) -> Result<&Value>

/// Convenience: extract bytes value from a required key.
pub fn require_bytes(pairs: &[(Value, Value)], key: i64, ctx: &str) -> Result<Vec<u8>>

/// Build a CBOR integer-keyed map from (i64, Value) pairs.
pub fn int_map(entries: impl IntoIterator<Item = (i64, Value)>) -> Value

/// Convenience: Value::Bytes wrapper
pub fn cbor_bytes(b: impl Into<Vec<u8>>) -> Value

/// Convenience: Value::Integer wrapper
pub fn cbor_int(i: i64) -> Value

/// Convenience: Value::Text wrapper
pub fn cbor_text(s: impl Into<String>) -> Value
```

### Steps

1. Create `src/cbor.rs` with the above helpers
2. Add `pub mod cbor;` to `src/lib.rs`
3. Replace each manual extraction in fido2.rs, pin.rs, verify.rs, credential.rs, ctap2.rs
4. Replace each manual `Value::Map(vec![...])` construction with `int_map([...])`
5. Verify `cargo test` passes

## Relevant Code

- `src/commands/key/fido2.rs`: lines ~50–120, ~350–420
- `src/commands/key/pin.rs`: lines ~40–130
- `src/commands/key/verify.rs`: lines ~60–130
- `src/commands/key/credential.rs`: lines ~40–100, ~140–300, ~390–500
- `src/ctap2.rs`: lines ~100–200

## References

- [ciborium crate docs](https://docs.rs/ciborium)
- [CTAP2 CBOR encoding §6](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#ctap2-canonical-cbor-encoding-form)
