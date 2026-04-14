---
name: HMAC unwrap in ctap2.rs
description: ClientPinSession::authenticate calls Hmac::new_from_slice().unwrap() which will panic if the shared secret is not exactly 32 bytes
type: project
---

# 0008 — HMAC `unwrap()` in `ctap2.rs`

## Problem

`src/ctap2.rs`, `ClientPinSession::authenticate`:

```rust
pub fn authenticate(&self, message: &[u8]) -> [u8; 16] {
    let mut mac = Hmac::<Sha256>::new_from_slice(&self.shared_secret)
        .unwrap();  // <-- panics if shared_secret length != 32
    mac.update(message);
    mac.finalize().into_bytes()[..16].try_into().unwrap()
}
```

`Hmac::new_from_slice` returns `Result<_, InvalidLength>` which is `Err` if the key length is zero or otherwise invalid. The `shared_secret` is a SHA-256 digest (always 32 bytes), so in practice this never panics — but:

1. It sets a bad precedent: `unwrap()` in security-critical code signals "I didn't think about this"
2. A future refactor that changes how `shared_secret` is stored (e.g., truncation, wrong source) would cause a silent panic rather than a propagated error
3. The second `.unwrap()` on the `try_into()` would panic if the HMAC output were shorter than 16 bytes (it won't be for SHA-256, but the invariant is implicit)

## Why It Needs Changing

- Panics in security-critical code are never acceptable; they can be turned into DoS conditions
- Error propagation via `?` is idiomatic Rust and makes the failure mode explicit

## Proposed Change

Change the signature to return `Result<[u8; 16]>` and propagate the error:

```rust
pub fn authenticate(&self, message: &[u8]) -> Result<[u8; 16]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(&self.shared_secret)
        .map_err(|_| SoloError::CryptoError("HMAC key length invalid".into()))?;
    mac.update(message);
    let result: [u8; 16] = mac.finalize().into_bytes()[..16]
        .try_into()
        .map_err(|_| SoloError::CryptoError("HMAC output truncation failed".into()))?;
    Ok(result)
}
```

Update all call sites to propagate with `?`.

### Call Sites

- `src/commands/key/pin.rs`: `cmd_set_pin`, `cmd_change_pin`
- `src/commands/key/verify.rs`: `cmd_verify`
- `src/commands/key/credential.rs`: `cmd_credential_ls`, `cmd_credential_rm`
- `src/commands/key/fido2.rs`: `cmd_challenge_response`

### Steps

1. Update `ClientPinSession::authenticate` signature in `src/ctap2.rs`
2. Add `?` at each call site
3. Verify `cargo test` passes

## Security Impact

No change to the cryptographic operation. This is a code correctness improvement that eliminates a latent panic.

## Relevant Code

- `src/ctap2.rs`: `ClientPinSession::authenticate` (~line 314)
- All command files that call `.authenticate()`
