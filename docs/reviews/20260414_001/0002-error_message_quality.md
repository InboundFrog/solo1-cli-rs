---
name: Error Message Quality
description: DeviceError(String) is used as a catch-all throughout, producing inconsistent internal-facing messages instead of actionable user guidance
type: project
---

# 0002 — Error Message Quality

## Problem

`SoloError::DeviceError(String)` is used wherever a specific variant does not already exist:

```rust
// Several examples from across the codebase:
SoloError::DeviceError(format!("Invalid credential_id hex: {}", e))
SoloError::DeviceError("makeCredential response missing authData (key 0x02)".into())
SoloError::DeviceError(format!("Invalid device public key: {}", e))
SoloError::DeviceError("authData ED flag not set — no extensions data in response".into())
SoloError::DeviceError(format!("No device with serial {}", sn))
```

And in `main.rs`, every error is printed identically:

```rust
if let Err(e) = result {
    eprintln!("Error: {}", e);
    std::process::exit(1);
}
```

### Issues

1. **All errors look the same to the user.** A hex-decode failure on user-supplied input
   (`"Invalid credential_id hex"`) is formatted identically to an internal protocol error
   (`"authData too short"`). Users cannot tell whether they made a mistake or the device misbehaved.

2. **No actionable guidance.** Errors caused by user mistakes (bad hex, wrong credential ID,
   no key plugged in) do not suggest what to do. `NoSoloFound` is the only variant with a
   helpful message today (it links to udev rules).

3. **`DeviceError` is overloaded.** It covers: hex decode failures, CBOR encode failures, bad
   responses from the device, and missing fields in parsed responses. These are different failure
   categories that may warrant different exit codes or different user-visible text.

4. **No distinction between user error and device error.** A script wrapping this tool has no
   reliable way to distinguish "wrong argument" (fixable by the user) from "device rejected the
   request" (may require a different action).

## Why It Needs Changing

A CLI tool for a security key is the kind of tool people run in enrollment pipelines and automated
scripts. Opaque internal error strings make debugging difficult and undermine trust.

## Proposed Changes

### 1. Add specific error variants for common failure modes

```rust
// Additions to SoloError in error.rs:

#[error("Invalid hex string: {0}")]
InvalidHex(#[from] hex::FromHexError),

#[error("CBOR encode/decode error: {0}")]
CborError(String),

#[error("Authenticator rejected the request (CTAP2 status {code:#04x}): {message}")]
AuthenticatorError { code: u8, message: &'static str },

#[error("Response from device was malformed: {0}")]
MalformedResponse(String),
```

Converting call sites from `DeviceError(format!(...))` to specific variants makes the
distinction clear both to the user and to any code wrapping the binary.

### 2. Map CTAP2 status codes to human-readable messages

`parse_cbor_map_response` in `ctap2.rs` currently formats the status byte as a hex string.
Add a lookup table:

```rust
fn ctap2_status_message(code: u8) -> &'static str {
    match code {
        0x01 => "invalid command",
        0x06 => "PIN invalid",
        0x07 => "PIN blocked",
        0x08 => "PIN auth invalid",
        0x09 => "PIN auth blocked",
        0x0A => "PIN not set",
        0x0B => "PIN required",
        0x26 => "operation denied",
        0x27 => "key store full",
        0x29 => "not allowed",
        0x2F => "credential not found",
        0x30 => "touch required — please touch the key",
        0x36 => "user action timeout",
        _ => "unknown error",
    }
}
```

### 3. Add actionable hints for common user-facing errors

For errors that have obvious remediation, append a hint:

| Error | Hint |
|-------|------|
| `NoSoloFound` | Already has udev link (keep it) |
| `NonUniqueDevice` | "Run `solo1 ls` to see serial numbers, then use `--serial`" |
| `InvalidHex` | "Credential IDs are printed by `make-credential` as hex strings" |
| CTAP2 0x30 (touch required) | "Touch the gold ring on your Solo key" |
| CTAP2 0x07 (PIN blocked) | "PIN is blocked. Factory reset required." |

### Steps

1. Add `InvalidHex`, `CborError`, `AuthenticatorError`, `MalformedResponse` variants to `error.rs`
2. Derive `#[from] hex::FromHexError` for `InvalidHex` (eliminates most manual conversions)
3. Update `parse_cbor_map_response` in `ctap2.rs` to emit `AuthenticatorError` with the status table
4. Update call sites in `fido2.rs`, `credential.rs`, `verify.rs` to use specific variants
5. Verify `cargo test` passes; update any test assertions that match on error strings

## Relevant Code

- `src/error.rs` — `SoloError` enum
- `src/ctap2.rs` — `parse_cbor_map_response`, CTAP2 status byte handling
- `src/commands/key/fido2.rs` — `cmd_challenge_response`, `cmd_make_credential`
- `src/commands/key/credential.rs` — `cmd_credential_ls`, `cmd_credential_rm`
- `src/commands/key/verify.rs` — `cmd_verify`
- `src/main.rs` — error display

## References

- [CTAP2 §6.3 — Status codes](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#error-responses)
- [Rust API Guidelines — Errors](https://rust-lang.github.io/api-guidelines/interoperability.html#error-types-are-meaningful-and-well-behaved-c-good-err)
