---
name: Duplicate PIN Token Acquisition
description: Interactive PIN prompting and PIN token acquisition is copy-pasted verbatim in three command files
type: project
---

# 0003 — Duplicate PIN Token Acquisition

## Problem

Three commands all prompt the user for a PIN, validate it, derive a PIN token from the device, and then use the token for a subsequent operation. The logic is copy-pasted:

### Appears in:

**`src/commands/key/verify.rs`** (~lines 20–38):
```rust
let pin = rpassword::prompt_password("Enter PIN: ")?;
if pin.is_empty() { return Err(SoloError::ProtocolError("PIN required".into())); }
let pin_token = ctap2::get_pin_token(hid, &pin)?;
```

**`src/commands/key/credential.rs` (`cmd_credential_ls`)** (~lines 135–144):
```rust
let pin = rpassword::prompt_password("Enter PIN: ")?;
if pin.is_empty() { return Err(...); }
let pin_token = ctap2::get_pin_token(hid, &pin)?;
```

**`src/commands/key/credential.rs` (`cmd_credential_rm`)** (~lines 456–465):
```rust
let pin = rpassword::prompt_password("Enter PIN: ")?;
if pin.is_empty() { return Err(...); }
let pin_token = ctap2::get_pin_token(hid, &pin)?;
```

The three copies differ only slightly in error message strings, making future changes (e.g., adding retry logic, PIN caching, or minimum-length enforcement) require edits in all three places.

## Why It Needs Changing

- DRY violation — any change (retry logic, better error message, PIN length enforcement) must be applied in three places
- Currently the error messages are slightly inconsistent across the three usages
- Makes it harder to add PIN caching within a session

## Proposed Change

Add a helper function in `src/ctap2.rs` (or a new `src/commands/key/common.rs`):

```rust
/// Prompt the user for a PIN, validate it is non-empty, and acquire
/// a PIN token from the device.
pub fn prompt_and_get_pin_token(hid: &mut SoloHid) -> Result<Vec<u8>> {
    let pin = rpassword::prompt_password("Enter PIN: ")
        .map_err(|e| SoloError::IoError(e))?;
    if pin.is_empty() {
        return Err(SoloError::ProtocolError("PIN is required".into()));
    }
    get_pin_token(hid, &pin)
}
```

Then replace all three call sites:
```rust
let pin_token = ctap2::prompt_and_get_pin_token(hid)?;
```

### Steps

1. Add `prompt_and_get_pin_token` to `src/ctap2.rs`
2. Replace the three duplicate call sites
3. Verify `cargo test` passes

## Relevant Code

- `src/commands/key/verify.rs`: ~lines 20–38
- `src/commands/key/credential.rs`: ~lines 135–144, ~lines 456–465
- `src/ctap2.rs`: `get_pin_token` function

## Notes

If PIN caching across commands within a session is ever desired, this is the right single place to implement it.
