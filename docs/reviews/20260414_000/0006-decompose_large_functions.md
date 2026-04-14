---
name: Decompose Large Functions
description: Several functions exceed 150 lines and mix multiple levels of abstraction — decompose into focused helpers
type: project
---

# 0006 — Decompose Large Functions

## Problem

Several functions are far too large to read, test, or reason about in isolation:

| Function | File | Approximate Lines | Issues |
|---|---|---|---|
| `cmd_credential_ls` | `credential.rs` | ~280 lines | 3 nested loops, inline CBOR, protocol + display mixed |
| `cmd_challenge_response` | `fido2.rs` | ~230 lines | Crypto setup, CBOR build, send/recv, response parse all inline |
| `merge_hex_files` | `firmware.rs` | ~150 lines | Multiple concerns: parse, patch auth word, patch attestation, write |
| `cmd_verify` | `verify.rs` | ~160 lines | PIN acquisition, credential creation, cert extraction, fingerprint check |

The CTAP2 spec is already complex; embedding all protocol handling inline in these functions makes it very difficult to understand where one protocol step ends and another begins.

## Why It Needs Changing

- Long functions with multiple abstraction levels violate the Single Responsibility Principle
- Harder to write unit tests for individual steps (e.g., test auth-word patching without running full mergehex)
- Harder to reuse sub-steps (e.g., the credential enumeration inner loop in `cmd_credential_ls`)
- Deeper indentation (5+ levels in `cmd_credential_ls`) makes it hard to track control flow

## Proposed Changes

### `cmd_credential_ls` (~280 lines → 4 functions)

```rust
// Extract RP enumeration into a helper
fn enumerate_rps(hid: &mut SoloHid, pin_token: &[u8]) -> Result<Vec<RpInfo>>

// Extract credential enumeration for a single RP
fn enumerate_credentials_for_rp(hid: &mut SoloHid, pin_token: &[u8], rp_id_hash: &[u8])
    -> Result<Vec<CredentialInfo>>

// Display formatting helper
fn print_credential(rp_id: &str, cred: &CredentialInfo)
```

### `cmd_challenge_response` (~230 lines → 3 functions)

```rust
// Separate ECDH setup and salt encryption
fn prepare_hmac_secret_input(
    dev_pub_key: &[u8],
    challenge: &[u8]
) -> Result<(Vec<u8>, Vec<u8>, [u8; 16])>  // (platform_pub_key_cbor, salt_enc, salt_auth)

// Separate response decryption
fn decrypt_hmac_secret_output(
    shared_secret: &[u8],
    encrypted_output: &[u8]
) -> Result<Vec<u8>>
```

### `merge_hex_files` (~150 lines → 3 functions)

```rust
// Extract attestation patching
fn patch_attestation(binary: &mut Vec<u8>, base_addr: u32, key: &[u8], cert: &[u8]) -> Result<()>

// Extract auth-word patching
fn patch_auth_word(binary: &mut Vec<u8>, base_addr: u32) -> Result<()>
```

### `cmd_verify` (~160 lines → 2 functions)

```rust
// Extract certificate extraction from makeCredential response
fn extract_attestation_cert(response: &[u8]) -> Result<Vec<u8>>
```

### Steps

1. Decompose `cmd_credential_ls` — this is highest priority
2. Decompose `cmd_challenge_response`
3. Decompose `merge_hex_files` (also enables better unit tests for each patching step)
4. Decompose `cmd_verify`
5. Ensure `cargo test` passes after each decomposition

## Notes

Each decomposition can be done in a separate commit. The helper functions should be private (`fn`, not `pub fn`) unless they are genuinely reusable across modules.

## Relevant Code

- `src/commands/key/credential.rs`: `cmd_credential_ls` (~lines 100–380)
- `src/commands/key/fido2.rs`: `cmd_challenge_response` (~lines 260–490)
- `src/firmware.rs`: `merge_hex_files` (~lines 350–500)
- `src/commands/key/verify.rs`: `cmd_verify` (~lines 1–160)
