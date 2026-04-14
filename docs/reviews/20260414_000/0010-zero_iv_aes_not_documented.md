---
name: Zero AES IV — Missing Documentation
description: AES-256-CBC is used throughout with an all-zero IV; this is mandated by the CTAP2 spec but is not documented in the code, making it look like a security bug
type: project
---

# 0010 — All-Zero AES IV Not Documented

## Problem

Throughout `src/ctap2.rs` and `src/commands/key/fido2.rs`, AES-256-CBC encryption is performed with a hardcoded all-zero IV:

```rust
const IV: [u8; 16] = [0u8; 16];
// or inline:
let iv = [0u8; 16];
```

An all-zero IV is a well-known anti-pattern in general AES-CBC usage because it leaks information about the first block when the same key is reused. Anyone reading this code without knowledge of the CTAP2 specification will immediately flag it as a security vulnerability.

However, **the CTAP2 specification explicitly mandates this IV** for the clientPIN and hmac-secret operations. From the spec:

> "The platform MUST use an IV of all 16 zero bytes for AES-256-CBC encryption."

The key is also never reused across sessions (it is derived from an ephemeral ECDH exchange), so the zero-IV is safe in this specific context.

## Why It Needs Changing

- Future code reviewers (or automated security scanners like `cargo-audit`) may flag this as a vulnerability
- There is no comment pointing to the spec section that mandates it
- The constant is defined in multiple places independently

## Proposed Change

1. Define a single named constant with a documentation comment:

```rust
/// All-zero IV as mandated by the CTAP2 spec for clientPIN AES-256-CBC operations.
///
/// This is safe because the AES key is derived from a fresh ephemeral ECDH exchange
/// for each session and is never reused. See CTAP2 §6.5.4.
///
/// Reference: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
///   fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto1
const CTAP2_AES_IV: [u8; 16] = [0u8; 16];
```

2. Replace all occurrences of `[0u8; 16]` used as AES IV with `CTAP2_AES_IV`.

3. Place this constant in `src/ctap2.rs` and re-export or `use` it in `fido2.rs`.

### Steps

1. Add `CTAP2_AES_IV` to `src/ctap2.rs` with the above doc comment
2. Replace all anonymous `[0u8; 16]` IV literals in `ctap2.rs` and `fido2.rs`
3. Verify `cargo test` passes

## Security Impact

None — this is documentation only. The cryptographic behaviour is unchanged.

## Relevant Code

- `src/ctap2.rs`: `ClientPinSession::encrypt_pin_hash`, `encrypt_pin`, `decrypt_pin_token`
- `src/commands/key/fido2.rs`: challenge-response salt encryption and decryption

## References

- [CTAP2 §6.5.4 PIN/UV Auth Protocol One](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#pinProto1)
