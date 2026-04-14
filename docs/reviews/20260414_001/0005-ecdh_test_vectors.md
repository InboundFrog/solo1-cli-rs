---
name: ECDH Test Vectors for derive_shared_secret
description: The P-256 ECDH key agreement in derive_shared_secret has no unit test covering correct shared-secret derivation against a known test vector
type: project
---

# 0005 — ECDH Test Vectors for `derive_shared_secret`

## Problem

`derive_shared_secret` in `src/commands/key/fido2.rs` performs:

1. Parse the device's P-256 public key from a COSE map
2. Generate an ephemeral P-256 keypair
3. ECDH: compute shared secret point
4. Extract the x-coordinate and SHA-256 it → 32-byte shared secret
5. Return the shared secret and the ephemeral COSE key for inclusion in the extension input

This is the security-critical kernel of the hmac-secret protocol. A bug here — wrong
coordinate extraction, wrong shared-secret derivation, wrong COSE key format — would cause the
device to silently reject the encrypted payload, with a confusing error message rather than a
clear indication that key agreement failed.

There are currently **no unit tests** for `derive_shared_secret`. Because it uses
`EphemeralSecret::random`, a direct test requires injecting a fixed key or restructuring the
function to accept the ephemeral secret as a parameter.

Additionally, `prepare_hmac_secret_input` (which calls `derive_shared_secret`) has no test
covering the full steps 1–6 of the hmac-secret protocol against a known-good reference output.

## Why It Needs Changing

The CTAP2 hmac-secret extension is the core feature that makes `challenge-response` and
`sign-file` work. If the ECDH implementation has a subtle bug (e.g., forgetting to hash the
x-coordinate, using the compressed vs. uncompressed point, big-endian vs. little-endian
coordinate order), it would not be caught by any existing test. The device would return a CTAP2
error and the user would see an opaque failure.

Test vectors from NIST or the CTAP2 conformance suite can be used to prove the implementation
is correct once and protect it from future regressions.

## Proposed Changes

### 1. Refactor `derive_shared_secret` to accept an optional ephemeral secret

To make the function testable without a random key, extract the key-agreement math into a
helper that accepts any `EphemeralSecret`:

```rust
// Private — accepts a pre-generated ephemeral secret for testing
fn derive_shared_secret_with_key(
    dev_pub_key_cbor_pairs: &[(Value, Value)],
    ephemeral_secret: p256::ecdh::EphemeralSecret,
) -> Result<([u8; 32], Value)>

// Public-facing — generates its own ephemeral secret
fn derive_shared_secret(dev_pub_key_cbor_pairs: &[(Value, Value)]) -> Result<([u8; 32], Value)> {
    derive_shared_secret_with_key(dev_pub_key_cbor_pairs, EphemeralSecret::random(&mut OsRng))
}
```

`derive_shared_secret_with_key` is `#[cfg(test)]`-visible via a re-export or by being `pub(crate)`.

### 2. Add a test using a fixed P-256 keypair

Use the NIST P-256 test vectors from [RFC 5114 §2.6] or derive a test vector offline using
Python's `cryptography` library:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Test vector: device private key d, platform ephemeral key e, expected shared secret.
    // Derived offline with: Python cryptography / OpenSSL / NIST CAVP P-256 test vectors.
    const DEV_PRIV_BYTES: [u8; 32] = [ /* ... */ ];
    const DEV_X: [u8; 32]          = [ /* ... */ ];
    const DEV_Y: [u8; 32]          = [ /* ... */ ];
    const EPH_PRIV_BYTES: [u8; 32] = [ /* ... */ ];
    const EXPECTED_SHARED: [u8; 32] = [ /* SHA-256(x-coord of ECDH point) */ ];

    #[test]
    fn derive_shared_secret_known_vector() {
        use p256::SecretKey;

        // Build device COSE public key pairs from known coordinates
        let dev_pub_pairs = vec![
            (cbor_int(-2), cbor_bytes(DEV_X.to_vec())),
            (cbor_int(-3), cbor_bytes(DEV_Y.to_vec())),
        ];

        // Build ephemeral secret from known private key bytes
        let eph_secret = SecretKey::from_bytes(&DEV_PRIV_BYTES.into()).unwrap();
        let eph_secret = p256::ecdh::EphemeralSecret::from(eph_secret.to_nonzero_scalar());

        let (shared, _cose_key) = derive_shared_secret_with_key(&dev_pub_pairs, eph_secret)
            .expect("derive_shared_secret failed");

        assert_eq!(shared, EXPECTED_SHARED);
    }
}
```

### 3. Add an integration-style test for `prepare_hmac_secret_input`

Using the same fixed keys, verify that the saltEnc and saltAuth outputs match a reference
computed offline:

```rust
#[test]
fn prepare_hmac_secret_input_known_vector() {
    // Fixed: device COSE pairs, challenge string, expected saltEnc, expected saltAuth prefix
    let (hmac_ext, shared) = prepare_hmac_secret_input_with_key(
        &dev_pub_pairs, "test-challenge", eph_secret
    ).unwrap();

    // Assert saltEnc and saltAuth values inside hmac_ext match references
    // ...
}
```

This would require a parallel `prepare_hmac_secret_input_with_key` that accepts the ephemeral
secret as a parameter, following the same pattern as step 1.

### Steps

1. Derive test vectors offline (Python script or OpenSSL commands — document the derivation)
2. Refactor `derive_shared_secret` to `derive_shared_secret_with_key` + thin public wrapper
3. Write `derive_shared_secret_known_vector` test
4. Refactor `prepare_hmac_secret_input` similarly
5. Write `prepare_hmac_secret_input_known_vector` test
6. Verify `cargo test` passes with the new tests included

## Relevant Code

- `src/commands/key/fido2.rs` — `derive_shared_secret` (lines 149–199), `prepare_hmac_secret_input` (lines 244–286)
- `src/ctap2.rs` — `extract_cose_coord`, `CTAP2_AES_IV` (used in the input preparation)

## References

- [CTAP2 §6.2 — PIN/UV Auth Protocol — hmac-secret extension](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-hmac-secret-extension)
- [NIST CAVP ECDH test vectors (P-256)](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/component-testing)
- [p256 crate — EphemeralSecret](https://docs.rs/p256/latest/p256/ecdh/struct.EphemeralSecret.html)
- [RFC 5114 §2.6 — 256-bit Random ECP Group](https://www.rfc-editor.org/rfc/rfc5114#section-2.6)
