---
name: Remove Unsafe AES Block Casting
description: Two unsafe blocks cast byte slices to AES Block16 references — replace with safe aes-crate APIs that accept byte slices directly
type: project
---

# 0007 — Remove Unsafe AES Block Casting

## Problem

`src/commands/key/fido2.rs` contains two `unsafe` blocks that cast a `&[u8]` buffer into `&[Block<Aes256>]` in order to call the AES encrypt/decrypt API:

```rust
// Encrypt
let blocks_in = unsafe {
    std::slice::from_raw_parts(salt.as_ptr() as *const Block<Aes256>, 2)
};
let mut blocks_out = [Block::<Aes256>::default(); 2];
let blocks_out_slice = unsafe {
    std::slice::from_raw_parts_mut(blocks_out.as_mut_ptr() as *mut Block<Aes256>, 2)
};
```

The same pattern appears twice (encrypt for `saltEnc`, decrypt for the `hmac_secret` output).

While the code is arguably sound (the types are aligned 16-byte arrays of the right size), it:
- Requires future readers to audit `unsafe` blocks
- Relies on implementation details of `Block<Aes256>` being `[u8; 16]`
- Was marked `#[allow(deprecated)]`, suggesting the API it uses was already transitional

## Why It Needs Changing

- Every `unsafe` block is a liability that must be audited on every security review
- The `aes` + `cbc` crates provide fully safe APIs that accept `&[u8]` and `&mut [u8]` directly via the `cipher` traits
- Removing these blocks makes the security review story much cleaner

## Proposed Change

Use the `cbc::Encryptor` / `cbc::Decryptor` safe API with `encrypt_vec` and `decrypt_vec`:

```rust
use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};

// Encrypt two 16-byte blocks:
let salt_enc: Vec<u8> = Encryptor::<Aes256>::new_from_slices(&shared_secret, &IV)
    .map_err(|_| SoloError::CryptoError("AES key/IV length error".into()))?
    .encrypt_padded_vec_mut::<cipher::block_padding::NoPadding>(&salt)
    .map_err(|_| SoloError::CryptoError("AES encrypt error".into()))?;
```

Or, since the input is always a multiple of the block size (32 bytes = 2 blocks), use in-place encryption:

```rust
use aes::Aes256;
use cipher::{BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
let mut buf = salt.to_vec(); // 32 bytes
Aes256CbcEnc::new_from_slices(&shared_secret, &IV)
    .unwrap()
    .encrypt_blocks_inout_mut(/* ... */);
```

The exact API depends on the pinned `aes`/`cbc` crate versions. The key requirement is: **no `unsafe` block**.

### Steps

1. Read the exact `aes` and `cbc` crate versions in `Cargo.toml`
2. Identify the safe in-place or allocating encrypt/decrypt API available for those versions
3. Replace the two `unsafe` blocks in `fido2.rs` with safe equivalents
4. Remove the `#[allow(deprecated)]` attribute(s)
5. Verify that the existing `cargo test` suite passes (the `test_challenge_response_crypto` test covers this path)

## Security Impact

None — the cryptographic operations are identical. This is purely a code quality and auditability improvement.

## Relevant Code

- `src/commands/key/fido2.rs`: salt encryption (~lines 395–410), hmac-secret decryption (~lines 440–455)
- `src/ctap2.rs`: `ClientPinSession::encrypt_pin_hash`, `encrypt_pin`, `decrypt_pin_token` — check whether these also use unsafe casts

## References

- [aes crate docs](https://docs.rs/aes)
- [cbc crate docs](https://docs.rs/cbc)
- [cipher::BlockEncryptMut](https://docs.rs/cipher/latest/cipher/trait.BlockEncryptMut.html)
