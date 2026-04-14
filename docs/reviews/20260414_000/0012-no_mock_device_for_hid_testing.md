---
name: No Mock Device for HID Testing
description: All HID-using command functions are untestable without a physical device — a trait abstraction over SoloHid would allow mock testing
type: project
---

# 0012 — No Mock Device for HID Testing

## Problem

Every command function that communicates with a SoloKey takes a `&mut SoloHid` parameter, which is a concrete type wrapping a real hidapi device handle. There is no way to test any of these functions without a physical device.

This means the following are completely untested (unless `#[ignore]`-d and run manually):

- All CTAP2 command logic in `fido2.rs`, `pin.rs`, `verify.rs`, `credential.rs`
- All device operations in `ops.rs`, `rng.rs`, `probe.rs`, `update.rs`
- Error handling paths (timeout, wrong response, protocol errors)
- Edge cases in response parsing

The existing test suite compensates by testing the pure-function helpers (frame encoding, CBOR parsing, crypto), but the "glue" code that calls the device and processes the response is untested.

## Why It Needs Changing

- Protocol bugs in the command layer will not be caught until a user runs the binary against a real device
- Error handling paths (e.g., "what happens if the device returns a malformed CBOR response?") are never exercised
- It becomes impossible to add regression tests for specific device-response scenarios

## Proposed Change

Introduce a `HidDevice` trait (or use `mockall`):

```rust
/// Trait abstracting the send/receive interface of a CTAP HID device.
/// This allows mock implementations for testing.
pub trait HidDevice {
    fn send_recv(&mut self, cmd: u8, data: &[u8]) -> Result<Vec<u8>>;
    fn send_bootloader_cmd(&mut self, cmd: u8, addr: u32, data: &[u8]) -> Result<Vec<u8>>;
    fn channel_id(&self) -> u32;
}

impl HidDevice for SoloHid { ... }
```

Change all command functions to accept `impl HidDevice` (or `&mut dyn HidDevice`):

```rust
pub fn cmd_ping(hid: &mut impl HidDevice, count: u8, data: &[u8]) -> Result<()>
```

Then in tests:

```rust
struct MockDevice {
    responses: VecDeque<Result<Vec<u8>>>,
}

impl HidDevice for MockDevice {
    fn send_recv(&mut self, _cmd: u8, _data: &[u8]) -> Result<Vec<u8>> {
        self.responses.pop_front().unwrap_or(Err(SoloError::Timeout))
    }
    // ...
}

#[test]
fn test_cmd_ping_success() {
    let ping_data = vec![0x01, 0x02, 0x03];
    let mut device = MockDevice {
        responses: vec![Ok(ping_data.clone())].into(),
    };
    let result = cmd_ping(&mut device, 1, &ping_data);
    assert!(result.is_ok());
}
```

### Scope Consideration

This is a significant refactor. It is recommended to:

1. Start with the `HidDevice` trait definition and implement it for `SoloHid`
2. Convert the simplest commands first (`cmd_ping`, `cmd_wink`, `cmd_key_version`)
3. Add mock tests for each converted command
4. Progressively convert remaining commands
5. This work naturally complements issue #0006 (decomposing large functions makes them easier to test with mocks)

### Alternative: `mockall` crate

If adding a hand-rolled mock is too much ceremony, the `mockall` crate can auto-generate mock implementations from trait definitions with `#[automock]`. This would reduce mock boilerplate significantly.

### Steps

1. Define `HidDevice` trait in `src/device.rs`
2. Implement `HidDevice` for `SoloHid`
3. Convert `cmd_ping` and `cmd_wink` as proofs of concept
4. Add mock tests for those two commands
5. Expand progressively to other commands

## Relevant Code

- `src/device.rs`: `SoloHid::send_recv`, `send_bootloader_cmd`
- All files in `src/commands/key/`

## References

- [mockall crate](https://docs.rs/mockall)
- [Rust book: trait objects](https://doc.rust-lang.org/book/ch17-02-trait-objects.html)
