---
name: HID Module Refactor
description: HID frame types, constants, and protocol logic are all in one large device.rs file — split into focused submodules
type: project
---

# 0001 — HID Module Refactor

## Problem

`src/device.rs` is a single ~500-line file that contains three distinct concerns:

1. **HID frame protocol** — `CtapHidFrame`, `FramePayload`, init/continuation frame encoding/decoding, multi-frame message assembly/reassembly
2. **CTAPHID protocol constants** — `CTAPHID_INIT`, `CTAPHID_CBOR`, `CMD_WRITE`, `CMD_RNG`, etc.
3. **Device communication** — `SoloHid`, `SoloDevice`, `list_solo_devices()`, `send_recv()`, `send_bootloader_cmd()`

These three concerns have different reasons to change, different test audiences, and different abstraction levels. Mixing them makes the file hard to navigate and test in isolation.

## Why It Needs Changing

- The constants (`CMD_*`, `CTAPHID_*`, USB VID/PID) are referenced from many places and would benefit from being importable from a clear path like `device::protocol::CMD_RNG`.
- The frame encoding/decoding logic is pure data transformation — entirely testable without a device handle — but it's buried alongside device I/O code.
- New contributors (or future-you) must read ~300 lines before reaching the device communication code.

## Proposed Change

Convert `device.rs` into a `device/` module with three submodules:

```
src/device/
├── mod.rs          — re-exports; SoloDevice, list_solo_devices, SoloHid::open
├── protocol.rs     — all CMD_* and CTAPHID_* constants, USB VID/PID
├── frame.rs        — CtapHidFrame, FramePayload, encode/decode, message assembly
└── hid.rs          — SoloHid struct, send_recv, send_bootloader_cmd
```

`mod.rs` re-exports everything that is currently public, so callers outside the module need no changes.

### Steps

1. Create `src/device/` directory, move `src/device.rs` → `src/device/hid.rs`
2. Extract constants block into `src/device/protocol.rs`
3. Extract `CtapHidFrame`, `FramePayload`, and all frame functions into `src/device/frame.rs`
4. Update `src/device/mod.rs` with `pub use` re-exports
5. Fix all intra-module `use` paths
6. Verify `cargo test` passes

### Public API Impact

None — all items remain public under the same names via re-export.

## Relevant Code

- `src/device.rs` (entire file)
- Constants: lines ~1–60 (VID, PID, CTAPHID_* commands, CMD_* bootloader commands)
- Frame types: lines ~60–180 (`CtapHidFrame`, `FramePayload`, impl blocks)
- Device I/O: lines ~180–450 (`SoloHid`, `SoloDevice`, `list_solo_devices`)

## References

- [Rust module best practices](https://doc.rust-lang.org/book/ch07-02-defining-modules-to-control-scope-and-privacy.html)
- [CTAPHID specification §8](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-discovery)
