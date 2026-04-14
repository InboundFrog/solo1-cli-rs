---
name: Duplicate Bootloader Signature Selection
description: Querying bootloader version and selecting the correct firmware signature is duplicated verbatim in update.rs and program.rs
type: project
---

# 0005 — Duplicate Bootloader Signature Selection

## Problem

Two commands — `cmd_update` and `cmd_program_bootloader` — both need to:
1. Query the connected device for its bootloader version
2. Compare the version against `2.5.3` to select either the v1 or v2 firmware signature

The code is copy-pasted:

### `src/commands/key/update.rs` (~lines 52–67):
```rust
let version_bytes = hid.send_recv(CMD_BOOT, &[CMD_VERSION])?;
let boot_major = version_bytes[0];
let boot_minor = version_bytes[1];
let boot_patch = version_bytes[2];
let sig = if (boot_major, boot_minor, boot_patch) <= (2, 5, 3) {
    &fw.signature_v1
} else {
    &fw.signature_v2
};
```

### `src/commands/program.rs` (~lines 30–47):
```rust
let version_bytes = hid.send_recv(CMD_BOOT, &[CMD_VERSION])?;
let boot_major = version_bytes[0];
let boot_minor = version_bytes[1];
let boot_patch = version_bytes[2];
let sig = if (boot_major, boot_minor, boot_patch) <= (2, 5, 3) {
    &fw.signature_v1
} else {
    &fw.signature_v2
};
```

## Why It Needs Changing

- DRY violation — any change to the version threshold or signature selection logic must be applied in both places
- The version comparison uses raw tuple comparison on bytes, which is correct but implicit; a helper with a clear name makes the intent obvious
- Introduces a single place to add logging or diagnostics about the selected signature

## Proposed Change

Add a function to `src/firmware.rs` (or `src/commands/key/common.rs`):

```rust
/// Query the bootloader version from a connected device and select the
/// appropriate firmware signature for that bootloader version.
///
/// Bootloaders <= 2.5.3 use the v1 signing region; later ones use v2.
pub fn select_signature<'a>(hid: &mut SoloHid, fw: &'a FirmwareJson) -> Result<&'a str> {
    let version_bytes = hid.send_recv(CMD_BOOT, &[CMD_VERSION])?;
    let ver = (version_bytes[0], version_bytes[1], version_bytes[2]);
    let sig = if ver <= (2, 5, 3) {
        &fw.signature_v1
    } else {
        &fw.signature_v2
    };
    Ok(sig)
}
```

Both call sites become:
```rust
let sig = firmware::select_signature(hid, &fw)?;
```

### Steps

1. Add `select_signature` to `src/firmware.rs`
2. Add the necessary `use` imports (`SoloHid`, `CMD_BOOT`, `CMD_VERSION`)
3. Replace both duplicate blocks in `update.rs` and `program.rs`
4. Verify `cargo test` passes

## Relevant Code

- `src/commands/key/update.rs`: ~lines 52–67
- `src/commands/program.rs`: ~lines 30–47
- `src/firmware.rs`: `FirmwareJson` struct (already there)
- `src/device.rs`: `CMD_BOOT`, `CMD_VERSION` constants
