---
name: Missing Tests for program.rs and aux.rs
description: commands/program.rs and commands/aux.rs have zero unit tests; the testable logic within them (version selection, address calculation, state transitions) should be extracted and tested
type: project
---

# 0011 — Missing Tests: `program.rs` and `aux.rs`

## Problem

`src/commands/program.rs` and `src/commands/aux.rs` have no unit or integration tests at all. While the top-level command functions require a physical device to run, there is logic inside them that could and should be tested independently.

### Untested logic in `program.rs`

- **Bootloader version comparison** — the `(boot_major, boot_minor, boot_patch) <= (2, 5, 3)` comparison that selects v1 vs v2 signature is tested nowhere. (Note: this is the same logic identified for extraction in issue #0005.)
- **Firmware chunk iteration** — the loop that slices firmware into 256-byte chunks is not tested for edge cases (firmware size not a multiple of 256, firmware smaller than one chunk, empty firmware).
- **Progress bar logic** — minor, but the chunk count calculation could be tested.

### Untested logic in `aux.rs`

- `cmd_bootloader_version` parses raw version bytes into a display string — this parsing is not tested.
- All aux commands are essentially one-line wrappers (`hid.send_recv(...)`) with no testable logic, so the gap here is smaller.

## Why It Needs Changing

- The bootloader version comparison is security-relevant (wrong signature selection → firmware update fails, or worse, the bootloader rejects the update silently)
- The firmware chunking logic is correctness-relevant (off-by-one errors would corrupt firmware)
- These are exactly the kinds of bugs that don't appear until a user tries to flash a device

## Proposed Change

### Step 1: Extract testable logic (prerequisite: issue #0005)

After the bootloader signature selection is extracted into `firmware::select_signature`, it becomes testable with mocked version bytes.

### Step 2: Add tests for firmware chunking

Add to `src/commands/program.rs` or `src/firmware.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firmware_chunks_exact_multiple() {
        let firmware = vec![0xABu8; 512];
        let chunks: Vec<&[u8]> = firmware.chunks(256).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 256);
        assert_eq!(chunks[1].len(), 256);
    }

    #[test]
    fn test_firmware_chunks_partial_last() {
        let firmware = vec![0xABu8; 300];
        let chunks: Vec<&[u8]> = firmware.chunks(256).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 256);
        assert_eq!(chunks[1].len(), 44);
    }

    #[test]
    fn test_firmware_chunks_empty() {
        let firmware: Vec<u8> = vec![];
        let chunks: Vec<&[u8]> = firmware.chunks(256).collect();
        assert_eq!(chunks.len(), 0);
    }
}
```

### Step 3: Add a test for `bootloader_version` display

```rust
#[test]
fn test_bootloader_version_display() {
    // Simulate version bytes [major, minor, patch]
    let version_bytes = vec![2u8, 5, 3];
    let display = format!("{}.{}.{}", version_bytes[0], version_bytes[1], version_bytes[2]);
    assert_eq!(display, "2.5.3");
}
```

### Steps

1. Ensure issue #0005 is done (extracted `select_signature`)
2. Add chunking tests to `src/commands/program.rs`
3. Add version display test to `src/commands/aux.rs`
4. Verify `cargo test` passes

## Relevant Code

- `src/commands/program.rs`: `cmd_program_bootloader` (entire function)
- `src/commands/aux.rs`: `cmd_bootloader_version`
