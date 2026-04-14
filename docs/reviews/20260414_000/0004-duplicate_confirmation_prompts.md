---
name: Duplicate Confirmation Prompts
description: Interactive "yes" confirmation prompts are copy-pasted in three places with subtle inconsistencies
type: project
---

# 0004 — Duplicate Confirmation Prompts

## Problem

Three destructive commands prompt the user to type "yes" before proceeding. The code is nearly identical in each:

### `src/commands/key/ops.rs` — `cmd_reset`:
```rust
println!("This will reset the key. Type 'yes' to confirm: ");
let mut input = String::new();
std::io::stdin().read_line(&mut input)?;
if input.trim() != "yes" {
    println!("Aborted.");
    return Ok(());
}
```

### `src/commands/key/ops.rs` — `cmd_disable_updates`:
```rust
println!("This will permanently disable firmware updates. Type 'yes' to confirm: ");
let mut input = String::new();
std::io::stdin().read_line(&mut input)?;
if input.trim() != "yes" {
    println!("Aborted.");
    return Ok(());
}
```

### `src/commands/key/credential.rs` — `cmd_credential_rm`:
```rust
println!("This will delete the credential. Type 'yes' to confirm: ");
let mut input = String::new();
std::io::stdin().read_line(&mut input)?;
if input.trim() != "yes" {
    return Err(SoloError::ProtocolError("Aborted".into()));
}
```

Note: the third copy uses `Err` rather than `Ok(())` for a "no" response — a subtle inconsistency that affects the exit code seen by the caller.

## Why It Needs Changing

- DRY violation — same stdin-reading boilerplate in three places
- Inconsistent behaviour: `cmd_credential_rm` returns `Err` on "no", while the others return `Ok(())`; this should be a deliberate choice made once
- Any change to the prompt UX (e.g., accepting "y", case-insensitive matching) must be applied in three places

## Proposed Change

Add a helper in a new `src/commands/key/common.rs` (or `src/commands/common.rs`):

```rust
/// Print `prompt` and require the user to type exactly "yes" to continue.
/// Returns Ok(true) if confirmed, Ok(false) if not, Err on I/O failure.
pub fn confirm(prompt: &str) -> Result<bool> {
    println!("{}", prompt);
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)
        .map_err(SoloError::IoError)?;
    Ok(input.trim() == "yes")
}
```

Call sites become:
```rust
if !common::confirm("This will reset the key. Type 'yes' to confirm:")? {
    println!("Aborted.");
    return Ok(());
}
```

Standardise all three to return `Ok(())` on abort (not `Err`) — aborting a destructive operation is not an error.

### Steps

1. Create `src/commands/key/common.rs` with `confirm()`
2. Add `mod common;` to `src/commands/key/mod.rs`
3. Replace the three duplicate confirmation blocks
4. Standardise all three to return `Ok(())` on "no"
5. Verify `cargo test` passes

## Relevant Code

- `src/commands/key/ops.rs`: `cmd_reset` (~lines 71–78), `cmd_disable_updates` (~lines 92–99)
- `src/commands/key/credential.rs`: `cmd_credential_rm` (~lines 434–447)
