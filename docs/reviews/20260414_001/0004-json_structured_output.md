---
name: JSON / Structured Output
description: Commands output plain text only — a --json flag would enable reliable scripted use without fragile text parsing
type: project
---

# 0004 — JSON / Structured Output

## Problem

Several commands produce output that is useful in scripts but only available as human-readable
plain text:

| Command                  | Current output               | Scripted use difficulty            |
|--------------------------|------------------------------|------------------------------------|
| `key make-credential`    | raw hex credential ID        | easy (single token)                |
| `key challenge-response` | raw hex HMAC output          | easy (single token)                |
| `key credential ls`      | multi-line human text        | hard (must parse table)            |
| `key version`            | "Firmware version: X.Y.Z"    | medium (must strip prefix)         |
| `ls`                     | human-readable device list   | hard (multi-field, variable width) |
| `key verify`             | "Key is authentic (Solo v3)" | medium (must grep for keyword)     |

Scripts that consume these outputs today are fragile: they use `awk`, `grep`, or fixed column
offsets that break if the message wording changes.

`serde_json` is already a dependency (`src/error.rs` has `JsonError(#[from] serde_json::Error)`),
so adding JSON output requires no new crates.

## Why It Needs Changing

The tool is explicitly useful in enrollment pipelines (create a credential, get the ID, store it
in a database). Supporting `--json` output makes this use case first-class and reduces coupling
between the tool's human-readable messages and any script that consumes them.

## Proposed Changes

### 1. Add a `--json` global flag

```rust
// cli.rs — Cli struct
/// Output results as JSON (for scripting)
#[arg(long, global = true)]
pub json: bool,
```

Pass `json: bool` through the command dispatch chain, or store it in a thread-local / global
(less clean but requires fewer signature changes).

### 2. Define output structs for each affected command

```rust
// src/output.rs (new file)
use serde::Serialize;

#[derive(Serialize)]
pub struct MakeCredentialOutput {
    pub credential_id: String,   // hex
}

#[derive(Serialize)]
pub struct ChallengeResponseOutput {
    pub hmac_output: String,     // hex, 32 bytes
}

#[derive(Serialize)]
pub struct CredentialEntry {
    pub rp_id: String,
    pub user_name: String,
    pub user_id: String,         // hex
    pub credential_id: String,   // hex
}

#[derive(Serialize)]
pub struct CredentialListOutput {
    pub credentials: Vec<CredentialEntry>,
}

#[derive(Serialize)]
pub struct DeviceInfo {
    pub path: String,
    pub serial: Option<String>,
    pub product: Option<String>,
    pub manufacturer: Option<String>,
}

#[derive(Serialize)]
pub struct ListOutput {
    pub devices: Vec<DeviceInfo>,
}

#[derive(Serialize)]
pub struct VerifyOutput {
    pub authentic: bool,
    pub device_type: String,     // "genuine", "developer", "unknown"
    pub device_name: Option<String>,
}

#[derive(Serialize)]
pub struct VersionOutput {
    pub firmware_version: String,
}
```

### 3. Print helper

```rust
// src/output.rs
pub fn print_output<T: Serialize>(value: &T, json: bool) -> crate::error::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}
```

Commands call `print_output(&output, json)?` after their human-readable `println!` calls.
Human output is still printed when `--json` is not set; when `--json` is set, suppress human
output and print only JSON.

### 4. Example: `cmd_challenge_response`

```rust
// After computing hmac_output:
if json {
    let out = ChallengeResponseOutput { hmac_output: hex::encode(&hmac_output[..32]) };
    print_output(&out, true)?;
} else {
    println!("{}", hex::encode(&hmac_output[..32]));
}
```

### Steps

1. Add `--json` global flag to `Cli` in `cli.rs`
2. Create `src/output.rs` with the output structs and `print_output` helper
3. Update `cmd_make_credential`, `cmd_challenge_response`, `cmd_verify`, `cmd_key_version`
4. Update `cmd_credential_ls` and `cmd_ls` (most valuable for scripting)
5. Ensure human output is unchanged when `--json` is absent
6. Add at least one test per command that captures JSON output and round-trips through `serde_json`
7. Verify `cargo test` passes

## Relevant Code

- `src/cli.rs` — `Cli` struct, `--json` flag
- `src/commands/key/fido2.rs` — `cmd_make_credential`, `cmd_challenge_response`
- `src/commands/key/credential.rs` — `cmd_credential_ls`
- `src/commands/key/verify.rs` — `cmd_verify`
- `src/commands/key/mod.rs` or `top.rs` — `cmd_ls`, `cmd_key_version`
- `src/main.rs` — dispatch; thread `json: bool` through

## References

- [serde_json](https://crates.io/crates/serde_json)
- [clap global flags](https://docs.rs/clap/latest/clap/struct.Arg.html#method.global)
