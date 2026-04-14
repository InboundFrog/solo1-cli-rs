---
name: Async Timeout and Cancellation
description: HID I/O is fully synchronous — no async executor, no cancellation signal, no user-interruptible wait for device touch
type: project
---

# 0001 — Async Timeout and Cancellation

## Problem

All device communication runs synchronously on the main thread. `SoloHid::recv_response` polls
`read_timeout(..., 500)` in a loop until either data arrives or a hard-coded `Duration` expires:

```rust
// device/hid.rs — send_recv hard-codes a 10-second timeout
pub fn send_recv(&self, cmd: u8, data: &[u8]) -> Result<Vec<u8>> {
    self.send(cmd, data)?;
    self.recv_response(cmd, Duration::from_secs(10))
}
```

Three concrete problems follow from this:

1. **No user cancellation.** If the user is prompted to touch the key and never does, the process
   blocks for 10 seconds with no way to interrupt (other than `kill`). There is no `Ctrl-C` handler
   that performs a clean shutdown.

2. **No configurable timeout.** The timeout is baked into each call site rather than being
   configurable via a CLI flag or environment variable. Commands that the user knows will be fast
   (e.g., `ping`, `wink`) still pay the same 10-second ceiling.

3. **No progress feedback during wait.** The user sees nothing between "Touch your authenticator…"
   and the response arriving (or timing out). An async-aware approach would allow a spinner or
   elapsed-time display.

## Why It Needs Changing

USB devices can hang for several reasons: device firmware is mid-reset, the USB stack is
confused, or (most commonly) the user forgot to touch the key. The current implementation gives
no actionable feedback and no escape hatch. A CLI tool for security keys should feel responsive
and trustworthy.

## Proposed Changes

### Short term — Ctrl-C handling (no async required)

Register a `ctrlc` handler before opening the device. On SIGINT, print a clean message and exit
rather than leaving the process in the blocking `read_timeout` loop:

```rust
// main.rs
ctrlc::set_handler(|| {
    eprintln!("\nInterrupted.");
    std::process::exit(130);
}).expect("Error setting Ctrl-C handler");
```

Add `ctrlc = "3"` to `Cargo.toml`.

This is the minimum viable fix and can land independently.

### Medium term — configurable timeout

Add a `--timeout <seconds>` global flag to `Cli` and thread it through to `send_recv`. Expose it
on `HidDevice::send_recv` if the trait needs it, or store it in a session context passed to
commands.

### Long term — async with tokio (optional)

Move `SoloHid` I/O to `tokio::task::spawn_blocking` and wrap the outer command functions in
`async fn`. This enables:

- `tokio::time::timeout` around any device interaction
- `tokio::select!` between the device wait and a cancellation future
- A spinner task running concurrently with device I/O

This is the highest-effort option. It is worth doing if the tool gains network-dependent
commands (firmware download with progress, OCSP, etc.) but is not required for the USB-only
path.

### Steps (short term)

1. Add `ctrlc = "3"` to `[dependencies]` in `Cargo.toml`
2. Register handler at the top of `main()` before `run(cli)`
3. Add `--timeout` global flag to `Cli` (default 10)
4. Pass timeout through `run()` → `SoloHid::open` or a wrapper struct
5. Verify `cargo test` passes

## Relevant Code

- `src/device/hid.rs`: `send_recv` (line 115), `recv_response` (line 142), `init` (line 89)
- `src/main.rs`: `main()`, `run_key_command()` — open device, call command fn
- `src/cli.rs`: `Cli` struct — add `--timeout` here

## References

- [ctrlc crate](https://crates.io/crates/ctrlc)
- [tokio spawn_blocking](https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html)
- [CTAPHID §6.2.1 — Transaction timeout](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb-hid-timeout)
