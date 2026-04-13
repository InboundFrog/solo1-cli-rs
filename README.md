# solo1-cli-rs

**WARN:** Not everything has been fully tested with a SoloKey v1 yet, so use at your own
          risk.

## Note

This is a port of the official [solokeys/solo1-cli](https://github.com/solokeys/solo1-cli) Python tool to Rust.

[Claude](https://claude.com/product/claude-code) did all the hard yards
porting the protocol implementation, working through the bootloader
protocol details, and debugging firmware update issues along the way.

## Overview

A Rust CLI for managing [SoloKeys Solo 1](https://solokeys.com/) hardware security keys.
Supports firmware updates, FIDO2 operations, credential management, and low-level
bootloader/DFU programming.

---

## Building

```sh
cargo build --release
```

The binary ends up at `target/release/solo1`.

---

## Usage

```sh
solo1 [OPTIONS] <COMMAND>
```

Global options:

| Flag              | Description                                                  |
|-------------------|--------------------------------------------------------------|
| `-v`, `--verbose` | Enable verbose output (HID frames, bootloader packets, etc.) |

---

## Commands

### Device discovery

```sh
# List connected Solo devices
solo1 ls
```

### Key commands (`solo1 key [--serial <SN>]`)

```sh
solo1 key version                        # Get firmware version
solo1 key wink                           # Blink LED
solo1 key ping [--count N] [--data HEX] # Ping and measure RTT
solo1 key rng hexbytes <N>              # Print N random bytes as hex
solo1 key rng raw                        # Stream raw entropy to stdout
solo1 key rng feedkernel                 # Feed entropy to /dev/random (Linux)
solo1 key verify                         # Verify key authenticity via attestation
solo1 key reset                          # Factory reset (destructive)
solo1 key set-pin                        # Set PIN on unpinned key
solo1 key change-pin                     # Change existing PIN
solo1 key disable-updates                # Permanently disable firmware updates
solo1 key keyboard <DATA>               # Program keyboard sequence (max 64 bytes)
solo1 key make-credential <RP_ID>       # Create FIDO2 credential with hmac-secret
solo1 key challenge-response <RP_ID> <SECRET>  # HMAC-secret challenge-response
solo1 key sign-file <FILE>              # Sign file with resident credential
solo1 key probe <sha256|sha512|rsa2048|ed25519>  # Calculate hash on device
solo1 key update [--firmware FILE]      # Update firmware (downloads latest if omitted)
solo1 key credential info               # Get credential slot info
solo1 key credential ls                 # List resident credentials
solo1 key credential rm <ID>           # Remove credential by ID
```

### Programming commands (`solo1 program [--serial <SN>]`)

```sh
# Flash firmware via Solo bootloader (device must be in bootloader mode)
solo1 program bootloader <firmware.json>

# Flash firmware via ST DFU
solo1 program dfu <firmware.hex>

# Auxiliary bootloader commands
solo1 program aux enter-bootloader
solo1 program aux leave-bootloader
solo1 program aux enter-dfu
solo1 program aux leave-dfu
solo1 program aux reboot
solo1 program aux bootloader-version
```

### Firmware utilities

```sh
# Generate ECDSA P-256 keypair (PEM)
solo1 genkey [-o OUTPUT] [--entropy FILE]

# Sign firmware HEX file, output JSON {firmware, signature}
solo1 sign <KEY.pem> <firmware.hex>

# Merge Intel HEX files
solo1 mergehex -o OUTPUT [--attestation-key FILE] [--attestation-cert FILE] INPUT...

# Monitor serial output
solo1 monitor <PORT>
```

---

## Firmware update notes

- Firmware JSON files are available from the [solo1 releases page](https://github.com/solokeys/solo1/releases).
- The bootloader enforces **anti-rollback protection** — you cannot downgrade to a
  firmware version older than what is currently installed.
- If `key update` is used without `--firmware`, the latest release is downloaded automatically.
