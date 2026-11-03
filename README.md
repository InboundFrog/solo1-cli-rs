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

The binary ends up at `target/release/solo`. (It used to be called `solo1`.)

### Workspace layout

| Crate | Path | What it holds |
|---|---|---|
| `solo-ctaphid` | `crates/solo-ctaphid` | CTAPHID framing and the USB HID transport. Device-neutral. |
| `solo-ctap2` | `crates/solo-ctap2` | CBOR helpers and CTAP2 protocol code (clientPIN, key agreement, request builders). Device-neutral. |
| `solo1` | `crates/solo1` | Solo 1 vendor commands, bootloader, ST DFU, firmware files and attestation fingerprints. |
| `solo2` | `crates/solo2` | Solo 2 USB IDs and admin-app vendor commands (version, uuid, locked, rng). |
| `solo-cli` | `crates/solo-cli` | The `solo` binary: argument parsing, prompts, output, and firmware downloads. |

Device crates build on `solo-ctaphid` (and `solo-ctap2` where they need CTAP2). Only `solo-cli` touches the terminal or the network.

### Supported devices

`solo ls` and every `solo key` command find both Solo 1 and Solo 2. On Solo 2,
everything that is plain CTAPHID or CTAP2 works: `ping`, `wink`, `reset`, `set-pin`,
`change-pin`, `credential …`, `challenge-response` and `sign-file`, as do `version`
and `rng`. The rest of `solo key` (`verify`, `keyboard`, `probe`, `update`,
`disable-updates`) is Solo 1 only for now; on a Solo 2 those commands stop with "not
supported on Solo 2 yet" before sending anything. `solo program` only looks for Solo 1
devices. Solo 2 firmware updates are not implemented. None of the Solo 2 support has been tested on hardware yet.

---

## Usage

```sh
solo [OPTIONS] <COMMAND>
```

Global options:

| Flag                  | Description                                                  |
|-----------------------|--------------------------------------------------------------|
| `-v`, `--verbose`     | Enable verbose output (HID frames, bootloader packets, etc.) |
| `--timeout <SECS>`    | Timeout in seconds for device responses (default: 30)        |

`--json` is available on commands that produce structured output (`version`, `genkey`, `ls`, and all `key` subcommands). Commands that always output JSON (`sign`) or produce no structured output (`mergehex`, `monitor`, `program`) do not expose this flag.

---

## Commands

### Version

```sh
solo version [--json]                   # Print library version
```

### Device discovery

```sh
solo ls [--json]                        # List connected Solo devices
```

### Key commands (`solo key [--serial <SN>] [--udp]`)

```sh
solo key version                           # Get firmware version
solo key wink                              # Blink LED
solo key ping [--count N] [--data HEX]     # Ping and measure RTT
solo key rng hexbytes <N>                  # Print N random bytes as hex
solo key rng raw                           # Stream raw entropy to stdout
solo key rng feedkernel                    # Feed entropy to /dev/random (Linux)
solo key verify                            # Verify key authenticity via attestation
solo key reset                             # Factory reset (destructive)
solo key set-pin                           # Set PIN on unpinned key
solo key change-pin                        # Change existing PIN
solo key disable-updates                   # Permanently disable firmware updates
solo key keyboard <DATA>                   # Program keyboard sequence (max 64 bytes)
solo key probe <HASH_TYPE> <FILE>          # Calculate hash on device (sha256|sha512|rsa2048|ed25519, file <=6144 bytes)
solo key sign-file <CREDENTIAL_ID> <FILE>  # Sign file with resident credential
solo key update [--firmware FILE]          # Update firmware (downloads latest if omitted)
```

#### Credential management

```sh
solo key credential info                # Get credential slot info
solo key credential ls                  # List resident credentials
solo key credential rm <ID>             # Remove credential by base64 ID
solo key credential rm --host <HOST> --user <USER>
                                         # Remove credential by relying party and username
solo key credential create --host <HOST> --user <USER> [--prompt <TEXT>]
                                         # Create FIDO2 credential with hmac-secret
```

#### Challenge-response

```sh
solo key challenge-response <CREDENTIAL_ID> <CHALLENGE> [--host <HOST>]
# HMAC-secret challenge-response using an existing credential
# CREDENTIAL_ID: hex string from credential create output
# CHALLENGE: string to hash
# --host defaults to "solokeys.dev"
```

### Programming commands (`solo program [--serial <SN>] [--udp]`)

```sh
# Flash firmware via Solo bootloader (device must be in bootloader mode)
solo program bootloader <firmware.json>

# Flash firmware via ST DFU
solo program dfu <firmware.hex>

# Auxiliary bootloader commands
solo program aux enter-bootloader
solo program aux leave-bootloader
solo program aux enter-dfu
solo program aux leave-dfu
solo program aux reboot
solo program aux bootloader-version
```

### Firmware utilities

```sh
# Generate ECDSA P-256 keypair (PEM)
solo genkey [-o OUTPUT] [--entropy FILE] [--json]

# Sign firmware HEX file, output JSON {firmware, signature}
solo sign <KEY.pem> <firmware.hex>

# Merge Intel HEX files
solo mergehex -o OUTPUT [--attestation-key FILE] [--attestation-cert FILE] INPUT...

# Monitor serial output
solo monitor <PORT>
```

---

## Firmware update notes

- Firmware JSON files are available from the [solo1 releases page](https://github.com/solokeys/solo1/releases).
- The bootloader enforces **anti-rollback protection** — you cannot downgrade to a
  firmware version older than what is currently installed.
- If `key update` is used without `--firmware`, the latest release is downloaded automatically.

---

## Key verification and SPKI fingerprints

`solo key verify` performs attestation by making a FIDO2 credential and checking the
attestation certificate against known fingerprints.  Two fingerprint types are computed:

- **Full-DER fingerprint** — SHA-256 of the complete certificate DER bytes.  Changes if
  the certificate is reissued.
- **SPKI fingerprint** — SHA-256 of the `SubjectPublicKeyInfo` structure only.  Stable
  across certificate renewals as long as the key is the same.  Intended for future
  certificate pinning.

### Known SPKI fingerprints

| Device type          | SPKI fingerprint (SHA-256)                                                      |
|----------------------|---------------------------------------------------------------------------------|
| Solo Tap             | `6b50560fef4c768b6e9a7a7749415a7c01d39842be3e4f7b8e859ba2a4be7049`              |
| Solo 1               | not yet collected (see [#3](https://github.com/solokeys/solo1-cli-rs/issues/3)) |
| Solo Mu              | not yet collected                                                               |
| Solo ≤v3.0.0         | not yet collected                                                               |
| Solo Hacker          | not yet collected                                                               |
| Emulation/simulation | not yet collected                                                               |

The missing values must be obtained by running `solo key verify --json` against real
hardware and reading the `spki_fingerprint` field from the output.  If you have one of
these devices please contribute the value via the issue linked above.

Verification still works without the SPKI fingerprints — full-DER fingerprints are used
for device identification today.  The SPKI constants are reserved for a future pinning
mode that will tolerate certificate renewal without requiring a tool update.
