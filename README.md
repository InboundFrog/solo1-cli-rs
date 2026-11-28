# solo1-cli-rs

**Warning:** Not everything is fully tested with a Solo 1 key yet. Use this tool at your own
risk.

## Note

This is a port of the official [solokeys/solo1-cli](https://github.com/solokeys/solo1-cli) Python tool to Rust.

[Claude](https://claude.com/product/claude-code) did all the hard work. It ported
the protocol code, worked out the bootloader protocol details, and fixed
firmware update bugs.

## Overview

A Rust command-line tool for [SoloKeys Solo 1](https://solokeys.com/) hardware security keys.
It can update firmware, run FIDO2 operations, manage credentials, and flash firmware
through the bootloader or ST DFU at a low level.

---

## Building

```sh
cargo build --release
```

The binary is `target/release/solo`. Its old name was `solo1`.

### Workspace layout

| Crate          | Path                  | What it holds                                                                                      |
|----------------|-----------------------|----------------------------------------------------------------------------------------------------|
| `solo-ctaphid` | `crates/solo-ctaphid` | CTAPHID framing and the USB HID transport. Device-neutral.                                         |
| `solo-ctap2`   | `crates/solo-ctap2`   | CBOR helpers and CTAP2 protocol code (clientPIN, key agreement, request builders). Device-neutral. |
| `solo1`        | `crates/solo1`        | Solo 1 vendor commands, bootloader, ST DFU, firmware files and attestation fingerprints.           |
| `solo2`        | `crates/solo2`        | Solo 2 USB IDs and admin-app vendor commands (version, uuid, locked, rng).                         |
| `solo-cli`     | `crates/solo-cli`     | The `solo` binary: argument parsing, prompts, output, and firmware downloads.                      |

The device crates build on `solo-ctaphid`. They also use `solo-ctap2` where they need CTAP2.
Only `solo-cli` uses the terminal or the network.

### Supported devices

`solo ls` and every `solo key` command find both Solo 1 and Solo 2 keys.

These commands work on Solo 2 because they use only CTAPHID or CTAP2: `ping`, `wink`,
`reset`, `set-pin`, `change-pin`, `credential …`, `challenge-response` and `sign-file`.
`version` and `rng` also work. They use Solo 2 admin-app commands.

For now, these commands work on Solo 1 only: `verify`, `keyboard`, `probe`, `update` and
`disable-updates`. On a Solo 2 they stop with "not supported on Solo 2 yet" and send
nothing to the key.

`solo program` finds Solo 1 keys only. Solo 2 firmware updates are not implemented.
No Solo 2 support is tested on hardware yet.

---

## Usage

```sh
solo [OPTIONS] <COMMAND>
```

Global options:

| Flag               | Description                                                  |
|--------------------|--------------------------------------------------------------|
| `-v`, `--verbose`  | Enable verbose output (HID frames, bootloader packets, etc.) |
| `--timeout <SECS>` | Timeout in seconds for device responses (default: 30)        |

The `--json` flag works on commands that print structured output: `version`, `genkey`,
`ls`, `verify-file` and these `key` subcommands: `rng hexbytes`, `challenge-response`, `verify`,
`version`, `ping`, `probe`, `sign-file`, `credential info`, `credential ls` and `credential create`.
`sign` always prints JSON. `mergehex`, `monitor` and `program` print no structured output.
`sign`, `mergehex`, `monitor` and `program` have no `--json` flag.
The other `key` subcommands accept `--json` only to refuse it: they stop with an error before
they open a device. These are `rng raw`, `rng feedkernel`, `wink`, `keyboard`, `reset`,
`change-pin`, `set-pin`, `disable-updates`, `update` and `credential rm`.
With `--json`, `key sign-file` prints its progress lines to stderr, so stdout holds only the JSON object.
`key ping` prints one JSON object per line (one line for each ping).

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

### Key commands (`solo key [--serial <SN>]`)

```sh
solo key version                           # Get firmware version
solo key wink                              # Blink LED
solo key ping [--count N] [--data DATA]    # Ping and measure RTT (DATA: hex or plain text, default deadbeef; N default 1)
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
solo key sign-file <CREDENTIAL_ID> <FILE> [--host <HOST>]
                                           # Sign file with resident credential (ID is hex); writes FILE.sig and FILE.authdata
solo key update [--firmware FILE.json]     # Update firmware (downloads latest if omitted)
```

#### Credential management

```sh
solo key credential info                # Get credential slot info
solo key credential ls                  # List resident credentials
solo key credential rm <ID>             # Remove credential by base64 ID
solo key credential rm --host <HOST> --user <USER>
                                         # Remove credential by relying party and username
solo key credential create --host <HOST> --user <USER> [--prompt <TEXT>] [--public-key-out <FILE>]
                                         # Create FIDO2 credential with hmac-secret
```

`credential create` prints the credential ID. With `--public-key-out <FILE>`, it also writes the
public key of the new credential to FILE as PEM text. With `--json`, the JSON object has the extra
field `public_key_pem`. `solo` does not give the key of a credential that already exists, so save it
when you create the credential. You need it to check the signatures of `sign-file`. If the key
cannot be read, the error text holds the credential ID. If the file cannot be written, the error
text holds the PEM text.

#### Sign a file and check the signature

`sign-file` needs a credential that was made for the same host. The default host is `solokeys.dev`.
Use `--host <HOST>` for a credential that was made with another host. The signature has the form of
a WebAuthn assertion for that host, so use a credential that you make only for file signing.

```sh
solo key credential create --host solokeys.dev --user me --public-key-out pub.pem
solo key sign-file <CREDENTIAL_ID> FILE
solo key sign-file <CREDENTIAL_ID> FILE --host example.com   # for a credential made with --host example.com
```

`sign-file` sends the SHA-256 hash of the file to the key. The key does not sign this hash alone. It
signs the authenticator data followed by the hash (ES256, as in the CTAP2 specification).
`sign-file` writes two files next to the input file, and overwrites them if they exist:

- `FILE.sig`: the signature.
- `FILE.authdata`: the authenticator data that was signed.

To check the signature, you need the file, `FILE.sig`, `FILE.authdata` and the public key of the
credential. Get the public key with `credential create --public-key-out pub.pem`.

The simple way is `solo verify-file`. It needs no device:

```sh
solo verify-file --public-key pub.pem FILE
solo verify-file --public-key pub.pem FILE --host example.com   # if you signed with --host example.com
```

It reads `FILE.sig` and `FILE.authdata` by default. Use `--signature` and `--authdata` for other
names. The check passes only if all of these are true:

- The public key file is a P-256 public key in PEM text.
- The authenticator data has at least 37 bytes.
- The authenticator data is for the rpId given with `--host` (default `solokeys.dev`). Use the same
  host as with `sign-file`. The error names the host that was expected.
- The user-present flag is set.
- The signature is a valid DER ECDSA signature by that public key over the authenticator data
  followed by the SHA-256 hash of the file.
- Only with `--counter-above N`: the signature counter is greater than `N`. Use it to check that a
  new signature is newer than the last one you saw. A counter of 0 never passes, because 0 is not
  greater than any `N`. Some authenticators always send 0, as WebAuthn allows for a key without a
  counter. In the Solo 1 firmware source (4.1.5) the counter is one counter for all credentials. It
  is not 0, and it goes up by a random step of 1 to 16 with each signature. Not checked on a device.
  The tool keeps no state: your script must save the last counter. A gap between two counters is
  normal, so the check shows only that a signature is newer than `N`.

If a check fails, the command says which one and exits with a non-zero code. If all pass, it prints
that the signature is good, the rpId (the `--host` value), whether the user-verified flag is set,
and the signature counter. With `--json` it prints one JSON object with `rp_id`, `user_verified` and
`sign_count`. The exit code is the result, so there is no `valid` field. If a check fails, stdout is
empty and the error goes to stderr. This differs from `key verify --json`, which prints a report
with `signature_valid: false` and then fails. `verify-file` stops at the first failed check and has
no facts to report.

As a second way, you can run this OpenSSL command in bash or zsh. It checks only the signature, not
the rpId or the flags:

```bash
openssl dgst -sha256 -verify pub.pem -signature FILE.sig <(cat FILE.authdata; openssl dgst -sha256 -binary FILE)
```

A good result from `verify-file` shows that the holder of the private key of the credential signed
the hash of this file, and that the user-present flag is set in the signed data. It does not show
that the private key is in a Solo key, which device holds it, or when the file was signed.

`sign-file` uses the CTAP2 getAssertion command. It puts the SHA-256 hash of the file in the place of
the `clientDataHash`. A WebAuthn login for the same rpId has the same form: the key signs the
authenticator data followed by the hash of the client data JSON. Nothing in the signed bytes says
"file signature". So `verify-file` cannot tell a file signature from a WebAuthn login of the same
credential. For this reason:

- Make a credential only for file signing, for example
  `solo key credential create --host solokeys.dev --user signer --public-key-out pub.pem`.
  Do not use it to log in to a web site.
- Do not sign a file from an untrusted source with a credential that is also used for logins. A file
  that holds a client data JSON text gets a signature that a web site could take as a login.

This is not the `sign-file` of the Python tool (solo1-cli). From its source, not tried on a key: it
sends the hash with the command number `0x50`, takes the credential ID as base64, and writes only a
`.sig` file. Here the credential ID is hex and two files are written. The Solo 1 firmware 4.1.5
source has no command `0x50`. So a `.sig` file from this tool is not the output of the Python tool.

#### Challenge-response

```sh
solo key challenge-response <CREDENTIAL_ID> <CHALLENGE> [--host <HOST>]
# HMAC-secret challenge-response using an existing credential
# CREDENTIAL_ID: hex string from credential create output
# CHALLENGE: string to hash
# --host defaults to "solokeys.dev"
```

### Programming commands (`solo program [--serial <SN>]`)

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
solo genkey [-o OUTPUT] [--json]

# Sign firmware HEX file, output JSON {firmware, signature, versions}
solo sign <KEY.pem> <firmware.hex>

# Merge Intel HEX files
solo mergehex -o OUTPUT [--attestation-key FILE] [--attestation-cert FILE] INPUT...

# Monitor serial output
solo monitor <PORT>
```

---

## Firmware update notes

- Get firmware JSON files from the [solo1 releases page](https://github.com/solokeys/solo1/releases).
- The bootloader enforces **anti-rollback protection**. You cannot install a firmware version
  older than the one on the key.
- If you run `key update` without `--firmware`, it downloads the latest release.

---

## Key verification and SPKI fingerprints

`solo key verify` checks the key by making a FIDO2 credential. It then compares the
attestation certificate with known fingerprints. It computes two kinds of fingerprint:

- **Full-DER fingerprint** — SHA-256 of the complete certificate DER bytes. It changes
  when the certificate is reissued.
- **SPKI fingerprint** — SHA-256 of the `SubjectPublicKeyInfo` structure only. It stays
  the same when the certificate is renewed, if the key is the same. It is meant for
  certificate pinning in the future.

### Known SPKI fingerprints

| Device type          | SPKI fingerprint (SHA-256)                                                      |
|----------------------|---------------------------------------------------------------------------------|
| Solo Tap             | `6b50560fef4c768b6e9a7a7749415a7c01d39842be3e4f7b8e859ba2a4be7049`              |
| Solo 1               | not yet collected                                                               |
| Solo Mu              | not yet collected                                                               |
| Solo ≤v3.0.0         | not yet collected                                                               |
| Solo Hacker          | not yet collected                                                               |
| Emulation/simulation | not yet collected                                                               |

To get a missing value, run `solo key verify --json` with a real key. Read the
`spki_fingerprint` field in the output. If you have one of these devices, please send
us the value by opening an issue at
<https://github.com/InboundFrog/solo1-cli-rs/issues>.

Verification works without the SPKI fingerprints. Today the tool identifies devices by
the full-DER fingerprints. The SPKI values are kept for a future pinning mode. That mode
will accept a renewed certificate without a tool update.
