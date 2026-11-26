# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial Solo 2 support (not yet tested on hardware). `solo ls` lists Solo 1 and Solo 2 keys with a model column, and
  `solo key` opens either. CTAPHID and CTAP2 commands work on both, as do `version` and `rng`; Solo 1-only commands
  refuse to run on a Solo 2 instead of sending a vendor command code that means something else there.
- `crates/solo2`: Solo 2 USB IDs and admin-app vendor commands (version, uuid, locked, rng), with sources noted in the
  code.
- `DeviceFilter` gains `Fido` (FIDO usage page), `AllOf` and `AnyOf`; `HidDeviceInfo` and `HidTransport` report the
  device's USB IDs.

### Changed

- `key rng hexbytes N` keeps reading until it has N bytes (Solo 2 returns a fixed 57 per request) and errors on an empty
  response.
- Split the device-neutral CTAPHID transport from Solo 1 vendor commands: the `HidDevice` trait no longer has
  `send_bootloader_cmd` (now `solo1::bootloader::bootloader_cmd`), Solo 1 USB IDs and vendor command codes moved to
  `solo1::protocol`, and device lookup takes a `DeviceFilter`.
- Library modules no longer do terminal I/O: the PIN prompt moved from `ctap2` to the CLI (`maybe_pin_uv_auth` takes a
  PIN callback), firmware and DFU writes report progress through callbacks, `select_signature` is split into
  `read_bootloader_version` and `FirmwareJson::signature_for_bootloader`, and the GitHub release client moved to
  `github.rs`.
- Verbose output goes through the `log` facade instead of a global flag and the `vlog!` macro. `--verbose` shows debug
  records from this project's crates; other crates only show warnings and errors.
- The repository is now a Cargo workspace. Dependency versions and the clippy lint set are shared through
  `[workspace.dependencies]` and `[workspace.lints]`.
- The CTAPHID transport is its own crate, `crates/solo-ctaphid`, with its own error type. `MockDevice` is available to
  other crates' tests through its `test-util` feature.
- CBOR helpers and the CTAP2 protocol code (status codes, clientPIN, key agreement, request builders) are their own
  crate, `crates/solo-ctap2`, with its own error type. `maybe_pin_uv_auth` is generic over the PIN callback's error
  type.
- Solo 1 support (vendor commands, bootloader, ST DFU, firmware files, attestation fingerprints) is its own crate,
  `crates/solo1`, with its own error type. The root package is renamed `solo-cli` (library `solo_cli`) to free the
  `solo1` name; the binary is still `solo1`.
- **Breaking:** the binary is renamed from `solo1` to `solo`, ahead of support for other SoloKeys devices. The CLI crate
  moved to `crates/solo-cli` and the root `Cargo.toml` is now a workspace-only manifest.
- **Breaking:** `solo key verify` now exits with a non-zero code when the attestation signature is invalid or the
  certificate fingerprint is unknown. The report is still printed first. (#107)
- `HidTransport` fields are now private; use the new `info()` accessor to read device info. (#109)
- HEX merging uses a sorted flash image type instead of a hash map, with no change to the output. (#110)
- Known attestation fingerprints now live in one table that `check_attestation_fingerprint` uses. (#108)
- Authenticator data from makeCredential and getAssertion is now parsed by one typed parser. (#116)
- Added a typed text getter for CBOR maps and used it when parsing credential management responses. (#114)
- Simplified firmware version parsing and named the Solo 1 application start address. (#113)
- Updated Rust dependencies and stopped Dependabot from ignoring `rand` updates. (#115)
- Rewrote comments, `--help` text and the README in plain English, and corrected comments and README details that did
  not match the code. (#118, #119, #120, #121, #122)

### Removed

- **Breaking:** the `--udp` flags of `key` and `program` and the `--entropy` option of `genkey`. They were accepted but
  ignored. (#106)

### Fixed

- CTAP2 status messages were shifted by one code (for example, a wrong PIN was reported as "PIN blocked"). (#96)
- `solo sign` now signs a single SHA-256 digest and writes a raw 64-byte signature, as the Solo 1 bootloader expects.
  Sign again any firmware file that an earlier version of this tool signed. (#98)
- `solo sign` now writes firmware JSON version entries in a stable sorted order, and overlapping version constraints
  pick the same signature every time. (#97)
- `solo mergehex` now writes correct Intel HEX when an image crosses a 64 KiB boundary. (#100)
- `solo mergehex` now rejects attestation key files that are not 32 raw bytes or 64 hex digits, instead of writing a
  wrong key. (#99)
- CTAPHID receive now checks the INIT nonce, accepts only the expected channel, validates continuation sequence numbers,
  and rejects short messages and oversized frame data. (#111)
- `key reset` now reports an error when the key refuses the reset instead of claiming the credentials are gone. (#94)
- `solo monitor` no longer drops data when a read times out in the middle of a line, and no longer stops on bytes that
  are not valid UTF-8. A real read error now ends the command with a non-zero exit code. (#95)
- `program dfu` now erases flash, writes to the firmware's own addresses and no longer detaches at the end, and
  `program aux leave-dfu` works over ST DFU, following the reference tool. It now writes the option bytes (sets nBOOT0
  and clears nSWBOOT0) and no longer sends a bootloader reboot. Not yet tested on hardware. (#117)
- `set-pin` and `change-pin` now reject new PINs shorter than 4 characters or longer than 63 bytes, instead of cutting
  off PINs longer than 64 bytes, and no longer send an unused version query. (#104)
- `key update` now reconnects to the selected serial after entering the bootloader, honours `--timeout`, and retries
  until the device returns. While it retries, it prints each new error to stderr. (#103, #130)
- The `sign-file` help text now says that the credential id is hex. (#106)
- `key rng feedkernel` now prints the kernel entropy count as a decimal number, without a misleading `0x` prefix. (#102)
- Firmware writes to the Solo 1 bootloader now fail on a flash address overflow instead of repeatedly writing to the
  last address. (#112)
- `solo key rng raw` and `solo monitor` now end quietly with exit code 0 when the program reading their output closes
  the pipe, instead of printing a "Broken pipe" error and exiting with code 1. (#125)

### Security

- `solo genkey` now writes the private key to a new file that only the owner can read (mode 0600).
  An existing regular file at the path is removed first and never written into, so a program that opened the old file
  earlier cannot read the new key. A symbolic link or other non-regular path is refused. (#101, #128, #129)
- Firmware downloads now have timeouts, fail on an HTTP error status, and are limited to 8 MiB. (#105)
- PIN strings, the padded PIN block, the PIN hash and the ECDH shared secret are wiped from memory after use. (#104)

## [0.2.1] - 2026-04-14

### Added

- Feature to allow deleting credentials by `--host` and `--user` in addition to base64-encoded ID.
- Unit tests for credential removal CBOR encoding.

### Fixed

- Corrected CBOR encoding for credential removal.
- Improved confirmation prompt display for credential removal.

### Changed

- Refactored various code snippets identified by code inspections (removal of unused dependencies, unused path prefixes,
  etc.).
- Upgraded `rcgen` to 0.14.

## [0.2.0] - 2026-04-14

### Added

- Configurable `--timeout` flag for device I/O operations.
- Global Ctrl-C handler for graceful interruption.
- `--json` flag for structured output in key commands.
- Extraction and display of SPKI fingerprints in attestation verification.
- Certificate validity checking during attestation verification.
- Unit tests for ECDH key agreement and HMAC-secret input preparation.

### Changed

- Refactored `make-credential` as `key credential create`.
- Updated README to reflect current CLI state and SPKI fingerprint documentation.
- Improved error types and user-facing error messages across several commands.

### Fixed

- Corrected touch prompt ordering in `make-credential`.
- Made `--host` and `--user` required for `make-credential`.
- Added missing PIN token support in `make-credential`.

## [0.1.0] - 2026-04-13

### Added

- Initial Rust implementation of `solo1-cli`, providing a command-line interface for Solo 1 hardware security keys.
- Comprehensive CTAP2 protocol support:
    - `make-credential` (FIDO2) with `hmac-secret` support.
    - `get-assertion` for file signing and challenge-response.
    - `clientPIN` management (Set PIN, Change PIN).
    - `credentialManagement` support for listing and deleting credentials.
- Device maintenance commands:
    - `update` for firmware upgrades.
    - `reset` for destructive device reset (with confirmation prompt).
    - `wink`, `ping`, `verify`, and `version` for device identification and state check.
- Utility features:
    - `rng` commands for hex, raw bytes, and kernel entropy feeding.
    - `probe` command for low-level device testing.
    - `mergehex` for firmware preparation matching Python reference.
- CLI enhancements:
    - `--verbose` global option for detailed logging.
    - Versioned signatures matching Python reference implementation.
- Extensive unit tests for core functionality and regression prevention.

### Changed

- Refactored command structure into modular directories under `src/commands/key/` for better maintainability.
- Standardized CLI API for better compatibility with Python reference (e.g., `make-credential` options,
  `challenge-response` arguments).
- Improved Linux RNG entropy feeding using `RNDADDENTROPY` ioctl.

### Fixed

- Multiple bootloader protocol bugs identified via firmware source review.
- CTAPHID command matching logic (correctly handling high bit).
- Firmware writing logic to correctly parse Intel HEX from JSON.
- Attestation fingerprints and crypto implementation to match Python reference values.
- `cmd_verify` to include PIN authentication when a PIN is set on the device.

[0.2.1]: https://github.com/InboundFrog/solo1-cli-rs/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/InboundFrog/solo1-cli-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/InboundFrog/solo1-cli-rs/releases/tag/v0.1.0
