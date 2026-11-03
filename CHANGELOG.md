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
