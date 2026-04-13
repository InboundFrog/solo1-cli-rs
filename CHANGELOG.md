# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Standardized CLI API for better compatibility with Python reference (e.g., `make-credential` options, `challenge-response` arguments).
- Improved Linux RNG entropy feeding using `RNDADDENTROPY` ioctl.

### Fixed
- Multiple bootloader protocol bugs identified via firmware source review.
- CTAPHID command matching logic (correctly handling high bit).
- Firmware writing logic to correctly parse Intel HEX from JSON.
- Attestation fingerprints and crypto implementation to match Python reference values.
- `cmd_verify` to include PIN authentication when a PIN is set on the device.

[0.1.0]: https://github.com/InboundFrog/solo1-cli-rs/releases/tag/v0.1.0
