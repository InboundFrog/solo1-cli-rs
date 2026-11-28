/// Clap CLI structure for the `solo` tool.
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Help text for every credential id argument. Keep it in one place so that the commands agree.
const CREDENTIAL_ID_HELP: &str = "Credential ID, as hex or base64. A text of only hex digits with an even length is read as hex; anything else is read as base64 (standard or URL-safe, with or without padding)";

/// Same rule for `credential rm`, where the id is an alternative to `--host` and `--user`.
const CREDENTIAL_ID_RM_HELP: &str = "Credential ID, as hex or base64; alternative to --host/--user. A text of only hex digits with an even length is read as hex; anything else is read as base64 (standard or URL-safe, with or without padding)";

/// The bytes of a credential id. A newtype, because clap reads a plain `Vec<u8>` as a list of values.
#[derive(Clone, Debug)]
pub struct CredentialId(pub Vec<u8>);

impl std::ops::Deref for CredentialId {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// Read a credential id from the command line.
///
/// A text of only hex digits (0-9, a-f, A-F) with an even length is read as hex. Anything else is read
/// as base64: standard or URL-safe alphabet, with or without padding. The two forms overlap: a base64
/// text that happens to be made of hex digits only, with an even length, is read as hex.
///
/// # Errors
/// Returns a message that names both forms if the text is empty or is neither hex nor base64.
pub fn parse_credential_id(text: &str) -> Result<CredentialId, String> {
    use base64::Engine as _;
    use base64::alphabet::{STANDARD, URL_SAFE};
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

    if text.is_empty() {
        return Err("the credential ID is empty; give it as hex or base64".into());
    }
    if text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex::decode(text)
            .map(CredentialId)
            .map_err(|e| format!("invalid hex credential ID: {e}"));
    }
    let config = GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
    let bytes = GeneralPurpose::new(&STANDARD, config)
        .decode(text)
        .or_else(|_| GeneralPurpose::new(&URL_SAFE, config).decode(text))
        .map_err(|_| "the credential ID is neither valid hex nor valid base64".to_owned())?;
    Ok(CredentialId(bytes))
}

#[derive(Parser, Debug)]
#[command(name = "solo", about = "CLI tool for SoloKeys hardware security keys", version)]
pub struct Cli {
    /// Show verbose output, such as HID frames, DFU status and bootloader packets
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Timeout in seconds for device responses (default: 30)
    #[arg(long, global = true, default_value = "30")]
    pub timeout: u64,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Print library version
    Version {
        /// Output results as JSON (for scripting)
        #[arg(long)]
        json: bool,
    },

    /// Generate ECDSA P-256 keypair (PEM)
    Genkey {
        /// Output file for private key (default: stdout)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Output results as JSON (for scripting)
        #[arg(long)]
        json: bool,
    },

    /// Check the signature that `key sign-file` made for a file. No device is needed
    VerifyFile {
        /// The public key of the credential (PEM text, P-256). `key credential create --public-key-out` writes it
        #[arg(long, value_name = "PEM")]
        public_key: PathBuf,

        /// The signature file. Default: the input file name with `.sig` added
        #[arg(long, value_name = "FILE")]
        signature: Option<PathBuf>,

        /// The authenticator data file. Default: the input file name with `.authdata` added
        #[arg(long, value_name = "FILE")]
        authdata: Option<PathBuf>,

        /// The file that was signed
        file: PathBuf,
    },

    /// Sign a firmware HEX file and print JSON with firmware, signature and versions
    Sign {
        /// Path to PEM private key
        key: PathBuf,

        /// Path to firmware Intel HEX file
        firmware_hex: PathBuf,
    },

    /// Merge Intel HEX files
    Mergehex {
        /// Input HEX files
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output HEX file. On Unix, with --attestation-key it holds the
        /// private key, so it is written as a new file with mode 0600 and a
        /// symbolic link at this path is refused
        #[arg(long, short = 'o', required = true)]
        output: PathBuf,

        /// Attestation key file: 32 raw bytes, or 64 hex digits as text
        #[arg(long)]
        attestation_key: Option<PathBuf>,

        /// Attestation certificate file
        #[arg(long)]
        attestation_cert: Option<PathBuf>,
    },

    /// List connected Solo devices
    Ls {
        /// Output results as JSON (for scripting)
        #[arg(long)]
        json: bool,
    },

    /// Key interaction commands
    Key(KeyArgs),

    /// Programming commands
    Program(ProgramArgs),

    /// Monitor serial output
    Monitor {
        /// Serial port path
        port: String,
    },
}

/// Key subcommand with optional device selection.
#[derive(Args, Debug)]
pub struct KeyArgs {
    /// Serial number of device to use
    #[arg(long)]
    pub serial: Option<String>,

    /// Output results as JSON (for scripting)
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: KeyCommands,
}

#[derive(Subcommand, Debug)]
pub enum KeyCommands {
    /// Random number generation
    Rng {
        #[command(subcommand)]
        command: RngCommands,
    },

    /// HMAC-secret challenge-response
    ChallengeResponse {
        #[arg(help = CREDENTIAL_ID_HELP, value_parser = parse_credential_id)]
        credential_id: CredentialId,
        /// Challenge/secret string to hash
        challenge: String,
        /// Relying party host
        #[arg(long, default_value = "solokeys.dev")]
        host: String,
    },

    /// Verify key authenticity via attestation
    Verify,

    /// Get firmware version from device
    Version,

    /// Blink LED
    Wink,

    /// Send a ping and measure the round-trip time (RTT)
    Ping {
        /// Number of pings to send
        #[arg(long, default_value = "1")]
        count: u32,

        /// Ping data (hex string or plain text)
        #[arg(long, default_value = "deadbeef")]
        data: String,
    },

    /// Program keyboard sequence (max 64 bytes)
    Keyboard {
        /// Data to program (as string)
        data: String,
    },

    /// Factory reset (destructive)
    Reset,

    /// Change existing PIN
    ChangePin,

    /// Set PIN on unpinned key
    SetPin,

    /// Permanently disable firmware updates
    DisableUpdates,

    /// Calculate a hash on the device
    Probe {
        /// Hash type: SHA256, SHA512, RSA2048, Ed25519 (case-insensitive)
        hash_type: String,
        /// File to hash (must be <= 6144 bytes)
        filename: PathBuf,
    },

    /// Sign a file with a resident credential
    SignFile {
        #[arg(help = CREDENTIAL_ID_HELP, value_parser = parse_credential_id)]
        credential_id: CredentialId,
        /// File to sign
        filename: PathBuf,
    },

    /// Update firmware
    Update {
        /// Path to firmware JSON (default: download latest)
        #[arg(long)]
        firmware: Option<PathBuf>,
    },

    /// Credential management
    Credential {
        #[command(subcommand)]
        command: CredentialCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum RngCommands {
    /// Print N random bytes as hex
    Hexbytes {
        /// Number of bytes
        num: usize,
    },

    /// Stream raw entropy to stdout
    Raw,

    /// Feed entropy to /dev/random (Linux only)
    Feedkernel,
}

#[derive(Subcommand, Debug)]
pub enum CredentialCommands {
    /// Get credential slot info
    Info,

    /// List resident credentials
    Ls,

    /// Remove a resident credential
    Rm {
        #[arg(required_unless_present = "host", help = CREDENTIAL_ID_RM_HELP, value_parser = parse_credential_id)]
        credential_id: Option<CredentialId>,
        /// Relying party host (requires --user)
        #[arg(long, requires = "user")]
        host: Option<String>,
        /// Username (requires --host)
        #[arg(long, requires = "host")]
        user: Option<String>,
    },

    /// Create FIDO2 credential with hmac-secret
    Create {
        /// Relying party host (e.g., example.com)
        #[arg(long)]
        host: String,
        /// User ID / username
        #[arg(long)]
        user: String,
        /// Prompt text. Use an empty string to hide it and print only the `credential_id`
        #[arg(long, default_value = "Touch your authenticator to generate a credential...")]
        prompt: String,
        /// Write the public key of the new credential to this file (PEM text). You need this file to check the signatures of `sign-file`
        #[arg(long, value_name = "FILE")]
        public_key_out: Option<PathBuf>,
    },
}

/// Program subcommand with optional device selection.
#[derive(Args, Debug)]
pub struct ProgramArgs {
    /// Serial number of device to use
    #[arg(long)]
    pub serial: Option<String>,

    #[command(subcommand)]
    pub command: ProgramCommands,
}

#[derive(Subcommand, Debug)]
pub enum ProgramCommands {
    /// Program via Solo bootloader
    Bootloader {
        /// Path to firmware JSON file
        firmware: PathBuf,
    },

    /// Program via ST DFU
    Dfu {
        /// Path to firmware HEX file
        firmware: PathBuf,
    },

    /// Auxiliary bootloader commands
    Aux {
        #[command(subcommand)]
        command: AuxCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuxCommands {
    /// Switch to bootloader mode
    EnterBootloader,

    /// Switch back to firmware
    LeaveBootloader,

    /// Switch to ST DFU mode
    EnterDfu,

    /// Leave ST DFU
    LeaveDfu,

    /// Reboot device
    Reboot,

    /// Get bootloader version
    BootloaderVersion,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::cast_possible_truncation
    )]
    use super::{Cli, Commands, CredentialCommands, KeyCommands, parse_credential_id};
    use clap::Parser as _;

    /// Bytes that give `+`, `/`, `-` and `_` in the base64 forms: 0xfb 0xff 0xbf 0xfe.
    const BYTES: [u8; 4] = [0xfb, 0xff, 0xbf, 0xfe];

    #[test]
    fn hex_is_read_as_hex() {
        assert_eq!(parse_credential_id("fbffbffe").unwrap().0, BYTES);
    }

    #[test]
    fn hex_in_mixed_case_is_read_as_hex() {
        assert_eq!(parse_credential_id("FbFfBfFe").unwrap().0, BYTES);
    }

    #[test]
    fn standard_base64_with_padding() {
        // 5 bytes, so the standard form has one `=`.
        assert_eq!(
            parse_credential_id("+/+//vo=").unwrap().0,
            [0xfb, 0xff, 0xbf, 0xfe, 0xfa]
        );
    }

    #[test]
    fn standard_base64_without_padding() {
        assert_eq!(
            parse_credential_id("+/+//vo").unwrap().0,
            [0xfb, 0xff, 0xbf, 0xfe, 0xfa]
        );
    }

    #[test]
    fn url_safe_base64_with_and_without_padding() {
        let want = [0xfb, 0xff, 0xbf, 0xfe, 0xfa];
        assert_eq!(parse_credential_id("-_-__vo=").unwrap().0, want);
        assert_eq!(parse_credential_id("-_-__vo").unwrap().0, want);
    }

    #[test]
    fn firmware_sized_id_from_credential_ls_is_read_as_base64() {
        // The 70-byte id used in the credential tests, in the form `credential ls` prints.
        let b64 = "6T35dsdagAWH0ly+ogGh/TUM8cq3GbuYX9JAuUsDrRVTsRrEkdnTcSxj97jWz634bQV9CZ04Ikbb6ch/Ez7RZ4gbaA8AAA==";
        assert_eq!(parse_credential_id(b64).unwrap().0.len(), 70);
    }

    /// The two forms overlap. "abcd" is valid hex (2 bytes) and valid base64 (3 bytes). It is read as hex.
    #[test]
    fn text_that_is_both_hex_and_base64_is_read_as_hex() {
        assert_eq!(parse_credential_id("abcd").unwrap().0, [0xab, 0xcd]);
    }

    /// An odd number of hex digits cannot be hex, so it is read as base64 ("abc" gives two bytes).
    #[test]
    fn odd_length_hex_digits_are_read_as_base64() {
        assert_eq!(parse_credential_id("abc").unwrap().0, [0x69, 0xb7]);
    }

    #[test]
    fn empty_is_an_error() {
        let e = parse_credential_id("").unwrap_err();
        assert!(e.contains("empty"), "{e}");
    }

    #[test]
    fn padding_only_is_an_error() {
        assert!(parse_credential_id("====").is_err());
    }

    #[test]
    fn invalid_text_names_both_forms() {
        let e = parse_credential_id("not a credential id!").unwrap_err();
        assert!(e.contains("hex") && e.contains("base64"), "{e}");
    }

    #[test]
    fn mixed_alphabets_are_an_error() {
        assert!(parse_credential_id("+_+//vo=").is_err());
    }

    #[test]
    fn all_three_commands_take_both_forms() {
        for text in ["fbffbffe", "+/+//g=="] {
            let key = |args: &[&str]| match Cli::try_parse_from(args).unwrap().command {
                Commands::Key(k) => k.command,
                other => panic!("{other:?}"),
            };
            let KeyCommands::ChallengeResponse { credential_id, .. } =
                key(&["solo", "key", "challenge-response", text, "c"])
            else {
                panic!()
            };
            assert_eq!(credential_id.0.len(), 4, "{text}");
            let KeyCommands::SignFile { credential_id, .. } = key(&["solo", "key", "sign-file", text, "f"]) else {
                panic!()
            };
            assert_eq!(credential_id.0.len(), 4, "{text}");
            let KeyCommands::Credential {
                command: CredentialCommands::Rm { credential_id, .. },
            } = key(&["solo", "key", "credential", "rm", text])
            else {
                panic!()
            };
            assert_eq!(credential_id.unwrap().0.len(), 4, "{text}");
        }
    }

    #[test]
    fn bad_credential_id_is_rejected_by_clap() {
        assert!(Cli::try_parse_from(["solo", "key", "sign-file", "!!", "f"]).is_err());
    }
}
