/// Clap CLI structure for the `solo` tool.
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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
        /// Credential ID (hex string from make-credential output)
        credential_id: String,
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
        /// Credential ID (hex-encoded)
        credential_id: String,
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
        /// Credential ID (base64); alternative to --host/--user
        #[arg(required_unless_present = "host")]
        credential_id: Option<String>,
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
    /// Serial number of device to use. For dfu and aux leave-dfu: the USB serial of the ST DFU device
    /// (0483:df11), which may not be the serial that solo ls shows. Needed when more than one is connected.
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
