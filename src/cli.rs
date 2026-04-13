/// Clap CLI structure for the solo1 tool.
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "solo1",
    about = "CLI tool for SoloKeys Solo 1 hardware security keys",
    version
)]
pub struct Cli {
    /// Enable verbose output (HID frames, DFU status, bootloader packets, etc.)
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Print library version
    Version,

    /// Generate ECDSA P-256 keypair (PEM)
    Genkey {
        /// Output file for private key (default: stdout)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// File to read additional entropy from
        #[arg(long)]
        entropy: Option<PathBuf>,
    },

    /// Sign firmware hex file, output JSON {firmware, signature}
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

        /// Output HEX file
        #[arg(long, short = 'o', required = true)]
        output: PathBuf,

        /// Attestation key file
        #[arg(long)]
        attestation_key: Option<PathBuf>,

        /// Attestation certificate file
        #[arg(long)]
        attestation_cert: Option<PathBuf>,
    },

    /// List connected Solo devices
    Ls,

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

    /// Use UDP transport (for simulation)
    #[arg(long)]
    pub udp: bool,

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

    /// Create FIDO2 credential with hmac-secret
    MakeCredential {
        /// Relying party host (e.g., solokeys.dev)
        #[arg(long, default_value = "solokeys.dev")]
        host: String,
        /// User ID
        #[arg(long, default_value = "they")]
        user: String,
        /// PIN (prompted if not provided and key has PIN set)
        #[arg(long)]
        pin: Option<String>,
        /// Prompt text (use empty string to suppress, outputting only the credential_id)
        #[arg(long, default_value = "Touch your authenticator to generate a credential...")]
        prompt: String,
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
        /// User ID
        #[arg(long, default_value = "they")]
        user: String,
        /// PIN (prompted if not provided)
        #[arg(long)]
        pin: Option<String>,
    },

    /// Verify key authenticity via attestation
    Verify,

    /// Get firmware version from device
    Version,

    /// Blink LED
    Wink,

    /// Send ping and measure RTT
    Ping {
        /// Number of pings
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

    /// Calculate hash on device
    Probe {
        /// Hash type: sha256, sha512, rsa2048, ed25519
        hash_type: String,
    },

    /// Sign file with resident credential
    SignFile {
        /// Credential ID (base64-encoded from make-credential)
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

    /// Remove credential by ID
    Rm {
        /// Credential ID (hex)
        credential_id: String,
    },
}

/// Program subcommand with optional device selection.
#[derive(Args, Debug)]
pub struct ProgramArgs {
    /// Serial number of device to use
    #[arg(long)]
    pub serial: Option<String>,

    /// Use UDP transport (for simulation)
    #[arg(long)]
    pub udp: bool,

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
