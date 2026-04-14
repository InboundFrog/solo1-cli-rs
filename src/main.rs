use clap::Parser;
use solo1::cli::{
    AuxCommands, Cli, Commands, CredentialCommands, KeyCommands, ProgramCommands, RngCommands,
};
use solo1::commands::{aux, key, program, top};
use solo1::device::SoloHid;
use solo1::error;

fn main() {
    let cli = Cli::parse();

    solo1::verbose::set_verbose(cli.verbose);

    let json = cli.json;
    let result = run(cli, json);
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli, json: bool) -> error::Result<()> {
    match cli.command {
        Commands::Version => {
            top::cmd_version();
        }

        Commands::Genkey { output, entropy } => {
            top::cmd_genkey(output.as_deref(), entropy.as_deref())?;
        }

        Commands::Sign { key, firmware_hex } => {
            top::cmd_sign(&key, &firmware_hex)?;
        }

        Commands::Mergehex {
            inputs,
            output,
            attestation_key,
            attestation_cert,
        } => {
            top::cmd_mergehex(
                &inputs,
                &output,
                attestation_key.as_deref(),
                attestation_cert.as_deref(),
            )?;
        }

        Commands::Ls => {
            top::cmd_ls(json)?;
        }

        Commands::Key(key_args) => {
            run_key_command(key_args.serial.as_deref(), key_args.command, json)?;
        }

        Commands::Program(prog_args) => {
            run_program_command(prog_args.serial.as_deref(), prog_args.command)?;
        }

        Commands::Monitor { port } => {
            run_monitor(&port)?;
        }
    }
    Ok(())
}

fn run_key_command(serial: Option<&str>, cmd: KeyCommands, json: bool) -> error::Result<()> {
    match cmd {
        KeyCommands::Rng { command } => {
            // Open device for all RNG subcommands
            let hid = SoloHid::open(serial)?;
            match command {
                RngCommands::Hexbytes { num } => {
                    let hex = key::cmd_rng_hexbytes(&hid, num)?;
                    println!("{}", hex);
                }
                RngCommands::Raw => {
                    key::cmd_rng_raw(&hid)?;
                }
                RngCommands::Feedkernel => {
                    key::cmd_rng_feedkernel(&hid)?;
                }
            }
        }

        KeyCommands::MakeCredential {
            host,
            user,
            pin: _,
            prompt,
        } => {
            let hid = SoloHid::open(serial)?;
            key::cmd_make_credential(&hid, &host, &user, &prompt, json)?;
        }

        KeyCommands::ChallengeResponse {
            credential_id,
            challenge,
            host,
            user: _,
            pin: _,
        } => {
            let hid = SoloHid::open(serial)?;
            key::cmd_challenge_response(&hid, &credential_id, &challenge, &host, json)?;
        }

        KeyCommands::Verify => {
            let hid = SoloHid::open(serial)?;
            key::cmd_verify(&hid, json)?;
        }

        KeyCommands::Version => {
            let hid = SoloHid::open(serial)?;
            key::cmd_key_version(&hid, json)?;
        }

        KeyCommands::Wink => {
            let hid = SoloHid::open(serial)?;
            key::cmd_wink(&hid)?;
        }

        KeyCommands::Ping { count, data } => {
            let hid = SoloHid::open(serial)?;
            // Parse data as hex if it looks like hex, otherwise use as UTF-8 bytes
            let ping_data = if data.chars().all(|c| c.is_ascii_hexdigit()) && data.len() % 2 == 0 {
                hex::decode(&data).unwrap_or_else(|_| data.as_bytes().to_vec())
            } else {
                data.as_bytes().to_vec()
            };
            key::cmd_ping(&hid, count, &ping_data)?;
        }

        KeyCommands::Keyboard { data } => {
            let hid = SoloHid::open(serial)?;
            key::cmd_keyboard(&hid, data.as_bytes())?;
        }

        KeyCommands::Reset => {
            let hid = SoloHid::open(serial)?;
            key::cmd_reset(&hid)?;
        }

        KeyCommands::ChangePin => {
            let hid = SoloHid::open(serial)?;
            key::cmd_change_pin(&hid)?;
        }

        KeyCommands::SetPin => {
            let hid = SoloHid::open(serial)?;
            key::cmd_set_pin(&hid)?;
        }

        KeyCommands::DisableUpdates => {
            let hid = SoloHid::open(serial)?;
            key::cmd_disable_updates(&hid)?;
        }

        KeyCommands::Probe {
            hash_type,
            filename,
        } => {
            let hid = SoloHid::open(serial)?;
            key::cmd_probe(&hid, &hash_type, &filename)?;
        }

        KeyCommands::SignFile {
            credential_id,
            filename,
        } => {
            let hid = SoloHid::open(serial)?;
            key::cmd_sign_file(&hid, &credential_id, &filename)?;
        }

        KeyCommands::Update { firmware } => {
            let hid = SoloHid::open(serial)?;
            key::cmd_update(&hid, firmware.as_deref())?;
        }

        KeyCommands::Credential { command } => {
            let hid = SoloHid::open(serial)?;
            match command {
                CredentialCommands::Info => {
                    key::credential::cmd_credential_info(&hid)?;
                }
                CredentialCommands::Ls => {
                    key::credential::cmd_credential_ls(&hid, json)?;
                }
                CredentialCommands::Rm { credential_id } => {
                    key::credential::cmd_credential_rm(&hid, &credential_id)?;
                }
            }
        }
    }
    Ok(())
}

fn run_program_command(serial: Option<&str>, cmd: ProgramCommands) -> error::Result<()> {
    match cmd {
        ProgramCommands::Bootloader { firmware } => {
            let hid = SoloHid::open_bootloader(serial)?;
            program::cmd_program_bootloader(&hid, &firmware)?;
        }

        ProgramCommands::Dfu { firmware } => {
            // DFU uses libusb directly, not HID
            program::cmd_program_dfu(&firmware)?;
        }

        ProgramCommands::Aux { command } => {
            let hid = SoloHid::open(serial)?;
            match command {
                AuxCommands::EnterBootloader => aux::cmd_enter_bootloader(&hid)?,
                AuxCommands::LeaveBootloader => aux::cmd_leave_bootloader(&hid)?,
                AuxCommands::EnterDfu => aux::cmd_enter_dfu(&hid)?,
                AuxCommands::LeaveDfu => aux::cmd_leave_dfu(&hid)?,
                AuxCommands::Reboot => aux::cmd_reboot(&hid)?,
                AuxCommands::BootloaderVersion => aux::cmd_bootloader_version(&hid)?,
            }
        }
    }
    Ok(())
}

fn run_monitor(port: &str) -> error::Result<()> {
    use std::io::{BufRead, BufReader};

    println!("Monitoring serial port {} at 115200 baud...", port);
    println!("Press Ctrl+C to stop.");

    let port = serialport::new(port, 115200)
        .timeout(std::time::Duration::from_millis(100))
        .open()
        .map_err(|e| error::SoloError::DeviceError(format!("Serial port error: {}", e)))?;

    let reader = BufReader::new(port);
    for line in reader.lines() {
        match line {
            Ok(l) => println!("{}", l),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                // Timeout is normal for serial; keep reading
                continue;
            }
            Err(e) => {
                eprintln!("Read error: {}", e);
                break;
            }
        }
    }
    Ok(())
}
