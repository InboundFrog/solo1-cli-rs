use clap::Parser;
use solo1::cli::{
    AuxCommands, Cli, Commands, CredentialCommands, KeyCommands, ProgramCommands, RngCommands,
};
use solo1::commands::{aux, key, program, top};
use solo1::device::SoloHid;
use solo1::error;

fn main() {
    ctrlc::set_handler(|| {
        eprintln!("\nInterrupted.");
        std::process::exit(130);
    }).expect("failed to set Ctrl-C handler");

    let cli = Cli::parse();

    solo1::verbose::set_verbose(cli.verbose);

    let result = run(cli);
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> error::Result<()> {
    let timeout = std::time::Duration::from_secs(cli.timeout);

    match cli.command {
        Commands::Version { json } => {
            top::cmd_version(json)?;
        }

        Commands::Genkey { output, entropy, json } => {
            top::cmd_genkey(output.as_deref(), entropy.as_deref(), json)?;
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

        Commands::Ls { json } => {
            top::cmd_ls(json)?;
        }

        Commands::Key(key_args) => {
            run_key_command(key_args.serial.as_deref(), key_args.command, key_args.json, timeout)?;
        }

        Commands::Program(prog_args) => {
            run_program_command(prog_args.serial.as_deref(), prog_args.command, timeout)?;
        }

        Commands::Monitor { port } => {
            run_monitor(&port)?;
        }
    }
    Ok(())
}

fn run_key_command(serial: Option<&str>, cmd: KeyCommands, json: bool, timeout: std::time::Duration) -> error::Result<()> {
    match cmd {
        KeyCommands::Rng { command } => {
            // Open device for all RNG subcommands
            let hid = SoloHid::open(serial, timeout)?;
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

        KeyCommands::ChallengeResponse {
            credential_id,
            challenge,
            host,
            user: _,
            pin: _,
        } => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_challenge_response(&hid, &credential_id, &challenge, &host, json)?;
        }

        KeyCommands::Verify => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_verify(&hid, json)?;
        }

        KeyCommands::Version => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_key_version(&hid, json)?;
        }

        KeyCommands::Wink => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_wink(&hid)?;
        }

        KeyCommands::Ping { count, data } => {
            let hid = SoloHid::open(serial, timeout)?;
            // Parse data as hex if it looks like hex, otherwise use as UTF-8 bytes
            let ping_data = if data.chars().all(|c| c.is_ascii_hexdigit()) && data.len() % 2 == 0 {
                hex::decode(&data).unwrap_or_else(|_| data.as_bytes().to_vec())
            } else {
                data.as_bytes().to_vec()
            };
            key::cmd_ping(&hid, count, &ping_data)?;
        }

        KeyCommands::Keyboard { data } => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_keyboard(&hid, data.as_bytes())?;
        }

        KeyCommands::Reset => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_reset(&hid)?;
        }

        KeyCommands::ChangePin => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_change_pin(&hid)?;
        }

        KeyCommands::SetPin => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_set_pin(&hid)?;
        }

        KeyCommands::DisableUpdates => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_disable_updates(&hid)?;
        }

        KeyCommands::Probe {
            hash_type,
            filename,
        } => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_probe(&hid, &hash_type, &filename)?;
        }

        KeyCommands::SignFile {
            credential_id,
            filename,
        } => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_sign_file(&hid, &credential_id, &filename)?;
        }

        KeyCommands::Update { firmware } => {
            let hid = SoloHid::open(serial, timeout)?;
            key::cmd_update(&hid, firmware.as_deref())?;
        }

        KeyCommands::Credential { command } => {
            let hid = SoloHid::open(serial, timeout)?;
            match command {
                CredentialCommands::Info => {
                    key::credential::cmd_credential_info(&hid)?;
                }
                CredentialCommands::Ls => {
                    key::credential::cmd_credential_ls(&hid, json)?;
                }
                CredentialCommands::Rm { credential_id, host, user } => {
                    if credential_id.is_none() && host.is_none() {
                        eprintln!("Error: provide either a credential ID or --host and --user");
                        std::process::exit(1);
                    }
                    key::credential::cmd_credential_rm(
                        &hid,
                        credential_id.as_deref(),
                        host.as_deref(),
                        user.as_deref(),
                    )?;
                }
                CredentialCommands::Create {
                    host,
                    user,
                    pin: _,
                    prompt,
                } => {
                    key::cmd_make_credential(&hid, &host, &user, &prompt, json)?;
                }
            }
        }
    }
    Ok(())
}

fn run_program_command(serial: Option<&str>, cmd: ProgramCommands, timeout: std::time::Duration) -> error::Result<()> {
    match cmd {
        ProgramCommands::Bootloader { firmware } => {
            let hid = SoloHid::open_bootloader(serial, timeout)?;
            program::cmd_program_bootloader(&hid, &firmware)?;
        }

        ProgramCommands::Dfu { firmware } => {
            // DFU uses libusb directly, not HID
            program::cmd_program_dfu(&firmware)?;
        }

        ProgramCommands::Aux { command } => {
            let hid = SoloHid::open(serial, timeout)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_timeout_default_is_30() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["solo1", "ls"]).unwrap();
        assert_eq!(cli.timeout, 30);
    }
}
