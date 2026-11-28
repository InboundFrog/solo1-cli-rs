use clap::Parser;
use solo_cli::cli::{AuxCommands, Cli, Commands, CredentialCommands, KeyCommands, ProgramCommands, RngCommands};
use solo_cli::commands::{aux, key, program, top};
use solo_cli::device::{Key, Model};
use solo_cli::error;
use solo_cli::output;

fn main() {
    if let Err(e) = ctrlc::set_handler(|| {
        eprintln!("\nInterrupted.");
        std::process::exit(130);
    }) {
        eprintln!("Warning: failed to set Ctrl-C handler: {e}");
    }

    let cli = Cli::parse();

    solo_cli::logger::init(cli.verbose);

    let result = run(cli);
    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> error::Result<()> {
    let timeout = std::time::Duration::from_secs(cli.timeout);

    match cli.command {
        Commands::Version { json } => {
            top::cmd_version(json)?;
        }

        Commands::Genkey { output, json } => {
            top::cmd_genkey(output.as_deref(), json)?;
        }

        Commands::VerifyFile {
            public_key,
            signature,
            authdata,
            file,
            json,
        } => {
            top::cmd_verify_file(
                &public_key,
                signature.as_deref(),
                authdata.as_deref(),
                &file,
                json,
                &mut std::io::stdout().lock(),
            )?;
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

/// The name of a `key` subcommand that has no JSON output, or `None` if `--json` works with it.
const fn json_unsupported(cmd: &KeyCommands) -> Option<&'static str> {
    match cmd {
        KeyCommands::Rng {
            command: RngCommands::Raw,
        } => Some("rng raw"),
        KeyCommands::Rng {
            command: RngCommands::Feedkernel,
        } => Some("rng feedkernel"),
        KeyCommands::Wink => Some("wink"),
        KeyCommands::Keyboard { .. } => Some("keyboard"),
        KeyCommands::Reset => Some("reset"),
        KeyCommands::ChangePin => Some("change-pin"),
        KeyCommands::SetPin => Some("set-pin"),
        KeyCommands::DisableUpdates => Some("disable-updates"),
        KeyCommands::Update { .. } => Some("update"),
        KeyCommands::Credential {
            command: CredentialCommands::Rm { .. },
        } => Some("credential rm"),
        KeyCommands::Rng {
            command: RngCommands::Hexbytes { .. },
        }
        | KeyCommands::Credential {
            command: CredentialCommands::Info | CredentialCommands::Ls | CredentialCommands::Create { .. },
        }
        | KeyCommands::ChallengeResponse { .. }
        | KeyCommands::Verify
        | KeyCommands::Version
        | KeyCommands::Ping { .. }
        | KeyCommands::Probe { .. }
        | KeyCommands::SignFile { .. } => None,
    }
}

fn refuse_json(cmd: &KeyCommands, json: bool) -> error::Result<()> {
    if json && let Some(name) = json_unsupported(cmd) {
        return Err(error::SoloError::Usage(format!(
            "`key {name}` has no JSON output, so `--json` is not accepted with it"
        )));
    }
    Ok(())
}

fn sign_file_to_stdio(
    hid: &impl solo_ctaphid::HidDevice,
    credential_id: &str,
    filename: &std::path::Path,
    json: bool,
) -> error::Result<()> {
    key::cmd_sign_file(
        hid,
        credential_id,
        filename,
        json,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

fn run_key_command(
    serial: Option<&str>,
    cmd: KeyCommands,
    json: bool,
    timeout: std::time::Duration,
) -> error::Result<()> {
    // Refuse `--json` first: no device is opened and nothing is sent to a key.
    refuse_json(&cmd, json)?;

    // Every key subcommand talks to a device, so open it once here.
    // Vendor commands depend on the model (Solo 1 and Solo 2 reuse codes), so
    // those arms check the model first. CTAPHID and CTAP2 commands work on any model.
    let key = Key::open(serial, timeout)?;
    let hid = &key.hid;
    match cmd {
        KeyCommands::Rng { command } => match command {
            RngCommands::Hexbytes { num } => {
                let hex = key::cmd_rng_hexbytes(hid, num)?;
                if json {
                    output::print_json(&output::RngOutput { bytes: hex })?;
                } else {
                    println!("{hex}");
                }
            }
            RngCommands::Raw => {
                key::cmd_rng_raw(hid)?;
            }
            RngCommands::Feedkernel => {
                key::cmd_rng_feedkernel(hid)?;
            }
        },

        KeyCommands::ChallengeResponse {
            credential_id,
            challenge,
            host,
        } => {
            key::cmd_challenge_response(hid, &credential_id, &challenge, &host, json)?;
        }

        KeyCommands::Verify => {
            // Only Solo 1 attestation fingerprints are known.
            key.require(Model::Solo1, "key verify")?;
            key::cmd_verify(hid, json)?;
        }

        KeyCommands::Version => match key.model {
            Model::Solo1 => key::cmd_key_version(hid, json)?,
            Model::Solo2 => key::cmd_key_version_solo2(hid, json)?,
        },

        KeyCommands::Wink => {
            key::cmd_wink(hid)?;
        }

        KeyCommands::Ping { count, data } => {
            // Use the data as hex bytes if it is valid hex. Otherwise use its UTF-8 bytes.
            let ping_data = hex::decode(&data).unwrap_or_else(|_| data.as_bytes().to_vec());
            key::cmd_ping(hid, count, &ping_data, json)?;
        }

        KeyCommands::Keyboard { data } => {
            key.require(Model::Solo1, "key keyboard")?;
            key::cmd_keyboard(hid, data.as_bytes())?;
        }

        KeyCommands::Reset => {
            key::cmd_reset(hid)?;
        }

        KeyCommands::ChangePin => {
            key::cmd_change_pin(hid)?;
        }

        KeyCommands::SetPin => {
            key::cmd_set_pin(hid)?;
        }

        KeyCommands::DisableUpdates => {
            key.require(Model::Solo1, "key disable-updates")?;
            key::cmd_disable_updates(hid)?;
        }

        KeyCommands::Probe { hash_type, filename } => {
            key.require(Model::Solo1, "key probe")?;
            key::cmd_probe(hid, &hash_type, &filename, json, &mut std::io::stdout().lock())?;
        }

        KeyCommands::SignFile {
            credential_id,
            filename,
        } => {
            sign_file_to_stdio(hid, &credential_id, &filename, json)?;
        }

        KeyCommands::Update { firmware } => {
            key.require(Model::Solo1, "key update")?;
            key::cmd_update(hid, firmware.as_deref(), serial, timeout)?;
        }

        KeyCommands::Credential { command } => match command {
            CredentialCommands::Info => {
                key::credential::cmd_credential_info(hid, json)?;
            }
            CredentialCommands::Ls => {
                key::credential::cmd_credential_ls(hid, json)?;
            }
            CredentialCommands::Rm {
                credential_id,
                host,
                user,
            } => {
                key::credential::cmd_credential_rm(hid, credential_id.as_deref(), host.as_deref(), user.as_deref())?;
            }
            CredentialCommands::Create {
                host,
                user,
                prompt,
                public_key_out,
            } => {
                key::cmd_make_credential(hid, &host, &user, &prompt, json, public_key_out.as_deref())?;
            }
        },
    }
    Ok(())
}

fn run_program_command(serial: Option<&str>, cmd: ProgramCommands, timeout: std::time::Duration) -> error::Result<()> {
    match cmd {
        ProgramCommands::Bootloader { firmware } => {
            let hid = solo1::open(serial, timeout)?;
            program::cmd_program_bootloader(&hid, &firmware)?;
        }

        ProgramCommands::Dfu { firmware } => {
            // DFU uses libusb directly, not HID
            program::cmd_program_dfu(&firmware)?;
        }

        // A device in ST DFU mode is not a HID device, so do not open one.
        ProgramCommands::Aux {
            command: AuxCommands::LeaveDfu,
        } => aux::cmd_leave_dfu()?,

        ProgramCommands::Aux { command } => {
            let hid = solo1::open(serial, timeout)?;
            match command {
                AuxCommands::EnterBootloader => aux::cmd_enter_bootloader(&hid)?,
                AuxCommands::LeaveBootloader => aux::cmd_leave_bootloader(&hid)?,
                AuxCommands::EnterDfu => aux::cmd_enter_dfu(&hid)?,
                // Handled above, without a HID device.
                AuxCommands::LeaveDfu => {}
                AuxCommands::Reboot => aux::cmd_reboot(&hid)?,
                AuxCommands::BootloaderVersion => aux::cmd_bootloader_version(&hid)?,
            }
        }
    }
    Ok(())
}

fn run_monitor(port: &str) -> error::Result<()> {
    println!("Monitoring serial port {port} at 115200 baud...");
    println!("Press Ctrl+C to stop.");

    let port = serialport::new(port, 115_200)
        .timeout(std::time::Duration::from_millis(100))
        .open()
        .map_err(|e| error::SoloError::DeviceError(format!("Serial port error: {e}")))?;

    copy_until_eof(port, std::io::stdout().lock())?;
    Ok(())
}

/// Copies bytes from `reader` to `writer` until the reader reports end of file.
///
/// Raw bytes are copied, so a read timeout in the middle of a line loses
/// nothing, and bytes that are not UTF-8 pass through unchanged. A timeout or
/// an interrupted read means "no data yet" and the loop goes on.
///
/// # Errors
///
/// Returns any read or write error other than a timeout or an interruption.
/// If the writer's pipe is closed (`BrokenPipe`), the copy stops with `Ok(())`.
fn copy_until_eof(mut reader: impl std::io::Read, mut writer: impl std::io::Write) -> std::io::Result<()> {
    use std::io::ErrorKind;

    let mut buf = [0_u8; 256];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => match writer
                .write_all(buf.get(..n).unwrap_or_default())
                .and_then(|()| writer.flush())
            {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::BrokenPipe => return Ok(()),
                Err(e) => return Err(e),
            },
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
            Err(e) => return Err(e),
        }
    }
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
    use super::*;

    #[test]
    fn udp_flag_is_rejected() {
        use clap::Parser;
        assert!(Cli::try_parse_from(["solo", "key", "--udp", "wink"]).is_err());
        assert!(Cli::try_parse_from(["solo", "program", "--udp", "aux", "reboot"]).is_err());
    }

    #[test]
    fn genkey_entropy_option_is_rejected() {
        use clap::Parser;
        assert!(Cli::try_parse_from(["solo", "genkey", "--entropy", "x"]).is_err());
    }

    #[test]
    fn json_is_refused_for_key_commands_without_json_output() {
        use clap::Parser;
        let name = |args: &[&str]| {
            let Commands::Key(k) = Cli::try_parse_from(args).unwrap().command else {
                panic!("not a key command");
            };
            json_unsupported(&k.command)
        };
        assert_eq!(name(&["solo", "key", "--json", "wink"]), Some("wink"));
        assert_eq!(name(&["solo", "key", "reset", "--json"]), Some("reset"));
        assert_eq!(name(&["solo", "key", "set-pin"]), Some("set-pin"));
        assert_eq!(name(&["solo", "key", "change-pin"]), Some("change-pin"));
        assert_eq!(name(&["solo", "key", "keyboard", "x"]), Some("keyboard"));
        assert_eq!(name(&["solo", "key", "update"]), Some("update"));
        assert_eq!(name(&["solo", "key", "disable-updates"]), Some("disable-updates"));
        assert_eq!(name(&["solo", "key", "rng", "raw"]), Some("rng raw"));
        assert_eq!(name(&["solo", "key", "rng", "feedkernel"]), Some("rng feedkernel"));
        assert_eq!(
            name(&["solo", "key", "credential", "rm", "--host", "h", "--user", "u"]),
            Some("credential rm")
        );
        assert_eq!(name(&["solo", "key", "version"]), None);
        assert!(refuse_json(&KeyCommands::Wink, false).is_ok());
        assert_eq!(name(&["solo", "key", "rng", "hexbytes", "4"]), None);
        assert_eq!(name(&["solo", "key", "credential", "ls"]), None);
    }

    /// The check runs before `Key::open`, so this needs no device.
    #[test]
    fn run_key_command_refuses_json_before_opening_a_device() {
        let err = run_key_command(None, KeyCommands::Wink, true, std::time::Duration::from_secs(1)).unwrap_err();
        assert!(matches!(err, error::SoloError::Usage(_)), "{err}");
        assert!(err.to_string().contains("`key wink` has no JSON output"), "{err}");
    }

    #[test]
    fn cli_timeout_default_is_30() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["solo", "ls"]).unwrap();
        assert_eq!(cli.timeout, 30);
    }

    #[test]
    fn copy_until_eof_keeps_all_bytes_across_timeouts() {
        use std::io::{Error, ErrorKind, Read};

        struct Fake(std::collections::VecDeque<std::io::Result<Vec<u8>>>);
        impl Read for Fake {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                match self.0.pop_front() {
                    None => Ok(0),
                    Some(Err(e)) => Err(e),
                    Some(Ok(v)) => {
                        buf[..v.len()].copy_from_slice(&v);
                        Ok(v.len())
                    }
                }
            }
        }

        let reader = Fake(
            vec![
                Ok(b"hel".to_vec()),
                Err(Error::from(ErrorKind::TimedOut)),
                Ok(vec![b'l', b'o', 0xff, 0xfe, b'\n']),
                Err(Error::from(ErrorKind::Interrupted)),
                Ok(b"end".to_vec()),
            ]
            .into(),
        );
        let mut out = Vec::new();
        copy_until_eof(reader, &mut out).unwrap();
        assert_eq!(out, b"hello\xff\xfe\nend");
    }

    #[test]
    fn copy_until_eof_stops_quietly_on_broken_pipe_but_reports_other_errors() {
        use std::io::{Error, ErrorKind, Write};

        struct Fail(ErrorKind);
        impl Write for Fail {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(Error::from(self.0))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        struct FlushFail;
        impl Write for FlushFail {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(Error::from(ErrorKind::BrokenPipe))
            }
        }

        copy_until_eof(&b"data"[..], FlushFail).unwrap();
        copy_until_eof(&b"data"[..], Fail(ErrorKind::BrokenPipe)).unwrap();
        let err = copy_until_eof(&b"data"[..], Fail(ErrorKind::PermissionDenied)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    }
}
