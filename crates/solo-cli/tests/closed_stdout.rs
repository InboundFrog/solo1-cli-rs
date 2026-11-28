#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Commands that print to stdout end quietly when the reader of stdout is gone.

use std::process::{Command, Stdio};

/// Runs `solo <args>` with stdout set to a pipe whose reader is already closed.
fn run_with_closed_stdout(args: &[&str]) {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = Command::new(env!("CARGO_BIN_EXE_solo"))
        .args(args)
        .stdout(Stdio::from(writer))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stderr, "", "stderr must stay empty");
    assert_eq!(out.status.code(), Some(141));
}

#[test]
fn version_ends_quietly_on_closed_stdout() {
    run_with_closed_stdout(&["version"]);
}

#[test]
fn version_json_ends_quietly_on_closed_stdout() {
    run_with_closed_stdout(&["version", "--json"]);
}
