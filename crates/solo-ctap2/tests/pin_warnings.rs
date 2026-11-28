#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The PIN is put into Unicode NFC form. When that changes it, a warning is logged.
//!
//! `log::set_logger` can be called once per process, so this file has its own
//! logger and one test.

use log::{Level, Log, Metadata, Record};
use solo_ctap2::ClientPinSession;
use std::sync::Mutex;

struct Recorder;

static WARNINGS: Mutex<Vec<String>> = Mutex::new(Vec::new());

impl Log for Recorder {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &Record<'_>) {
        if record.level() == Level::Warn {
            WARNINGS.lock().unwrap().push(record.args().to_string());
        }
    }
    fn flush(&self) {}
}

/// Runs `f` and returns the warnings it logged.
fn warnings_from(f: impl FnOnce()) -> Vec<String> {
    WARNINGS.lock().unwrap().clear();
    f();
    WARNINGS.lock().unwrap().clone()
}

#[test]
fn pin_that_changes_in_nfc_form_logs_a_warning_and_other_pins_do_not() {
    static RECORDER: Recorder = Recorder;
    log::set_logger(&RECORDER).unwrap();
    log::set_max_level(log::LevelFilter::Warn);

    let device_key = p256::SecretKey::from_slice(&[0x42; 32]).unwrap().public_key();
    let session = ClientPinSession::new(&device_key).unwrap();
    // "e" and a combining acute accent. NFC makes it the single character U+00E9.
    let decomposed = "pin-e\u{301}x";
    let composed = "pin-\u{e9}x";

    let w = warnings_from(|| {
        session.encrypt_pin(decomposed).unwrap();
    });
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(
        w[0].starts_with("The new PIN was converted to Unicode NFC form."),
        "{w:?}"
    );
    assert!(!w[0].contains("pin-"), "the warning must not hold PIN data: {w:?}");

    let w = warnings_from(|| {
        session.encrypt_pin_hash(decomposed).unwrap();
    });
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(
        w[0].starts_with("The PIN was converted to Unicode NFC form before use."),
        "{w:?}"
    );
    assert!(!w[0].contains("pin-"), "the warning must not hold PIN data: {w:?}");

    for pin in [composed, "plain-ascii-pin"] {
        let w = warnings_from(|| {
            session.encrypt_pin(pin).unwrap();
            session.encrypt_pin_hash(pin).unwrap();
        });
        assert!(w.is_empty(), "no warning expected for {pin:?}: {w:?}");
    }
}
