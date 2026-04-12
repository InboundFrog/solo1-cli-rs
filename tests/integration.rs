/// Integration tests for solo1-cli-rs.
///
/// Tests marked `#[ignore]` require actual hardware (a Solo 1 device plugged in).
/// Run hardware tests with: `cargo test -- --ignored`

use solo1::device::{list_solo_devices, SoloHid};

/// Test that we can list devices (returns empty list without hardware, not an error).
#[test]
fn test_list_devices_no_hardware() {
    // This should not panic or return an error even when no device is present.
    // It may return an empty list.
    let result = list_solo_devices();
    // We don't assert a particular count because hardware may or may not be present.
    // We just verify it doesn't error out.
    assert!(result.is_ok(), "list_solo_devices should not fail: {:?}", result);
}

/// Ping the device (requires hardware).
#[test]
#[ignore]
fn test_ping_hardware() {
    let hid = SoloHid::open(None).expect("Failed to open Solo device");
    let data = b"hello";
    let response = hid
        .send_recv(solo1::device::CTAPHID_PING, data)
        .expect("Ping failed");
    assert_eq!(response, data, "Ping response should match sent data");
}

/// Get firmware version (requires hardware).
#[test]
#[ignore]
fn test_version_hardware() {
    let hid = SoloHid::open(None).expect("Failed to open Solo device");
    let response = hid
        .send_recv(solo1::device::CMD_GET_VERSION, &[])
        .expect("Version command failed");
    assert!(response.len() >= 3, "Version response should be at least 3 bytes");
    println!(
        "Firmware version: {}.{}.{}",
        response[0], response[1], response[2]
    );
}
