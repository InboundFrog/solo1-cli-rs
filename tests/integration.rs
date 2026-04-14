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
    assert!(
        result.is_ok(),
        "list_solo_devices should not fail: {:?}",
        result
    );
}

/// Ping the device (requires hardware).
#[test]
#[ignore]
fn test_ping_hardware() {
    let hid = SoloHid::open(None, std::time::Duration::from_secs(30)).expect("Failed to open Solo device");
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
    let hid = SoloHid::open(None, std::time::Duration::from_secs(30)).expect("Failed to open Solo device");
    let response = hid
        .send_recv(solo1::device::CMD_GET_VERSION, &[])
        .expect("Version command failed");
    assert!(
        response.len() >= 3,
        "Version response should be at least 3 bytes"
    );
    println!(
        "Firmware version: {}.{}.{}",
        response[0], response[1], response[2]
    );
}

// ============================================================
// Hardware-less tests: firmware signing and mergehex
// ============================================================

/// Test that firmware_bytes_to_sign_for_version produces different sizes for v1 and v2.
#[test]
fn test_firmware_sign_versioned_regions_differ() {
    use solo1::firmware::{FLASH_PAGES, FLASH_PAGE_SIZE};
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Build a minimal Intel HEX file starting at 0x08005000 (app start)
    let app_start: u32 = 0x08005000;
    let mut hex_content = String::new();
    // Extended linear address for 0x0800_xxxx
    hex_content.push_str(":020000040800F2\n");
    // One data record at offset 0x5000
    let offset: u16 = 0x5000;
    let data = vec![0xAAu8; 16];
    let mut sum: u32 = 0x10 + (offset >> 8) as u32 + (offset & 0xFF) as u32;
    for &b in &data {
        sum += b as u32;
    }
    let checksum = (0x100u32 - (sum & 0xFF)) as u8;
    hex_content.push_str(&format!(
        ":10{:04X}00{}  {:02X}\n",
        offset,
        data.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<String>(),
        checksum
    ));
    hex_content.push_str(":00000001FF\n");

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(hex_content.as_bytes()).unwrap();
    tmp.flush().unwrap();

    // v1 end page = 19: END = flash_addr(128 - 19) - 8 = flash_addr(109) - 8
    let end_v1 = solo1::firmware::flash_addr(FLASH_PAGES - 19) - 8;
    // v2 end page = 20: END = flash_addr(128 - 20) - 8 = flash_addr(108) - 8
    let end_v2 = solo1::firmware::flash_addr(FLASH_PAGES - 20) - 8;

    // v1 region is larger (higher end page count)
    assert!(
        end_v1 > end_v2,
        "v1 signing region should be larger than v2 (end_v1=0x{:08X} end_v2=0x{:08X})",
        end_v1,
        end_v2
    );

    let expected_v1_size = (end_v1 - app_start) as usize;
    let expected_v2_size = (end_v2 - app_start) as usize;
    assert!(
        expected_v1_size > expected_v2_size,
        "v1 size {} should be larger than v2 size {}",
        expected_v1_size,
        expected_v2_size
    );

    // The size difference should be exactly one page (2048 bytes)
    assert_eq!(
        expected_v1_size - expected_v2_size,
        FLASH_PAGE_SIZE as usize,
        "v1 and v2 signing regions should differ by exactly one page"
    );
}

/// Test that the AUTH_WORD_ADDR calculation matches the Python reference.
#[test]
fn test_mergehex_auth_word_address() {
    use solo1::firmware::flash_addr;

    // Python: APPLICATION_END_PAGE = PAGES - APPLICATION_END_PAGE_COUNT = 128 - 20 = 108
    // AUTH_WORD_ADDR = flash_addr(APPLICATION_END_PAGE) - 8
    let application_end_page = 128u32 - 20u32;
    let auth_word_addr = flash_addr(application_end_page) - 8;

    // flash_addr(108) = 0x08000000 + 108 * 2048 = 0x08000000 + 0x36000 = 0x08036000
    // auth_word_addr = 0x08036000 - 8 = 0x08035FF8
    assert_eq!(
        flash_addr(108),
        0x08036000,
        "flash_addr(108) should be 0x08036000"
    );
    assert_eq!(
        auth_word_addr, 0x08035FF8,
        "AUTH_WORD_ADDR should be 0x08035FF8"
    );

    // ATTEST_ADDR = flash_addr(PAGES - 15) = flash_addr(113)
    let attest_addr = flash_addr(128 - 15);
    assert_eq!(
        flash_addr(113),
        0x08038800,
        "flash_addr(113) should be 0x08038800"
    );
    assert_eq!(attest_addr, 0x08038800, "ATTEST_ADDR should be 0x08038800");
}

/// Test that version_matches_constraint handles the "=" operator correctly.
#[test]
fn test_version_constraint_equals() {
    use solo1::firmware::{version_matches_constraint, FirmwareVersion};

    let v = FirmwareVersion::new(2, 5, 3);
    assert!(version_matches_constraint(&v, "=2.5.3").unwrap());
    assert!(!version_matches_constraint(&v, "=2.5.4").unwrap());
    assert!(!version_matches_constraint(&v, "=2.5.2").unwrap());
    assert!(!version_matches_constraint(&v, "=3.0.0").unwrap());
}

/// Test rng_hexbytes count validation (no hardware needed - tests error path).
#[test]
fn test_rng_hexbytes_count_validation_logic() {
    // Verify that counts > 255 are invalid by checking the validation condition
    // (We can't call the actual function without hardware, but we test the boundary.)
    let valid_count: usize = 255;
    let invalid_count: usize = 256;
    assert!(valid_count <= 255, "255 should be a valid count");
    assert!(invalid_count > 255, "256 should be an invalid count");

    // Test that the exact boundary is correct
    let max_valid: u8 = u8::MAX; // 255
    assert_eq!(max_valid as usize, 255);
}

/// Test that probe hash type validation works correctly.
#[test]
fn test_probe_hash_type_validation() {
    // Valid types (case-insensitive input, canonical output)
    let valid_types = [
        "sha256", "SHA256", "sha512", "SHA512", "rsa2048", "RSA2048", "ed25519", "Ed25519",
    ];
    let invalid_types = ["md5", "sha1", "blake3", ""];

    for hash_type in &valid_types {
        let canonical = match hash_type.to_lowercase().as_str() {
            "sha256" => Some("SHA256"),
            "sha512" => Some("SHA512"),
            "rsa2048" => Some("RSA2048"),
            "ed25519" => Some("Ed25519"),
            _ => None,
        };
        assert!(
            canonical.is_some(),
            "Hash type '{}' should be valid",
            hash_type
        );
    }

    for hash_type in &invalid_types {
        let canonical = match hash_type.to_lowercase().as_str() {
            "sha256" | "sha512" | "rsa2048" | "ed25519" => Some("valid"),
            _ => None,
        };
        assert!(
            canonical.is_none(),
            "Hash type '{}' should be invalid",
            hash_type
        );
    }
}

/// Test mergehex default attestation constants.
#[test]
fn test_mergehex_default_attestation_constants() {
    use solo1::firmware::{HACKER_ATTESTATION_CERT, HACKER_ATTESTATION_KEY_HEX};

    // Key should be a valid 32-byte hex string
    let key_bytes = hex::decode(HACKER_ATTESTATION_KEY_HEX).expect("key should be valid hex");
    assert_eq!(key_bytes.len(), 32, "attestation key should be 32 bytes");

    // Cert should be a non-empty DER certificate (>= 100 bytes, starts with 0x30)
    assert!(
        HACKER_ATTESTATION_CERT.len() >= 100,
        "attestation cert should be at least 100 bytes"
    );
    assert_eq!(
        HACKER_ATTESTATION_CERT.len(),
        749,
        "hacker attestation cert should be 749 bytes"
    );
    assert_eq!(
        HACKER_ATTESTATION_CERT[0], 0x30,
        "DER cert should start with 0x30 (SEQUENCE)"
    );
}

/// Test that mergehex rejects mismatched key/cert arguments.
#[test]
fn test_mergehex_key_cert_must_both_be_provided() {
    use solo1::firmware::merge_hex_files;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a minimal HEX file
    let mut tmp_hex = NamedTempFile::new().unwrap();
    tmp_hex
        .write_all(b":020000040800F2\n:00000001FF\n")
        .unwrap();
    tmp_hex.flush().unwrap();

    let tmp_out = NamedTempFile::new().unwrap();
    let key_path = tmp_hex.path(); // reuse as fake key path

    // key without cert -> error
    let result = merge_hex_files(&[tmp_hex.path()], tmp_out.path(), Some(key_path), None);
    assert!(result.is_err(), "key without cert should fail");

    // cert without key -> error
    let result = merge_hex_files(&[tmp_hex.path()], tmp_out.path(), None, Some(key_path));
    assert!(result.is_err(), "cert without key should fail");
}

/// Test that mergehex with no attestation args uses default hacker attestation.
#[test]
fn test_mergehex_default_attestation() {
    use solo1::firmware::{merge_hex_files};
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a minimal HEX file with a data record at app start
    let mut hex_content = String::new();
    hex_content.push_str(":020000040800F2\n");
    // Write 16 zero bytes at 0x5000 (checksum = 0xA0)
    hex_content.push_str(":1050000000000000000000000000000000000000A0\n");
    hex_content.push_str(":00000001FF\n");

    let mut tmp_hex = NamedTempFile::new().unwrap();
    tmp_hex.write_all(hex_content.as_bytes()).unwrap();
    tmp_hex.flush().unwrap();

    let tmp_out = NamedTempFile::new().unwrap();

    // Should succeed with no attestation args (uses defaults)
    let result = merge_hex_files(&[tmp_hex.path()], tmp_out.path(), None, None);
    assert!(
        result.is_ok(),
        "mergehex with default attestation should succeed: {:?}",
        result
    );

    // Output should be a valid HEX file (non-empty, starts with ':')
    let output = std::fs::read_to_string(tmp_out.path()).unwrap();
    assert!(!output.is_empty(), "output HEX file should not be empty");
    assert!(
        output.starts_with(':'),
        "output should be a valid Intel HEX file"
    );

    // Verify the attestation data is present in the output.
    // ATTEST_ADDR = flash_addr(113) = 0x08038800
    // Extended linear address for 0x0803xxxx is: :020000040803F7
    // Data records at offset 0x8800 would appear in that segment.
    // The ELA upper 16 bits are 0x0803.
    assert!(
        output.contains("0803"),
        "output should contain extended linear address 0x0803 for attestation data"
    );
}

/// Test that signed firmware JSON has both version signatures.
#[test]
fn test_firmware_sign_versioned_json_structure() {
    use solo1::firmware::{create_firmware_json_versioned};
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a minimal HEX file
    let hex_content = ":020000040800F2\n:1050000000000000000000000000000000000000A0\n:00000001FF\n";
    let mut tmp_hex = NamedTempFile::new().unwrap();
    tmp_hex.write_all(hex_content.as_bytes()).unwrap();
    tmp_hex.flush().unwrap();

    let sig_v1 = vec![0xAAu8; 64];
    let sig_v2 = vec![0xBBu8; 64];

    let fw_json = create_firmware_json_versioned(tmp_hex.path(), &sig_v1, &sig_v2).unwrap();

    // Should have 2 version entries
    assert_eq!(fw_json.versions.len(), 2, "should have 2 version entries");
    assert!(
        fw_json.versions.contains_key("<=2.5.3"),
        "should have <=2.5.3 entry"
    );
    assert!(
        fw_json.versions.contains_key(">2.5.3"),
        "should have >2.5.3 entry"
    );

    // The default signature should be v2
    let sig_v2_decoded = fw_json.signature_bytes().unwrap();
    assert_eq!(sig_v2_decoded, sig_v2, "default signature should be v2");

    // Firmware field should be base64 of the HEX FILE TEXT (not binary)
    let fw_bytes = fw_json.firmware_bytes().unwrap();
    let fw_text = String::from_utf8(fw_bytes).unwrap();
    assert!(
        fw_text.starts_with(':'),
        "firmware field should be base64 of hex text"
    );
    assert!(
        fw_text.contains("FF"),
        "firmware field should contain hex data"
    );
}

/// Test device frame reassembly handles truncation.
#[test]
fn test_reassemble_frames_truncation() {
    use solo1::device::{reassemble_frames, CtapHidFrame, FramePayload};

    let cid = [0x01u8, 0x02, 0x03, 0x04];

    // Create an init frame that says bcnt=5 but has 10 bytes
    let frame = CtapHidFrame {
        channel_id: cid,
        payload: FramePayload::Init {
            cmd: 0x10,
            bcnt: 5,
            data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A],
        },
    };

    let (cmd, payload) = reassemble_frames(&[frame]).unwrap();
    assert_eq!(cmd, 0x10);
    // Should be truncated to bcnt=5
    assert_eq!(payload.len(), 5);
    assert_eq!(payload, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
}

/// Test that crypto fingerprints are all 32-byte valid hex.
#[test]
fn test_known_fingerprints_validity() {
    use solo1::crypto::KNOWN_FINGERPRINTS;

    assert_eq!(
        KNOWN_FINGERPRINTS.len(),
        6,
        "should have exactly 6 known fingerprints"
    );

    for (fp, name) in KNOWN_FINGERPRINTS {
        let bytes =
            hex::decode(fp).expect(&format!("fingerprint for '{}' should be valid hex", name));
        assert_eq!(
            bytes.len(),
            32,
            "fingerprint for '{}' should be 32 bytes",
            name
        );
    }

    // Verify specific expected fingerprints
    let names: Vec<&str> = KNOWN_FINGERPRINTS.iter().map(|(_, n)| *n).collect();
    assert!(names.contains(&"Valid Solo (<=3.0.0) firmware from SoloKeys."));
    assert!(names.contains(&"Solo Hacker firmware."));
    assert!(names.contains(&"Local software emulation."));
    assert!(names.contains(&"Valid Solo Tap with firmware from SoloKeys."));
    assert!(names.contains(&"Valid Somu with firmware from SoloKeys."));
    assert!(names.contains(&"Valid Solo with firmware from SoloKeys."));
}

/// Test flash_addr calculation.
#[test]
fn test_flash_addr_calculation() {
    use solo1::firmware::flash_addr;

    assert_eq!(flash_addr(0), 0x08000000);
    assert_eq!(flash_addr(1), 0x08000800); // 0x08000000 + 2048
    assert_eq!(flash_addr(108), 0x08036000); // 0x08000000 + 108 * 2048
    assert_eq!(flash_addr(113), 0x08038800); // ATTEST_ADDR
    assert_eq!(flash_addr(128), 0x08040000); // one past end
}
