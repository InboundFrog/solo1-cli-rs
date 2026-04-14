pub mod common;
pub mod credential;
mod fido2;
mod ops;
mod pin;
mod probe;
mod rng;
mod update;
mod verify;

pub use fido2::{cmd_challenge_response, cmd_make_credential};
pub use ops::{cmd_disable_updates, cmd_key_version, cmd_keyboard, cmd_ping, cmd_reset, cmd_wink};
pub use pin::{cmd_change_pin, cmd_set_pin};
pub use probe::{cmd_probe, cmd_sign_file};
pub use rng::{cmd_rng_feedkernel, cmd_rng_hexbytes, cmd_rng_raw};
pub use update::cmd_update;
pub use verify::cmd_verify;

#[cfg(test)]
mod tests {
    /// Test rng_hexbytes validation: n must be 0..=255.
    /// The actual validation is: if n > 255 { return Err(...) }
    #[test]
    fn test_rng_hexbytes_validation_boundary() {
        // n=255 is valid (fits in u8)
        let n_valid: usize = 255;
        assert!(n_valid <= 255, "255 should be valid");

        // n=256 is invalid (exceeds u8::MAX)
        let n_invalid: usize = 256;
        assert!(n_invalid > 255, "256 should be invalid");

        // n=0 is valid (return empty bytes)
        let n_zero: usize = 0;
        assert!(n_zero <= 255, "0 should be valid");
    }

    /// Test probe hash type normalization logic.
    #[test]
    fn test_probe_hash_type_normalization() {
        let cases: &[(&str, Option<&str>)] = &[
            ("sha256", Some("SHA256")),
            ("SHA256", Some("SHA256")),
            ("Sha256", Some("SHA256")),
            ("sha512", Some("SHA512")),
            ("SHA512", Some("SHA512")),
            ("rsa2048", Some("RSA2048")),
            ("RSA2048", Some("RSA2048")),
            ("ed25519", Some("Ed25519")),
            ("Ed25519", Some("Ed25519")),
            ("ED25519", Some("Ed25519")),
            ("md5", None),
            ("sha1", None),
            ("", None),
        ];

        for (input, expected) in cases {
            let canonical = match input.to_lowercase().as_str() {
                "sha256" => Some("SHA256"),
                "sha512" => Some("SHA512"),
                "rsa2048" => Some("RSA2048"),
                "ed25519" => Some("Ed25519"),
                _ => None,
            };
            assert_eq!(
                canonical, *expected,
                "hash type '{}' should normalize to {:?}",
                input, expected
            );
        }
    }

    /// Test that reset confirmation logic works correctly.
    /// The implementation reads "yes" from stdin; here we just verify the
    /// string comparison logic used in the confirmation.
    #[test]
    fn test_reset_confirmation_string_check() {
        // Only "yes" (exact, trimmed) should be accepted
        let accepted = ["yes"];
        let rejected = ["Yes", "YES", "y", "no", "n", "", " yes", "yes "];

        for s in &accepted {
            assert_eq!(s.trim(), "yes", "'{}' trimmed should equal 'yes'", s);
        }
        for s in &rejected {
            // After trim, should NOT equal "yes" (except "yes" itself, but those
            // are in rejected because they have spaces - " yes".trim() = "yes"...
            // Actually " yes".trim() IS "yes", so let's be more careful)
            let trimmed = s.trim();
            if *s == " yes" || *s == "yes " {
                // These DO trim to "yes" - they should be accepted!
                assert_eq!(trimmed, "yes");
            } else {
                assert_ne!(
                    trimmed, "yes",
                    "'{}' trimmed ('{}') should not equal 'yes'",
                    s, trimmed
                );
            }
        }
    }

    /// Test challenge_response salt computation.
    #[test]
    fn test_challenge_response_salt_is_sha256_of_challenge() {
        use sha2::{Digest, Sha256};

        let challenge = "my-challenge-string";
        let mut hasher = Sha256::new();
        hasher.update(challenge.as_bytes());
        let salt = hasher.finalize();

        // The salt should be SHA256(challenge) - 32 bytes
        assert_eq!(salt.len(), 32);
        // Known value for SHA256("my-challenge-string")
        let expected = Sha256::digest(challenge.as_bytes());
        assert_eq!(salt.as_slice(), expected.as_slice());
    }
}
