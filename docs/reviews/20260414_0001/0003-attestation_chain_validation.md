---
name: Attestation Chain Validation
description: Attestation verification pins the full certificate DER — a re-issued cert with the same key fails, and there is no chain, date, or revocation check
type: project
---

# 0003 — Attestation Chain Validation

## Problem

The previous review (0009) introduced `AttestationResult` to differentiate genuine from developer
devices, and added comments explaining the limits of the fingerprint check. That was the right
short-term step. The underlying structural problems remain and are worth addressing when
SoloKeys issues new firmware or re-signs certificates.

The current `check_attestation_fingerprint` in `src/crypto.rs`:

1. **Pins the full certificate DER, not the public key (SPKI).** Any change to the certificate
   — updated validity dates, added extension, re-issuance with the same attestation key — will
   cause verification to fail for a genuinely authentic device. This is likely to happen over the
   product lifetime.

2. **No validity date check.** The notBefore/notAfter fields are ignored. An expired or
   not-yet-valid certificate is silently accepted.

3. **No certificate chain validation.** The fingerprint list is checked against a hardcoded
   set of leaf-certificate digests. There is no root CA, no intermediate, and no chain. An
   attacker cannot forge the key, but the design does not scale to new device variants — adding
   a new Solo device model requires a code update to add a fingerprint.

4. **`SOLO_HACKER_FINGERPRINT` and `SOLO_EMULATION_FINGERPRINT` return `DeveloperDevice`** —
   this is correct after 0009, but these fingerprints are for non-genuine devices. The word
   "authentic" must not appear in output for these variants.

## Why It Needs Changing

Item 1 (SPKI pinning) is the highest-priority practical fix. When SoloKeys re-issues attestation
certificates (firmware update, CA rotation, expiry), users with otherwise-genuine keys will see
verification fail. This erodes trust in the tool itself.

Items 2 and 3 are defense-in-depth improvements. They do not change the threat model dramatically
for a well-known single-vendor device, but they are cheap to add and align with standard PKI
verification practice.

## Proposed Changes

### 1. Pin the Subject Public Key Info (SPKI), not the full DER

Parse the certificate with the `x509-cert` crate and extract the SPKI bytes, then fingerprint those:

```rust
use x509_cert::Certificate;
use der::Decode;

pub fn check_attestation_spki(cert_der: &[u8]) -> AttestationResult {
    let cert = match Certificate::from_der(cert_der) {
        Ok(c) => c,
        Err(_) => return AttestationResult::Unknown,
    };

    // DER-encode just the SubjectPublicKeyInfo
    let spki_der = match cert.tbs_certificate.subject_public_key_info.to_der() {
        Ok(d) => d,
        Err(_) => return AttestationResult::Unknown,
    };

    let digest = sha256_hex(&spki_der);
    match digest.as_str() {
        SOLO_V3_SPKI_FINGERPRINT      => AttestationResult::GenuineConsumer("Solo v3"),
        SOMU_SPKI_FINGERPRINT         => AttestationResult::GenuineConsumer("SoloMU"),
        SOLO_SPKI_FINGERPRINT         => AttestationResult::GenuineConsumer("Solo 1"),
        SOLO_TAP_SPKI_FINGERPRINT     => AttestationResult::GenuineConsumer("Solo Tap"),
        SOLO_HACKER_SPKI_FINGERPRINT  => AttestationResult::DeveloperDevice("Solo Hacker"),
        SOLO_EMULATION_SPKI_FINGERPRINT => AttestationResult::DeveloperDevice("Solo Emulation"),
        _ => AttestationResult::Unknown,
    }
}
```

Add `x509-cert = "0.2"` and `der = "0.7"` to `Cargo.toml`. The SPKI fingerprint constants
must be re-derived from the existing certificate DER test fixtures.

### 2. Add notBefore / notAfter validation

After parsing the certificate, check the validity window:

```rust
use x509_cert::time::Validity;

fn check_validity(cert: &Certificate) -> Result<()> {
    let now = std::time::SystemTime::now();
    // x509-cert exposes validity as der::asn1::GeneralizedTime or UtcTime
    // Compare against SystemTime
    // Return Err if now < notBefore or now > notAfter
    // ...
}
```

This does not require an external time service and adds meaningful protection against expired certs.

### 3. Keep full-DER fingerprints for backwards compatibility (transitional)

During the transition, keep both sets of constants (SPKI and full-DER). Prefer SPKI matching;
fall back to DER matching with a deprecation warning printed to stderr:

```
Warning: Attestation matched by full-certificate fingerprint (deprecated).
         This device may still be genuine but the certificate has been re-issued.
         Update solo1-cli to the latest version.
```

Remove the DER fallback in the next breaking release.

### Steps

1. Add `x509-cert = "0.2"`, `der = "0.7"` to `Cargo.toml`
2. Extract SPKI bytes from existing test-fixture certificates; compute new fingerprint constants
3. Implement `check_attestation_spki` in `src/crypto.rs`
4. Add `check_validity` helper
5. Update `cmd_verify` in `verify.rs` to call the new function
6. Keep old `check_attestation_fingerprint` as a deprecated fallback with the warning
7. Update / add tests for: valid SPKI match, expired cert rejection, unknown cert, developer cert
8. Verify `cargo test` passes

## Relevant Code

- `src/crypto.rs` — `check_attestation_fingerprint`, SPKI constant definitions to add
- `src/commands/key/verify.rs` — `cmd_verify`, `extract_attestation_cert`
- `tests/` — attestation fixture certificates (DER bytes in test helpers)

## References

- [CTAP2 §8.1 — Packed Attestation](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-packed-attestation)
- [WebAuthn §7.2 — Attestation statement verification](https://www.w3.org/TR/webauthn-2/#sctn-attestation)
- [x509-cert crate](https://crates.io/crates/x509-cert)
- [RFC 5280 §4.1.2.7 — Subject Public Key Info](https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7)
