---
name: Attestation Security Gaps
description: Attestation verification only checks a SHA-256 fingerprint against a hardcoded list — no certificate chain validation, no validity date check, no revocation
type: project
---

# 0009 — Attestation Security Gaps

## Problem

`src/commands/key/verify.rs` `cmd_verify` and `src/crypto.rs` `check_attestation_fingerprint` implement "verify key authenticity" by:

1. Triggering a `makeCredential` to get the device's attestation certificate
2. Computing `SHA-256(certificate_der)`
3. Checking whether the digest matches one of six hardcoded fingerprints

```rust
pub fn check_attestation_fingerprint(cert_der: &[u8]) -> bool {
    let digest = sha256_hex(cert_der);
    [
        SOLO_V3_FINGERPRINT,
        SOLO_HACKER_FINGERPRINT,
        SOLO_EMULATION_FINGERPRINT,
        SOLO_TAP_FINGERPRINT,
        SOMU_FINGERPRINT,
        SOLO_FINGERPRINT,
    ].contains(&digest.as_str())
}
```

### Issues

1. **No certificate chain validation.** The attestation certificate is only useful if it chains to a known root. Without chain validation, an attacker with any device could self-sign a certificate whose DER bytes happen to match a known fingerprint (practically infeasible with SHA-256, but not proven impossible by the code alone).

2. **Fingerprints validate the whole certificate DER, not the public key.** Any change to the certificate (e.g., updated validity dates, updated extensions) will cause the fingerprint to not match, even for a legitimate Solo device with a genuine attestation key. This has likely already affected users with newer firmware builds.

3. **No validity date check.** Expired certificates are accepted.

4. **No revocation check.** There is no CRL or OCSP check.

5. **`SOLO_HACKER_FINGERPRINT` and `SOLO_EMULATION_FINGERPRINT` represent non-genuine devices.** The verify command will return "authentic" for hacker and emulation builds, which could mislead users. This is probably intentional for developer convenience but should be clearly documented and perhaps guarded by a `--include-developer-devices` flag.

6. **No user-visible explanation** of what level of assurance the fingerprint check provides.

## Why It Needs Changing

Items 3–6 are security UX issues that could mislead users. Item 2 will cause false negatives for users with newer firmware. Items 1 and 4 are theoretical but worth documenting.

This issue does not require a full X.509 validation implementation immediately — the primary deliverable is **honest documentation and improved UX**.

## Proposed Changes

### Short term (code changes)

1. **Add a comment block above `check_attestation_fingerprint`** that clearly explains:
   - What the check does and does not prove
   - That hacker/emulation fingerprints represent developer devices, not genuine consumer keys
   - That fingerprints are valid only for specific certificate versions (link to SoloKeys docs if available)

2. **Differentiate genuine vs. developer fingerprints** in the return value:

```rust
pub enum AttestationResult {
    GenuineConsumer(&'static str),    // e.g., "Solo v3"
    DeveloperDevice(&'static str),    // e.g., "Solo Hacker"
    Unknown,
}

pub fn check_attestation_fingerprint(cert_der: &[u8]) -> AttestationResult
```

3. **Update `cmd_verify` output** to distinguish between consumer and developer attestation results.

### Medium term (if/when practical)

4. Validate certificate `notBefore`/`notAfter` dates using the `x509-cert` or `rustls-pki-types` crate.

5. Consider pinning the attestation public key (SPKI) rather than the full certificate DER, to be resilient to certificate re-issuance with the same key.

### Steps (short term)

1. Define `AttestationResult` enum in `src/crypto.rs`
2. Update `check_attestation_fingerprint` to return `AttestationResult`
3. Update `cmd_verify` in `verify.rs` to print appropriate messages per variant
4. Add explanatory comments to `check_attestation_fingerprint`
5. Verify `cargo test` passes (update tests for new return type)

## Relevant Code

- `src/crypto.rs`: `check_attestation_fingerprint`, fingerprint constants
- `src/commands/key/verify.rs`: `cmd_verify` (~lines 130–160)

## References

- [CTAP2 §8.1 Attestation](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-attestation)
- [WebAuthn attestation verification](https://www.w3.org/TR/webauthn-2/#sctn-attestation)
- [SoloKeys attestation (GitHub)](https://github.com/solokeys/solo1)
