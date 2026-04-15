use std::io::Write;

use crate::device::{HidDevice, CMD_RNG};
use crate::error::{Result, SoloError};

/// Get N random bytes from the device, return as hex string.
pub fn cmd_rng_hexbytes(hid: &impl HidDevice, n: usize) -> Result<String> {
    if n > 255 {
        return Err(SoloError::ProtocolError(format!(
            "Number of bytes must be between 0 and 255, you passed {}",
            n
        )));
    }
    let request = [n as u8];
    let response = hid.send_recv(CMD_RNG, &request)?;
    Ok(hex::encode(&response[..response.len().min(n)]))
}

/// Stream raw random bytes to stdout.
pub fn cmd_rng_raw(hid: &impl HidDevice) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    loop {
        let request = [64u8];
        let response = hid.send_recv(CMD_RNG, &request)?;
        out.write_all(&response)?;
        out.flush()?;
    }
}

/// Feed entropy to /dev/random (Linux only) using RNDADDENTROPY ioctl.
///
/// Uses the RNDADDENTROPY ioctl (0x40085203) to properly inform the kernel
/// of the entropy being added, rather than just writing bytes. The struct
/// sent to the ioctl is: entropy_count (i32) | buf_size (i32) | data (bytes).
/// entropy_count = count * 2 (2 bits per byte, pessimistic estimate).
#[cfg(target_os = "linux")]
pub fn cmd_rng_feedkernel(hid: &impl HidDevice) -> Result<()> {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    const ENTROPY_INFO: &str = "/proc/sys/kernel/random/entropy_avail";
    const RNDADDENTROPY: libc::c_ulong = 0x40085203;
    const COUNT: usize = 64;
    const ENTROPY_BITS_PER_BYTE: i32 = 2;

    let before = std::fs::read_to_string(ENTROPY_INFO).unwrap_or_else(|_| "unknown".into());
    println!("Entropy before: 0x{}", before.trim());

    let request = [COUNT as u8];
    let response = hid.send_recv(CMD_RNG, &request)?;
    let data = &response[..response.len().min(COUNT)];

    // Build rand_pool_info struct: entropy_count (i32), buf_size (i32), buf (bytes)
    let mut buf = Vec::with_capacity(8 + data.len());
    let entropy_count: i32 = data.len() as i32 * ENTROPY_BITS_PER_BYTE;
    let buf_size: i32 = data.len() as i32;
    buf.extend_from_slice(&entropy_count.to_ne_bytes());
    buf.extend_from_slice(&buf_size.to_ne_bytes());
    buf.extend_from_slice(data);

    let dev_random = File::options().write(true).open("/dev/random")?;
    let ret = unsafe { libc::ioctl(dev_random.as_raw_fd(), RNDADDENTROPY, buf.as_ptr()) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let after = std::fs::read_to_string(ENTROPY_INFO).unwrap_or_else(|_| "unknown".into());
    println!("Entropy after:  0x{}", after.trim());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn cmd_rng_feedkernel(_hid: &impl HidDevice) -> Result<()> {
    Err(SoloError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::mock::MockDevice;
    use crate::error::SoloError;

    // ── cmd_rng_hexbytes ─────────────────────────────────────────────────────

    /// Device returns N bytes; the result must be a lowercase hex string of length 2*N.
    #[test]
    fn test_cmd_rng_hexbytes_valid_response() {
        let rng_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let device = MockDevice::new(vec![Ok(rng_bytes)]);
        let hex = cmd_rng_hexbytes(&device, 4).unwrap();
        assert_eq!(hex, "deadbeef");
        assert_eq!(hex.len(), 8); // 4 bytes × 2 hex chars each
    }

    /// Device returns more bytes than requested: only the first n are hex-encoded.
    #[test]
    fn test_cmd_rng_hexbytes_truncates_to_n() {
        // Device returns 8 bytes, but we only asked for 4
        let rng_bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let device = MockDevice::new(vec![Ok(rng_bytes)]);
        let hex = cmd_rng_hexbytes(&device, 4).unwrap();
        assert_eq!(hex, "01020304");
    }

    /// count=0 edge case: device returns empty bytes, result is an empty hex string.
    #[test]
    fn test_cmd_rng_hexbytes_count_zero() {
        // When n=0, the device is called with request=[0x00]; it returns empty bytes.
        let device = MockDevice::new(vec![Ok(vec![])]);
        let hex = cmd_rng_hexbytes(&device, 0).unwrap();
        assert_eq!(hex, "");
    }

    /// n > 255 must be rejected before any device communication.
    #[test]
    fn test_cmd_rng_hexbytes_n_too_large() {
        // Queue is empty — if the device were called, we'd get Timeout.
        // The validation must fire before any send_recv is attempted.
        let device = MockDevice::new(vec![]);
        let err = cmd_rng_hexbytes(&device, 256).unwrap_err();
        assert!(matches!(err, SoloError::ProtocolError(_)));
        let msg = err.to_string();
        assert!(msg.contains("256"), "error should mention the bad value: {}", msg);
    }

    /// Device timeout propagates as SoloError::Timeout.
    #[test]
    fn test_cmd_rng_hexbytes_timeout() {
        let device = MockDevice::new(vec![]);
        let err = cmd_rng_hexbytes(&device, 8).unwrap_err();
        assert!(matches!(err, SoloError::Timeout));
    }

    /// Hex output uses lowercase letters.
    #[test]
    fn test_cmd_rng_hexbytes_hex_is_lowercase() {
        let rng_bytes = vec![0xAB, 0xCD, 0xEF];
        let device = MockDevice::new(vec![Ok(rng_bytes)]);
        let hex = cmd_rng_hexbytes(&device, 3).unwrap();
        assert_eq!(hex, "abcdef");
        assert!(hex.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }
}
