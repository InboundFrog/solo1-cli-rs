use std::io::Write;

use crate::device::{SoloHid, CMD_RNG};
use crate::error::{Result, SoloError};

/// Get N random bytes from the device, return as hex string.
pub fn cmd_rng_hexbytes(hid: &SoloHid, n: usize) -> Result<String> {
    if n > 255 {
        return Err(SoloError::DeviceError(format!(
            "Number of bytes must be between 0 and 255, you passed {}",
            n
        )));
    }
    let request = [n as u8];
    let response = hid.send_recv(CMD_RNG, &request)?;
    Ok(hex::encode(&response[..response.len().min(n)]))
}

/// Stream raw random bytes to stdout.
pub fn cmd_rng_raw(hid: &SoloHid) -> Result<()> {
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
pub fn cmd_rng_feedkernel(hid: &SoloHid) -> Result<()> {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;

    const ENTROPY_INFO: &str = "/proc/sys/kernel/random/entropy_avail";
    const RNDADDENTROPY: libc::c_ulong = 0x40085203;
    const COUNT: usize = 64;
    const ENTROPY_BITS_PER_BYTE: i32 = 2;

    let before = std::fs::read_to_string(ENTROPY_INFO)
        .unwrap_or_else(|_| "unknown".into());
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
    let ret = unsafe {
        libc::ioctl(dev_random.as_raw_fd(), RNDADDENTROPY, buf.as_ptr())
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let after = std::fs::read_to_string(ENTROPY_INFO)
        .unwrap_or_else(|_| "unknown".into());
    println!("Entropy after:  0x{}", after.trim());
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn cmd_rng_feedkernel(_hid: &SoloHid) -> Result<()> {
    Err(SoloError::UnsupportedPlatform)
}
