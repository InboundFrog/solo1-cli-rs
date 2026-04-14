use crate::error::{Result, SoloError};

/// Print `prompt` and require the user to type exactly "yes" to continue.
///
/// Returns `Ok(true)` if the user typed "yes" (trimmed), `Ok(false)` for any
/// other input, and `Err` only on I/O failure.
pub fn confirm(prompt: &str) -> Result<bool> {
    println!("{}", prompt);
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(SoloError::IoError)?;
    Ok(input.trim() == "yes")
}
