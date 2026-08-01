use crate::error::{Result, SoloError};

/// Print `prompt` and require the user to type exactly "yes" to continue.
///
/// Returns `Ok(true)` if the user typed "yes" (trimmed), `Ok(false)` for any
/// other input, and `Err` only on I/O failure.
///
/// # Errors
/// Returns an error if reading a line from standard input fails.
pub fn confirm(prompt: &str) -> Result<bool> {
    println!("{prompt}");
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(SoloError::IoError)?;
    Ok(is_confirmed(&input))
}

/// Returns true only if `input`, after trimming whitespace, is exactly "yes".
fn is_confirmed(input: &str) -> bool {
    input.trim() == "yes"
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::cast_possible_truncation
    )]
    use super::is_confirmed;

    #[test]
    fn test_is_confirmed_accepts_trimmed_yes() {
        for input in ["yes", "yes\n", "yes\r\n", " yes ", "\tyes\n"] {
            assert!(is_confirmed(input), "{input:?} should confirm");
        }
    }

    #[test]
    fn test_is_confirmed_rejects_everything_else() {
        for input in ["Yes", "YES", "y", "no", "n", "", "yess", "yes please"] {
            assert!(!is_confirmed(input), "{input:?} should not confirm");
        }
    }
}
