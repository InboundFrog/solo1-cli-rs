/// Minimal GitHub releases client used to download firmware.
use serde::Deserialize;

use crate::error::{Result, SoloError};

/// GitHub release API response (simplified).
#[derive(Debug, Deserialize)]
pub struct GithubRelease {
    pub tag_name: String,
    pub assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
pub struct GithubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

impl GithubRelease {
    /// Find the first asset whose name satisfies `is_wanted`.
    #[must_use]
    pub fn find_asset(&self, is_wanted: impl Fn(&str) -> bool) -> Option<&GithubAsset> {
        self.assets.iter().find(|a| is_wanted(&a.name))
    }
}

/// Build the blocking HTTP client used for GitHub requests.
fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent("solo1-cli-rs")
        .build()
        .map_err(|e| SoloError::NetworkError(e.to_string()))
}

/// Fetch the latest release of `repo` (`owner/name`) from GitHub.
///
/// # Errors
/// Returns [`SoloError::NetworkError`] if the HTTP client cannot be built, the
/// request fails, or the response body is not valid release JSON.
pub fn fetch_latest_release(repo: &str) -> Result<GithubRelease> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let client = http_client()?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| SoloError::NetworkError(e.to_string()))?;
    let release: GithubRelease = resp
        .json()
        .map_err(|e| SoloError::NetworkError(format!("Failed to parse release JSON: {e}")))?;
    Ok(release)
}

/// Download a URL to bytes.
///
/// # Errors
/// Returns [`SoloError::NetworkError`] if the HTTP client cannot be built, the
/// request fails, or the response body cannot be read.
pub fn download_url(url: &str) -> Result<Vec<u8>> {
    let client = http_client()?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| SoloError::NetworkError(e.to_string()))?;
    let bytes = resp.bytes().map_err(|e| SoloError::NetworkError(e.to_string()))?;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn asset(name: &str) -> GithubAsset {
        GithubAsset {
            name: name.into(),
            browser_download_url: format!("https://example.invalid/{name}"),
            size: 0,
        }
    }

    #[test]
    fn test_find_asset_returns_first_match() {
        let release = GithubRelease {
            tag_name: "4.1.5".into(),
            assets: vec![asset("firmware.hex"), asset("a.json"), asset("b.json")],
        };
        let found = release.find_asset(|n| n != "firmware.hex").unwrap();
        assert_eq!(found.name, "a.json");
    }

    #[test]
    fn test_find_asset_none() {
        let release = GithubRelease {
            tag_name: "4.1.5".into(),
            assets: vec![asset("firmware.hex")],
        };
        assert!(release.find_asset(|n| n == "missing.json").is_none());
    }
}
