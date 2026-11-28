/// Minimal GitHub releases client used to download firmware.
use std::io::Read;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{Result, SoloError};

/// Time allowed to open a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Time allowed for a whole request, including reading the body.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Largest firmware file (and release JSON) we accept: 8 MiB.
const MAX_DOWNLOAD_BYTES: u64 = 8 * 1024 * 1024;

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

impl GithubAsset {
    /// Reject an asset whose declared size is over the download limit.
    ///
    /// # Errors
    /// Returns [`SoloError::NetworkError`] if the declared size is too large.
    pub fn check_size(&self) -> Result<()> {
        if self.size > MAX_DOWNLOAD_BYTES {
            return Err(SoloError::NetworkError(format!(
                "Asset {} is too large ({} bytes, limit {MAX_DOWNLOAD_BYTES})",
                self.name, self.size
            )));
        }
        Ok(())
    }
}

impl GithubRelease {
    /// Find the first asset whose name satisfies `is_wanted`.
    #[must_use]
    pub fn find_asset(&self, is_wanted: impl Fn(&str) -> bool) -> Option<&GithubAsset> {
        self.assets.iter().find(|a| is_wanted(&a.name))
    }
}

/// Build the blocking HTTP client used for GitHub requests.
/// `request_timeout` is the time allowed for a whole request.
fn http_client(request_timeout: Duration) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent("solo1-cli-rs")
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(request_timeout)
        .build()
        .map_err(|e| SoloError::NetworkError(e.to_string()))
}

/// Read all of `reader`, failing if it holds more than `max` bytes.
///
/// The limit is enforced while reading, so a lying size header cannot make
/// us buffer an unbounded body.
fn read_limited(reader: impl Read, max: u64) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    // Read one byte past the limit so that "too big" can be told from "exact".
    reader
        .take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| SoloError::NetworkError(e.to_string()))?;
    if u64::try_from(buf.len()).map_or(true, |n| n > max) {
        return Err(SoloError::NetworkError(format!(
            "Download is larger than the {max} byte limit"
        )));
    }
    Ok(buf)
}

/// Send a GET request and return the response body, with status and size checks.
fn get_limited(url: &str) -> Result<Vec<u8>> {
    get_limited_with(url, REQUEST_TIMEOUT)
}

/// `get_limited` with the request timeout passed in, so a test needs no long wait.
fn get_limited_with(url: &str, request_timeout: Duration) -> Result<Vec<u8>> {
    let resp = http_client(request_timeout)?
        .get(url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .map_err(|e| SoloError::NetworkError(e.to_string()))?;
    if resp.content_length().is_some_and(|n| n > MAX_DOWNLOAD_BYTES) {
        return Err(SoloError::NetworkError(format!(
            "Download is larger than the {MAX_DOWNLOAD_BYTES} byte limit"
        )));
    }
    read_limited(resp, MAX_DOWNLOAD_BYTES)
}

/// Fetch the latest release of `repo` (`owner/name`) from GitHub.
///
/// # Errors
/// Returns [`SoloError::NetworkError`] if the HTTP client cannot be built, the
/// request fails, the HTTP status is not a success, the body is over the size
/// limit, or the body is not valid release JSON.
pub fn fetch_latest_release(repo: &str) -> Result<GithubRelease> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let body = get_limited(&url)?;
    serde_json::from_slice(&body).map_err(|e| SoloError::NetworkError(format!("Failed to parse release JSON: {e}")))
}

/// Download a URL to bytes.
///
/// # Errors
/// Returns [`SoloError::NetworkError`] if the HTTP client cannot be built, the
/// request fails, the HTTP status is not a success, or the body cannot be read
/// or is over the size limit.
pub fn download_url(url: &str) -> Result<Vec<u8>> {
    get_limited(url)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

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
    fn test_read_limited_accepts_exact_limit() {
        assert_eq!(read_limited(&[7u8; 4][..], 4).unwrap().len(), 4);
    }

    #[test]
    fn test_read_limited_rejects_over_limit() {
        assert!(read_limited(&[7u8; 5][..], 4).is_err());
    }

    #[test]
    fn test_check_size_rejects_large_asset() {
        let mut a = asset("a.json");
        assert!(a.check_size().is_ok());
        a.size = MAX_DOWNLOAD_BYTES + 1;
        assert!(a.check_size().is_err());
    }

    #[test]
    fn test_find_asset_none() {
        let release = GithubRelease {
            tag_name: "4.1.5".into(),
            assets: vec![asset("firmware.hex")],
        };
        assert!(release.find_asset(|n| n == "missing.json").is_none());
    }

    /// Serve one connection on 127.0.0.1 in a thread: read the request head, send `response`,
    /// then wait until the client closes. Returns the URL to fetch.
    fn serve(response: impl FnOnce(&mut std::net::TcpStream) + Send + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/fw.json", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
                head.extend_from_slice(&byte);
            }
            response(&mut stream);
            // Hold the connection until the client is done with it.
            let _ = stream.read(&mut byte);
        });
        url
    }

    fn reply(status: &str, headers: &str, body: Vec<u8>) -> impl FnOnce(&mut std::net::TcpStream) + Send + 'static {
        let head = format!("HTTP/1.1 {status}\r\n{headers}Connection: close\r\n\r\n");
        move |s| {
            // The client may stop reading early (size limit), so a write error is fine.
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
            // Connection: close, so end the body here and do not wait for the client.
            let _ = s.shutdown(std::net::Shutdown::Write);
        }
    }

    #[test]
    fn test_download_ok() {
        let url = serve(reply("200 OK", "Content-Length: 5\r\n", b"hello".to_vec()));
        assert_eq!(download_url(&url).unwrap(), b"hello");
    }

    #[test]
    fn test_download_403_names_the_status() {
        let url = serve(reply("403 Forbidden", "Content-Length: 0\r\n", vec![]));
        let text = download_url(&url).unwrap_err().to_string();
        assert!(text.contains("403 Forbidden"), "{text}");
    }

    #[test]
    fn test_download_404_names_the_status() {
        let url = serve(reply("404 Not Found", "Content-Length: 0\r\n", vec![]));
        let text = download_url(&url).unwrap_err().to_string();
        assert!(text.contains("404 Not Found"), "{text}");
    }

    #[test]
    fn test_download_times_out_when_the_server_never_answers() {
        let url = serve(|_| {});
        let (tx, rx) = std::sync::mpsc::channel();
        let start = std::time::Instant::now();
        std::thread::spawn(move || tx.send(get_limited_with(&url, Duration::from_millis(300))).unwrap());
        // Without the timeout the request would wait 30 s (the reqwest default), so do not wait for it here.
        let err = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the request did not time out")
            .unwrap_err();
        assert!(matches!(err, SoloError::NetworkError(_)), "{err}");
        assert!(start.elapsed() >= Duration::from_millis(300), "failed early: {err}");
    }

    #[test]
    fn test_download_rejects_a_declared_size_over_the_limit() {
        let headers = format!("Content-Length: {}\r\n", MAX_DOWNLOAD_BYTES + 1);
        let url = serve(reply("200 OK", &headers, vec![]));
        let text = download_url(&url).unwrap_err().to_string();
        assert!(text.contains("limit"), "{text}");
    }

    #[test]
    fn test_download_rejects_a_body_over_the_limit_without_a_size_header() {
        let body = vec![7u8; usize::try_from(MAX_DOWNLOAD_BYTES).unwrap() + 1];
        let url = serve(reply("200 OK", "", body));
        let text = download_url(&url).unwrap_err().to_string();
        assert!(text.contains("limit"), "{text}");
    }
}
