use anyhow::{Context, Result, bail};
use base64::Engine;
use tracing::debug;

use crate::platform::network;

const YURIKEY_URL: &str =
    "https://raw.githubusercontent.com/Yurii0307/yurikey/main/key";
const UPSTREAM_URL: &str =
    "https://raw.githubusercontent.com/KOWX712/Tricky-Addon-Update-Target-List/keybox/.extra";

pub fn fetch_yurikey() -> Result<Vec<u8>> {
    debug!("fetching keybox from yurikey");
    let text = network::download_text(YURIKEY_URL)
        .context("yurikey download failed")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .context("yurikey base64 decode failed")?;
    Ok(decoded)
}

pub fn fetch_upstream() -> Result<Vec<u8>> {
    debug!("fetching keybox from upstream");
    let text = network::download_text(UPSTREAM_URL)
        .context("upstream download failed")?;
    let hex_decoded = hex_decode(text.trim())
        .context("upstream hex decode failed")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&hex_decoded)
        .context("upstream base64 decode failed")?;
    Ok(decoded)
}

pub fn fetch_custom_url(url: &str) -> Result<Vec<u8>> {
    debug!("fetching keybox from custom URL: {}", url);
    let data = network::download(url)
        .context("custom URL download failed")?;
    Ok(data)
}

fn hex_decode(s: &str) -> Result<String> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if !clean.len().is_multiple_of(2) {
        bail!("hex string has odd length");
    }
    let bytes: Result<Vec<u8>, _> = (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
        .collect();
    Ok(String::from_utf8(bytes?)?)
}

pub fn compute_sha256(data: &[u8]) -> String {
    use std::io::Write;
    let output = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(data)?;
            child.wait_with_output()
        });
    match output {
        Ok(o) => {
            let out = String::from_utf8_lossy(&o.stdout);
            out.split_whitespace().next().unwrap_or("").to_string()
        }
        Err(_) => String::new(),
    }
}
