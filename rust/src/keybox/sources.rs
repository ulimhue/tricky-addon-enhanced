use anyhow::{Context, Result, bail};
use base64::Engine;
use tracing::{debug, warn};

use crate::platform::network;

const YURIKEY_URL: &str =
    "https://raw.githubusercontent.com/Yurii0307/yurikey/main/key";
const UPSTREAM_URL: &str =
    "https://raw.githubusercontent.com/KOWX712/Tricky-Addon-Update-Target-List/keybox/.extra";
const INTEGRITYBOX_URL: &str =
    "https://raw.githubusercontent.com/MeowDump/MeowDump/refs/heads/main/NullVoid/ShockWave.tar";
const INTEGRITYBOX_MIRROR: &str =
    "https://raw.gitmirror.com/MeowDump/MeowDump/refs/heads/main/NullVoid/ShockWave.tar";

const FILTER_WORDS: &[&str] = &["every", "soul", "will", "taste", "death"];

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

pub fn fetch_integritybox() -> Result<Vec<u8>> {
    debug!("fetching keybox from integritybox");
    let raw = network::download(INTEGRITYBOX_URL)
        .or_else(|e| {
            warn!("integritybox primary failed: {e}, trying mirror");
            network::download(INTEGRITYBOX_MIRROR)
        })
        .context("integritybox download failed")?;

    decode_integritybox(&raw)
}

pub fn fetch_custom_url(url: &str) -> Result<Vec<u8>> {
    debug!("fetching keybox from custom URL: {}", url);
    let data = network::download(url)
        .context("custom URL download failed")?;
    Ok(data)
}

fn decode_integritybox(raw: &[u8]) -> Result<Vec<u8>> {
    let mut data = raw.to_vec();

    for i in 0..10 {
        let text = String::from_utf8(data)
            .with_context(|| format!("integritybox round {}: not valid UTF-8", i + 1))?;
        data = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .with_context(|| format!("integritybox base64 round {} failed", i + 1))?;
    }

    let hex_text = String::from_utf8(data)
        .context("integritybox hex stage: not valid UTF-8")?;
    let hex_decoded = hex_decode(hex_text.trim())
        .context("integritybox hex decode failed")?;

    let rot13 = apply_rot13(&hex_decoded);
    let filtered = word_filter(&rot13);

    Ok(filtered.into_bytes())
}

fn hex_decode(s: &str) -> Result<String> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() % 2 != 0 {
        bail!("hex string has odd length");
    }
    let bytes: Result<Vec<u8>, _> = (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16))
        .collect();
    Ok(String::from_utf8(bytes?)?)
}

fn apply_rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='M' | 'a'..='m' => (c as u8 + 13) as char,
            'N'..='Z' | 'n'..='z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

fn word_filter(s: &str) -> String {
    let mut result = s.to_string();
    for word in FILTER_WORDS {
        result = result.replace(word, "");
    }
    result
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
