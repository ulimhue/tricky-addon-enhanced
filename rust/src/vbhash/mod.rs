pub mod keystore;

use std::path::Path;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::config::Config;

const BOOT_HASH_FILE: &str = "/data/adb/boot_hash";

pub fn handle_vbhash(action: crate::cli::VbhashAction, cfg: &Config) -> Result<()> {
    use crate::cli::VbhashAction;
    match action {
        VbhashAction::Extract => {
            if !cfg.vbhash.enabled {
                println!("vbhash disabled");
                return Ok(());
            }
            match extract() {
                Ok(hash) => {
                    println!("{hash}");
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        VbhashAction::Pass => {
            if !cfg.vbhash.enabled {
                debug!("vbhash disabled, skipping pass");
                return Ok(());
            }
            pass()
        }
        VbhashAction::Show => {
            match get_stored() {
                Some(hash) => println!("{hash}"),
                None => println!("no valid hash stored"),
            }
            Ok(())
        }
    }
}

pub fn get_stored() -> Option<String> {
    let content = std::fs::read_to_string(BOOT_HASH_FILE).ok()?;
    let hash = content.lines().next()?.trim().to_string();
    if verify_hash_format(&hash) {
        Some(hash)
    } else {
        None
    }
}

pub fn persist(hash: &str, source: &str) -> Result<()> {
    info!("persisting vbhash from {source}");
    crate::platform::fs::atomic_write(Path::new(BOOT_HASH_FILE), hash.as_bytes())
        .context("failed to write boot_hash")?;
    std::process::Command::new("chmod")
        .args(["644", BOOT_HASH_FILE])
        .status()
        .ok();
    Ok(())
}

pub fn extract_from_property() -> Option<String> {
    let val = crate::platform::props::getprop("ro.boot.vbmeta.digest")?;
    let lower = val.to_ascii_lowercase();
    if verify_hash_format(&lower) {
        Some(lower)
    } else {
        None
    }
}

pub fn extract() -> Result<String> {
    let stored = get_stored();

    if let Some(hash) = extract_from_property() {
        if stored.as_deref() != Some(&*hash) {
            debug!("vbhash changed, updating persisted file");
            persist(&hash, "property")?;
        }
        return Ok(hash);
    }

    if let Some(hash) = stored {
        debug!("property unavailable, using persisted hash");
        return Ok(hash);
    }

    match keystore::extract_from_apk() {
        Ok(hash) => {
            persist(&hash, "apk")?;
            Ok(hash)
        }
        Err(e) => {
            warn!("all vbhash extraction methods failed");
            Err(e).context("all VBHash extraction methods failed")
        }
    }
}

pub fn pass() -> Result<()> {
    let hash = extract()?;
    info!("vbhash pass complete: {}", &hash[..8]);
    Ok(())
}

fn verify_hash_format(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}
