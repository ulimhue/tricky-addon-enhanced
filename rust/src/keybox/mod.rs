pub mod sources;
pub mod validate;
pub mod generate;

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use serde::{Serialize, Deserialize};
use tracing::{info, warn, error};

use crate::cli::KeyboxAction;
use crate::config::Config;
use crate::platform::fs::atomic_write;

const TARGET_KEYBOX: &str = "/data/adb/tricky_store/keybox.xml";
const BACKUP_KEYBOX: &str = "/data/adb/tricky_store/keybox.xml.bak";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyboxSource {
    Yurikey,
    Upstream,
    Custom,
}

impl Default for KeyboxSource {
    fn default() -> Self { Self::Yurikey }
}

impl fmt::Display for KeyboxSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yurikey => write!(f, "yurikey"),
            Self::Upstream => write!(f, "upstream"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl FromStr for KeyboxSource {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "yurikey" => Ok(Self::Yurikey),
            "upstream" => Ok(Self::Upstream),
            "custom" => Ok(Self::Custom),
            _ => bail!("unknown keybox source: {s}"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SourceInfo {
    pub name: String,
    pub active: bool,
}

#[derive(Debug)]
pub struct FetchResult {
    pub source: &'static str,
}

pub fn handle_keybox(action: KeyboxAction, cfg: &Config) -> Result<()> {
    match action {
        KeyboxAction::Fetch => {
            let result = fetch(cfg)?;
            println!("keybox fetched from {}", result.source);
            Ok(())
        }
        KeyboxAction::Validate { path } => {
            let target = path.as_deref().unwrap_or(TARGET_KEYBOX);
            validate::validate_file(Path::new(target))?;
            println!("keybox valid: {target}");
            Ok(())
        }
        KeyboxAction::SetCustom { path } => {
            set_custom(Path::new(&path))?;
            println!("custom keybox installed from {path}");
            Ok(())
        }
        KeyboxAction::Sources => {
            let sources = get_sources(cfg);
            let json = serde_json::to_string_pretty(&sources)?;
            println!("{json}");
            Ok(())
        }
        KeyboxAction::Generate => {
            generate::generate_and_install()?;
            println!("device keybox generated");
            Ok(())
        }
        KeyboxAction::Backup => {
            backup()?;
            println!("keybox backed up");
            Ok(())
        }
    }
}

pub fn fetch(config: &Config) -> Result<FetchResult> {
    let preferred = KeyboxSource::from_str(&config.keybox.source).unwrap_or_else(|e| {
        warn!("keybox source {:?} invalid ({e}); defaulting to yurikey", config.keybox.source);
        KeyboxSource::default()
    });
    let custom_url = &config.keybox.custom_url;

    let order = build_source_order(preferred);
    let existing_hash = current_keybox_hash();

    for source in &order {
        let result = match source {
            KeyboxSource::Yurikey => sources::fetch_yurikey(),
            KeyboxSource::Upstream => sources::fetch_upstream(),
            KeyboxSource::Custom => {
                if custom_url.is_empty() {
                    continue;
                }
                sources::fetch_custom_url(custom_url)
            }
        };

        match result {
            Ok(data) => {
                if let Err(e) = validate::validate(&data) {
                    warn!("keybox from {} failed validation: {e}", source);
                    continue;
                }
                let new_hash = sources::compute_sha256(&data);
                if !new_hash.is_empty() && Some(&new_hash) == existing_hash.as_ref() {
                    info!("keybox from {} identical to installed, skipping", source);
                    return Ok(FetchResult { source: source_label(source) });
                }
                install_data(&data)?;
                info!("keybox installed from {}", source);
                return Ok(FetchResult { source: source_label(source) });
            }
            Err(e) => {
                warn!("keybox source {} failed: {e}", source);
            }
        }
    }

    if has_valid_existing_keybox() {
        warn!("all remote sources failed, preserving existing keybox");
        return Ok(FetchResult { source: "existing" });
    }

    bail!("all keybox sources failed")
}

pub fn backup() -> Result<()> {
    let target = Path::new(TARGET_KEYBOX);
    if !target.exists() {
        bail!("no keybox to backup at {}", TARGET_KEYBOX);
    }
    let bak = Path::new(BACKUP_KEYBOX);
    if bak.exists() {
        let bak1 = PathBuf::from(format!("{}.1", BACKUP_KEYBOX));
        std::fs::rename(bak, &bak1)
            .context("failed to rotate backup")?;
    }
    std::fs::copy(target, bak)
        .context("failed to create keybox backup")?;
    info!("keybox backed up to {}", BACKUP_KEYBOX);
    Ok(())
}

pub fn set_custom(path: &Path) -> Result<()> {
    if !path.exists() {
        bail!("custom keybox not found: {}", path.display());
    }
    let data = std::fs::read(path)?;
    validate::validate(&data)?;
    install_data(&data)?;
    info!("custom keybox installed from {}", path.display());
    Ok(())
}

pub fn get_sources(config: &Config) -> Vec<SourceInfo> {
    let active = KeyboxSource::from_str(&config.keybox.source).unwrap_or_else(|e| {
        warn!("keybox source {:?} invalid ({e}); defaulting to yurikey", config.keybox.source);
        KeyboxSource::default()
    });
    vec![
        SourceInfo { name: "yurikey".into(), active: active == KeyboxSource::Yurikey },
        SourceInfo { name: "upstream".into(), active: active == KeyboxSource::Upstream },
        SourceInfo { name: "custom".into(), active: active == KeyboxSource::Custom },
    ]
}

fn build_source_order(preferred: KeyboxSource) -> Vec<KeyboxSource> {
    let all = [
        KeyboxSource::Yurikey,
        KeyboxSource::Upstream,
        KeyboxSource::Custom,
    ];
    let mut order = vec![preferred];
    for s in all {
        if s != preferred {
            order.push(s);
        }
    }
    order
}

fn install_data(data: &[u8]) -> Result<()> {
    if Path::new(TARGET_KEYBOX).exists() {
        if let Err(e) = backup() {
            error!("backup failed before install: {e}");
            bail!("aborting keybox install: backup failed");
        }
    }
    atomic_write(Path::new(TARGET_KEYBOX), data)
        .context("failed to write keybox")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            TARGET_KEYBOX,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    Ok(())
}

fn current_keybox_hash() -> Option<String> {
    let data = std::fs::read(TARGET_KEYBOX).ok()?;
    let hash = sources::compute_sha256(&data);
    if hash.is_empty() { None } else { Some(hash) }
}

fn has_valid_existing_keybox() -> bool {
    Path::new(TARGET_KEYBOX).exists()
        && validate::validate_file(Path::new(TARGET_KEYBOX)).is_ok()
}

fn source_label(s: &KeyboxSource) -> &'static str {
    match s {
        KeyboxSource::Yurikey => "yurikey",
        KeyboxSource::Upstream => "upstream",
        KeyboxSource::Custom => "custom",
    }
}
