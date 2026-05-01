use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::config::Config;
use crate::platform::network;

const MODULE_DIR: &str = "/data/adb/modules/TA_enhanced";
const MODULE_DIR_HIDDEN: &str = "/data/adb/modules/.TA_enhanced";
const UPDATE_JSON_URL: &str =
    "https://raw.githubusercontent.com/KOWX712/Tricky-Addon-Update-Target-List/main/ta-enhanced/update.json";
const GITHUB_API_RELEASES: &str =
    "https://api.github.com/repos/KOWX712/Tricky-Addon-Update-Target-List/releases/latest";
const LOCALES_BASE_URL: &str =
    "https://raw.githubusercontent.com/KOWX712/Tricky-Addon-Update-Target-List/main/ta-enhanced/locales";

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub available: bool,
    pub current_version: String,
    pub latest_version: String,
    pub download_url: String,
    pub changelog_url: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct UpdateJson {
    version: Option<String>,
    #[serde(alias = "versionCode")]
    version_code: Option<u32>,
    #[serde(alias = "zipUrl")]
    zip_url: Option<String>,
    changelog: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct GithubRelease {
    tag_name: Option<String>,
    body: Option<String>,
    assets: Option<Vec<GithubAsset>>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub fn handle_module(action: crate::cli::ModuleAction, cfg: &Config) -> Result<()> {
    use crate::cli::ModuleAction;
    match action {
        ModuleAction::CheckUpdate => {
            let available = check_update(cfg)?;
            println!("{}", if available { "update_available" } else { "up_to_date" });
            Ok(())
        }
        ModuleAction::GetUpdate => {
            let info = get_update(cfg)?;
            serde_json::to_writer(std::io::stdout(), &info)?;
            println!();
            Ok(())
        }
        ModuleAction::InstallUpdate => install_update(cfg),
        ModuleAction::ReleaseNote => {
            let note = release_note(cfg)?;
            println!("{note}");
            Ok(())
        }
        ModuleAction::Uninstall => uninstall(),
        ModuleAction::UpdateLocales => update_locales(cfg),
        ModuleAction::Download { url } => {
            let tmp_dir = Path::new("/data/local/tmp");
            let filename = url
                .rsplit('/')
                .next()
                .unwrap_or("download.bin");
            let dest = tmp_dir.join(filename);
            download_file(&url, &dest)?;
            println!("{}", dest.display());
            Ok(())
        }
    }
}

pub fn check_update(_cfg: &Config) -> Result<bool> {
    let text = network::download_text(UPDATE_JSON_URL)
        .context("failed to fetch update.json")?;
    let update: UpdateJson = serde_json::from_str(&text)
        .context("failed to parse update.json")?;

    let latest = update.version.unwrap_or_default();
    let current = current_version();
    debug!("version check: current={current}, latest={latest}");

    Ok(version_newer(&latest, &current))
}

pub fn get_update(_cfg: &Config) -> Result<UpdateInfo> {
    let text = network::download_text(UPDATE_JSON_URL)
        .context("failed to fetch update.json")?;
    let update: UpdateJson = serde_json::from_str(&text)
        .context("failed to parse update.json")?;

    let current = current_version();
    let latest = update.version.unwrap_or_default();
    let available = version_newer(&latest, &current);

    Ok(UpdateInfo {
        available,
        current_version: current,
        latest_version: latest,
        download_url: update.zip_url.unwrap_or_default(),
        changelog_url: update.changelog.unwrap_or_default(),
    })
}

pub fn install_update(_cfg: &Config) -> Result<()> {
    let text = network::download_text(UPDATE_JSON_URL)
        .context("failed to fetch update.json")?;
    let update: UpdateJson = serde_json::from_str(&text)
        .context("failed to parse update.json")?;

    let zip_url = update.zip_url
        .filter(|u| !u.is_empty())
        .ok_or_else(|| anyhow::anyhow!("no download URL in update.json"))?;

    let dest = Path::new("/data/local/tmp/ta-enhanced-update.zip");
    download_file(&zip_url, dest)?;

    info!("update downloaded to {}", dest.display());
    println!("{}", dest.display());
    Ok(())
}

pub fn release_note(_cfg: &Config) -> Result<String> {
    let text = network::download_text(GITHUB_API_RELEASES)
        .context("failed to fetch GitHub release")?;
    let release: GithubRelease = serde_json::from_str(&text)
        .context("failed to parse GitHub release")?;

    let tag = release.tag_name.unwrap_or_else(|| "unknown".into());
    let body = release.body.unwrap_or_else(|| "No release notes.".into());

    Ok(format!("{tag}\n\n{body}"))
}

pub fn uninstall() -> Result<()> {
    let mod_dir = find_module_dir()
        .ok_or_else(|| anyhow::anyhow!("module directory not found"))?;

    if let Err(e) = crate::status::restore_original_description() {
        debug!("could not restore description: {e}");
    }

    let remove_flag = Path::new(&mod_dir).join("remove");
    std::fs::write(&remove_flag, "")
        .context("failed to write remove flag")?;

    info!("module marked for removal on next reboot");
    println!("module will be removed on next reboot");
    Ok(())
}

pub fn update_locales(_cfg: &Config) -> Result<()> {
    let mod_dir = find_module_dir()
        .ok_or_else(|| anyhow::anyhow!("module directory not found"))?;
    let locale_dir = Path::new(&mod_dir).join("webui").join("locales");
    crate::platform::fs::ensure_dir(&locale_dir)?;

    let locales = [
        "ar", "az", "bn", "de", "el", "en", "es-ES", "fa", "fr", "id", "it",
        "ja", "ko", "pl", "pt-BR", "ru", "th", "tl", "tr", "uk", "vi", "zh-CN", "zh-TW",
    ];

    let mut updated = 0u32;
    for locale in &locales {
        let url = format!("{LOCALES_BASE_URL}/{locale}/strings.xml");
        let dest = locale_dir.join(locale).join("strings.xml");

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).ok();
        }

        match download_file(&url, &dest) {
            Ok(_) => {
                updated += 1;
                debug!("updated locale: {locale}");
            }
            Err(e) => {
                debug!("failed to update locale {locale}: {e}");
            }
        }
    }

    info!("{updated}/{} locales updated", locales.len());
    println!("{updated} locales updated");
    Ok(())
}

fn download_file(url: &str, dest: &Path) -> Result<()> {
    let data = network::download(url)
        .with_context(|| format!("failed to download {url}"))?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(dest, &data)
        .with_context(|| format!("failed to write {}", dest.display()))?;
    Ok(())
}

fn current_version() -> String {
    read_module_prop("version").unwrap_or_else(|| VERSION.to_string())
}

fn read_module_prop(key: &str) -> Option<String> {
    let dir = find_module_dir()?;
    let prop_path = Path::new(&dir).join("module.prop");
    let content = std::fs::read_to_string(prop_path).ok()?;
    content
        .lines()
        .find(|l| l.starts_with(&format!("{key}=")))
        .map(|l| l.split_once('=').map(|x| x.1).unwrap_or("").to_string())
}

fn find_module_dir() -> Option<String> {
    [MODULE_DIR_HIDDEN, MODULE_DIR]
        .iter()
        .find(|p| Path::new(p).is_dir())
        .map(|p| p.to_string())
}

fn version_newer(latest: &str, current: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.trim_start_matches('v')
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect()
    };

    let l = parse(latest);
    let c = parse(current);

    for i in 0..l.len().max(c.len()) {
        let lv = l.get(i).copied().unwrap_or(0);
        let cv = c.get(i).copied().unwrap_or(0);
        if lv > cv {
            return true;
        }
        if lv < cv {
            return false;
        }
    }
    false
}
