use serde::Serialize;
use std::path::Path;
use crate::config::Config;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const KEYBOX_PATH: &str = "/data/adb/tricky_store/keybox.xml";
const TARGET_PATH: &str = "/data/adb/tricky_store/target.txt";
const BOOT_HASH_PATH: &str = "/data/adb/boot_hash";
const SP_PATH: &str = "/data/adb/tricky_store/security_patch.txt";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebuiInitResponse {
    pub module: ModuleInfo,
    pub config: Config,
    pub status: StatusInfo,
    pub conflicts: ConflictReport,
    pub keybox: KeyboxInfo,
    pub security_patch: SecurityPatchInfo,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModuleInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub version_code: u32,
    pub author: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusInfo {
    pub engine: String,
    pub engine_running: bool,
    pub active_apps: u32,
    pub total_targeted: u32,
    pub keybox_label: String,
    pub patch_level: String,
    pub vbhash_active: bool,
    pub restart_count: u32,
    pub ts_fork_supported: bool,
    pub ts_james_fork: bool,
    pub magisk_available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictReport {
    pub modules: Vec<ConflictModule>,
    pub apps: Vec<ConflictApp>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictModule {
    pub id: String,
    pub name: String,
    pub reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictApp {
    pub package_name: String,
    pub name: String,
    pub reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyboxInfo {
    pub valid: bool,
    pub source: String,
    pub root_type: String,
    pub last_fetch: Option<String>,
    pub validation_errors: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPatchInfo {
    pub system: String,
    pub boot: String,
    pub vendor: String,
    pub latest: Option<String>,
    pub auto_update: bool,
}

fn read_module_prop(key: &str) -> Option<String> {
    [
        "/data/adb/tricky_store/ta-enhanced/module.prop",
        "/data/adb/modules/.TA_enhanced/module.prop",
        "/data/adb/modules/TA_enhanced/module.prop",
    ]
    .iter()
    .find_map(|p| std::fs::read_to_string(p).ok())
    .and_then(|s| {
        s.lines()
            .find(|l| l.starts_with(&format!("{key}=")))
            .map(|l| l.split_once('=').map(|x| x.1).unwrap_or("").to_string())
    })
}

fn count_target_entries() -> u32 {
    std::fs::read_to_string(TARGET_PATH)
        .map(|c| c.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')).count() as u32)
        .unwrap_or(0)
}

fn read_patch_dates() -> (String, String, String) {
    let Ok(content) = std::fs::read_to_string(SP_PATH) else {
        return (String::new(), String::new(), String::new());
    };
    let mut system = String::new();
    let mut boot = String::new();
    let mut vendor = String::new();
    for line in content.lines() {
        if let Some(val) = line.strip_prefix("system=") {
            system = val.trim().into();
        } else if let Some(val) = line.strip_prefix("boot=") {
            boot = val.trim().into();
        } else if let Some(val) = line.strip_prefix("vendor=") {
            vendor = val.trim().into();
        }
    }
    (system, boot, vendor)
}

fn check_keybox() -> (bool, String, Vec<String>) {
    let path = Path::new(KEYBOX_PATH);
    if !path.exists() {
        return (false, "none".into(), vec!["keybox.xml not found".into()]);
    }
    match crate::keybox::validate::validate_file_full(path) {
        Ok(report) => {
            let root_type = report
                .keys
                .first()
                .map(|k| k.root_type.as_snake_case().to_string())
                .unwrap_or_else(|| "unknown".into());
            let errors: Vec<String> = report
                .keys
                .iter()
                .filter(|k| !k.ok)
                .flat_map(|k| k.errors.clone())
                .collect();
            (report.ok, root_type, errors)
        }
        Err(e) => (false, "unknown".into(), vec![e.to_string()]),
    }
}

fn build_conflicts(cfg: &Config) -> ConflictReport {
    if !cfg.conflict.enabled {
        return ConflictReport { modules: Vec::new(), apps: Vec::new() };
    }
    let status = match crate::conflict::check_all(false) {
        Ok(s) => s,
        Err(_) => return ConflictReport { modules: Vec::new(), apps: Vec::new() },
    };

    let mut modules: Vec<ConflictModule> = status.aggressive_conflicts.iter()
        .map(|id| ConflictModule { id: id.clone(), name: id.clone(), reason: "aggressive".into() })
        .collect();
    modules.extend(status.regular_conflicts.iter()
        .map(|id| ConflictModule { id: id.clone(), name: id.clone(), reason: "regular".into() }));

    let apps: Vec<ConflictApp> = status.app_conflicts.iter()
        .map(|pkg| ConflictApp { package_name: pkg.clone(), name: pkg.clone(), reason: "conflicting app".into() })
        .collect();

    ConflictReport { modules, apps }
}

pub fn handle_webui_init(cfg: &Config) -> anyhow::Result<()> {
    let engine = crate::health::detect_engine();
    let engine_running = crate::health::is_engine_enabled();
    let total = count_target_entries();
    let (system, boot, vendor) = read_patch_dates();
    let (kb_valid, kb_root_type, kb_errors) = check_keybox();
    let vbhash_active = std::fs::read_to_string(BOOT_HASH_PATH)
        .map(|h| h.trim().len() == 64 && h.trim().chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or(false);

    let restart_count = crate::health::read_state()
        .map(|s| s.restarts).unwrap_or(0);

    let ts_prop = std::fs::read_to_string("/data/adb/modules/tricky_store/module.prop")
        .unwrap_or_default();
    let ts_ver: u32 = ts_prop.lines()
        .find(|l| l.starts_with("versionCode="))
        .and_then(|l| l.split_once('=')?.1.trim().parse().ok())
        .unwrap_or(0);
    let has_james = ts_prop.contains("James");
    let has_beakthoven = ts_prop.contains("beakthoven");
    let has_jingmatrix = ts_prop.contains("JingMatrix");
    let ts_fork_supported = has_james || has_beakthoven || has_jingmatrix || ts_ver >= 158;
    let ts_james_fork = has_james && !has_beakthoven;

    let magisk_available = std::process::Command::new("sh")
        .args(["-c", "command -v magisk"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let resp = WebuiInitResponse {
        module: ModuleInfo {
            id: read_module_prop("id").unwrap_or_else(|| "TA_enhanced".into()),
            name: read_module_prop("name").unwrap_or_else(|| "Tricky Addon Enhanced".into()),
            version: read_module_prop("version").unwrap_or_else(|| format!("v{VERSION}")),
            version_code: read_module_prop("versionCode").and_then(|v| v.parse().ok()).unwrap_or(0),
            author: read_module_prop("author").unwrap_or_else(|| "KOWX712, Enginex0".into()),
        },
        config: cfg.clone(),
        status: StatusInfo {
            engine_running,
            active_apps: total,
            total_targeted: total,
            keybox_label: if kb_valid { cfg.keybox.source.clone() } else { "none".into() },
            patch_level: system.clone(),
            vbhash_active,
            engine,
            restart_count,
            ts_fork_supported,
            ts_james_fork,
            magisk_available,
        },
        conflicts: build_conflicts(cfg),
        keybox: KeyboxInfo {
            valid: kb_valid,
            source: if kb_valid { cfg.keybox.source.clone() } else { "none".into() },
            root_type: kb_root_type,
            last_fetch: None,
            validation_errors: kb_errors,
        },
        security_patch: SecurityPatchInfo {
            system,
            boot,
            vendor,
            latest: None,
            auto_update: cfg.security_patch.auto_update,
        },
    };

    serde_json::to_writer(std::io::stdout(), &resp)?;
    println!();
    Ok(())
}
