use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::RegionConfig;
use crate::platform::fs::atomic_write;
use crate::platform::props::{getprop, set as prop_set};

const SNAPSHOT_PATH: &str = "/data/adb/tricky_store/ta-enhanced/region.snapshot.json";

#[derive(Default, Serialize, Deserialize)]
struct Snapshot {
    hwc: String,
    hwcountry: String,
    mod_device: String,
    hardware_sku: String,
}

pub fn apply(cfg: &RegionConfig) {
    let snap = load_or_capture_snapshot();
    let mappings: [(&str, &str, &str); 4] = [
        ("ro.boot.hwc", &cfg.hwc, &snap.hwc),
        ("ro.boot.hwcountry", &cfg.hwcountry, &snap.hwcountry),
        ("ro.product.mod_device", &cfg.mod_device, &snap.mod_device),
        ("ro.boot.product.hardware.sku", &cfg.hardware_sku, &snap.hardware_sku),
    ];

    for (prop, configured, original) in mappings {
        let value = if cfg.enabled && !configured.is_empty() {
            configured
        } else {
            original
        };
        if value.is_empty() {
            continue;
        }
        match prop_set(prop, value) {
            Ok(()) => info!("region: {prop} set"),
            Err(e) => warn!("region: failed to set {prop}: {e}"),
        }
    }
}

fn load_or_capture_snapshot() -> Snapshot {
    let path = Path::new(SNAPSHOT_PATH);
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(snap) = serde_json::from_str::<Snapshot>(&content) {
                return snap;
            }
            warn!("region: snapshot at {SNAPSHOT_PATH} unparseable; recapturing");
        }
    }
    let snap = Snapshot {
        hwc: getprop("ro.boot.hwc").unwrap_or_default(),
        hwcountry: getprop("ro.boot.hwcountry").unwrap_or_default(),
        mod_device: getprop("ro.product.mod_device").unwrap_or_default(),
        hardware_sku: getprop("ro.boot.product.hardware.sku").unwrap_or_default(),
    };
    match serde_json::to_string_pretty(&snap) {
        Ok(json) => {
            if let Err(e) = atomic_write(path, json.as_bytes()) {
                warn!("region: snapshot persist failed: {e}");
            } else {
                info!("region: snapshot captured at {SNAPSHOT_PATH}");
            }
        }
        Err(e) => warn!("region: snapshot serialize failed: {e}"),
    }
    snap
}
