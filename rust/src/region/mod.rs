use tracing::{info, warn};

use crate::config::RegionConfig;
use crate::platform::props::set as prop_set;

const REGION_PROPS: &[(&str, fn(&RegionConfig) -> &str)] = &[
    ("ro.boot.hwc", |c| c.hwc.as_str()),
    ("ro.boot.hwcountry", |c| c.hwcountry.as_str()),
    ("ro.product.mod_device", |c| c.mod_device.as_str()),
    ("ro.boot.product.hardware.sku", |c| c.hardware_sku.as_str()),
];

pub fn apply(cfg: &RegionConfig) {
    if !cfg.enabled {
        return;
    }
    for (prop, accessor) in REGION_PROPS {
        let value = accessor(cfg);
        if value.is_empty() {
            continue;
        }
        match prop_set(prop, value) {
            Ok(()) => info!("region: {prop}={value}"),
            Err(e) => warn!("region: failed to set {prop}: {e}"),
        }
    }
}
