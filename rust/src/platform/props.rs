use std::process::Command;

pub const RP_PATH: &str = "/data/adb/tricky_store/ta-enhanced/bin/resetprop-rs";

pub fn getprop(name: &str) -> Option<String> {
    let output = Command::new("getprop").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if val.is_empty() { None } else { Some(val) }
}

pub fn set(name: &str, value: &str) -> anyhow::Result<()> {
    let status = Command::new(RP_PATH)
        .args(["-n", name, value])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("resetprop-rs -n {name} failed")
    }
}

