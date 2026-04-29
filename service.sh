MODPATH=${0%/*}
MODDIR="$MODPATH"
PATH=$MODPATH/common/bin:/data/adb/ap/bin:/data/adb/ksu/bin:/data/adb/magisk:$PATH
HIDE_DIR="/data/adb/modules/.TA_enhanced"
TSPA="/data/adb/modules/tsupport-advance"

. "$MODPATH/common/common.sh"
detect_manager

_log "INFO" "Service started (manager=$MANAGER)"

# Denylist merge function (Magisk only)
add_denylist_to_target() {
    local target_file="$TS_DIR/target.txt"
    local tmp_file="${target_file}.tmp"
    local exclamation_target question_target existing denylist

    exclamation_target=$(grep '!' "$target_file" | sed 's/!$//')
    question_target=$(grep '?' "$target_file" | sed 's/?$//')
    existing=$(sed 's/[!?]$//' "$target_file")
    denylist=$(magisk --denylist ls 2>/dev/null | awk -F'|' '{print $1}' | grep -v "isolated")

    if ! printf "%s\n" "$existing" "$denylist" | sort -u > "$tmp_file"; then
        _log "ERROR" "Failed to write target.txt from denylist"
        rm -f "$tmp_file"
        return 1
    fi

    for pkg in $exclamation_target; do
        sed -i "s/^${pkg}$/${pkg}!/" "$tmp_file"
    done
    for pkg in $question_target; do
        sed -i "s/^${pkg}$/${pkg}?/" "$tmp_file"
    done

    mv "$tmp_file" "$target_file"
}

# Security patch is handled by the daemon's SecurityPatchTask (with retries + bulletin fetch).
# Running `set` here would overwrite bulletin-fetched dates with stale device props.

# Stage resetprop-rs CLI before the inline spoof block — every prop write needs $RP
# Atomic via temp+rename so concurrent execs cannot SIGBUS / hit ETXTBSY
if [ -z "$ABI" ]; then
    _log "ERROR" "Unknown ABI (ARCH=$ARCH uname=$(uname -m)) — prop spoofing will fail"
elif [ ! -f "$MODPATH/bin/$ABI/resetprop-rs" ]; then
    _log "ERROR" "resetprop-rs binary missing for ABI=$ABI at $MODPATH/bin/$ABI/"
else
    mkdir -p "/data/adb/tricky_store/ta-enhanced/bin"
    _rp_dst="/data/adb/tricky_store/ta-enhanced/bin/resetprop-rs"
    _rp_tmp="${_rp_dst}.new"
    if cp -f "$MODPATH/bin/$ABI/resetprop-rs" "$_rp_tmp"; then
        chmod 755 "$_rp_tmp" || _log "WARN" "chmod on $_rp_tmp failed"
        mv -f "$_rp_tmp" "$_rp_dst" || _log "ERROR" "atomic rename to $_rp_dst failed"
    else
        rm -f "$_rp_tmp" 2>/dev/null
        _log "ERROR" "cp resetprop-rs to $_rp_tmp failed"
    fi
fi

# Property Spoofing (synchronous, inline — single source of truth)
# Mirrors the susfs4ksu/service.sh:113 pattern: short wait gates init's
# early prop pass without the post-zygote tax of waiting for value=1.
if [ -x "$RP" ]; then
    _log "INFO" "Property spoofing starting"
    _PROP_SPOOF_COUNT=0
    _PROP_FAIL_COUNT=0

    "$RP" --wait sys.boot_completed 0 2>/dev/null || true

    check_reset_prop "ro.boot.vbmeta.device_state" "locked"
    check_reset_prop "ro.boot.verifiedbootstate" "green"
    check_reset_prop "ro.boot.flash.locked" "1"
    check_reset_prop "ro.boot.veritymode" "enforcing"
    check_reset_prop "ro.boot.warranty_bit" "0"
    check_reset_prop "ro.warranty_bit" "0"
    check_reset_prop "ro.debuggable" "0"
    check_reset_prop "ro.force.debuggable" "0"
    check_reset_prop "ro.secure" "1"
    check_reset_prop "ro.adb.secure" "1"
    check_reset_prop "ro.build.type" "user"
    check_reset_prop "ro.build.tags" "release-keys"
    check_reset_prop "ro.vendor.boot.warranty_bit" "0"
    check_reset_prop "ro.vendor.warranty_bit" "0"
    check_reset_prop "vendor.boot.vbmeta.device_state" "locked"
    check_reset_prop "vendor.boot.verifiedbootstate" "green"
    check_reset_prop "sys.oem_unlock_allowed" "0"
    check_reset_prop "ro.secureboot.lockstate" "locked"
    check_reset_prop "ro.boot.realmebootstate" "green"
    check_reset_prop "ro.boot.realme.lockstate" "1"
    check_reset_prop "ro.crypto.state" "encrypted"
    check_reset_prop "ro.is_ever_orange" "0"
    check_reset_prop "ro.oem_unlock_supported" "0"
    check_reset_prop "ro.secureboot.devicelock" "1"

    contains_reset_prop "ro.bootmode" "recovery" "unknown"
    contains_reset_prop "ro.boot.bootmode" "recovery" "unknown"
    contains_reset_prop "ro.boot.mode" "recovery" "unknown"
    contains_reset_prop "vendor.bootmode" "recovery" "unknown"
    contains_reset_prop "vendor.boot.bootmode" "recovery" "unknown"
    contains_reset_prop "vendor.boot.mode" "recovery" "unknown"

    "$RP" --nuke ro.kernel.qemu 2>/dev/null || true

    # VBMeta digest: prefer TEESimulator-RS boot_hash.bin, fall back to /data/adb/boot_hash
    _hash_value=""
    _hash_src=""
    _ts_mp=$(cat "$TS/module.prop" 2>/dev/null)
    case "$_ts_mp" in
        *TEESimulator-RS*)
            if [ -d "$TS" ] && [ ! -f "$TS/disable" ] && [ ! -f "$TS/remove" ] \
                && [ -f "$TS_DIR/boot_hash.bin" ]; then
                _hash_value=$(od -A n -t x1 "$TS_DIR/boot_hash.bin" 2>/dev/null | tr -d ' \n')
                if echo "$_hash_value" | grep -qE '^[a-f0-9]{64}$'; then
                    _hash_src="teesim"
                else
                    _hash_value=""
                fi
            fi
            ;;
    esac
    if [ -z "$_hash_value" ] && [ -f "/data/adb/boot_hash" ]; then
        _hash_value=$(grep -v '^#' "/data/adb/boot_hash" 2>/dev/null | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        [ -n "$_hash_value" ] && _hash_src="boot_hash"
    fi
    if echo "$_hash_value" | grep -qE '^[a-f0-9]{64}$'; then
        if "$RP" -st ro.boot.vbmeta.digest "$_hash_value" 2>/dev/null; then
            _PROP_SPOOF_COUNT=$((_PROP_SPOOF_COUNT + 1))
            _log "INFO" "VBMeta digest set from $_hash_src: $(printf '%.16s' "$_hash_value")..."
            _vb_read=$(getprop ro.boot.vbmeta.digest)
            [ "$_vb_read" = "$_hash_value" ] || _log "WARN" "vbmeta.digest readback mismatch"
        else
            _PROP_FAIL_COUNT=$((_PROP_FAIL_COUNT + 1))
            _log "ERROR" "Failed to set vbmeta.digest from $_hash_src"
        fi
    elif [ -n "$_hash_value" ]; then
        _log "WARN" "boot_hash invalid from $_hash_src (not 64-char hex)"
    fi

    ensure_prop "ro.boot.vbmeta.device_state" "locked"
    ensure_prop "ro.boot.vbmeta.invalidate_on_error" "yes"
    ensure_prop "ro.boot.vbmeta.avb_version" "1.0"
    ensure_prop "ro.boot.vbmeta.hash_alg" "sha256"

    _slot=$(getprop ro.boot.slot_suffix 2>/dev/null)
    _vbmeta_size=""
    for _candidate in \
        "/dev/block/by-name/vbmeta${_slot}" \
        "/dev/block/by-name/vbmeta" \
        "/dev/block/by-name/vbmeta_a" \
        "/dev/block/by-name/vbmeta_b"; do
        if [ -b "$_candidate" ]; then
            _vbmeta_size=$(blockdev --getsize64 "$_candidate" 2>/dev/null)
            [ -n "$_vbmeta_size" ] && [ "$_vbmeta_size" -gt 0 ] 2>/dev/null && break
            _vbmeta_size=""
        fi
    done
    ensure_prop "ro.boot.vbmeta.size" "${_vbmeta_size:-4096}"

    # Region restore — values snapshotted at install by customize.sh:179-190
    if [ "$(read_config region.enabled true)" = "true" ]; then
        _r_hwc=$(read_config region.hwc "")
        _r_hwcountry=$(read_config region.hwcountry "")
        _r_mod_device=$(read_config region.mod_device "")
        _r_hw_sku=$(read_config region.hardware_sku "")
        [ -n "$_r_hwc" ] && check_reset_prop "ro.boot.hwc" "$_r_hwc"
        [ -n "$_r_hwcountry" ] && check_reset_prop "ro.boot.hwcountry" "$_r_hwcountry"
        [ -n "$_r_mod_device" ] && check_reset_prop "ro.product.mod_device" "$_r_mod_device"
        [ -n "$_r_hw_sku" ] && check_reset_prop "ro.boot.product.hardware.sku" "$_r_hw_sku"
    fi

    # User-defined custom props from [props].custom_props in config.toml.
    # Capture-then-iterate so counter increments survive (pipe-fed `while` runs in a subshell).
    _custom_props=$("$BIN" config props-custom 2>/dev/null)
    while IFS="$(printf '\t')" read -r _cp_name _cp_value; do
        [ -z "$_cp_name" ] && continue
        if "$RP" -st "$_cp_name" "$_cp_value" 2>/dev/null; then
            _PROP_SPOOF_COUNT=$((_PROP_SPOOF_COUNT + 1))
            _log "DEBUG" "custom_prop set: $_cp_name"
        else
            _PROP_FAIL_COUNT=$((_PROP_FAIL_COUNT + 1))
            _log "ERROR" "Failed to set custom_prop: $_cp_name"
        fi
    done <<HEREDOC
$_custom_props
HEREDOC

    # --- Early cleanup pass: init-bound props only ---
    # Fingerprint scrub targets ROM-version props that init populates from
    # build.prop at its first pass. Late-binding artifacts (Xposed-injected
    # GMS spoofs, system_ext/product/odm_dlkm overlays) get a second pass
    # post-boot below.
    _all_props=$(getprop)

    _fingerprint_file="$MODPATH/common/rom-fingerprints.txt"
    if [ -f "$_fingerprint_file" ]; then
        while IFS= read -r _fp; do
            case "$_fp" in \#*|"") continue ;; esac
            if echo "$_all_props" | grep -qi "^\[ro\.${_fp}"; then
                _log "INFO" "Preserving own ROM props: $_fp"
                continue
            fi
            echo "$_all_props" | cut -d'[' -f2 | cut -d']' -f1 | grep -F "$_fp" | \
                while IFS= read -r _prop_name; do
                    [ -n "$_prop_name" ] && "$RP" --nuke "$_prop_name" 2>/dev/null
                done
        done < "$_fingerprint_file"
    fi

    _log "INFO" "Property spoofing (early) complete: $_PROP_SPOOF_COUNT spoofed, $_PROP_FAIL_COUNT failed"
else
    _log "ERROR" "resetprop-rs missing at $RP — skipping property spoofing"
fi

# TSupport-A Interop
if [ -d "$TSPA" ]; then
    touch "/storage/emulated/0/stop-tspa-auto-target" 2>/dev/null || true
elif [ ! -d "$TSPA" ] && [ -f "/storage/emulated/0/stop-tspa-auto-target" ]; then
    rm -f "/storage/emulated/0/stop-tspa-auto-target"
fi

# Magisk Module Hiding
# Dot-prefix hides from Magisk's module list scan (stable since Magisk v24+).
# service.sh re-copies on every boot so the hidden copy is always fresh.
if [ -f "$MODPATH/action.sh" ]; then
    if [ "$MODPATH" != "$HIDE_DIR" ]; then
        _log "INFO" "Module hiding (Magisk)"
        rm -rf "$HIDE_DIR"
        mkdir -p "$HIDE_DIR"
        busybox chcon --reference="$MODPATH" "$HIDE_DIR" 2>/dev/null || true
        if ! cp -af "$MODPATH/." "$HIDE_DIR/"; then
            _log "ERROR" "Module hiding copy failed, using original path"
            rm -rf "$HIDE_DIR"
        else
            MODPATH="$HIDE_DIR"
            MODDIR="$MODPATH"
            BIN="$MODPATH/bin/${ABI}/ta-enhanced"
        fi
    fi

    # Merge Magisk denylist into target.txt (flag-file-gated)
    [ -f "$TS_DIR/target_from_denylist" ] && add_denylist_to_target
else
    # KSU/APatch: clean up any stale hidden dir
    [ -d "$HIDE_DIR" ] && rm -rf "$HIDE_DIR"
fi

# Ensure system_app file exists for WebUI system app display
if [ ! -f "$TS_DIR/system_app" ]; then
    : > "$TS_DIR/system_app"
    for app in com.google.android.gms com.google.android.gsf com.android.vending \
               com.oplus.deepthinker com.heytap.speechassist com.coloros.sceneservice; do
        pm list packages -s 2>/dev/null | grep -q "package:$app" && echo "$app" >> "$TS_DIR/system_app"
    done
fi

# Preserve module.prop for WebUI version display, then hide from manager UI
cp -f "$MODPATH/module.prop" "/data/adb/tricky_store/ta-enhanced/module.prop" 2>/dev/null || true
rm -f "$MODPATH/module.prop"

# Symlink Management
if [ -f "$MODPATH/action.sh" ] && [ ! -e "$TS/action.sh" ]; then
    ln -s "$MODPATH/action.sh" "$TS/action.sh" 2>/dev/null || true
fi
if [ ! -e "$TS/webroot" ]; then
    ln -s "$MODPATH/webui" "$TS/webroot" 2>/dev/null || true
fi
if [ ! -e "$TS/banner.png" ] && [ -f "$MODPATH/banner.png" ]; then
    ln -s "$MODPATH/banner.png" "$TS/banner.png" 2>/dev/null || true
fi
if [ -f "$TS/module.prop" ] && ! grep -q "^banner=" "$TS/module.prop"; then
    sed -i '$ a\banner=banner.png' "$TS/module.prop" 2>/dev/null || true
fi

# Wait for Boot Completion
_log "INFO" "Waiting for boot completion"
# getprop -w blocks until property is set (Android 10+)
# Timeout after 120s to prevent hanging on broken boots
timeout 120 getprop -w sys.boot_completed 2>/dev/null || {
    until [ "$(getprop sys.boot_completed)" = "1" ]; do
        sleep 5
    done
}
_log "INFO" "Boot completed"

# Property Spoofing — Late Phase (post-zygote)
# GMS-spoof artifacts come from Xposed at zygote; build-string overlays from
# late-mounted partitions (system_ext, product, odm_dlkm) — both need a fresh
# getprop snapshot taken after sys.boot_completed=1.
if [ -x "$RP" ]; then
    _log "INFO" "Property spoofing (late) starting"
    _late_base_spoof=$_PROP_SPOOF_COUNT
    _late_base_fail=$_PROP_FAIL_COUNT
    _all_props=$(getprop)

    echo "$_all_props" | grep -E "pihook|pixelprops|eliteprops|spoof.gms" | \
        sed -E 's/^\[(.*)\]:.*/\1/' | while IFS= read -r _prop_name; do
            [ -n "$_prop_name" ] && "$RP" --nuke "$_prop_name" 2>/dev/null
        done

    replace_value_prop ro.build.flavor "lineage_" ""
    replace_value_prop ro.build.flavor "userdebug" "user"
    replace_value_prop ro.build.display.id "eng." ""
    replace_value_prop ro.build.display.id "lineage_" ""
    replace_value_prop ro.build.display.id "userdebug" "user"
    replace_value_prop ro.build.display.id "dev-keys" "release-keys"
    replace_value_prop vendor.camera.aux.packagelist "lineageos." ""
    replace_value_prop ro.build.version.incremental "eng." ""

    for _prefix in bootimage odm odm_dlkm oem product system system_ext vendor vendor_dlkm; do
        check_reset_prop "ro.${_prefix}.build.type" "user"
        check_reset_prop "ro.${_prefix}.build.tags" "release-keys"
        replace_value_prop "ro.${_prefix}.build.version.incremental" "eng." ""
        for _suffix in build.description build.fingerprint; do
            replace_value_prop "ro.${_prefix}.${_suffix}" "aosp_" ""
        done
        replace_value_prop "ro.product.${_prefix}.name" "aosp_" ""
    done

    _test_keys_props=$(echo "$_all_props" | grep "test-keys" | cut -d'[' -f2 | cut -d']' -f1)
    while IFS= read -r _prop_name; do
        [ -n "$_prop_name" ] && replace_value_prop "$_prop_name" "test-keys" "release-keys"
    done <<HEREDOC
$_test_keys_props
HEREDOC

    _late_spoof=$((_PROP_SPOOF_COUNT - _late_base_spoof))
    _late_fail=$((_PROP_FAIL_COUNT - _late_base_fail))
    _log "INFO" "Property spoofing (late) complete: $_late_spoof spoofed, $_late_fail failed"
fi

pm list packages -s 2>/dev/null | sed 's/^package://' | sort > "/data/adb/tricky_store/ta-enhanced/system_packages.txt"

# VBHash Extraction (config-gated)
vbhash_enabled=$(read_config vbhash.enabled true)
if [ "$vbhash_enabled" = "true" ]; then
    _log "INFO" "Running VBHash extraction"
    "$BIN" vbhash extract 2>/dev/null || _log "WARN" "VBHash extraction failed"
else
    _log "INFO" "VBHash extraction disabled"
fi

# Conflict Check
_log "INFO" "Checking for conflicts at boot"
"$BIN" conflict check 2>/dev/null || _log "WARN" "Conflicts detected, check conflict.log"

# Create tmp directory (needed by action.sh for KSU WebUI APK download)
mkdir -p "$MODPATH/common/tmp"

# Xposed Detection (background)
"$BIN" status xposed-scan >> "$LOG_BASE_DIR/main.log" 2>&1 &

# Magisk: clean up unhidden module dir
[ -f "$MODPATH/action.sh" ] && rm -rf "/data/adb/modules/TA_enhanced"

# Launch Daemon
_log "INFO" "Starting ta-enhanced daemon"
"$BIN" daemon --manager "$MANAGER" &
_log "INFO" "Daemon launched"
