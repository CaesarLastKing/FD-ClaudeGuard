use crate::mihomo::clash_verge_config_dir;
use crate::state::{StartupAuditReport, StartupEntry};
use std::fs;

/// 100% 只读扫描 Windows 开机启动项（Run 注册表、Startup 文件夹、MSIX StartupTask、Clash verge.yaml）
/// 铁律：绝不修改、禁用或删除用户的任何启动项，仅如实汇报顺序竞争风险
pub fn audit_windows_startup_items(guard_boot_enabled: bool) -> StartupAuditReport {
    let clash_enabled = detect_clash_autostart();
    let claude_enabled = detect_claude_autostart();

    let entries = vec![
        StartupEntry {
            app: "FD Claude Guard".into(),
            enabled: guard_boot_enabled,
            risk_level: if guard_boot_enabled {
                "ok".into()
            } else {
                "neutral".into()
            },
            detail: if guard_boot_enabled {
                "已开启开机自启（默认仅显悬浮窗，开机自动护航）".into()
            } else {
                "当前未开启自启，建议在上方开启以提供开机防裸奔护航".into()
            },
        },
        StartupEntry {
            app: "Clash Verge Rev".into(),
            enabled: clash_enabled,
            risk_level: if clash_enabled {
                "ok".into()
            } else {
                "warn".into()
            },
            detail: if clash_enabled {
                "已开启开机自启，有助于确保代理早于应用就绪".into()
            } else {
                "未检测到 Clash Verge 开机自启，开机后请先启动代理再打开 Claude".into()
            },
        },
        StartupEntry {
            app: "Claude Desktop".into(),
            enabled: claude_enabled,
            risk_level: if claude_enabled {
                "warn".into()
            } else {
                "ok".into()
            },
            detail: if claude_enabled {
                "风险提示：检测到 Claude 已设开机自启！若早于 Clash 虚拟网卡启动，开机前 5 秒可能裸奔直连；我们绝不擅自删除你的启动项，建议手动关闭".into()
            } else {
                "未发现 Claude 开机自启项，无开机抢跑裸奔风险".into()
            },
        },
    ];

    StartupAuditReport {
        entries,
        claude_autostart_risk: claude_enabled,
    }
}

fn detect_clash_autostart() -> bool {
    // 1. 读取 Clash Verge verge.yaml 的 enable_auto_launch
    if let Some(dir) = clash_verge_config_dir() {
        let verge_yaml = dir.join("verge.yaml");
        if let Ok(content) = fs::read_to_string(verge_yaml) {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(val) = trimmed.strip_prefix("enable_auto_launch:") {
                    if val.trim().eq_ignore_ascii_case("true") {
                        return true;
                    }
                }
            }
        }
    }

    // 2. 只读扫描 Run 注册表与用户 Startup 目录
    has_startup_match(&["clash-verge", "clash verge"])
}

fn detect_claude_autostart() -> bool {
    if has_startup_match(&["claude"]) {
        return true;
    }
    detect_msix_claude_startup_task()
}

/// 判断启动项名称/命令是否属于本工具自身（防止开启 FD Claude Guard 自启后被误报为 Claude Desktop 自启）
fn is_self_guard_startup_entry(text_lower: &str) -> bool {
    if text_lower.contains("fd-claude-guard")
        || text_lower.contains("fd claude guard")
        || text_lower.contains("fdclaudeguard")
        || text_lower.contains("fdtools")
    {
        return true;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(stem) = exe.file_stem().and_then(|s| s.to_str()) {
            let stem_lower = stem.to_lowercase();
            if stem_lower.len() >= 4 && text_lower.contains(&stem_lower) {
                return true;
            }
        }
    }
    false
}

#[cfg(windows)]
fn has_startup_match(keywords: &[&str]) -> bool {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let run_subkey = r"Software\Microsoft\Windows\CurrentVersion\Run";
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        if let Ok(key) = RegKey::predef(hive).open_subkey(run_subkey) {
            for item in key.enum_values().flatten() {
                let name = item.0.to_lowercase();
                let val = format!("{:?}", item.1).to_lowercase();
                // 排除本工具自身（同时覆盖 fd-claude-guard / FD Claude Guard / 当前可执行名）
                if is_self_guard_startup_entry(&name) || is_self_guard_startup_entry(&val) {
                    continue;
                }
                if keywords.iter().any(|k| name.contains(k) || val.contains(k)) {
                    return true;
                }
            }
        }
    }

    if let Some(cfg_dir) = dirs::config_dir() {
        let startup_dir = cfg_dir
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs")
            .join("Startup");
        if let Ok(entries) = fs::read_dir(startup_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_lowercase();
                if is_self_guard_startup_entry(&fname) {
                    continue;
                }
                if keywords.iter().any(|k| fname.contains(k)) {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(not(windows))]
fn has_startup_match(_keywords: &[&str]) -> bool {
    false
}

/// 只读检查 Windows MSIX StartupTask 注册表状态（State == 2 表示用户已启用）
#[cfg(windows)]
fn detect_msix_claude_startup_task() -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    let base = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData";
    let Ok(root) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(base) else {
        return false;
    };

    for pkg in root.enum_keys().flatten() {
        let lower = pkg.to_lowercase();
        if !lower.contains("claude") && !lower.contains("anthropic") {
            continue;
        }
        if let Ok(pkg_key) = root.open_subkey(&pkg) {
            for task in pkg_key.enum_keys().flatten() {
                if let Ok(task_key) = pkg_key.open_subkey(&task) {
                    if let Ok(state) = task_key.get_value::<u32, _>("State") {
                        // Windows StartupTask State: 2 = Enabled, 4 = EnabledByPolicy
                        if state == 2 || state == 4 {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

#[cfg(not(windows))]
fn detect_msix_claude_startup_task() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch3_startup_audit_excludes_fd_claude_guard_display_and_product_names() {
        assert!(is_self_guard_startup_entry("fd claude guard"));
        assert!(is_self_guard_startup_entry("fd-claude-guard"));
        assert!(is_self_guard_startup_entry(r"c:\program files\fd claude guard\fd-claude-guard.exe --autostart"));
        assert!(!is_self_guard_startup_entry(r"c:\users\u\appdata\local\anthropicclaude\claude.exe"));
    }
}
