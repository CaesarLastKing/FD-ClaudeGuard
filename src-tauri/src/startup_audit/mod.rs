use crate::mihomo::clash_verge_config_dir;
use crate::state::{StartupAuditReport, StartupEntry};
use std::fs;

/// Windows 管理员高权限登录自启计划任务名（突破 requireAdministrator 被 HKCU\Run UAC 静默拦截）
pub const AUTOSTART_TASK_NAME: &str = "FDClaudeGuard_AutoStart";

/// 同步 Windows 管理员高权限登录自启计划任务（并顺手清理无效的旧 HKCU\Run 项）
#[cfg(windows)]
pub fn sync_windows_autostart_task(enable: bool) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // 清理可能由旧版 tauri-plugin-autostart 写入但会被 UAC 拦截的 HKCU\Run 项
    if let Ok(run_key) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Run", KEY_WRITE)
    {
        for old_name in ["FD Claude Guard", "fd-claude-guard", "FDClaudeGuard"] {
            let _ = run_key.delete_value(old_name);
        }
    }

    if enable {
        let exe = std::env::current_exe().map_err(|e| format!("无法获取当前程序路径: {e}"))?;
        let exe_str = exe.to_string_lossy();
        let tr = format!("\"{exe_str}\" --autostart");
        let out = Command::new("schtasks")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "/Create",
                "/F",
                "/SC",
                "ONLOGON",
                "/RL",
                "HIGHEST",
                "/TN",
                AUTOSTART_TASK_NAME,
                "/TR",
                &tr,
            ])
            .output()
            .map_err(|e| format!("调用 schtasks 注册开机自启失败: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            return Err(format!(
                "注册 Windows 管理员开机自启计划任务失败（请确认以管理员权限运行）: {} {}",
                stderr.trim(),
                stdout.trim()
            ));
        }
        Ok(())
    } else {
        let out = Command::new("schtasks")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/Delete", "/F", "/TN", AUTOSTART_TASK_NAME])
            .output()
            .map_err(|e| format!("调用 schtasks 删除开机自启任务失败: {e}"))?;
        // 若原本就不存在该任务（exit code 1）视为已关闭成功
        if !out.status.success() && is_windows_autostart_task_enabled() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!("删除开机自启计划任务失败: {}", stderr.trim()));
        }
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn sync_windows_autostart_task(_enable: bool) -> Result<(), String> {
    Ok(())
}

/// 真实查询 Windows 管理员开机自启计划任务是否已注册
#[cfg(windows)]
pub fn is_windows_autostart_task_enabled() -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new("schtasks")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["/Query", "/TN", AUTOSTART_TASK_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
pub fn is_windows_autostart_task_enabled() -> bool {
    false
}

/// 100% 只读扫描 Windows 开机启动项（Run 注册表含 StartupApproved 禁用位、用户与公共 Startup 目录、MSIX StartupTask、Clash verge.yaml）
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
                "已通过 Windows 高权限计划任务注册开机自启（开机自动护航）".into()
            } else {
                "当前未注册开机自启任务，建议在上方开启以提供开机防裸奔护航".into()
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

/// 判断 StartupApproved 注册表二进制值是否被用户禁用（Windows 规范：首字节为奇数如 0x03/0x07 表示已禁用，偶数为启用）
#[cfg(windows)]
fn is_startup_approved_disabled(hive: winreg::HKEY, subkey: &str, value_name: &str) -> bool {
    use winreg::RegKey;
    let Ok(key) = RegKey::predef(hive).open_subkey(subkey) else {
        return false;
    };
    let Ok(raw) = key.get_raw_value(value_name) else {
        return false;
    };
    raw.bytes.first().map(|&b| b % 2 == 1).unwrap_or(false)
}

#[cfg(windows)]
fn has_startup_match(keywords: &[&str]) -> bool {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let run_pairs = [
        (
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32",
        ),
    ];
    for (hive, run_subkey, approved_subkey) in run_pairs {
        if let Ok(key) = RegKey::predef(hive).open_subkey(run_subkey) {
            for item in key.enum_values().flatten() {
                let raw_name = item.0;
                let name = raw_name.to_lowercase();
                let val = format!("{:?}", item.1).to_lowercase();
                if is_self_guard_startup_entry(&name) || is_self_guard_startup_entry(&val) {
                    continue;
                }
                if keywords.iter().any(|k| name.contains(k) || val.contains(k)) {
                    // 遵循 Windows StartupApproved：用户在系统设置中关闭自启时首字节为奇数，视为已禁用
                    if is_startup_approved_disabled(hive, approved_subkey, &raw_name) {
                        continue;
                    }
                    return true;
                }
            }
        }
    }

    let mut startup_dirs: Vec<(winreg::HKEY, std::path::PathBuf)> = Vec::new();
    if let Some(cfg_dir) = dirs::config_dir() {
        startup_dirs.push((
            HKEY_CURRENT_USER,
            cfg_dir
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
        ));
    }
    if let Ok(prog_data) = std::env::var("ProgramData") {
        startup_dirs.push((
            HKEY_LOCAL_MACHINE,
            std::path::PathBuf::from(prog_data)
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup"),
        ));
    }
    for (hive, startup_dir) in startup_dirs {
        if let Ok(entries) = fs::read_dir(startup_dir) {
            for entry in entries.flatten() {
                let raw_fname = entry.file_name().to_string_lossy().to_string();
                let fname = raw_fname.to_lowercase();
                if is_self_guard_startup_entry(&fname) {
                    continue;
                }
                if keywords.iter().any(|k| fname.contains(k)) {
                    if is_startup_approved_disabled(
                        hive,
                        r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder",
                        &raw_fname,
                    ) {
                        continue;
                    }
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
