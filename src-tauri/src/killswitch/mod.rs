use crate::mihomo::{discover_endpoint, is_blocked_node_name, mihomo_request, MihomoEndpoint};
use crate::process::{kill_claude_process_tree, resolve_claude_exe_path};
use crate::protocol::FD_ERR_KILL_SWITCH;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Command;

/// 增量 15：本工具写入的全部 Windows Defender 防火墙规则统一固定前缀
pub const FIREWALL_RULE_PREFIX: &str = "FDClaudeGuard_KillSwitch_";
pub const FIREWALL_RULE_NAME: &str = "FDClaudeGuard_KillSwitch_BlockOut";
pub const FIREWALL_WAKE_RULE_NAME: &str = "FDClaudeGuard_KillSwitch_WakeWindow";
pub const FIREWALL_PROBE_RULE_NAME: &str = "FDClaudeGuard_KillSwitch_Probe";
pub const FIREWALL_HELPER_TASK_NAME: &str = "FDClaudeGuard_FirewallHelper";
/// 兼容旧版本可能遗留的规则名，清理时一并清除
const LEGACY_FIREWALL_RULE_NAME: &str = "FDGuard_Block_Claude_Out";

/// 单条 Claude 实时连接流记录（来自 Mihomo GET /connections）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeConn {
    pub id: String,
    pub anomaly: bool,
    pub process: String,
    pub host: String,
    pub rule: String,
    pub chain: String,
    pub action: String,
    pub time: String,
    pub bytes_label: String,
}

/// 4 层紧急防回传 / 防火墙熔断状态
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KillSwitchState {
    pub active: bool,
    pub rule_name: String,
    pub target_exe: Option<String>,
    pub firewall_applied: bool,
    pub claude_connections_closed: usize,
    pub killed_processes: u32,
    pub telemetry_cleared_bytes: u64,
    pub reason: String,
    pub updated_at: String,
}

impl Default for KillSwitchState {
    fn default() -> Self {
        Self {
            active: false,
            rule_name: FIREWALL_RULE_NAME.to_string(),
            target_exe: None,
            firewall_applied: false,
            claude_connections_closed: 0,
            killed_processes: 0,
            telemetry_cleared_bytes: 0,
            reason: String::new(),
            updated_at: String::new(),
        }
    }
}

/// 解析 Mihomo /connections JSON，筛选所有 Claude 相关或 Anthropic 域名连接并标记异常流量
pub fn parse_claude_connections(raw_json: &str) -> Vec<ClaudeConn> {
    let Ok(val) = serde_json::from_str::<Value>(raw_json) else {
        return Vec::new();
    };
    let Some(arr) = val.get("connections").and_then(|c| c.as_array()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for item in arr {
        let id = item
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let meta = item.get("metadata").unwrap_or(&Value::Null);
        let process = meta
            .get("process")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let host_raw = meta
            .get("host")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| meta.get("destinationIP").and_then(|v| v.as_str()))
            .unwrap_or("unknown");
        let port = meta
            .get("destinationPort")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let host = if port.is_empty() {
            host_raw.to_string()
        } else {
            format!("{host_raw}:{port}")
        };

        let lower_proc = process.to_lowercase();
        let lower_host = host.to_lowercase();
        let is_claude = lower_proc.contains("claude")
            || lower_host.contains("anthropic.com")
            || lower_host.contains("claude.ai")
            || lower_host.contains("claude.com")
            || lower_host.contains("claudeusercontent.com");

        if !is_claude {
            continue;
        }

        let rule = item
            .get("rule")
            .and_then(|v| v.as_str())
            .unwrap_or("MATCH")
            .to_string();
        let chains: Vec<String> = item
            .get("chains")
            .and_then(|c| c.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .rev()
                    .collect()
            })
            .unwrap_or_default();
        let chain_str = chains.join(" → ");

        let blocked_chain = chains
            .iter()
            .any(|c| is_blocked_node_name(c) || c.eq_ignore_ascii_case("DIRECT"));
        let missed_rule = !chains.iter().any(|c| c == "Claude-Fixed") && rule == "MATCH";
        let anomaly = blocked_chain || missed_rule;

        let upload = item.get("upload").and_then(|v| v.as_u64()).unwrap_or(0);
        let download = item.get("download").and_then(|v| v.as_u64()).unwrap_or(0);
        let bytes_label = format_bytes(upload + download);
        let time = item
            .get("start")
            .and_then(|v| v.as_str())
            .and_then(|s| s.get(11..19))
            .unwrap_or("--:--:--")
            .to_string();

        out.push(ClaudeConn {
            id,
            anomaly,
            process: if process.is_empty() {
                "Claude".into()
            } else {
                process
            },
            host,
            rule,
            chain: if chain_str.is_empty() {
                "DIRECT".into()
            } else {
                chain_str
            },
            action: if anomaly {
                "风险连接（建议立即掐断）".into()
            } else {
                "正常放行".into()
            },
            time,
            bytes_label,
        });
    }

    out.sort_by(|a, b| b.anomaly.cmp(&a.anomaly));
    out
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

/// 在已发现的 Mihomo 端点上实时拉取 Claude 相关连接（避免哨兵循环重复 discover_endpoint）
pub async fn get_live_claude_connections_on(ep: &MihomoEndpoint) -> Vec<ClaudeConn> {
    let Ok((200, body)) = mihomo_request(ep, "GET", "/connections", None).await else {
        return Vec::new();
    };
    parse_claude_connections(&body)
}

/// 实时拉取 Mihomo 中的 Claude 相关连接
pub async fn get_live_claude_connections() -> Vec<ClaudeConn> {
    let Some(ep) = discover_endpoint().await else {
        return Vec::new();
    };
    get_live_claude_connections_on(&ep).await
}

/// 毫秒级掐断指定连接 ID (`DELETE /connections/{id}`)
pub async fn close_mihomo_connection(id: &str) -> Result<(), String> {
    let ep = discover_endpoint()
        .await
        .ok_or_else(|| "未检测到在线的 Clash Verge Mihomo 实例".to_string())?;
    let path = format!("/connections/{}", urlencoding::encode(id));
    let (status, body) = mihomo_request(&ep, "DELETE", &path, None).await?;
    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(format!("掐断连接失败 (HTTP {status}): {body}"))
    }
}

/// 执行 4 层紧急防回传与熔断（Clash 掐流 + 防火墙封死出站 + 强杀进程跳过 onQuitCleanup + 清离线遥测）
pub async fn trigger_four_layer_killswitch(
    reason: &str,
    anti_upload_flush: bool,
) -> KillSwitchState {
    let started = std::time::Instant::now();
    // 第 1A 层：复用单个 Mihomo 端点毫秒级强掐所有 Claude 连接（避免 N 次重复 discover_endpoint）
    let mut closed = 0usize;
    if let Some(ep) = discover_endpoint().await {
        let conns = get_live_claude_connections_on(&ep).await;
        for c in &conns {
            let path = format!("/connections/{}", urlencoding::encode(&c.id));
            if let Ok((status, _)) = mihomo_request(&ep, "DELETE", &path, None).await {
                if (200..300).contains(&status) {
                    closed += 1;
                }
            }
        }
    }

    // 第 1B 层：追踪 Claude.exe 并写入 Windows Defender 防火墙出站阻断规则
    let target_exe = resolve_claude_exe_path().map(|p| p.to_string_lossy().to_string());
    let firewall_applied = apply_defender_block_rule(FIREWALL_RULE_NAME, target_exe.as_deref());
    if firewall_applied {
        crate::rollback::mark_firewall_touched(false, true);
    }

    // 第 2 层：循环强杀 Claude 进程树确认彻底归 0（跳过 onQuitCleanup 丢弃内存事件队列）+ 清空离线遥测缓存
    let (killed_processes, telemetry_cleared_bytes) = if anti_upload_flush {
        let mut total_killed = 0u32;
        let mut total_cleared = 0u64;
        for attempt in 0..8 {
            let rep = kill_claude_process_tree(attempt == 0);
            total_killed = total_killed.saturating_add(rep.before_count.saturating_sub(rep.after_count));
            total_cleared = total_cleared.saturating_add(rep.telemetry_cleared_bytes);
            if crate::process::list_claude_processes().is_empty() {
                break;
            }
            if attempt < 7 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }
        (total_killed, total_cleared)
    } else {
        (0, 0)
    };

    let final_reason = if firewall_applied {
        reason.to_string()
    } else {
        format!("{reason}（提示：当前未获取到防火墙写入权限 fw=false，请以管理员身份运行；已先执行掐流与强杀盯防）")
    };

    crate::logger::log_event(
        "WARN",
        "killswitch",
        "killswitch_triggered",
        Some(started.elapsed().as_millis() as u64),
        format!(
            "[{FD_ERR_KILL_SWITCH}] 触发 4 层熔断: {final_reason} | closed={closed} killed={killed_processes} fw={firewall_applied}"
        ),
        Some(serde_json::json!({
            "rule": FIREWALL_RULE_NAME,
            "firewallApplied": firewall_applied,
            "closedConnections": closed,
            "killedProcesses": killed_processes,
            "telemetryClearedBytes": telemetry_cleared_bytes
        })),
    );

    KillSwitchState {
        active: true,
        rule_name: FIREWALL_RULE_NAME.to_string(),
        target_exe,
        firewall_applied,
        claude_connections_closed: closed,
        killed_processes,
        telemetry_cleared_bytes,
        reason: final_reason,
        updated_at: chrono::Local::now().format("%H:%M:%S").to_string(),
    }
}

/// 增量 13：休眠唤醒 / 切网临时预阻断规则挂起与释放
pub fn set_wake_preblock_rule(enable: bool) -> bool {
    let target_exe = resolve_claude_exe_path().map(|p| p.to_string_lossy().to_string());
    if enable {
        apply_defender_block_rule(FIREWALL_WAKE_RULE_NAME, target_exe.as_deref())
    } else {
        remove_defender_rule_by_name(FIREWALL_WAKE_RULE_NAME)
    }
}

/// 按风险确认解除 Windows 防火墙阻断规则
pub fn release_killswitch(confirmed: bool, bg_procs: u32) -> Result<KillSwitchState, String> {
    if !confirmed {
        return Err("必须先二次确认风险才允许解除防火墙熔断。".into());
    }
    cleanup_all_guard_firewall_rules()?;
    let note = if bg_procs > 0 {
        format!("已强制解除熔断（注意：当前仍有 {bg_procs} 个 Claude 进程运行，请勿在禁区节点继续操作）")
    } else {
        format!("已解除防火墙熔断规则 {FIREWALL_RULE_PREFIX}*。")
    };

    crate::logger::log_event(
        "INFO",
        "killswitch",
        "killswitch_released",
        None,
        &note,
        Some(serde_json::json!({ "bgProcs": bg_procs })),
    );

    Ok(KillSwitchState {
        active: false,
        rule_name: FIREWALL_RULE_NAME.to_string(),
        target_exe: resolve_claude_exe_path().map(|p| p.to_string_lossy().to_string()),
        firewall_applied: false,
        claude_connections_closed: 0,
        killed_processes: 0,
        telemetry_cleared_bytes: 0,
        reason: note,
        updated_at: chrono::Local::now().format("%H:%M:%S").to_string(),
    })
}

/// 增量 15：清除本工具写入的全部 `FDClaudeGuard_KillSwitch_*` 防火墙规则（防自锁救援 + 退出自愈）
/// 删除后真实复查是否仍有规则残留，权限不足无法删除时如实返回错误绝不报假成功
pub fn cleanup_all_guard_firewall_rules() -> Result<String, String> {
    #[cfg(windows)]
    {
        for rule in [
            FIREWALL_RULE_NAME,
            FIREWALL_WAKE_RULE_NAME,
            FIREWALL_PROBE_RULE_NAME,
            LEGACY_FIREWALL_RULE_NAME,
        ] {
            let _ = remove_defender_rule_by_name(rule);
        }
        if has_active_guard_firewall_rules() {
            let msg = format!(
                "[{FD_ERR_KILL_SWITCH}] 检测到仍有 {FIREWALL_RULE_PREFIX}* 防火墙规则未能移除（当前权限不足），请以管理员身份运行本工具后重试。"
            );
            crate::logger::log_warn("killswitch", &msg);
            return Err(msg);
        }
    }
    crate::logger::log_event(
        "INFO",
        "killswitch",
        "firewall_cleanup_all",
        None,
        format!("已执行防自锁救援：清空全部 {FIREWALL_RULE_PREFIX}* 防火墙规则"),
        None,
    );
    Ok(format!(
        "已清空全部 {FIREWALL_RULE_PREFIX}* 防火墙规则，Claude 出站连接已彻底恢复放行。"
    ))
}

/// 快速检测当前系统是否存在任何活跃的 `FDClaudeGuard_KillSwitch_*` 阻断规则
/// 使用轻量 `netsh show rule`（约 30ms），彻底替代会阻塞主线程 3~4 秒的 PowerShell Get-NetFirewallRule
pub fn has_active_guard_firewall_rules() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        for rule in [
            FIREWALL_RULE_NAME,
            FIREWALL_WAKE_RULE_NAME,
            LEGACY_FIREWALL_RULE_NAME,
        ] {
            let exists = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args([
                    "advfirewall",
                    "firewall",
                    "show",
                    "rule",
                    &format!("name={rule}"),
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if exists {
                return true;
            }
        }
        false
    }
    #[cfg(not(windows))]
    {
        false
    }
}

static FW_HELPER_CACHE: std::sync::OnceLock<
    std::sync::Mutex<Option<(std::time::Instant, (bool, bool, String))>>,
> = std::sync::OnceLock::new();

/// 增量 16（opt_fw）：实测免 UAC 守护计划任务是否已安装且具备读写 FDClaudeGuard_KillSwitch_* 规则能力
/// 60 秒缓存复用结果，避免每轮体检重复向 Windows 防火墙增删探针规则（安装守护任务后自动失效缓存）
pub fn check_firewall_helper_ready() -> (bool, bool, String) {
    let lock = FW_HELPER_CACHE.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(guard) = lock.lock() {
        if let Some((ts, ref cached)) = *guard {
            if ts.elapsed() < std::time::Duration::from_secs(60) {
                return cached.clone();
            }
        }
    }
    let result = check_firewall_helper_ready_uncached();
    if let Ok(mut guard) = lock.lock() {
        *guard = Some((std::time::Instant::now(), result.clone()));
    }
    result
}

fn invalidate_firewall_helper_cache() {
    if let Some(lock) = FW_HELPER_CACHE.get() {
        if let Ok(mut guard) = lock.lock() {
            *guard = None;
        }
    }
}

fn check_firewall_helper_ready_uncached() -> (bool, bool, String) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let task_installed = Command::new("schtasks")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/Query", "/TN", FIREWALL_HELPER_TASK_NAME])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        // 轻量实测读写一条临时探针规则后立即删除（验证当前权限是否可直接写 Defender 规则）
        let probe_add = Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={FIREWALL_PROBE_RULE_NAME}"),
                "dir=out",
                "action=allow",
                "enable=no",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if probe_add {
            let _ = remove_defender_rule_by_name(FIREWALL_PROBE_RULE_NAME);
        }

        let detail = format!(
            "Elevated Helper Task: {}\nRule Probe ({FIREWALL_RULE_PREFIX}*): {}",
            if task_installed { "Active" } else { "Not Installed" },
            if probe_add { "Writable" } else { "Requires Admin / Helper" }
        );
        (task_installed, probe_add, detail)
    }
    #[cfg(not(windows))]
    {
        (false, false, "Non-Windows environment".into())
    }
}

/// 增量 16（opt_fw）：以管理员提权注册免 UAC 守护计划任务并实测读写一条探针规则
pub fn install_firewall_helper_task() -> Result<String, String> {
    #[cfg(windows)]
    {
        let exe_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "fd-claude-guard.exe".into());
        invalidate_firewall_helper_cache();

        // 管理员态直跑、非管理员态按需提权并校验退出码
        let inner_cmd = format!(
            "schtasks /Create /F /RL HIGHEST /SC ONEVENT /EC Application /MO '*[System[EventID=0]]' /TN '{FIREWALL_HELPER_TASK_NAME}' /TR '\"{exe_path}\" --autostart'; netsh advfirewall firewall add rule name={FIREWALL_PROBE_RULE_NAME} dir=out action=allow enable=no; netsh advfirewall firewall delete rule name={FIREWALL_PROBE_RULE_NAME}"
        );
        match crate::rollback::run_ps_elevated_checked(&inner_cmd, "安装免 UAC 防火墙守护计划任务") {
            Ok(_) => {
                crate::rollback::mark_firewall_touched(true, false);
                Ok(format!(
                    "已完成免 UAC 守护计划任务 ({FIREWALL_HELPER_TASK_NAME}) 安装与规则读写探针验证。"
                ))
            }
            Err(err) => Err(format!(
                "[{FD_ERR_KILL_SWITCH}] 安装免 UAC 守护计划任务未完成: {err}"
            )),
        }
    }
    #[cfg(not(windows))]
    {
        Err("仅 Windows 支持防火墙计划任务安装".into())
    }
}

#[cfg(windows)]
fn apply_defender_block_rule(rule_name: &str, exe_path: Option<&str>) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let Some(program) = exe_path else {
        return false;
    };

    let _ = remove_defender_rule_by_name(rule_name);

    let out = Command::new("netsh")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={rule_name}"),
            "dir=out",
            "action=block",
            &format!("program={program}"),
            "enable=yes",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            crate::logger::log_warn(
                "killswitch",
                format!("netsh 写入防火墙规则失败 (rule={rule_name}, program={program}): stdout={msg} stderr={err}"),
            );
            false
        }
        Err(e) => {
            crate::logger::log_warn(
                "killswitch",
                format!("调用 netsh 失败 (rule={rule_name}): {e}"),
            );
            false
        }
    }
}

#[cfg(not(windows))]
fn apply_defender_block_rule(_rule_name: &str, _exe_path: Option<&str>) -> bool {
    false
}

#[cfg(windows)]
fn remove_defender_rule_by_name(rule_name: &str) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new("netsh")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={rule_name}"),
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn remove_defender_rule_by_name(_rule_name: &str) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_rule_names_use_unified_prefix() {
        assert!(FIREWALL_RULE_NAME.starts_with(FIREWALL_RULE_PREFIX));
        assert!(FIREWALL_WAKE_RULE_NAME.starts_with(FIREWALL_RULE_PREFIX));
        assert!(FIREWALL_PROBE_RULE_NAME.starts_with(FIREWALL_RULE_PREFIX));
        assert_eq!(FIREWALL_RULE_PREFIX, "FDClaudeGuard_KillSwitch_");
    }

    #[tokio::test]
    #[ignore = "真机管理员权限实测 Defender 防火墙熔断规则真实写入与防自锁彻底清除"]
    async fn live_firewall_killswitch_write_and_cleanup_audit() {
        let ks = trigger_four_layer_killswitch("v0.2.5 真机防火墙写入与防自锁验收", false).await;
        println!(
            "=== LIVE KILLSWITCH: active={} fw={} target={:?} ===",
            ks.active, ks.firewall_applied, ks.target_exe
        );
        assert!(ks.active, "killswitch must be active");
        assert!(ks.firewall_applied, "Defender firewall rule must apply (fw=true)");
        assert!(has_active_guard_firewall_rules(), "netsh must report active guard rule");

        let rel = release_killswitch(true, 0).expect("release_killswitch must succeed");
        assert!(!rel.active, "killswitch must be released");
        assert!(
            !has_active_guard_firewall_rules(),
            "all FDClaudeGuard_KillSwitch_* rules must be cleaned up (zero self-lock)"
        );
    }

    #[test]
    fn identifies_anomalous_and_normal_claude_connections() {
        let sample = r#"{
            "connections": [
                {
                    "id": "conn-1",
                    "upload": 0,
                    "download": 0,
                    "start": "2026-11-23T20:54:02Z",
                    "rule": "MATCH",
                    "chains": ["HK-Edge-03", "PROXY"],
                    "metadata": { "process": "Claude.exe", "host": "api.anthropic.com", "destinationPort": "443" }
                },
                {
                    "id": "conn-2",
                    "upload": 2048,
                    "download": 1048576,
                    "start": "2026-11-23T20:52:18Z",
                    "rule": "DOMAIN-SUFFIX",
                    "chains": ["US-LA-Static-01", "Claude-Fixed"],
                    "metadata": { "process": "Claude.exe", "host": "claude.ai", "destinationPort": "443" }
                },
                {
                    "id": "conn-3",
                    "upload": 100,
                    "download": 100,
                    "start": "2026-11-23T20:50:00Z",
                    "rule": "DIRECT",
                    "chains": ["DIRECT"],
                    "metadata": { "process": "chrome.exe", "host": "example.com", "destinationPort": "443" }
                }
            ]
        }"#;

        let conns = parse_claude_connections(sample);
        assert_eq!(conns.len(), 2);
        assert!(conns[0].anomaly);
        assert_eq!(conns[0].id, "conn-1");
        assert!(!conns[1].anomaly);
        assert_eq!(conns[1].id, "conn-2");
    }

    #[test]
    fn release_requires_explicit_confirmation() {
        assert!(release_killswitch(false, 0).is_err());
    }
}
