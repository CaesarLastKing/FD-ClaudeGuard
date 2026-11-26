//! 系统基线快照、6 项精准可撤回引擎与无门槛「一键网络急救」模块。
//!
//! 设计原则：
//! 1. First-Write-Wins（首次改动前锁定原始基线）：同一项重复修复绝不覆盖最初记录的原始值。
//! 2. 精准去痕：撤回 Clash 策略组时不整文件覆盖 `profiles.yaml`，100% 保留用户后续新增订阅。
//! 3. 绝不静默吞权限错：管理员态直接调用原生命令，非管理员态按需提权并校验退出码。
//! 4. 网络急救无付费墙：无论是否激活、无论 Clash 是否在线，一键拯救“关 TUN 断网 / 无法导入订阅”。

use crate::killswitch::{cleanup_all_guard_firewall_rules, has_active_guard_firewall_rules, FIREWALL_HELPER_TASK_NAME};
use crate::mihomo::{
    clash_verge_config_dir, discover_endpoint, fetch_configs, reload_config_via_payload,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BASELINE_VERSION: u32 = 1;

static BASELINE_IO_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static BASELINE_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn baseline_io_lock() -> &'static Mutex<()> {
    BASELINE_IO_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterIpv6State {
    pub interface_index: u32,
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ipv6Baseline {
    pub captured_at_ms: i64,
    pub adapters: Vec<AdapterIpv6State>,
    pub disabled_components: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationBaseline {
    pub captured_at_ms: i64,
    pub hklm_value: Option<String>,
    pub hkcu_value: Option<String>,
    pub non_packaged_value: Option<String>,
    pub lfsvc_start: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebRtcRegBaseline {
    pub hive: String,
    pub subkey: String,
    pub label: String,
    pub original_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebRtcBaseline {
    pub captured_at_ms: i64,
    pub entries: Vec<WebRtcRegBaseline>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SysEnvBaseline {
    pub captured_at_ms: i64,
    #[serde(default)]
    pub hkcu_env: BTreeMap<String, Option<String>>,
    #[serde(default)]
    pub hklm_env: BTreeMap<String, Option<String>>,
    pub wininet_proxy_enable: Option<u32>,
    pub wininet_proxy_server: Option<String>,
    pub claude_settings_base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClashRulesBaseline {
    pub captured_at_ms: i64,
    pub script_existed: bool,
    pub original_script: Option<String>,
    pub profiles_had_script_uid: bool,
    pub original_mode: Option<String>,
    pub original_verge_tun: Option<bool>,
    pub original_verge_sysproxy: Option<bool>,
    #[serde(default)]
    pub original_config_ipv6: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallBaseline {
    pub captured_at_ms: i64,
    pub helper_task_installed: bool,
    pub killswitch_applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeSettingsEnvBaseline {
    pub captured_at_ms: i64,
    pub settings_path: String,
    pub existed_before: bool,
    /// First-Write-Wins：记录每个被本工具修改过的 `env` 键的原始值（原不存在记为 None）
    #[serde(default)]
    pub original_env: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemBaseline {
    pub version: u32,
    pub updated_at_ms: i64,
    pub clash_rules: Option<ClashRulesBaseline>,
    pub sys_ipv6: Option<Ipv6Baseline>,
    pub sys_location: Option<LocationBaseline>,
    pub sys_webrtc: Option<WebRtcBaseline>,
    pub sys_env: Option<SysEnvBaseline>,
    pub firewall: Option<FirewallBaseline>,
    #[serde(default)]
    pub original_claude_settings_env: Option<ClaudeSettingsEnvBaseline>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackItemStatus {
    pub id: String,
    pub title: String,
    pub category: String,
    pub touched_by_guard: bool,
    pub can_rollback: bool,
    pub original_summary: String,
    pub current_summary: String,
    pub risk_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackOverview {
    pub baseline_exists: bool,
    pub baseline_path: String,
    pub is_elevated: bool,
    pub loopback_dns_adapters: Vec<String>,
    pub active_firewall_rules: bool,
    pub touched_count: usize,
    pub items: Vec<RollbackItemStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackActionReport {
    pub item_id: String,
    pub ok: bool,
    pub message: String,
    pub overview: RollbackOverview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollbackBatchReport {
    pub all_ok: bool,
    pub reverted_ids: Vec<String>,
    pub skipped_ids: Vec<String>,
    pub failed: Vec<String>,
    pub summary: String,
    pub overview: RollbackOverview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RescueStepResult {
    pub step: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkRescueReport {
    pub ok: bool,
    pub is_elevated: bool,
    pub direct_connectivity_ok: bool,
    pub steps: Vec<RescueStepResult>,
    pub summary: String,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 返回基线快照文件的默认持久化路径：`~/.fd-claude-guard/system-baseline.json`
pub fn baseline_file_path() -> PathBuf {
    let base = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".fd-claude-guard");
    base.join("system-baseline.json")
}

/// 从指定路径加载基线快照（文件不存在返回默认基线；若存在但 JSON 损坏则自动备份为 `.corrupt-{ts}` 保留取证）
pub fn load_baseline_from(path: &Path) -> SystemBaseline {
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<SystemBaseline>(raw.trim_start_matches('\u{feff}')) {
            Ok(bl) => bl,
            Err(err) => {
                let backup = path.with_extension(format!("json.corrupt-{}", now_ms()));
                let _ = fs::copy(path, &backup);
                crate::logger::log_warn(
                    "rollback",
                    format!(
                        "系统基线 JSON 损坏，已保留损坏副本至 {} ({err})",
                        backup.display()
                    ),
                );
                SystemBaseline {
                    version: BASELINE_VERSION,
                    ..Default::default()
                }
            }
        },
        Err(_) => SystemBaseline {
            version: BASELINE_VERSION,
            ..Default::default()
        },
    }
}

/// 原子写入基线快照（进程内串行 + 唯一临时文件名 + 覆盖重命名，彻底消除并发写盘 `.tmp` 竞态）
pub fn save_baseline_to(path: &Path, baseline: &SystemBaseline) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建基线目录失败: {e}"))?;
    }
    let mut to_save = baseline.clone();
    to_save.version = BASELINE_VERSION;
    to_save.updated_at_ms = now_ms();
    let body = serde_json::to_string_pretty(&to_save)
        .map_err(|e| format!("序列化系统基线失败: {e}"))?;
    let seq = BASELINE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("json.tmp.{}.{}", std::process::id(), seq));
    fs::write(&tmp, body).map_err(|e| format!("写入临时基线文件失败: {e}"))?;
    fs::rename(&tmp, path)
        .or_else(|_| {
            let _ = fs::remove_file(path);
            fs::rename(&tmp, path)
        })
        .map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("原子落盘系统基线失败: {e}")
        })
}

pub fn load_baseline() -> SystemBaseline {
    let _guard = baseline_io_lock().lock().unwrap_or_else(|e| e.into_inner());
    load_baseline_from(&baseline_file_path())
}

fn update_baseline<F>(updater: F)
where
    F: FnOnce(&mut SystemBaseline) -> bool,
{
    let _guard = baseline_io_lock().lock().unwrap_or_else(|e| e.into_inner());
    let path = baseline_file_path();
    let mut bl = load_baseline_from(&path);
    if updater(&mut bl) {
        let _ = save_baseline_to(&path, &bl);
    }
}

/// 从 Windows `ProxyServer` 字符串中解析全部指向本机回环地址的端口号。
/// 兼容：`127.0.0.1:7897`、`localhost:7890`、`http://127.0.0.1:7897`、
/// `http=127.0.0.1:7897;https=127.0.0.1:7897;socks=127.0.0.1:7898`、`[::1]:7897`。
pub fn extract_local_proxy_ports(server: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for seg in server.split(';') {
        let mut s = seg.trim();
        if s.is_empty() {
            continue;
        }
        // 剥离 `http=` / `https=` / `socks=` 协议段前缀
        if let Some((_, rhs)) = s.split_once('=') {
            s = rhs.trim();
        }
        // 剥离 `http://` / `https://` / `socks5://`
        if let Some((_, rhs)) = s.split_once("://") {
            s = rhs.trim();
        }
        // 剥离路径后缀与账密前缀
        if let Some((before_slash, _)) = s.split_once('/') {
            s = before_slash;
        }
        if let Some((_, after_at)) = s.rsplit_once('@') {
            s = after_at;
        }
        let Some((host_raw, port_raw)) = s.rsplit_once(':') else {
            continue;
        };
        let host = host_raw.trim().trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
        let is_local = matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1" | "0.0.0.0");
        if !is_local {
            continue;
        }
        if let Ok(port) = port_raw.trim().parse::<u16>() {
            if port > 0 && !ports.contains(&port) {
                ports.push(port);
            }
        }
    }
    ports
}

/// 向 Windows 广播环境变量变更（`WM_SETTINGCHANGE`）并通知 WinINET 即时重读系统代理配置
pub fn notify_windows_env_and_inet_refresh() {
    #[cfg(windows)]
    {
        use std::ptr::null_mut;
        use windows_sys::Win32::Networking::WinInet::{
            InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
        };
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
        };

        let env_wide: Vec<u16> = "Environment\0".encode_utf16().collect();
        unsafe {
            let mut result: usize = 0;
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                env_wide.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                1500,
                &mut result,
            );
            let _ = InternetSetOptionW(null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, null_mut(), 0);
            let _ = InternetSetOptionW(null_mut(), INTERNET_OPTION_REFRESH, null_mut(), 0);
        }
    }
}

/// 检测当前进程是否拥有 Windows 管理员权限
pub fn is_current_process_elevated() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let out = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ])
            .output();
        out.ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }
    #[cfg(not(windows))]
    {
        true
    }
}

/// 将 PowerShell 脚本编码为 UTF-16LE Base64，供 `-EncodedCommand` 无损传递（彻底免疫单双引号、换行与中文路径转义）
#[cfg(windows)]
fn encode_ps_utf16le_base64(script: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for u in script.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// 执行需要管理员权限的 PowerShell 命令：
/// - 管理员态直接经 `-EncodedCommand` 执行（零 UAC 弹窗、免疫单双引号与中文转义）；
/// - 非管理员态交互提权并严格校验取消 UAC 与真实退出码，绝不静默假成功。
#[cfg(windows)]
pub fn run_ps_elevated_checked(script: &str, action_label: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;

    let wrapped = format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ErrorActionPreference = 'Stop'; {script}"
    );
    let encoded = encode_ps_utf16le_base64(&wrapped);
    if is_current_process_elevated() {
        let out = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .output()
            .map_err(|e| format!("执行 {action_label} 失败: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if out.status.success() {
            return Ok(stdout);
        }
        return Err(format!(
            "{action_label}执行失败: {}",
            if stderr.is_empty() { stdout } else { stderr }
        ));
    }

    // 非管理员态：通过 -EncodedCommand 传递内层脚本，并在外层捕获 UAC 取消强制返回非 0 退出码
    let runner = format!(
        "$ErrorActionPreference = 'Stop'; try {{ $p = Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','{encoded}'); if (-not $p) {{ exit 1 }}; exit $p.ExitCode }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
    );
    let out = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-Command", &runner])
        .output()
        .map_err(|e| format!("请求管理员权限执行 {action_label} 失败: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(format!(
            "当前未获得管理员权限或用户取消了授权，无法完成{action_label}（请以管理员身份运行本工具后重试{}）。",
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        ))
    }
}

#[cfg(not(windows))]
pub fn run_ps_elevated_checked(_script: &str, _action_label: &str) -> Result<String, String> {
    Ok(String::new())
}

/// 扫描所有存在残留 `127.0.0.1` IPv4 DNS 的物理网卡（排除虚拟网卡，UTF-8 输出免疫中文乱码）
pub fn detect_loopback_dns_physical_adapters() -> Vec<(u32, String)> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let out = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -contains '127.0.0.1' } | ForEach-Object { \"$($_.InterfaceIndex)|$($_.InterfaceAlias)\" }",
            ])
            .output();
        let Ok(o) = out else {
            return Vec::new();
        };
        let mut res = Vec::new();
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            let trimmed = line.trim();
            let Some((idx_raw, alias_raw)) = trimmed.split_once('|') else {
                continue;
            };
            let Ok(if_idx) = idx_raw.trim().parse::<u32>() else {
                continue;
            };
            let alias = alias_raw.trim();
            if alias.is_empty() || crate::preflight::is_clash_tun_virtual_adapter(alias, "") {
                continue;
            }
            let lower = alias.to_ascii_lowercase();
            if lower.contains("loopback") || lower.contains("wintun") || lower.contains("tap") {
                continue;
            }
            res.push((if_idx, alias.to_string()));
        }
        res
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

// ==================== First-Write-Wins 基线捕获钩子 ====================

/// 首次修改物理网卡 IPv6 前捕获原始状态（含每张物理网卡 `ms_tcpip6` 开关 + `DisabledComponents` 原值）
pub fn capture_ipv6_baseline_if_needed() {
    #[cfg(windows)]
    {
        update_baseline(|bl| {
            if bl.sys_ipv6.is_some() {
                return false;
            }
            use std::os::windows::process::CommandExt;
            use winreg::enums::HKEY_LOCAL_MACHINE;
            use winreg::RegKey;

            let out = Command::new("powershell")
                .creation_flags(CREATE_NO_WINDOW)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object { $a = $_; $b = ($a | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Select-Object -First 1); if ($b) { \"$($a.ifIndex)|$($a.Name)|$($b.Enabled)\" } }",
                ])
                .output();
            let mut adapters = Vec::new();
            if let Ok(o) = out {
                for line in String::from_utf8_lossy(&o.stdout).lines() {
                    let parts: Vec<&str> = line.trim().split('|').collect();
                    if parts.len() == 3 {
                        if let Ok(idx) = parts[0].trim().parse::<u32>() {
                            let name = parts[1].trim().to_string();
                            let enabled = parts[2].trim().eq_ignore_ascii_case("true");
                            if !crate::preflight::is_clash_tun_virtual_adapter(&name, "") {
                                adapters.push(AdapterIpv6State {
                                    interface_index: idx,
                                    name,
                                    enabled,
                                });
                            }
                        }
                    }
                }
            }
            let disabled_components: Option<u32> = RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey(r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters")
                .ok()
                .and_then(|k| k.get_value::<u32, _>("DisabledComponents").ok());

            bl.sys_ipv6 = Some(Ipv6Baseline {
                captured_at_ms: now_ms(),
                adapters,
                disabled_components,
            });
            true
        });
    }
}

/// 首次关闭 Windows 系统定位前捕获 3 处注册表原值与 `lfsvc` 原始启动类型
pub fn capture_location_baseline_if_needed() {
    #[cfg(windows)]
    {
        update_baseline(|bl| {
            if bl.sys_location.is_some() {
                return false;
            }
            use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
            use winreg::RegKey;

            const CONSENT: &str =
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location";
            const NON_PACKAGED: &str =
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged";

            let hklm_value = RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey(CONSENT)
                .ok()
                .and_then(|k| k.get_value::<String, _>("Value").ok());
            let hkcu_value = RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey(CONSENT)
                .ok()
                .and_then(|k| k.get_value::<String, _>("Value").ok());
            let non_packaged_value = RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey(NON_PACKAGED)
                .ok()
                .and_then(|k| k.get_value::<String, _>("Value").ok());
            let lfsvc_start = RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey(r"SYSTEM\CurrentControlSet\Services\lfsvc")
                .ok()
                .and_then(|k| k.get_value::<u32, _>("Start").ok());

            bl.sys_location = Some(LocationBaseline {
                captured_at_ms: now_ms(),
                hklm_value,
                hkcu_value,
                non_packaged_value,
                lfsvc_start,
            });
            true
        });
    }
}

/// 首次写入浏览器 WebRTC 组策略前捕获各浏览器原值
pub fn capture_webrtc_baseline_if_needed(browsers: &[(&str, &str)]) {
    #[cfg(windows)]
    {
        update_baseline(|bl| {
            if bl.sys_webrtc.is_some() {
                return false;
            }
            use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
            use winreg::RegKey;

            let mut entries = Vec::new();
            for (label, subkey) in browsers {
                let hkcu_val = RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey(subkey)
                    .ok()
                    .and_then(|k| k.get_value::<String, _>("WebRtcIPHandling").ok());
                let hklm_val = RegKey::predef(HKEY_LOCAL_MACHINE)
                    .open_subkey(subkey)
                    .ok()
                    .and_then(|k| k.get_value::<String, _>("WebRtcIPHandling").ok());
                entries.push(WebRtcRegBaseline {
                    hive: "HKCU".into(),
                    subkey: (*subkey).to_string(),
                    label: (*label).to_string(),
                    original_value: hkcu_val,
                });
                entries.push(WebRtcRegBaseline {
                    hive: "HKLM".into(),
                    subkey: (*subkey).to_string(),
                    label: (*label).to_string(),
                    original_value: hklm_val,
                });
            }
            bl.sys_webrtc = Some(WebRtcBaseline {
                captured_at_ms: now_ms(),
                entries,
            });
            true
        });
    }
}

/// 首次修改系统代理与环境变量前捕获原始值（First-Write-Wins，合并记录被触碰的键）
pub fn capture_sys_env_baseline_if_needed(
    hkcu_pairs: &[(String, String)],
    hklm_pairs: &[(String, String)],
    wininet_enable: Option<u32>,
    wininet_server: Option<String>,
    settings_base_url: Option<String>,
) {
    if hkcu_pairs.is_empty()
        && hklm_pairs.is_empty()
        && wininet_enable.is_none()
        && wininet_server.is_none()
        && settings_base_url.is_none()
    {
        return;
    }
    update_baseline(|bl| {
        let entry = bl.sys_env.get_or_insert_with(|| SysEnvBaseline {
            captured_at_ms: now_ms(),
            hkcu_env: BTreeMap::new(),
            hklm_env: BTreeMap::new(),
            wininet_proxy_enable: None,
            wininet_proxy_server: None,
            claude_settings_base_url: None,
        });
        let mut changed = false;
        for (k, v) in hkcu_pairs {
            if !entry.hkcu_env.contains_key(k) {
                entry.hkcu_env.insert(k.clone(), Some(v.clone()));
                changed = true;
            }
        }
        for (k, v) in hklm_pairs {
            if !entry.hklm_env.contains_key(k) {
                entry.hklm_env.insert(k.clone(), Some(v.clone()));
                changed = true;
            }
        }
        if entry.wininet_proxy_enable.is_none() && wininet_enable.is_some() {
            entry.wininet_proxy_enable = wininet_enable;
            changed = true;
        }
        if entry.wininet_proxy_server.is_none() && wininet_server.is_some() {
            entry.wininet_proxy_server = wininet_server;
            changed = true;
        }
        if entry.claude_settings_base_url.is_none() && settings_base_url.is_some() {
            entry.claude_settings_base_url = settings_base_url;
            changed = true;
        }
        changed
    });
}

/// 读取顶层 YAML 布尔字段（严格仅匹配无前导空格的顶层键，自动剥离 UTF-8 BOM，绝不误读缩进的 `dns.ipv6` 等子键）
pub fn read_top_level_yaml_bool(raw: &str, key: &str) -> Option<bool> {
    let clean = raw.trim_start_matches('\u{feff}');
    let prefix = format!("{key}:");
    for line in clean.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            let val = rest.split('#').next().unwrap_or("").trim();
            if val.eq_ignore_ascii_case("true") {
                return Some(true);
            }
            if val.eq_ignore_ascii_case("false") {
                return Some(false);
            }
        }
    }
    None
}

/// 纯函数：精准更新 YAML 顶层布尔字段（如 `ipv6: false`），自动剥离 UTF-8 BOM 且严格不触碰缩进子键（如 `dns:\n  ipv6: true`）
pub fn patch_top_level_yaml_bool(raw: &str, key: &str, value: bool) -> String {
    let clean = raw.trim_start_matches('\u{feff}');
    let prefix = format!("{key}:");
    let mut replaced = false;
    let mut out: Vec<String> = clean
        .lines()
        .map(|line| {
            if !replaced && line.starts_with(&prefix) {
                replaced = true;
                format!("{key}: {value}")
            } else {
                line.to_string()
            }
        })
        .collect();
    if !replaced {
        out.push(format!("{key}: {value}"));
    }
    out.join("\n") + "\n"
}

/// 首次写入 Clash Verge 策略组/覆写脚本/`verge.yaml`/`config.yaml` 前捕获原始状态
pub fn capture_clash_rules_baseline_if_needed(dir: &Path) {
    update_baseline(|bl| {
        let current_config_ipv6 = fs::read_to_string(dir.join("config.yaml"))
            .ok()
            .and_then(|raw| read_top_level_yaml_bool(&raw, "ipv6"));
        if let Some(ref mut existing) = bl.clash_rules {
            // 向下兼容旧版基线：若此前未记录过 config.yaml 顶层 ipv6 原值，则仅在首次补采一次（First-Write-Wins）
            if existing.original_config_ipv6.is_none() && current_config_ipv6.is_some() {
                existing.original_config_ipv6 = current_config_ipv6;
                return true;
            }
            return false;
        }
        let script_path = dir.join("profiles").join("Script.js");
        let script_existed = script_path.exists();
        let original_script = if script_existed {
            fs::read_to_string(&script_path).ok()
        } else {
            None
        };
        let profiles_had_script_uid = fs::read_to_string(dir.join("profiles.yaml"))
            .ok()
            .and_then(|raw| serde_yaml::from_str::<serde_yaml::Value>(&raw).ok())
            .and_then(|doc| {
                doc.get("items").and_then(|v| v.as_sequence()).map(|seq| {
                    seq.iter().any(|it| {
                        it.get("uid").and_then(|v| v.as_str()) == Some("Script")
                            && it.get("file").and_then(|v| v.as_str()) == Some("Script.js")
                    })
                })
            })
            .unwrap_or(false);

        let original_mode = fs::read_to_string(dir.join("clash-verge.yaml"))
            .ok()
            .and_then(|raw| {
                raw.lines()
                    .find(|l| l.trim_start().starts_with("mode:"))
                    .map(|l| l.split_once(':').map(|(_, v)| v.trim().trim_matches('"').to_string()).unwrap_or_default())
            })
            .filter(|s| !s.is_empty());

        let (original_verge_tun, original_verge_sysproxy) = fs::read_to_string(dir.join("verge.yaml"))
            .ok()
            .map(|raw| {
                let mut tun = None;
                let mut sysp = None;
                for line in raw.lines() {
                    let t = line.trim();
                    if let Some(rest) = t.strip_prefix("enable_tun_mode:") {
                        tun = rest.trim().parse::<bool>().ok();
                    } else if let Some(rest) = t.strip_prefix("enable_system_proxy:") {
                        sysp = rest.trim().parse::<bool>().ok();
                    }
                }
                (tun, sysp)
            })
            .unwrap_or((None, None));

        bl.clash_rules = Some(ClashRulesBaseline {
            captured_at_ms: now_ms(),
            script_existed,
            original_script,
            profiles_had_script_uid,
            original_mode,
            original_verge_tun,
            original_verge_sysproxy,
            original_config_ipv6: current_config_ipv6,
        });
        true
    });
}

/// 首次修改 `~/.claude/settings.json` 中的 `env` 键（4 项降噪 / 非官方端点）前捕获 First-Write-Wins 基线
pub fn capture_claude_settings_env_baseline_if_needed(
    settings_path: &Path,
    existed_before: bool,
    original_env_keys: &std::collections::HashMap<String, Option<String>>,
) {
    if original_env_keys.is_empty() {
        return;
    }
    update_baseline(|bl| {
        let entry = bl
            .original_claude_settings_env
            .get_or_insert_with(|| ClaudeSettingsEnvBaseline {
                captured_at_ms: now_ms(),
                settings_path: settings_path.to_string_lossy().to_string(),
                existed_before,
                original_env: BTreeMap::new(),
            });
        let mut changed = false;
        for (k, v) in original_env_keys {
            if !entry.original_env.contains_key(k) {
                entry.original_env.insert(k.clone(), v.clone());
                changed = true;
            }
        }
        changed
    });
}

/// 标记本工具写入过防火墙规则或计划任务
pub fn mark_firewall_touched(helper_task_installed: bool, killswitch_applied: bool) {
    update_baseline(|bl| {
        let entry = bl.firewall.get_or_insert_with(|| FirewallBaseline {
            captured_at_ms: now_ms(),
            helper_task_installed: false,
            killswitch_applied: false,
        });
        let mut changed = false;
        if helper_task_installed && !entry.helper_task_installed {
            entry.helper_task_installed = true;
            changed = true;
        }
        if killswitch_applied && !entry.killswitch_applied {
            entry.killswitch_applied = true;
            changed = true;
        }
        changed
    });
}

// ==================== 精准去痕纯函数（可 100% 单元测试） ====================

/// 精准清理 `profiles.yaml` 中本工具留下的痕迹，100% 保留用户后续新导入的所有订阅：
/// - 若 `remove_script_uid == true`，仅删除 `uid: Script` + `file: Script.js` 项；
/// - 从全部订阅项的 `selected` 列表中删除 `name: Claude-Fixed`。
pub fn strip_claude_from_profiles_yaml(
    raw: &str,
    remove_script_uid: bool,
) -> Result<(String, bool), String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(|e| format!("解析 profiles.yaml 失败: {e}"))?;
    let mut changed = false;

    if let Some(items) = doc.get_mut("items").and_then(|v| v.as_sequence_mut()) {
        if remove_script_uid {
            let before = items.len();
            items.retain(|it| {
                !(it.get("uid").and_then(|v| v.as_str()) == Some("Script")
                    && it.get("file").and_then(|v| v.as_str()) == Some("Script.js"))
            });
            if items.len() != before {
                changed = true;
            }
        }
        for item in items.iter_mut() {
            if let Some(selected) = item.get_mut("selected").and_then(|v| v.as_sequence_mut()) {
                let before = selected.len();
                selected.retain(|s| s.get("name").and_then(|v| v.as_str()) != Some("Claude-Fixed"));
                if selected.len() != before {
                    changed = true;
                }
            }
        }
    }

    if !changed {
        return Ok((raw.to_string(), false));
    }
    let out = serde_yaml::to_string(&doc).map_err(|e| format!("序列化 profiles.yaml 失败: {e}"))?;
    Ok((out, true))
}

/// 精准从 `clash-verge.yaml` 剥离 `Claude-Fixed` 策略组与指向 `Claude-Fixed` 的规则，
/// 完整保留当前订阅的所有真实节点与用户原有策略组。
pub fn strip_claude_from_clash_yaml(raw: &str) -> Result<(String, bool), String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(|e| format!("解析 clash-verge.yaml 失败: {e}"))?;
    let mut changed = false;

    if let Some(groups) = doc.get_mut("proxy-groups").and_then(|v| v.as_sequence_mut()) {
        let before = groups.len();
        groups.retain(|g| g.get("name").and_then(|v| v.as_str()) != Some("Claude-Fixed"));
        if groups.len() != before {
            changed = true;
        }
        for g in groups.iter_mut() {
            if let Some(proxies) = g.get_mut("proxies").and_then(|v| v.as_sequence_mut()) {
                let b = proxies.len();
                proxies.retain(|p| p.as_str() != Some("Claude-Fixed"));
                if proxies.len() != b {
                    changed = true;
                }
            }
        }
    }

    if let Some(rules) = doc.get_mut("rules").and_then(|v| v.as_sequence_mut()) {
        let before = rules.len();
        rules.retain(|r| {
            let Some(line) = r.as_str() else {
                return true;
            };
            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            !parts.contains(&"Claude-Fixed")
        });
        if rules.len() != before {
            changed = true;
        }
    }

    if !changed {
        return Ok((raw.to_string(), false));
    }
    let out =
        serde_yaml::to_string(&doc).map_err(|e| format!("序列化 clash-verge.yaml 失败: {e}"))?;
    Ok((out, true))
}

// ==================== 状态总览查询 ====================

/// 扫描系统基线与当前真实状态，供前端「撤回中心」与「一键网络急救」展示
pub async fn inspect_rollback_status() -> RollbackOverview {
    let path = baseline_file_path();
    let baseline_exists = path.exists();
    let bl = load_baseline_from(&path);

    let (is_elevated, loopback_adapters, active_fw, clash_has_claude_group, helper_exists) =
        tokio::task::spawn_blocking(|| {
            let elev = is_current_process_elevated();
            let dns_bad: Vec<String> = detect_loopback_dns_physical_adapters()
                .into_iter()
                .map(|(idx, name)| format!("{name} (#{idx})"))
                .collect();
            let fw = has_active_guard_firewall_rules();
            let (helper_ready, _, _) = crate::killswitch::check_firewall_helper_ready();
            let has_script_or_group = clash_verge_config_dir()
                .map(|d| {
                    let has_group = fs::read_to_string(d.join("clash-verge.yaml"))
                        .map(|s| s.contains("Claude-Fixed"))
                        .unwrap_or(false);
                    let has_script = fs::read_to_string(d.join("profiles").join("Script.js"))
                        .map(|s| s.contains("Claude-Fixed"))
                        .unwrap_or(false);
                    has_group || has_script
                })
                .unwrap_or(false);
            (elev, dns_bad, fw, has_script_or_group, helper_ready)
        })
        .await
        .unwrap_or((false, Vec::new(), false, false, false));

    let clash_touched = bl.clash_rules.is_some() || clash_has_claude_group;
    let ipv6_touched = bl.sys_ipv6.is_some();
    let loc_touched = bl.sys_location.is_some();
    let webrtc_touched = bl.sys_webrtc.is_some();
    let env_touched = bl.sys_env.is_some();
    let claude_settings_touched = bl.original_claude_settings_env.is_some();
    let fw_touched = bl.firewall.is_some() || active_fw || helper_exists;

    let items = vec![
        RollbackItemStatus {
            id: "clash_rules".into(),
            title: "Clash 策略组与覆写脚本（Claude-Fixed）".into(),
            category: "Clash 配置".into(),
            touched_by_guard: clash_touched,
            can_rollback: clash_touched,
            original_summary: match &bl.clash_rules {
                Some(c) if c.script_existed => "原存在自定义 Script.js（已备份）".into(),
                Some(_) => "原无 Claude-Fixed 策略组与全局 Script.js".into(),
                None => "未记录过基线（按安全精准剥离处理）".into(),
            },
            current_summary: if clash_has_claude_group {
                "当前 Clash 配置中存在 Claude-Fixed 规则/脚本".into()
            } else {
                "当前配置中未检测到 Claude-Fixed 残留".into()
            },
            risk_note: "精准移除 Claude-Fixed 策略组与规则并热重载，100% 保留你后续新导入的所有订阅。".into(),
        },
        RollbackItemStatus {
            id: "sys_ipv6".into(),
            title: "物理网卡 IPv6 绑定与系统优先策略".into(),
            category: "Windows 网络".into(),
            touched_by_guard: ipv6_touched,
            can_rollback: ipv6_touched,
            original_summary: match &bl.sys_ipv6 {
                Some(v) => format!(
                    "已记录 {} 张物理网卡原态；DisabledComponents 原值={}",
                    v.adapters.len(),
                    v.disabled_components
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "未设置".into())
                ),
                None => "本工具未修改过 IPv6".into(),
            },
            current_summary: if ipv6_touched {
                "已由本工具禁用物理网卡 IPv6".into()
            } else {
                "保持系统原状".into()
            },
            risk_note: "若校园网、内网或 NAS 依赖 IPv6，可随时一键恢复修改前的精确原值。".into(),
        },
        RollbackItemStatus {
            id: "sys_location".into(),
            title: "Windows 系统定位权限与 lfsvc 服务".into(),
            category: "Windows 隐私".into(),
            touched_by_guard: loc_touched,
            can_rollback: loc_touched,
            original_summary: match &bl.sys_location {
                Some(l) => format!(
                    "HKLM={} / HKCU={} / lfsvc Start={}",
                    l.hklm_value.as_deref().unwrap_or("未设置"),
                    l.hkcu_value.as_deref().unwrap_or("未设置"),
                    l.lfsvc_start
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "3(手动)".into())
                ),
                None => "本工具未修改过系统定位".into(),
            },
            current_summary: if loc_touched {
                "已由本工具关闭定位并停用 lfsvc".into()
            } else {
                "保持系统原状".into()
            },
            risk_note: "撤回后将恢复天气、地图、自动时区等依赖 Windows 定位的系统功能。".into(),
        },
        RollbackItemStatus {
            id: "sys_webrtc".into(),
            title: "Chrome / Edge WebRTC 浏览器组策略".into(),
            category: "浏览器策略".into(),
            touched_by_guard: webrtc_touched,
            can_rollback: webrtc_touched,
            original_summary: match &bl.sys_webrtc {
                Some(w) => format!("已记录 {} 条浏览器策略原值", w.entries.len()),
                None => "本工具未写入过浏览器组策略".into(),
            },
            current_summary: if webrtc_touched {
                "已写入 WebRtcIPHandling 策略".into()
            } else {
                "保持系统原状".into()
            },
            risk_note: "撤回后可消除浏览器「由你的组织管理」提示，并恢复网页视频会议直连 UDP。".into(),
        },
        RollbackItemStatus {
            id: "sys_env".into(),
            title: "系统代理（WinINET）与环境变量".into(),
            category: "Windows 网络".into(),
            touched_by_guard: env_touched,
            can_rollback: env_touched,
            original_summary: match &bl.sys_env {
                Some(e) => format!(
                    "已记录 HKCU({}) / HKLM({}) / WinINET({}) 原始配置",
                    e.hkcu_env.len(),
                    e.hklm_env.len(),
                    e.wininet_proxy_server.as_deref().unwrap_or("无变更")
                ),
                None => "本工具未修改过系统代理或环境变量".into(),
            },
            current_summary: if env_touched {
                "已按当前 Clash 端口校准代理与环境变量".into()
            } else {
                "保持系统原状".into()
            },
            risk_note: "撤回后恢复修改前的环境变量、WinINET 代理与 Claude settings.json 原值。".into(),
        },
        RollbackItemStatus {
            id: "claude_settings".into(),
            title: "Claude CLI 隐私降噪与官方端点配置（settings.json）".into(),
            category: "Claude 配置".into(),
            touched_by_guard: claude_settings_touched,
            can_rollback: claude_settings_touched,
            original_summary: match &bl.original_claude_settings_env {
                Some(s) => format!(
                    "已记录 {} 个 settings.json env 键修改前原值（首次基线）",
                    s.original_env.len()
                ),
                None => "本工具未修改过 ~/.claude/settings.json".into(),
            },
            current_summary: if claude_settings_touched {
                "已由本工具补齐降噪开关或还原官方端点".into()
            } else {
                "保持配置原状".into()
            },
            risk_note: "仅精准还原被本工具改动的 env 键，100% 保留你的自定义 hooks 与 permissions。".into(),
        },
        RollbackItemStatus {
            id: "firewall".into(),
            title: "Defender 防火墙熔断规则与守护计划任务".into(),
            category: "Windows 安全".into(),
            touched_by_guard: fw_touched,
            can_rollback: fw_touched,
            original_summary: "使用前无 FDClaudeGuard 防火墙规则与计划任务".into(),
            current_summary: format!(
                "防火墙规则：{}｜计划任务：{}",
                if active_fw { "存在拦截规则" } else { "已放行(0)" },
                if helper_exists { "已安装" } else { "未安装" }
            ),
            risk_note: "卸载前或排障时一键彻底清除所有本工具防火墙拦截规则与守护任务，防止永久封死 Claude。".into(),
        },
    ];

    let touched_count = items.iter().filter(|i| i.touched_by_guard).count();

    RollbackOverview {
        baseline_exists,
        baseline_path: path.to_string_lossy().to_string(),
        is_elevated,
        loopback_dns_adapters: loopback_adapters,
        active_firewall_rules: active_fw,
        touched_count,
        items,
    }
}

// ==================== 6 项精准单项撤回实现 ====================

async fn rollback_clash_rules_inner(bl: &SystemBaseline) -> Result<String, String> {
    let dir = clash_verge_config_dir()
        .ok_or_else(|| "未检测到 Clash Verge Rev 配置目录，无法撤回 Clash 规则。".to_string())?;

    let mut actions: Vec<String> = Vec::new();
    let cfg = bl.clash_rules.as_ref();

    // 1. 恢复或删除 profiles/Script.js
    let script_path = dir.join("profiles").join("Script.js");
    if let Some(c) = cfg {
        if c.script_existed {
            if let Some(ref orig) = c.original_script {
                fs::write(&script_path, orig).map_err(|e| format!("还原原 Script.js 失败: {e}"))?;
                actions.push("已恢复用户原有 Script.js".into());
            }
        } else if script_path.exists() {
            let _ = fs::remove_file(&script_path);
            actions.push("已移除本工具写入的 Script.js".into());
        }
    } else if script_path.exists() {
        // 即使无基线，仅当脚本确由本工具生成才移除
        if fs::read_to_string(&script_path)
            .map(|s| s.contains("Claude-Fixed"))
            .unwrap_or(false)
        {
            let _ = fs::remove_file(&script_path);
            actions.push("已移除含 Claude-Fixed 的全局 Script.js".into());
        }
    }

    // 2. 精准清理 profiles.yaml（绝不整文件覆盖，100% 保留用户后续新增订阅）
    let profiles_path = dir.join("profiles.yaml");
    if let Ok(raw) = fs::read_to_string(&profiles_path) {
        let remove_uid = cfg.map(|c| !c.profiles_had_script_uid).unwrap_or(true);
        let (updated, changed) = strip_claude_from_profiles_yaml(&raw, remove_uid)?;
        if changed {
            fs::write(&profiles_path, updated)
                .map_err(|e| format!("回写 profiles.yaml 失败: {e}"))?;
            actions.push("已清理 profiles.yaml 中的 Claude-Fixed 绑定（完整保留现有订阅）".into());
        }
    }

    // 3. 精准剥离 clash-verge.yaml 中的 Claude-Fixed 策略组与规则并热重载 Mihomo
    let runtime_yaml = dir.join("clash-verge.yaml");
    let mut reloaded = false;
    if let Ok(raw) = fs::read_to_string(&runtime_yaml) {
        let (mut updated, mut changed) = strip_claude_from_clash_yaml(&raw)?;
        if let Some(orig_v6) = cfg.and_then(|c| c.original_config_ipv6) {
            if read_top_level_yaml_bool(&updated, "ipv6") != Some(orig_v6) {
                updated = patch_top_level_yaml_bool(&updated, "ipv6", orig_v6);
                changed = true;
            }
        }
        if changed {
            fs::write(&runtime_yaml, &updated)
                .map_err(|e| format!("回写 clash-verge.yaml 失败: {e}"))?;
            if let Some(ep) = discover_endpoint().await {
                if reload_config_via_payload(&ep, &updated).await.is_ok() {
                    reloaded = true;
                    actions.push("已热重载 Mihomo，Claude-Fixed 策略组已即时移除".into());
                }
            }
            if !reloaded {
                actions.push("已清理 clash-verge.yaml 中的 Claude-Fixed（Clash 重载订阅后生效）".into());
            }
        }
    }

    // 4. 若基线记录了 config.yaml 原始顶层 ipv6 值，精准还原并确保内核一致
    if let Some(orig_v6) = cfg.and_then(|c| c.original_config_ipv6) {
        let cfg_yaml = dir.join("config.yaml");
        if let Ok(raw) = fs::read_to_string(&cfg_yaml) {
            if read_top_level_yaml_bool(&raw, "ipv6") != Some(orig_v6) {
                let restored = patch_top_level_yaml_bool(&raw, "ipv6", orig_v6);
                fs::write(&cfg_yaml, restored)
                    .map_err(|e| format!("还原 config.yaml ipv6 失败: {e}"))?;
                actions.push(format!("已还原 Clash config.yaml 原始 ipv6: {orig_v6}"));
            }
        }
        if !reloaded {
            if let Some(ep) = discover_endpoint().await {
                let _ = crate::mihomo::patch_ipv6_enabled(&ep, orig_v6).await;
            }
        }
    }

    // 5. 若基线记录了 verge.yaml 的原始 TUN / 系统代理开关或 clash-verge.yaml 原始 mode，精准还原
    if let Some(orig_tun) = cfg.and_then(|c| c.original_verge_tun) {
        let verge_yaml = dir.join("verge.yaml");
        if let Ok(raw) = fs::read_to_string(&verge_yaml) {
            let mut next = raw.clone();
            if read_top_level_yaml_bool(&next, "enable_tun_mode") != Some(orig_tun) {
                next = patch_top_level_yaml_bool(&next, "enable_tun_mode", orig_tun);
            }
            if let Some(orig_sp) = cfg.and_then(|c| c.original_verge_sysproxy) {
                if read_top_level_yaml_bool(&next, "enable_system_proxy") != Some(orig_sp) {
                    next = patch_top_level_yaml_bool(&next, "enable_system_proxy", orig_sp);
                }
            }
            if next != raw {
                let _ = fs::write(&verge_yaml, &next);
                actions.push(format!("已还原 verge.yaml 原始 TUN={orig_tun}"));
            }
        }
    }
    if let Some(orig_mode) = cfg.and_then(|c| c.original_mode.as_deref()) {
        if let Some(ep) = discover_endpoint().await {
            let body = serde_json::json!({ "mode": orig_mode });
            let _ = crate::mihomo::patch_configs_json(&ep, &body).await;
            actions.push(format!("已还原 Clash 代理模式为 {orig_mode}"));
        }
    }

    // 清理基线中的 clash_rules 标记
    update_baseline(|b| {
        if b.clash_rules.is_some() {
            b.clash_rules = None;
            true
        } else {
            false
        }
    });

    if actions.is_empty() {
        Ok("Clash 配置中未发现需要撤回的本工具痕迹。".into())
    } else {
        Ok(actions.join("；") + "。")
    }
}

fn rollback_ipv6_inner(bl: &SystemBaseline) -> Result<String, String> {
    let Some(ref v6) = bl.sys_ipv6 else {
        return Ok("本工具未修改过 IPv6，无需撤回。".into());
    };

    #[cfg(windows)]
    {
        let mut cmds: Vec<String> = Vec::new();
        for a in &v6.adapters {
            if a.enabled {
                cmds.push(format!(
                    "Get-NetAdapter -InterfaceIndex {} -ErrorAction SilentlyContinue | Enable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue",
                    a.interface_index
                ));
            }
        }
        match v6.disabled_components {
            Some(orig) => {
                cmds.push(format!(
                    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters' -Name 'DisabledComponents' -Value {orig} -Type DWord -Force"
                ));
            }
            None => {
                cmds.push(
                    "Remove-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters' -Name 'DisabledComponents' -ErrorAction SilentlyContinue".into()
                );
            }
        }
        if !cmds.is_empty() {
            run_ps_elevated_checked(&cmds.join("; "), "恢复物理网卡 IPv6 原状")?;
        }
    }

    update_baseline(|b| {
        if b.sys_ipv6.is_some() {
            b.sys_ipv6 = None;
            true
        } else {
            false
        }
    });

    Ok(format!(
        "已按基线恢复 {} 张物理网卡的 IPv6 绑定，并将 DisabledComponents 精确还原为 {}。",
        v6.adapters.len(),
        v6.disabled_components
            .map(|n| n.to_string())
            .unwrap_or_else(|| "未设置(已清除)".into())
    ))
}

fn rollback_location_inner(bl: &SystemBaseline) -> Result<String, String> {
    let Some(ref loc) = bl.sys_location else {
        return Ok("本工具未修改过系统定位，无需撤回。".into());
    };

    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
        use winreg::RegKey;

        const CONSENT: &str =
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location";
        const NON_PACKAGED: &str =
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged";

        // 1. 恢复 HKCU 两处
        for (subkey, orig) in [(CONSENT, &loc.hkcu_value), (NON_PACKAGED, &loc.non_packaged_value)] {
            if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(subkey, KEY_SET_VALUE) {
                match orig {
                    Some(v) => {
                        let _ = key.set_value("Value", v);
                    }
                    None => {
                        let _ = key.delete_value("Value");
                    }
                }
            }
        }

        // 2. 恢复 HKLM 定位与 lfsvc 启动类型（默认 3=Manual）
        let startup_str = match loc.lfsvc_start.unwrap_or(3) {
            2 => "Automatic",
            4 => "Disabled",
            _ => "Manual",
        };
        let hklm_cmd = match &loc.hklm_value {
            Some(v) => format!(
                "$p='HKLM:\\{CONSENT}'; if (!(Test-Path $p)) {{ New-Item -Path $p -Force | Out-Null }}; Set-ItemProperty -Path $p -Name Value -Value '{}' -Force",
                v.replace('\'', "''")
            ),
            None => format!(
                "Remove-ItemProperty -Path 'HKLM:\\{CONSENT}' -Name Value -ErrorAction SilentlyContinue"
            ),
        };
        let script = format!(
            "{hklm_cmd}; Set-Service -Name lfsvc -StartupType {startup_str} -ErrorAction SilentlyContinue"
        );
        run_ps_elevated_checked(&script, "恢复 Windows 系统定位与 lfsvc 服务")?;
    }

    update_baseline(|b| {
        if b.sys_location.is_some() {
            b.sys_location = None;
            true
        } else {
            false
        }
    });

    Ok("已按基线还原 Windows 设备/用户/桌面定位权限与 lfsvc 服务原启动类型。".into())
}

fn rollback_webrtc_inner(bl: &SystemBaseline) -> Result<String, String> {
    let Some(ref w) = bl.sys_webrtc else {
        return Ok("本工具未写入过浏览器 WebRTC 策略，无需撤回。".into());
    };

    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
        use winreg::RegKey;

        let mut hklm_cmds = Vec::new();
        for e in &w.entries {
            if e.hive == "HKCU" {
                if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
                    .open_subkey_with_flags(&e.subkey, KEY_SET_VALUE)
                {
                    match &e.original_value {
                        Some(v) => {
                            let _ = key.set_value("WebRtcIPHandling", v);
                        }
                        None => {
                            let _ = key.delete_value("WebRtcIPHandling");
                        }
                    }
                }
            } else if e.hive == "HKLM" {
                let reg_path = format!(r"HKLM:\{}", e.subkey);
                match &e.original_value {
                    Some(v) => hklm_cmds.push(format!(
                        "if (Test-Path '{reg_path}') {{ Set-ItemProperty -Path '{reg_path}' -Name 'WebRtcIPHandling' -Value '{}' -Type String }}",
                        v.replace('\'', "''")
                    )),
                    None => hklm_cmds.push(format!(
                        "Remove-ItemProperty -Path '{reg_path}' -Name 'WebRtcIPHandling' -ErrorAction SilentlyContinue"
                    )),
                }
            }
        }
        if !hklm_cmds.is_empty() {
            run_ps_elevated_checked(&hklm_cmds.join("; "), "清理浏览器 WebRTC 组策略")?;
        }
    }

    update_baseline(|b| {
        if b.sys_webrtc.is_some() {
            b.sys_webrtc = None;
            true
        } else {
            false
        }
    });

    Ok("已清理/还原 Chrome 与 Edge 的 WebRtcIPHandling 策略（重启浏览器后“由你的组织管理”提示将消失）。".into())
}

fn rollback_sys_env_inner(bl: &SystemBaseline) -> Result<String, String> {
    let Some(ref env_bl) = bl.sys_env else {
        return Ok("本工具未修改过系统代理或环境变量，无需撤回。".into());
    };

    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
        use winreg::RegKey;

        if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
        {
            for (k, v) in &env_bl.hkcu_env {
                if let Some(val) = v {
                    let _ = key.set_value(k, val);
                }
            }
        }
        if !env_bl.hklm_env.is_empty() {
            let mut hklm_cmds = Vec::new();
            for (k, v) in &env_bl.hklm_env {
                if let Some(val) = v {
                    hklm_cmds.push(format!(
                        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name '{}' -Value '{}'",
                        k.replace('\'', "''"),
                        val.replace('\'', "''")
                    ));
                }
            }
            if !hklm_cmds.is_empty() {
                run_ps_elevated_checked(&hklm_cmds.join("; "), "恢复系统级环境变量")?;
            }
        }
        if let Ok(inet) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            KEY_READ | KEY_WRITE,
        ) {
            if let Some(en) = env_bl.wininet_proxy_enable {
                let _ = inet.set_value("ProxyEnable", &en);
            }
            if let Some(ref srv) = env_bl.wininet_proxy_server {
                let _ = inet.set_value("ProxyServer", srv);
            }
        }
        notify_windows_env_and_inet_refresh();
    }

    if let Some(ref base_url) = env_bl.claude_settings_base_url {
        if let Some(settings_path) = dirs::home_dir().map(|h| h.join(".claude").join("settings.json")) {
            if let Ok(raw) = fs::read_to_string(&settings_path) {
                if let Ok(mut val) = serde_json::from_str::<Value>(&raw) {
                    if let Some(obj) = val.as_object_mut() {
                        let env_map = obj
                            .entry("env")
                            .or_insert_with(|| Value::Object(serde_json::Map::new()));
                        if let Some(m) = env_map.as_object_mut() {
                            m.insert("ANTHROPIC_BASE_URL".into(), Value::String(base_url.clone()));
                        }
                    }
                    if let Ok(pretty) = serde_json::to_string_pretty(&val) {
                        let _ = fs::write(&settings_path, pretty);
                    }
                }
            }
        }
    }

    update_baseline(|b| {
        if b.sys_env.is_some() {
            b.sys_env = None;
            true
        } else {
            false
        }
    });

    Ok("已按基线还原修改前的系统代理、环境变量与 Claude settings.json 原值。".into())
}

fn rollback_claude_settings_inner(bl: &SystemBaseline) -> Result<String, String> {
    let Some(ref cs) = bl.original_claude_settings_env else {
        return Ok("本工具未修改过 ~/.claude/settings.json，无需撤回。".into());
    };
    let settings_path = PathBuf::from(&cs.settings_path);
    if settings_path.exists() {
        let raw = fs::read_to_string(&settings_path)
            .map_err(|e| format!("读取 settings.json 失败: {e}"))?;
        let restored = crate::account_audit::rollback_settings_json_env_keys(&raw, &cs.original_env)?;
        if !cs.existed_before {
            let is_empty_env_only = serde_json::from_str::<Value>(&restored)
                .ok()
                .and_then(|v| v.as_object().cloned())
                .map(|obj| {
                    obj.len() <= 1
                        && obj
                            .get("env")
                            .and_then(|e| e.as_object())
                            .map(|m| m.is_empty())
                            .unwrap_or(obj.is_empty())
                })
                .unwrap_or(false);
            if is_empty_env_only {
                let _ = fs::remove_file(&settings_path);
            } else {
                fs::write(&settings_path, restored)
                    .map_err(|e| format!("写回 settings.json 失败: {e}"))?;
            }
        } else {
            fs::write(&settings_path, restored)
                .map_err(|e| format!("写回 settings.json 失败: {e}"))?;
        }
    }

    update_baseline(|b| {
        if b.original_claude_settings_env.is_some() {
            b.original_claude_settings_env = None;
            true
        } else {
            false
        }
    });

    Ok(format!(
        "已精准撤回 ~/.claude/settings.json 的 {} 个 env 键并完整保留自定义 hooks/permissions。",
        cs.original_env.len()
    ))
}

fn rollback_firewall_inner() -> Result<String, String> {
    let fw_msg = cleanup_all_guard_firewall_rules()?;

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let query = Command::new("schtasks")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/Query", "/TN", FIREWALL_HELPER_TASK_NAME])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if query {
            let del_direct = Command::new("schtasks")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["/Delete", "/F", "/TN", FIREWALL_HELPER_TASK_NAME])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !del_direct {
                run_ps_elevated_checked(
                    &format!("schtasks /Delete /F /TN '{FIREWALL_HELPER_TASK_NAME}'"),
                    "卸载免 UAC 防火墙计划任务",
                )?;
            }
        }
        // 立刻失效 60s 计划任务就绪缓存，避免撤回后仍假显示「已安装」
        crate::killswitch::invalidate_firewall_helper_cache();
    }

    update_baseline(|b| {
        if b.firewall.is_some() {
            b.firewall = None;
            true
        } else {
            false
        }
    });

    Ok(format!("{fw_msg} 并已清理守护计划任务（{FIREWALL_HELPER_TASK_NAME}）。"))
}

/// 单项精准撤回入口
pub async fn rollback_single_item(item_id: &str) -> RollbackActionReport {
    let bl = load_baseline();
    let res = match item_id {
        "clash_rules" => rollback_clash_rules_inner(&bl).await,
        "sys_ipv6" => tokio::task::spawn_blocking(move || rollback_ipv6_inner(&bl))
            .await
            .unwrap_or_else(|e| Err(format!("IPv6 撤回任务异常: {e}"))),
        "sys_location" => tokio::task::spawn_blocking(move || rollback_location_inner(&bl))
            .await
            .unwrap_or_else(|e| Err(format!("系统定位撤回任务异常: {e}"))),
        "sys_webrtc" => tokio::task::spawn_blocking(move || rollback_webrtc_inner(&bl))
            .await
            .unwrap_or_else(|e| Err(format!("WebRTC 策略撤回任务异常: {e}"))),
        "sys_env" => tokio::task::spawn_blocking(move || rollback_sys_env_inner(&bl))
            .await
            .unwrap_or_else(|e| Err(format!("代理与环境变量撤回任务异常: {e}"))),
        "claude_settings" => {
            tokio::task::spawn_blocking(move || rollback_claude_settings_inner(&bl))
                .await
                .unwrap_or_else(|e| Err(format!("Claude settings.json 撤回任务异常: {e}")))
        }
        "firewall" => tokio::task::spawn_blocking(rollback_firewall_inner)
            .await
            .unwrap_or_else(|e| Err(format!("防火墙撤回任务异常: {e}"))),
        other => Err(format!("不支持的撤回项: {other}")),
    };

    let (ok, message) = match res {
        Ok(m) => (true, m),
        Err(e) => (false, e),
    };

    crate::logger::log_event(
        if ok { "INFO" } else { "WARN" },
        "rollback",
        "rollback_single",
        None,
        format!("单项撤回 item={item_id} ok={ok} msg={message}"),
        Some(serde_json::json!({ "itemId": item_id, "ok": ok })),
    );

    let overview = inspect_rollback_status().await;
    RollbackActionReport {
        item_id: item_id.to_string(),
        ok,
        message,
        overview,
    }
}

/// 按安全逆序一键撤回本工具全部系统与 Clash 改动（每项独立容错，不因某一项失败中断后续恢复）
pub async fn rollback_all_changes() -> RollbackBatchReport {
    let before = inspect_rollback_status().await;
    let order = [
        "firewall",
        "clash_rules",
        "claude_settings",
        "sys_env",
        "sys_ipv6",
        "sys_location",
        "sys_webrtc",
    ];
    let mut reverted_ids = Vec::new();
    let mut skipped_ids = Vec::new();
    let mut failed = Vec::new();

    for id in order {
        let touched = before
            .items
            .iter()
            .find(|i| i.id == id)
            .map(|i| i.touched_by_guard)
            .unwrap_or(false);
        if !touched {
            skipped_ids.push(id.to_string());
            continue;
        }
        let r = rollback_single_item(id).await;
        if r.ok {
            reverted_ids.push(id.to_string());
        } else {
            failed.push(format!("{id}: {}", r.message));
        }
    }

    let overview = inspect_rollback_status().await;
    let all_ok = failed.is_empty();
    let summary = if reverted_ids.is_empty() && failed.is_empty() {
        "当前未检测到需要撤回的系统或 Clash 改动，你的电脑已处于干净状态。".into()
    } else if all_ok {
        format!("已成功撤回全部 {} 项系统/Clash 改动，电脑已还原至使用前状态。", reverted_ids.len())
    } else {
        format!(
            "已撤回 {} 项，另有 {} 项需要管理员权限或手动确认：{}",
            reverted_ids.len(),
            failed.len(),
            failed.join("；")
        )
    };

    RollbackBatchReport {
        all_ok,
        reverted_ids,
        skipped_ids,
        failed,
        summary,
        overview,
    }
}

// ==================== 无门槛「一键网络急救」（不设付费墙） ====================

/// 4 步网络急救：专治“关 TUN / 卸载 Clash 后国内外全部断网、订阅无法导入”
pub async fn run_network_emergency_rescue() -> NetworkRescueReport {
    let is_elevated = tokio::task::spawn_blocking(is_current_process_elevated)
        .await
        .unwrap_or(false);
    let mut steps: Vec<RescueStepResult> = Vec::new();

    // 步骤 1：检测并恢复物理网卡残留的 127.0.0.1 死 DNS 为 DHCP 自动获取
    let step1 = tokio::task::spawn_blocking(|| {
        let bad = detect_loopback_dns_physical_adapters();
        if bad.is_empty() {
            return RescueStepResult {
                step: "恢复物理网卡 DNS".into(),
                ok: true,
                detail: "未检测到物理网卡残留 127.0.0.1 DNS，无需重置。".into(),
            };
        }
        let names: Vec<String> = bad.iter().map(|(i, n)| format!("{n}(#{i})")).collect();
        let cmds: Vec<String> = bad
            .iter()
            .map(|(i, _)| format!("Set-DnsClientServerAddress -InterfaceIndex {i} -ResetServerAddresses -ErrorAction Stop"))
            .collect();
        match run_ps_elevated_checked(&cmds.join("; "), "重置物理网卡 DNS 为 DHCP") {
            Ok(_) => {
                // 回读确认是否真的消除了 127.0.0.1
                let still_bad = detect_loopback_dns_physical_adapters();
                if still_bad.is_empty() {
                    RescueStepResult {
                        step: "恢复物理网卡 DNS".into(),
                        ok: true,
                        detail: format!("已将 {} 的死 DNS (127.0.0.1) 恢复为自动获取 (DHCP) 并复测通过。", names.join("、")),
                    }
                } else {
                    RescueStepResult {
                        step: "恢复物理网卡 DNS".into(),
                        ok: false,
                        detail: format!("已尝试重置 {}，但复测仍残留 127.0.0.1，请右键以管理员身份运行本工具重试。", names.join("、")),
                    }
                }
            }
            Err(e) => RescueStepResult {
                step: "恢复物理网卡 DNS".into(),
                ok: false,
                detail: format!("检测到 {} 残留 127.0.0.1 死 DNS，但重置失败：{e}", names.join("、")),
            },
        }
    })
    .await
    .unwrap_or_else(|e| RescueStepResult {
        step: "恢复物理网卡 DNS".into(),
        ok: false,
        detail: format!("DNS 修复任务异常: {e}"),
    });
    steps.push(step1);

    // 步骤 2：检测并关闭指向不可达本地端口的失效 WinINET 系统代理
    let step2 = tokio::task::spawn_blocking(|| {
        #[cfg(windows)]
        {
            use std::net::{SocketAddr, TcpStream};
            use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
            use winreg::RegKey;

            let Ok(inet) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                KEY_READ | KEY_WRITE,
            ) else {
                return RescueStepResult {
                    step: "清理失效系统代理".into(),
                    ok: true,
                    detail: "系统代理注册表无需调整。".into(),
                };
            };
            let enabled: u32 = inet.get_value("ProxyEnable").unwrap_or(0);
            let server: String = inet.get_value("ProxyServer").unwrap_or_default();
            if enabled == 1 {
                // 兼容解析 127.0.0.1:7897 / localhost:7897 / http://127.0.0.1:7897 / http=127.0.0.1:7897;https=127.0.0.1:7897
                let local_ports = extract_local_proxy_ports(&server);
                let dead_local = !local_ports.is_empty()
                    && local_ports.iter().all(|&port| {
                        TcpStream::connect_timeout(
                            &SocketAddr::from(([127, 0, 0, 1], port)),
                            Duration::from_millis(250),
                        )
                        .is_err()
                    });
                if dead_local {
                    let _ = inet.set_value("ProxyEnable", &0u32);
                    notify_windows_env_and_inet_refresh();
                    return RescueStepResult {
                        step: "清理失效系统代理".into(),
                        ok: true,
                        detail: format!("已关闭指向死端口 ({server}) 的 Windows 系统代理开关并刷新 WinINET。"),
                    };
                }
            }
            RescueStepResult {
                step: "清理失效系统代理".into(),
                ok: true,
                detail: "未检测到悬空失效的 Windows 系统代理。".into(),
            }
        }
        #[cfg(not(windows))]
        {
            RescueStepResult {
                step: "清理失效系统代理".into(),
                ok: true,
                detail: "非 Windows 环境无需处理。".into(),
            }
        }
    })
    .await
    .unwrap_or_else(|e| RescueStepResult {
        step: "清理失效系统代理".into(),
        ok: false,
        detail: format!("系统代理清理任务异常: {e}"),
    });
    steps.push(step2);

    // 步骤 3：清空全部本工具防火墙出站阻断规则
    let step3 = tokio::task::spawn_blocking(|| {
        if !has_active_guard_firewall_rules() {
            return RescueStepResult {
                step: "清除防火墙阻断规则".into(),
                ok: true,
                detail: "当前无本工具残留的防火墙阻断规则。".into(),
            };
        }
        match cleanup_all_guard_firewall_rules() {
            Ok(msg) => RescueStepResult {
                step: "清除防火墙阻断规则".into(),
                ok: true,
                detail: msg,
            },
            Err(e) => RescueStepResult {
                step: "清除防火墙阻断规则".into(),
                ok: false,
                detail: e,
            },
        }
    })
    .await
    .unwrap_or_else(|e| RescueStepResult {
        step: "清除防火墙阻断规则".into(),
        ok: false,
        detail: format!("防火墙清理异常: {e}"),
    });
    steps.push(step3);

    // 步骤 4：刷新 DNS 缓存 + 实测国内直连连通性（绕过代理）
    let _ = tokio::task::spawn_blocking(|| {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let _ = Command::new("ipconfig")
                .creation_flags(CREATE_NO_WINDOW)
                .arg("/flushdns")
                .status();
        }
    })
    .await;

    let direct_connectivity_ok = probe_domestic_direct_connectivity().await;
    steps.push(RescueStepResult {
        step: "刷新 DNS 并实测国内直连".into(),
        ok: direct_connectivity_ok,
        detail: if direct_connectivity_ok {
            "已刷新系统 DNS 缓存，实测国内直连可达（无需开 TUN 也可正常上网与导入订阅）。".into()
        } else {
            "已刷新系统 DNS 缓存，但直连探测暂未通；请确认物理网线/Wi-Fi 已连接，或以管理员身份运行后重试。".into()
        },
    });

    let all_steps_ok = steps.iter().all(|s| s.ok);
    let summary = if all_steps_ok {
        "网络急救完成！物理网卡 DNS、系统代理与防火墙均已恢复正常，国内直连实测畅通。".into()
    } else if direct_connectivity_ok {
        "国内直连已通，但有部分系统项需要管理员权限完成彻底清理，请查看下方逐项回执。".into()
    } else {
        "网络急救部分步骤未通过，请确认以管理员身份运行本工具后重试，并检查下方明细。".into()
    };

    crate::logger::log_event(
        if all_steps_ok { "INFO" } else { "WARN" },
        "rollback",
        "network_rescue",
        None,
        format!("网络急救 ok={all_steps_ok} direct={direct_connectivity_ok} elevated={is_elevated}"),
        Some(serde_json::json!({
            "ok": all_steps_ok,
            "directOk": direct_connectivity_ok,
            "isElevated": is_elevated,
        })),
    );

    NetworkRescueReport {
        ok: all_steps_ok,
        is_elevated,
        direct_connectivity_ok,
        steps,
        summary,
    }
}

/// 绕过所有系统代理，实测国内直连连通性（校验用户关闭代理/TUN 后确实能上网）
async fn probe_domestic_direct_connectivity() -> bool {
    let client = match reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(4))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    for url in [
        "https://www.baidu.com",
        "http://connect.rom.miui.com/generate_204",
    ] {
        if let Ok(resp) = client.head(url).send().await {
            if resp.status().as_u16() < 500 {
                return true;
            }
        }
    }
    false
}

/// 暴露给测试和排障：查询当前是否仍开启 Clash TUN
#[allow(dead_code)]
pub async fn query_clash_tun_enabled() -> Option<bool> {
    let ep = discover_endpoint().await?;
    fetch_configs(&ep).await.ok().map(|c| c.tun_enable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_first_write_wins_does_not_overwrite_original_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("system-baseline.json");

        let mut bl = load_baseline_from(&p);
        bl.sys_ipv6 = Some(Ipv6Baseline {
            captured_at_ms: 100,
            adapters: vec![AdapterIpv6State {
                interface_index: 6,
                name: "以太网".into(),
                enabled: true,
            }],
            disabled_components: Some(8),
        });
        save_baseline_to(&p, &bl).expect("save first");

        // 模拟二次捕获：必须保留原值 8 与 enabled=true，不被第二次覆盖
        let mut bl2 = load_baseline_from(&p);
        if bl2.sys_ipv6.is_none() {
            bl2.sys_ipv6 = Some(Ipv6Baseline {
                captured_at_ms: 200,
                adapters: vec![],
                disabled_components: Some(32),
            });
            save_baseline_to(&p, &bl2).expect("save second");
        }

        let reloaded = load_baseline_from(&p);
        let v6 = reloaded.sys_ipv6.expect("ipv6 baseline must exist");
        assert_eq!(v6.disabled_components, Some(8));
        assert_eq!(v6.adapters.len(), 1);
        assert_eq!(v6.adapters[0].name, "以太网");
        assert!(v6.adapters[0].enabled);
    }

    #[test]
    fn strip_profiles_yaml_removes_claude_trace_but_preserves_later_user_subscriptions() {
        let raw = r#"current: sub-new-2026
items:
  - uid: Script
    type: script
    name: 全局扩展脚本
    file: Script.js
  - uid: sub-old
    type: remote
    name: 旧机场
    selected:
      - name: Claude-Fixed
        now: 🇺🇸美国1
      - name: Proxy
        now: 🇭🇰香港1
  - uid: sub-new-2026
    type: remote
    name: 用户后来新导入的机场
    selected:
      - name: Claude-Fixed
        now: 🇺🇸美国2
      - name: DemoAirport
        now: 🇯🇵日本1
"#;
        let (cleaned, changed) =
            strip_claude_from_profiles_yaml(raw, true).expect("strip profiles.yaml");
        assert!(changed);
        assert!(!cleaned.contains("Script.js"), "应移除我们注册的 Script.js 项");
        assert!(!cleaned.contains("Claude-Fixed"), "应移除全部 Claude-Fixed 选中记录");
        assert!(cleaned.contains("sub-new-2026"), "必须 100% 保留用户后来新导入的订阅");
        assert!(cleaned.contains("用户后来新导入的机场"));
        assert!(cleaned.contains("DemoAirport"));
    }

    #[test]
    fn strip_profiles_yaml_keeps_user_custom_script_uid_when_originally_existed() {
        let raw = r#"current: sub-1
items:
  - uid: Script
    type: script
    file: Script.js
  - uid: sub-1
    selected:
      - name: Claude-Fixed
        now: US1
      - name: Main
        now: JP1
"#;
        let (cleaned, changed) =
            strip_claude_from_profiles_yaml(raw, false).expect("strip keeping Script");
        assert!(changed);
        assert!(cleaned.contains("Script.js"), "用户原本就有 Script.js 时应保留其注册项");
        assert!(!cleaned.contains("Claude-Fixed"));
        assert!(cleaned.contains("Main"));
    }

    #[test]
    fn strip_clash_yaml_removes_claude_group_and_rules_without_touching_proxies() {
        let raw = r#"mixed-port: 7897
mode: rule
proxies:
  - name: 🇺🇸美国1
    type: vless
  - name: 🇯🇵日本1
    type: anytls
proxy-groups:
  - name: Claude-Fixed
    type: select
    proxies:
      - 🇺🇸美国1
  - name: DemoAirport
    type: select
    proxies:
      - Claude-Fixed
      - 🇺🇸美国1
      - 🇯🇵日本1
rules:
  - DOMAIN-SUFFIX,claude.ai,Claude-Fixed
  - DOMAIN-SUFFIX,anthropic.com,Claude-Fixed
  - IP-CIDR,160.79.104.0/23,Claude-Fixed,no-resolve
  - DOMAIN-SUFFIX,google.com,DemoAirport
  - MATCH,DemoAirport
"#;
        let (cleaned, changed) = strip_claude_from_clash_yaml(raw).expect("strip clash yaml");
        assert!(changed);
        assert!(!cleaned.contains("Claude-Fixed"), "必须彻底剥离 Claude-Fixed 组与规则");
        assert!(cleaned.contains("🇺🇸美国1"), "必须完整保留节点列表");
        assert!(cleaned.contains("🇯🇵日本1"));
        assert!(cleaned.contains("DOMAIN-SUFFIX,google.com,DemoAirport"), "必须保留原有业务规则");
        assert!(cleaned.contains("MATCH,DemoAirport"));
    }

    #[tokio::test]
    #[ignore = "Gate 2/3 真机双向闭环实测：Clash 精准撤回(保留现有订阅且 Mihomo 实时移除) -> 正向重注入(服务模式热重载变绿 + 基线落盘) + 中文网卡 DNS 检出"]
    async fn live_v028_clash_rollback_and_reinject_bidirectional_audit() {
        let ep = discover_endpoint().await.expect("本机 Clash Verge 应在线");
        let dir = clash_verge_config_dir().expect("应命中真实 Clash Verge 用户目录");
        println!("[Gate2] config_dir={}", dir.display());

        // 0. 记录当前订阅数量，用于断言撤回后绝不丢失用户订阅
        let before_profiles = fs::read_to_string(dir.join("profiles.yaml")).expect("read profiles.yaml");
        let before_doc: serde_yaml::Value = serde_yaml::from_str(&before_profiles).expect("parse profiles.yaml");
        let before_remote_subs: Vec<String> = before_doc
            .get("items")
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter(|it| it.get("type").and_then(|v| v.as_str()) == Some("remote"))
                    .filter_map(|it| it.get("uid").and_then(|v| v.as_str()).map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        println!("[Gate2] remote_subs_before={before_remote_subs:?}");

        // 1. 执行精准撤回 clash_rules
        let rb = rollback_single_item("clash_rules").await;
        println!("[Gate2] rollback clash_rules ok={} msg={}", rb.ok, rb.message);
        assert!(rb.ok, "撤回 clash_rules 必须成功: {}", rb.message);

        // 验证 Mihomo 实时 /proxies 中 Claude-Fixed 已消失
        let proxies_after_rb = crate::mihomo::fetch_proxies_raw(&ep).await.expect("fetch proxies after rollback");
        assert!(
            crate::mihomo::extract_proxy_group(&proxies_after_rb, "Claude-Fixed").is_none(),
            "撤回并热重载后 Mihomo 中不应残留 Claude-Fixed 策略组"
        );

        // 验证原有全部远程订阅 100% 完整保留
        let after_profiles = fs::read_to_string(dir.join("profiles.yaml")).expect("read profiles.yaml after rollback");
        for uid in &before_remote_subs {
            assert!(
                after_profiles.contains(uid),
                "撤回后绝不能丢失用户原有订阅 uid={uid}"
            );
        }

        // 2. 执行正向重注入，验证服务模式下一次热重载变绿 + First-Write-Wins 基线落盘
        let cfg = crate::config::AppConfig::default();
        let fix = crate::preflight::execute_fix_item("node_group", &cfg, 0)
            .await
            .expect("reinject node_group");
        println!("[Gate2] reinject node_group success={} msg={}", fix.success, fix.message);
        assert!(fix.success, "正向重注入 node_group 必须一次变绿: {}", fix.message);

        let proxies_after_fix = crate::mihomo::fetch_proxies_raw(&ep).await.expect("fetch proxies after fix");
        assert!(
            crate::mihomo::extract_proxy_group(&proxies_after_fix, "Claude-Fixed").is_some(),
            "正向重注入后 Mihomo 中必须实时存在 Claude-Fixed 策略组"
        );

        // 3. 验证 inspect_rollback_status 检出基线与中文物理网卡 DNS 无乱码
        let ov = inspect_rollback_status().await;
        println!(
            "[Gate2/3] baseline_exists={} is_elevated={} touched={} loopback_dns={:?}",
            ov.baseline_exists, ov.is_elevated, ov.touched_count, ov.loopback_dns_adapters
        );
        assert!(ov.baseline_exists, "正向注入后应已落盘 system-baseline.json");
        assert!(
            ov.items.iter().any(|i| i.id == "clash_rules" && i.touched_by_guard),
            "overview 应准确标记 clash_rules 已被本工具改动"
        );
        for name in &ov.loopback_dns_adapters {
            assert!(!name.contains('\u{FFFD}'), "中文网卡名绝不能出现 GBK 替换乱码: {name}");
        }
    }

    #[test]
    fn t053_patch_top_level_yaml_bool_preserves_nested_dns_ipv6_and_supports_roundtrip() {
        let sample = "# Clash Verge\nmode: rule\nipv6: true\ndns:\n  enable: true\n  ipv6: true\n";
        assert_eq!(read_top_level_yaml_bool(sample, "ipv6"), Some(true));

        let disabled = patch_top_level_yaml_bool(sample, "ipv6", false);
        assert_eq!(read_top_level_yaml_bool(&disabled, "ipv6"), Some(false));
        assert!(
            disabled.contains("\ndns:\n  enable: true\n  ipv6: true\n"),
            "绝不能误伤缩进的 dns.ipv6 字段: {disabled}"
        );

        let restored = patch_top_level_yaml_bool(&disabled, "ipv6", true);
        assert_eq!(read_top_level_yaml_bool(&restored, "ipv6"), Some(true));
        assert!(restored.contains("\nipv6: true\n"));
        assert!(restored.contains("\ndns:\n  enable: true\n  ipv6: true\n"));
    }

    #[test]
    fn extract_local_proxy_ports_handles_multi_proto_scheme_and_ipv6() {
        assert_eq!(extract_local_proxy_ports("127.0.0.1:7897"), vec![7897]);
        assert_eq!(extract_local_proxy_ports("localhost:7890"), vec![7890]);
        assert_eq!(
            extract_local_proxy_ports("http://127.0.0.1:7897"),
            vec![7897]
        );
        assert_eq!(
            extract_local_proxy_ports("http=127.0.0.1:7897;https=127.0.0.1:7897;socks=localhost:7898"),
            vec![7897, 7898]
        );
        assert_eq!(extract_local_proxy_ports("[::1]:10809"), vec![10809]);
        assert!(extract_local_proxy_ports("192.168.1.10:7897").is_empty());
        assert!(extract_local_proxy_ports("proxy.corp.local:8080").is_empty());
    }

    #[test]
    fn corrupted_baseline_is_backed_up_instead_of_silently_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("system-baseline.json");
        fs::write(&p, "{ broken json !!!").expect("write broken");
        let bl = load_baseline_from(&p);
        assert!(bl.sys_ipv6.is_none());
        let has_corrupt_backup = fs::read_dir(dir.path())
            .expect("readdir")
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains(".corrupt-"));
        assert!(has_corrupt_backup, "坏基线文件应自动保留 .corrupt-* 备份");
    }
}
