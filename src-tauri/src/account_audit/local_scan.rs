//! 本地非侵入只读扫描模块（100% 遵守 6 条 `ProfileContext` 契约，零网络、零 DPAPI 解密、零硬编码路径）。
//!
//! 关键安全与性能保障：
//! 1. 所有路径通过 `ProfileContext` 注入，测试与未来多号可直接复用；
//! 2. `.credentials.json` 使用白名单结构体 `CredentialsMetaRaw` 反序列化，编译期杜绝 `accessToken` / `refreshToken` 进入内存；
//! 3. Windows 下以共享只读模式（`FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`）打开正在被 Claude 写入的日志与 JSON；
//! 4. 单日志最多读取尾部 `2 MB`；`.jsonl` 带 `(path, mtime_ms, size)` 内存缓存，严禁阻塞主线程；
//! 5. `org_level_disabled` 严格不视为风控异常。

use super::mask_email_readable;
use chrono::{DateTime, Timelike, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// 官方隐私降噪 4 项环境变量真源（账户审计与控制台 `claude_tel` 100% 同源共用）
pub const PRIVACY_ENV_KEYS: [&str; 4] = [
    "DISABLE_TELEMETRY",
    "DISABLE_ERROR_REPORTING",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "DISABLE_BUG_COMMAND",
];

/// 官方 API 端点防反代检测环境变量键集合（账户审计与控制台 `claude_endpoint` 100% 同源共用）
pub const API_ENDPOINT_ENV_KEYS: [&str; 3] = [
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_URL",
    "CLAUDE_API_BASE_URL",
];

/// 单日志最大尾读上限（2 MiB）
const MAX_LOG_TAIL_BYTES: u64 = 2 * 1024 * 1024;
/// MCP 报错风暴静默兜底阈值（短时间 >= 50 条循环错误才吐 1 条提示，平时 0 噪音）
pub const MCP_STORM_THRESHOLD: usize = 50;

/// 桌面端目录来源（经典 Electron / 微软商店 MSIX）
#[derive(Debug, Clone)]
pub struct DesktopDataRoot {
    pub kind: String,
    pub dir: PathBuf,
}

/// 6 条防返工契约核心上下文：严禁在解析函数内硬编码 `~/.claude` 或 `%LOCALAPPDATA%\Claude`
#[derive(Debug, Clone)]
pub struct ProfileContext {
    pub profile_id: String,
    pub cli_config_dir: Option<PathBuf>,
    pub claude_json_path: Option<PathBuf>,
    pub desktop_data_dirs: Vec<DesktopDataRoot>,
    pub expected_geo: Option<String>,
    pub bound_proxy_port: Option<u16>,
    /// 是否扫描 Windows 注册表 HKCU/HKLM 环境变量（单测中可置 false 隔离宿主机状态）
    pub scan_system_env: bool,
}

impl ProfileContext {
    /// 构造默认单号档案上下文（profile_id 固定 `"default"`）
    pub fn default_local(
        profile_id: Option<String>,
        expected_geo: Option<String>,
        bound_proxy_port: Option<u16>,
    ) -> Self {
        let pid = profile_id
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "default".to_string());
        let home = dirs::home_dir();
        let cli_config_dir = home.as_ref().map(|h| h.join(".claude"));
        let claude_json_path = home.as_ref().map(|h| h.join(".claude.json"));
        let desktop_data_dirs = discover_desktop_data_dirs(
            dirs::data_local_dir().as_deref(),
            dirs::config_dir().as_deref(),
        );
        Self {
            profile_id: pid,
            cli_config_dir,
            claude_json_path,
            desktop_data_dirs,
            expected_geo,
            bound_proxy_port,
            scan_system_env: true,
        }
    }
}

/// 发现桌面端目录（经典 Local/Roaming + MSIX LocalCache），参数化便于单测注入
pub fn discover_desktop_data_dirs(
    data_local_dir: Option<&Path>,
    config_dir: Option<&Path>,
) -> Vec<DesktopDataRoot> {
    let mut out = Vec::new();
    if let Some(local) = data_local_dir {
        let classic = local.join("Claude");
        if classic.exists() {
            out.push(DesktopDataRoot {
                kind: "LocalAppData".into(),
                dir: classic,
            });
        }
        let pkgs = local.join("Packages");
        if let Ok(entries) = fs::read_dir(pkgs) {
            for ent in entries.flatten() {
                let name = ent.file_name().to_string_lossy().to_string();
                let lower = name.to_ascii_lowercase();
                if lower.starts_with("claude_") || lower.contains("anthropic") {
                    let roaming = ent
                        .path()
                        .join("LocalCache")
                        .join("Roaming")
                        .join("Claude");
                    let local_msix = ent
                        .path()
                        .join("LocalCache")
                        .join("Local")
                        .join("Claude");
                    if roaming.exists() {
                        out.push(DesktopDataRoot {
                            kind: format!("MSIX-Roaming({name})"),
                            dir: roaming,
                        });
                    }
                    if local_msix.exists() {
                        out.push(DesktopDataRoot {
                            kind: format!("MSIX-Local({name})"),
                            dir: local_msix,
                        });
                    }
                }
            }
        }
    }
    if let Some(roaming) = config_dir {
        let classic = roaming.join("Claude");
        if classic.exists() {
            out.push(DesktopDataRoot {
                kind: "RoamingAppData".into(),
                dir: classic,
            });
        }
    }
    out
}

/// 以 Windows 共享只读模式打开文件（防止抢占正在被 Claude 写入的文件锁）
pub fn open_shared_readonly(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ (1) | FILE_SHARE_WRITE (2) | FILE_SHARE_DELETE (4)
        opts.share_mode(0x0000_0001 | 0x0000_0002 | 0x0000_0004);
    }
    opts.open(path)
}

/// 共享只读读取小文本文件（上限 16 MiB）
pub fn read_text_shared(path: &Path) -> std::io::Result<String> {
    let mut f = open_shared_readonly(path)?;
    let meta = f.metadata()?;
    if meta.len() > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "文件体积超出安全上限 (16MB)",
        ));
    }
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    Ok(buf)
}

/// 共享只读读取大日志文件尾部（上限 `max_bytes`）
pub fn read_tail_shared(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let mut f = open_shared_readonly(path)?;
    let len = f.metadata()?.len();
    let read_len = len.min(max_bytes) as usize;
    if len > max_bytes {
        f.seek(SeekFrom::Start(len - max_bytes))?;
    }
    let mut bytes = vec![0u8; read_len];
    f.read_exact(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ==================== 白名单凭据结构（编译期绝不定义 accessToken / refreshToken） ====================

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialsMetaRaw {
    claude_ai_oauth: Option<ClaudeAiOauthMetaRaw>,
    mcp_oauth: Option<HashMap<String, Value>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaudeAiOauthMetaRaw {
    subscription_type: Option<String>,
    rate_limit_tier: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    expires_at: Option<Value>,
}

/// 凭据元数据扫描摘要（零明文 Token）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsMetaSummary {
    pub exists: bool,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub is_expired: Option<bool>,
    pub mcp_oauth_providers: Vec<String>,
}

/// 历史备份中识别出的脱敏账号记录
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupAccountRecord {
    pub org_prefix: String,
    pub email_masked: Option<String>,
    pub plan_label: Option<String>,
    pub merchant_channel: Option<String>,
    pub backup_count: usize,
}

/// 本地缓存用量快照（源自 `~/.claude.json`）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedUsageSummary {
    pub fetched_at_ms: Option<i64>,
    pub five_hour_pct: Option<f64>,
    pub five_hour_resets_at: Option<String>,
    pub five_hour_locked_reason: Option<String>,
    pub seven_day_pct: Option<f64>,
    pub seven_day_resets_at: Option<String>,
    pub seven_day_locked_reason: Option<String>,
    pub cached_extra_usage_disabled_reason: Option<String>,
}

/// `~/.claude.json` 账号与设备指纹扫描结果
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeJsonSummary {
    pub exists: bool,
    pub parse_error: Option<String>,
    pub email_masked: Option<String>,
    pub org_uuid_prefix8: Option<String>,
    pub plan_label: Option<String>,
    pub billing_type: Option<String>,
    pub merchant_channel: Option<String>,
    pub account_created_at: Option<String>,
    pub account_age_days: Option<u64>,
    pub subscription_created_at: Option<String>,
    pub subscription_age_days: Option<u64>,
    pub first_start_time: Option<String>,
    pub local_device_age_days: Option<u64>,
    pub machine_id_prefix8: Option<String>,
    pub user_id_prefix8: Option<String>,
    pub cached_usage: Option<CachedUsageSummary>,
}

/// `settings.json` 与端点/隐私降噪/遥测/定时任务扫描结果（控制台与账户审计 100% 同源）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsHygieneSummary {
    pub settings_exists: bool,
    pub settings_path: Option<String>,
    /// 4 项隐私降噪开关状态（true 表示已设置为 `"1"`）
    pub privacy_env_flags: BTreeMap<String, bool>,
    pub privacy_enabled_count: usize,
    pub privacy_missing_keys: Vec<String>,
    /// `settings.json` 中的非官方端点（仅展示脱敏 host）
    pub settings_non_official_endpoint: Option<String>,
    /// 系统环境变量中的非官方端点冲突列表（脱敏）
    pub system_env_endpoint_conflicts: Vec<String>,
    pub telemetry_file_count: usize,
    pub telemetry_total_bytes: u64,
    pub scheduled_tasks_count: usize,
    pub backup_file_count: usize,
    pub backup_accounts: Vec<BackupAccountRecord>,
}

/// 单时间窗口离线 `.jsonl` 统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowBehaviorStats {
    pub assistant_turns: u64,
    pub sidechain_turns: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
}

/// 离线 `.jsonl` 行为强度与跨夜节律监测（零网络，不读聊天正文）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineBehaviorSummary {
    pub projects_dir_exists: bool,
    pub files_scanned_7d: usize,
    pub last_5h: WindowBehaviorStats,
    pub last_24h: WindowBehaviorStats,
    pub last_7d: WindowBehaviorStats,
    pub subagent_ratio_24h_pct: u32,
    pub active_hours_24h: usize,
    pub overnight_bot_rhythm_suspected: bool,
}

/// 桌面客户端日志与组织残留扫描摘要
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopLogsSummary {
    pub discovered_dirs: Vec<String>,
    pub scanned_log_files: usize,
    pub org_id_prefixes: Vec<String>,
    pub account_banned_hits: usize,
    pub portal_verify_hits: usize,
    pub cross_org_404_hits: usize,
    pub oauth_403_hits: usize,
    pub cookie_403_hits: usize,
    pub cf_shield_403_hits: usize,
    pub rate_limit_429_hits: usize,
    pub plan_changed_hits: usize,
    pub five_hour_soft_lock_hits: usize,
    pub max_side_sessions_seen: u32,
    pub high_side_session_hits: usize,
    pub mcp_error_hits: usize,
    pub mcp_error_storm: bool,
    pub disconnect_hits: usize,
    /// 提取用于「实时异常日志流」与消歧的脱敏日志摘录
    pub recent_samples: Vec<LocalLogSample>,
}

/// 用于前端「实时异常日志流」与 403 消歧的精简脱敏样本
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalLogSample {
    pub id: String,
    pub category: String,
    pub time: String,
    pub file_ref: String,
    pub raw_sanitized: String,
    pub count: usize,
}

/// 本地非侵入只读全量扫描聚合结果
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalAccountAudit {
    pub profile_id: String,
    pub scanned_at_ms: i64,
    pub claude_json: ClaudeJsonSummary,
    pub credentials: CredentialsMetaSummary,
    pub hygiene: SettingsHygieneSummary,
    pub behavior: OfflineBehaviorSummary,
    pub desktop: DesktopLogsSummary,
    /// CLI 与 Desktop 跨端组织是否冲突
    pub cross_client_org_mismatch: bool,
    /// 本机观测到的全部唯一 orgId 前缀（CLI + Desktop + Backups 并集）
    pub all_observed_org_prefixes: Vec<String>,
}

/// 统一判断 URL 是否属于非官方 Anthropic API 端点
pub fn is_non_official_anthropic_url(raw: &str) -> bool {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return false;
    }
    let host_port = trimmed
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("");
    !matches!(host, "api.anthropic.com" | "claude.ai" | "api.claude.ai")
}

/// 提取 URL 脱敏 host（绝不泄露路径 Token 或代理账密）
pub fn extract_safe_host(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or("custom");
    // 若包含 user:pass@host，仅保留 @ 后半段
    let host_part = authority.rsplit('@').next().unwrap_or("custom");
    if host_part.is_empty() {
        "custom".to_string()
    } else {
        host_part.to_string()
    }
}

/// 标准化套餐名称
pub fn normalize_plan_label(
    org_type: Option<&str>,
    sub_type: Option<&str>,
    rate_tier: Option<&str>,
) -> Option<String> {
    let joined = format!(
        "{} {} {}",
        org_type.unwrap_or(""),
        sub_type.unwrap_or(""),
        rate_tier.unwrap_or("")
    )
    .to_ascii_lowercase();
    if joined.trim().is_empty() {
        return None;
    }
    if joined.contains("enterprise") {
        return Some("Enterprise".into());
    }
    if joined.contains("team") || joined.contains("raven") {
        return Some("Team".into());
    }
    if joined.contains("max") {
        if joined.contains("20x") || joined.contains("x20") {
            return Some("Max 20x".into());
        }
        if joined.contains("5x") || joined.contains("x5") {
            return Some("Max 5x".into());
        }
        return Some("Max".into());
    }
    if joined.contains("pro") {
        return Some("Pro".into());
    }
    if joined.contains("free") || joined.contains("default_claude_ai") {
        return Some("Free".into());
    }
    None
}

/// 标准化商户支付渠道为清晰中文
pub fn format_merchant_channel(
    billing_type: Option<&str>,
    merchant_of_record: Option<&str>,
) -> Option<String> {
    let raw = format!(
        "{} {}",
        billing_type.unwrap_or(""),
        merchant_of_record.unwrap_or("")
    )
    .to_ascii_lowercase();
    if raw.trim().is_empty() {
        return None;
    }
    if raw.contains("stripe") {
        return Some("Stripe 直付".into());
    }
    if raw.contains("apple") || raw.contains("app_store") || raw.contains("ios") {
        return Some("Apple 内购".into());
    }
    if raw.contains("google") || raw.contains("play") || raw.contains("android") {
        return Some("Google Play".into());
    }
    if raw.contains("enterprise") || raw.contains("invoice") {
        return Some("Enterprise".into());
    }
    if raw.contains("none") {
        return Some("Free 无订阅".into());
    }
    None
}

fn days_since_iso(iso: &str, now_ms: i64) -> Option<u64> {
    let dt = DateTime::parse_from_rfc3339(iso).ok()?;
    let diff = now_ms - dt.timestamp_millis();
    Some(if diff > 0 {
        (diff / 86_400_000) as u64
    } else {
        0
    })
}

fn prefix8(raw: Option<&str>) -> Option<String> {
    raw.map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(8).collect::<String>().to_ascii_lowercase())
}

fn now_epoch_ms_i64() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 扫描 `~/.claude.json`
pub fn scan_claude_json(path: Option<&Path>, now_ms: i64) -> ClaudeJsonSummary {
    let Some(p) = path else {
        return ClaudeJsonSummary::default();
    };
    if !p.exists() {
        return ClaudeJsonSummary::default();
    }
    let raw = match read_text_shared(p) {
        Ok(s) => s,
        Err(e) => {
            return ClaudeJsonSummary {
                exists: true,
                parse_error: Some(format!("读取失败: {e}")),
                ..Default::default()
            };
        }
    };
    let val: Value = match serde_json::from_str(raw.trim_start_matches('\u{feff}')) {
        Ok(v) => v,
        Err(e) => {
            return ClaudeJsonSummary {
                exists: true,
                parse_error: Some(format!("JSON 格式损坏: {e}")),
                ..Default::default()
            };
        }
    };

    let oa = val.get("oauthAccount");
    let email_masked = oa
        .and_then(|o| o.get("emailAddress"))
        .and_then(|v| v.as_str())
        .map(mask_email_readable);
    let org_uuid_prefix8 = prefix8(
        oa.and_then(|o| o.get("organizationUuid"))
            .and_then(|v| v.as_str()),
    );
    let org_type = oa
        .and_then(|o| o.get("organizationType"))
        .and_then(|v| v.as_str());
    let billing_type = oa
        .and_then(|o| o.get("billingType"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let rate_tier = oa
        .and_then(|o| o.get("organizationRateLimitTier"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            oa.and_then(|o| o.get("userRateLimitTier"))
                .and_then(|v| v.as_str())
        });
    let plan_label = normalize_plan_label(org_type, None, rate_tier);
    let merchant_channel = format_merchant_channel(billing_type.as_deref(), None);

    let account_created_at = oa
        .and_then(|o| o.get("accountCreatedAt"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let account_age_days = account_created_at
        .as_deref()
        .and_then(|iso| days_since_iso(iso, now_ms));

    let subscription_created_at = oa
        .and_then(|o| o.get("subscriptionCreatedAt"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let subscription_age_days = subscription_created_at
        .as_deref()
        .and_then(|iso| days_since_iso(iso, now_ms));

    let first_start_time = val
        .get("firstStartTime")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let local_device_age_days = first_start_time
        .as_deref()
        .and_then(|iso| days_since_iso(iso, now_ms));

    let machine_id_prefix8 = prefix8(val.get("machineID").and_then(|v| v.as_str()));
    let user_id_prefix8 = prefix8(val.get("userID").and_then(|v| v.as_str()));

    let cached_extra_reason = val
        .get("cachedExtraUsageDisabledReason")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    let cached_usage = val.get("cachedUsageUtilization").map(|cu| {
        let u = cu.get("utilization");
        CachedUsageSummary {
            fetched_at_ms: cu.get("fetchedAtMs").and_then(|v| v.as_i64()),
            five_hour_pct: u
                .and_then(|x| x.get("five_hour"))
                .and_then(|x| x.get("utilization"))
                .and_then(|v| v.as_f64()),
            five_hour_resets_at: u
                .and_then(|x| x.get("five_hour"))
                .and_then(|x| x.get("resets_at"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            five_hour_locked_reason: u
                .and_then(|x| x.get("five_hour"))
                .and_then(|x| x.get("locked_reason"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            seven_day_pct: u
                .and_then(|x| x.get("seven_day"))
                .and_then(|x| x.get("utilization"))
                .and_then(|v| v.as_f64()),
            seven_day_resets_at: u
                .and_then(|x| x.get("seven_day"))
                .and_then(|x| x.get("resets_at"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            seven_day_locked_reason: u
                .and_then(|x| x.get("seven_day"))
                .and_then(|x| x.get("locked_reason"))
                .and_then(|v| v.as_str())
                .map(ToString::to_string),
            cached_extra_usage_disabled_reason: cached_extra_reason.clone(),
        }
    });

    ClaudeJsonSummary {
        exists: true,
        parse_error: None,
        email_masked,
        org_uuid_prefix8,
        plan_label,
        billing_type,
        merchant_channel,
        account_created_at,
        account_age_days,
        subscription_created_at,
        subscription_age_days,
        first_start_time,
        local_device_age_days,
        machine_id_prefix8,
        user_id_prefix8,
        cached_usage,
    }
}

/// 扫描 `~/.claude/.credentials.json`（严格白名单结构，编译期绝不读明文 Token）
pub fn scan_credentials_meta(cli_dir: Option<&Path>, now_ms: i64) -> CredentialsMetaSummary {
    let Some(dir) = cli_dir else {
        return CredentialsMetaSummary::default();
    };
    let path = dir.join(".credentials.json");
    if !path.exists() {
        return CredentialsMetaSummary::default();
    }
    let Ok(raw) = read_text_shared(&path) else {
        return CredentialsMetaSummary {
            exists: true,
            ..Default::default()
        };
    };
    let Ok(parsed) = serde_json::from_str::<CredentialsMetaRaw>(raw.trim_start_matches('\u{feff}'))
    else {
        return CredentialsMetaSummary {
            exists: true,
            ..Default::default()
        };
    };

    let oauth = parsed.claude_ai_oauth;
    let expires_ms = oauth.as_ref().and_then(|o| o.expires_at.as_ref()).and_then(|v| {
        if let Some(n) = v.as_i64() {
            Some(n)
        } else if let Some(s) = v.as_str() {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.timestamp_millis())
        } else {
            None
        }
    });
    let expires_at = expires_ms
        .and_then(|ms| DateTime::<Utc>::from_timestamp_millis(ms))
        .map(|dt| dt.to_rfc3339());
    let is_expired = expires_ms.map(|ms| ms <= now_ms);

    let mcp_oauth_providers = parsed
        .mcp_oauth
        .map(|m| {
            let mut v: Vec<String> = m
                .keys()
                .map(|k| k.split('|').next().unwrap_or(k).to_string())
                .collect();
            v.sort();
            v.dedup();
            v
        })
        .unwrap_or_default();

    CredentialsMetaSummary {
        exists: true,
        subscription_type: oauth.as_ref().and_then(|o| o.subscription_type.clone()),
        rate_limit_tier: oauth.as_ref().and_then(|o| o.rate_limit_tier.clone()),
        scopes: oauth.map(|o| o.scopes).unwrap_or_default(),
        expires_at,
        is_expired,
        mcp_oauth_providers,
    }
}

/// 扫描系统环境变量中的非官方 Anthropic API 端点冲突
pub fn scan_system_env_api_endpoints() -> Vec<String> {
    let mut conflicts = Vec::new();

    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        use winreg::RegKey;
        if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey("Environment") {
            for k in API_ENDPOINT_ENV_KEYS {
                if let Ok(v) = key.get_value::<String, _>(k) {
                    if is_non_official_anthropic_url(&v) {
                        conflicts.push(format!("HKCU\\Environment {k}={}", extract_safe_host(&v)));
                    }
                }
            }
        }
        if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
        {
            for k in API_ENDPOINT_ENV_KEYS {
                if let Ok(v) = key.get_value::<String, _>(k) {
                    if is_non_official_anthropic_url(&v) {
                        conflicts.push(format!("HKLM\\Environment {k}={}", extract_safe_host(&v)));
                    }
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        for k in API_ENDPOINT_ENV_KEYS {
            if let Ok(v) = std::env::var(k) {
                if is_non_official_anthropic_url(&v) {
                    conflicts.push(format!("ENV {k}={}", extract_safe_host(&v)));
                }
            }
        }
    }

    conflicts.sort();
    conflicts.dedup();
    conflicts
}

fn dir_file_stats_bounded(dir: &Path, depth: usize) -> (usize, u64) {
    if depth > 12 {
        return (0, 0);
    }
    let Ok(meta) = fs::symlink_metadata(dir) else {
        return (0, 0);
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return (0, 0);
    }
    let Ok(rd) = fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut files = 0usize;
    let mut bytes = 0u64;
    for ent in rd.flatten() {
        let p = ent.path();
        let Ok(m) = fs::symlink_metadata(&p) else {
            continue;
        };
        if m.file_type().is_symlink() {
            continue;
        }
        if m.is_dir() {
            let (f, b) = dir_file_stats_bounded(&p, depth + 1);
            files += f;
            bytes = bytes.saturating_add(b);
        } else if m.is_file() {
            files += 1;
            bytes = bytes.saturating_add(m.len());
        }
    }
    (files, bytes)
}

/// 扫描 `~/.claude/settings.json`、`telemetry/`、`scheduled-tasks/` 与 `backups/`
pub fn scan_settings_and_hygiene(
    cli_dir: Option<&Path>,
    scan_system_env: bool,
) -> SettingsHygieneSummary {
    let mut summary = SettingsHygieneSummary::default();
    for k in PRIVACY_ENV_KEYS {
        summary.privacy_env_flags.insert(k.to_string(), false);
    }

    if scan_system_env {
        summary.system_env_endpoint_conflicts = scan_system_env_api_endpoints();
    }

    let Some(dir) = cli_dir else {
        summary.privacy_missing_keys = PRIVACY_ENV_KEYS.iter().map(|s| (*s).to_string()).collect();
        return summary;
    };

    let settings_path = dir.join("settings.json");
    summary.settings_path = Some(settings_path.to_string_lossy().to_string());
    if settings_path.exists() {
        summary.settings_exists = true;
        if let Ok(raw) = read_text_shared(&settings_path) {
            if let Ok(val) = serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}')) {
                if let Some(env_map) = val.get("env").and_then(|e| e.as_object()) {
                    for k in PRIVACY_ENV_KEYS {
                        let enabled = env_map
                            .get(k)
                            .and_then(|v| {
                                v.as_str()
                                    .map(|s| s.trim() == "1" || s.eq_ignore_ascii_case("true"))
                                    .or_else(|| v.as_bool())
                                    .or_else(|| v.as_i64().map(|n| n == 1))
                            })
                            .unwrap_or(false);
                        summary.privacy_env_flags.insert(k.to_string(), enabled);
                    }
                    for k in API_ENDPOINT_ENV_KEYS {
                        if let Some(url) = env_map.get(k).and_then(|v| v.as_str()) {
                            if is_non_official_anthropic_url(url) {
                                summary.settings_non_official_endpoint =
                                    Some(format!("{k}={}", extract_safe_host(url)));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    summary.privacy_enabled_count = summary.privacy_env_flags.values().filter(|&&v| v).count();
    summary.privacy_missing_keys = PRIVACY_ENV_KEYS
        .iter()
        .filter(|&&k| !summary.privacy_env_flags.get(k).copied().unwrap_or(false))
        .map(|s| (*s).to_string())
        .collect();

    // telemetry 待传目录
    let (tel_files, tel_bytes) = dir_file_stats_bounded(&dir.join("telemetry"), 0);
    summary.telemetry_file_count = tel_files;
    summary.telemetry_total_bytes = tel_bytes;

    // scheduled-tasks 定时脚本
    let (sched_files, _) = dir_file_stats_bounded(&dir.join("scheduled-tasks"), 0);
    summary.scheduled_tasks_count = sched_files;

    // backups/.claude.json.backup.* 反查脱敏账号信息
    let backups_dir = dir.join("backups");
    let mut backup_map: BTreeMap<String, BackupAccountRecord> = BTreeMap::new();
    if let Ok(rd) = fs::read_dir(&backups_dir) {
        for ent in rd.flatten() {
            let fname = ent.file_name().to_string_lossy().to_string();
            if !fname.contains(".claude.json.backup") {
                continue;
            }
            summary.backup_file_count += 1;
            if let Ok(raw) = read_text_shared(&ent.path()) {
                if let Ok(val) = serde_json::from_str::<Value>(raw.trim_start_matches('\u{feff}')) {
                    let oa = val.get("oauthAccount");
                    if let Some(org_prefix) = prefix8(
                        oa.and_then(|o| o.get("organizationUuid"))
                            .and_then(|v| v.as_str()),
                    ) {
                        let email_masked = oa
                            .and_then(|o| o.get("emailAddress"))
                            .and_then(|v| v.as_str())
                            .map(mask_email_readable);
                        let plan_label = normalize_plan_label(
                            oa.and_then(|o| o.get("organizationType"))
                                .and_then(|v| v.as_str()),
                            None,
                            oa.and_then(|o| o.get("organizationRateLimitTier"))
                                .and_then(|v| v.as_str()),
                        );
                        let merchant_channel = format_merchant_channel(
                            oa.and_then(|o| o.get("billingType"))
                                .and_then(|v| v.as_str()),
                            None,
                        );
                        let entry =
                            backup_map
                                .entry(org_prefix.clone())
                                .or_insert(BackupAccountRecord {
                                    org_prefix,
                                    email_masked: None,
                                    plan_label: None,
                                    merchant_channel: None,
                                    backup_count: 0,
                                });
                        entry.backup_count += 1;
                        if entry.email_masked.is_none() {
                            entry.email_masked = email_masked;
                        }
                        if entry.plan_label.is_none() {
                            entry.plan_label = plan_label;
                        }
                        if entry.merchant_channel.is_none() {
                            entry.merchant_channel = merchant_channel;
                        }
                    }
                }
            }
        }
    }
    summary.backup_accounts = backup_map.into_values().collect();
    summary
}

// ==================== `.jsonl` (path, mtime, size) 增量缓存与离线节律扫描 ====================

#[derive(Debug, Clone)]
struct JsonlTurnRecord {
    ts_ms: i64,
    is_sidechain: bool,
    in_tok: u64,
    out_tok: u64,
    cache_read: u64,
}

#[derive(Debug, Clone)]
struct JsonlFileCache {
    mtime_ms: i64,
    size: u64,
    turns: Vec<JsonlTurnRecord>,
}

fn jsonl_cache() -> &'static Mutex<HashMap<PathBuf, JsonlFileCache>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, JsonlFileCache>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn parse_jsonl_turns_cached(path: &Path, mtime_ms: i64, size: u64) -> Vec<JsonlTurnRecord> {
    if let Ok(guard) = jsonl_cache().lock() {
        if let Some(hit) = guard.get(path) {
            if hit.mtime_ms == mtime_ms && hit.size == size {
                return hit.turns.clone();
            }
        }
    }

    let mut turns = Vec::new();
    if let Ok(raw) = read_text_shared(path) {
        for line in raw.lines() {
            if !line.contains("\"usage\"") {
                continue;
            }
            let Ok(obj) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let usage = obj
                .get("message")
                .and_then(|m| m.get("usage"))
                .or_else(|| obj.get("usage"));
            let Some(u) = usage else {
                continue;
            };
            let ts_ms = obj
                .get("timestamp")
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.timestamp_millis())
                .unwrap_or(mtime_ms);
            let is_sidechain = obj
                .get("isSidechain")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let in_tok = u.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
            let out_tok = u.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
            let cache_read = u
                .get("cache_read_input_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            turns.push(JsonlTurnRecord {
                ts_ms,
                is_sidechain,
                in_tok,
                out_tok,
                cache_read,
            });
        }
    }

    if let Ok(mut guard) = jsonl_cache().lock() {
        // 防止缓存无限增长
        if guard.len() > 512 {
            guard.clear();
        }
        guard.insert(
            path.to_path_buf(),
            JsonlFileCache {
                mtime_ms,
                size,
                turns: turns.clone(),
            },
        );
    }
    turns
}

/// 离线扫描 `~/.claude/projects/**/*.jsonl`（绝不读聊天正文）
pub fn scan_offline_jsonl_behavior(cli_dir: Option<&Path>, now_ms: i64) -> OfflineBehaviorSummary {
    let Some(dir) = cli_dir else {
        return OfflineBehaviorSummary::default();
    };
    let projects_dir = dir.join("projects");
    if !projects_dir.exists() {
        return OfflineBehaviorSummary::default();
    }

    let cutoff_7d = now_ms - 7 * 86_400_000;
    let cutoff_24h = now_ms - 24 * 3_600_000;
    let cutoff_5h = now_ms - 5 * 3_600_000;

    let mut summary = OfflineBehaviorSummary {
        projects_dir_exists: true,
        ..Default::default()
    };
    let mut active_hours_24h: BTreeSet<u32> = BTreeSet::new();

    let mut stack: Vec<(PathBuf, usize)> = vec![(projects_dir, 0)];
    while let Some((cur, depth)) = stack.pop() {
        if depth > 3 {
            continue;
        }
        let Ok(rd) = fs::read_dir(&cur) else {
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push((p, depth + 1));
            } else if meta.is_file()
                && p.extension().and_then(|e| e.to_str()) == Some("jsonl")
            {
                let mtime_ms = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                if mtime_ms < cutoff_7d {
                    continue;
                }
                summary.files_scanned_7d += 1;
                let turns = parse_jsonl_turns_cached(&p, mtime_ms, meta.len());
                for t in turns {
                    if t.ts_ms < cutoff_7d {
                        continue;
                    }
                    let apply = |b: &mut WindowBehaviorStats| {
                        b.assistant_turns += 1;
                        if t.is_sidechain {
                            b.sidechain_turns += 1;
                        }
                        b.input_tokens = b.input_tokens.saturating_add(t.in_tok);
                        b.output_tokens = b.output_tokens.saturating_add(t.out_tok);
                        b.cache_read_tokens = b.cache_read_tokens.saturating_add(t.cache_read);
                    };
                    apply(&mut summary.last_7d);
                    if t.ts_ms >= cutoff_24h {
                        apply(&mut summary.last_24h);
                        if let Some(dt) = DateTime::<Utc>::from_timestamp_millis(t.ts_ms) {
                            active_hours_24h.insert(dt.hour());
                        }
                    }
                    if t.ts_ms >= cutoff_5h {
                        apply(&mut summary.last_5h);
                    }
                }
            }
        }
    }

    summary.active_hours_24h = active_hours_24h.len();
    summary.subagent_ratio_24h_pct = if summary.last_24h.assistant_turns > 0 {
        ((summary.last_24h.sidechain_turns * 100) / summary.last_24h.assistant_turns) as u32
    } else {
        0
    };
    // 判定跨夜 24×7 机刷节律：过去 24h 内覆盖 >= 18 个不同小时且总轮次 >= 120 轮
    summary.overnight_bot_rhythm_suspected =
        summary.active_hours_24h >= 18 && summary.last_24h.assistant_turns >= 120;

    summary
}

/// 扫描桌面端日志（单文件尾读 <= 2MB，共享只读）
pub fn scan_desktop_logs(roots: &[DesktopDataRoot]) -> DesktopLogsSummary {
    static RE_ORG: OnceLock<Regex> = OnceLock::new();
    static RE_429: OnceLock<Regex> = OnceLock::new();
    static RE_SIDE: OnceLock<Regex> = OnceLock::new();

    let re_org = RE_ORG.get_or_init(|| {
        Regex::new(r#"(?i)(?:orgId|organization_uuid|organizationId)["'=:\s]+([a-f0-9-]{8,36})"#)
            .unwrap()
    });
    let re_429 = RE_429
        .get_or_init(|| Regex::new(r#"(?i)(?:http[/\s]+|status[_\s:=]+["']?)429\b"#).unwrap());
    let re_side = RE_SIDE.get_or_init(|| Regex::new(r"(?i)sidesessions?\s*[:=]\s*(\d+)").unwrap());

    let mut summary = DesktopLogsSummary::default();
    let mut org_set: BTreeSet<String> = BTreeSet::new();
    let mut sample_map: BTreeMap<String, LocalLogSample> = BTreeMap::new();

    for root in roots {
        if !root.dir.exists() {
            continue;
        }
        summary.discovered_dirs.push(root.kind.clone());
        let logs_dir = root.dir.join("logs");
        let Ok(rd) = fs::read_dir(&logs_dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("log") {
                continue;
            }
            let fname = ent.file_name().to_string_lossy().to_string();
            let Ok(text) = read_tail_shared(&p, MAX_LOG_TAIL_BYTES) else {
                continue;
            };
            summary.scanned_log_files += 1;

            for caps in re_org.captures_iter(&text) {
                if let Some(m) = caps.get(1) {
                    let p8: String = m.as_str().chars().take(8).collect();
                    if p8.len() == 8 {
                        org_set.insert(p8.to_ascii_lowercase());
                    }
                }
            }

            let is_mcp_log = fname.to_ascii_lowercase().contains("mcp");
            let mut last_ts = String::new();
            for (idx, line) in text.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if trimmed.len() >= 19
                    && trimmed.is_char_boundary(19)
                    && trimmed.as_bytes()[..19].iter().all(|b| b.is_ascii())
                    && trimmed.as_bytes()[4] == b'-'
                    && trimmed.as_bytes()[13] == b':'
                {
                    last_ts = trimmed[..19].replace('T', " ");
                }
                let lower = trimmed.to_ascii_lowercase();
                let line_no = idx + 1;

                let mut push_sample = |cat: &str, sample_line: &str| {
                    let key = format!("{cat}:{fname}");
                    let sanitized = crate::maintenance::sanitize_sensitive_text(sample_line);
                    let entry = sample_map.entry(key.clone()).or_insert(LocalLogSample {
                        id: format!("audit-sample-{cat}-{fname}"),
                        category: cat.to_string(),
                        time: if last_ts.is_empty() {
                            "近期".into()
                        } else {
                            last_ts.clone()
                        },
                        file_ref: format!("{fname}:{line_no}"),
                        raw_sanitized: sanitized,
                        count: 0,
                    });
                    entry.count += 1;
                    if !last_ts.is_empty() {
                        entry.time = last_ts.clone();
                    }
                    entry.file_ref = format!("{fname}:{line_no}");
                };

                if lower.contains("account_banned")
                    || (lower.contains("permission_error")
                        && (lower.contains("len=130") || lower.contains("len=123")))
                {
                    summary.account_banned_hits += 1;
                    push_sample("account_banned", trimmed);
                }
                if lower.contains("portal.anthropic.com/verify")
                    || lower.contains("withpersona.com")
                {
                    summary.portal_verify_hits += 1;
                    push_sample("portal_verify", trimmed);
                }
                if lower.contains("orgid") && lower.contains("404") {
                    summary.cross_org_404_hits += 1;
                    push_sample("cross_org_404", trimmed);
                }
                if ((lower.contains("authorize returned 403") || lower.contains("oauth failed"))
                    && lower.contains("permission_error"))
                    || (lower.contains("permission_error")
                        && (lower.contains("len=164") || lower.contains("len=156")))
                {
                    summary.oauth_403_hits += 1;
                    push_sample("oauth_403", trimmed);
                }
                if (lower.contains("403")
                    && lower.contains("credential: cookie")
                    && lower.contains("withheld"))
                    || lower.contains("credentialed upload refused")
                {
                    summary.cookie_403_hits += 1;
                    push_sample("cookie_403", trimmed);
                }
                if lower.contains("navigation to https://claude.ai/ failed with status code 403") {
                    summary.cf_shield_403_hits += 1;
                    push_sample("cf_403", trimmed);
                }
                if re_429.is_match(&lower) || lower.contains("rate_limit_error") {
                    summary.rate_limit_429_hits += 1;
                    push_sample("rate_429", trimmed);
                }
                if lower.contains("plan_changed") {
                    summary.plan_changed_hits += 1;
                }
                if lower.contains("5-hour limit") || lower.contains("hit your 5-hour") {
                    summary.five_hour_soft_lock_hits += 1;
                }
                if lower.contains("err_connection_closed")
                    || lower.contains("err_connection_reset")
                    || lower.contains("socket closed: 1006")
                {
                    summary.disconnect_hits += 1;
                    push_sample("disconnect", trimmed);
                }
                if let Some(caps) = re_side.captures(&lower) {
                    if let Some(n) = caps.get(1).and_then(|m| m.as_str().parse::<u32>().ok()) {
                        if n > summary.max_side_sessions_seen {
                            summary.max_side_sessions_seen = n;
                        }
                        if n >= 3 {
                            summary.high_side_session_hits += 1;
                        }
                    }
                }
                if is_mcp_log && (lower.contains("[error]") || lower.contains("error:")) {
                    summary.mcp_error_hits += 1;
                }
            }
        }
    }

    summary.mcp_error_storm = summary.mcp_error_hits >= MCP_STORM_THRESHOLD;
    if summary.mcp_error_storm {
        sample_map.insert(
            "mcp_storm".into(),
            LocalLogSample {
                id: "audit-sample-mcp-storm".into(),
                category: "mcp_storm".into(),
                time: "近期".into(),
                file_ref: "mcp.log".into(),
                raw_sanitized: format!(
                    "mcp.log 捕获 {} 条高频循环错误（>= {} 条阈值），建议检查异常 MCP 插件进程",
                    summary.mcp_error_hits, MCP_STORM_THRESHOLD
                ),
                count: summary.mcp_error_hits,
            },
        );
    }

    summary.org_id_prefixes = org_set.into_iter().collect();
    summary.recent_samples = sample_map.into_values().collect();
    summary
}

/// 执行完整的本地非侵入只读扫描（统一入口，严格使用 `ProfileContext` 路径）
pub fn scan_local_profile(ctx: &ProfileContext) -> LocalAccountAudit {
    let now_ms = now_epoch_ms_i64();
    scan_local_profile_at(ctx, now_ms)
}

/// 可指定时间戳的本地扫描（方便确定性单元测试）
pub fn scan_local_profile_at(ctx: &ProfileContext, now_ms: i64) -> LocalAccountAudit {
    let claude_json = scan_claude_json(ctx.claude_json_path.as_deref(), now_ms);
    let credentials = scan_credentials_meta(ctx.cli_config_dir.as_deref(), now_ms);
    let hygiene = scan_settings_and_hygiene(ctx.cli_config_dir.as_deref(), ctx.scan_system_env);
    let behavior = scan_offline_jsonl_behavior(ctx.cli_config_dir.as_deref(), now_ms);
    let desktop = scan_desktop_logs(&ctx.desktop_data_dirs);

    let cli_org = claude_json.org_uuid_prefix8.as_deref();
    let cross_client_org_mismatch = match cli_org {
        Some(cli) if !desktop.org_id_prefixes.is_empty() => {
            desktop.org_id_prefixes.iter().any(|d| d != cli)
        }
        _ => false,
    };

    let mut all_orgs: BTreeSet<String> = BTreeSet::new();
    if let Some(c) = cli_org {
        all_orgs.insert(c.to_string());
    }
    for d in &desktop.org_id_prefixes {
        all_orgs.insert(d.clone());
    }
    for b in &hygiene.backup_accounts {
        all_orgs.insert(b.org_prefix.clone());
    }

    LocalAccountAudit {
        profile_id: ctx.profile_id.clone(),
        scanned_at_ms: now_ms,
        claude_json,
        credentials,
        hygiene,
        behavior,
        desktop,
        cross_client_org_mismatch,
        all_observed_org_prefixes: all_orgs.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn profile_context_scans_cli_desktop_mismatch_and_4_privacy_keys() {
        let dir = tempdir().unwrap();
        let claude_json = dir.path().join(".claude.json");
        let cli_dir = dir.path().join(".claude");
        let desktop_dir = dir.path().join("ClaudeDesktop");
        fs::create_dir_all(cli_dir.join("backups")).unwrap();
        fs::create_dir_all(cli_dir.join("telemetry")).unwrap();
        fs::create_dir_all(desktop_dir.join("logs")).unwrap();

        fs::write(
            &claude_json,
            r#"{
              "oauthAccount": {
                "emailAddress": "steven.chen88@gmail.com",
                "organizationUuid": "7aacf131-1111-2222-3333-444455556666",
                "organizationType": "claude_pro",
                "billingType": "stripe_subscription",
                "accountCreatedAt": "2026-10-24T00:00:00Z",
                "subscriptionCreatedAt": "2026-10-24T00:00:00Z"
              },
              "machineID": "4cfdc2d2-aaaa-bbbb-cccc-dddddddddddd",
              "userID": "e084f6b6-1111-2222-3333-444455556666",
              "cachedExtraUsageDisabledReason": "org_level_disabled",
              "cachedUsageUtilization": {
                "fetchedAtMs": 1794800000000,
                "utilization": {
                  "five_hour": { "utilization": 22.0 },
                  "seven_day": { "utilization": 72.0 }
                }
              }
            }"#,
        )
        .unwrap();

        // 白名单凭据解析：即使包含敏感 accessToken / refreshToken，结构体也绝不读取
        fs::write(
            cli_dir.join(".credentials.json"),
            r#"{
              "claudeAiOauth": {
                "accessToken": "sk-ant-oat01-SUPER-SECRET-NEVER-READ",
                "refreshToken": "sk-ant-ort01-SUPER-SECRET-NEVER-READ",
                "subscriptionType": "pro",
                "rateLimitTier": "default_claude_pro",
                "scopes": ["user:inference"],
                "expiresAt": 1900000000000
              }
            }"#,
        )
        .unwrap();

        // 仅开启 2/4 降噪开关（复现真实本机 Bug）
        fs::write(
            cli_dir.join("settings.json"),
            r#"{
              "env": {
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "DISABLE_ERROR_REPORTING": "1"
              },
              "permissions": { "allow": ["Bash(git status)"] }
            }"#,
        )
        .unwrap();

        // 桌面端日志出现不同 orgId a4722ea6 + 1 次 CF 盾 + 2 次 OAuth 403
        fs::write(
            desktop_dir.join("logs").join("main.log"),
            "2026-11-25 19:41:18 orgId=a4722ea6-9999-8888-7777-666655554444\n\
             2026-11-25 19:41:19 navigation to https://claude.ai/ failed with status code 403\n\
             2026-11-25 19:41:20 authorize returned 403 permission_error (len=164)\n\
             2026-11-25 19:41:21 authorize returned 403 permission_error (len=156)\n",
        )
        .unwrap();

        let ctx = ProfileContext {
            profile_id: "default".into(),
            cli_config_dir: Some(cli_dir),
            claude_json_path: Some(claude_json),
            desktop_data_dirs: vec![DesktopDataRoot {
                kind: "TestDesktop".into(),
                dir: desktop_dir,
            }],
            expected_geo: None,
            bound_proxy_port: None,
            scan_system_env: false,
        };

        let now_ms = DateTime::parse_from_rfc3339("2026-11-26T00:00:00Z")
            .unwrap()
            .timestamp_millis();
        let report = scan_local_profile_at(&ctx, now_ms);

        assert_eq!(
            report.claude_json.email_masked.as_deref(),
            Some("stev***88@gmail.com")
        );
        assert_eq!(
            report.claude_json.org_uuid_prefix8.as_deref(),
            Some("7aacf131")
        );
        assert_eq!(report.claude_json.plan_label.as_deref(), Some("Pro"));
        assert_eq!(report.claude_json.account_age_days, Some(33));
        assert!(report.cross_client_org_mismatch);
        assert_eq!(report.hygiene.privacy_enabled_count, 2);
        assert_eq!(report.hygiene.privacy_missing_keys.len(), 2);
        assert!(report
            .hygiene
            .privacy_missing_keys
            .contains(&"DISABLE_TELEMETRY".to_string()));
        assert!(report
            .hygiene
            .privacy_missing_keys
            .contains(&"DISABLE_BUG_COMMAND".to_string()));
        assert_eq!(report.desktop.cf_shield_403_hits, 1);
        assert_eq!(report.desktop.oauth_403_hits, 2);

        // 断言序列化结果中绝不泄露明文 Token 或真实邮箱
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("SUPER-SECRET"));
        assert!(!serialized.contains("steven.chen88@gmail.com"));
    }

    #[test]
    fn graceful_degradation_on_missing_and_corrupted_files() {
        let dir = tempdir().unwrap();
        let bad_json = dir.path().join(".claude.json");
        fs::write(&bad_json, "{not-valid-json").unwrap();

        let ctx = ProfileContext {
            profile_id: "broken".into(),
            cli_config_dir: Some(dir.path().join("nonexistent-cli")),
            claude_json_path: Some(bad_json),
            desktop_data_dirs: Vec::new(),
            expected_geo: None,
            bound_proxy_port: None,
            scan_system_env: false,
        };

        let report = scan_local_profile(&ctx);
        assert!(report.claude_json.exists);
        assert!(report.claude_json.parse_error.is_some());
        assert!(!report.cross_client_org_mismatch);
        assert_eq!(report.hygiene.privacy_enabled_count, 0);
    }
}
