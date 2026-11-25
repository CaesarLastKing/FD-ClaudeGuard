use crate::config::AppConfig;
use crate::process::{kill_claude_process_tree, list_claude_processes};
use crate::protocol::{
    DIAG_MANIFEST_MAGIC, DIAG_MANIFEST_MAGIC_HEX, FD_ERR_BACKUP_TX, REDACT_PLACEHOLDER,
};
use crate::state::{GuardSnapshot, PreflightReport};
use crate::watchdog::LogEvent;
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

const MAX_BACKUP_RETENTION: usize = 10;
/// 单个未知二进制文件保护阈值（50 MiB）：超过此体积且非明确日志/缓存时自动跳过保护，杜绝打包卡死或误删 VM 镜像
const PROTECTED_LARGE_FILE_BYTES: u64 = 50 * 1024 * 1024;
/// 超过 4 MiB 的备份条目改用 Stored 极速直写，避免纯 Rust 单线程 Deflate 卡顿
const ZIP_STORED_THRESHOLD_BYTES: u64 = 4 * 1024 * 1024;

/// 清理分类 ID（前后端严格对齐）
pub const CLEAN_CAT_AUTH: &str = "auth";
pub const CLEAN_CAT_LOGS: &str = "logs";
pub const CLEAN_CAT_TELEMETRY: &str = "telemetry";
pub const CLEAN_CAT_CACHE: &str = "cache";
pub const CLEAN_CAT_MCP_SESSIONS: &str = "mcp_sessions";
pub const CLEAN_CAT_CLI_AUTH: &str = "cli_auth_and_backups";

pub const DEFAULT_CLEAN_CATEGORIES: &[&str] = &[
    CLEAN_CAT_AUTH,
    CLEAN_CAT_LOGS,
    CLEAN_CAT_TELEMETRY,
    CLEAN_CAT_CACHE,
];

/// 清理前透明预览弹窗的单条分类明细
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupCategoryPreview {
    pub id: String,
    pub title: String,
    pub description: String,
    pub default_selected: bool,
    pub will_backup: bool,
    pub file_count: usize,
    pub total_bytes: u64,
    pub size_label: String,
    pub sample_paths: Vec<String>,
}

/// 始终锁定保护不打包不删除项汇总
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProtectedSummary {
    pub file_count: usize,
    pub total_bytes: u64,
    pub size_label: String,
    pub reasons: Vec<String>,
}

/// 清理前透明清单完整预览结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CleanupPlanPreview {
    pub detected_install_modes: Vec<String>,
    pub active_claude_procs: u32,
    pub categories: Vec<CleanupCategoryPreview>,
    pub protected: ProtectedSummary,
    pub scanned_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfo {
    pub file_name: String,
    pub full_path: String,
    pub kind: String, // "clean" | "pre-restore" | "manual" | "legacy"
    pub created_at: String,
    pub created_ts: i64,
    pub size_bytes: u64,
    pub size_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticBundleResult {
    pub zip_path: String,
    pub prompt_markdown: String,
    pub manifest_magic: u32,
}

/// 严格正则脱敏引擎（100% 遵循 docs/protocol-constants.md 统一占位符 `<REDACTED:2W>`）
/// 涵盖：邮箱、Bearer/OAuth/API/JWT Token、SessionKey/cf_clearance、完整公网 IPv4 & IPv6、Windows 用户名路径（含 JSON 双反斜杠）、订阅链接凭证
pub fn sanitize_sensitive_text(input: &str) -> String {
    static RE_EMAIL: OnceLock<Regex> = OnceLock::new();
    static RE_BEARER: OnceLock<Regex> = OnceLock::new();
    static RE_JWT: OnceLock<Regex> = OnceLock::new();
    static RE_SK_ANT: OnceLock<Regex> = OnceLock::new();
    static RE_SK_GENERIC: OnceLock<Regex> = OnceLock::new();
    static RE_KV_SECRET: OnceLock<Regex> = OnceLock::new();
    static RE_USER_PATH: OnceLock<Regex> = OnceLock::new();
    static RE_IPV6: OnceLock<Regex> = OnceLock::new();
    static RE_IPV4: OnceLock<Regex> = OnceLock::new();
    static RE_URL_TOKEN: OnceLock<Regex> = OnceLock::new();
    static RE_SUB_PATH: OnceLock<Regex> = OnceLock::new();

    let re_email = RE_EMAIL.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap()
    });
    let re_bearer = RE_BEARER
        .get_or_init(|| Regex::new(r"(?i)Bearer\s+[A-Za-z0-9._~+/=-]{8,}").unwrap());
    let re_jwt = RE_JWT.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b").unwrap()
    });
    let re_sk_ant =
        RE_SK_ANT.get_or_init(|| Regex::new(r"sk-ant-[A-Za-z0-9_-]{8,}").unwrap());
    let re_sk_generic =
        RE_SK_GENERIC.get_or_init(|| Regex::new(r"\bsk-[A-Za-z0-9_-]{16,}\b").unwrap());
    let re_kv = RE_KV_SECRET.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(sessionKey|oauth_token|access_token|refresh_token|cookie|cf_clearance|x-api-key|anthropic-api-key)(?:\\)?["']?\s*([:=])\s*(?:\\)?["']?([^\s"',;}{\\]+)(?:\\)?["']?"#,
        )
        .unwrap()
    });
    // 同时覆盖普通路径 C:\Users\name、正斜杠 C:/Users/name 及 JSON 转义双反斜杠 C:\\Users\\name
    let re_user_path = RE_USER_PATH
        .get_or_init(|| Regex::new(r"(?i)([A-Z]:[/\\]+Users[/\\]+)([^/\\\s\x22'\x7d]+)").unwrap());
    let re_ipv6 = RE_IPV6.get_or_init(|| {
        Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b").unwrap()
    });
    let re_ipv4 = RE_IPV4.get_or_init(|| {
        Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").unwrap()
    });
    // T-303：脱敏机场订阅 URL 或查询参数中的 token / key / secret / auth
    let re_url_token = RE_URL_TOKEN.get_or_init(|| {
        Regex::new(r"(?i)([?&](?:token|key|secret|auth|password|pass|pwd)=)([^&\s\x22'\x7d]+)").unwrap()
    });
    // 路径型订阅链接（如 /subscribe/<token>、/link/<token>）
    let re_sub_path = RE_SUB_PATH.get_or_init(|| {
        Regex::new(r"(?i)(/(?:api/v1/client/)?(?:subscribe|sub|link)/)([A-Za-z0-9._~-]{8,})").unwrap()
    });

    let mut out = re_email.replace_all(input, REDACT_PLACEHOLDER).to_string();
    out = re_bearer
        .replace_all(&out, format!("Bearer {REDACT_PLACEHOLDER}"))
        .to_string();
    out = re_jwt.replace_all(&out, REDACT_PLACEHOLDER).to_string();
    out = re_sk_ant.replace_all(&out, REDACT_PLACEHOLDER).to_string();
    out = re_sk_generic
        .replace_all(&out, REDACT_PLACEHOLDER)
        .to_string();
    out = re_kv
        .replace_all(&out, |caps: &Captures| {
            format!("{}{}{REDACT_PLACEHOLDER}", &caps[1], &caps[2])
        })
        .to_string();
    out = re_user_path
        .replace_all(&out, |caps: &Captures| {
            format!("{}{REDACT_PLACEHOLDER}", &caps[1])
        })
        .to_string();
    out = re_ipv6
        .replace_all(&out, |caps: &Captures| {
            let s = &caps[0];
            // 排除 HH:MM:SS 时间戳格式
            if s.len() == 8 && s.as_bytes()[2] == b':' && s.as_bytes()[5] == b':' {
                s.to_string()
            } else if s == "::1" || s == "::" {
                s.to_string()
            } else {
                REDACT_PLACEHOLDER.to_string()
            }
        })
        .to_string();
    out = re_ipv4
        .replace_all(&out, |caps: &Captures| {
            let a = &caps[1];
            let b = &caps[2];
            // 保留本地回环、Fake-IP (198.18/19) 与内网地址便于排障，公网 IP 统一打码
            if a == "127"
                || (a == "198" && (b == "18" || b == "19"))
                || a == "10"
                || (a == "192" && b == "168")
            {
                caps[0].to_string()
            } else {
                REDACT_PLACEHOLDER.to_string()
            }
        })
        .to_string();

    out = re_url_token
        .replace_all(&out, |caps: &Captures| {
            format!("{}{REDACT_PLACEHOLDER}", &caps[1])
        })
        .to_string();
    out = re_sub_path
        .replace_all(&out, |caps: &Captures| {
            format!("{}{REDACT_PLACEHOLDER}", &caps[1])
        })
        .to_string();
    out
}

/// T-302/T-303：面向云端遥测与匿名排障上报的强脱敏函数（在通用脱敏基础上额外剥离完整 UUID / orgId）
pub fn sanitize_for_telemetry(input: &str) -> String {
    static RE_UUID: OnceLock<Regex> = OnceLock::new();
    let re_uuid = RE_UUID.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap()
    });
    let base = sanitize_sensitive_text(input);
    re_uuid.replace_all(&base, REDACT_PLACEHOLDER).to_string()
}

/// 递归强脱敏任意 JSON 值中的所有字符串字段（所有出站遥测 Payload 统一经过此兜底）
pub fn sanitize_json_value_for_telemetry(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) => serde_json::Value::String(sanitize_for_telemetry(&s)),
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.into_iter()
                .map(sanitize_json_value_for_telemetry)
                .collect(),
        ),
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, val)| (k, sanitize_json_value_for_telemetry(val)))
                .collect(),
        ),
        other => other,
    }
}

pub fn backups_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("FDtools-Backups")
}

fn infer_backup_kind(file_name: &str) -> String {
    if file_name.contains("-pre-restore-") {
        "pre-restore".into()
    } else if file_name.contains("-clean-") {
        "clean".into()
    } else if file_name.contains("-manual-") {
        "manual".into()
    } else {
        "legacy".into()
    }
}

pub fn list_backups_in(dir: &Path) -> Vec<BackupInfo> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut list = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("zip") {
            continue;
        }
        let Ok(meta) = fs::metadata(&path) else {
            continue;
        };
        let file_name = entry.file_name().to_string_lossy().to_string();
        let size_bytes = meta.len();
        let (created_at, created_ts) = meta
            .modified()
            .ok()
            .map(|t| {
                let dt: chrono::DateTime<chrono::Local> = t.into();
                (dt.format("%Y-%m-%d %H:%M:%S").to_string(), dt.timestamp_millis())
            })
            .unwrap_or_else(|| ("-".into(), 0));
        list.push(BackupInfo {
            kind: infer_backup_kind(&file_name),
            file_name,
            full_path: path.to_string_lossy().to_string(),
            created_at,
            created_ts,
            size_bytes,
            size_label: format_size(size_bytes),
        });
    }
    // 严格按实际创建/修改时间戳降序排列（同毫秒按文件名兜底）
    list.sort_by(|a, b| b.created_ts.cmp(&a.created_ts).then_with(|| b.file_name.cmp(&a.file_name)));
    list
}

/// 删除单份历史备份快照（严格校验文件名防路径穿越）
pub fn delete_backup_file_in(dir: &Path, file_name: &str) -> Result<String, String> {
    if file_name.is_empty()
        || file_name.contains("..")
        || file_name.contains('/')
        || file_name.contains('\\')
        || !file_name.ends_with(".zip")
    {
        return Err(format!("[{FD_ERR_BACKUP_TX}] 非法的备份文件名: {file_name}"));
    }
    let path = dir.join(file_name);
    if !path.exists() {
        return Err(format!("[{FD_ERR_BACKUP_TX}] 备份文件不存在: {file_name}"));
    }
    fs::remove_file(&path).map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 删除备份文件失败: {e}"))?;
    crate::logger::log_event(
        "INFO",
        "maintenance",
        "backup_deleted",
        None,
        format!("已删除单份历史备份: {file_name}"),
        None,
    );
    Ok(format!("已删除备份快照 {file_name}"))
}

/// 清空全部历史备份快照
pub fn clear_all_backups_in(dir: &Path) -> Result<usize, String> {
    let list = list_backups_in(dir);
    let mut removed = 0usize;
    for item in list {
        if fs::remove_file(&item.full_path).is_ok() {
            removed += 1;
        }
    }
    crate::logger::log_event(
        "INFO",
        "maintenance",
        "backups_cleared_all",
        None,
        format!("已清空全部历史备份快照，共删除 {removed} 份"),
        Some(serde_json::json!({ "removedCount": removed })),
    );
    Ok(removed)
}

fn prune_old_backups(dir: &Path, keep: usize) {
    let list = list_backups_in(dir);
    if list.len() <= keep {
        return;
    }
    for old in list.iter().skip(keep) {
        let _ = fs::remove_file(&old.full_path);
    }
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

/// 单个文件在清理/备份体系中的精确分类结果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileDisposition {
    /// 纳入指定可勾选分类（第二个布尔值表示是否写入备份 ZIP）
    Category(&'static str, bool),
    /// 强制锁定保护：绝不打包、绝不删除
    Protected(&'static str),
}

/// 单个待处理文件条目
#[derive(Debug, Clone)]
struct ScannedEntry {
    abs_path: PathBuf,
    zip_name: String,
    display_hint: String,
    size_bytes: u64,
    disposition: FileDisposition,
}

/// 判断目录名是否为受保护的虚拟机镜像目录或程序本体目录
fn is_protected_dir_name(name_lower: &str, is_classic_local: bool) -> Option<&'static str> {
    if matches!(
        name_lower,
        "vm_bundles" | "claude-code-vm" | "vm" | "vms" | "virtualmachines"
    ) {
        return Some("Cowork / Claude Code 虚拟机镜像目录");
    }
    if is_classic_local
        && (name_lower.starts_with("app-")
            || matches!(name_lower, "packages" | "resources" | "locales" | "swiftshader"))
    {
        return Some("经典安装版 Claude 程序本体目录");
    }
    None
}

/// 判断目录名是否为可再生浏览器内核大缓存（仅清理不入 ZIP，彻底根治大目录压缩卡死）
fn is_regenerable_cache_dir(name_lower: &str) -> bool {
    matches!(
        name_lower,
        "cache"
            | "cache_data"
            | "code cache"
            | "gpucache"
            | "dawngraphitecache"
            | "dawnwebgpucache"
            | "grshadercache"
            | "shadercache"
            | "service worker"
            | "blob_storage"
            | "webstorage"
            | "shared_proto_db"
            | "dictionaries"
            | "hyphen-data"
    )
}

/// 判断目录名是否为个人 MCP 配置或本地工作会话（默认保留防错删）
fn is_mcp_or_session_dir(name_lower: &str) -> bool {
    matches!(
        name_lower,
        "local-agent-mode-sessions"
            | "claude-code-sessions"
            | "claude_code_sessions"
            | "extensions"
            | "mcp"
            | "skills"
            | "plugins"
    )
}

/// 对单个普通文件按所在根目录类型与相对路径做精准分类
fn classify_claude_file(
    rel_slash: &str,
    size_bytes: u64,
    is_telemetry_root: bool,
    is_classic_local: bool,
    is_claude_data_root: bool,
) -> FileDisposition {
    if is_telemetry_root {
        return FileDisposition::Category(CLEAN_CAT_TELEMETRY, true);
    }

    let lower = rel_slash.to_ascii_lowercase();
    let segments: Vec<&str> = lower.split('/').collect();
    let file_name = segments.last().copied().unwrap_or("");

    // 1. 强保护：VM 磁盘镜像扩展名 & 经典版程序二进制本体
    if file_name.ends_with(".vhdx")
        || file_name.ends_with(".vhd")
        || file_name.ends_with(".vmdk")
        || file_name.ends_with(".iso")
        || file_name.ends_with(".qcow2")
        || (file_name.ends_with(".img") && size_bytes > 10 * 1024 * 1024)
    {
        return FileDisposition::Protected("虚拟机磁盘镜像文件");
    }
    if is_classic_local
        && (file_name == "update.exe"
            || file_name.ends_with(".exe")
            || file_name.ends_with(".dll")
            || file_name.ends_with(".pak")
            || file_name.ends_with(".nupkg")
            || file_name.starts_with("squirrel"))
    {
        return FileDisposition::Protected("经典安装版 Claude 程序本体文件");
    }

    // 2. 目录路径分类（逐段检测）
    for seg in &segments[..segments.len().saturating_sub(1)] {
        if let Some(reason) = is_protected_dir_name(seg, is_classic_local) {
            return FileDisposition::Protected(reason);
        }
        if is_mcp_or_session_dir(seg) {
            return FileDisposition::Category(CLEAN_CAT_MCP_SESSIONS, true);
        }
        if is_regenerable_cache_dir(seg) {
            return FileDisposition::Category(CLEAN_CAT_CACHE, false);
        }
        if matches!(*seg, "crashpad" | "sentry" | "telemetry") {
            return FileDisposition::Category(CLEAN_CAT_TELEMETRY, true);
        }
        if *seg == "logs" {
            return FileDisposition::Category(CLEAN_CAT_LOGS, true);
        }
    }

    // 3. 精确文件名分类
    if file_name == "claude_desktop_config.json" || file_name == "mcp.json" {
        return FileDisposition::Category(CLEAN_CAT_MCP_SESSIONS, true);
    }
    if file_name.ends_with(".log") {
        return FileDisposition::Category(CLEAN_CAT_LOGS, true);
    }
    if matches!(
        file_name,
        "visited links" | "videodecodestats" | "network persistent state" | "transportsecurity"
    ) {
        return FileDisposition::Category(CLEAN_CAT_CACHE, false);
    }

    // 4. Local\Claude-Data 根下的顶层 config.json 为 MSIX OAuth 凭证缓存，归入登录态
    if is_claude_data_root && file_name == "config.json" {
        return FileDisposition::Category(CLEAN_CAT_AUTH, true);
    }

    // 5. 未知超大单文件（> 50 MiB）自动保护，杜绝未知大镜像卡死打包或误删
    if size_bytes >= PROTECTED_LARGE_FILE_BYTES {
        return FileDisposition::Protected("超过 50 MB 的未知大文件");
    }

    // 6. 其余登录态、Cookie、Local Storage、Session Storage、Preferences、state.json 等统一归登录凭证
    FileDisposition::Category(CLEAN_CAT_AUTH, true)
}

/// 递归扫描单个根目录（严格使用 symlink_metadata，严禁跟随符号链接 / NTFS Junction）
fn scan_root_dir(
    src_dir: &Path,
    zip_prefix: &str,
    display_prefix: &str,
    is_telemetry_root: bool,
    is_classic_local: bool,
    is_claude_data_root: bool,
    entries_out: &mut Vec<ScannedEntry>,
    protected_reasons: &mut std::collections::BTreeSet<String>,
) {
    let Ok(root_meta) = fs::symlink_metadata(src_dir) else {
        return;
    };
    if root_meta.file_type().is_symlink() {
        protected_reasons.insert("符号链接 / NTFS Junction 外部目标".to_string());
        return;
    }
    if !root_meta.is_dir() {
        return;
    }

    let mut stack = vec![src_dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(rd) = fs::read_dir(&current) else {
            continue;
        };
        for entry in rd.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            // 严禁跟随软链接/Junction，避免死循环或误删外部目录
            if meta.file_type().is_symlink() {
                protected_reasons.insert("符号链接 / NTFS Junction 外部目标".to_string());
                continue;
            }
            if meta.is_dir() {
                let dir_name_lower = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if let Some(reason) = is_protected_dir_name(&dir_name_lower, is_classic_local) {
                    // 仅轻量估算一层/目录体积展示，绝不进入清理队列
                    let (p_cnt, p_bytes) = estimate_protected_dir_stats(&path);
                    protected_reasons.insert(reason.to_string());
                    entries_out.push(ScannedEntry {
                        abs_path: path,
                        zip_name: String::new(),
                        display_hint: format!("{display_prefix}\\{}", entry.file_name().to_string_lossy()),
                        size_bytes: p_bytes,
                        disposition: FileDisposition::Protected(reason),
                    });
                    // 仅用一条汇总记录避免遍历成千上万受保护文件拖慢扫描
                    let _ = p_cnt;
                    continue;
                }
                stack.push(path);
            } else if meta.is_file() {
                let rel = path
                    .strip_prefix(src_dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let size_bytes = meta.len();
                let disposition = classify_claude_file(
                    &rel,
                    size_bytes,
                    is_telemetry_root,
                    is_classic_local,
                    is_claude_data_root,
                );
                if let FileDisposition::Protected(reason) = disposition {
                    protected_reasons.insert(reason.to_string());
                }
                entries_out.push(ScannedEntry {
                    abs_path: path,
                    zip_name: format!("{zip_prefix}/{rel}"),
                    display_hint: format!("{display_prefix}\\{}", rel.replace('/', "\\")),
                    size_bytes,
                    disposition,
                });
            }
        }
    }
}

/// 快速统计受保护目录（如 vm_bundles）的文件数与总大小，带节点上限防止极端目录拖慢预览
fn estimate_protected_dir_stats(dir: &Path) -> (usize, u64) {
    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    let mut visited = 0usize;
    while let Some(cur) = stack.pop() {
        let Ok(rd) = fs::read_dir(&cur) else {
            continue;
        };
        for entry in rd.flatten() {
            visited += 1;
            if visited > 2000 {
                return (files.max(1), bytes);
            }
            let p = entry.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                stack.push(p);
            } else if meta.is_file() {
                files += 1;
                bytes = bytes.saturating_add(meta.len());
            }
        }
    }
    (files.max(1), bytes)
}

/// 流式将单个文件写入 ZIP（严禁 read_to_end 整文件吃内存；大条目走 Stored + ZIP64 防卡顿）
fn write_file_stream_to_zip(
    zip: &mut ZipWriter<File>,
    src_path: &Path,
    zip_name: &str,
    size_bytes: u64,
) -> Result<bool, String> {
    let Ok(mut f) = File::open(src_path) else {
        return Ok(false);
    };
    let method = if size_bytes >= ZIP_STORED_THRESHOLD_BYTES {
        CompressionMethod::Stored
    } else {
        CompressionMethod::Deflated
    };
    let options = SimpleFileOptions::default()
        .compression_method(method)
        .large_file(true);
    zip.start_file(zip_name, options)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 写入 ZIP 条目失败: {e}"))?;
    std::io::copy(&mut f, zip)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 流式写入 ZIP 数据失败: {e}"))?;
    Ok(true)
}

/// 清理已变空的子目录（绝不删除根目录自身，绝不跟随软链）
fn prune_empty_subdirs(root: &Path) {
    let Ok(meta) = fs::symlink_metadata(root) else {
        return;
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return;
    }
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        let Ok(m) = fs::symlink_metadata(&p) else {
            continue;
        };
        if m.file_type().is_symlink() || !m.is_dir() {
            continue;
        }
        prune_empty_subdirs(&p);
        let _ = fs::remove_dir(&p);
    }
}

/// 微软商店版（MSIX）单个包目录下的 LocalCache Roaming/Local 路径映射
#[derive(Debug, Clone)]
pub struct MsixClaudeRoot {
    pub package_dir_name: String,
    pub roaming: PathBuf,
    pub local: PathBuf,
}

/// 微软商店版（MSIX）额外存放 OAuth config.json 与 local-agent-mode-sessions 的 Local\Claude-Data 目录
#[derive(Debug, Clone)]
pub struct ClaudeDataExtraRoot {
    pub package_dir_name: String,
    pub dir: PathBuf,
}

/// 本机全部 Claude 数据目录根集合（经典安装版 + 微软商店 MSIX + Local\Claude-Data + CLI 遥测 + CLI 登录态与备份）
#[derive(Debug, Clone, Default)]
pub struct ClaudeDataRoots {
    pub classic_roaming: Option<PathBuf>,
    pub classic_local: Option<PathBuf>,
    pub telemetry: Option<PathBuf>,
    pub cli_claude_json: Option<PathBuf>,
    pub cli_credentials: Option<PathBuf>,
    pub cli_backups_dir: Option<PathBuf>,
    pub msix_roots: Vec<MsixClaudeRoot>,
    pub msix_claude_data: Vec<ClaudeDataExtraRoot>,
    pub classic_install_detected: bool,
}

/// 前端环境维护页只读展示的本机 Claude 目录覆盖摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeDataRootsSummary {
    pub classic_detected: bool,
    pub msix_packages: Vec<String>,
    pub telemetry_exists: bool,
}

/// 探测本机实际存在的 Claude 目录类型（经典 Electron / 微软商店 MSIX / 离线遥测）
pub fn inspect_claude_data_roots_summary() -> ClaudeDataRootsSummary {
    let roots = discover_claude_data_roots();
    let classic_detected = roots.classic_install_detected
        || roots
            .classic_roaming
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false)
        || roots
            .classic_local
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false);
    let mut pkg_set: std::collections::BTreeSet<String> = roots
        .msix_roots
        .into_iter()
        .map(|m| m.package_dir_name)
        .collect();
    for extra in roots.msix_claude_data {
        pkg_set.insert(extra.package_dir_name);
    }
    let msix_packages = pkg_set.into_iter().collect();
    let telemetry_exists = roots
        .telemetry
        .as_ref()
        .map(|p| p.exists())
        .unwrap_or(false);
    ClaudeDataRootsSummary {
        classic_detected,
        msix_packages,
        telemetry_exists,
    }
}

/// 统一发现本机全部 Claude 污染/配置数据目录（兼容传统安装版、微软商店 MSIX LocalCache 与 Local\Claude-Data，绝不碰 WindowsApps 与经典版程序本体）
pub fn discover_claude_data_roots() -> ClaudeDataRoots {
    discover_claude_data_roots_from(
        dirs::config_dir().as_deref(),
        dirs::data_local_dir().as_deref(),
        dirs::home_dir().as_deref(),
    )
}

pub fn discover_claude_data_roots_from(
    config_dir: Option<&Path>,
    data_local_dir: Option<&Path>,
    home_dir: Option<&Path>,
) -> ClaudeDataRoots {
    let classic_roaming = config_dir.map(|d| d.join("Claude"));
    let classic_local = data_local_dir.map(|d| d.join("Claude"));
    let telemetry = home_dir.map(|h| h.join(".claude").join("telemetry"));
    let cli_claude_json = home_dir.map(|h| h.join(".claude.json"));
    let cli_credentials = home_dir.map(|h| h.join(".claude").join(".credentials.json"));
    let cli_backups_dir = home_dir.map(|h| h.join(".claude").join("backups"));
    let mut msix_roots = Vec::new();
    let mut msix_claude_data = Vec::new();
    let mut classic_install_detected = false;

    if let Some(local_base) = data_local_dir {
        if local_base.join("AnthropicClaude").join("Claude.exe").exists()
            || local_base.join("Claude").join("Update.exe").exists()
        {
            classic_install_detected = true;
        }
        let packages = local_base.join("Packages");
        if let Ok(entries) = fs::read_dir(packages) {
            for e in entries.flatten() {
                let pkg_name = e.file_name().to_string_lossy().to_string();
                let lower = pkg_name.to_lowercase();
                if lower.contains("claude") || lower.contains("anthropic") {
                    let roaming = e
                        .path()
                        .join("LocalCache")
                        .join("Roaming")
                        .join("Claude");
                    let local = e
                        .path()
                        .join("LocalCache")
                        .join("Local")
                        .join("Claude");
                    if roaming.exists() || local.exists() {
                        msix_roots.push(MsixClaudeRoot {
                            package_dir_name: pkg_name,
                            roaming,
                            local,
                        });
                    }
                }
            }
        }
        let claude_data_dir = local_base.join("Claude-Data");
        if let Ok(entries) = fs::read_dir(&claude_data_dir) {
            for e in entries.flatten() {
                let pkg_name = e.file_name().to_string_lossy().to_string();
                let lower = pkg_name.to_lowercase();
                if lower.contains("claude") || lower.contains("anthropic") {
                    let p = e.path();
                    if p.is_dir() {
                        msix_claude_data.push(ClaudeDataExtraRoot {
                            package_dir_name: pkg_name,
                            dir: p,
                        });
                    }
                }
            }
        }
    }
    msix_roots.sort_by(|a, b| a.package_dir_name.cmp(&b.package_dir_name));
    msix_claude_data.sort_by(|a, b| a.package_dir_name.cmp(&b.package_dir_name));

    ClaudeDataRoots {
        classic_roaming,
        classic_local,
        telemetry,
        cli_claude_json,
        cli_credentials,
        cli_backups_dir,
        msix_roots,
        msix_claude_data,
        classic_install_detected,
    }
}

/// 扫描全部根目录并返回所有已分类条目与保护原因集合
fn scan_all_claude_roots(
    roots: &ClaudeDataRoots,
) -> (Vec<ScannedEntry>, std::collections::BTreeSet<String>) {
    let mut entries = Vec::new();
    let mut protected_reasons = std::collections::BTreeSet::new();

    if let Some(p) = roots.classic_roaming.as_deref() {
        scan_root_dir(
            p,
            "roaming",
            "%APPDATA%\\Claude",
            false,
            false,
            false,
            &mut entries,
            &mut protected_reasons,
        );
    }
    if let Some(p) = roots.classic_local.as_deref() {
        scan_root_dir(
            p,
            "local",
            "%LOCALAPPDATA%\\Claude",
            false,
            true,
            false,
            &mut entries,
            &mut protected_reasons,
        );
    }
    if let Some(p) = roots.telemetry.as_deref() {
        scan_root_dir(
            p,
            "telemetry",
            "~\\.claude\\telemetry",
            true,
            false,
            false,
            &mut entries,
            &mut protected_reasons,
        );
    }
    // 扫描可选 CLI 登录态与历史旧号备份（cli_auth_and_backups，清理前强制 ZIP 原子备份）
    if let Some(p) = roots.cli_claude_json.as_deref() {
        if let Ok(meta) = fs::symlink_metadata(p) {
            if !meta.file_type().is_symlink() && meta.is_file() {
                entries.push(ScannedEntry {
                    abs_path: p.to_path_buf(),
                    zip_name: "cli/.claude.json".to_string(),
                    display_hint: "~\\.claude.json (仅清除 oauthAccount)".to_string(),
                    size_bytes: meta.len(),
                    disposition: FileDisposition::Category(CLEAN_CAT_CLI_AUTH, true),
                });
            }
        }
    }
    if let Some(p) = roots.cli_credentials.as_deref() {
        if let Ok(meta) = fs::symlink_metadata(p) {
            if !meta.file_type().is_symlink() && meta.is_file() {
                entries.push(ScannedEntry {
                    abs_path: p.to_path_buf(),
                    zip_name: "cli/.claude/.credentials.json".to_string(),
                    display_hint: "~\\.claude\\.credentials.json".to_string(),
                    size_bytes: meta.len(),
                    disposition: FileDisposition::Category(CLEAN_CAT_CLI_AUTH, true),
                });
            }
        }
    }
    if let Some(backups_dir) = roots.cli_backups_dir.as_deref() {
        if let Ok(rd) = fs::read_dir(backups_dir) {
            for ent in rd.flatten() {
                let p = ent.path();
                let Ok(meta) = fs::symlink_metadata(&p) else {
                    continue;
                };
                if meta.file_type().is_symlink() || !meta.is_file() {
                    continue;
                }
                let fname = ent.file_name().to_string_lossy().to_string();
                entries.push(ScannedEntry {
                    abs_path: p,
                    zip_name: format!("cli/.claude/backups/{fname}"),
                    display_hint: format!("~\\.claude\\backups\\{fname}"),
                    size_bytes: meta.len(),
                    disposition: FileDisposition::Category(CLEAN_CAT_CLI_AUTH, true),
                });
            }
        }
    }
    for m in &roots.msix_roots {
        if m.roaming.exists() {
            scan_root_dir(
                &m.roaming,
                &format!("msix/{}/roaming", m.package_dir_name),
                &format!("MSIX\\{}\\Roaming\\Claude", m.package_dir_name),
                false,
                false,
                false,
                &mut entries,
                &mut protected_reasons,
            );
        }
        if m.local.exists() {
            scan_root_dir(
                &m.local,
                &format!("msix/{}/local", m.package_dir_name),
                &format!("MSIX\\{}\\Local\\Claude", m.package_dir_name),
                false,
                false,
                false,
                &mut entries,
                &mut protected_reasons,
            );
        }
    }
    for extra in &roots.msix_claude_data {
        if extra.dir.exists() {
            scan_root_dir(
                &extra.dir,
                &format!("claude-data/{}", extra.package_dir_name),
                &format!("%LOCALAPPDATA%\\Claude-Data\\{}", extra.package_dir_name),
                false,
                false,
                true,
                &mut entries,
                &mut protected_reasons,
            );
        }
    }

    (entries, protected_reasons)
}

/// 预览清理与备份分项清单（用于清理前透明弹窗展示，纯只读、毫秒级）
pub fn preview_claude_cleanup_plan_with_roots(
    roots: &ClaudeDataRoots,
    active_claude_procs: u32,
) -> CleanupPlanPreview {
    let started = std::time::Instant::now();
    let (entries, protected_reasons) = scan_all_claude_roots(roots);

    let mut detected_install_modes = Vec::new();
    if !roots.msix_roots.is_empty() || !roots.msix_claude_data.is_empty() {
        detected_install_modes.push("微软商店 MSIX 版".to_string());
    }
    if roots.classic_install_detected
        || roots.classic_roaming.as_ref().is_some_and(|p| p.exists())
        || roots.classic_local.as_ref().is_some_and(|p| p.exists())
    {
        detected_install_modes.push("经典安装版 (Roaming/Local)".to_string());
    }
    if roots.telemetry.as_ref().is_some_and(|p| p.exists()) {
        detected_install_modes.push("Claude Code CLI".to_string());
    }
    if detected_install_modes.is_empty() {
        detected_install_modes.push("暂未检测到本地数据目录".to_string());
    }

    let specs: &[(&str, &str, &str, bool, bool)] = &[
        (
            CLEAN_CAT_AUTH,
            "桌面端登录态、Cookie 与 OAuth 凭证",
            "清除后立即退出本地桌面端登录态（Cookies / Local Storage / Session Storage / OAuth config.json）。",
            true,
            true,
        ),
        (
            CLEAN_CAT_LOGS,
            "本地运行日志与风控记录",
            "清除旧的 main.log / window.log，避免历史 403/429 与旧账号 orgId 持续触发单号锁和日志报警。",
            true,
            true,
        ),
        (
            CLEAN_CAT_TELEMETRY,
            "离线遥测与崩溃上报队列",
            "清空断网期间暂存的遥测事件与 Crashpad，防止恢复联网后补传异常日志给 Anthropic。",
            true,
            true,
        ),
        (
            CLEAN_CAT_CACHE,
            "浏览器内核临时缓存（可再生）",
            "Cache / Code Cache / GPUCache / Service Worker 等网页渲染缓存，不打包可避免卡死，重启自动重建。",
            true,
            false,
        ),
        (
            CLEAN_CAT_MCP_SESSIONS,
            "个人 MCP 配置与本地工作会话",
            "包含 claude_desktop_config.json（MCP 服务器配置）及 local-agent-mode-sessions，仅需彻底重置时再勾选。",
            false,
            true,
        ),
        (
            CLEAN_CAT_CLI_AUTH,
            "CLI 登录态与历史旧号备份（~/.claude）",
            "先 ZIP 原子备份后，移除 ~/.claude.json 中的 oauthAccount、.credentials.json 及 ~/.claude/backups/ 旧号快照，保留个人偏好与项目设置。",
            false,
            true,
        ),
    ];

    let mut categories = Vec::with_capacity(specs.len());
    for &(id, title, description, default_selected, will_backup) in specs {
        let mut file_count = 0usize;
        let mut total_bytes = 0u64;
        let mut samples = Vec::new();
        for e in &entries {
            if let FileDisposition::Category(cid, _) = e.disposition {
                if cid == id {
                    file_count += 1;
                    total_bytes = total_bytes.saturating_add(e.size_bytes);
                    if samples.len() < 3 && !samples.contains(&e.display_hint) {
                        samples.push(e.display_hint.clone());
                    }
                }
            }
        }
        categories.push(CleanupCategoryPreview {
            id: id.to_string(),
            title: title.to_string(),
            description: description.to_string(),
            default_selected,
            will_backup,
            file_count,
            total_bytes,
            size_label: format_size(total_bytes),
            sample_paths: samples,
        });
    }

    let mut prot_files = 0usize;
    let mut prot_bytes = 0u64;
    for e in &entries {
        if matches!(e.disposition, FileDisposition::Protected(_)) {
            prot_files += 1;
            prot_bytes = prot_bytes.saturating_add(e.size_bytes);
        }
    }
    let mut reasons: Vec<String> = protected_reasons.into_iter().collect();
    if reasons.is_empty() {
        reasons.push("WindowsApps 程序本体 · 经典版程序文件 · 项目代码与云端对话".to_string());
    }

    CleanupPlanPreview {
        detected_install_modes,
        active_claude_procs,
        categories,
        protected: ProtectedSummary {
            file_count: prot_files,
            total_bytes: prot_bytes,
            size_label: format_size(prot_bytes),
            reasons,
        },
        scanned_ms: started.elapsed().as_millis() as u64,
    }
}

/// 对本机真实目录执行清理前透明清单预扫描
pub fn preview_claude_cleanup_plan() -> CleanupPlanPreview {
    let roots = discover_claude_data_roots();
    let procs = list_claude_processes().len() as u32;
    preview_claude_cleanup_plan_with_roots(&roots, procs)
}

/// 原子创建带唯一时间戳与来源类型（clean / pre-restore / manual）的 ZIP 快照（流式直写、自动跳过大缓存/VM 镜像/软链）
pub fn create_snapshot_zip_with_roots(
    bdir: &Path,
    kind: &str,
    roots: &ClaudeDataRoots,
) -> Result<BackupInfo, String> {
    create_snapshot_zip_for_categories(bdir, kind, roots, None)
}

/// 按可选分类集合原子创建 ZIP 快照（仅打包 `will_backup == true` 且非受保护文件，流式写入零 OOM）
fn create_snapshot_zip_for_categories(
    bdir: &Path,
    kind: &str,
    roots: &ClaudeDataRoots,
    selected_categories: Option<&std::collections::HashSet<String>>,
) -> Result<BackupInfo, String> {
    let started = std::time::Instant::now();
    fs::create_dir_all(bdir)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 创建备份目录失败: {e}"))?;

    let (entries, protected_reasons) = scan_all_claude_roots(roots);
    let scan_ms = started.elapsed().as_millis() as u64;

    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S-%3f");
    let file_name = format!("claude-backup-{kind}-{ts}.zip");
    let final_path = bdir.join(&file_name);
    let tmp_path = bdir.join(format!("{file_name}.tmp"));

    let file = File::create(&tmp_path)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 创建临时备份 ZIP 失败: {e}"))?;
    let mut zip = ZipWriter::new(file);

    let mut total_files = 0usize;
    let mut skipped_cache_files = 0usize;
    let mut skipped_protected_files = 0usize;
    let mut msix_pkgs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for e in &entries {
        match e.disposition {
            FileDisposition::Protected(_) => {
                skipped_protected_files += 1;
            }
            FileDisposition::Category(cid, will_backup) => {
                if let Some(sel) = selected_categories {
                    if !sel.contains(cid) {
                        continue;
                    }
                }
                if !will_backup {
                    skipped_cache_files += 1;
                    continue;
                }
                if write_file_stream_to_zip(&mut zip, &e.abs_path, &e.zip_name, e.size_bytes)? {
                    total_files += 1;
                    if let Some(rest) = e.zip_name.strip_prefix("msix/") {
                        if let Some(pkg) = rest.split('/').next() {
                            msix_pkgs.insert(pkg.to_string());
                        }
                    } else if let Some(rest) = e.zip_name.strip_prefix("claude-data/") {
                        if let Some(pkg) = rest.split('/').next() {
                            msix_pkgs.insert(pkg.to_string());
                        }
                    }
                }
            }
        }
    }

    let manifest = serde_json::json!({
        "magic": DIAG_MANIFEST_MAGIC,
        "magicHex": DIAG_MANIFEST_MAGIC_HEX,
        "kind": kind,
        "createdAt": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "archivedFiles": total_files,
        "skippedCacheFiles": skipped_cache_files,
        "skippedProtectedFiles": skipped_protected_files,
        "protectedReasons": protected_reasons.into_iter().collect::<Vec<_>>(),
        "msixPackages": msix_pkgs.into_iter().collect::<Vec<_>>(),
    });
    let manifest_opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    zip.start_file("backup-manifest.json", manifest_opts)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 写入备份清单失败: {e}"))?;
    zip.write_all(manifest.to_string().as_bytes())
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 写入备份清单内容失败: {e}"))?;
    zip.finish()
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 封存 ZIP 快照失败: {e}"))?;

    fs::rename(&tmp_path, &final_path)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 原子提交备份快照失败: {e}"))?;

    prune_old_backups(bdir, MAX_BACKUP_RETENTION);

    let now_dt = chrono::Local::now();
    let size_bytes = fs::metadata(&final_path).map(|m| m.len()).unwrap_or(0);
    crate::logger::log_event(
        "INFO",
        "maintenance",
        "snapshot_zip_created",
        Some(started.elapsed().as_millis() as u64),
        format!(
            "快照打包完成 kind={kind} file={file_name} archived={total_files} skipped_cache={skipped_cache_files} skipped_protected={skipped_protected_files} size={} (scan={}ms total={}ms)",
            format_size(size_bytes),
            scan_ms,
            started.elapsed().as_millis()
        ),
        None,
    );
    Ok(BackupInfo {
        kind: kind.to_string(),
        file_name,
        full_path: final_path.to_string_lossy().to_string(),
        created_at: now_dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        created_ts: now_dt.timestamp_millis(),
        size_bytes,
        size_label: format_size(size_bytes),
    })
}

/// 原子创建带唯一时间戳与来源类型（clean / pre-restore / manual）的 ZIP 快照（向后兼容旧签名）
pub fn create_snapshot_zip(
    bdir: &Path,
    kind: &str,
    roaming: Option<&Path>,
    local: Option<&Path>,
    telemetry: Option<&Path>,
) -> Result<BackupInfo, String> {
    let roots = ClaudeDataRoots {
        classic_roaming: roaming.map(Path::to_path_buf),
        classic_local: local.map(Path::to_path_buf),
        telemetry: telemetry.map(Path::to_path_buf),
        ..Default::default()
    };
    create_snapshot_zip_with_roots(bdir, kind, &roots)
}

/// 强杀进程并等待完全退出释放文件锁 → 按用户勾选分类原子 ZIP 备份 → 精准清理已勾选项（不碰未勾选项、VM 镜像、程序本体与软链外部目标）
pub fn backup_and_clean_claude_dirs_selected(
    selected_categories: Option<&[String]>,
) -> Result<BackupInfo, String> {
    let started = std::time::Instant::now();
    // 循环强杀并等待直至 Claude 进程树归 0（最长 3 秒），防止 Electron/MSIX 句柄未释放导致 Cookies/logs 删除失败
    for attempt in 0..10 {
        let _ = kill_claude_process_tree(false);
        if crate::process::list_claude_processes().is_empty() {
            break;
        }
        if attempt < 9 {
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
    }
    // 额外等待 200ms 确保 Windows 文件系统句柄彻底释放
    std::thread::sleep(std::time::Duration::from_millis(200));
    let roots = discover_claude_data_roots();
    let info = backup_and_clean_with_roots_selected(&backups_dir(), &roots, selected_categories)?;
    crate::logger::log_event(
        "INFO",
        "maintenance",
        "backup_and_clean_done",
        Some(started.elapsed().as_millis() as u64),
        format!(
            "原子备份与分项清理全部完成: {} ({})，耗时 {}ms",
            info.file_name,
            info.size_label,
            started.elapsed().as_millis()
        ),
        None,
    );
    Ok(info)
}

/// 向后兼容入口：按默认安全分类集合执行备份清理
pub fn backup_and_clean_claude_dirs() -> Result<BackupInfo, String> {
    backup_and_clean_claude_dirs_selected(None)
}

pub fn backup_and_clean_with_roots(bdir: &Path, roots: &ClaudeDataRoots) -> Result<BackupInfo, String> {
    backup_and_clean_with_roots_selected(bdir, roots, None)
}

pub fn backup_and_clean_with_roots_selected(
    bdir: &Path,
    roots: &ClaudeDataRoots,
    selected_categories: Option<&[String]>,
) -> Result<BackupInfo, String> {
    let selected_set: std::collections::HashSet<String> = match selected_categories {
        Some(list) if !list.is_empty() => list.iter().cloned().collect(),
        Some(_) => {
            return Err(format!("[{FD_ERR_BACKUP_TX}] 请至少勾选 1 个清理项目再执行。"));
        }
        None => DEFAULT_CLEAN_CATEGORIES
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    };

    let info = create_snapshot_zip_for_categories(bdir, "clean", roots, Some(&selected_set))?;

    let (entries, _) = scan_all_claude_roots(roots);
    let mut removed_files = 0usize;
    let mut freed_bytes = 0u64;
    for e in entries {
        if let FileDisposition::Category(cid, _) = e.disposition {
            if selected_set.contains(cid) {
                if cid == CLEAN_CAT_CLI_AUTH && e.zip_name == "cli/.claude.json" {
                    // 无损清除 ~/.claude.json 中的 oauthAccount 登录态，保留其余个人偏好设置
                    if strip_oauth_account_from_claude_json(&e.abs_path).is_ok() {
                        removed_files += 1;
                    }
                } else if fs::remove_file(&e.abs_path).is_ok() {
                    removed_files += 1;
                    freed_bytes = freed_bytes.saturating_add(e.size_bytes);
                }
            }
        }
    }

    // 清理变空的子目录（受保护目录与未勾选目录因为内部仍有文件不会被删除）
    for target in [
        roots.classic_roaming.as_deref(),
        roots.classic_local.as_deref(),
        roots.telemetry.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        prune_empty_subdirs(target);
    }
    for m in &roots.msix_roots {
        prune_empty_subdirs(&m.roaming);
        prune_empty_subdirs(&m.local);
    }
    for extra in &roots.msix_claude_data {
        prune_empty_subdirs(&extra.dir);
    }

    crate::logger::log_info(
        "maintenance",
        format!(
            "分项清理完成: selected={:?} removed_files={removed_files} freed={}",
            selected_set.iter().collect::<Vec<_>>(),
            format_size(freed_bytes)
        ),
    );
    Ok(info)
}

/// 无损剥离 `~/.claude.json` 中的 `oauthAccount` 字段（保留用户其余偏好与项目记录）
pub fn strip_oauth_account_from_claude_json(path: &Path) -> Result<bool, String> {
    if !path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("读取 .claude.json 失败: {e}"))?;
    let mut val: serde_json::Value = serde_json::from_str(raw.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("解析 .claude.json 失败: {e}"))?;
    let Some(obj) = val.as_object_mut() else {
        return Ok(false);
    };
    if obj.remove("oauthAccount").is_none() {
        return Ok(false);
    }
    let out =
        serde_json::to_string_pretty(&val).map_err(|e| format!("序列化 .claude.json 失败: {e}"))?;
    fs::write(path, out).map_err(|e| format!("写回 .claude.json 失败: {e}"))?;
    Ok(true)
}

/// 供账户审计页「清理 CLI 凭据与备份」按钮一键调用：先原子 ZIP 备份，再清理 CLI 登录态与旧备份
pub fn clean_claude_cli_credentials_with_backup_in(
    bdir: &Path,
    home_dir: Option<&Path>,
) -> Result<BackupInfo, String> {
    let roots = ClaudeDataRoots {
        cli_claude_json: home_dir.map(|h| h.join(".claude.json")),
        cli_credentials: home_dir.map(|h| h.join(".claude").join(".credentials.json")),
        cli_backups_dir: home_dir.map(|h| h.join(".claude").join("backups")),
        ..Default::default()
    };
    let cats = vec![CLEAN_CAT_CLI_AUTH.to_string()];
    backup_and_clean_with_roots_selected(bdir, &roots, Some(&cats))
}

/// 供账户审计页直接调用的默认路径 CLI 备份清理
pub fn clean_claude_cli_credentials_with_backup() -> Result<BackupInfo, String> {
    clean_claude_cli_credentials_with_backup_in(&backups_dir(), dirs::home_dir().as_deref())
}

/// 手动创建一份当前环境快照（含 MSIX 与 Local\Claude-Data，自动跳过大缓存与 VM 镜像，不清理目录）
pub fn create_manual_backup_snapshot() -> Result<BackupInfo, String> {
    let roots = discover_claude_data_roots();
    create_snapshot_zip_with_roots(&backups_dir(), "manual", &roots)
}

/// 校验 ZIP 完整性并计算总解压体积（流式分块校验防大快照 OOM）
pub fn verify_zip_integrity(zip_path: &Path) -> Result<(usize, u64), String> {
    let file = File::open(zip_path)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 打开备份 ZIP 失败: {e}"))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 备份 ZIP 格式损坏: {e}"))?;
    let mut total_uncompressed = 0u64;
    let mut file_count = 0usize;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 校验 ZIP 条目失败: {e}"))?;
        let name = entry.name().to_string();
        if name.contains("..") {
            return Err(format!("[{FD_ERR_BACKUP_TX}] 检测到非法路径穿越条目: {name}"));
        }
        if !entry.is_dir() {
            let copied = std::io::copy(&mut entry, &mut std::io::sink())
                .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] ZIP 条目 CRC/解压校验失败 ({name}): {e}"))?;
            total_uncompressed = total_uncompressed.saturating_add(copied);
            file_count += 1;
        }
    }

    Ok((file_count, total_uncompressed))
}

#[cfg(windows)]
fn check_free_disk_space(target_dir: &Path, required_bytes: u64) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // 严格提取绝对本地盘符 A..=Z（跳过 UNC 网络路径与相对路径，杜绝拼接非法 PowerShell 表达式）
    let canonical_or_abs = fs::canonicalize(target_dir).unwrap_or_else(|_| target_dir.to_path_buf());
    let raw_s = canonical_or_abs.to_string_lossy();
    let trimmed = raw_s.strip_prefix(r"\\?\").unwrap_or(&raw_s);
    let mut chars = trimmed.chars();
    let first = chars.next();
    let second = chars.next();
    let Some(drive) = first
        .filter(|c| c.is_ascii_alphabetic() && second == Some(':'))
        .map(|c| c.to_ascii_uppercase())
    else {
        return Ok(());
    };
    let out = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-PSDrive -Name {drive} -ErrorAction SilentlyContinue).Free"),
        ])
        .output();
    if let Ok(o) = out {
        if let Ok(free) = String::from_utf8_lossy(&o.stdout).trim().parse::<u64>() {
            if free < required_bytes {
                return Err(format!(
                    "[{FD_ERR_BACKUP_TX}] 目标磁盘 {drive}: 剩余空间不足（需要至少 2 倍余量 {}，当前可用 {}）",
                    format_size(required_bytes),
                    format_size(free)
                ));
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn check_free_disk_space(_target_dir: &Path, _required_bytes: u64) -> Result<(), String> {
    Ok(())
}

/// 原子事务还原：校验 0 进程 + ZIP 完整性 + 2 倍磁盘余量 → 自动建 pre-restore 安全点 → 临时目录解压 → 原子重命名切换
pub fn restore_backup_file(file_name: &str) -> Result<String, String> {
    if file_name.contains("..") || file_name.contains('/') || file_name.contains('\\') {
        return Err(format!("[{FD_ERR_BACKUP_TX}] 非法备份文件名"));
    }

    let procs = list_claude_processes();
    if !procs.is_empty() {
        return Err(format!(
            "[{FD_ERR_BACKUP_TX}] 检测到 {} 个 Claude 进程运行中，原子还原前必须确保 Claude 为 0 进程。",
            procs.len()
        ));
    }

    let bdir = backups_dir();
    let zip_path = bdir.join(file_name);
    if !zip_path.exists() {
        return Err(format!("[{FD_ERR_BACKUP_TX}] 找不到备份文件: {file_name}"));
    }

    let (_, uncompressed_bytes) = verify_zip_integrity(&zip_path)?;
    check_free_disk_space(&bdir, uncompressed_bytes.saturating_mul(2).saturating_add(16 * 1024 * 1024))?;

    let roots = discover_claude_data_roots();

    // 还原前强制先创建「还原前安全点 (pre-restore)」，随时支持反悔回滚（覆盖经典 + MSIX）
    let safety_point = create_snapshot_zip_with_roots(&bdir, "pre-restore", &roots)?;

    let restored = atomic_extract_and_swap_with_roots(
        &zip_path,
        &roots,
        dirs::data_local_dir().as_deref(),
    )?;

    Ok(format!(
        "已自动建立还原前安全点 {}，并原子还原 {restored} 个文件自 {file_name}。",
        safety_point.file_name
    ))
}

/// 先解压到临时目录并校验，全部成功后再安全合并写回目标目录（向后兼容旧签名）
pub fn atomic_extract_and_swap(
    zip_path: &Path,
    roaming: Option<&Path>,
    local: Option<&Path>,
    telemetry: Option<&Path>,
) -> Result<usize, String> {
    let roots = ClaudeDataRoots {
        classic_roaming: roaming.map(Path::to_path_buf),
        classic_local: local.map(Path::to_path_buf),
        telemetry: telemetry.map(Path::to_path_buf),
        ..Default::default()
    };
    atomic_extract_and_swap_with_roots(zip_path, &roots, None)
}

/// 原子解压并按文件粒度合并写回经典目录 + MSIX LocalCache + Local\Claude-Data（绝不覆盖受保护的 vm_bundles、程序本体与未备份的 MCP 配置）
pub fn atomic_extract_and_swap_with_roots(
    zip_path: &Path,
    roots: &ClaudeDataRoots,
    data_local_dir_for_msix: Option<&Path>,
) -> Result<usize, String> {
    let ts = chrono::Local::now().format("%Y%m%d%H%M%S%3f");
    let staging_root = zip_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".restore-staging-{ts}"));
    fs::create_dir_all(&staging_root)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 创建临时还原目录失败: {e}"))?;

    let file = File::open(zip_path)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 打开备份 ZIP 失败: {e}"))?;
    let mut archive = ZipArchive::new(file)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 解析备份 ZIP 失败: {e}"))?;

    let mut extracted = 0usize;
    let mut has_roaming = false;
    let mut has_local = false;
    let mut has_telemetry = false;
    let mut has_cli = false;
    let mut msix_buckets: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();
    let mut claude_data_buckets: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 读取 ZIP 条目失败: {e}"))?;
        let name = entry.name().to_string();
        if entry.is_dir()
            || name == "backup-manifest.txt"
            || name == "backup-manifest.json"
            || name.contains("..")
        {
            continue;
        }
        let target_dest: Option<PathBuf> = if let Some(rel) = name.strip_prefix("roaming/") {
            has_roaming = true;
            Some(staging_root.join("roaming").join(rel))
        } else if let Some(rel) = name.strip_prefix("local/") {
            has_local = true;
            Some(staging_root.join("local").join(rel))
        } else if let Some(rel) = name.strip_prefix("telemetry/") {
            has_telemetry = true;
            Some(staging_root.join("telemetry").join(rel))
        } else if let Some(rel) = name.strip_prefix("cli/") {
            has_cli = true;
            Some(staging_root.join("cli").join(rel))
        } else if let Some(rest) = name.strip_prefix("msix/") {
            // msix/<package_dir_name>/(roaming|local)/<rel>
            let mut parts = rest.splitn(3, '/');
            match (parts.next(), parts.next(), parts.next()) {
                (Some(pkg), Some(kind @ ("roaming" | "local")), Some(rel))
                    if !pkg.is_empty() && !rel.is_empty() =>
                {
                    msix_buckets.insert((pkg.to_string(), kind.to_string()));
                    Some(staging_root.join("msix").join(pkg).join(kind).join(rel))
                }
                _ => None,
            }
        } else if let Some(rest) = name.strip_prefix("claude-data/") {
            // claude-data/<package_dir_name>/<rel>
            let mut parts = rest.splitn(2, '/');
            match (parts.next(), parts.next()) {
                (Some(pkg), Some(rel)) if !pkg.is_empty() && !rel.is_empty() => {
                    claude_data_buckets.insert(pkg.to_string());
                    Some(staging_root.join("claude-data").join(pkg).join(rel))
                }
                _ => None,
            }
        } else {
            None
        };

        if let Some(dest) = target_dest {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 创建临时子目录失败: {e}"))?;
            }
            let mut out_f = File::create(&dest)
                .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 创建临时还原文件失败: {e}"))?;
            std::io::copy(&mut entry, &mut out_f)
                .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 流式解压文件失败: {e}"))?;
            extracted += 1;
        }
    }

    // 按文件粒度合并覆盖还原，保留目录内受保护的 vm_bundles、程序本体与用户保留项
    let merge_into_dest = |src: PathBuf, dest: &Path| -> Result<(), String> {
        if !src.exists() {
            return Ok(());
        }
        copy_dir_recursive(&src, dest)
    };

    let mut res = Ok(());
    if has_roaming {
        if let Some(dest) = roots.classic_roaming.as_deref() {
            res = res.and_then(|_| merge_into_dest(staging_root.join("roaming"), dest));
        }
    }
    if has_local {
        if let Some(dest) = roots.classic_local.as_deref() {
            res = res.and_then(|_| merge_into_dest(staging_root.join("local"), dest));
        }
    }
    if has_telemetry {
        if let Some(dest) = roots.telemetry.as_deref() {
            res = res.and_then(|_| merge_into_dest(staging_root.join("telemetry"), dest));
        }
    }
    if has_cli {
        let cli_stage = staging_root.join("cli");
        if let Some(dest) = roots.cli_claude_json.as_deref() {
            let src = cli_stage.join(".claude.json");
            if src.exists() {
                res = res.and_then(|_| {
                    fs::copy(&src, dest)
                        .map(|_| ())
                        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 还原 .claude.json 失败: {e}"))
                });
            }
        }
        if let Some(dest) = roots.cli_credentials.as_deref() {
            let src = cli_stage.join(".claude").join(".credentials.json");
            if src.exists() {
                res = res.and_then(|_| {
                    if let Some(parent) = dest.parent() {
                        fs::create_dir_all(parent)
                            .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 创建 .claude 目录失败: {e}"))?;
                    }
                    fs::copy(&src, dest)
                        .map(|_| ())
                        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 还原 .credentials.json 失败: {e}"))
                });
            }
        }
        if let Some(dest) = roots.cli_backups_dir.as_deref() {
            let src = cli_stage.join(".claude").join("backups");
            if src.exists() {
                res = res.and_then(|_| merge_into_dest(src, dest));
            }
        }
    }
    for (pkg, kind) in msix_buckets {
        let target_dest = roots
            .msix_roots
            .iter()
            .find(|m| m.package_dir_name == pkg)
            .map(|m| if kind == "roaming" { m.roaming.clone() } else { m.local.clone() })
            .or_else(|| {
                data_local_dir_for_msix.map(|base| {
                    base.join("Packages")
                        .join(&pkg)
                        .join("LocalCache")
                        .join(if kind == "roaming" { "Roaming" } else { "Local" })
                        .join("Claude")
                })
            });
        if let Some(dest) = target_dest {
            let src = staging_root.join("msix").join(&pkg).join(&kind);
            res = res.and_then(|_| merge_into_dest(src, &dest));
        }
    }
    for pkg in claude_data_buckets {
        let target_dest = roots
            .msix_claude_data
            .iter()
            .find(|m| m.package_dir_name == pkg)
            .map(|m| m.dir.clone())
            .or_else(|| data_local_dir_for_msix.map(|base| base.join("Claude-Data").join(&pkg)));
        if let Some(dest) = target_dest {
            let src = staging_root.join("claude-data").join(&pkg);
            res = res.and_then(|_| merge_into_dest(src, &dest));
        }
    }

    let _ = fs::remove_dir_all(&staging_root);
    res?;
    Ok(extracted)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), String> {
    fs::create_dir_all(dst).map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 创建还原目标目录失败: {e}"))?;
    for entry in fs::read_dir(src)
        .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 读取临时目录失败: {e}"))?
        .flatten()
    {
        let sp = entry.path();
        let dp = dst.join(entry.file_name());
        if sp.is_dir() {
            copy_dir_recursive(&sp, &dp)?;
        } else {
            fs::copy(&sp, &dp)
                .map_err(|e| format!("[{FD_ERR_BACKUP_TX}] 拷贝还原文件失败: {e}"))?;
        }
    }
    Ok(())
}

/// 零侵入采集脱敏后的 Claude 官方诊断元数据（system-info / vm-info / mcp-info / supported-features / settings.json）
fn collect_official_diag_metadata() -> Vec<(String, String)> {
    let mut collected = Vec::new();
    let diag_names = [
        "system-info.txt",
        "vm-info.json",
        "mcp-info.json",
        "supported-features-info.json",
    ];

    let mut search_dirs: Vec<PathBuf> = Vec::new();
    let roots = discover_claude_data_roots();
    if let Some(local) = roots.classic_local {
        search_dirs.push(local.clone());
        search_dirs.push(local.join("logs"));
    }
    if let Some(roaming) = roots.classic_roaming {
        search_dirs.push(roaming.clone());
        search_dirs.push(roaming.join("logs"));
    }
    for m in roots.msix_roots {
        search_dirs.push(m.roaming.clone());
        search_dirs.push(m.roaming.join("logs"));
        search_dirs.push(m.local.clone());
        search_dirs.push(m.local.join("logs"));
    }

    for name in diag_names {
        for dir in &search_dirs {
            let p = dir.join(name);
            if p.is_file() {
                if let Ok(raw) = fs::read_to_string(&p) {
                    collected.push((format!("official-diag/{name}"), sanitize_sensitive_text(&raw)));
                    break;
                }
            }
        }
    }

    if let Some(settings) = dirs::home_dir().map(|h| h.join(".claude").join("settings.json")) {
        if let Ok(raw) = fs::read_to_string(settings) {
            collected.push((
                "official-diag/claude-settings.json".into(),
                sanitize_sensitive_text(&raw),
            ));
        }
    }

    collected
}

/// 导出脱敏 AI 排障包（严格包含 manifest.json 魔数 0x12708F87、官方状态与诊断元数据、运行日志，统一占位符 <REDACTED:2W>）
pub fn export_ai_diagnostic_bundle(
    context_item_id: Option<&str>,
    cfg: &AppConfig,
    snapshot: &GuardSnapshot,
    report: &PreflightReport,
    logs: &[LogEvent],
) -> Result<DiagnosticBundleResult, String> {
    let focus_item = context_item_id.and_then(|id| report.items.iter().find(|i| i.id == id));

    let mut md = String::new();
    md.push_str("# FD Claude Guard 脱敏排障上下文\n\n");
    md.push_str(&format!(
        "- 生成时间：{}\n- 协议魔数：{}\n- 当前状态：{}（必须项 {}/{}，建议项 {}/{}）\n- 当前锁定节点：{}（地区 {}）| 脱敏出口：{}\n- Clash Verge：{}（端口 {}，在线：{}）\n- Anthropic 官方服务状态：{}（{}）\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
        DIAG_MANIFEST_MAGIC_HEX,
        snapshot.status_label,
        snapshot.must_passed,
        snapshot.must_total,
        snapshot.opt_passed,
        snapshot.opt_total,
        snapshot.current_node,
        snapshot.region_code,
        snapshot.exit_ip_masked,
        snapshot.clash_version,
        snapshot.clash_port,
        snapshot.clash_online,
        snapshot.anthropic_status_indicator,
        snapshot.anthropic_status_desc
    ));

    if let Some(it) = focus_item {
        md.push_str(&format!(
            "\n## 聚焦排查项：{}\n- 状态：{:?}\n- 摘要：{}\n- 探针证据：\n```text\n{}\n```\n",
            it.title, it.status, it.summary, it.evidence
        ));
    }

    md.push_str("\n## 全部两级三防线实测摘要\n");
    for it in &report.items {
        md.push_str(&format!("- [{:?}] {}：{}\n", it.status, it.title, it.summary));
    }

    md.push_str("\n## 账号观测与噪音摘要（含 MSIX 与轮转日志）\n");
    let acct_audit = crate::watchdog::audit_claude_logs_for_accounts();
    let (_, log_stats_live) = crate::watchdog::collect_log_analysis(&[]);
    let ban_attribution = crate::watchdog::build_ban_attribution_snapshot(
        logs,
        &acct_audit,
        log_stats_live.timezone_jump_warning.as_deref(),
        &snapshot.region_code,
        snapshot.node_drift_warn,
        snapshot.kill_switch_active,
    );
    md.push_str(&format!(
        "- 已扫描日志数（含 main1.log 轮转与 MSIX）：{}\n- 观测到的 orgId 前缀（{}）：{}\n- 观测到的 accountId 前缀（{}）：{}\n- 关联过验证受限/高危 403 的 orgId：{}\n- 已自动排除的无关噪音条数：{}\n- 72h 封号前置高危因子：{}\n",
        acct_audit.scanned_files,
        acct_audit.unique_org_ids.len(),
        if acct_audit.unique_org_ids.is_empty() { "无".into() } else { acct_audit.unique_org_ids.join(", ") },
        acct_audit.unique_account_ids.len(),
        if acct_audit.unique_account_ids.is_empty() { "无".into() } else { acct_audit.unique_account_ids.join(", ") },
        if acct_audit.restricted_org_ids.is_empty() { "无".into() } else { acct_audit.restricted_org_ids.join(", ") },
        log_stats_live.ignored_noise_count,
        if ban_attribution.top_risk_factors.is_empty() {
            "无".into()
        } else {
            ban_attribution.top_risk_factors.join(", ")
        }
    ));
    if let Some(ref tz_warn) = log_stats_live.timezone_jump_warning {
        md.push_str(&format!("- 历史时区跳变提醒：{tz_warn}\n"));
    }

    md.push_str("\n## 最近异常与行为日志（最多 12 条）\n");
    if logs.is_empty() {
        md.push_str("- （暂无 Claude 客户端日志记录）\n");
    } else {
        for ev in logs.iter().take(12) {
            md.push_str(&format!(
                "- [{}] {} ({})：{}\n  上下文：{}\n",
                ev.tag, ev.title, ev.file, ev.cause, ev.context
            ));
        }
    }

    let guard_runtime_logs = crate::logger::read_recent_logs(80);
    let recent_7d_jsonl = crate::logger::collect_recent_jsonl_files(7);
    md.push_str("\n## FD Claude Guard 结构化运行日志（今日最近 30 条 JSONL）\n```jsonl\n");
    if guard_runtime_logs.is_empty() {
        md.push_str("（当前尚无落盘运行日志）\n");
    } else {
        let start = guard_runtime_logs.len().saturating_sub(30);
        for line in &guard_runtime_logs[start..] {
            md.push_str(line);
            md.push('\n');
        }
    }
    md.push_str("```\n");

    let review_template = build_ai_review_prompt_template(
        snapshot,
        report,
        recent_7d_jsonl.len(),
        official_diag_count_hint(&md),
    );
    let sanitized_review = sanitize_sensitive_text(&review_template);

    let official_diag = collect_official_diag_metadata();
    let sanitized_md = sanitize_sensitive_text(&md);
    let ban_attr_json = sanitize_for_telemetry(
        &serde_json::to_string_pretty(&ban_attribution).unwrap_or_else(|_| "{}".into()),
    );
    let raw_json = serde_json::to_string_pretty(&serde_json::json!({
        "schemaVersion": 2,
        "config": cfg,
        "snapshot": snapshot,
        "preflight": report,
        "banAttribution72h": ban_attribution,
        "recentLogs": logs.iter().take(20).collect::<Vec<_>>(),
        "guardRuntimeLogs": guard_runtime_logs,
        "packagedJsonlFiles": recent_7d_jsonl.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        "officialDiagFiles": official_diag.iter().map(|(k, _)| k).collect::<Vec<_>>(),
    }))
    .unwrap_or_else(|_| "{}".into());
    let sanitized_json = sanitize_sensitive_text(&raw_json);

    let manifest_json = serde_json::to_string_pretty(&serde_json::json!({
        "magic": DIAG_MANIFEST_MAGIC,
        "magicHex": DIAG_MANIFEST_MAGIC_HEX,
        "schemaVersion": 2,
        "product": "FD Claude Guard",
        "version": env!("CARGO_PKG_VERSION"),
        "redactPlaceholder": REDACT_PLACEHOLDER,
        "createdAt": chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "officialMetadataCount": official_diag.len(),
        "runtimeJsonlFileCount": recent_7d_jsonl.len(),
        "includesAiReviewPrompt": true,
        "includesBanAttribution": true,
    }))
    .unwrap_or_else(|_| "{}".into());

    let out_dir = dirs::desktop_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    let ts = chrono::Local::now().format("%Y%m%d-%H%M");
    let zip_path = out_dir.join(format!("FDClaudeGuard-诊断包-{ts}.zip"));

    let file = File::create(&zip_path).map_err(|e| format!("创建诊断包 ZIP 失败: {e}"))?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

    zip.start_file("manifest.json", options)
        .map_err(|e| format!("写入 manifest.json 失败: {e}"))?;
    zip.write_all(manifest_json.as_bytes())
        .map_err(|e| format!("写入 manifest.json 内容失败: {e}"))?;

    zip.start_file("ban-attribution.json", options)
        .map_err(|e| format!("写入 ban-attribution.json 失败: {e}"))?;
    zip.write_all(ban_attr_json.as_bytes())
        .map_err(|e| format!("写入 ban-attribution.json 内容失败: {e}"))?;

    zip.start_file("ai-diagnostic-prompt.md", options)
        .map_err(|e| format!("写入诊断 Markdown 失败: {e}"))?;
    zip.write_all(sanitized_md.as_bytes())
        .map_err(|e| format!("写入诊断 Markdown 内容失败: {e}"))?;

    zip.start_file("ai-review-prompt.md", options)
        .map_err(|e| format!("写入 AI 复盘模板失败: {e}"))?;
    zip.write_all(sanitized_review.as_bytes())
        .map_err(|e| format!("写入 AI 复盘模板内容失败: {e}"))?;

    zip.start_file("sanitized-report.json", options)
        .map_err(|e| format!("写入诊断 JSON 失败: {e}"))?;
    zip.write_all(sanitized_json.as_bytes())
        .map_err(|e| format!("写入诊断 JSON 内容失败: {e}"))?;

    // 自动打包最近 7 天的脱敏 guard-runtime-YYYYMMDD.jsonl
    for (file_name, content) in recent_7d_jsonl {
        let entry_name = format!("logs/{file_name}");
        if zip.start_file(entry_name, options).is_ok() {
            let _ = zip.write_all(content.as_bytes());
        }
    }

    for (zip_entry, content) in official_diag {
        if zip.start_file(zip_entry, options).is_ok() {
            let _ = zip.write_all(content.as_bytes());
        }
    }

    zip.finish()
        .map_err(|e| format!("封存诊断包 ZIP 失败: {e}"))?;

    crate::logger::log_event(
        "INFO",
        "maintenance",
        "diag_bundle_exported",
        None,
        format!("导出脱敏 AI 排障包完成: {}", zip_path.display()),
        Some(serde_json::json!({ "magic": DIAG_MANIFEST_MAGIC_HEX })),
    );

    Ok(DiagnosticBundleResult {
        zip_path: zip_path.to_string_lossy().to_string(),
        prompt_markdown: sanitized_md,
        manifest_magic: DIAG_MANIFEST_MAGIC,
    })
}

fn official_diag_count_hint(_md: &str) -> usize {
    collect_official_diag_metadata().len()
}

/// 生成附带在诊断包中的持续复盘优化模板 `ai-review-prompt.md`
pub fn build_ai_review_prompt_template(
    snapshot: &GuardSnapshot,
    report: &PreflightReport,
    jsonl_file_count: usize,
    official_meta_count: usize,
) -> String {
    let failed_must: Vec<String> = report
        .items
        .iter()
        .filter(|i| i.part == crate::state::CheckPart::Must && i.status != crate::state::CheckStatus::Ok)
        .map(|i| format!("{} ({})", i.title, i.id))
        .collect();

    format!(
        r#"# FD Claude Guard 运行日志与防封复盘分析模板（ai-review-prompt.md）

请作为资深 Windows 安全工程与桌面架构师，结合本压缩包内的以下文件做系统复盘与迭代优化建议：
- `manifest.json`（协议魔数 `{}`，统一脱敏占位符 `{}`）
- `logs/guard-runtime-YYYYMMDD.jsonl`（最近 7 天共 {} 份结构化运行日志，记录探针耗时、失败归因、一键修复、熔断与休眠唤醒预阻断时间轴、落地 IP 静默漂移及前端错误）
- `sanitized-report.json`（当前 10 项必须 + 3 项建议体检全量实测快照）
- `official-diag/*`（{} 份脱敏官方诊断元数据）

## 当前基线快照
- 状态：{}（必须项 {}/{}，建议项 {}/{}）
- 锁定节点：{}（地区 {}）| 脱敏出口：{}
- Anthropic 官方状态页：{}（{}）
- 当前未通过必须项：{}

## 请重点复盘以下 5 个维度并输出可执行改进清单
1. **探针性能与可靠性**：统计 `logs/guard-runtime-*.jsonl` 中 `event="preflight_done"` 的 `durationMs` 分布与慢探针瓶颈，检查是否有管道忙重试（`pipe_retry`）或超时抖动。
2. **失败根因与修复闭环**：梳理高频未通过项、一键修复（`fix_item` / `one_click_fix_all`）的成功与失败原因，评估是否存在误报或缺少自动修复路径。
3. **节点与防封安全时间轴**：审查 `landing_ip_drift`（落地 IP 静默漂移）、`killswitch_triggered`（熔断）、`wake_preblock_window`（休眠唤醒预阻断）与 CF 403 拦截记录，识别薄弱窗口。
4. **前端异常与用户体验**：排查 `module="frontend"` 的 `window.onerror` / `unhandledrejection` 与交互卡点。
5. **下阶段优先级排序（P0 / P1 / P2）**：给出具体到模块、文件与验收断言的优化建议。
"#,
        DIAG_MANIFEST_MAGIC_HEX,
        REDACT_PLACEHOLDER,
        jsonl_file_count,
        official_meta_count,
        snapshot.status_label,
        snapshot.must_passed,
        snapshot.must_total,
        snapshot.opt_passed,
        snapshot.opt_total,
        snapshot.current_node,
        snapshot.region_code,
        snapshot.exit_ip_masked,
        snapshot.anthropic_status_indicator,
        snapshot.anthropic_status_desc,
        if failed_must.is_empty() {
            "无（全绿就绪）".to_string()
        } else {
            failed_must.join("、")
        }
    )
}

/// 在系统文件资源管理器中定位文件所在文件夹
pub fn open_folder_and_select(path: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        let p = Path::new(path);
        if p.exists() {
            std::process::Command::new("explorer")
                .arg(format!("/select,{}", p.display()))
                .spawn()
                .map_err(|e| format!("打开文件夹失败: {e}"))?;
        } else if let Some(parent) = p.parent() {
            std::process::Command::new("explorer")
                .arg(parent)
                .spawn()
                .map_err(|e| format!("打开文件夹失败: {e}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn sanitizer_uses_exact_protocol_placeholder_for_all_sensitive_fields() {
        let raw = r#"
            User: alice.dev@example.com
            Header: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc123
            Key: sk-ant-api03-SECRETTOKEN1234567890
            Session: sessionKey="sk-ant-sid01-verysecretvalue999"
            PublicIP: 104.28.192.44 | IPv6: 2606:4700:4700::1111 | FakeIP: 198.18.0.14 | Local: 127.0.0.1
            Time: 22:15:09
            Path: C:\Users\alice\AppData\Local\Claude\logs\main.log
        "#;

        let clean = sanitize_sensitive_text(raw);
        assert!(!clean.contains("alice.dev@example.com"));
        assert!(!clean.contains("eyJhbGciOiJIUzI1Ni"));
        assert!(!clean.contains("SECRETTOKEN1234567890"));
        assert!(!clean.contains("verysecretvalue999"));
        assert!(!clean.contains("104.28.192.44"));
        assert!(!clean.contains("2606:4700:4700::1111"));
        assert!(!clean.contains(r"Users\alice"));

        assert!(clean.contains(REDACT_PLACEHOLDER));
        assert!(clean.contains("Bearer <REDACTED:2W>"));
        assert!(clean.contains("198.18.0.14"));
        assert!(clean.contains("127.0.0.1"));
        assert!(clean.contains("22:15:09"));
    }

    #[test]
    fn atomic_backup_verify_and_swap_roundtrip() {
        let dir = tempdir().unwrap();
        let backups = dir.path().join("backups");
        let roaming = dir.path().join("roaming_claude");
        fs::create_dir_all(&roaming).unwrap();
        fs::write(roaming.join("state.json"), r#"{"org":"clean"}"#).unwrap();

        let snap = create_snapshot_zip(&backups, "clean", Some(&roaming), None, None).unwrap();
        assert!(snap.file_name.contains("-clean-"));
        let (cnt, bytes) = verify_zip_integrity(Path::new(&snap.full_path)).unwrap();
        assert!(cnt >= 2);
        assert!(bytes > 0);

        // 模拟目录污染后原子还原
        fs::write(roaming.join("state.json"), r#"{"org":"polluted"}"#).unwrap();
        let restored = atomic_extract_and_swap(
            Path::new(&snap.full_path),
            Some(&roaming),
            None,
            None,
        )
        .unwrap();
        assert_eq!(restored, 1);
        assert_eq!(
            fs::read_to_string(roaming.join("state.json")).unwrap(),
            r#"{"org":"clean"}"#
        );
    }

    #[test]
    fn msix_backup_clean_and_atomic_restore_roundtrip() {
        let dir = tempdir().unwrap();
        let backups = dir.path().join("backups");
        let cfg_base = dir.path().join("Roaming");
        let local_base = dir.path().join("Local");
        let home_base = dir.path().join("Home");
        let pkg = "Claude_pzs8sxrjxfjjc";
        let msix_roaming = local_base
            .join("Packages")
            .join(pkg)
            .join("LocalCache")
            .join("Roaming")
            .join("Claude");
        let msix_local = local_base
            .join("Packages")
            .join(pkg)
            .join("LocalCache")
            .join("Local")
            .join("Claude");
        fs::create_dir_all(msix_roaming.join("Network")).unwrap();
        fs::create_dir_all(msix_roaming.join("logs")).unwrap();
        fs::create_dir_all(&msix_local).unwrap();

        fs::write(msix_roaming.join("Network").join("Cookies"), "cookie-bytes-v1").unwrap();
        fs::write(msix_roaming.join("logs").join("main.log"), "portal.anthropic.com/verify").unwrap();
        fs::write(msix_local.join("cache.bin"), "cache-bytes-v1").unwrap();

        let roots = discover_claude_data_roots_from(Some(&cfg_base), Some(&local_base), Some(&home_base));
        assert_eq!(roots.msix_roots.len(), 1);
        assert_eq!(roots.msix_roots[0].package_dir_name, pkg);

        // 备份并清理：MSIX Cookies / main.log / cache.bin 必须被全部清空
        let snap = backup_and_clean_with_roots(&backups, &roots).unwrap();
        assert!(!msix_roaming.join("Network").join("Cookies").exists());
        assert!(!msix_roaming.join("logs").join("main.log").exists());
        assert!(!msix_local.join("cache.bin").exists());

        // 原子还原：字节级恢复原 MSIX 目录
        let restored = atomic_extract_and_swap_with_roots(
            Path::new(&snap.full_path),
            &roots,
            Some(&local_base),
        )
        .unwrap();
        assert_eq!(restored, 3);
        assert_eq!(
            fs::read_to_string(msix_roaming.join("Network").join("Cookies")).unwrap(),
            "cookie-bytes-v1"
        );
        assert_eq!(
            fs::read_to_string(msix_roaming.join("logs").join("main.log")).unwrap(),
            "portal.anthropic.com/verify"
        );
        assert_eq!(
            fs::read_to_string(msix_local.join("cache.bin")).unwrap(),
            "cache-bytes-v1"
        );
    }

    #[test]
    fn multi_install_cleanup_preview_protection_large_vm_and_selective_clean() {
        let dir = tempdir().unwrap();
        let backups = dir.path().join("backups");
        let cfg_base = dir.path().join("Roaming");
        let local_base = dir.path().join("Local");
        let home_base = dir.path().join("Home");

        // 1. 构造经典版（含程序本体 app-0.9 + Update.exe + MCP 配置 + 大缓存 + VM 镜像 + Cookie/日志）
        let classic_roaming = cfg_base.join("Claude");
        let classic_local = local_base.join("Claude");
        fs::create_dir_all(classic_roaming.join("Network")).unwrap();
        fs::create_dir_all(classic_roaming.join("logs")).unwrap();
        fs::create_dir_all(classic_roaming.join("Cache")).unwrap();
        fs::create_dir_all(classic_roaming.join("vm_bundles")).unwrap();
        fs::create_dir_all(classic_local.join("app-0.9.1")).unwrap();
        fs::create_dir_all(home_base.join(".claude").join("telemetry")).unwrap();

        fs::write(classic_roaming.join("Network").join("Cookies"), "cookie-secret").unwrap();
        fs::write(classic_roaming.join("logs").join("main.log"), "403 permission_error").unwrap();
        fs::write(classic_roaming.join("claude_desktop_config.json"), r#"{"mcpServers":{}}"#).unwrap();
        fs::write(classic_roaming.join("Cache").join("data_1"), vec![b'C'; 2 * 1024 * 1024]).unwrap();
        fs::write(classic_roaming.join("vm_bundles").join("rootfs.img"), vec![b'V'; 12 * 1024 * 1024]).unwrap();
        fs::write(classic_local.join("Update.exe"), "squirrel-updater").unwrap();
        fs::write(classic_local.join("app-0.9.1").join("Claude.exe"), "classic-binary").unwrap();
        fs::write(home_base.join(".claude").join("telemetry").join("ev.json"), "{}").unwrap();

        // 2. 构造 MSIX Local\Claude-Data（OAuth config.json + local-agent-mode-sessions）
        let cdata = local_base.join("Claude-Data").join("anthropicpbc.claude_test123");
        fs::create_dir_all(cdata.join("local-agent-mode-sessions")).unwrap();
        fs::write(cdata.join("config.json"), r#"{"oauth":"tok"}"#).unwrap();
        fs::write(cdata.join("local-agent-mode-sessions").join("s1.json"), "session-1").unwrap();

        let roots = discover_claude_data_roots_from(Some(&cfg_base), Some(&local_base), Some(&home_base));
        assert!(roots.classic_install_detected);
        assert_eq!(roots.msix_claude_data.len(), 1);

        // 3. 预览扫描校验分项与保护项
        let preview = preview_claude_cleanup_plan_with_roots(&roots, 0);
        assert!(preview.detected_install_modes.iter().any(|m| m.contains("MSIX")));
        assert!(preview.detected_install_modes.iter().any(|m| m.contains("经典")));
        assert!(preview.protected.total_bytes >= 12 * 1024 * 1024);

        let mcp_cat = preview.categories.iter().find(|c| c.id == CLEAN_CAT_MCP_SESSIONS).unwrap();
        assert!(!mcp_cat.default_selected, "MCP 配置与本地会话必须默认不勾选防错删");
        assert_eq!(mcp_cat.file_count, 2);

        let cache_cat = preview.categories.iter().find(|c| c.id == CLEAN_CAT_CACHE).unwrap();
        assert!(cache_cat.default_selected);
        assert!(!cache_cat.will_backup, "可再生缓存必须仅清理不入 ZIP");

        // 4. 按默认项清理（不勾选 mcp_sessions），断言耗时快且 0 误删
        let started = std::time::Instant::now();
        let snap = backup_and_clean_with_roots_selected(&backups, &roots, None).unwrap();
        assert!(started.elapsed().as_secs() < 5);

        // 已勾选项被清理
        assert!(!classic_roaming.join("Network").join("Cookies").exists());
        assert!(!classic_roaming.join("logs").join("main.log").exists());
        assert!(!classic_roaming.join("Cache").join("data_1").exists());
        assert!(!cdata.join("config.json").exists());
        assert!(!home_base.join(".claude").join("telemetry").join("ev.json").exists());

        // 未勾选的 MCP 与本地会话、以及受保护的 VM 镜像和经典程序本体 100% 完整保留！
        assert!(classic_roaming.join("claude_desktop_config.json").exists());
        assert!(cdata.join("local-agent-mode-sessions").join("s1.json").exists());
        assert!(classic_roaming.join("vm_bundles").join("rootfs.img").exists());
        assert!(classic_local.join("Update.exe").exists());
        assert!(classic_local.join("app-0.9.1").join("Claude.exe").exists());

        // ZIP 体积应极小（未打包 2MB 缓存和 12MB VM 镜像）
        assert!(snap.size_bytes < 512 * 1024, "ZIP 体积异常偏大: {}", snap.size_bytes);

        // 5. 还原快照：精准还原登录态与 Local\Claude-Data\config.json，且不破坏保留的 MCP 与 VM
        let restored = atomic_extract_and_swap_with_roots(
            Path::new(&snap.full_path),
            &roots,
            Some(&local_base),
        )
        .unwrap();
        assert_eq!(restored, 4);
        assert_eq!(fs::read_to_string(cdata.join("config.json")).unwrap(), r#"{"oauth":"tok"}"#);
        assert!(classic_roaming.join("claude_desktop_config.json").exists());
        assert!(classic_roaming.join("vm_bundles").join("rootfs.img").exists());
    }

    #[test]
    #[ignore = "Layer 3 真机磁盘压测：真实 Windows NTFS Junction 软链 + 300MB VM 镜像 + 50MB 缓存 + 本机真实扫描实测"]
    fn live_windows_ntfs_junction_and_300mb_stress_audit() {
        let dir = tempdir().unwrap();
        let backups = dir.path().join("backups");
        let cfg_base = dir.path().join("Roaming");
        let local_base = dir.path().join("Local");
        let home_base = dir.path().join("Home");
        let external_code_dir = dir.path().join("ExternalProjectCode");

        let roaming = cfg_base.join("Claude");
        fs::create_dir_all(roaming.join("Network")).unwrap();
        fs::create_dir_all(roaming.join("logs")).unwrap();
        fs::create_dir_all(roaming.join("Cache")).unwrap();
        fs::create_dir_all(roaming.join("vm_bundles")).unwrap();
        fs::create_dir_all(&external_code_dir).unwrap();

        // 外部敏感目录，通过真实 Windows mklink /J 挂载到 Claude 目录内部，验证绝不跟随、绝不误删
        let secret_file = external_code_dir.join("important-user-code.rs");
        fs::write(&secret_file, "fn keep_me_safe() {}").unwrap();
        #[cfg(windows)]
        {
            let junction_path = roaming.join("linked_external");
            let status = std::process::Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &junction_path.to_string_lossy(),
                    &external_code_dir.to_string_lossy(),
                ])
                .status()
                .expect("执行 mklink /J 失败");
            assert!(status.success(), "创建真实 Windows NTFS Junction 失败");
        }

        // 真实写入 300MB 虚拟机镜像 + 50MB 浏览器缓存 + 登录态 + 日志 + MCP 配置
        let vm_path = roaming.join("vm_bundles").join("rootfs.img");
        {
            let f = File::create(&vm_path).unwrap();
            f.set_len(300 * 1024 * 1024).unwrap();
        }
        let cache_path = roaming.join("Cache").join("data_big");
        {
            let f = File::create(&cache_path).unwrap();
            f.set_len(50 * 1024 * 1024).unwrap();
        }
        fs::write(roaming.join("Network").join("Cookies"), "real-cookie-token").unwrap();
        fs::write(roaming.join("logs").join("main.log"), "real-log-line").unwrap();
        fs::write(roaming.join("claude_desktop_config.json"), r#"{"mcpServers":{"demo":{}}}"#).unwrap();

        let roots = discover_claude_data_roots_from(Some(&cfg_base), Some(&local_base), Some(&home_base));

        // 1. 实测预览扫描耗时
        let preview = preview_claude_cleanup_plan_with_roots(&roots, 0);
        println!(
            "=== STRESS PREVIEW ({}ms) | modes={:?} | protected={} ({:?}) ===",
            preview.scanned_ms,
            preview.detected_install_modes,
            preview.protected.size_label,
            preview.protected.reasons
        );
        assert!(preview.scanned_ms < 1000, "预览扫描过慢: {}ms", preview.scanned_ms);
        assert!(preview.protected.total_bytes >= 300 * 1024 * 1024);

        // 2. 实测默认分项备份清理耗时与防误删断言
        let t0 = std::time::Instant::now();
        let snap = backup_and_clean_with_roots_selected(&backups, &roots, None).unwrap();
        let clean_ms = t0.elapsed().as_millis();
        println!(
            "=== STRESS CLEAN ({}ms) | zip={} ({}) ===",
            clean_ms, snap.file_name, snap.size_label
        );
        assert!(clean_ms < 2000, "300MB VM + 50MB 缓存清理耗时超标: {}ms", clean_ms);
        assert!(snap.size_bytes < 100 * 1024, "ZIP 不应包含缓存/VM/外部软链，实际: {} B", snap.size_bytes);

        // 强断言：外部 Junction 目录、300MB VM 镜像、MCP 配置 100% 完好；缓存/Cookie/日志全部清空
        assert!(secret_file.exists(), "NTFS Junction 外部文件遭到误删！");
        assert_eq!(fs::read_to_string(&secret_file).unwrap(), "fn keep_me_safe() {}");
        assert!(vm_path.exists() && fs::metadata(&vm_path).unwrap().len() == 300 * 1024 * 1024);
        assert!(roaming.join("claude_desktop_config.json").exists());
        assert!(!cache_path.exists());
        assert!(!roaming.join("Network").join("Cookies").exists());
        assert!(!roaming.join("logs").join("main.log").exists());

        // 3. 顺带实测本机真实目录预扫描（纯只读）
        let real_preview = preview_claude_cleanup_plan();
        println!(
            "=== REAL MACHINE PREVIEW ({}ms) | modes={:?} | procs={} ===",
            real_preview.scanned_ms, real_preview.detected_install_modes, real_preview.active_claude_procs
        );
        for c in &real_preview.categories {
            println!(
                "  - [{}] {} | default={} backup={} | files={} size={}",
                c.id, c.title, c.default_selected, c.will_backup, c.file_count, c.size_label
            );
        }
        println!(
            "  - [protected] files={} size={} reasons={:?}",
            real_preview.protected.file_count,
            real_preview.protected.size_label,
            real_preview.protected.reasons
        );
    }
}
