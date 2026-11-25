use crate::maintenance::sanitize_sensitive_text;
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static LOG_LOCK: Mutex<()> = Mutex::new(());
const MAX_LOG_FILE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB 单文件滚动上限
const RETENTION_DAYS: i64 = 14;

/// 结构化运行日志记录（JSON Lines，严禁包含任何明文 Token / 邮箱 / 口令）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredLogEntry {
    pub ts: String,
    pub level: String,
    pub module: String,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// 运行诊断日志目录：`%LOCALAPPDATA%\FDClaudeGuard\logs`
pub fn guard_logs_dir() -> PathBuf {
    dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("FDClaudeGuard")
        .join("logs")
}

/// 当日结构化日志文件路径：`%LOCALAPPDATA%\FDClaudeGuard\logs\guard-runtime-YYYYMMDD.jsonl`
pub fn today_log_file_in(dir: &Path) -> PathBuf {
    let date = chrono::Local::now().format("%Y%m%d");
    dir.join(format!("guard-runtime-{date}.jsonl"))
}

/// 递归脱敏 JSON Value 中的全部字符串字段
fn sanitize_json_value(v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(sanitize_sensitive_text(&s)),
        Value::Array(arr) => Value::Array(arr.into_iter().map(sanitize_json_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, val)| (k, sanitize_json_value(val)))
                .collect(),
        ),
        other => other,
    }
}

/// 写入一条结构化运行事件日志（带事件名、耗时与扩展字段，自动全量脱敏）
pub fn log_event(
    level: &str,
    module: &str,
    event: &str,
    duration_ms: Option<u64>,
    message: impl AsRef<str>,
    meta: Option<Value>,
) {
    let dir = guard_logs_dir();
    let _ = write_structured_to_dir(&dir, level, module, event, duration_ms, message.as_ref(), meta);
}

/// 便捷日志写入（自动生成 event="log"）
pub fn write_log(level: &str, module: &str, message: &str) {
    let dir = guard_logs_dir();
    let _ = write_structured_to_dir(&dir, level, module, "log", None, message, None);
}

pub fn log_info(module: &str, message: impl AsRef<str>) {
    write_log("INFO", module, message.as_ref());
}

pub fn log_warn(module: &str, message: impl AsRef<str>) {
    write_log("WARN", module, message.as_ref());
}

pub fn log_error(module: &str, message: impl AsRef<str>) {
    write_log("ERROR", module, message.as_ref());
}

/// 写入指定目录（JSONL 格式，自动脱敏 + 单文件超 10MB 自动归档滚动）
pub fn write_structured_to_dir(
    dir: &Path,
    level: &str,
    module: &str,
    event: &str,
    duration_ms: Option<u64>,
    message: &str,
    meta: Option<Value>,
) -> Result<(), String> {
    let _guard = LOG_LOCK.lock().map_err(|_| "日志锁异常".to_string())?;
    fs::create_dir_all(dir).map_err(|e| format!("创建日志目录失败: {e}"))?;

    let path = today_log_file_in(dir);
    if let Ok(meta_fs) = fs::metadata(&path) {
        if meta_fs.len() >= MAX_LOG_FILE_BYTES {
            let ts = chrono::Local::now().format("%H%M%S-%3f");
            let archived = dir.join(format!(
                "{}-{ts}.jsonl",
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("guard-runtime")
            ));
            let _ = fs::rename(&path, archived);
        }
    }

    let entry = StructuredLogEntry {
        ts: chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z").to_string(),
        level: level.to_uppercase(),
        module: module.to_string(),
        event: event.to_string(),
        duration_ms,
        message: sanitize_sensitive_text(message).replace('\r', "").replace('\n', " | "),
        meta: meta.map(sanitize_json_value),
    };

    let mut line = serde_json::to_string(&entry).map_err(|e| format!("序列化日志失败: {e}"))?;
    line.push('\n');

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("打开日志文件失败: {e}"))?;
    file.write_all(line.as_bytes())
        .map_err(|e| format!("写入日志失败: {e}"))?;
    Ok(())
}

/// 清理超过 14 天的历史运行日志
pub fn cleanup_old_logs() {
    let dir = guard_logs_dir();
    let _ = cleanup_old_logs_in(&dir, RETENTION_DAYS);
}

pub fn cleanup_old_logs_in(dir: &Path, retention_days: i64) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let cutoff = chrono::Local::now() - chrono::Duration::days(retention_days);
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|s| s.to_str());
        if ext != Some("jsonl") && ext != Some("log") {
            continue;
        }
        if let Ok(meta) = fs::metadata(&path) {
            if let Ok(modified) = meta.modified() {
                let dt: chrono::DateTime<chrono::Local> = modified.into();
                if dt < cutoff && fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }
        }
    }
    removed
}

/// 读取当日最近 N 行脱敏 JSONL 运行日志
pub fn read_recent_logs(max_lines: usize) -> Vec<String> {
    read_recent_logs_in(&guard_logs_dir(), max_lines)
}

pub fn read_recent_logs_in(dir: &Path, max_lines: usize) -> Vec<String> {
    if max_lines == 0 {
        return Vec::new();
    }
    let path = today_log_file_in(dir);
    let Ok(mut file) = File::open(&path) else {
        return Vec::new();
    };
    let Ok(meta) = file.metadata() else {
        return Vec::new();
    };
    // 仅从文件尾最多 seek 256KB 读取，避免 10MB 运行日志整文件读入内存
    let max_tail_bytes = ((max_lines as u64).saturating_mul(2048)).clamp(32 * 1024, 256 * 1024);
    let start_offset = meta.len().saturating_sub(max_tail_bytes);
    if start_offset > 0 {
        let _ = file.seek(SeekFrom::Start(start_offset));
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let raw = String::from_utf8_lossy(&buf);
    let mut iter = raw.trim_start_matches('\u{FEFF}').lines();
    if start_offset > 0 {
        // 丢弃可能截断的首行残片
        let _ = iter.next();
    }
    let lines: Vec<String> = iter
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();
    if lines.len() > max_lines {
        lines[lines.len() - max_lines..].to_vec()
    } else {
        lines
    }
}

/// 采集最近 N 天（默认 7 天）的脱敏 `guard-runtime-*.jsonl` 文件，供诊断包自动打包
pub fn collect_recent_jsonl_files(days: i64) -> Vec<(String, String)> {
    collect_recent_jsonl_files_in(&guard_logs_dir(), days)
}

pub fn collect_recent_jsonl_files_in(dir: &Path, days: i64) -> Vec<(String, String)> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let cutoff = chrono::Local::now() - chrono::Duration::days(days);
    let mut files: Vec<(String, String)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().to_string();
        if !file_name.starts_with("guard-runtime-") {
            continue;
        }
        if let Ok(meta) = fs::metadata(&path) {
            if let Ok(modified) = meta.modified() {
                let dt: chrono::DateTime<chrono::Local> = modified.into();
                if dt < cutoff {
                    continue;
                }
            }
        }
        if let Ok(raw) = fs::read_to_string(&path) {
            // 二次保险脱敏，确保任何敏感字段不会落入诊断包
            files.push((file_name, sanitize_sensitive_text(&raw)));
        }
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    files
}

/// 在资源管理器中打开运行日志目录
pub fn open_logs_directory() -> Result<String, String> {
    let dir = guard_logs_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("创建日志目录失败: {e}"))?;
    let dir_str = dir.to_string_lossy().to_string();

    #[cfg(windows)]
    {
        std::process::Command::new("explorer")
            .arg(&dir_str)
            .spawn()
            .map_err(|e| format!("打开日志目录失败: {e}"))?;
    }

    Ok(dir_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_sanitized_jsonl_logs_and_collects_recent_7d() {
        let dir = tempdir().unwrap();
        write_structured_to_dir(
            dir.path(),
            "INFO",
            "preflight",
            "audit_done",
            Some(321),
            "user alice@example.com token Bearer eyJhbGci1234567890 ip 104.28.192.44",
            Some(serde_json::json!({ "email": "bob@test.org", "failed": ["sys_ipv6"] })),
        )
        .unwrap();
        write_structured_to_dir(
            dir.path(),
            "WARN",
            "mihomo",
            "pipe_retry",
            Some(25),
            "pipe busy retry=1",
            None,
        )
        .unwrap();

        let lines = read_recent_logs_in(dir.path(), 10);
        assert_eq!(lines.len(), 2);
        let parsed0: Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(parsed0["module"], "preflight");
        assert_eq!(parsed0["event"], "audit_done");
        assert_eq!(parsed0["durationMs"], 321);
        let msg0 = parsed0["message"].as_str().unwrap();
        assert!(!msg0.contains("alice@example.com"));
        assert!(!msg0.contains("eyJhbGci1234567890"));
        assert!(!msg0.contains("104.28.192.44"));
        assert!(msg0.contains(crate::protocol::REDACT_PLACEHOLDER));
        assert_eq!(parsed0["meta"]["email"], crate::protocol::REDACT_PLACEHOLDER);

        let collected = collect_recent_jsonl_files_in(dir.path(), 7);
        assert_eq!(collected.len(), 1);
        assert!(collected[0].0.starts_with("guard-runtime-"));
        assert!(collected[0].0.ends_with(".jsonl"));
    }
}
