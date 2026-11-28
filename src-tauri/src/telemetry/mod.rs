//! T-302 / T-303：FDtools 客户机低频高价值匿名遥测与一键上报排障单号模块
//!
//! 分层原则（L1 / L2 / L3）：
//! - L1（纯本地记录，绝不主动发网）：全部常规体检、业务日志与所有 Claude `warn` 风险提醒
//!   （含 Free/KYC 403 `len=164/156`、`OAuth v2 鉴权`、529 官方过载、普通网络断连）；
//! - L2（静默低频高价值遥测）：仅在用户开启对应开关且发生真实故障（修复实测失败、4 层热熔断/防裸奔拦截）
//!   或 Claude 高危实锤事件（`level == "fail"`：账号封禁/验证受限/地区封锁/账号连坐/带凭证 403/退出回传 403）时触发；
//!   具备跨重启持久化去重（7 天 TTL、上限 500 条）、单机每日硬上限（10 条事件 / 3 批请求），且仅 HTTP 2xx 成功后落盘去重；
//! - L3（人工一键匿名排障单号）：由用户在环境维护页主动触发，返回唯一 `FD-YYYYMMDD-XXXXXXXX` 单号。
//!
//! 隐私红线：
//! - 绝不采集任何聊天内容、Prompt、本地代码、明文邮箱、Cookie/Token、机场订阅 URL、真实公网 IP 或完整 orgId；
//! - 所有出站字符串与嵌套 JSON 均经 `maintenance::sanitize_json_value_for_telemetry` 递归强脱敏。

use crate::config::AppConfig;
use crate::maintenance::{sanitize_for_telemetry, sanitize_json_value_for_telemetry};
use crate::state::{CheckStatus, GuardSnapshot, PreflightReport};
use crate::watchdog::{audit_claude_logs_for_accounts, build_ban_attribution_snapshot, LogEvent};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// 跨重启持久化去重保留天数（7 天）
const DEDUP_RETENTION_SECS: i64 = 7 * 24 * 3600;
/// 持久化去重表最大容量（防止无限膨胀）
const DEDUP_MAX_ENTRIES: usize = 500;
/// 单机每日 L2 主动遥测最大事件数硬上限
const DAILY_MAX_EVENTS: u32 = 10;
/// 单机每日 L2 主动遥测最大请求批次数硬上限
const DAILY_MAX_BATCHES: u32 = 3;

/// 生成匿名短安装标识（纯本地 FNV-1a 哈希，不采集任何硬件/个人明文信息，完全脱离商业授权）
pub fn anonymous_install_short_id() -> String {
    static CACHED: OnceLock<String> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            let base = dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("FDClaudeGuard");
            let id_path = base.join("inst.id");
            let seed = fs::read_to_string(&id_path)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    let now = chrono::Local::now().timestamp_nanos_opt().unwrap_or(0);
                    let pid = std::process::id();
                    let generated = format!("oss-{now:x}-{pid:x}");
                    let _ = fs::create_dir_all(&base);
                    let _ = fs::write(&id_path, &generated);
                    generated
                });
            let mut hash: u64 = 0xcbf29ce484222325;
            for b in seed.as_bytes() {
                hash ^= *b as u64;
                hash = hash.wrapping_mul(0x100000001b3);
            }
            format!("{hash:016x}")[..8].to_string()
        })
        .clone()
}

/// 官方默认脱敏诊断日志与排障单号接收服务（Cloudflare Worker + D1，14 天自动清理）
pub const DEFAULT_DIAG_TELEMETRY_API_URL: &str = "https://diag.rookiebird.org";

/// 脱敏遥测/排障服务端点：
/// - 优先读取环境变量 `FD_TELEMETRY_API_URL`（方便自托管覆盖，设为 `off`/`none`/`disabled` 可彻底禁发）；
/// - 未显式覆写时指向官方脱敏诊断服务 `https://diag.rookiebird.org`（仍严格受用户开关与二次强脱敏约束）。
pub fn telemetry_api_endpoint() -> Option<String> {
    if let Ok(val) = std::env::var("FD_TELEMETRY_API_URL") {
        let trimmed = val.trim().to_string();
        if trimmed.is_empty()
            || trimmed.eq_ignore_ascii_case("off")
            || trimmed.eq_ignore_ascii_case("none")
            || trimmed.eq_ignore_ascii_case("disabled")
        {
            return None;
        }
        return Some(trimmed);
    }
    Some(DEFAULT_DIAG_TELEMETRY_API_URL.to_string())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TelemetryDedupStore {
    day_key: String,
    daily_events: u32,
    daily_batches: u32,
    /// client_event_id -> 首次成功上报的 Unix 秒时间戳
    reported: HashMap<String, i64>,
}

static DEDUP_STATE: OnceLock<Mutex<TelemetryDedupStore>> = OnceLock::new();
static TELEMETRY_HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
static FEEDBACK_HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn telemetry_http_client() -> &'static reqwest::Client {
    TELEMETRY_HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

fn feedback_http_client() -> &'static reqwest::Client {
    FEEDBACK_HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(6))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

fn dedup_store_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".fd-claude-guard").join("telemetry-dedup.json"))
}

fn load_dedup_store_from(path: &Path) -> TelemetryDedupStore {
    let Ok(raw) = fs::read_to_string(path) else {
        return TelemetryDedupStore::default();
    };
    serde_json::from_str::<TelemetryDedupStore>(&raw).unwrap_or_default()
}

fn persist_dedup_store_to(path: &Path, store: &TelemetryDedupStore) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json_str) = serde_json::to_string_pretty(store) {
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, json_str).is_ok() {
            if fs::rename(&tmp, path).is_err() {
                let _ = fs::remove_file(&tmp);
            }
        }
    }
}

fn dedup_store_mutex() -> &'static Mutex<TelemetryDedupStore> {
    DEDUP_STATE.get_or_init(|| {
        let loaded = dedup_store_path()
            .map(|p| load_dedup_store_from(&p))
            .unwrap_or_default();
        Mutex::new(loaded)
    })
}

fn prune_and_roll_day(store: &mut TelemetryDedupStore, today: &str, now_unix: i64) {
    if store.day_key != today {
        store.day_key = today.to_string();
        store.daily_events = 0;
        store.daily_batches = 0;
    }
    store
        .reported
        .retain(|_, ts| now_unix.saturating_sub(*ts) <= DEDUP_RETENTION_SECS);
    if store.reported.len() > DEDUP_MAX_ENTRIES {
        let mut pairs: Vec<(String, i64)> =
            store.reported.iter().map(|(k, v)| (k.clone(), *v)).collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(DEDUP_MAX_ENTRIES);
        store.reported = pairs.into_iter().collect();
    }
}

/// 纯函数：从候选事件列表中按已去重集合 + 单机当日剩余配额筛选出允许发网的事件列表
fn filter_events_with_quota(
    store: &mut TelemetryDedupStore,
    candidates: Vec<Value>,
    today: &str,
    now_unix: i64,
) -> Vec<Value> {
    prune_and_roll_day(store, today, now_unix);
    if store.daily_batches >= DAILY_MAX_BATCHES || store.daily_events >= DAILY_MAX_EVENTS {
        return Vec::new();
    }
    let remaining_quota = (DAILY_MAX_EVENTS - store.daily_events) as usize;
    let mut selected = Vec::new();
    let mut batch_seen = std::collections::HashSet::new();

    for ev in candidates {
        if selected.len() >= remaining_quota {
            break;
        }
        let cid = ev
            .get("client_event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if !cid.is_empty() {
            if store.reported.contains_key(&cid) || !batch_seen.insert(cid) {
                continue;
            }
        }
        selected.push(ev);
    }
    selected
}

/// 仅在 HTTP 2xx 确认服务端落库成功后，才提交去重指纹与单机日配额
fn commit_reported_events(
    store: &mut TelemetryDedupStore,
    sent_events: &[Value],
    today: &str,
    now_unix: i64,
) {
    prune_and_roll_day(store, today, now_unix);
    store.daily_batches = store.daily_batches.saturating_add(1);
    store.daily_events = store
        .daily_events
        .saturating_add(sent_events.len().min(u32::MAX as usize) as u32);
    for ev in sent_events {
        if let Some(cid) = ev.get("client_event_id").and_then(|v| v.as_str()) {
            let trimmed = cid.trim();
            if !trimmed.is_empty() {
                store.reported.insert(trimmed.to_string(), now_unix);
            }
        }
    }
    prune_and_roll_day(store, today, now_unix);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedbackReportResult {
    pub ticket_id: String,
    pub created_at: String,
    pub uploaded_bytes: usize,
    pub endpoint_used: String,
    pub message: String,
}

/// 从现有授权服务 API URL（如 `https://xxx/api/v1/activate`）推导同源 Worker 根路径
pub fn derive_worker_base_url(activate_endpoint: Option<&str>) -> Option<String> {
    let raw = activate_endpoint?.trim();
    if raw.is_empty() || !raw.starts_with("http") {
        return None;
    }
    let trimmed = raw.trim_end_matches('/');
    if let Some(prefix) = trimmed.strip_suffix("/api/v1/activate") {
        Some(prefix.to_string())
    } else if let Some(idx) = trimmed.find("/api/v1/") {
        Some(trimmed[..idx].to_string())
    } else {
        Some(trimmed.to_string())
    }
}

/// 判断单条 Claude 日志事件是否符合 L2 后台静默遥测准入条件：
/// 仅采集非模拟的高危实锤事件（`level == "fail"`），严格排除所有 `warn`（含难以区分 Free/KYC 的 403 `len=164/156`、`OAuth v2 鉴权`、529 过载、普通网络断连）
pub fn is_eligible_for_l2_claude_telemetry(ev: &LogEvent) -> bool {
    ev.anomaly && !ev.simulated && ev.level == "fail"
}

/// 构建统一脱敏载荷（同时供前端预览 JSON 与 L3 一键匿名上报排障复用）
pub fn build_anonymized_feedback_payload(
    install_id_short: &str,
    snapshot: &GuardSnapshot,
    report: &PreflightReport,
    logs: &[LogEvent],
    tz_jump_warning: Option<&str>,
) -> Value {
    let acct_audit = audit_claude_logs_for_accounts();
    let attribution = build_ban_attribution_snapshot(
        logs,
        &acct_audit,
        tz_jump_warning,
        &snapshot.region_code,
        snapshot.node_drift_warn,
        snapshot.kill_switch_active,
    );

    let failed_checks: Vec<Value> = report
        .items
        .iter()
        .filter(|i| i.status != CheckStatus::Ok)
        .map(|i| {
            json!({
                "id": i.id,
                "status": format!("{:?}", i.status).to_lowercase(),
                "summary": sanitize_for_telemetry(&i.summary),
            })
        })
        .collect();

    // L3 人工一键排障上报：采集命中的 fail / warn 摘要（最多 20 条，绝不传 ok 与对话内容）
    let claude_error_events: Vec<Value> = logs
        .iter()
        .filter(|e| e.anomaly && !e.simulated)
        .take(20)
        .map(|e| {
            let first_line = e.context.lines().next().unwrap_or("");
            let sig = sanitize_for_telemetry(first_line);
            let compact_sig: String = sig.chars().take(180).collect();
            json!({
                "id": e.id,
                "tag": e.tag,
                "level": e.level,
                "ruleId": e.rule_id,
                "repeatCount": e.repeat_count.max(1),
                "signature": compact_sig,
            })
        })
        .collect();

    // 仅采集最近 15 条 FDtools 自身 WARN/ERROR 运行日志
    let recent_tool_errors: Vec<String> = crate::logger::read_recent_logs(60)
        .into_iter()
        .filter(|line| line.contains("\"WARN\"") || line.contains("\"ERROR\""))
        .rev()
        .take(15)
        .map(|l| sanitize_for_telemetry(&l))
        .collect();

    let normalized_install_id = if install_id_short.is_empty() {
        "anonymous"
    } else {
        install_id_short
    };
    let raw_payload = json!({
        "schemaVersion": 2,
        "appVersion": env!("CARGO_PKG_VERSION"),
        "app_version": env!("CARGO_PKG_VERSION"),
        "installIdHash": normalized_install_id,
        "install_id_hash": normalized_install_id,
        "toolDiagnostics": {
            "clashVersion": sanitize_for_telemetry(&snapshot.clash_version),
            "clashPort": snapshot.clash_port,
            "clashOnline": snapshot.clash_online,
            "regionCode": snapshot.region_code,
            "killSwitchActive": snapshot.kill_switch_active,
            "mustPassed": snapshot.must_passed,
            "mustTotal": snapshot.must_total,
            "failedChecks": failed_checks,
            "recentToolErrors": recent_tool_errors,
        },
        "claudeErrorEvents": claude_error_events,
        "preBanAttribution72h": attribution,
    });

    sanitize_json_value_for_telemetry(raw_payload)
}

/// T-303：用户主动触发「一键匿名上报排障」，POST 到 Worker `/api/v1/feedback/report` 生成唯一排障单号
pub async fn submit_anonymous_feedback_report(
    api_endpoint: Option<&str>,
    install_id_short: &str,
    snapshot: &GuardSnapshot,
    report: &PreflightReport,
    logs: &[LogEvent],
    tz_jump_warning: Option<&str>,
) -> Result<FeedbackReportResult, String> {
    let base = derive_worker_base_url(api_endpoint).ok_or_else(|| {
        "当前版本未配置云端遥测服务地址，请改用「导出脱敏 AI 诊断包」手动发送。".to_string()
    })?;
    let url = format!("{base}/api/v1/feedback/report");

    // 重磁盘日志扫描移入 spawn_blocking，不阻塞 async 工作线程
    let install_owned = install_id_short.to_string();
    let snap_owned = snapshot.clone();
    let report_owned = report.clone();
    let logs_owned = logs.to_vec();
    let tz_owned = tz_jump_warning.map(|s| s.to_string());
    let payload = tokio::task::spawn_blocking(move || {
        build_anonymized_feedback_payload(
            &install_owned,
            &snap_owned,
            &report_owned,
            &logs_owned,
            tz_owned.as_deref(),
        )
    })
    .await
    .map_err(|e| format!("构造脱敏载荷任务异常: {e}"))?;

    let body_str =
        serde_json::to_string(&payload).map_err(|e| format!("序列化脱敏载荷失败: {e}"))?;
    let uploaded_bytes = body_str.len();

    let resp = feedback_http_client()
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body_str)
        .send()
        .await
        .map_err(|e| format!("连接匿名排障上报服务失败（可改用本地导出脱敏诊断包）：{e}"))?;

    let status = resp.status();
    let resp_json: Value = resp
        .json()
        .await
        .map_err(|e| format!("解析上报服务响应失败 (HTTP {status}): {e}"))?;

    if !status.is_success() || resp_json.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let msg = resp_json
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("服务端拒绝或尚未升级遥测表结构");
        return Err(format!("匿名上报未完成 (HTTP {status})：{msg}"));
    }

    let ticket_id = resp_json
        .get("ticket_id")
        .and_then(|v| v.as_str())
        .unwrap_or("FD-UNKNOWN")
        .to_string();
    let created_at = resp_json
        .get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(FeedbackReportResult {
        ticket_id: ticket_id.clone(),
        created_at,
        uploaded_bytes,
        endpoint_used: url,
        message: format!("已通过统一脱敏管线匿名上报，排障单号：{ticket_id}"),
    })
}

/// T-302：L2 严格低频高价值后台静默遥测
/// - 严格受双开关控制
/// - Claude 日志仅收 `level == "fail"`（严禁上报 Free/KYC 403 `warn`、`OAuth v2 鉴权`、529、普通断连）
/// - 跨重启持久化去重 + 单机每日硬上限（10 条事件 / 3 批请求）
/// - 仅 HTTP 2xx 成功后落盘去重与计数，断网不丢指纹、超时 2s 静默放弃
pub async fn flush_telemetry_events_if_enabled(
    cfg: &AppConfig,
    api_endpoint: Option<&str>,
    install_id_short: &str,
    snapshot: &GuardSnapshot,
    new_claude_events: &[LogEvent],
    tool_events: Vec<Value>,
) {
    if !cfg.telemetry_tool_diag_enabled && !cfg.telemetry_claude_summary_enabled {
        return;
    }
    let Some(base) = derive_worker_base_url(api_endpoint) else {
        return;
    };

    let mut candidates: Vec<Value> = Vec::new();

    // 1. Claude 高危实锤日志（仅 level == "fail"）
    if cfg.telemetry_claude_summary_enabled {
        let eligible_claude: Vec<LogEvent> = new_claude_events
            .iter()
            .filter(|e| is_eligible_for_l2_claude_telemetry(e))
            .cloned()
            .collect();
        if !eligible_claude.is_empty() {
            let snap_region = snapshot.region_code.clone();
            let snap_drift = snapshot.node_drift_warn;
            let snap_ks = snapshot.kill_switch_active;
            let evs_for_attr = eligible_claude.clone();
            let attr = tokio::task::spawn_blocking(move || {
                let acct_audit = audit_claude_logs_for_accounts();
                build_ban_attribution_snapshot(
                    &evs_for_attr,
                    &acct_audit,
                    None,
                    &snap_region,
                    snap_drift,
                    snap_ks,
                )
            })
            .await
            .ok();

            for ev in &eligible_claude {
                let sig = sanitize_for_telemetry(ev.context.lines().next().unwrap_or(""));
                let (factors, org_cnt) = match &attr {
                    Some(a) => (a.top_risk_factors.clone(), a.unique_org_hash_count),
                    None => (Vec::new(), 0),
                };
                candidates.push(sanitize_json_value_for_telemetry(json!({
                    "category": "claude_error",
                    "event_type": "claude_log_alert",
                    "level": ev.level,
                    "tag": ev.tag,
                    "signature": sig.chars().take(180).collect::<String>(),
                    "repeat_count": ev.repeat_count.max(1),
                    "pre_ban_factors": factors,
                    "env": {
                        "region": snapshot.region_code,
                        "clashPort": snapshot.clash_port,
                        "driftWarn": snapshot.node_drift_warn,
                        "uniqueOrgHashCount": org_cnt,
                    },
                    "client_event_id": format!("claude:{}", ev.id),
                })));
            }
        }
    }

    // 2. 工具自身高价值诊断事件（仅修复真实失败 / 4 层熔断 / 防裸奔拦截等真实异常）
    if cfg.telemetry_tool_diag_enabled {
        for tev in tool_events {
            candidates.push(sanitize_json_value_for_telemetry(tev));
        }
    }

    if candidates.is_empty() {
        return;
    }

    let today = chrono::Local::now().format("%Y%m%d").to_string();
    let now_unix = chrono::Utc::now().timestamp();

    let batch = {
        let Ok(mut store) = dedup_store_mutex().lock() else {
            return;
        };
        filter_events_with_quota(&mut store, candidates, &today, now_unix)
    };

    if batch.is_empty() {
        return;
    }

    let url = format!("{base}/api/v1/telemetry/batch");
    let body = json!({
        "install_id_hash": if install_id_short.is_empty() { "anonymous" } else { install_id_short },
        "app_version": env!("CARGO_PKG_VERSION"),
        "events": batch,
    });

    // 仅 HTTP 2xx 成功后落盘去重集与配额
    if let Ok(resp) = telemetry_http_client().post(&url).json(&body).send().await {
        if resp.status().is_success() {
            let store_snapshot = if let Ok(mut store) = dedup_store_mutex().lock() {
                commit_reported_events(&mut store, &batch, &today, now_unix);
                Some(store.clone())
            } else {
                None
            };
            if let (Some(snap_store), Some(path)) = (store_snapshot, dedup_store_path()) {
                let _ = tokio::task::spawn_blocking(move || {
                    persist_dedup_store_to(&path, &snap_store);
                })
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watchdog::parse_log_line;
    use tempfile::tempdir;

    #[test]
    fn t302_derive_worker_base_url_strips_activate_path() {
        assert_eq!(
            derive_worker_base_url(Some("https://fd-lic.example.workers.dev/api/v1/activate")),
            Some("https://fd-lic.example.workers.dev".to_string())
        );
        assert_eq!(derive_worker_base_url(Some("")), None);
        assert_eq!(derive_worker_base_url(None), None);
    }

    #[test]
    fn t303_sanitize_for_telemetry_strips_uuid_sub_token_json_path_and_jwt() {
        let raw = r#"url=https://sub.example.net/api/v1/client/subscribe/AbCdEf123456?token=deadbeef01234567 orgId=11111111-2222-4333-8444-555555555555 user=alice@test.com path="C:\\Users\\alice\\AppData" jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c \"sessionKey\":\"sk-secret-99999\""#;
        let clean = sanitize_for_telemetry(raw);
        assert!(!clean.contains("deadbeef01234567"));
        assert!(!clean.contains("AbCdEf123456"));
        assert!(!clean.contains("11111111-2222-4333-8444-555555555555"));
        assert!(!clean.contains("alice@test.com"));
        assert!(!clean.contains("alice"));
        assert!(!clean.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(!clean.contains("sk-secret-99999"));
    }

    #[test]
    fn batch2_l2_telemetry_excludes_warn_and_free_403_noise_and_allows_fail_only() {
        // Free/KYC 403 len=164（warn）必须被 L2 过滤，绝不主动上报
        let free_or_kyc = parse_log_line(
            "main.log",
            10,
            "2026-11-24 01:42:49 [info] oauth failed: authorize returned 403 <json error=permission_error len=164>",
        )
        .unwrap();
        assert_eq!(free_or_kyc.level, "warn");
        assert!(!is_eligible_for_l2_claude_telemetry(&free_or_kyc));

        // OAuth v2 鉴权（warn）与 529 官方过载（warn）必须被 L2 过滤
        let oauth_v2 = parse_log_line(
            "main.log",
            11,
            "2026-11-24 01:42:49 [info] [oauth-v2] fresh exchange failed for orgId=11111111 (auth_error)",
        )
        .unwrap();
        assert!(!is_eligible_for_l2_claude_telemetry(&oauth_v2));

        let overloaded = parse_log_line(
            "main.log",
            12,
            "2026-11-24 10:10:00 [warn] Anthropic API overloaded_error status=529",
        )
        .unwrap();
        assert!(!is_eligible_for_l2_claude_telemetry(&overloaded));

        // 确认封号 / 验证受限（fail）允许进入 L2
        let banned = parse_log_line(
            "main.log",
            13,
            "2026-11-23 12:54:05 [error] oauth failed: authorize returned 403 <json error=permission_error len=130> OAuth token revoked",
        )
        .unwrap();
        assert_eq!(banned.level, "fail");
        assert!(is_eligible_for_l2_claude_telemetry(&banned));
    }

    #[test]
    fn batch2_dedup_persistence_and_daily_quota_enforcement() {
        let dir = tempdir().unwrap();
        let store_path = dir.path().join("telemetry-dedup.json");
        let mut store = TelemetryDedupStore::default();
        let now = 1_795_000_000i64;

        // 1. 生成 15 条不同事件：受 DAILY_MAX_EVENTS=10 截断，仅允许 10 条
        let cands: Vec<Value> = (0..15)
            .map(|i| json!({ "client_event_id": format!("ev-{i}") }))
            .collect();
        let selected = filter_events_with_quota(&mut store, cands.clone(), "20261125", now);
        assert_eq!(selected.len(), DAILY_MAX_EVENTS as usize);

        // 未提交前（模拟断网失败），再次过滤仍可重发
        let retry_before_commit = filter_events_with_quota(&mut store, cands.clone(), "20261125", now);
        assert_eq!(retry_before_commit.len(), DAILY_MAX_EVENTS as usize);

        // 模拟 HTTP 2xx 成功后落盘
        commit_reported_events(&mut store, &selected, "20261125", now);
        persist_dedup_store_to(&store_path, &store);

        // 模拟进程重启后重新加载：当日配额已满，且已报指纹被过滤
        let mut reloaded = load_dedup_store_from(&store_path);
        assert!(filter_events_with_quota(&mut reloaded, cands.clone(), "20261125", now).is_empty());

        // 跨日后（20261126）：当日配额清零，但 7 天内已报过的 10 条仍被去重，仅剩 5 条新指纹
        let next_day = filter_events_with_quota(&mut reloaded, cands, "20261126", now + 86_400);
        assert_eq!(next_day.len(), 5);
    }

    #[test]
    fn v041_b08_feedback_payload_includes_snake_and_camel_install_and_version_fields() {
        let snap = crate::state::build_initial_snapshot(&AppConfig::default());
        let report = PreflightReport {
            checked_at: "2026-11-27 18:00:00".into(),
            stage: "ready".into(),
            items: Vec::new(),
        };
        let payload = build_anonymized_feedback_payload("9f2a8c1d", &snap, &report, &[], None);
        assert_eq!(payload.get("install_id_hash").and_then(|v| v.as_str()), Some("9f2a8c1d"));
        assert_eq!(payload.get("installIdHash").and_then(|v| v.as_str()), Some("9f2a8c1d"));
        assert_eq!(
            payload.get("app_version").and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            payload.get("appVersion").and_then(|v| v.as_str()),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }
}
