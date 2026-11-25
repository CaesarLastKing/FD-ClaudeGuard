//! 账户审计统一聚合模块（`T-058`）。
//!
//! 职责：
//! 1. 高辨识自适应脱敏邮箱（`mask_email_readable`）与跨洲属地一致性判定；
//! 2. 持久化脱敏云端缓存（`%LOCALAPPDATA%\FDClaudeGuard\account-audit-cache.json`，按 `profile_id` 命名空间隔离，7 天时效衰减且 `workspaceGeo` 永久有效）；
//! 3. 3 层零风控额度提精（本地缓存 + 离线 `.jsonl` 过窗校正 + 按需云端校准）；
//! 4. 面向桌面端的统一 `AccountAuditReport` 聚合与修复动作（First-Write-Wins 可撤回）；
//! 5. 面向外部的唯一极简只读脱敏 API 契约（`POST /v1/audit/check-sk` DTO 与纯异步处理器）。

pub mod cloud_probe;
pub mod disambiguate;
pub mod local_scan;
pub mod score;

use chrono::{DateTime, Utc};
use cloud_probe::{
    probe_session_key_readonly, CloudProbeError, CloudProbeErrorCode, CloudProbeOptions,
    CloudProbeSnapshot,
};
use disambiguate::{disambiguate_403, AccountFacts, DataSource, Log403Input};
use local_scan::{
    scan_local_profile, LocalAccountAudit, ProfileContext, API_ENDPOINT_ENV_KEYS, PRIVACY_ENV_KEYS,
};
use score::{compute_risk_score, RiskScoreInput, ScoreConfidenceMode, ScoreResult};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// 云端状态时效衰减周期（7 天）
pub const CLOUD_CACHE_TTL_MS: i64 = 7 * 86_400_000;
/// 本地缓存 5h 窗口过期判定阈值
const FIVE_HOUR_MS: i64 = 5 * 3_600_000;

/// 高辨识自适应脱敏邮箱（严格对齐 `docs/handoff-v030-account-audit.md` 3.2 节第 4 条）：
/// - `len >= 8` → 前 4 + `***` + 后 2（如 `stev***88@gmail.com`）
/// - `5..=7` → 前 3 + `***` + 后 2
/// - `3..=4` → 前 2 + `***` + 后 1
/// - `<= 2` → 前 1 + `***`
pub fn mask_email_readable(email: &str) -> String {
    let trimmed = email.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return "***".to_string();
    };
    let chars: Vec<char> = local.chars().collect();
    let len = chars.len();
    let masked_local = if len >= 8 {
        let head: String = chars[..4].iter().collect();
        let tail: String = chars[len - 2..].iter().collect();
        format!("{head}***{tail}")
    } else if len >= 5 {
        let head: String = chars[..3].iter().collect();
        let tail: String = chars[len - 2..].iter().collect();
        format!("{head}***{tail}")
    } else if len >= 3 {
        let head: String = chars[..2].iter().collect();
        let tail: String = chars[len - 1..].iter().collect();
        format!("{head}***{tail}")
    } else if len >= 1 {
        format!("{}***", chars[0])
    } else {
        "***".to_string()
    };
    format!("{masked_local}@{domain}")
}

/// 国家/地区码映射至大洲，用于精准区分「同区一致 / 同洲异国 / 跨洲错配」
pub fn country_to_continent(code: &str) -> Option<&'static str> {
    match code.trim().to_ascii_uppercase().as_str() {
        "US" | "CA" | "MX" => Some("NA"),
        "GB" | "UK" | "DE" | "FR" | "NL" | "IE" | "CH" | "SE" | "NO" | "FI" | "IT" | "ES"
        | "PL" | "AT" | "BE" => Some("EU"),
        "JP" | "SG" | "KR" | "TW" | "IN" | "MY" | "TH" | "VN" | "ID" | "PH" | "HK" | "CN" => {
            Some("AS")
        }
        "AU" | "NZ" => Some("OC"),
        "BR" | "AR" | "CL" | "CO" => Some("SA"),
        _ => None,
    }
}

/// 归属地 × 出口一致性比较结果
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoConsistency {
    Pending,
    Match,
    SameContinentDiffCountry,
    CrossContinentMismatch,
}

/// 比对账户归属地与当前代理出口国家码
pub fn evaluate_geo_consistency(
    workspace_geo: Option<&str>,
    exit_country: Option<&str>,
) -> GeoConsistency {
    let Some(wg) = workspace_geo.map(str::trim).filter(|s| !s.is_empty()) else {
        return GeoConsistency::Pending;
    };
    let Some(ec) = exit_country
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("GL"))
    else {
        return GeoConsistency::Pending;
    };
    if wg.eq_ignore_ascii_case(ec) {
        return GeoConsistency::Match;
    }
    match (country_to_continent(wg), country_to_continent(ec)) {
        (Some(c1), Some(c2)) if c1 == c2 => GeoConsistency::SameContinentDiffCountry,
        _ => GeoConsistency::CrossContinentMismatch,
    }
}

// ==================== 持久化脱敏云端缓存（按 profile_id 隔离） ====================

/// 单个档案持久化的脱敏云端核验缓存（严禁存明文 sk 或完整邮箱）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileCloudCache {
    pub profile_id: String,
    /// 已绑定的官方注册归属地（永久有效，不随 7 天衰减清除）
    pub bound_workspace_geo: Option<String>,
    pub bound_org_prefix8: Option<String>,
    pub verify_count: u32,
    pub last_verified_at_ms: Option<i64>,
    pub last_snapshot: Option<CloudProbeSnapshot>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditCacheStore {
    version: u32,
    profiles: HashMap<String, ProfileCloudCache>,
}

/// 缓存文件路径：`%LOCALAPPDATA%\FDClaudeGuard\account-audit-cache.json`
pub fn default_audit_cache_path() -> PathBuf {
    dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("FDClaudeGuard")
        .join("account-audit-cache.json")
}

pub fn load_profile_cloud_cache(path: &Path, profile_id: &str) -> Option<ProfileCloudCache> {
    let raw = fs::read_to_string(path).ok()?;
    let store: AuditCacheStore = serde_json::from_str(raw.trim_start_matches('\u{feff}')).ok()?;
    store.profiles.get(profile_id).cloned()
}

pub fn save_profile_cloud_cache(
    path: &Path,
    cache: &ProfileCloudCache,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建账户审计缓存目录失败: {e}"))?;
    }
    let mut store: AuditCacheStore = fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(raw.trim_start_matches('\u{feff}')).ok())
        .unwrap_or_else(|| AuditCacheStore {
            version: 1,
            profiles: HashMap::new(),
        });
    store.version = 1;
    store.profiles.insert(cache.profile_id.clone(), cache.clone());

    let body = serde_json::to_string_pretty(&store)
        .map_err(|e| format!("序列化账户审计缓存失败: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &body).map_err(|e| format!("写入临时缓存文件失败: {e}"))?;
    if fs::rename(&tmp, path).is_err() {
        fs::write(path, &body).map_err(|e| format!("保存账户审计缓存失败: {e}"))?;
        let _ = fs::remove_file(&tmp);
    }
    Ok(())
}

/// 读取默认档案已持久化的永久绑定归属地（供控制台 `node_geo` 同源联动）
pub fn load_bound_workspace_geo(profile_id: &str) -> Option<String> {
    load_profile_cloud_cache(&default_audit_cache_path(), profile_id)
        .and_then(|c| c.bound_workspace_geo)
}

/// 判断云端快照是否超过 7 天时效
pub fn cloud_cache_age_days(verified_at_ms: i64, now_ms: i64) -> u64 {
    let diff = now_ms.saturating_sub(verified_at_ms);
    (diff / 86_400_000) as u64
}

pub fn is_cloud_cache_stale(verified_at_ms: i64, now_ms: i64) -> bool {
    now_ms.saturating_sub(verified_at_ms) > CLOUD_CACHE_TTL_MS
}

// ==================== 桌面端聚合审计报告 DTO ====================

/// 3 层零风控额度展示结果
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaDisplaySummary {
    pub five_hour_pct: Option<u32>,
    pub seven_day_pct: Option<u32>,
    /// 紧凑时间标签（如 "刚刚" / "9天前" / "12天前" / "未知"）
    pub stamp_short: String,
    /// 完整来源悬浮提示（如 "云端核验 · 刚刚同步" / "本地缓存 · 9 天前采样"）
    pub stamp_tooltip: String,
    /// 若缓存已过期且近 5h 本地 .jsonl 为 0 轮，给出诚实校正提示
    pub five_hour_offline_note: Option<String>,
    pub soft_locked: bool,
    pub source: DataSource,
}

/// 桌面端「实时异常日志流」单条消歧后事件
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogFlowItem {
    pub id: String,
    pub cat: String, // "403" | "net" | "other"
    pub denoised: bool,
    pub chip_label: String,
    pub chip_tone: String, // "danger" | "warn" | "neutral"
    pub title: String,
    pub desc: String,
    pub time_label: String,
    pub raw_sanitized: String,
    pub count: usize,
}

/// 桌面端运行时上下文（由 Tauri AppState 注入，核心逻辑不依赖 `AppHandle`）
#[derive(Debug, Clone, Default)]
pub struct RuntimeGuardContext {
    pub clash_online: bool,
    pub clash_port: u16,
    pub tun_online: bool,
    pub current_node: Option<String>,
    pub exit_country: Option<String>,
    pub exit_colo: Option<String>,
    pub exit_ip_purity: Option<String>,
    pub exit_is_datacenter: bool,
    pub drift_count_24h: u32,
    pub bg_claude_procs: u32,
    pub kill_hold_active: bool,
    pub kill_hold_remaining_secs: u32,
}

/// 桌面端「账户审计」页完整聚合报告 DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountAuditReport {
    pub profile_id: String,
    pub audited_at_ms: i64,
    pub email_masked: String,
    pub org_id_prefix8: Option<String>,
    pub plan: String,
    pub merchant_channel: String,
    pub account_age_days: Option<u64>,
    pub subscription_age_days: Option<u64>,
    pub local_device_age_days: Option<u64>,
    /// 未输 sk 时本地推算（带 `~`），输 sk 后为官方准确到期日
    pub subscription_renew_label: String,
    pub subscription_renew_is_estimated: bool,

    pub workspace_geo: Option<String>,
    pub exit_country: Option<String>,
    pub exit_colo: Option<String>,
    pub exit_ip_purity: Option<String>,
    pub geo_consistency: GeoConsistency,

    pub cloud_verified: bool,
    pub cloud_stale: bool,
    pub cloud_age_days: Option<u64>,
    pub verify_count: u32,
    pub cloud_snapshot: Option<CloudProbeSnapshot>,

    pub quota: QuotaDisplaySummary,
    pub score_result: ScoreResult,
    pub local: LocalAccountAudit,
    pub runtime_clash_port: u16,
    pub runtime_proxy_ok: bool,
    pub runtime_bg_procs: u32,
    pub runtime_kill_hold_active: bool,
    pub runtime_kill_hold_secs: u32,

    pub denoised_oauth_403_count: usize,
    pub log_flow_items: Vec<AuditLogFlowItem>,
    pub pending_issue_count: usize,
    pub has_danger_issue: bool,
}

/// 修复操作返回 DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountAuditActionResult {
    pub ok: bool,
    pub action: String,
    pub message: String,
    pub report: Option<AccountAuditReport>,
}

fn format_short_age(ts_ms: i64, now_ms: i64) -> String {
    let diff_secs = now_ms.saturating_sub(ts_ms) / 1000;
    if diff_secs < 120 {
        "刚刚".into()
    } else if diff_secs < 3600 {
        format!("{}分钟前", diff_secs / 60)
    } else if diff_secs < 86400 {
        format!("{}小时前", diff_secs / 3600)
    } else {
        format!("{}天前", diff_secs / 86400)
    }
}

fn estimate_next_renew_mmdd(sub_created_iso: Option<&str>, now_ms: i64) -> Option<String> {
    let dt = DateTime::parse_from_rfc3339(sub_created_iso?).ok()?;
    let day = dt.format("%d").to_string().parse::<u32>().ok()?;
    let now = DateTime::<Utc>::from_timestamp_millis(now_ms)?;
    let (mut y, mut m) = (
        now.format("%Y").to_string().parse::<i32>().ok()?,
        now.format("%m").to_string().parse::<u32>().ok()?,
    );
    let cur_day = now.format("%d").to_string().parse::<u32>().ok()?;
    if cur_day >= day {
        m += 1;
        if m > 12 {
            m = 1;
            y += 1;
        }
    }
    let _ = y;
    let clamped_day = day.min(28);
    Some(format!("预计续费 ~{:02}-{:02}", m, clamped_day))
}

/// 汇总本地扫描 + 脱敏云端缓存 + 运行时代理态 → 生成桌面端完整 `AccountAuditReport`
pub fn build_account_audit_report(
    local: LocalAccountAudit,
    cache: Option<&ProfileCloudCache>,
    runtime: &RuntimeGuardContext,
) -> AccountAuditReport {
    let now_ms = local.scanned_at_ms;
    let cloud_snap = cache.and_then(|c| c.last_snapshot.clone());
    let last_verified_ms = cache.and_then(|c| c.last_verified_at_ms);
    let cloud_verified = cloud_snap.is_some() && last_verified_ms.is_some();
    let cloud_age_days = last_verified_ms.map(|ts| cloud_cache_age_days(ts, now_ms));
    let cloud_stale = last_verified_ms
        .map(|ts| is_cloud_cache_stale(ts, now_ms))
        .unwrap_or(false);

    // 绑定属地永久有效不衰减
    let workspace_geo = cache
        .and_then(|c| c.bound_workspace_geo.clone())
        .or_else(|| cloud_snap.as_ref().and_then(|s| s.workspace_geo.clone()));

    let exit_country = runtime
        .exit_country
        .clone()
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("GL"))
        .or_else(|| cloud_snap.as_ref().and_then(|s| s.edge_country.clone()));
    let exit_colo = runtime
        .exit_colo
        .clone()
        .or_else(|| cloud_snap.as_ref().and_then(|s| s.edge_colo.clone()));

    let geo_consistency =
        evaluate_geo_consistency(workspace_geo.as_deref(), exit_country.as_deref());

    let email_masked = local
        .claude_json
        .email_masked
        .clone()
        .or_else(|| cloud_snap.as_ref().and_then(|s| s.email_masked.clone()))
        .unwrap_or_else(|| "未检测到本机账号".into());

    let org_id_prefix8 = local
        .claude_json
        .org_uuid_prefix8
        .clone()
        .or_else(|| cloud_snap.as_ref().and_then(|s| s.org_id_prefix8.clone()))
        .or_else(|| local.desktop.org_id_prefixes.first().cloned());

    let plan = cloud_snap
        .as_ref()
        .map(|s| s.plan.clone())
        .filter(|p| !p.is_empty() && p != "未知")
        .or_else(|| local.claude_json.plan_label.clone())
        .or_else(|| {
            local_scan::normalize_plan_label(
                None,
                local.credentials.subscription_type.as_deref(),
                local.credentials.rate_limit_tier.as_deref(),
            )
        })
        .unwrap_or_else(|| "未知".into());

    let merchant_channel = cloud_snap
        .as_ref()
        .and_then(|s| s.merchant_channel.clone())
        .or_else(|| local.claude_json.merchant_channel.clone())
        .unwrap_or_else(|| "渠道未知".into());

    let account_age_days = local
        .claude_json
        .account_age_days
        .or_else(|| cloud_snap.as_ref().and_then(|s| s.account_age_days));
    let subscription_age_days = local
        .claude_json
        .subscription_age_days
        .or_else(|| cloud_snap.as_ref().and_then(|s| s.subscription_age_days));
    let local_device_age_days = local.claude_json.local_device_age_days;

    let (subscription_renew_label, subscription_renew_is_estimated) = match cloud_snap
        .as_ref()
        .and_then(|s| s.subscription_ends_at.as_deref())
    {
        Some(ends) => (format!("到期 {ends}"), false),
        None => match estimate_next_renew_mmdd(
            local.claude_json.subscription_created_at.as_deref(),
            now_ms,
        ) {
            Some(est) => (est, true),
            None => ("预计续费 未知".into(), true),
        },
    };

    // 3 层零风控额度计算
    let quota = build_quota_summary(&local, cloud_snap.as_ref(), last_verified_ms, cloud_stale, now_ms);

    // 7 类 403 消歧日志流组装
    let facts = AccountFacts {
        plan: if plan == "未知" { None } else { Some(plan.clone()) },
        plan_source: if cloud_verified {
            DataSource::OfficialProbe
        } else if local.claude_json.plan_label.is_some() || local.credentials.subscription_type.is_some()
        {
            DataSource::LocalConfig
        } else {
            DataSource::Unknown
        },
        kyc_status: cloud_snap
            .as_ref()
            .and_then(|s| s.persona_kyc_status.clone()),
        kyc_source: if cloud_verified {
            DataSource::OfficialProbe
        } else {
            DataSource::Unknown
        },
        is_banned: cloud_snap
            .as_ref()
            .map(|s| s.is_banned)
            .or_else(|| {
                if local.desktop.account_banned_hits > 0 {
                    Some(true)
                } else {
                    None
                }
            }),
    };

    let mut log_flow_items = Vec::new();
    let mut denoised_oauth_403_count = 0usize;
    for sample in &local.desktop.recent_samples {
        if matches!(
            sample.category.as_str(),
            "account_banned" | "portal_verify" | "oauth_403" | "cookie_403" | "cf_403"
        ) {
            let dis = disambiguate_403(
                &Log403Input {
                    raw_line: &sample.raw_sanitized,
                    status_code: Some(403),
                    cf_mitigated: None,
                    error_code: None,
                },
                &facts,
            );
            if dis.denoised {
                denoised_oauth_403_count += sample.count;
            }
            let chip_tone = match dis.risk_level {
                disambiguate::DisambiguatedRiskLevel::Critical
                | disambiguate::DisambiguatedRiskLevel::High => "danger",
                disambiguate::DisambiguatedRiskLevel::Warn => "warn",
                _ => "neutral",
            };
            log_flow_items.push(AuditLogFlowItem {
                id: sample.id.clone(),
                cat: "403".into(),
                denoised: dis.denoised,
                chip_label: if sample.count > 1 {
                    format!("{} · x{}", dis.chip_label, sample.count)
                } else {
                    dis.chip_label
                },
                chip_tone: chip_tone.into(),
                title: dis.title,
                desc: dis.explanation,
                time_label: format!("{} · {}", sample.time, sample.file_ref),
                raw_sanitized: sample.raw_sanitized.clone(),
                count: sample.count,
            });
        } else if sample.category == "disconnect" {
            log_flow_items.push(AuditLogFlowItem {
                id: sample.id.clone(),
                cat: "net".into(),
                denoised: false,
                chip_label: format!("代理断连 · x{}", sample.count),
                chip_tone: "neutral".into(),
                title: format!(
                    "代理长连接瞬时断开（{} 次回传 Cookie 403）",
                    local.desktop.cookie_403_hits
                ),
                desc: "节点短暂抖动导致连接重置；切换或关闭代理前建议先开启防复活盯防。".into(),
                time_label: format!("{} · {}", sample.time, sample.file_ref),
                raw_sanitized: sample.raw_sanitized.clone(),
                count: sample.count,
            });
        } else if sample.category == "mcp_storm" {
            log_flow_items.push(AuditLogFlowItem {
                id: sample.id.clone(),
                cat: "other".into(),
                denoised: false,
                chip_label: format!("MCP 报错风暴 · x{}", sample.count),
                chip_tone: "warn".into(),
                title: "mcp.log 捕获极端高频循环报错".into(),
                desc: "正常安装 MCP 不会引发封号，但极端死循环报错可能拖慢客户端，建议排查故障插件。"
                    .into(),
                time_label: format!("{} · {}", sample.time, sample.file_ref),
                raw_sanitized: sample.raw_sanitized.clone(),
                count: sample.count,
            });
        }
    }

    // 构造 100 分纯函数评分输入（严禁把 org_level_disabled 算作异常）
    let confidence_mode = if !cloud_verified {
        ScoreConfidenceMode::LocalOnly
    } else if cloud_stale {
        ScoreConfidenceMode::Stale7d
    } else {
        ScoreConfidenceMode::FullCombined
    };

    let account_banned = local.desktop.account_banned_hits > 0
        || cloud_snap.as_ref().map(|s| s.is_banned).unwrap_or(false);
    let portal_hold = cloud_snap.as_ref().map(|s| s.portal_hold).unwrap_or(false);

    let in_new_acct_window = account_age_days.map(|d| d < 7).unwrap_or(false);
    let in_pay_window = subscription_age_days.map(|d| d <= 1).unwrap_or(false);
    let in_kyc_72h_window = cloud_snap
        .as_ref()
        .and_then(|s| s.persona_kyc_age_hours)
        .map(|h| h <= 72)
        .unwrap_or(false);
    let in_high_risk_window =
        in_new_acct_window || in_pay_window || in_kyc_72h_window || local.desktop.plan_changed_hits > 0;

    let persona_kyc_verified_over_72h = cloud_snap
        .as_ref()
        .map(|s| {
            s.persona_kyc_status.as_deref() == Some("verified")
                && s.persona_kyc_age_hours.map(|h| h > 72).unwrap_or(true)
        })
        .unwrap_or(false);

    let non_official_endpoint = local.hygiene.settings_non_official_endpoint.is_some()
        || !local.hygiene.system_env_endpoint_conflicts.is_empty();
    let ban_residue_or_cross_org_404 =
        local.desktop.account_banned_hits > 0 || local.desktop.cross_org_404_hits > 0;
    let cross_client_or_multi_org_mix =
        local.cross_client_org_mismatch || local.desktop.org_id_prefixes.len() > 1;
    let severe_automation_or_429 = local.hygiene.scheduled_tasks_count > 0
        || local.behavior.overnight_bot_rhythm_suspected
        || local.desktop.rate_limit_429_hits >= 3
        || local.desktop.high_side_session_hits > 0;
    let mild_rate_limit_429 =
        !severe_automation_or_429 && local.desktop.rate_limit_429_hits > 0;
    let proxy_or_hold_unready = !runtime.clash_online
        || !runtime.tun_online
        || (runtime.bg_claude_procs > 0 && !runtime.kill_hold_active);

    let score_input = RiskScoreInput {
        confidence_mode: Some(confidence_mode),
        stale_days: cloud_age_days,
        account_banned,
        portal_hold,
        geo_cross_continent_mismatch: geo_consistency == GeoConsistency::CrossContinentMismatch,
        geo_mismatch_detail: if geo_consistency == GeoConsistency::CrossContinentMismatch {
            Some(format!(
                "账号属地 {} 与当前出口 {}{} 跨洲，建议尽快切回同区稳定节点",
                workspace_geo.as_deref().unwrap_or("?"),
                exit_country.as_deref().unwrap_or("?"),
                exit_colo
                    .as_deref()
                    .map(|c| format!("({c})"))
                    .unwrap_or_default()
            ))
        } else {
            None
        },
        datacenter_or_frequent_hop: runtime.exit_is_datacenter || runtime.drift_count_24h >= 2,
        datacenter_or_hop_detail: if runtime.drift_count_24h >= 2 {
            Some(format!(
                "近 24h 检测到 {} 次落地 IP 漂移，建议切换静态稳定节点",
                runtime.drift_count_24h
            ))
        } else {
            None
        },
        non_official_endpoint,
        non_official_endpoint_detail: local
            .hygiene
            .settings_non_official_endpoint
            .clone()
            .or_else(|| local.hygiene.system_env_endpoint_conflicts.first().cloned()),
        ban_residue_or_cross_org_404,
        cross_client_or_multi_org_mix,
        multi_acct_detail: if local.cross_client_org_mismatch {
            Some(format!(
                "CLI ({}) 与桌面端日志 ({}) 组织不一致，存在跨端残留风险",
                local.claude_json.org_uuid_prefix8.as_deref().unwrap_or("无"),
                local.desktop.org_id_prefixes.join(", ")
            ))
        } else {
            None
        },
        cloud_warning_active: cloud_snap
            .as_ref()
            .map(|s| s.has_monitoring_notice)
            .unwrap_or(false),
        cloud_warning_detail: cloud_snap
            .as_ref()
            .and_then(|s| s.warning_summary_zh.clone()),
        in_high_risk_window,
        high_risk_window_detail: None,
        severe_automation_or_429,
        mild_rate_limit_429,
        rhythm_detail: None,
        quit_cookie_403_hit: local.desktop.cookie_403_hits > 0,
        proxy_or_hold_unready,
        disconnect_detail: None,
        telemetry_env_missing_count: local.hygiene.privacy_missing_keys.len(),
        telemetry_dir_bytes: local.hygiene.telemetry_total_bytes,
        persona_kyc_verified_over_72h,
    };

    let score_result = compute_risk_score(&score_input);

    // 计算 7 个分组中存在 warn/danger 的待处理计数（用于左侧徽章）
    let mut pending_issue_count = 0usize;
    let mut has_danger_issue = false;
    if in_high_risk_window {
        pending_issue_count += 1;
    }
    if severe_automation_or_429 || mild_rate_limit_429 {
        pending_issue_count += 1;
        if severe_automation_or_429 {
            has_danger_issue = true;
        }
    }
    if geo_consistency == GeoConsistency::CrossContinentMismatch {
        pending_issue_count += 1;
        has_danger_issue = true;
    }
    if ban_residue_or_cross_org_404 || cross_client_or_multi_org_mix {
        pending_issue_count += 1;
        if ban_residue_or_cross_org_404 {
            has_danger_issue = true;
        }
    }
    if non_official_endpoint {
        pending_issue_count += 1;
        has_danger_issue = true;
    }
    if local.desktop.cookie_403_hits > 0 || proxy_or_hold_unready {
        pending_issue_count += 1;
        if local.desktop.cookie_403_hits > 0 || !runtime.clash_online || !runtime.tun_online {
            has_danger_issue = true;
        }
    }
    if !local.hygiene.privacy_missing_keys.is_empty() || local.hygiene.telemetry_total_bytes > 0 {
        pending_issue_count += 1;
    }
    if account_banned || portal_hold {
        has_danger_issue = true;
    }

    AccountAuditReport {
        profile_id: local.profile_id.clone(),
        audited_at_ms: now_ms,
        email_masked,
        org_id_prefix8,
        plan,
        merchant_channel,
        account_age_days,
        subscription_age_days,
        local_device_age_days,
        subscription_renew_label,
        subscription_renew_is_estimated,
        workspace_geo,
        exit_country,
        exit_colo,
        exit_ip_purity: runtime.exit_ip_purity.clone(),
        geo_consistency,
        cloud_verified,
        cloud_stale,
        cloud_age_days,
        verify_count: cache.map(|c| c.verify_count).unwrap_or(0),
        cloud_snapshot: cloud_snap,
        quota,
        score_result,
        local,
        runtime_clash_port: runtime.clash_port,
        runtime_proxy_ok: runtime.clash_online && runtime.tun_online,
        runtime_bg_procs: runtime.bg_claude_procs,
        runtime_kill_hold_active: runtime.kill_hold_active,
        runtime_kill_hold_secs: runtime.kill_hold_remaining_secs,
        denoised_oauth_403_count,
        log_flow_items,
        pending_issue_count,
        has_danger_issue,
    }
}

/// 3 层零风控额度提精汇总
fn build_quota_summary(
    local: &LocalAccountAudit,
    cloud_snap: Option<&CloudProbeSnapshot>,
    last_verified_ms: Option<i64>,
    cloud_stale: bool,
    now_ms: i64,
) -> QuotaDisplaySummary {
    let soft_locked = local.desktop.five_hour_soft_lock_hits > 0
        || local
            .claude_json
            .cached_usage
            .as_ref()
            .map(|u| u.five_hour_locked_reason.is_some() || u.seven_day_locked_reason.is_some())
            .unwrap_or(false);

    // 优先使用未过期云端核验快照
    if let (Some(snap), Some(v_ms)) = (cloud_snap, last_verified_ms) {
        if snap.five_hour_pct.is_some() || snap.seven_day_pct.is_some() {
            let short = format_short_age(v_ms, now_ms);
            let tooltip = if cloud_stale {
                format!("云端缓存 · {short}核验")
            } else {
                format!("云端核验 · {short}同步")
            };
            let mut five_pct = snap.five_hour_pct.map(|v| v.round().clamp(0.0, 100.0) as u32);
            let mut offline_note = None;
            if now_ms.saturating_sub(v_ms) > FIVE_HOUR_MS
                && local.behavior.last_5h.assistant_turns == 0
                && five_pct.unwrap_or(0) > 0
            {
                offline_note = Some("缓存超 5h 且近 5h 本地 0 轮，实际大概率已重置".into());
                five_pct = Some(0);
            }
            return QuotaDisplaySummary {
                five_hour_pct: five_pct,
                seven_day_pct: snap.seven_day_pct.map(|v| v.round().clamp(0.0, 100.0) as u32),
                stamp_short: short,
                stamp_tooltip: tooltip,
                five_hour_offline_note: offline_note,
                soft_locked,
                source: DataSource::OfficialProbe,
            };
        }
    }

    // 回退到本地 ~/.claude.json 缓存 + 层 2 离线 .jsonl 校正
    if let Some(ref cu) = local.claude_json.cached_usage {
        let fetched_ms = cu.fetched_at_ms.unwrap_or(0);
        let short = if fetched_ms > 0 {
            format_short_age(fetched_ms, now_ms)
        } else {
            "缓存".into()
        };
        let tooltip = if fetched_ms > 0 {
            format!("本地缓存 · {short}采样")
        } else {
            "本地缓存采样".into()
        };
        let cache_expired_5h = fetched_ms > 0 && now_ms.saturating_sub(fetched_ms) > FIVE_HOUR_MS;
        let resets_passed = cu
            .five_hour_resets_at
            .as_deref()
            .and_then(|iso| DateTime::parse_from_rfc3339(iso).ok())
            .map(|dt| dt.timestamp_millis() < now_ms)
            .unwrap_or(false);

        let raw_5h = cu.five_hour_pct.map(|v| v.round().clamp(0.0, 100.0) as u32);
        let (five_pct, offline_note) =
            if (cache_expired_5h || resets_passed) && local.behavior.last_5h.assistant_turns == 0 {
                (
                    Some(0),
                    Some(format!(
                        "本地缓存已滞后（{short}），结合近 5h 本地 0 轮对话校正为 0%"
                    )),
                )
            } else {
                (raw_5h, None)
            };

        let source = if offline_note.is_some() {
            DataSource::OfflineJsonl
        } else {
            DataSource::LocalConfig
        };
        return QuotaDisplaySummary {
            five_hour_pct: five_pct,
            seven_day_pct: cu.seven_day_pct.map(|v| v.round().clamp(0.0, 100.0) as u32),
            stamp_short: short,
            stamp_tooltip: tooltip,
            five_hour_offline_note: offline_note,
            soft_locked,
            source,
        };
    }

    QuotaDisplaySummary {
        five_hour_pct: None,
        seven_day_pct: None,
        stamp_short: "暂无".into(),
        stamp_tooltip: "本机尚无额度缓存，按需云端核验后可同步".into(),
        five_hour_offline_note: None,
        soft_locked,
        source: DataSource::Unknown,
    }
}

// ==================== First-Write-Wins 无损写入 settings.json 纯函数 ====================

/// 纯函数：无损补齐 4/4 隐私降噪环境变量（保留用户自定义 hooks / permissions / 其余 env 键），
/// 并返回 `(新 JSON 内容, 修改前各键的原值映射)` 供 First-Write-Wins 基线捕获。
pub fn patch_settings_json_privacy_4(
    existing_json: Option<&str>,
) -> Result<(String, HashMap<String, Option<String>>), String> {
    let mut root: Value = match existing_json {
        Some(raw) if !raw.trim().is_empty() => {
            serde_json::from_str(raw.trim_start_matches('\u{feff}'))
                .map_err(|e| format!("解析现有 settings.json 失败: {e}"))?
        }
        _ => serde_json::json!({}),
    };
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "settings.json 根节点不是 JSON 对象".to_string())?;
    let env_val = obj
        .entry("env")
        .or_insert_with(|| Value::Object(Map::new()));
    if !env_val.is_object() {
        *env_val = Value::Object(Map::new());
    }
    let env_map = env_val.as_object_mut().expect("env map");

    let mut original_values = HashMap::new();
    for k in PRIVACY_ENV_KEYS {
        let orig = env_map
            .get(k)
            .and_then(|v| v.as_str().map(ToString::to_string));
        original_values.insert(k.to_string(), orig);
        env_map.insert(k.to_string(), Value::String("1".to_string()));
    }

    let pretty =
        serde_json::to_string_pretty(&root).map_err(|e| format!("序列化 settings.json 失败: {e}"))?;
    Ok((pretty, original_values))
}

/// 纯函数：无损移除 `settings.json` 中的非官方 API 端点键，返回 `(新 JSON, 被移除键原值映射)`
pub fn patch_settings_json_restore_official_endpoint(
    existing_json: &str,
) -> Result<(String, HashMap<String, Option<String>>), String> {
    let mut root: Value = serde_json::from_str(existing_json.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("解析 settings.json 失败: {e}"))?;
    let mut removed = HashMap::new();
    if let Some(env_map) = root
        .as_object_mut()
        .and_then(|o| o.get_mut("env"))
        .and_then(|e| e.as_object_mut())
    {
        for k in API_ENDPOINT_ENV_KEYS {
            if let Some(v) = env_map.get(k).and_then(|v| v.as_str()) {
                if local_scan::is_non_official_anthropic_url(v) {
                    removed.insert(k.to_string(), Some(v.to_string()));
                    env_map.remove(k);
                }
            }
        }
    }
    let pretty =
        serde_json::to_string_pretty(&root).map_err(|e| format!("序列化 settings.json 失败: {e}"))?;
    Ok((pretty, removed))
}

/// 纯函数：按首次基线精准撤回 `settings.json` 中被修改的 `env` 键（100% 保留用户后续新增的 hooks / permissions / 其余 env 键）
pub fn rollback_settings_json_env_keys(
    current_json: &str,
    original_env: &std::collections::BTreeMap<String, Option<String>>,
) -> Result<String, String> {
    let mut root: Value = serde_json::from_str(current_json.trim_start_matches('\u{feff}'))
        .map_err(|e| format!("解析 settings.json 失败: {e}"))?;
    let obj = root
        .as_object_mut()
        .ok_or_else(|| "settings.json 根节点不是 JSON 对象".to_string())?;
    let env_val = obj
        .entry("env")
        .or_insert_with(|| Value::Object(Map::new()));
    if !env_val.is_object() {
        *env_val = Value::Object(Map::new());
    }
    let env_map = env_val.as_object_mut().expect("env map");

    for (k, orig) in original_env {
        match orig {
            Some(v) => {
                env_map.insert(k.clone(), Value::String(v.clone()));
            }
            None => {
                env_map.remove(k);
            }
        }
    }
    serde_json::to_string_pretty(&root).map_err(|e| format!("序列化 settings.json 失败: {e}"))
}

/// 共享给桌面端与控制台的一键补齐 4/4 降噪（自动捕获 First-Write-Wins 基线）
pub fn apply_claude_privacy_env_fix(cli_dir: &Path) -> Result<String, String> {
    fs::create_dir_all(cli_dir).map_err(|e| format!("创建 ~/.claude 目录失败: {e}"))?;
    let settings_path = cli_dir.join("settings.json");
    let existed_before = settings_path.exists();
    let existing = fs::read_to_string(&settings_path).ok();
    let (merged, orig_map) = patch_settings_json_privacy_4(existing.as_deref())?;

    crate::rollback::capture_claude_settings_env_baseline_if_needed(
        &settings_path,
        existed_before,
        &orig_map,
    );

    fs::write(&settings_path, merged).map_err(|e| format!("写入 settings.json 失败: {e}"))?;
    Ok("已无损补齐 4/4 隐私降噪环境变量（已锁定首次基线，可随时精准撤回）".into())
}

/// 共享给桌面端与控制台的一键清空 `~/.claude/telemetry` 目录
pub fn clean_claude_telemetry_dir(cli_dir: &Path) -> Result<(usize, u64), String> {
    let tel_dir = cli_dir.join("telemetry");
    if !tel_dir.exists() {
        return Ok((0, 0));
    }
    let mut removed = 0usize;
    let mut freed = 0u64;
    let rd = fs::read_dir(&tel_dir).map_err(|e| format!("读取 telemetry 目录失败: {e}"))?;
    for ent in rd.flatten() {
        let p = ent.path();
        let Ok(meta) = fs::symlink_metadata(&p) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let _ = fs::remove_dir_all(&p);
            removed += 1;
        } else {
            let len = meta.len();
            if fs::remove_file(&p).is_ok() {
                removed += 1;
                freed = freed.saturating_add(len);
            }
        }
    }
    Ok((removed, freed))
}

/// 共享给桌面端与控制台的一键还原官方 API 端点（First-Write-Wins 备份 `settings.json` + HKCU/HKLM 冲突环境变量）
pub fn restore_claude_official_endpoint(
    cli_dir: Option<&Path>,
    clean_system_env: bool,
) -> Result<String, String> {
    let mut actions: Vec<String> = Vec::new();

    if let Some(dir) = cli_dir {
        let settings_path = dir.join("settings.json");
        if settings_path.exists() {
            if let Ok(raw) = fs::read_to_string(&settings_path) {
                let (patched, removed) = patch_settings_json_restore_official_endpoint(&raw)?;
                if !removed.is_empty() {
                    crate::rollback::capture_claude_settings_env_baseline_if_needed(
                        &settings_path,
                        true,
                        &removed,
                    );
                    fs::write(&settings_path, patched)
                        .map_err(|e| format!("写回 settings.json 失败: {e}"))?;
                    actions.push(format!(
                        "已移除 settings.json 中的 {} 项非官方端点",
                        removed.len()
                    ));
                }
            }
        }
    }

    if clean_system_env {
        #[cfg(windows)]
        {
            use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
            use winreg::RegKey;
            let mut hkcu_orig = Vec::new();
            let mut hklm_orig = Vec::new();

            if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
            {
                for k in API_ENDPOINT_ENV_KEYS {
                    if let Ok(v) = key.get_value::<String, _>(k) {
                        if local_scan::is_non_official_anthropic_url(&v) {
                            hkcu_orig.push((k.to_string(), v));
                            let _ = key.delete_value(k);
                        }
                    }
                }
            }
            if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                KEY_READ | KEY_WRITE,
            ) {
                for k in API_ENDPOINT_ENV_KEYS {
                    if let Ok(v) = key.get_value::<String, _>(k) {
                        if local_scan::is_non_official_anthropic_url(&v) {
                            hklm_orig.push((k.to_string(), v));
                            let _ = key.delete_value(k);
                        }
                    }
                }
            }
            if !hkcu_orig.is_empty() || !hklm_orig.is_empty() {
                crate::rollback::capture_sys_env_baseline_if_needed(
                    &hkcu_orig,
                    &hklm_orig,
                    None,
                    None,
                    None,
                );
                actions.push(format!(
                    "已清理 {} 项系统环境变量非官方端点",
                    hkcu_orig.len() + hklm_orig.len()
                ));
            }
        }
    }

    if actions.is_empty() {
        Ok("当前已直连官方原生端点，无需修改。".into())
    } else {
        Ok(format!(
            "{}（已保存首次基线，可随时撤回）。",
            actions.join("；")
        ))
    }
}

/// 桌面端按需 `sk` 核验并落盘脱敏缓存
pub async fn run_desktop_cloud_verify(
    ctx: &ProfileContext,
    cache_path: &Path,
    raw_input: &str,
    runtime: &RuntimeGuardContext,
) -> Result<AccountAuditReport, CloudProbeError> {
    let local = tokio::task::spawn_blocking({
        let c = ctx.clone();
        move || scan_local_profile(&c)
    })
    .await
    .map_err(|_| CloudProbeError {
        code: CloudProbeErrorCode::ProxyOrUpstreamFailed,
        http_status: 502,
        message: "本地扫描任务异常".into(),
        retry_after_secs: None,
    })?;

    let proxy_url = if runtime.clash_online && runtime.clash_port > 0 {
        Some(format!("http://127.0.0.1:{}", runtime.clash_port))
    } else if let Some(p) = ctx.bound_proxy_port {
        Some(format!("http://127.0.0.1:{p}"))
    } else {
        None
    };

    let snap = probe_session_key_readonly(
        raw_input,
        CloudProbeOptions {
            proxy_url,
            expected_org_prefix8: local.claude_json.org_uuid_prefix8.clone(),
            base_url: None,
            timeout_secs: Some(15),
            bypass_cooldown: false,
        },
    )
    .await?;

    let prev = load_profile_cloud_cache(cache_path, &ctx.profile_id);
    let next_cache = ProfileCloudCache {
        profile_id: ctx.profile_id.clone(),
        bound_workspace_geo: snap
            .workspace_geo
            .clone()
            .or_else(|| prev.as_ref().and_then(|p| p.bound_workspace_geo.clone())),
        bound_org_prefix8: snap
            .org_id_prefix8
            .clone()
            .or_else(|| prev.as_ref().and_then(|p| p.bound_org_prefix8.clone())),
        verify_count: prev.as_ref().map(|p| p.verify_count + 1).unwrap_or(1),
        last_verified_at_ms: Some(snap.verified_at_ms),
        last_snapshot: Some(snap),
    };
    let _ = save_profile_cloud_cache(cache_path, &next_cache);

    Ok(build_account_audit_report(local, Some(&next_cache), runtime))
}

// ==================== 外部查分 API 预留契约：POST /v1/audit/check-sk ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSkRequest {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    pub session_key: String,
    #[serde(default)]
    pub proxy_url: Option<String>,
}

fn default_schema_version() -> String {
    "1.0".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSkAccountDto {
    pub email_masked: Option<String>,
    pub org_id_prefix: Option<String>,
    pub plan: String,
    pub merchant_channel: Option<String>,
    pub workspace_geo: Option<String>,
    pub edge_country: Option<String>,
    pub edge_colo: Option<String>,
    pub account_age_days: Option<u64>,
    pub subscription_age_days: Option<u64>,
    pub subscription_ends_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSkCloudStatusDto {
    pub chat_available: bool,
    pub is_banned: bool,
    pub appeals_redirect_enabled: bool,
    pub has_monitoring_notice: bool,
    pub active_flag_types: Vec<String>,
    pub persona_kyc_status: Option<String>,
    pub persona_kyc_completed_at: Option<String>,
    pub portal_hold: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSkUsageDto {
    pub five_hour_pct: Option<u32>,
    pub seven_day_pct: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSkResponse {
    pub schema_version: String,
    pub checked_at: String,
    pub account: CheckSkAccountDto,
    pub cloud_status: CheckSkCloudStatusDto,
    pub usage: CheckSkUsageDto,
    pub score_result: ScoreResult,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSkErrorResponse {
    pub schema_version: String,
    pub error_code: CloudProbeErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

/// 纯函数：将云端探针脱敏快照转换为外部 `POST /v1/audit/check-sk` 标准响应
pub fn build_check_sk_response(snap: CloudProbeSnapshot) -> CheckSkResponse {
    let geo_cmp = evaluate_geo_consistency(
        snap.workspace_geo.as_deref(),
        snap.edge_country.as_deref(),
    );
    let in_high_risk_window = snap.account_age_days.map(|d| d < 7).unwrap_or(false)
        || snap.persona_kyc_age_hours.map(|h| h <= 72).unwrap_or(false);
    let persona_kyc_verified_over_72h = snap.persona_kyc_status.as_deref() == Some("verified")
        && snap.persona_kyc_age_hours.map(|h| h > 72).unwrap_or(true);

    let score_result = compute_risk_score(&RiskScoreInput {
        confidence_mode: Some(ScoreConfidenceMode::CloudOnly),
        account_banned: snap.is_banned,
        portal_hold: snap.portal_hold,
        geo_cross_continent_mismatch: geo_cmp == GeoConsistency::CrossContinentMismatch,
        geo_mismatch_detail: if geo_cmp == GeoConsistency::CrossContinentMismatch {
            Some(format!(
                "账号属地 {} 与当前出口 {}{} 跨洲，建议切回同区稳定节点",
                snap.workspace_geo.as_deref().unwrap_or("?"),
                snap.edge_country.as_deref().unwrap_or("?"),
                snap.edge_colo
                    .as_deref()
                    .map(|c| format!("({c})"))
                    .unwrap_or_default()
            ))
        } else {
            None
        },
        cloud_warning_active: snap.has_monitoring_notice,
        cloud_warning_detail: snap.warning_summary_zh.clone(),
        in_high_risk_window,
        persona_kyc_verified_over_72h,
        ..Default::default()
    });

    CheckSkResponse {
        schema_version: "1.0".into(),
        checked_at: snap.checked_at_iso,
        account: CheckSkAccountDto {
            email_masked: snap.email_masked,
            org_id_prefix: snap.org_id_prefix8,
            plan: snap.plan,
            merchant_channel: snap.merchant_channel,
            workspace_geo: snap.workspace_geo,
            edge_country: snap.edge_country,
            edge_colo: snap.edge_colo,
            account_age_days: snap.account_age_days,
            subscription_age_days: snap.subscription_age_days,
            subscription_ends_at: snap.subscription_ends_at,
        },
        cloud_status: CheckSkCloudStatusDto {
            chat_available: snap.chat_available,
            is_banned: snap.is_banned,
            appeals_redirect_enabled: snap.appeals_redirect_enabled,
            has_monitoring_notice: snap.has_monitoring_notice,
            active_flag_types: snap.active_flag_types,
            persona_kyc_status: snap.persona_kyc_status,
            persona_kyc_completed_at: snap.persona_kyc_completed_at,
            portal_hold: snap.portal_hold,
        },
        usage: CheckSkUsageDto {
            five_hour_pct: snap.five_hour_pct.map(|v| v.round().clamp(0.0, 100.0) as u32),
            seven_day_pct: snap.seven_day_pct.map(|v| v.round().clamp(0.0, 100.0) as u32),
        },
        score_result,
        warnings: snap.warnings,
    }
}

/// 外部 `POST /v1/audit/check-sk` 零耦合核心处理入口（未来直接套轻量 HTTP 路由即可上线）
pub async fn handle_external_check_sk(
    req: CheckSkRequest,
) -> Result<CheckSkResponse, CheckSkErrorResponse> {
    let snap = probe_session_key_readonly(
        &req.session_key,
        CloudProbeOptions {
            proxy_url: req.proxy_url,
            expected_org_prefix8: None,
            base_url: None,
            timeout_secs: Some(15),
            bypass_cooldown: false,
        },
    )
    .await
    .map_err(|e| CheckSkErrorResponse {
        schema_version: "1.0".into(),
        error_code: e.code,
        message: e.message,
        retry_after_secs: e.retry_after_secs,
    })?;

    Ok(build_check_sk_response(snap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    #[test]
    fn adaptive_mask_email_readable_rules() {
        assert_eq!(
            mask_email_readable("steven.chen88@gmail.com"),
            "stev***88@gmail.com"
        );
        assert_eq!(mask_email_readable("alice99@a.com"), "ali***99@a.com");
        assert_eq!(mask_email_readable("abcd@a.com"), "ab***d@a.com");
        assert_eq!(mask_email_readable("ab@a.com"), "a***@a.com");
        assert_eq!(mask_email_readable("no-at-sign"), "***");
    }

    #[test]
    fn geo_consistency_distinguishes_match_same_continent_and_cross_continent() {
        assert_eq!(
            evaluate_geo_consistency(Some("US"), Some("US")),
            GeoConsistency::Match
        );
        assert_eq!(
            evaluate_geo_consistency(Some("US"), Some("CA")),
            GeoConsistency::SameContinentDiffCountry
        );
        assert_eq!(
            evaluate_geo_consistency(Some("US"), Some("AU")),
            GeoConsistency::CrossContinentMismatch
        );
        assert_eq!(
            evaluate_geo_consistency(None, Some("US")),
            GeoConsistency::Pending
        );
    }

    #[test]
    fn settings_json_patch_and_precise_rollback_preserves_user_hooks() {
        let initial = r#"{
          "env": {
            "DISABLE_ERROR_REPORTING": "1",
            "USER_CUSTOM_VAR": "keep_me"
          },
          "permissions": { "allow": ["Bash(git status)"] },
          "hooks": { "PreToolUse": [] }
        }"#;

        let (patched, orig) = patch_settings_json_privacy_4(Some(initial)).unwrap();
        let v_patched: Value = serde_json::from_str(&patched).unwrap();
        for k in PRIVACY_ENV_KEYS {
            assert_eq!(
                v_patched["env"][k].as_str(),
                Some("1"),
                "expected {k} to be patched to 1"
            );
        }
        assert_eq!(v_patched["env"]["USER_CUSTOM_VAR"].as_str(), Some("keep_me"));
        assert!(v_patched["hooks"]["PreToolUse"].is_array());

        let orig_bt: BTreeMap<String, Option<String>> = orig.into_iter().collect();
        let reverted = rollback_settings_json_env_keys(&patched, &orig_bt).unwrap();
        let v_rev: Value = serde_json::from_str(&reverted).unwrap();
        assert_eq!(v_rev["env"]["DISABLE_ERROR_REPORTING"].as_str(), Some("1"));
        assert!(v_rev["env"].get("DISABLE_TELEMETRY").is_none());
        assert!(v_rev["env"].get("DISABLE_BUG_COMMAND").is_none());
        assert!(v_rev["env"]
            .get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC")
            .is_none());
        assert_eq!(v_rev["env"]["USER_CUSTOM_VAR"].as_str(), Some("keep_me"));
        assert!(v_rev["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn external_check_sk_response_matches_contract_and_sanitizes() {
        let snap = CloudProbeSnapshot {
            verified_at_ms: 1_795_500_000_000,
            checked_at_iso: "2026-11-26T09:05:00+11:00".into(),
            email_masked: Some("stev***88@gmail.com".into()),
            org_id_prefix8: Some("7aacf131".into()),
            plan: "Pro".into(),
            merchant_channel: Some("Stripe 直付".into()),
            workspace_geo: Some("US".into()),
            edge_country: Some("AU".into()),
            edge_colo: Some("SYD".into()),
            account_age_days: Some(33),
            subscription_age_days: Some(33),
            subscription_ends_at: Some("2026-12-22".into()),
            chat_available: true,
            is_banned: false,
            appeals_redirect_enabled: false,
            has_monitoring_notice: true,
            active_flag_types: vec!["monitoring_notice".into()],
            warning_summary_zh: Some("后台观察标".into()),
            persona_kyc_status: Some("verified".into()),
            persona_kyc_completed_at: Some("2026-10-24T00:00:00Z".into()),
            persona_kyc_age_hours: Some(720),
            portal_hold: false,
            portal_state: "clear".into(),
            five_hour_pct: Some(34.0),
            five_hour_resets_at: None,
            seven_day_pct: Some(64.0),
            seven_day_resets_at: None,
            warnings: Vec::new(),
        };

        let resp = build_check_sk_response(snap);
        assert_eq!(resp.schema_version, "1.0");
        assert_eq!(resp.account.email_masked.as_deref(), Some("stev***88@gmail.com"));
        assert_eq!(resp.account.org_id_prefix.as_deref(), Some("7aacf131"));
        assert_eq!(resp.usage.five_hour_pct, Some(34));
        assert_eq!(resp.usage.seven_day_pct, Some(64));
        assert_eq!(resp.score_result.score, 69);
        assert_eq!(resp.score_result.level, "mid_high");
        assert_eq!(resp.score_result.confidence, "cloud_only");
    }

    #[test]
    fn cloud_cache_persists_per_profile_and_decays_after_7_days() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("account-audit-cache.json");
        let now_ms = 1_795_500_000_000i64;
        let old_ms = now_ms - 12 * 86_400_000;

        let cache = ProfileCloudCache {
            profile_id: "default".into(),
            bound_workspace_geo: Some("US".into()),
            bound_org_prefix8: Some("7aacf131".into()),
            verify_count: 1,
            last_verified_at_ms: Some(old_ms),
            last_snapshot: None,
        };
        save_profile_cloud_cache(&path, &cache).unwrap();

        let loaded = load_profile_cloud_cache(&path, "default").unwrap();
        assert_eq!(loaded.bound_workspace_geo.as_deref(), Some("US"));
        assert!(is_cloud_cache_stale(old_ms, now_ms));
        assert_eq!(cloud_cache_age_days(old_ms, now_ms), 12);
        assert!(load_profile_cloud_cache(&path, "other-profile").is_none());
    }

    #[test]
    fn cli_credentials_cleanup_backs_up_strips_oauth_and_restores_cleanly() {
        let dir = tempdir().unwrap();
        let bdir = dir.path().join("backups-out");
        let home = dir.path().join("home");
        let cli_dir = home.join(".claude");
        let cli_backups = cli_dir.join("backups");
        fs::create_dir_all(&cli_backups).unwrap();

        let claude_json = home.join(".claude.json");
        fs::write(
            &claude_json,
            r#"{"oauthAccount":{"emailAddress":"a@b.com","organizationUuid":"11111111-2222"},"theme":"dark"}"#,
        )
        .unwrap();
        let cred_file = cli_dir.join(".credentials.json");
        fs::write(&cred_file, r#"{"claudeAiOauth":{"subscriptionType":"pro"}}"#).unwrap();
        let old_bak = cli_backups.join(".claude.json.backup.1");
        fs::write(&old_bak, r#"{"oauthAccount":{"organizationUuid":"22222222-3333"}}"#).unwrap();

        let info = crate::maintenance::clean_claude_cli_credentials_with_backup_in(
            &bdir,
            Some(&home),
        )
        .unwrap();
        assert!(Path::new(&info.full_path).exists());

        // 清理后：.credentials.json 与旧备份已删除，.claude.json 剥离了 oauthAccount 但保留了 theme
        assert!(!cred_file.exists());
        assert!(!old_bak.exists());
        let after_json: Value =
            serde_json::from_str(&fs::read_to_string(&claude_json).unwrap()).unwrap();
        assert!(after_json.get("oauthAccount").is_none());
        assert_eq!(after_json["theme"], "dark");

        // 反向原子还原：100% 恢复原 .claude.json / .credentials.json / 旧备份
        let roots = crate::maintenance::ClaudeDataRoots {
            cli_claude_json: Some(claude_json.clone()),
            cli_credentials: Some(cred_file.clone()),
            cli_backups_dir: Some(cli_backups.clone()),
            ..Default::default()
        };
        let restored = crate::maintenance::atomic_extract_and_swap_with_roots(
            Path::new(&info.full_path),
            &roots,
            None,
        )
        .unwrap();
        assert!(restored >= 3);
        assert!(cred_file.exists());
        assert!(old_bak.exists());
        let restored_json: Value =
            serde_json::from_str(&fs::read_to_string(&claude_json).unwrap()).unwrap();
        assert_eq!(restored_json["oauthAccount"]["emailAddress"], "a@b.com");
    }

    #[tokio::test]
    #[ignore = "Gate 2 真机双向闭环实测：初始态扫描(检出真实 2/4 降噪缺失与跨端混登) -> 正向补齐 settings.json 验证 4/4 生效 -> 反向精准撤回并验证 100% 还原原文件"]
    async fn live_m2_real_machine_settings_and_audit_bidirectional() {
        let home = dirs::home_dir().expect("home dir");
        let cli_dir = home.join(".claude");
        let settings_path = cli_dir.join("settings.json");
        let baseline_path = crate::rollback::baseline_file_path();

        let orig_settings_raw = fs::read_to_string(&settings_path).ok();
        let orig_baseline_raw = fs::read_to_string(&baseline_path).ok();

        // 1. 初始态真机只读扫描（同步验证控制台与账户审计 100% 同源）
        let ctx = ProfileContext::default_local(None, None, None);
        let before_local = scan_local_profile(&ctx);
        let cfg = crate::config::AppConfig::default();
        let before_preflight = crate::preflight::run_all_preflight_checks(&cfg, 0).await;
        let before_tel = before_preflight
            .report
            .items
            .iter()
            .find(|i| i.id == "claude_tel")
            .expect("claude_tel must exist");
        let before_acct = before_preflight
            .report
            .items
            .iter()
            .find(|i| i.id == "claude_acct")
            .expect("claude_acct must exist");
        let before_ep = before_preflight
            .report
            .items
            .iter()
            .find(|i| i.id == "claude_endpoint")
            .expect("claude_endpoint must exist");

        println!(
            "[M2-Gate2] BEFORE email={:?} cli_org={:?} desktop_orgs={:?} cross_mismatch={} privacy={}/4 missing={:?}",
            before_local.claude_json.email_masked,
            before_local.claude_json.org_uuid_prefix8,
            before_local.desktop.org_id_prefixes,
            before_local.cross_client_org_mismatch,
            before_local.hygiene.privacy_enabled_count,
            before_local.hygiene.privacy_missing_keys
        );
        println!(
            "[M2-Gate2] BEFORE preflight claude_acct={:?} ({}) | claude_tel={:?} ({}) | claude_endpoint={:?} ({})",
            before_acct.status, before_acct.summary, before_tel.status, before_tel.summary, before_ep.status, before_ep.summary
        );

        // 口径 100% 同源断言
        if before_local.cross_client_org_mismatch {
            assert_eq!(
                before_acct.status,
                crate::state::CheckStatus::Fail,
                "跨端混登时控制台 claude_acct 必须与账户审计一致报 Fail"
            );
        }
        if !before_local.hygiene.privacy_missing_keys.is_empty() {
            assert_eq!(
                before_tel.status,
                crate::state::CheckStatus::Fail,
                "settings.json 缺降噪项时控制台 claude_tel 必须报 Fail"
            );
        }

        // 2. 正向修复：一键补齐 4/4 隐私降噪
        let fix_msg = apply_claude_privacy_env_fix(&cli_dir).expect("apply 4/4 privacy fix");
        println!("[M2-Gate2] FORWARD FIX msg={fix_msg}");
        let mid_local = scan_local_profile(&ctx);
        assert_eq!(mid_local.hygiene.privacy_enabled_count, 4);
        assert!(mid_local.hygiene.privacy_missing_keys.is_empty());
        let mid_preflight = crate::preflight::run_all_preflight_checks(&cfg, 0).await;
        let mid_tel = mid_preflight
            .report
            .items
            .iter()
            .find(|i| i.id == "claude_tel")
            .unwrap();
        println!(
            "[M2-Gate2] AFTER FIX preflight claude_tel={:?} ({})",
            mid_tel.status, mid_tel.summary
        );
        if mid_local.hygiene.telemetry_total_bytes == 0 {
            assert_eq!(mid_tel.status, crate::state::CheckStatus::Ok);
        }

        // 3. 反向撤回：通过 rollback_single_item("claude_settings") 精准还原
        let rb = crate::rollback::rollback_single_item("claude_settings").await;
        println!("[M2-Gate2] ROLLBACK ok={} msg={}", rb.ok, rb.message);
        assert!(rb.ok, "反向撤回 claude_settings 必须成功: {}", rb.message);

        let after_local = scan_local_profile(&ctx);
        assert_eq!(
            after_local.hygiene.privacy_enabled_count,
            before_local.hygiene.privacy_enabled_count,
            "撤回后降噪开关数必须 100% 恢复原状"
        );
        assert_eq!(
            after_local.hygiene.privacy_missing_keys,
            before_local.hygiene.privacy_missing_keys,
            "撤回后缺失键列表必须 100% 恢复原状"
        );

        // 校验 JSON 语义 100% 等价（含自定义 hooks / permissions 丝毫无损），并恢复原始格式/基线
        if let Some(orig) = orig_settings_raw {
            let v_orig: Value = serde_json::from_str(&orig).unwrap();
            let v_after: Value =
                serde_json::from_str(&fs::read_to_string(&settings_path).unwrap()).unwrap();
            assert_eq!(v_orig, v_after, "撤回后 settings.json 必须与修改前 100% 语义一致");
            let _ = fs::write(&settings_path, orig);
        }
        if let Some(orig_bl) = orig_baseline_raw {
            let _ = fs::write(&baseline_path, orig_bl);
        }
        println!("[M2-Gate2] BIDIRECTIONAL CLOSED-LOOP PASSED 100%!");
    }
}
