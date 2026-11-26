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
    scan_local_profile, LocalAccountAudit, ProfileContext, ACTIVE_SCHEDULED_TASKS_WARN_THRESHOLD,
    API_ENDPOINT_ENV_KEYS, PRIVACY_ENV_KEYS,
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

/// 持久化已知脱敏账号索引条目（严禁存明文邮箱、Token 或 Cookie，仅用于反查 8 位 org 前缀对应的脱敏展示）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownAccountMeta {
    pub org_prefix8: String,
    pub email_masked: Option<String>,
    pub plan: Option<String>,
    /// 来源标签（如 "云端核验" / "CLI" / "桌面端"）
    pub source: String,
    pub updated_at_ms: i64,
}

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
    /// 按 org_prefix8（小写）分桶存储云端核验快照，切号时不串号、切回老号可复用缓存
    #[serde(default)]
    org_snapshots: HashMap<String, ProfileCloudCache>,
    /// org_prefix8 (小写) -> 脱敏账号元数据（云端核验自动登记，供桌面端/控制台单号锁/清理弹窗反查显示）
    #[serde(default)]
    known_accounts: HashMap<String, KnownAccountMeta>,
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

/// 按本地当前活跃组织精准匹配云端缓存（防止新号登录后继续被老号缓存锁死）：
/// - 若本地识别到当前活跃组织（桌面端最新活跃 org 或 CLI org），优先按该 org 分桶命中；
/// - 若该新号从未做过 sk 核验，则返回 `None`（由前端/报告如实展示新号「待 sk 核验」），绝不张冠李戴套用老号快照；
/// - 若本机桌面端与 CLI 均未检测到任何登录态（纯网页端用户），仍沿用 profile 默认槽位缓存。
pub fn load_profile_cloud_cache_for_local(
    path: &Path,
    profile_id: &str,
    local: &LocalAccountAudit,
) -> Option<ProfileCloudCache> {
    let raw = fs::read_to_string(path).ok()?;
    let store: AuditCacheStore = serde_json::from_str(raw.trim_start_matches('\u{feff}')).ok()?;

    let active_org = local
        .desktop
        .latest_active_org_prefix
        .as_deref()
        .or_else(|| local.desktop.org_id_prefixes.first().map(String::as_str))
        .or(local.claude_json.org_uuid_prefix8.as_deref())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    if let Some(ref cur_org) = active_org {
        if let Some(bucket) = store.org_snapshots.get(cur_org) {
            return Some(bucket.clone());
        }
        if let Some(prof) = store.profiles.get(profile_id) {
            let cached_org = prof
                .last_snapshot
                .as_ref()
                .and_then(|s| s.org_id_prefix8.as_deref())
                .or(prof.bound_org_prefix8.as_deref())
                .map(|s| s.trim().to_ascii_lowercase());
            if cached_org.as_deref() == Some(cur_org.as_str()) {
                return Some(prof.clone());
            }
        }
        return None;
    }

    store.profiles.get(profile_id).cloned()
}

/// 清理登录态后使默认主档案云端缓存失效（保留 known_accounts 脱敏索引与 org_snapshots 分桶，便于排障回显）
pub fn invalidate_profile_cloud_cache(path: &Path, profile_id: &str) {
    let Ok(raw) = fs::read_to_string(path) else {
        return;
    };
    let Ok(mut store) = serde_json::from_str::<AuditCacheStore>(raw.trim_start_matches('\u{feff}'))
    else {
        return;
    };
    if store.profiles.remove(profile_id).is_some() {
        if let Ok(body) = serde_json::to_string_pretty(&store) {
            let tmp = path.with_extension("json.tmp");
            if fs::write(&tmp, &body).is_ok() && fs::rename(&tmp, path).is_err() {
                let _ = fs::write(path, &body);
                let _ = fs::remove_file(&tmp);
            }
        }
    }
}

/// 读取已持久化的脱敏账号反查表（org_prefix8 -> KnownAccountMeta）
pub fn load_known_accounts_map(path: &Path) -> HashMap<String, KnownAccountMeta> {
    let Ok(raw) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    let Ok(store) = serde_json::from_str::<AuditCacheStore>(raw.trim_start_matches('\u{feff}'))
    else {
        return HashMap::new();
    };
    let mut map = store.known_accounts;
    // 兼容历史缓存：把已保存的 profile.last_snapshot 也补进反查表
    for prof in store.profiles.values() {
        if let Some(ref snap) = prof.last_snapshot {
            if let Some(ref org) = snap.org_id_prefix8 {
                let key = org.to_ascii_lowercase();
                map.entry(key.clone()).or_insert(KnownAccountMeta {
                    org_prefix8: key,
                    email_masked: snap.email_masked.clone(),
                    plan: Some(snap.plan.clone()).filter(|p| !p.is_empty() && p != "未知"),
                    source: "云端已识".into(),
                    updated_at_ms: snap.verified_at_ms,
                });
            }
        }
    }
    map
}

/// 单独登记一条脱敏账号元数据（即使本次核验因需切换确认未覆盖主档案，也保留脱敏邮箱映射供提示与清理弹窗使用）
pub fn record_known_account_meta(path: &Path, meta: KnownAccountMeta) {
    let key = meta.org_prefix8.trim().to_ascii_lowercase();
    if key.is_empty() {
        return;
    }
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut store: AuditCacheStore = fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(raw.trim_start_matches('\u{feff}')).ok())
        .unwrap_or_else(|| AuditCacheStore {
            version: 1,
            profiles: HashMap::new(),
            org_snapshots: HashMap::new(),
            known_accounts: HashMap::new(),
        });
    store.version = 1;
    store.known_accounts.insert(key, meta);
    if let Ok(body) = serde_json::to_string_pretty(&store) {
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, &body).is_ok() && fs::rename(&tmp, path).is_err() {
            let _ = fs::write(path, &body);
            let _ = fs::remove_file(&tmp);
        }
    }
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
            org_snapshots: HashMap::new(),
            known_accounts: HashMap::new(),
        });
    store.version = 1;
    if let Some(ref snap) = cache.last_snapshot {
        if let Some(ref org) = snap.org_id_prefix8 {
            let key = org.to_ascii_lowercase();
            store.org_snapshots.insert(key.clone(), cache.clone());
            store.known_accounts.insert(
                key.clone(),
                KnownAccountMeta {
                    org_prefix8: key,
                    email_masked: snap.email_masked.clone(),
                    plan: Some(snap.plan.clone()).filter(|p| !p.is_empty() && p != "未知"),
                    source: "云端已识".into(),
                    updated_at_ms: snap.verified_at_ms,
                },
            );
        }
    }
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

/// 统一格式化任意 `org_prefix8` 的脱敏可读账号标签（绝不再只显示孤立的 8 位组织号）
pub fn format_org_account_label(
    org_prefix8: &str,
    local: &LocalAccountAudit,
    known_map: &HashMap<String, KnownAccountMeta>,
) -> String {
    let key = org_prefix8.trim().to_ascii_lowercase();
    if key.is_empty() {
        return "未知账号".into();
    }
    let in_desktop = local
        .desktop
        .org_id_prefixes
        .iter()
        .any(|d| d.eq_ignore_ascii_case(&key));
    let in_cli = local
        .claude_json
        .org_uuid_prefix8
        .as_deref()
        .map(|c| c.eq_ignore_ascii_case(&key))
        .unwrap_or(false);

    let source_tag = match (in_desktop, in_cli) {
        (true, true) => "桌面端+CLI",
        (true, false) => "桌面端",
        (false, true) => "CLI",
        (false, false) => "本机记录",
    };

    // 1. CLI 当前 ~/.claude.json
    if in_cli {
        if let Some(ref em) = local.claude_json.email_masked {
            let plan = local.claude_json.plan_label.as_deref().unwrap_or("");
            return if !plan.is_empty() && plan != "未知" {
                format!("{em} ({plan} · {source_tag} · {key})")
            } else {
                format!("{em} ({source_tag} · {key})")
            };
        }
    }

    // 2. CLI 历史备份 ~/.claude/backups/
    if let Some(b) = local
        .hygiene
        .backup_accounts
        .iter()
        .find(|b| b.org_prefix.eq_ignore_ascii_case(&key))
    {
        if let Some(ref em) = b.email_masked {
            let plan = b.plan_label.as_deref().unwrap_or("");
            let src = if in_desktop { "桌面端/备份" } else { "CLI备份" };
            return if !plan.is_empty() && plan != "未知" {
                format!("{em} ({plan} · {src} · {key})")
            } else {
                format!("{em} ({src} · {key})")
            };
        }
    }

    // 3. 脱敏云端缓存反查表（曾核验过该组织的桌面端/网页端号）
    if let Some(known) = known_map.get(&key) {
        if let Some(ref em) = known.email_masked {
            let plan = known.plan.as_deref().unwrap_or("");
            return if !plan.is_empty() && plan != "未知" {
                format!("{em} ({plan} · {source_tag} · {key})")
            } else {
                format!("{em} ({source_tag} · {key})")
            };
        }
    }

    // 4. 纯桌面端日志/配置未含邮箱时，明确标出端来源，不让用户只看一串冷冰冰的哈希
    if in_desktop {
        format!("桌面端账号 (本地不含邮箱 · org {key})")
    } else if in_cli {
        format!("CLI 账号 (org {key})")
    } else {
        format!("未识别邮箱账号 (org {key})")
    }
}

/// 前端可视化展示用的多端已识别脱敏账号摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedAccountBadge {
    pub org_prefix8: String,
    pub email_masked: Option<String>,
    pub plan: Option<String>,
    /// 来源端（如 "桌面端" / "CLI" / "桌面端+CLI" / "CLI备份" / "网页云端"）
    pub client_source: String,
    pub display_label: String,
    pub is_primary: bool,
}

/// 本机多端账号卫生 6 态穷举（控制台单号锁、账户审计、清理引导 100% 单一真源，杜绝打补丁与假绿谎报）
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountHygieneState {
    /// 1. 双端均空（桌面端与 CLI 均无活跃登录态与污染残留），可安全登录新主号
    #[default]
    CleanEmpty,
    /// 2. 双端同号一致（桌面端与 CLI 均已登录且为同一健康账号，无失效凭据与内部跨号缓存）
    CleanSyncedSingle,
    /// 3. 单端活跃且另一端彻底干净（文案如实标明仅某端登录，绝不谎称“两端一致”）
    SingleSurfaceClean,
    /// 4. 单端存在失效凭据 / 同文件跨号交叉污染 / 旧号会话目录残留（黄灯预警，引导清理防连坐）
    SingleSurfaceStaleOrPolluted,
    /// 5. 双端混登不同账号或单端检出多个不同组织（红灯阻断，引导分项清理并可自主保留单端）
    CrossSurfaceMix,
    /// 6. 命中实锤封禁 / Portal 验证 / 跨组织 404 竞态（最高危红灯阻断）
    HighRiskBanContamination,
}

/// 本机多端账号拓扑（单一真源 DTO）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalAccountTopology {
    pub hygiene_state: AccountHygieneState,
    pub headline: String,
    pub detail: String,
    /// "empty" | "single" | "multi"
    pub desktop_status: String,
    pub desktop_accounts: Vec<String>,
    /// "empty" | "active" | "stale_or_polluted"
    pub cli_status: String,
    pub cli_account: Option<String>,
    pub cli_stale_reasons: Vec<String>,
    pub session_dir_orphans: Vec<String>,
    /// 只要存在 CLI 登录态 / 缓存 / 凭据 / 历史备份任意一项即为 true，确保用户永远有权清理旧号
    pub has_cli_cleanup_target: bool,
}

/// 纯函数：基于本地扫描 + 受限号清单 + 跨号竞态数 + 已知脱敏映射，严格输出唯一 `LocalAccountTopology`
pub fn evaluate_account_topology(
    local: &LocalAccountAudit,
    restricted_orgs: &[String],
    cross_race_hits: usize,
    known_map: &HashMap<String, KnownAccountMeta>,
) -> LocalAccountTopology {
    let fmt = |o: &str| format_org_account_label(o, local, known_map);

    // 1. 桌面端盘点
    let desktop_accounts: Vec<String> = local.desktop.org_id_prefixes.iter().map(|o| fmt(o)).collect();
    let desktop_status = match local.desktop.org_id_prefixes.len() {
        0 => "empty",
        1 => "single",
        _ => "multi",
    }
    .to_string();

    // 2. CLI 盘点（登录态、失效凭据、同文件跨号交叉缓存、历史旧备份）
    let cli_org = local.claude_json.org_uuid_prefix8.as_deref();
    let cli_account = cli_org.map(fmt);
    let has_cli_cached_usage = local.claude_json.cached_usage.is_some();
    let has_cli_presence = cli_org.is_some() || local.credentials.exists || has_cli_cached_usage;
    let has_cli_cleanup_target =
        has_cli_presence || local.hygiene.backup_file_count > 0;

    let mut cli_stale_reasons: Vec<String> = Vec::new();
    if local.claude_json.internal_account_mismatch {
        let a = local
            .claude_json
            .account_uuid_prefix8
            .as_deref()
            .unwrap_or("?");
        let b = local
            .claude_json
            .cached_usage_account_uuid_prefix8
            .as_deref()
            .unwrap_or("?");
        cli_stale_reasons.push(format!(
            "~/.claude.json 内部双账号交叉污染（oauth={a} ≠ cachedUsage={b}）"
        ));
    }
    if local.credentials.exists && local.credentials.is_expired == Some(true) {
        cli_stale_reasons.push("CLI 登录凭据 (.credentials.json) 已失效/过期".into());
    }
    if cli_org.is_none() && (local.credentials.exists || has_cli_cached_usage) {
        cli_stale_reasons.push("CLI 未登录但残留旧凭据或缓存".into());
    }
    if local.hygiene.backup_accounts.len() > 1 {
        cli_stale_reasons.push(format!(
            "~/.claude/backups/ 含 {} 个不同历史账号旧备份",
            local.hygiene.backup_accounts.len()
        ));
    } else if cli_org.is_none() && local.hygiene.backup_file_count > 0 {
        cli_stale_reasons.push(format!(
            "~/.claude/backups/ 仍残留 {} 份旧号备份",
            local.hygiene.backup_file_count
        ));
    }

    let cli_status = if !has_cli_presence && cli_stale_reasons.is_empty() {
        "empty"
    } else if !cli_stale_reasons.is_empty() {
        "stale_or_polluted"
    } else {
        "active"
    }
    .to_string();

    // 3. 桌面端 Claude-Data 会话目录残留提示（排除当前活跃账号自身目录）
    let mut active_prefixes: Vec<String> = local
        .desktop
        .org_id_prefixes
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    if let Some(c) = cli_org {
        active_prefixes.push(c.to_ascii_lowercase());
    }
    if let Some(ref a) = local.claude_json.account_uuid_prefix8 {
        active_prefixes.push(a.to_ascii_lowercase());
    }
    let session_dir_orphans: Vec<String> = local
        .desktop
        .session_dir_org_prefixes
        .iter()
        .filter(|p| {
            // 若桌面端已空，则所有旧会话目录都标为可核查留存；若桌面端活跃，则仅标出与当前活跃前缀不同的旧目录
            local.desktop.org_id_prefixes.is_empty()
                || !active_prefixes.iter().any(|a| a.eq_ignore_ascii_case(p))
        })
        .cloned()
        .collect();

    // 4. 严格 6 态归类
    let total_cross_race = cross_race_hits + local.desktop.cross_org_404_hits;
    let has_ban_or_portal =
        local.desktop.account_banned_hits > 0 || !restricted_orgs.is_empty() || total_cross_race > 0;
    let is_multi_or_cross_mix =
        local.cross_client_org_mismatch || local.desktop.org_id_prefixes.len() > 1;

    let (hygiene_state, headline, detail) = if has_ban_or_portal {
        let mut reasons = Vec::new();
        if total_cross_race > 0 {
            reasons.push(format!("跨组织竞态 {total_cross_race} 次"));
        }
        if !restricted_orgs.is_empty() {
            let r_labels: Vec<String> = restricted_orgs.iter().map(|o| fmt(o)).collect();
            reasons.push(format!("含已受限/封禁号（{}）", r_labels.join(" / ")));
        } else if local.desktop.account_banned_hits > 0 {
            reasons.push(format!("封禁残留 {} 条", local.desktop.account_banned_hits));
        }
        (
            AccountHygieneState::HighRiskBanContamination,
            format!("高危连坐预警：{}，建议立即双端彻底备份清理", reasons.join("，")),
            "检测到实锤封禁/待验证记录或跨 orgId 竞态；登录健康新号前请先通过分项清单双端彻底清理残留。".into(),
        )
    } else if is_multi_or_cross_mix {
        let desk_str = if desktop_accounts.is_empty() {
            "无".into()
        } else {
            desktop_accounts.join(" / ")
        };
        let cli_str = cli_account.as_deref().unwrap_or("未登录");
        (
            AccountHygieneState::CrossSurfaceMix,
            format!("跨端混登预警：桌面端 [{desk_str}] 与 CLI [{cli_str}] 账号不一致"),
            "桌面端与 CLI 当前记录属于不同账号；打开分项清理弹窗可默认双端全清，也可取消勾选保留你想留的那一端。".into(),
        )
    } else if !cli_stale_reasons.is_empty() {
        let cli_str = cli_account.as_deref().unwrap_or("CLI 旧残留");
        let desk_note = if local.desktop.org_id_prefixes.is_empty() {
            "桌面端已清空"
        } else {
            "桌面端已登录"
        };
        (
            AccountHygieneState::SingleSurfaceStaleOrPolluted,
            format!(
                "{desk_note}，但 CLI 仍残留失效/跨号旧数据（{cli_str}）：{}",
                cli_stale_reasons.join("；")
            ),
            "若该 CLI 旧号已停用或封禁，继续在本机登录新号极易触发同机连坐！建议立即点击「清理 CLI 凭据与备份」或打开分项清理彻底洗净。".into(),
        )
    } else if local.desktop.org_id_prefixes.is_empty() && cli_org.is_none() {
        let orphan_note = if session_dir_orphans.is_empty() {
            String::new()
        } else {
            format!(
                "（Claude-Data 仍保留 {} 个历史会话目录，换新号彻底洗白时可在清理弹窗额外勾选会话项）",
                session_dir_orphans.len()
            )
        };
        (
            AccountHygieneState::CleanEmpty,
            format!("本机桌面端与 CLI 均已清空，无登录态残留，可安全登录新主号{orphan_note}"),
            "桌面端与 CLI 均未检测到活跃登录态或污染记录。".into(),
        )
    } else if !local.desktop.org_id_prefixes.is_empty() && cli_org.is_some() {
        let same_label = desktop_accounts
            .first()
            .cloned()
            .or_else(|| cli_account.clone())
            .unwrap_or_else(|| "单一主号".into());
        (
            AccountHygieneState::CleanSyncedSingle,
            format!("桌面端与 CLI 同号一致（{same_label}），无混登或跨 orgId 竞态"),
            "双端组织完全一致、无失效凭据与跨号残留。".into(),
        )
    } else if !local.desktop.org_id_prefixes.is_empty() {
        let d_label = desktop_accounts[0].clone();
        (
            AccountHygieneState::SingleSurfaceClean,
            format!("仅桌面端已登录（{d_label}）· CLI 已清空，单端环境纯净"),
            "当前仅桌面端存在单一登录态，CLI 未登录且无残留，无跨端混登风险。".into(),
        )
    } else {
        let c_label = cli_account.clone().unwrap_or_else(|| "CLI 账号".into());
        (
            AccountHygieneState::SingleSurfaceClean,
            format!("桌面端已清空 · 仅 CLI 保留登录态（{c_label}），如准备换新号请先清理 CLI 旧号"),
            "桌面端当前无登录态，仅 CLI 仍保留账号记录；若你打算在桌面端登录另一个新号，务必先一键清理 CLI 凭据与旧备份防连坐。".into(),
        )
    };

    LocalAccountTopology {
        hygiene_state,
        headline,
        detail,
        desktop_status,
        desktop_accounts,
        cli_status,
        cli_account,
        cli_stale_reasons,
        session_dir_orphans,
        has_cli_cleanup_target,
    }
}

/// 读取默认档案已持久化的永久绑定归属地（BUG-P1-16：优先按当前活跃 org 分桶查找，绝不把老号属地张冠李戴给新号）
pub fn load_bound_workspace_geo(profile_id: &str) -> Option<String> {
    let cache_path = default_audit_cache_path();
    let ctx = local_scan::ProfileContext::default_local(Some(profile_id.to_string()), None, None);
    let local = local_scan::scan_local_profile(&ctx);
    load_profile_cloud_cache_for_local(&cache_path, profile_id, &local)
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
    /// 若 7d 窗口缓存已过 resets_at，给出诚实校正/旧缓存提示
    #[serde(default)]
    pub seven_day_offline_note: Option<String>,
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
    /// 策略组与全家桶规则是否已锁死（`node_group == Ok`）
    pub group_rules_ok: bool,
    /// Clash Fake-IP DNS 防泄漏是否已实测通过（`node_dns == Ok`）
    pub fake_ip_dns_ok: bool,
    /// 是否已开启「运行中自动 4 层热熔断」兜底
    pub auto_kill_switch_enabled: bool,
    /// 当前活跃 Claude 实时异常连接数（直连 / 非锁定节点）
    pub live_flow_anomalies: usize,
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

/// 纯函数：严格 5 重条件评估「Clash 断连回传 Cookie 403 防护」是否存在真实漏链缺口
///
/// 判定准则：
/// - 基础硬防线：Clash 在线 + TUN 在线（任一离线必判漏链）；
/// - 当 Claude 正在运行（`bg_claude_procs > 0 && !kill_hold_active`）时，绝不因「进程存活」本身误判漏链，
///   而是严格核验 5 重运行护航条件：① Clash 在线、② TUN 在线、③ 策略组与全家桶规则锁死、
///   ④ Fake-IP DNS 防泄漏通过且 0 条实时异常连接、⑤ 已开启运行中自动 4 层热熔断兜底；
///   5 重全绿即返回空缺口（防护就绪 · 运行护航中），任一缺口立即明确指出。
pub fn evaluate_disconnect_guard_strict(runtime: &RuntimeGuardContext) -> Vec<String> {
    let mut gaps = Vec::new();
    if !runtime.clash_online {
        gaps.push("Clash 代理引擎离线".into());
    }
    if !runtime.tun_online {
        gaps.push("Clash TUN 虚拟网卡未接管".into());
    }
    if runtime.bg_claude_procs > 0 && !runtime.kill_hold_active {
        if !runtime.group_rules_ok {
            gaps.push("策略组与全家桶规则未锁死".into());
        }
        if !runtime.fake_ip_dns_ok {
            gaps.push("Fake-IP DNS 防泄漏未通过".into());
        }
        if runtime.live_flow_anomalies > 0 {
            gaps.push(format!(
                "实时连接存在 {} 条直连/非锁定节点异常",
                runtime.live_flow_anomalies
            ));
        }
        if !runtime.auto_kill_switch_enabled {
            gaps.push("未开启「运行中自动 4 层热熔断」兜底".into());
        }
    }
    gaps
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
    /// 5 重严格防漏链判定是否全部就绪（true 表示无漏链缺口，即便 Claude 运行中也不误报）
    #[serde(default)]
    pub runtime_disconnect_guard_ok: bool,
    /// 若 5 重严格防漏链存在缺口，逐条列出精确原因
    #[serde(default)]
    pub runtime_disconnect_gaps: Vec<String>,

    pub denoised_oauth_403_count: usize,
    pub log_flow_items: Vec<AuditLogFlowItem>,
    pub pending_issue_count: usize,
    pub has_danger_issue: bool,
    /// 主力档案来源标注（"desktop_web" | "cli_and_desktop" | "cli" | "cli_stale" | "none"）
    #[serde(default)]
    pub primary_source: String,
    /// 本机所有端已识别到的脱敏账号清单（用于在卡片、混登排查、清理前透明呈现）
    #[serde(default)]
    pub detected_accounts: Vec<DetectedAccountBadge>,
    /// 单一真源：本机多端账号拓扑与 6 态卫生结论
    #[serde(default)]
    pub topology: LocalAccountTopology,
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
    let known = load_known_accounts_map(&default_audit_cache_path());
    build_account_audit_report_with_known(local, cache, runtime, &known)
}

/// 可注入已知脱敏账号映射表的完整报告构造（便于确定性单元测试）
pub fn build_account_audit_report_with_known(
    local: LocalAccountAudit,
    cache: Option<&ProfileCloudCache>,
    runtime: &RuntimeGuardContext,
    known_map: &HashMap<String, KnownAccountMeta>,
) -> AccountAuditReport {
    let now_ms = local.scanned_at_ms;
    // 动态随 now_ms 推进缓存里的注册天数、订阅天数与 KYC 已过小时数，并修正 Free 账号误标订阅天数
    let mut cloud_snap = cache.and_then(|c| c.last_snapshot.clone());
    if let Some(ref mut snap) = cloud_snap {
        let elapsed_ms = now_ms.saturating_sub(snap.verified_at_ms);
        let elapsed_days = (elapsed_ms / 86_400_000) as u64;
        let calc_days_from_iso = |iso: Option<&str>| -> Option<u64> {
            let dt = DateTime::parse_from_rfc3339(iso?).ok()?;
            let diff = now_ms.saturating_sub(dt.timestamp_millis());
            Some((diff / 86_400_000) as u64)
        };
        if let Some(d) = calc_days_from_iso(snap.account_created_at.as_deref()) {
            snap.account_age_days = Some(d);
        } else if let Some(prev_d) = snap.account_age_days {
            snap.account_age_days = Some(prev_d.saturating_add(elapsed_days));
        }
        if snap.plan.eq_ignore_ascii_case("Free") {
            snap.subscription_created_at = None;
            snap.subscription_age_days = None;
        } else if let Some(d) = calc_days_from_iso(snap.subscription_created_at.as_deref()) {
            snap.subscription_age_days = Some(d);
        } else if let Some(prev_d) = snap.subscription_age_days {
            snap.subscription_age_days = Some(prev_d.saturating_add(elapsed_days));
        }
        if let Some(iso) = snap.persona_kyc_completed_at.as_deref() {
            if let Ok(dt) = DateTime::parse_from_rfc3339(iso) {
                let diff = now_ms.saturating_sub(dt.timestamp_millis());
                snap.persona_kyc_age_hours = Some((diff / 3_600_000) as u64);
            }
        } else if let Some(prev_h) = snap.persona_kyc_age_hours {
            let elapsed_hours = (elapsed_ms / 3_600_000) as u64;
            snap.persona_kyc_age_hours = Some(prev_h.saturating_add(elapsed_hours));
        }
    }
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

    // BUG-P0-13：统一计算单一真源 6 态拓扑，完整传入 local.desktop.portal_org_prefixes 与控制台单号卫生锁 100% 同源
    let topology = evaluate_account_topology(&local, &local.desktop.portal_org_prefixes, 0, known_map);

    let cli_org = local.claude_json.org_uuid_prefix8.clone();
    // 优先采用本地按最新时间/lastActiveOrg 识别出的当前活跃桌面账号，避免 BTreeSet 字母序把新号排在老号后面
    let desktop_first_org = local
        .desktop
        .latest_active_org_prefix
        .clone()
        .or_else(|| local.desktop.org_id_prefixes.first().cloned());
    let cloud_org = cloud_snap.as_ref().and_then(|s| s.org_id_prefix8.clone());
    let cloud_matches_cli = match (cloud_org.as_deref(), cli_org.as_deref()) {
        (Some(co), Some(cl)) => co.eq_ignore_ascii_case(cl),
        _ => false,
    };
    let cloud_matches_desktop = match (cloud_org.as_deref(), desktop_first_org.as_deref()) {
        (Some(co), Some(de)) => co.eq_ignore_ascii_case(de),
        _ => false,
    };
    // 只有当云端快照与本机当前活跃桌面账号一致（或本机桌面端未登录、属网页端/CLI 主力）时，才采用云端缓存作为主档案；
    // 若本地桌面端新登录了与旧云端缓存不同的 orgId，绝不再用老号缓存锁死覆写新号！
    let cloud_applies_to_primary =
        cloud_verified && (desktop_first_org.is_none() || cloud_matches_desktop);

    let desktop_known = desktop_first_org
        .as_deref()
        .and_then(|o| known_map.get(&o.to_ascii_lowercase()));

    let (org_id_prefix8, email_masked, primary_source) = if cloud_applies_to_primary {
        let org = cloud_org
            .clone()
            .or_else(|| desktop_first_org.clone())
            .or_else(|| cli_org.clone());
        let email = cloud_snap
            .as_ref()
            .and_then(|s| s.email_masked.clone())
            .or_else(|| {
                if cloud_matches_cli {
                    local.claude_json.email_masked.clone()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                org.as_deref()
                    .map(|o| format!("已核验账号 (org {o})"))
                    .unwrap_or_else(|| "未检测到本机账号".into())
            });
        let src = if cloud_matches_cli && !local.desktop.org_id_prefixes.is_empty() {
            "cli_and_desktop"
        } else {
            "desktop_web"
        };
        (org, email, src.to_string())
    } else if let Some(ref d_org) = desktop_first_org {
        let desktop_same_as_cli = cli_org
            .as_deref()
            .map(|c| c.eq_ignore_ascii_case(d_org))
            .unwrap_or(false);
        if desktop_same_as_cli {
            (
                Some(d_org.clone()),
                local
                    .claude_json
                    .email_masked
                    .clone()
                    .or_else(|| desktop_known.and_then(|k| k.email_masked.clone()))
                    .unwrap_or_else(|| format!("桌面端+CLI 账号 (org {d_org})")),
                "cli_and_desktop".to_string(),
            )
        } else if let Some(k) = desktop_known.filter(|k| k.email_masked.is_some()) {
            (
                Some(d_org.clone()),
                k.email_masked.clone().unwrap(),
                "desktop_web".to_string(),
            )
        } else if let Some(ref c_org) = cli_org {
            (
                Some(c_org.clone()),
                local
                    .claude_json
                    .email_masked
                    .clone()
                    .unwrap_or_else(|| format!("CLI 账号 (org {c_org})")),
                if topology.cli_status == "stale_or_polluted" {
                    "cli_stale".to_string()
                } else {
                    "cli".to_string()
                },
            )
        } else {
            (
                Some(d_org.clone()),
                format!("桌面端账号 (本地不含邮箱 · org {d_org})"),
                "desktop_web".to_string(),
            )
        }
    } else if let Some(ref c_org) = cli_org {
        (
            Some(c_org.clone()),
            local
                .claude_json
                .email_masked
                .clone()
                .unwrap_or_else(|| format!("CLI 账号 (org {c_org})")),
            if topology.cli_status == "stale_or_polluted" {
                "cli_stale".to_string()
            } else {
                "cli".to_string()
            },
        )
    } else {
        (None, "未检测到本机账号".into(), "none".to_string())
    };

    // 若本地桌面端新登录了与旧云端缓存不同的 orgId，则本次报告不应用老号云端快照，让界面诚实展示新号「待 sk 核验」
    let cloud_snap = if cloud_applies_to_primary {
        cloud_snap
    } else {
        None
    };
    let cloud_verified = cloud_applies_to_primary;
    let last_verified_ms = if cloud_applies_to_primary {
        last_verified_ms
    } else {
        None
    };
    let cloud_age_days = if cloud_applies_to_primary {
        cloud_age_days
    } else {
        None
    };
    let cloud_stale = if cloud_applies_to_primary {
        cloud_stale
    } else {
        false
    };
    let workspace_geo = if cloud_applies_to_primary {
        workspace_geo
    } else {
        None
    };
    let geo_consistency =
        evaluate_geo_consistency(workspace_geo.as_deref(), exit_country.as_deref());

    let plan = cloud_snap
        .as_ref()
        .map(|s| s.plan.clone())
        .filter(|p| !p.is_empty() && p != "未知")
        .or_else(|| {
            if primary_source == "desktop_web" {
                desktop_known.and_then(|k| k.plan.clone())
            } else {
                None
            }
        })
        .or_else(|| {
            if matches!(primary_source.as_str(), "cli" | "cli_stale" | "cli_and_desktop") {
                local.claude_json.plan_label.clone()
            } else {
                None
            }
        })
        .or_else(|| {
            if matches!(primary_source.as_str(), "cli" | "cli_stale" | "cli_and_desktop") {
                local_scan::normalize_plan_label(
                    None,
                    local.credentials.subscription_type.as_deref(),
                    local.credentials.rate_limit_tier.as_deref(),
                )
            } else {
                None
            }
        })
        .unwrap_or_else(|| "未知".into());

    let merchant_channel = cloud_snap
        .as_ref()
        .and_then(|s| s.merchant_channel.clone())
        .or_else(|| {
            if matches!(primary_source.as_str(), "cli" | "cli_stale" | "cli_and_desktop") {
                local.claude_json.merchant_channel.clone()
            } else {
                None
            }
        })
        .unwrap_or_else(|| "渠道未知".into());

    let account_age_days = if cloud_verified && !cloud_matches_cli {
        cloud_snap.as_ref().and_then(|s| s.account_age_days)
    } else {
        local
            .claude_json
            .account_age_days
            .or_else(|| cloud_snap.as_ref().and_then(|s| s.account_age_days))
    };
    let subscription_age_days = if cloud_verified && !cloud_matches_cli {
        cloud_snap.as_ref().and_then(|s| s.subscription_age_days)
    } else {
        local
            .claude_json
            .subscription_age_days
            .or_else(|| cloud_snap.as_ref().and_then(|s| s.subscription_age_days))
    };
    let local_device_age_days = local.claude_json.local_device_age_days;

    // 汇总本机全部已识别脱敏账号清单（供 UI 多端展示）
    let mut detected_accounts: Vec<DetectedAccountBadge> = Vec::new();
    let mut seen_orgs: Vec<String> = Vec::new();
    let mut push_org_badge = |org: &str| {
        let lower = org.trim().to_ascii_lowercase();
        if lower.is_empty() || seen_orgs.contains(&lower) {
            return;
        }
        seen_orgs.push(lower.clone());
        let in_desktop = local
            .desktop
            .org_id_prefixes
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&lower));
        let in_cli = cli_org
            .as_deref()
            .map(|c| c.eq_ignore_ascii_case(&lower))
            .unwrap_or(false);
        let in_cloud = cloud_org
            .as_deref()
            .map(|c| c.eq_ignore_ascii_case(&lower))
            .unwrap_or(false);
        let src = match (in_desktop || in_cloud, in_cli) {
            (true, true) => "桌面端+CLI",
            (true, false) if in_desktop => "桌面端",
            (true, false) => "网页/云端",
            (false, true) => "CLI",
            (false, false) => "CLI备份",
        };
        let email_m = if in_cloud && cloud_snap.as_ref().and_then(|s| s.email_masked.as_ref()).is_some() {
            cloud_snap.as_ref().and_then(|s| s.email_masked.clone())
        } else if in_cli && local.claude_json.email_masked.is_some() {
            local.claude_json.email_masked.clone()
        } else if let Some(b) = local
            .hygiene
            .backup_accounts
            .iter()
            .find(|b| b.org_prefix.eq_ignore_ascii_case(&lower))
        {
            b.email_masked.clone()
        } else {
            known_map.get(&lower).and_then(|k| k.email_masked.clone())
        };
        let plan_m = if in_cloud {
            cloud_snap
                .as_ref()
                .map(|s| s.plan.clone())
                .filter(|p| !p.is_empty() && p != "未知")
        } else if in_cli {
            local.claude_json.plan_label.clone()
        } else if let Some(b) = local
            .hygiene
            .backup_accounts
            .iter()
            .find(|b| b.org_prefix.eq_ignore_ascii_case(&lower))
        {
            b.plan_label.clone()
        } else {
            known_map.get(&lower).and_then(|k| k.plan.clone())
        };
        let is_primary = org_id_prefix8
            .as_deref()
            .map(|p| p.eq_ignore_ascii_case(&lower))
            .unwrap_or(false);
        let display_label = format_org_account_label(&lower, &local, known_map);
        detected_accounts.push(DetectedAccountBadge {
            org_prefix8: lower,
            email_masked: email_m,
            plan: plan_m,
            client_source: src.to_string(),
            display_label,
            is_primary,
        });
    };
    if let Some(ref o) = org_id_prefix8 {
        push_org_badge(o);
    }
    for d in &local.desktop.org_id_prefixes {
        push_org_badge(d);
    }
    if let Some(ref c) = cli_org {
        push_org_badge(c);
    }
    for b in &local.hygiene.backup_accounts {
        push_org_badge(&b.org_prefix);
    }

    // BUG-P1-16：仅当主档案非 Free 且与 CLI 属同一组织（或本身以 CLI 为主）时才允许回退 CLI 的 subscription_created_at 推算续费日
    let primary_is_free = plan.eq_ignore_ascii_case("Free");
    let primary_matches_cli = match (org_id_prefix8.as_deref(), cli_org.as_deref()) {
        (Some(p), Some(c)) => p.eq_ignore_ascii_case(c),
        (None, Some(_)) => true,
        _ => false,
    };
    let (subscription_renew_label, subscription_renew_is_estimated) = if primary_is_free {
        ("Free 无订阅".into(), false)
    } else {
        match cloud_snap
            .as_ref()
            .and_then(|s| s.subscription_ends_at.as_deref())
        {
            Some(ends) => (format!("到期 {ends}"), false),
            None => {
                let fallback_sub_iso = if primary_matches_cli {
                    local.claude_json.subscription_created_at.as_deref()
                } else {
                    None
                };
                match estimate_next_renew_mmdd(fallback_sub_iso, now_ms) {
                    Some(est) => (est, true),
                    None => ("预计续费 未知".into(), true),
                }
            }
        }
    };

    // 3 层零风控额度计算（跨端不同号或桌面 Free 号绝不误借 CLI 旧号额度缓存）
    let allow_cli_usage_fallback = !primary_is_free && primary_matches_cli;
    let quota = build_quota_summary(
        &local,
        cloud_snap.as_ref(),
        last_verified_ms,
        cloud_stale,
        now_ms,
        allow_cli_usage_fallback,
    );

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
    // 精确按 orgId 融合本地 claude.ai-web.log 的 Portal 实锤：
    // 1) 若日志明确捕获了 portal.anthropic.com/verify?org=<当前主号>，绝不被云端 unknown 盖掉；
    // 2) 若仅单组织且无行内 org 标识但存在 portal_verify_hits，亦融合提醒。
    let local_portal_matches_primary = org_id_prefix8
        .as_deref()
        .map(|cur| {
            local
                .desktop
                .portal_org_prefixes
                .iter()
                .any(|p| p.eq_ignore_ascii_case(cur))
        })
        .unwrap_or(false)
        || (local.desktop.portal_verify_hits > 0
            && local.desktop.portal_org_prefixes.is_empty()
            && local.all_observed_org_prefixes.len() <= 1);
    let mut cloud_snap = cloud_snap;
    if local_portal_matches_primary {
        if let Some(ref mut snap) = cloud_snap {
            if !snap.portal_hold && snap.portal_state != "clear" {
                snap.portal_hold = true;
                snap.portal_state = "local_hold".into();
            }
        }
    }
    let portal_hold = cloud_snap.as_ref().map(|s| s.portal_hold).unwrap_or(false)
        || (local_portal_matches_primary
            && cloud_snap
                .as_ref()
                .map(|s| s.portal_state != "clear")
                .unwrap_or(true));
    let chat_restricted = cloud_snap
        .as_ref()
        .map(|s| !s.chat_available && !s.is_banned)
        .unwrap_or(false);

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
        topology.hygiene_state == AccountHygieneState::HighRiskBanContamination;
    let cross_client_or_multi_org_mix =
        topology.hygiene_state == AccountHygieneState::CrossSurfaceMix;
    let stale_or_polluted_cli_residue =
        topology.hygiene_state == AccountHygieneState::SingleSurfaceStaleOrPolluted;
    // 定时任务按真实行为分级：
    // - 历史留存 (>72h) 0 扣分不标红；
    // - 活跃定时任务 0~5 个正常绿灯，>= 6 个归为轻微风险（黄灯 -5 分）；
    // - 仅真实跨夜机刷、高频 429 (>=3) 或高并发才进严重红灯 (-10 分)。
    let active_sched = local.hygiene.active_scheduled_tasks_count;
    let severe_automation_or_429 = local.behavior.overnight_bot_rhythm_suspected
        || local.desktop.rate_limit_429_hits >= 3
        || local.desktop.high_side_session_hits > 0;
    let mild_rate_limit_429 =
        !severe_automation_or_429 && local.desktop.rate_limit_429_hits > 0;
    let mild_scheduled_tasks =
        !severe_automation_or_429 && active_sched >= ACTIVE_SCHEDULED_TASKS_WARN_THRESHOLD;
    let disconnect_gaps = evaluate_disconnect_guard_strict(runtime);
    let proxy_or_hold_unready = !disconnect_gaps.is_empty();
    let disconnect_detail = if !disconnect_gaps.is_empty() {
        Some(format!(
            "运行中 5 重防漏链存在缺口：{}，请先前往控制台或守卫配置补齐",
            disconnect_gaps.join("；")
        ))
    } else {
        None
    };
    let cli_telemetry_exempt =
        !local.hygiene.cli_installed && local.hygiene.telemetry_total_bytes == 0;

    let multi_acct_detail = if matches!(
        topology.hygiene_state,
        AccountHygieneState::HighRiskBanContamination
            | AccountHygieneState::CrossSurfaceMix
            | AccountHygieneState::SingleSurfaceStaleOrPolluted
    ) {
        Some(topology.headline.clone())
    } else {
        None
    };

    let score_input = RiskScoreInput {
        confidence_mode: Some(confidence_mode),
        stale_days: cloud_age_days,
        account_banned,
        portal_hold,
        chat_restricted,
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
        stale_or_polluted_cli_residue,
        multi_acct_detail,
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
        mild_scheduled_tasks,
        rhythm_detail: if mild_scheduled_tasks && !mild_rate_limit_429 {
            Some(format!(
                "检测到 {} 个近期活跃定时任务（≥{} 个轻微提醒阈值），建议控制频率避免压线限流",
                active_sched, ACTIVE_SCHEDULED_TASKS_WARN_THRESHOLD
            ))
        } else {
            None
        },
        quit_cookie_403_hit: local.desktop.cookie_403_hits > 0,
        proxy_or_hold_unready,
        disconnect_detail,
        telemetry_env_missing_count: if cli_telemetry_exempt {
            0
        } else {
            local.hygiene.privacy_missing_keys.len()
        },
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
    if severe_automation_or_429 || mild_rate_limit_429 || mild_scheduled_tasks {
        pending_issue_count += 1;
        if severe_automation_or_429 {
            has_danger_issue = true;
        }
    }
    if geo_consistency == GeoConsistency::CrossContinentMismatch {
        pending_issue_count += 1;
        has_danger_issue = true;
    }
    if ban_residue_or_cross_org_404 || cross_client_or_multi_org_mix || stale_or_polluted_cli_residue {
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
        if local.desktop.cookie_403_hits > 0
            || !runtime.clash_online
            || !runtime.tun_online
            || runtime.live_flow_anomalies > 0
        {
            has_danger_issue = true;
        }
    }
    if !cli_telemetry_exempt
        && (!local.hygiene.privacy_missing_keys.is_empty()
            || local.hygiene.telemetry_total_bytes > 0)
    {
        pending_issue_count += 1;
    }
    if account_banned || portal_hold || chat_restricted {
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
        runtime_disconnect_guard_ok: !proxy_or_hold_unready,
        runtime_disconnect_gaps: disconnect_gaps,
        denoised_oauth_403_count,
        log_flow_items,
        pending_issue_count,
        has_danger_issue,
        primary_source,
        detected_accounts,
        topology,
    }
}

/// 3 层零风控额度提精汇总
fn build_quota_summary(
    local: &LocalAccountAudit,
    cloud_snap: Option<&CloudProbeSnapshot>,
    last_verified_ms: Option<i64>,
    cloud_stale: bool,
    now_ms: i64,
    allow_cli_usage_fallback: bool,
) -> QuotaDisplaySummary {
    let soft_locked = local.desktop.five_hour_soft_lock_hits > 0
        || (allow_cli_usage_fallback
            && local
                .claude_json
                .cached_usage
                .as_ref()
                .map(|u| u.five_hour_locked_reason.is_some() || u.seven_day_locked_reason.is_some())
                .unwrap_or(false));

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
                seven_day_offline_note: None,
                soft_locked,
                source: DataSource::OfficialProbe,
            };
        }
    }

    // 回退到本地缓存（仅同号付费才允许回退 CLI ~/.claude.json，否则优先桌面端 plan-usage-history.json）+ 层 2 离线 .jsonl 校正
    let local_cached_usage: Option<(&local_scan::CachedUsageSummary, &str)> =
        if allow_cli_usage_fallback {
            local
                .claude_json
                .cached_usage
                .as_ref()
                .map(|u| (u, "本地缓存"))
                .or_else(|| {
                    local
                        .desktop
                        .cached_usage
                        .as_ref()
                        .map(|u| (u, "桌面端本地缓存"))
                })
        } else {
            local
                .desktop
                .cached_usage
                .as_ref()
                .map(|u| (u, "桌面端本地缓存"))
        };

    if let Some((cu, source_label)) = local_cached_usage {
        let fetched_ms = cu.fetched_at_ms.unwrap_or(0);
        let short = if fetched_ms > 0 {
            format_short_age(fetched_ms, now_ms)
        } else {
            "缓存".into()
        };
        let tooltip = if fetched_ms > 0 {
            format!("{source_label} · {short}采样")
        } else {
            format!("{source_label}采样")
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

        let seven_day_resets_passed = cu
            .seven_day_resets_at
            .as_deref()
            .and_then(|iso| DateTime::parse_from_rfc3339(iso).ok())
            .map(|dt| dt.timestamp_millis() < now_ms)
            .unwrap_or(false);
        let cache_expired_7d =
            fetched_ms > 0 && now_ms.saturating_sub(fetched_ms) > CLOUD_CACHE_TTL_MS;
        let raw_7d = cu.seven_day_pct.map(|v| v.round().clamp(0.0, 100.0) as u32);
        let (seven_pct, seven_offline_note) = if seven_day_resets_passed || cache_expired_7d {
            if local.behavior.last_7d.assistant_turns == 0 {
                (
                    Some(0),
                    Some(format!(
                        "本地缓存为 {short}旧采样（原 7d 窗口已重置），近 7 天本地 CLI 0 轮，已校正为 0%；实际实时额度可按需 sk 核验刷新"
                    )),
                )
            } else {
                (
                    None,
                    Some(format!(
                        "本地 7d 缓存（{short}采样）所属周期已重置，暂停显示过期旧值，请按需云端 sk 核验刷新"
                    )),
                )
            }
        } else {
            (raw_7d, None)
        };

        let source = if offline_note.is_some() || seven_offline_note.is_some() {
            DataSource::OfflineJsonl
        } else {
            DataSource::LocalConfig
        };
        return QuotaDisplaySummary {
            five_hour_pct: five_pct,
            seven_day_pct: seven_pct,
            stamp_short: short,
            stamp_tooltip: tooltip,
            five_hour_offline_note: offline_note,
            seven_day_offline_note: seven_offline_note,
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
        seven_day_offline_note: None,
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
        // BUG-P1-17：保留非字符串原值（如 bool/number）避免撤回时被误删
        let orig = env_map.get(k).map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        });
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
            let mut env_changed = false;

            if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
            {
                for k in API_ENDPOINT_ENV_KEYS {
                    if let Ok(v) = key.get_value::<String, _>(k) {
                        if local_scan::is_non_official_anthropic_url(&v) {
                            key.delete_value(k)
                                .map_err(|e| format!("清理用户环境变量 {k} 失败: {e}"))?;
                            hkcu_orig.push((k.to_string(), v));
                            env_changed = true;
                        }
                    }
                }
            }
            match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                KEY_READ | KEY_WRITE,
            ) {
                Ok(key) => {
                    for k in API_ENDPOINT_ENV_KEYS {
                        if let Ok(v) = key.get_value::<String, _>(k) {
                            if local_scan::is_non_official_anthropic_url(&v) {
                                key.delete_value(k)
                                    .map_err(|e| format!("清理系统环境变量 {k} 失败: {e}"))?;
                                hklm_orig.push((k.to_string(), v));
                                env_changed = true;
                            }
                        }
                    }
                }
                Err(_) => {
                    if let Ok(ro) = RegKey::predef(HKEY_LOCAL_MACHINE)
                        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
                    {
                        let mut del_cmds = Vec::new();
                        for k in API_ENDPOINT_ENV_KEYS {
                            if let Ok(v) = ro.get_value::<String, _>(k) {
                                if local_scan::is_non_official_anthropic_url(&v) {
                                    hklm_orig.push((k.to_string(), v));
                                    del_cmds.push(format!(
                                        "Remove-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name '{}' -ErrorAction Stop",
                                        k.replace('\'', "''")
                                    ));
                                }
                            }
                        }
                        if !del_cmds.is_empty() {
                            crate::rollback::run_ps_elevated_checked(
                                &del_cmds.join("; "),
                                "清理系统级非官方端点环境变量",
                            )?;
                            env_changed = true;
                        }
                    }
                }
            }
            if env_changed {
                crate::rollback::notify_windows_env_and_inet_refresh();
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
                    "已清理 {} 项系统环境变量非官方端点并广播生效",
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
///
/// 不再强行假定本机 CLI (`~/.claude.json`) 一定是唯一主力档案：
/// - 若 `allow_switch_primary == true`、或本机无 CLI、或 `sk` 组织等于 CLI 组织、或 `sk` 组织已出现在桌面端日志/配置中，均直接放行并设为当前主审计档案；
/// - 仅当本机 CLI 存在另一号，且本次 `sk` 既非 CLI 号也不在桌面端记录中、且尚未确认切换时，才返回带 `[ORG_MISMATCH_CONFIRM]` 的双账号脱敏对比提示，由前端一键确认切换。
pub async fn run_desktop_cloud_verify(
    ctx: &ProfileContext,
    cache_path: &Path,
    raw_input: &str,
    runtime: &RuntimeGuardContext,
    allow_switch_primary: bool,
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

    // 先完成只读探测，以便获取云端脱敏邮箱与套餐，不再盲目用 CLI orgId 拦死桌面端/网页端用户
    let snap = probe_session_key_readonly(
        raw_input,
        CloudProbeOptions {
            proxy_url,
            expected_org_prefix8: None,
            base_url: None,
            timeout_secs: Some(15),
            bypass_cooldown: allow_switch_primary,
        },
    )
    .await?;

    // 无论后续是否切主档案，先将云端脱敏邮箱登记到反查表（严禁存明文邮箱/sk）
    if let Some(ref org) = snap.org_id_prefix8 {
        record_known_account_meta(
            cache_path,
            KnownAccountMeta {
                org_prefix8: org.to_ascii_lowercase(),
                email_masked: snap.email_masked.clone(),
                plan: Some(snap.plan.clone()).filter(|p| !p.is_empty() && p != "未知"),
                source: "云端已识".into(),
                updated_at_ms: snap.verified_at_ms,
            },
        );
    }

    // 跨端确认保护：仅当本机 CLI 存在另一号，且 sk 组织不在桌面端记录里、且用户未显式确认切换时提示对比
    if !allow_switch_primary {
        if let (Some(cli_org), Some(actual_org)) = (
            local.claude_json.org_uuid_prefix8.as_deref(),
            snap.org_id_prefix8.as_deref(),
        ) {
            let matches_cli = cli_org.eq_ignore_ascii_case(actual_org);
            let matches_desktop = local
                .desktop
                .org_id_prefixes
                .iter()
                .any(|d| d.eq_ignore_ascii_case(actual_org));
            if !matches_cli && !matches_desktop {
                let sk_email = snap.email_masked.as_deref().unwrap_or("未含邮箱");
                let cli_email = local.claude_json.email_masked.as_deref().unwrap_or("CLI账号");
                let cli_plan = local.claude_json.plan_label.as_deref().unwrap_or("未知");
                return Err(CloudProbeError {
                    code: CloudProbeErrorCode::OrgMismatch,
                    http_status: 409,
                    message: format!(
                        "[ORG_MISMATCH_CONFIRM] 当前浏览器账号 {sk_email} ({} · {actual_org}) 与本机 CLI 账号 {cli_email} ({cli_plan} · {cli_org}) 不一致。你可以直接以此浏览器/桌面端账号为主档案继续核验，或先去浏览器切回 CLI 账号。",
                        snap.plan
                    ),
                    retry_after_secs: None,
                });
            }
        }
    }

    let prev = load_profile_cloud_cache(cache_path, &ctx.profile_id);
    let org_changed = match (
        prev.as_ref().and_then(|p| p.bound_org_prefix8.as_deref()),
        snap.org_id_prefix8.as_deref(),
    ) {
        (Some(old), Some(new_org)) => !old.eq_ignore_ascii_case(new_org),
        _ => false,
    };
    let next_cache = ProfileCloudCache {
        profile_id: ctx.profile_id.clone(),
        bound_workspace_geo: if org_changed {
            snap.workspace_geo.clone()
        } else {
            snap.workspace_geo
                .clone()
                .or_else(|| prev.as_ref().and_then(|p| p.bound_workspace_geo.clone()))
        },
        bound_org_prefix8: snap
            .org_id_prefix8
            .clone()
            .or_else(|| prev.as_ref().and_then(|p| p.bound_org_prefix8.clone())),
        verify_count: prev.as_ref().map(|p| p.verify_count + 1).unwrap_or(1),
        last_verified_at_ms: Some(snap.verified_at_ms),
        last_snapshot: Some(snap),
    };
    let _ = save_profile_cloud_cache(cache_path, &next_cache);

    let known = load_known_accounts_map(cache_path);
    Ok(build_account_audit_report_with_known(
        local,
        Some(&next_cache),
        runtime,
        &known,
    ))
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
        chat_restricted: !snap.chat_available && !snap.is_banned,
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
            account_created_at: None,
            subscription_age_days: Some(33),
            subscription_created_at: None,
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

    #[test]
    fn free_account_oauth_len164_not_misclassified_as_restricted_org() {
        // 回归：Free 号桌面端背景 OAuth 403 (len=164/len=156) 属于正常权限边界，绝不打进 restricted_org_ids
        let log_free = r#"
2026-11-25 07:53:34 [info] Org changed from null to a4722ea6-5260-4b99-b90e-184c66adb1d7
2026-11-25 07:53:37 [info] oauth failed: authorize returned 403 <json error=permission_error len=164>
2026-11-25 07:53:39 [info] oauth failed: authorize returned 403 <json error=permission_error len=156>
"#;
        let mut audit = crate::watchdog::AccountLogAudit::default();
        crate::watchdog::audit_log_text_for_accounts(log_free, &mut audit);
        assert!(
            audit.restricted_org_ids.is_empty(),
            "Free 号 len=164/156 OAuth 403 不应被误标为受限号: {:?}",
            audit.restricted_org_ids
        );

        // 真正封号/门户核验（len=130 / portal.anthropic.com/verify）仍必须准确捕获
        let log_real_ban = r#"
2026-11-25 08:00:00 [warn] orgId=deadbeef-1111-2222-3333-444455556666
2026-11-25 08:00:01 [error] authorize returned 403 <json error=permission_error len=130>
"#;
        let mut audit_ban = crate::watchdog::AccountLogAudit::default();
        crate::watchdog::audit_log_text_for_accounts(log_real_ban, &mut audit_ban);
        assert_eq!(audit_ban.restricted_org_ids, vec!["deadbeef".to_string()]);
    }

    #[test]
    fn scheduled_tasks_threshold_and_historical_scripts_scoring() {
        let rt = RuntimeGuardContext {
            clash_online: true,
            clash_port: 7890,
            tun_online: true,
            ..Default::default()
        };
        let mut local = LocalAccountAudit::default();
        local.scanned_at_ms = 1_795_600_000_000;

        // 场景 A：0 个活跃 + 10 个历史旧脚本(>72h) => 0 扣分、不进 severe 也不进 mild
        local.hygiene.active_scheduled_tasks_count = 0;
        local.hygiene.scheduled_tasks_count = 0;
        local.hygiene.historical_scheduled_tasks_count = 10;
        let rep_hist = build_account_audit_report_with_known(local.clone(), None, &rt, &HashMap::new());
        assert!(
            !rep_hist
                .score_result
                .deductions
                .iter()
                .any(|d| d.id.contains("automation") || d.id.contains("scheduled")),
            "历史留存脚本不应扣分: {:?}",
            rep_hist.score_result.deductions
        );

        // 场景 B：5 个活跃定时任务 => 仍在正常范围(0~5)，0 扣分
        local.hygiene.active_scheduled_tasks_count = 5;
        local.hygiene.scheduled_tasks_count = 5;
        let rep_5 = build_account_audit_report_with_known(local.clone(), None, &rt, &HashMap::new());
        assert!(
            !rep_5
                .score_result
                .deductions
                .iter()
                .any(|d| d.id.contains("automation") || d.id.contains("scheduled")),
            "5 个活跃定时任务应为绿灯正常"
        );

        // 场景 C：6 个活跃定时任务 => 轻微风险黄灯 (-5)，绝不判红灯机刷 (-10)
        local.hygiene.active_scheduled_tasks_count = 6;
        local.hygiene.scheduled_tasks_count = 6;
        let rep_6 = build_account_audit_report_with_known(local, None, &rt, &HashMap::new());
        let item = rep_6
            .score_result
            .deductions
            .iter()
            .find(|d| d.id == "mild_scheduled_tasks")
            .expect("6 个活跃定时任务应触发 mild_scheduled_tasks 黄灯");
        assert_eq!(item.delta, -5);
        assert_eq!(item.tone, "warn");
    }

    #[test]
    fn cloud_verified_desktop_account_takes_primary_over_stale_cli() {
        let rt = RuntimeGuardContext {
            clash_online: true,
            clash_port: 7890,
            tun_online: true,
            exit_country: Some("US".into()),
            ..Default::default()
        };
        let mut local = LocalAccountAudit::default();
        local.scanned_at_ms = 1_795_600_000_000;
        local.claude_json.exists = true;
        local.claude_json.email_masked = Some("star***t4@gmail.com".into());
        local.claude_json.org_uuid_prefix8 = Some("7aacf131".into());
        local.claude_json.plan_label = Some("Pro".into());
        local.desktop.org_id_prefixes = vec!["a4722ea6".into()];
        local.cross_client_org_mismatch = true;

        let snap = CloudProbeSnapshot {
            verified_at_ms: 1_795_599_000_000,
            checked_at_iso: "2026-11-26T00:00:00Z".into(),
            email_masked: Some("desk***99@gmail.com".into()),
            org_id_prefix8: Some("a4722ea6".into()),
            plan: "Free".into(),
            merchant_channel: Some("Free".into()),
            workspace_geo: Some("US".into()),
            edge_country: Some("US".into()),
            edge_colo: Some("SJC".into()),
            account_age_days: Some(20),
            account_created_at: None,
            subscription_age_days: None,
            subscription_created_at: None,
            subscription_ends_at: None,
            chat_available: true,
            is_banned: false,
            appeals_redirect_enabled: false,
            has_monitoring_notice: false,
            active_flag_types: Vec::new(),
            warning_summary_zh: None,
            persona_kyc_status: None,
            persona_kyc_completed_at: None,
            persona_kyc_age_hours: None,
            portal_hold: false,
            portal_state: "clear".into(),
            five_hour_pct: Some(5.0),
            five_hour_resets_at: None,
            seven_day_pct: Some(12.0),
            seven_day_resets_at: None,
            warnings: Vec::new(),
        };
        let cache = ProfileCloudCache {
            profile_id: "default".into(),
            bound_workspace_geo: Some("US".into()),
            bound_org_prefix8: Some("a4722ea6".into()),
            verify_count: 1,
            last_verified_at_ms: Some(1_795_599_000_000),
            last_snapshot: Some(snap),
        };
        let mut known = HashMap::new();
        known.insert(
            "a4722ea6".into(),
            KnownAccountMeta {
                org_prefix8: "a4722ea6".into(),
                email_masked: Some("desk***99@gmail.com".into()),
                plan: Some("Free".into()),
                source: "云端已识".into(),
                updated_at_ms: 1_795_599_000_000,
            },
        );

        let report = build_account_audit_report_with_known(local, Some(&cache), &rt, &known);
        assert_eq!(report.email_masked, "desk***99@gmail.com");
        assert_eq!(report.org_id_prefix8.as_deref(), Some("a4722ea6"));
        assert_eq!(report.plan, "Free");
        assert_eq!(report.primary_source, "desktop_web");
        assert!(report.detected_accounts.len() >= 2);
    }

    #[test]
    fn cleanup_preview_defaults_cli_checked_and_shows_masked_accounts() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let cli_dir = home.join(".claude");
        let roaming = dir.path().join("Roaming");
        let local_base = dir.path().join("Local");
        fs::create_dir_all(cli_dir.join("backups")).unwrap();
        fs::create_dir_all(roaming.join("Claude").join("logs")).unwrap();
        fs::write(
            home.join(".claude.json"),
            r#"{"oauthAccount":{"emailAddress":"starktest4@gmail.com","organizationUuid":"7aacf131-0000-0000-0000-000000000000","billingType":"stripe_subscription","organizationType":"claude_pro"}}"#,
        )
        .unwrap();
        fs::write(
            roaming.join("Claude").join("logs").join("main.log"),
            "orgId=a4722ea6-5260-4b99-b90e-184c66adb1d7",
        )
        .unwrap();

        let roots = crate::maintenance::discover_claude_data_roots_from(
            Some(&roaming),
            Some(&local_base),
            Some(&home),
        );
        let preview = crate::maintenance::preview_claude_cleanup_plan_with_roots(&roots, 0);
        let cli_cat = preview
            .categories
            .iter()
            .find(|c| c.id == crate::maintenance::CLEAN_CAT_CLI_AUTH)
            .expect("cli_auth_and_backups category must exist");
        assert!(cli_cat.default_selected, "CLI 登录态清理必须默认勾选");
        let cli_acct = cli_cat.account_summary.as_deref().unwrap_or("");
        assert!(
            cli_acct.contains("star***t4@gmail.com") && cli_acct.contains("7aacf131"),
            "CLI 清理项必须展示脱敏账号与组织: {cli_acct}"
        );

        let auth_cat = preview
            .categories
            .iter()
            .find(|c| c.id == crate::maintenance::CLEAN_CAT_AUTH)
            .expect("auth category must exist");
        let desk_acct = auth_cat.account_summary.as_deref().unwrap_or("");
        assert!(
            desk_acct.contains("a4722ea6") && desk_acct.contains("桌面端"),
            "桌面端清理项必须展示桌面端识别信息: {desk_acct}"
        );
    }

    #[test]
    fn topology_detects_stale_cli_and_internal_cross_account_mismatch_never_fakes_synced() {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let cli_dir = home.join(".claude");
        fs::create_dir_all(&cli_dir).unwrap();

        // 构造真实真机场景：桌面端已清空，但 CLI ~/.claude.json 内部双账号交叉(b3a8b422 != 078cfdb1) 且 .credentials.json expiresAt=0
        let claude_json = home.join(".claude.json");
        fs::write(
            &claude_json,
            r#"{
                "oauthAccount": {
                    "accountUuid": "b3a8b422-1111-2222-3333-444455556666",
                    "emailAddress": "starktest4@gmail.com",
                    "organizationUuid": "7aacf131-1111-2222-3333-444455556666",
                    "organizationType": "claude_pro",
                    "billingType": "stripe_subscription"
                },
                "cachedUsageUtilization": {
                    "fetchedAtMs": 1794848917463,
                    "accountUuid": "078cfdb1-0f3b-4e3c-b2bb-44f0c3b8d5a3",
                    "utilization": {
                        "seven_day": { "utilization": 72, "resets_at": "2026-11-20T18:00:00Z" }
                    }
                },
                "theme": "dark"
            }"#,
        )
        .unwrap();
        fs::write(
            cli_dir.join(".credentials.json"),
            r#"{"claudeAiOauth":{"subscriptionType":"pro","expiresAt":0,"scopes":["user:inference"]}}"#,
        )
        .unwrap();

        let ctx = ProfileContext {
            profile_id: "default".into(),
            cli_config_dir: Some(cli_dir.clone()),
            claude_json_path: Some(claude_json.clone()),
            desktop_data_dirs: Vec::new(),
            expected_geo: None,
            bound_proxy_port: None,
            scan_system_env: false,
        };
        let local = local_scan::scan_local_profile_at(&ctx, 1_795_600_000_000);
        assert!(local.claude_json.internal_account_mismatch);
        assert_eq!(local.credentials.is_expired, Some(true));

        let rt = RuntimeGuardContext {
            clash_online: true,
            clash_port: 7890,
            tun_online: true,
            ..Default::default()
        };
        let report = build_account_audit_report_with_known(local, None, &rt, &HashMap::new());
        assert_eq!(
            report.topology.hygiene_state,
            AccountHygieneState::SingleSurfaceStaleOrPolluted
        );
        assert_eq!(report.primary_source, "cli_stale");
        assert!(report.topology.has_cli_cleanup_target);
        assert!(
            !report.topology.headline.contains("组织一致"),
            "桌面端为空时绝不可谎称 CLI 与桌面端组织一致: {}",
            report.topology.headline
        );
        assert!(report
            .score_result
            .deductions
            .iter()
            .any(|d| d.id == "cli_stale_or_cross_residue"));

        // 一键清理 CLI 后：同步剥离 oauthAccount 与 cachedUsageUtilization（保留 theme）
        let bdir = dir.path().join("backups");
        let _ = crate::maintenance::clean_claude_cli_credentials_with_backup_in(&bdir, Some(&home))
            .unwrap();
        let after_val: Value =
            serde_json::from_str(&fs::read_to_string(&claude_json).unwrap()).unwrap();
        assert!(after_val.get("oauthAccount").is_none());
        assert!(after_val.get("cachedUsageUtilization").is_none());
        assert_eq!(after_val["theme"], "dark");

        // 清理后再扫：彻底进入 CleanEmpty 纯净待登态
        let local_after = local_scan::scan_local_profile_at(&ctx, 1_795_600_000_000);
        let report_after =
            build_account_audit_report_with_known(local_after, None, &rt, &HashMap::new());
        assert_eq!(
            report_after.topology.hygiene_state,
            AccountHygieneState::CleanEmpty
        );
        assert!(!report_after.topology.has_cli_cleanup_target);
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

    #[test]
    fn strict_disconnect_guard_passes_when_running_with_5_protections_and_catches_any_gap() {
        let base_running = RuntimeGuardContext {
            clash_online: true,
            clash_port: 7890,
            tun_online: true,
            group_rules_ok: true,
            fake_ip_dns_ok: true,
            auto_kill_switch_enabled: true,
            live_flow_anomalies: 0,
            bg_claude_procs: 8,
            kill_hold_active: false,
            ..Default::default()
        };
        assert!(
            evaluate_disconnect_guard_strict(&base_running).is_empty(),
            "5 重防护全绿时运行 8 个 Claude 进程绝不应判为存在漏链"
        );

        let mut local = LocalAccountAudit::default();
        local.scanned_at_ms = 1_795_650_000_000;
        let rep_ok = build_account_audit_report_with_known(local.clone(), None, &base_running, &HashMap::new());
        assert!(rep_ok.runtime_disconnect_guard_ok);
        assert!(rep_ok.runtime_disconnect_gaps.is_empty());
        assert!(!rep_ok
            .score_result
            .deductions
            .iter()
            .any(|d| d.id == "disconnect_guard_unready"));

        // 逐项验证 5 重缺口均会被严格拦截
        let mut no_rules = base_running.clone();
        no_rules.group_rules_ok = false;
        assert!(evaluate_disconnect_guard_strict(&no_rules)
            .iter()
            .any(|g| g.contains("策略组")));

        let mut no_dns = base_running.clone();
        no_dns.fake_ip_dns_ok = false;
        assert!(evaluate_disconnect_guard_strict(&no_dns)
            .iter()
            .any(|g| g.contains("Fake-IP")));

        let mut live_leak = base_running.clone();
        live_leak.live_flow_anomalies = 2;
        assert!(evaluate_disconnect_guard_strict(&live_leak)
            .iter()
            .any(|g| g.contains("2 条")));

        let mut no_auto_ks = base_running.clone();
        no_auto_ks.auto_kill_switch_enabled = false;
        let rep_gap = build_account_audit_report_with_known(local, None, &no_auto_ks, &HashMap::new());
        assert!(!rep_gap.runtime_disconnect_guard_ok);
        assert!(rep_gap
            .runtime_disconnect_gaps
            .iter()
            .any(|g| g.contains("热熔断")));
        assert!(rep_gap
            .score_result
            .deductions
            .iter()
            .any(|d| d.id == "disconnect_guard_unready"));
    }

    #[test]
    fn desktop_plan_usage_fallback_and_no_cli_telemetry_exemption() {
        let dir = tempdir().unwrap();
        let desktop_root = dir.path().join("Claude-Data").join("claude_pkg");
        let sessions_dir = desktop_root.join("claude-code-sessions").join("org-1");
        fs::create_dir_all(&sessions_dir).unwrap();

        let now_ms = 1_795_650_000_000i64;
        fs::write(
            desktop_root.join("plan-usage-history.json"),
            format!(
                r#"{{"version":2,"samples":[{{"t":{},"org":"a4722ea6","u":{{"five_hour":{{"utilization":28}},"seven_day":{{"utilization":41}}}}}}]}}"#,
                now_ms - 60_000
            ),
        )
        .unwrap();
        fs::write(
            sessions_dir.join("session.jsonl"),
            r#"{"type":"assistant","timestamp":"2026-11-26T00:00:00Z","message":{"usage":{"input_tokens":100,"output_tokens":50}}}"#,
        )
        .unwrap();

        let ctx = ProfileContext {
            profile_id: "default".into(),
            cli_config_dir: Some(dir.path().join("nonexistent-cli")),
            claude_json_path: Some(dir.path().join("nonexistent.claude.json")),
            desktop_data_dirs: vec![local_scan::DesktopDataRoot {
                kind: "Claude-Data(claude_pkg)".into(),
                dir: desktop_root,
            }],
            expected_geo: None,
            bound_proxy_port: None,
            scan_system_env: false,
        };
        let local = local_scan::scan_local_profile_at(&ctx, now_ms);
        assert!(!local.hygiene.cli_installed, "未安装 CLI 时 cli_installed 必须为 false");
        assert_eq!(local.behavior.desktop_sessions_files_7d, 1);
        assert!(local.desktop.cached_usage.is_some());

        let rt = RuntimeGuardContext {
            clash_online: true,
            clash_port: 7890,
            tun_online: true,
            group_rules_ok: true,
            fake_ip_dns_ok: true,
            auto_kill_switch_enabled: true,
            ..Default::default()
        };
        let report = build_account_audit_report_with_known(local, None, &rt, &HashMap::new());
        assert_eq!(report.quota.five_hour_pct, Some(28));
        assert_eq!(report.quota.seven_day_pct, Some(41));
        assert!(report.quota.stamp_tooltip.contains("桌面端本地缓存"));
        assert!(
            !report
                .score_result
                .deductions
                .iter()
                .any(|d| d.id == "telemetry_env_missing"),
            "未安装 CLI 且 0 B 遥测时应自动豁免，不扣遥测分: {:?}",
            report.score_result.deductions
        );
        assert_eq!(report.pending_issue_count, 0);
    }

    #[test]
    fn local_portal_hold_merges_by_exact_org_and_does_not_misattribute_other_org() {
        let now_ms = 1_795_650_000_000i64;
        let rt = RuntimeGuardContext {
            clash_online: true,
            clash_port: 7890,
            tun_online: true,
            group_rules_ok: true,
            fake_ip_dns_ok: true,
            auto_kill_switch_enabled: true,
            ..Default::default()
        };

        // 场景 A：本地日志明确捕获 portal.anthropic.com/verify?org=bce33885，且当前云端核验也是 bce33885（portal_state = unknown）
        let mut local_same = LocalAccountAudit::default();
        local_same.scanned_at_ms = now_ms;
        local_same.desktop.org_id_prefixes = vec!["bce33885".into()];
        local_same.desktop.portal_verify_hits = 6;
        local_same.desktop.portal_org_prefixes = vec!["bce33885".into()];
        local_same.all_observed_org_prefixes = vec!["bce33885".into(), "ce65bc28".into()];

        let snap_same = CloudProbeSnapshot {
            verified_at_ms: now_ms - 60_000,
            checked_at_iso: "2026-11-26T00:00:00Z".into(),
            email_masked: Some("demo***01@example.com".into()),
            org_id_prefix8: Some("bce33885".into()),
            plan: "Pro".into(),
            merchant_channel: Some("Stripe".into()),
            workspace_geo: Some("US".into()),
            edge_country: Some("US".into()),
            edge_colo: Some("SJC".into()),
            account_age_days: Some(30),
            account_created_at: None,
            subscription_age_days: Some(20),
            subscription_created_at: None,
            subscription_ends_at: None,
            chat_available: true,
            is_banned: false,
            appeals_redirect_enabled: false,
            has_monitoring_notice: false,
            active_flag_types: Vec::new(),
            warning_summary_zh: None,
            persona_kyc_status: None,
            persona_kyc_completed_at: None,
            persona_kyc_age_hours: None,
            portal_hold: false,
            portal_state: "unknown".into(),
            five_hour_pct: Some(10.0),
            five_hour_resets_at: None,
            seven_day_pct: Some(20.0),
            seven_day_resets_at: None,
            warnings: Vec::new(),
        };
        let cache_same = ProfileCloudCache {
            profile_id: "default".into(),
            bound_workspace_geo: Some("US".into()),
            bound_org_prefix8: Some("bce33885".into()),
            verify_count: 1,
            last_verified_at_ms: Some(now_ms - 60_000),
            last_snapshot: Some(snap_same.clone()),
        };

        let rep_same = build_account_audit_report_with_known(
            local_same.clone(),
            Some(&cache_same),
            &rt,
            &HashMap::new(),
        );
        let merged_snap = rep_same.cloud_snapshot.as_ref().unwrap();
        assert!(merged_snap.portal_hold, "同 org 本地 Portal 实锤必须穿透云端 unknown");
        assert_eq!(merged_snap.portal_state, "local_hold");
        assert!(
            rep_same.score_result.score <= 15,
            "命中 local_hold 必须触发致命熔断 <=15，实得 {}",
            rep_same.score_result.score
        );
        assert!(rep_same.has_danger_issue);

        // 场景 B：当前主号切换为 ce65bc28，本地只有 bce33885 的 Portal 记录 -> 绝不张冠李戴误判为 ce65bc28 的 local_hold
        let mut local_other = local_same;
        local_other.desktop.org_id_prefixes = vec!["ce65bc28".into()];
        let mut snap_other = snap_same;
        snap_other.org_id_prefix8 = Some("ce65bc28".into());
        let cache_other = ProfileCloudCache {
            profile_id: "default".into(),
            bound_workspace_geo: Some("US".into()),
            bound_org_prefix8: Some("ce65bc28".into()),
            verify_count: 1,
            last_verified_at_ms: Some(now_ms - 60_000),
            last_snapshot: Some(snap_other),
        };

        let rep_other = build_account_audit_report_with_known(
            local_other,
            Some(&cache_other),
            &rt,
            &HashMap::new(),
        );
        let other_snap = rep_other.cloud_snapshot.as_ref().unwrap();
        assert!(!other_snap.portal_hold, "不同 org 的历史 Portal 不得误判到当前主号");
        assert_eq!(other_snap.portal_state, "unknown");
    }

    #[test]
    fn new_login_org_not_overwritten_by_old_cloud_cache_and_dynamic_ages_advance() {
        let dir = tempdir().unwrap();
        let cache_path = dir.path().join("account-audit-cache.json");
        let verified_ms = 1_795_500_000_000i64;
        // 3 天后（+72h）：原 KYC 61h 必须动态推进为 133h（脱离 <=72h 高敏观察窗），注册 85 天推进为 88 天，且 Free 账号 subscription_age_days 必须为 None
        let later_ms = verified_ms + 3 * 86_400_000;

        let old_snap = CloudProbeSnapshot {
            verified_at_ms: verified_ms,
            checked_at_iso: "2026-11-26T00:00:00Z".into(),
            email_masked: Some("old***11@example.com".into()),
            org_id_prefix8: Some("a4722ea6".into()),
            plan: "Free".into(),
            merchant_channel: Some("Free 无订阅".into()),
            workspace_geo: Some("US".into()),
            edge_country: Some("TW".into()),
            edge_colo: Some("TPE".into()),
            account_age_days: Some(85),
            account_created_at: None,
            subscription_age_days: Some(40), // 模拟旧缓存里遗留的错误 40 天
            subscription_created_at: None,
            subscription_ends_at: None,
            chat_available: true,
            is_banned: false,
            appeals_redirect_enabled: false,
            has_monitoring_notice: false,
            active_flag_types: Vec::new(),
            warning_summary_zh: None,
            persona_kyc_status: Some("verified".into()),
            persona_kyc_completed_at: None,
            persona_kyc_age_hours: Some(61),
            portal_hold: false,
            portal_state: "clear".into(),
            five_hour_pct: None,
            five_hour_resets_at: None,
            seven_day_pct: None,
            seven_day_resets_at: None,
            warnings: Vec::new(),
        };
        let old_cache = ProfileCloudCache {
            profile_id: "default".into(),
            bound_workspace_geo: Some("US".into()),
            bound_org_prefix8: Some("a4722ea6".into()),
            verify_count: 1,
            last_verified_at_ms: Some(verified_ms),
            last_snapshot: Some(old_snap),
        };
        save_profile_cloud_cache(&cache_path, &old_cache).unwrap();

        let rt = RuntimeGuardContext {
            clash_online: true,
            clash_port: 7890,
            tun_online: true,
            group_rules_ok: true,
            fake_ip_dns_ok: true,
            auto_kill_switch_enabled: true,
            exit_country: Some("US".into()),
            exit_colo: Some("SJC".into()),
            ..Default::default()
        };

        // 1. 同一老号在 3 天后刷新：天数/KYC 必须动态推进，且 Free 不再显示订阅 40 天
        let mut local_old = LocalAccountAudit::default();
        local_old.scanned_at_ms = later_ms;
        local_old.desktop.org_id_prefixes = vec!["a4722ea6".into()];
        local_old.desktop.latest_active_org_prefix = Some("a4722ea6".into());
        let loaded_old = load_profile_cloud_cache_for_local(&cache_path, "default", &local_old);
        assert!(loaded_old.is_some());
        let known = load_known_accounts_map(&cache_path);
        let rep_old = build_account_audit_report_with_known(
            local_old,
            loaded_old.as_ref(),
            &rt,
            &known,
        );
        assert_eq!(rep_old.account_age_days, Some(88), "注册天数必须随时间自动递增 85 -> 88");
        assert_eq!(rep_old.subscription_age_days, None, "Free 账号绝不可误显订阅 40 天");
        assert_eq!(
            rep_old.cloud_snapshot.as_ref().and_then(|s| s.persona_kyc_age_hours),
            Some(133),
            "KYC 小时数必须从 61h 动态推进到 133h"
        );
        assert_eq!(rep_old.exit_country.as_deref(), Some("US"), "出口必须跟随实时运行态同步刷新为 US");

        // 2. 客户端新登录账号 ce65bc28（且旧号 a4722ea6 仍在日志中）：绝不被老号缓存锁死！
        let mut local_new = LocalAccountAudit::default();
        local_new.scanned_at_ms = later_ms;
        local_new.desktop.org_id_prefixes = vec!["a4722ea6".into(), "ce65bc28".into()];
        local_new.desktop.latest_active_org_prefix = Some("ce65bc28".into());
        local_new.all_observed_org_prefixes = vec!["a4722ea6".into(), "ce65bc28".into()];

        let loaded_new = load_profile_cloud_cache_for_local(&cache_path, "default", &local_new);
        assert!(
            loaded_new.is_none(),
            "新号 ce65bc28 未做过 sk 核验时绝不可错误命中老号 a4722ea6 的云端缓存"
        );
        let rep_new = build_account_audit_report_with_known(
            local_new,
            loaded_new.as_ref(),
            &rt,
            &known,
        );
        assert_eq!(rep_new.org_id_prefix8.as_deref(), Some("ce65bc28"));
        assert!(!rep_new.cloud_verified, "新登录号应诚实显示待 sk 核验");
        assert_eq!(rep_new.detected_accounts.len(), 2, "必须明确识别出 2 份登录/历史账号状态");
        assert!(rep_new.detected_accounts.iter().any(|a| a.org_prefix8 == "ce65bc28" && a.is_primary));
        assert!(rep_new
            .detected_accounts
            .iter()
            .any(|a| a.org_prefix8 == "a4722ea6" && a.email_masked.as_deref() == Some("old***11@example.com")));
    }

    #[test]
    fn account_audit_topology_matches_console_when_portal_org_detected() {
        let mut local = LocalAccountAudit::default();
        local.desktop.org_id_prefixes = vec!["1111aaaa".into(), "2222bbbb".into()];
        local.desktop.latest_active_org_prefix = Some("2222bbbb".into());
        local.desktop.portal_verify_hits = 2;
        local.desktop.portal_org_prefixes = vec!["1111aaaa".into()];
        local.all_observed_org_prefixes = vec!["1111aaaa".into(), "2222bbbb".into()];

        let rt = RuntimeGuardContext::default();
        let rep = build_account_audit_report_with_known(local, None, &rt, &HashMap::new());
        assert_eq!(
            rep.topology.hygiene_state,
            AccountHygieneState::HighRiskBanContamination,
            "账户审计传入 portal_org_prefixes 后必须与控制台 100% 同源识别为高危连坐"
        );
    }
}
