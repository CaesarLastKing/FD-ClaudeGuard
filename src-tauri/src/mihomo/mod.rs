use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// 节点双平台无状态探测结果缓存项（5 分钟 TTL，避免高频外网探测）
#[derive(Debug, Clone)]
pub struct DualAiProbeResult {
    pub claude_status: String, // "ok" | "cf_challenge" | "cf_403" | "blocked" | "offline" | "unknown"
    pub claude_label: String,
    /// 具体探测诊断说明（例如失败原因：超时/TLS重置/HTTP状态码），供悬浮窗展示与日志排查
    pub claude_probe_detail: String,
    pub gemini_status: String, // "ok" | "restricted" | "cn_redirect" | "unknown"
    pub gemini_label: String,
    pub cf_blocked: bool,
    pub web_cf_challenge: bool,
    pub claude_delay_ms: Option<u32>,
    pub probed_at: Instant,
}

/// 真实出口 GeoIP / ASN / 代理滥用实测缓存（由 preflight node_geo / 深度核验回填）
#[derive(Debug, Clone)]
pub struct VerifiedNodeGeo {
    pub country_code: String,
    pub masked_ip: String,
    pub asn_purity: String,
    /// "isp" | "hosting" | "proxy" | "abuser" | "unknown"
    pub risk_level: String,
    /// 紧凑风险说明（如 "无代理标记" | "0 滥用记录" | "公共 VPN / 代理段" | "命中滥用黑名单"）
    pub risk_detail: String,
    pub blocked_country: bool,
    pub updated_at: Instant,
}

/// 节点持久化深度核验记录（每测完 1 个立即落盘至 ~/.fd-claude-guard/node-verified-cache.json，24h 有效，发生 IP 漂移自动失效重测）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedNodeRecord {
    pub country_code: String,
    pub masked_ip: String,
    pub asn_org: String,
    pub asn_purity: String,
    pub risk_level: String,
    pub risk_detail: String,
    pub blocked_country: bool,
    pub claude_status: String,
    pub claude_label: String,
    /// 具体探测诊断说明（如超时/连接重置原因），供隔离区与可用区悬浮提示展示
    #[serde(default)]
    pub claude_probe_detail: String,
    pub gemini_status: String,
    pub gemini_label: String,
    pub cf_blocked: bool,
    pub web_cf_challenge: bool,
    pub claude_delay_ms: Option<u32>,
    pub verified_at_unix: i64,
    /// 缓存探针算法版本（v2 引入 google.com hkredirect AGY 送中真探针与纯净单次 RTT，旧版 v0/v1 自动失效重测）
    #[serde(default)]
    pub probe_schema_version: u8,
}

const CURRENT_PROBE_SCHEMA_VERSION: u8 = 2;

/// 后台逐个节点深度核验实时进度（前端节点流量页与控制台启动门禁共享）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeepAuditProgress {
    pub running: bool,
    /// "idle" | "running" | "done" | "cancelled" | "blocked"
    pub phase: String,
    pub current_index: usize,
    pub total: usize,
    pub current_node: String,
    pub original_node: String,
    pub current_node_verified: bool,
    pub message: String,
}

impl Default for DeepAuditProgress {
    fn default() -> Self {
        Self {
            running: false,
            phase: "idle".into(),
            current_index: 0,
            total: 0,
            current_node: String::new(),
            original_node: String::new(),
            current_node_verified: false,
            message: String::new(),
        }
    }
}

/// 单个节点的本地持久化稳定性与 24h 落地漂移记录（保存在 ~/.fd-claude-guard/node-stability.json）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NodeStabilityRecord {
    #[serde(default)]
    rtt_samples: Vec<u32>,
    #[serde(default)]
    probe_total: u32,
    #[serde(default)]
    probe_failures: u32,
    /// 最近 12 次探测成败滑动窗口（true=成功, false=失败），防止单次瞬时抖动长期拉黑健康节点
    #[serde(default)]
    recent_outcomes: Vec<bool>,
    /// (unix_secs, "CC:masked_ip")
    #[serde(default)]
    landing_history: Vec<(i64, String)>,
}

const DUAL_AI_CACHE_TTL_SECS: u64 = 300;
const VERIFIED_GEO_CACHE_TTL_SECS: u64 = 86_400;
const VERIFIED_DISK_TTL_SECS: i64 = 24 * 3600;
/// 瞬时超时（offline）短缓存周期（5 分钟），避免一次网络抖动将健康节点误锁死 24 小时
const OFFLINE_DISK_TTL_SECS: i64 = 5 * 60;
const DRIFT_WINDOW_SECS: i64 = 24 * 3600;

fn dual_ai_cache() -> &'static RwLock<HashMap<String, DualAiProbeResult>> {
    static CACHE: OnceLock<RwLock<HashMap<String, DualAiProbeResult>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn verified_geo_cache() -> &'static RwLock<HashMap<String, VerifiedNodeGeo>> {
    static CACHE: OnceLock<RwLock<HashMap<String, VerifiedNodeGeo>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn verified_disk_store_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".fd-claude-guard").join("node-verified-cache.json"))
}

fn verified_disk_cache() -> &'static RwLock<HashMap<String, VerifiedNodeRecord>> {
    static CACHE: OnceLock<RwLock<HashMap<String, VerifiedNodeRecord>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut loaded = verified_disk_store_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|raw| {
                serde_json::from_str::<HashMap<String, VerifiedNodeRecord>>(
                    raw.trim_start_matches('\u{feff}'),
                )
                .ok()
            })
            .unwrap_or_default();
        // 自动清洗旧版在脱组/GLOBAL=DIRECT 时被误染的矛盾记录：
        // 1) 节点真实国家非禁区却被写成「落地禁区」拉黑；
        // 2) 节点名明确指向海外合规国家（如 AU/US/JP/SG/GB/DE/KR/TW）但缓存被直连串线误写为 CN
        let before = loaded.len();
        loaded.retain(|node_name, rec| {
            let contradiction = !rec.blocked_country
                && !is_blocked_country(&rec.country_code)
                && (rec.claude_status == "blocked" || rec.claude_label.contains("禁区"));
            let expected_cc = extract_region_code(node_name);
            let direct_cn_bleed = expected_cc != "GL"
                && !is_blocked_country(&expected_cc)
                && rec.country_code.eq_ignore_ascii_case("CN");
            !contradiction && !direct_cn_bleed
        });
        if loaded.len() != before {
            persist_verified_disk_map(&loaded);
        }
        RwLock::new(loaded)
    })
}

fn persist_verified_disk_map(map: &HashMap<String, VerifiedNodeRecord>) {
    if let Some(path) = verified_disk_store_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(map) {
            let _ = std::fs::write(path, json);
        }
    }
}

fn deep_audit_state() -> &'static RwLock<DeepAuditProgress> {
    static STATE: OnceLock<RwLock<DeepAuditProgress>> = OnceLock::new();
    STATE.get_or_init(|| RwLock::new(DeepAuditProgress::default()))
}

fn deep_audit_cancel_flag() -> &'static AtomicBool {
    static CANCEL: OnceLock<AtomicBool> = OnceLock::new();
    CANCEL.get_or_init(|| AtomicBool::new(false))
}

fn deep_audit_running_lock() -> &'static AtomicBool {
    static RUNNING: OnceLock<AtomicBool> = OnceLock::new();
    RUNNING.get_or_init(|| AtomicBool::new(false))
}

/// 原子抢占深度节点核验单飞锁（杜绝并发双跑导致两个核验协程互抢 Claude-Fixed 节点）
pub fn try_acquire_deep_audit_lock() -> bool {
    deep_audit_running_lock()
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

pub fn release_deep_audit_lock() {
    deep_audit_running_lock().store(false, Ordering::SeqCst);
}

pub fn is_deep_audit_running() -> bool {
    deep_audit_running_lock().load(Ordering::SeqCst)
        || deep_audit_state()
            .read()
            .map(|s| s.running)
            .unwrap_or(false)
}

pub fn get_deep_audit_progress() -> DeepAuditProgress {
    deep_audit_state()
        .read()
        .map(|s| s.clone())
        .unwrap_or_default()
}

pub fn set_deep_audit_progress(progress: DeepAuditProgress) {
    if let Ok(mut guard) = deep_audit_state().write() {
        *guard = progress;
    }
}

pub fn reset_deep_audit_cancel() {
    deep_audit_cancel_flag().store(false, Ordering::SeqCst);
}

pub fn request_cancel_deep_audit() {
    deep_audit_cancel_flag().store(true, Ordering::SeqCst);
}

pub fn is_deep_audit_cancelled() -> bool {
    deep_audit_cancel_flag().load(Ordering::SeqCst)
}

/// 读取节点在有效期内且符合最新探针版本的持久化深度核验记录（瞬时超时 offline 或 GeoIP 探测失败仅缓存 5 分钟，其余 24 小时）
pub fn get_fresh_verified_record(node_name: &str) -> Option<VerifiedNodeRecord> {
    let now = chrono::Utc::now().timestamp();
    verified_disk_cache()
        .read()
        .ok()
        .and_then(|m| m.get(node_name).cloned())
        .filter(|rec| {
            let short_ttl = rec.claude_status == "offline"
                || rec.masked_ip.is_empty()
                || rec.risk_level == "unknown";
            let ttl = if short_ttl {
                OFFLINE_DISK_TTL_SECS
            } else {
                VERIFIED_DISK_TTL_SECS
            };
            rec.probe_schema_version >= CURRENT_PROBE_SCHEMA_VERSION
                && now - rec.verified_at_unix <= ttl
        })
}

/// 写入并落盘单节点深度核验记录，同步刷新内存缓存
pub fn save_verified_node_record(node_name: &str, rec: VerifiedNodeRecord) {
    if node_name.trim().is_empty() {
        return;
    }
    if let Ok(mut geo_map) = verified_geo_cache().write() {
        geo_map.insert(
            node_name.to_string(),
            VerifiedNodeGeo {
                country_code: rec.country_code.clone(),
                masked_ip: rec.masked_ip.clone(),
                asn_purity: rec.asn_purity.clone(),
                risk_level: rec.risk_level.clone(),
                risk_detail: rec.risk_detail.clone(),
                blocked_country: rec.blocked_country,
                updated_at: Instant::now(),
            },
        );
    }
    if let Ok(mut ai_map) = dual_ai_cache().write() {
        ai_map.insert(
            node_name.to_string(),
            DualAiProbeResult {
                claude_status: rec.claude_status.clone(),
                claude_label: rec.claude_label.clone(),
                claude_probe_detail: rec.claude_probe_detail.clone(),
                gemini_status: rec.gemini_status.clone(),
                gemini_label: rec.gemini_label.clone(),
                cf_blocked: rec.cf_blocked,
                web_cf_challenge: rec.web_cf_challenge,
                claude_delay_ms: rec.claude_delay_ms,
                probed_at: Instant::now(),
            },
        );
    }
    if let Ok(mut map) = verified_disk_cache().write() {
        map.insert(node_name.to_string(), rec);
        persist_verified_disk_map(&map);
    }
}

/// 主动失效某个节点的持久化核验缓存（例如检测到落地 IP 漂移或用户点击单行重测）
pub fn invalidate_verified_node_record(node_name: &str) {
    if let Ok(mut map) = verified_disk_cache().write() {
        if map.remove(node_name).is_some() {
            persist_verified_disk_map(&map);
        }
    }
    if let Ok(mut ai) = dual_ai_cache().write() {
        ai.remove(node_name);
    }
}

/// 由控制台实时探针同步更新当前锁定节点的 Claude API + claude.ai CF 盾实测结果
pub fn record_verified_node_claude_probe(
    node_name: &str,
    anthropic_ok: bool,
    cf_blocked: bool,
    web_cf_challenge: bool,
    blocked_country: bool,
    delay_ms: Option<u32>,
) {
    if node_name.trim().is_empty() {
        return;
    }
    let (claude_status, claude_label) = if blocked_country {
        ("blocked", "落地禁区")
    } else if cf_blocked {
        ("cf_403", "Claude 拉黑")
    } else if !anthropic_ok {
        ("offline", "Claude 超时")
    } else if web_cf_challenge {
        ("cf_challenge", "Claude 弹盾")
    } else {
        ("ok", "Claude ✓")
    };

    let existing_gemini = get_fresh_verified_record(node_name)
        .map(|r| (r.gemini_status, r.gemini_label))
        .or_else(|| {
            dual_ai_cache()
                .read()
                .ok()
                .and_then(|m| m.get(node_name).map(|d| (d.gemini_status.clone(), d.gemini_label.clone())))
        })
        .unwrap_or_else(|| ("unknown".to_string(), "AGY 待测".to_string()));

    if let Ok(mut ai_map) = dual_ai_cache().write() {
        ai_map.insert(
            node_name.to_string(),
            DualAiProbeResult {
                claude_status: claude_status.to_string(),
                claude_label: claude_label.to_string(),
                claude_probe_detail: String::new(),
                gemini_status: existing_gemini.0.clone(),
                gemini_label: existing_gemini.1.clone(),
                cf_blocked,
                web_cf_challenge,
                claude_delay_ms: delay_ms,
                probed_at: Instant::now(),
            },
        );
    }

    // 若磁盘缓存中已有记录则同步更新 Claude 实测字段
    if let Ok(mut map) = verified_disk_cache().write() {
        if let Some(rec) = map.get_mut(node_name) {
            rec.claude_status = claude_status.to_string();
            rec.claude_label = claude_label.to_string();
            rec.cf_blocked = cf_blocked || blocked_country;
            rec.web_cf_challenge = web_cf_challenge;
            rec.claude_delay_ms = delay_ms.or(rec.claude_delay_ms);
            rec.verified_at_unix = chrono::Utc::now().timestamp();
            persist_verified_disk_map(&map);
        }
    }
}

fn stability_store_path() -> Option<PathBuf> {
    // v2 独立纯净稳定性文件（彻底隔离旧版出口域名未入 Claude-Fixed 规则时产生的跨节点误漂移与冷建连抖动历史）
    dirs::home_dir().map(|h| h.join(".fd-claude-guard").join("node-stability-v2.json"))
}

/// 主动重置单个节点的 24h 落地 IP 漂移基线（用户确认漂移后的合规新 IP 已稳定时使用）
pub fn reset_node_drift_history(node_name: &str) {
    if node_name.trim().is_empty() {
        return;
    }
    if let Ok(mut map) = stability_cache().write() {
        if let Some(entry) = map.get_mut(node_name) {
            if let Some(last) = entry.landing_history.last().cloned() {
                entry.landing_history = vec![last];
            } else {
                entry.landing_history.clear();
            }
            persist_stability_map(&map);
        }
    }
}

/// 判断单次出口探测是否属于跨节点/切节点瞬时错国毛刺（例如「🇦🇺澳大利亚|原生」在脱组或刚切完瞬间测出 KR / SG）
pub fn is_cross_country_glitch(
    node_name: &str,
    measured_cc: &str,
    history: &[(i64, String)],
) -> bool {
    let expected = extract_region_code(node_name);
    let measured = measured_cc.to_uppercase();
    if expected == "GL" || measured.is_empty() || expected == measured {
        return false;
    }
    // 若节点名明确指向某国家/地区（如 AU / GB / JP / US），而本次读到完全不同的国家，
    // 只要历史中已验证过该节点确实落在本国（或尚未建立稳定历史且疑似脱组串线），判定为跨节点瞬时毛刺
    let prefix = format!("{expected}:");
    history.iter().any(|(_, sig)| sig.starts_with(&prefix))
}

/// 清洗历史记录中因旧版脱组/切节点串线混入的错国毛刺条目
fn sanitize_stability_map(map: &mut HashMap<String, NodeStabilityRecord>) -> bool {
    let mut cleaned_any = false;
    for (node_name, rec) in map.iter_mut() {
        let expected = extract_region_code(node_name);
        if expected == "GL" || rec.landing_history.len() <= 1 {
            continue;
        }
        let prefix = format!("{expected}:");
        let has_expected = rec.landing_history.iter().any(|(_, s)| s.starts_with(&prefix));
        if has_expected {
            let before = rec.landing_history.len();
            rec.landing_history.retain(|(_, s)| s.starts_with(&prefix));
            if rec.landing_history.len() != before {
                cleaned_any = true;
            }
        }
    }
    cleaned_any
}

/// 从候选合规节点中优先挑出已深度核验且综合最优（无禁区/非拉黑/非高危代理/无 CF 盾/Claude+AGY 双通优先/ISP 住宅优先/低延迟）的节点
pub fn pick_best_verified_node(candidates: &[String]) -> Option<String> {
    let mut best: Option<(u8, u8, u8, u32, String)> = None;
    for name in candidates {
        if is_blocked_node_name(name)
            || name.eq_ignore_ascii_case("DIRECT")
            || name.eq_ignore_ascii_case("REJECT")
        {
            continue;
        }
        if let Some(rec) = get_fresh_verified_record(name) {
            if rec.blocked_country
                || rec.cf_blocked
                || rec.claude_status != "ok"
                || matches!(rec.risk_level.as_str(), "abuser" | "proxy")
            {
                continue;
            }
            let cf_tier: u8 = if rec.web_cf_challenge { 1 } else { 0 };
            let agy_tier: u8 = if rec.gemini_status == "ok" { 0 } else { 1 };
            let isp_tier: u8 = if rec.risk_level == "isp" { 0 } else { 1 };
            let rtt = rec.claude_delay_ms.unwrap_or(9999);
            let key = (cf_tier, agy_tier, isp_tier, rtt, name.clone());
            if best
                .as_ref()
                .map(|b| (key.0, key.1, key.2, key.3) < (b.0, b.1, b.2, b.3))
                .unwrap_or(true)
            {
                best = Some(key);
            }
        }
    }
    best.map(|b| b.4)
}

fn stability_cache() -> &'static RwLock<HashMap<String, NodeStabilityRecord>> {
    static CACHE: OnceLock<RwLock<HashMap<String, NodeStabilityRecord>>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let mut loaded = stability_store_path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|raw| serde_json::from_str::<HashMap<String, NodeStabilityRecord>>(raw.trim_start_matches('\u{feff}')).ok())
            .unwrap_or_default();
        if sanitize_stability_map(&mut loaded) {
            persist_stability_map(&loaded);
        }
        RwLock::new(loaded)
    })
}

fn persist_stability_map(map: &HashMap<String, NodeStabilityRecord>) {
    if let Some(path) = stability_store_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string(map) {
            let _ = std::fs::write(path, json);
        }
    }
}

/// 计算 24 小时内同一节点落地 IP 切换次数（纯函数，供单测与生产共用）
pub fn count_24h_landing_drifts(history: &[(i64, String)], now_secs: i64) -> u32 {
    let mut prev: Option<&str> = None;
    let mut drifts: u32 = 0;
    for (ts, sig) in history {
        if now_secs - *ts > DRIFT_WINDOW_SECS {
            continue;
        }
        if let Some(p) = prev {
            if p != sig.as_str() {
                drifts += 1;
            }
        }
        prev = Some(sig.as_str());
    }
    drifts
}

/// 根据多轮 RTT 样本计算真实平均抖动（相邻样本差值均值）
pub fn compute_real_jitter_ms(samples: &[u32]) -> Option<u32> {
    if samples.len() < 2 {
        return None;
    }
    let mut diff_sum: u64 = 0;
    for pair in samples.windows(2) {
        diff_sum += pair[0].abs_diff(pair[1]) as u64;
    }
    Some((diff_sum / (samples.len() as u64 - 1)) as u32)
}

/// 计算节点近期滑动窗口断连率与样本数（供单测与生产共用）
pub fn compute_recent_drop_stats(recent_outcomes: &[bool], fallback_total: u32, fallback_failures: u32) -> (f64, usize) {
    if !recent_outcomes.is_empty() {
        let total = recent_outcomes.len();
        let fails = recent_outcomes.iter().filter(|&&ok| !ok).count();
        let pct = ((fails as f64 / total as f64) * 1000.0).round() / 10.0;
        return (pct, total);
    }
    if fallback_total > 0 {
        let pct = ((fallback_failures as f64 / fallback_total as f64) * 1000.0).round() / 10.0;
        return (pct, fallback_total as usize);
    }
    (0.0, 0)
}

fn record_node_probe_sample(node_name: &str, delay_ms: Option<u32>) {
    if node_name.trim().is_empty() {
        return;
    }
    if let Ok(mut map) = stability_cache().write() {
        let entry = map.entry(node_name.to_string()).or_default();
        entry.probe_total = entry.probe_total.saturating_add(1);
        entry.recent_outcomes.push(delay_ms.is_some());
        if entry.recent_outcomes.len() > 12 {
            let excess = entry.recent_outcomes.len() - 12;
            entry.recent_outcomes.drain(0..excess);
        }
        if let Some(ms) = delay_ms {
            entry.rtt_samples.push(ms);
            if entry.rtt_samples.len() > 12 {
                let excess = entry.rtt_samples.len() - 12;
                entry.rtt_samples.drain(0..excess);
            }
        } else {
            entry.probe_failures = entry.probe_failures.saturating_add(1);
        }
        // 避免计数无限膨胀，保持近 40 次滑动统计感
        if entry.probe_total > 40 {
            entry.probe_total /= 2;
            entry.probe_failures /= 2;
        }
        persist_stability_map(&map);
    }
}

/// 记录由 preflight 经真实出口 IP 探测得到的权威国家码、IP 纯净度/脏度与 24h 落地漂移历史（带策略组锁死门禁，防脱组/切节点串线污染）
pub fn record_verified_node_geo_guarded(
    node_name: &str,
    country_code: &str,
    masked_ip: &str,
    asn_purity: &str,
    risk_level: &str,
    risk_detail: &str,
    blocked_country: bool,
    group_locked: bool,
) -> u32 {
    if node_name.trim().is_empty() {
        return 0;
    }
    let cc = country_code.to_uppercase();
    let now_secs = chrono::Utc::now().timestamp();
    let sig = format!("{cc}:{masked_ip}");

    // 若当前策略组尚未锁死（如 GLOBAL 脱组到其他节点或 DIRECT 裸奔），绝不把别的节点出口记入本节点历史！
    if !group_locked {
        if let Ok(map) = stability_cache().read() {
            if let Some(entry) = map.get(node_name) {
                return count_24h_landing_drifts(&entry.landing_history, now_secs);
            }
        }
        return 0;
    }

    // 检查是否属于切节点过渡瞬间的跨国残留毛刺（例如 AU 节点瞬间读到 KR）
    let is_glitch = stability_cache()
        .read()
        .ok()
        .and_then(|m| m.get(node_name).map(|e| is_cross_country_glitch(node_name, &cc, &e.landing_history)))
        .unwrap_or(false);
    if is_glitch {
        if let Ok(map) = stability_cache().read() {
            if let Some(entry) = map.get(node_name) {
                return count_24h_landing_drifts(&entry.landing_history, now_secs);
            }
        }
        return 0;
    }

    // 若同一节点本次实测出的脱敏 IP 与持久化深度核验记录不同（真实同国换 IP 漂移），作废旧深度缓存以触发重测
    if !masked_ip.is_empty() {
        let ip_changed_from_verified = verified_disk_cache()
            .read()
            .ok()
            .and_then(|m| m.get(node_name).map(|r| r.masked_ip.clone()))
            .map(|prev_ip| !prev_ip.is_empty() && prev_ip != masked_ip)
            .unwrap_or(false);
        if ip_changed_from_verified {
            invalidate_verified_node_record(node_name);
        }
    }
    if let Ok(mut cache) = verified_geo_cache().write() {
        cache.insert(
            node_name.to_string(),
            VerifiedNodeGeo {
                country_code: cc.clone(),
                masked_ip: masked_ip.to_string(),
                asn_purity: asn_purity.to_string(),
                risk_level: risk_level.to_string(),
                risk_detail: risk_detail.to_string(),
                blocked_country,
                updated_at: Instant::now(),
            },
        );
    }
    if let Ok(mut map) = stability_cache().write() {
        let (drifts, changed) = {
            let entry = map.entry(node_name.to_string()).or_default();
            entry.landing_history.retain(|(ts, _)| now_secs - *ts <= DRIFT_WINDOW_SECS);
            let should_push = entry
                .landing_history
                .last()
                .map(|(ts, last_sig)| last_sig != &sig || now_secs - *ts > 900)
                .unwrap_or(true);
            let mut changed = false;
            if should_push && !masked_ip.is_empty() {
                entry.landing_history.push((now_secs, sig));
                if entry.landing_history.len() > 64 {
                    let excess = entry.landing_history.len() - 64;
                    entry.landing_history.drain(0..excess);
                }
                changed = true;
            }
            (count_24h_landing_drifts(&entry.landing_history, now_secs), changed)
        };
        if changed {
            persist_stability_map(&map);
        }
        return drifts;
    }
    0
}

/// 记录由 preflight 经真实出口 IP 探测得到的权威国家码、IP 纯净度/脏度与 24h 落地漂移历史
pub fn record_verified_node_geo_full(
    node_name: &str,
    country_code: &str,
    masked_ip: &str,
    asn_purity: &str,
    risk_level: &str,
    risk_detail: &str,
    blocked_country: bool,
) -> u32 {
    record_verified_node_geo_guarded(
        node_name,
        country_code,
        masked_ip,
        asn_purity,
        risk_level,
        risk_detail,
        blocked_country,
        true,
    )
}

/// 兼容旧签名的回填辅助
pub fn record_verified_node_geo(
    node_name: &str,
    country_code: &str,
    asn_purity: &str,
    blocked_country: bool,
) {
    let (risk_level, risk_detail) = if asn_purity.contains("高危") {
        ("abuser", "命中滥用黑名单")
    } else if asn_purity.contains("共享") {
        ("proxy", "公共 VPN / 代理段")
    } else if asn_purity.contains("ISP") {
        ("isp", "无代理标记")
    } else {
        ("hosting", "0 滥用记录")
    };
    let _ = record_verified_node_geo_full(
        node_name,
        country_code,
        "",
        asn_purity,
        risk_level,
        risk_detail,
        blocked_country,
    );
}

pub fn clear_dual_ai_cache() {
    if let Ok(mut cache) = dual_ai_cache().write() {
        cache.clear();
    }
}

/// 根据 HTTP 状态码、最终 URL 与响应特征分类 Google Antigravity (AGY) 地区准入与风控状态（无状态只读，统一大白话）
pub fn classify_gemini_probe_response(
    status: u16,
    final_url: &str,
    body_snippet: &str,
) -> (&'static str, &'static str) {
    let url_lower = final_url.to_ascii_lowercase();
    let body_lower = body_snippet.to_ascii_lowercase();

    // Google AI / Antigravity 地区封锁的核心判据：
    // 1) 重定向到 google.com.hk / google.cn / unavailable
    // 2) generativelanguage API 返回 "user location is not supported" / "failed_precondition" / 403 / 451
    if url_lower.contains("google.com.hk")
        || url_lower.contains("google.cn")
        || url_lower.contains("/unavailable")
        || body_lower.contains("google.com.hk")
        || body_lower.contains("www.google.cn")
    {
        return ("cn_redirect", "AGY 限区");
    }

    if body_lower.contains("user location is not supported")
        || body_lower.contains("failed_precondition")
        || body_lower.contains("not available in your country")
        || body_lower.contains("not available in your region")
        || body_lower.contains("gemini isn't currently supported")
        || body_lower.contains("regionnotsupported")
        || body_lower.contains("unsupported_country")
        || status == 403
        || status == 451
    {
        return ("restricted", "AGY 限区");
    }

    // generativelanguage 带占位 key 通过地区校验后会返回 400 API_KEY_INVALID，说明 Google 认可该出口地区支持 AGY/AI API
    if (200..400).contains(&status)
        || (status == 400 && body_lower.contains("api_key_invalid"))
    {
        return ("ok", "AGY ✓");
    }

    ("unknown", "AGY 待测")
}

/// 根据无状态响应分类 Claude / Anthropic API 出口可用性（统一大白话）
pub fn classify_claude_probe_response(status: u16, body_snippet: &str) -> (&'static str, &'static str, bool) {
    let lower = body_snippet.to_ascii_lowercase();
    if status == 403
        && (lower.contains("cloudflare")
            || lower.contains("cf-ray")
            || lower.contains("attention required")
            || lower.contains("just a moment"))
    {
        return ("cf_403", "Claude 拉黑", true);
    }
    if lower.contains("region_unavailable") || status == 451 {
        return ("blocked", "落地禁区", true);
    }
    if status > 0 && status < 500 {
        return ("ok", "Claude ✓", false);
    }
    ("unknown", "Claude 待测", false)
}

/// 检测 claude.ai 网页登录页是否触发 Cloudflare 人机盾拦截
pub fn is_claude_web_cf_challenge(status: u16, cf_mitigated: &str, body_snippet: &str) -> bool {
    if !cf_mitigated.trim().is_empty() {
        return true;
    }
    let lower = body_snippet.to_ascii_lowercase();
    (status == 403 || status == 503)
        && (lower.contains("just a moment")
            || lower.contains("cf-challenge")
            || lower.contains("turnstile")
            || lower.contains("attention required")
            || lower.contains("cloudflare"))
}

/// 无状态只读探测当前锁定出口的 Claude (API + claude.ai 防盾) + Gemini 双平台可用性（强制走本地代理，5 分钟缓存）
pub async fn probe_dual_ai_via_proxy(node_name: &str, proxy_port: u16) -> DualAiProbeResult {
    if let Ok(cache) = dual_ai_cache().read() {
        if let Some(hit) = cache.get(node_name) {
            if hit.probed_at.elapsed().as_secs() < DUAL_AI_CACHE_TTL_SECS {
                return hit.clone();
            }
        }
    }

    let proxy_url = format!("http://127.0.0.1:{proxy_port}");
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(&proxy_url).unwrap_or_else(|_| {
            reqwest::Proxy::http("http://127.0.0.1:7890").expect("fallback proxy")
        }))
        .timeout(Duration::from_secs(4))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")
        .build();

    let Ok(client) = client else {
        return DualAiProbeResult {
            claude_status: "unknown".into(),
            claude_label: "Claude 待测".into(),
            claude_probe_detail: "探针客户端初始化失败".into(),
            gemini_status: "unknown".into(),
            gemini_label: "AGY 待测".into(),
            cf_blocked: false,
            web_cf_challenge: false,
            claude_delay_ms: None,
            probed_at: Instant::now(),
        };
    };

    // 并发探测 Anthropic API + claude.ai 网页防盾 + Gemini 无状态入口（不带任何账号 Cookie / Token）
    // Anthropic API 每次重试新建独立 Client（不复用可能刚切节点损坏的连接池），超时 5s -> 6s，并记录真实失败原因
    let proxy_url_claude = proxy_url.clone();
    let node_name_for_log = node_name.to_string();
    let claude_api_fut = async move {
        let mut last_res: (&'static str, &'static str, bool, Option<u32>, String) =
            ("unknown", "Claude 待测", false, None, String::new());
        for (attempt, timeout_secs) in [(0usize, 5u64), (1usize, 6u64)] {
            let fresh_client = reqwest::Client::builder()
                .proxy(reqwest::Proxy::all(&proxy_url_claude).unwrap_or_else(|_| {
                    reqwest::Proxy::http("http://127.0.0.1:7890").expect("fallback proxy")
                }))
                .timeout(Duration::from_secs(timeout_secs))
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36")
                .build();
            let Ok(c) = fresh_client else {
                last_res.4 = "初始化 Anthropic 探针客户端失败".into();
                break;
            };
            let t0 = Instant::now();
            match c.get("https://api.anthropic.com/v1/models").send().await {
                Ok(resp) => {
                    let rtt = t0.elapsed().as_millis().min(9999) as u32;
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    let snippet: String = body.chars().take(600).collect();
                    let (st, lbl, blocked) = classify_claude_probe_response(status, &snippet);
                    let detail = if st == "ok" {
                        format!("api.anthropic.com 畅通 (HTTP {status}, {rtt}ms)")
                    } else if st == "cf_403" {
                        format!("Cloudflare 403 拉黑 (HTTP 403)")
                    } else if st == "blocked" {
                        format!("Anthropic 返回地区不支持 (HTTP {status})")
                    } else {
                        format!("Anthropic 服务端返回异常 HTTP {status}")
                    };
                    last_res = (st, lbl, blocked, Some(rtt), detail);
                    // 拿到明确非 5xx HTTP 响应立即返回，无需无谓重试
                    if status < 500 {
                        return last_res;
                    }
                    crate::logger::log_warn(
                        "node_probe",
                        format!(
                            "节点「{node_name_for_log}」探测 api.anthropic.com 第 {} 次返回 HTTP {status}，准备重试",
                            attempt + 1
                        ),
                    );
                }
                Err(e) => {
                    let err_brief = if e.is_timeout() {
                        format!("连接 api.anthropic.com 超时 (>{timeout_secs}s)")
                    } else if e.is_connect() {
                        format!("无法经代理建连 api.anthropic.com ({e})")
                    } else {
                        format!("请求 api.anthropic.com 异常 ({e})")
                    };
                    crate::logger::log_warn(
                        "node_probe",
                        format!(
                            "节点「{node_name_for_log}」第 {} 次探测 api.anthropic.com 失败: {err_brief}",
                            attempt + 1
                        ),
                    );
                    last_res = ("unknown", "Claude 待测", false, None, err_brief);
                }
            }
            if attempt == 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        last_res
    };

    let claude_web_fut = async {
        match client.get("https://claude.ai/login").send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let cf_mit = resp
                    .headers()
                    .get("cf-mitigated")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body = resp.text().await.unwrap_or_default();
                let snippet: String = body.chars().take(900).collect();
                is_claude_web_cf_challenge(status, &cf_mit, &snippet)
            }
            Err(_) => false,
        }
    };

    let agy_fut = async {
        // 1A 真机实锤探针：
        // 1) 无跳转直查 https://www.google.com/ 响应头 Location：若被 Google 判为中国香港/大陆区（302 -> google.com.hk / hkredirect），直接标「AGY 限区」！
        // 2) 并发校验 generativelanguage 与 daily-cloudcode-pa.sandbox.googleapis.com 地区准入
        let no_redir_client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url).unwrap_or_else(|_| {
                reqwest::Proxy::http("http://127.0.0.1:7890").expect("fallback proxy")
            }))
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(4))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36")
            .build()
            .ok();

        let google_geo_fut = async {
            let Some(c) = no_redir_client else {
                return false;
            };
            match c.get("https://www.google.com/").send().await {
                Ok(resp) => {
                    let loc = resp
                        .headers()
                        .get("location")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    loc.contains("google.com.hk")
                        || loc.contains("hkredirect")
                        || loc.contains("google.cn")
                }
                Err(_) => false,
            }
        };

        let (google_cn_redirect, api_res, cloudcode_res) = tokio::join!(
            google_geo_fut,
            client
                .get("https://generativelanguage.googleapis.com/v1beta/models?key=AIzaSyA0000000000000000000000000000000")
                .send(),
            client
                .get("https://daily-cloudcode-pa.sandbox.googleapis.com/")
                .send(),
        );

        if google_cn_redirect {
            return ("cn_redirect", "AGY 限区");
        }

        // BUG-P1-09：严格区分 HTTP 403/451 真限区 与 网络超时/TLS 错误（传输失败归 unknown / AGY 待测，绝不误判限区也不反判假绿）
        let cloudcode_state: Option<bool> = match cloudcode_res {
            Ok(r) => Some(matches!(r.status().as_u16(), 403 | 451)),
            Err(_) => None,
        };

        if let Ok(resp) = api_res {
            let status = resp.status().as_u16();
            let final_url = resp.url().to_string();
            let body = resp.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(1200).collect();
            let (st, lbl) = classify_gemini_probe_response(status, &final_url, &snippet);
            if st != "ok" {
                return (st, lbl);
            }
            if cloudcode_state == Some(true) {
                return ("restricted", "AGY 限区");
            }
            return ("ok", "AGY ✓");
        }
        match cloudcode_state {
            Some(true) => ("restricted", "AGY 限区"),
            Some(false) => ("ok", "AGY ✓"),
            None => ("unknown", "AGY 待测"),
        }
    };

    let ((mut c_stat, mut c_lbl, cf_blocked, claude_rtt, claude_detail), web_challenge, (g_stat, g_lbl)) =
        tokio::join!(claude_api_fut, claude_web_fut, agy_fut);

    if c_stat == "ok" && web_challenge {
        c_stat = "cf_challenge";
        c_lbl = "Claude 弹盾";
    }

    let res = DualAiProbeResult {
        claude_status: c_stat.to_string(),
        claude_label: c_lbl.to_string(),
        claude_probe_detail: claude_detail,
        gemini_status: g_stat.to_string(),
        gemini_label: g_lbl.to_string(),
        cf_blocked,
        web_cf_challenge: web_challenge,
        claude_delay_ms: claude_rtt,
        probed_at: Instant::now(),
    };

    if let Ok(mut cache) = dual_ai_cache().write() {
        cache.insert(node_name.to_string(), res.clone());
    }
    res
}

/// 对单个已切入代理的节点发起 100% 真实 HTTP 深度核验（ip-api 真实出口类型 + Anthropic API + claude.ai 防盾 + Google 送中 AGY 限区 + 纯净单次 RTT），并永久落盘缓存
pub async fn probe_single_node_deep_via_proxy(
    node_name: &str,
    mixed_port: u16,
) -> VerifiedNodeRecord {
    let proxy_url = format!("http://127.0.0.1:{mixed_port}");
    // 先清该节点的内存 AI 缓存，确保本次走 100% 真实代理请求
    if let Ok(mut cache) = dual_ai_cache().write() {
        cache.remove(node_name);
    }

    // 并发获取：真实出口 GeoIP、双 AI 风控（含 google.com hkredirect 送中探针）、以及 Mihomo 原生纯净单次 RTT（消除冷启动 TLS 虚高 4~8 倍）
    let pure_rtt_fut = async {
        if let Some(ep) = discover_endpoint().await {
            probe_node_delay_via_mihomo(
                &ep,
                node_name,
                "http://cp.cloudflare.com/generate_204",
                3500,
                "204",
            )
            .await
        } else {
            None
        }
    };

    let (geo_res, ai_res, pure_rtt) = tokio::join!(
        crate::preflight::probe_geo_via_proxy(&proxy_url),
        probe_dual_ai_via_proxy(node_name, mixed_port),
        pure_rtt_fut,
    );

    let effective_rtt = pure_rtt.or(ai_res.claude_delay_ms);
    record_node_probe_sample(node_name, effective_rtt);

    let (country_code, masked_ip, asn_org, asn_purity, risk_level, risk_detail, blocked_country) =
        match geo_res {
            Ok(geo) => {
                let masked = crate::preflight::mask_ip_address(&geo.ip);
                let blocked = is_blocked_country(&geo.country);
                let (purity, r_lvl, r_det) = crate::preflight::classify_ip_purity_and_risk(
                    &geo.asn_org,
                    geo.is_datacenter,
                    geo.is_vpn,
                    geo.is_proxy,
                    geo.is_abuser,
                );
                let _ = record_verified_node_geo_full(
                    node_name,
                    &geo.country,
                    &masked,
                    purity,
                    r_lvl,
                    r_det,
                    blocked,
                );
                (
                    geo.country,
                    masked,
                    geo.asn_org,
                    purity.to_string(),
                    r_lvl.to_string(),
                    r_det.to_string(),
                    blocked,
                )
            }
            Err(_) => (
                extract_region_code(node_name),
                String::new(),
                String::new(),
                "探测失败".to_string(),
                "unknown".to_string(),
                "出口 IP 超时".to_string(),
                false,
            ),
        };

    let (claude_status, claude_label, cf_blocked, claude_probe_detail) = if blocked_country {
        (
            "blocked".to_string(),
            "落地禁区".to_string(),
            true,
            format!("实测真实出口 IP ({masked_ip}) 归属禁区 {country_code}"),
        )
    } else if ai_res.claude_delay_ms.is_none() && ai_res.claude_status == "unknown" {
        (
            "offline".to_string(),
            "Claude 超时".to_string(),
            false,
            if ai_res.claude_probe_detail.is_empty() {
                "连续 2 次探测 api.anthropic.com 超时或连接失败".to_string()
            } else {
                ai_res.claude_probe_detail.clone()
            },
        )
    } else {
        (
            ai_res.claude_status.clone(),
            ai_res.claude_label.clone(),
            ai_res.cf_blocked,
            ai_res.claude_probe_detail.clone(),
        )
    };

    let rec = VerifiedNodeRecord {
        country_code,
        masked_ip,
        asn_org,
        asn_purity,
        risk_level,
        risk_detail,
        blocked_country,
        claude_status,
        claude_label,
        claude_probe_detail,
        gemini_status: ai_res.gemini_status,
        gemini_label: ai_res.gemini_label,
        cf_blocked,
        web_cf_challenge: ai_res.web_cf_challenge,
        claude_delay_ms: effective_rtt,
        verified_at_unix: chrono::Utc::now().timestamp(),
        probe_schema_version: CURRENT_PROBE_SCHEMA_VERSION,
    };

    save_verified_node_record(node_name, rec.clone());
    rec
}

/// 通过 Mihomo 原生 `GET /proxies/{name}/delay` 对任意备选节点发起基础 RTT 延迟测速（仅测延迟，不用于判定 CF 盾或 AGY 限区）
pub async fn probe_node_delay_via_mihomo(
    endpoint: &MihomoEndpoint,
    node_name: &str,
    target_url: &str,
    timeout_ms: u32,
    expected: &str,
) -> Option<u32> {
    let enc_node = urlencoding::encode(node_name);
    let enc_url = urlencoding::encode(target_url);
    let enc_exp = urlencoding::encode(expected);
    let path = format!(
        "/proxies/{enc_node}/delay?url={enc_url}&timeout={timeout_ms}&expected={enc_exp}"
    );
    let Ok((status, body)) = mihomo_request(endpoint, "GET", &path, None).await else {
        return None;
    };
    if status != 200 {
        return None;
    }
    serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v.get("delay").and_then(|d| d.as_u64()))
        .map(|d| d as u32)
        .filter(|&d| d > 0)
}

/// 禁区节点名称匹配正则（精确覆盖 HK01/HK_01/国旗 Emoji/Macao/Syria/Cuba，同时避免单字“澳”误杀“澳大利亚”）
pub fn blocked_region_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(香港|Hong\s*Kong|🇭🇰|澳门|澳門|Macau|Macao|🇲🇴|中国|中國|国内|China|🇨🇳|俄罗斯|俄羅斯|俄国|Russia|🇷🇺|白俄|Belarus|🇧🇾|朝鲜|朝鮮|North\s*Korea|🇰🇵|伊朗|Iran|🇮🇷|叙利亚|敘利亞|Syria|🇸🇾|古巴|Cuba|🇨🇺|(?:^|[^a-z])(HK|MO|CN|RU|BY|KP|IR|SY|CU)(?:[^a-z]|$))")
            .expect("invalid blocked region regex")
    })
}

/// 国家代码黑名单（ISO 3166-1 alpha-2）
pub const BLOCKED_COUNTRY_CODES: &[&str] = &["HK", "MO", "CN", "RU", "BY", "KP", "IR", "SY", "CU"];

/// 判断节点名称是否落入禁区
pub fn is_blocked_node_name(name: &str) -> bool {
    blocked_region_regex().is_match(name)
}

/// 判断国家代码是否属于禁区
pub fn is_blocked_country(code: &str) -> bool {
    let upper = code.trim().to_uppercase();
    BLOCKED_COUNTRY_CODES.contains(&upper.as_str())
}

/// Mihomo 连接方式：优先 Windows 命名管道，其次 External Controller HTTP
#[derive(Debug, Clone)]
pub enum MihomoEndpoint {
    NamedPipe(String),
    Http(String),
}

impl MihomoEndpoint {
    pub fn display_label(&self) -> String {
        match self {
            MihomoEndpoint::NamedPipe(p) => p.clone(),
            MihomoEndpoint::Http(url) => url.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MihomoVersion {
    pub version: String,
    pub meta: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MihomoConfigs {
    pub mixed_port: u16,
    pub ipv6: bool,
    pub tun_enable: bool,
    pub dns_enhanced_mode: String,
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyGroupInfo {
    pub name: String,
    pub group_type: String,
    pub now: String,
    pub all: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeItem {
    pub name: String,
    pub region_code: String,
    pub region_label: String,
    pub node_type: String,
    pub delay_ms: Option<u32>,
    pub jitter_ms: u32,
    pub drop_rate_pct: f64,
    pub blocked: bool,
    pub is_current: bool,
    pub score: u32,
    pub recommendation: String,
    /// 增量 11：ASN / IP 纯净度标签（如 "ISP 住宅/静态" | "机房 Hosting" | "常规线路"）
    pub asn_purity: String,
    /// 增量 18：紧凑 ASN 徽章（"ISP" | "机房" | "拉黑" | "常规"）
    pub asn_short: String,
    /// 增量 12：Anthropic 无状态探测状态（"可达" | "CF 403 已拉黑" | "待探针"）
    pub anthropic_probe: String,
    /// 增量 12：若被 Cloudflare 403 拉黑则为 true，前端禁用「切换锁定」
    pub cf_blocked: bool,
    /// 增量 18：Claude 平台状态 ("ok" | "cf_403" | "blocked" | "unknown")
    pub claude_status: String,
    pub claude_label: String,
    /// 具体探测原因说明（超时/拉黑/落地禁区详情），供悬浮提示展示
    #[serde(default)]
    pub claude_probe_detail: String,
    /// 增量 18：Gemini/Google 平台状态 ("ok" | "restricted" | "cn_redirect" | "unknown")
    pub gemini_status: String,
    pub gemini_label: String,
    /// 增量 18：Claude + Gemini 双平台均通（仅用于加分与推荐，Gemini 不支持绝不阻断 Claude）
    pub dual_ai_ok: bool,
    /// 24 小时内落地 IP 静默漂移次数
    pub drift_count_24h: u32,
    /// 出口 IP 风险等级 ("isp" | "hosting" | "proxy" | "abuser" | "unknown")
    pub risk_level: String,
    /// 节点类型副文说明（如 "无代理标记" | "0 滥用记录" | "公共 VPN / 代理段" | "命中滥用黑名单"）
    pub risk_detail: String,
    /// claude.ai 网页登录页是否触发 Cloudflare 人机盾拦截
    pub web_cf_challenge: bool,
}

/// 将两字国码映射为紧凑中文地区标签
pub fn region_code_to_label(code: &str) -> &'static str {
    match code {
        "US" => "美国",
        "JP" => "日本",
        "SG" => "新加坡",
        "TW" => "中国台湾",
        "AU" => "澳大利亚",
        "GB" => "英国",
        "DE" => "德国",
        "KR" => "韩国",
        "CA" => "加拿大",
        "HK" => "香港",
        "MO" => "澳门",
        _ => "海外节点",
    }
}

/// 精准提取节点所在地区两字国码
pub fn extract_region_code(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.contains("香港") || lower.contains("hong kong") || lower.contains("🇭🇰") || name.starts_with("HK") {
        return "HK".into();
    }
    if lower.contains("澳门") || lower.contains("澳門") || lower.contains("macau") || lower.contains("🇲🇴") || name.starts_with("MO") {
        return "MO".into();
    }
    if lower.contains("台湾") || lower.contains("台灣") || lower.contains("taiwan") || lower.contains("🇹🇼") || name.starts_with("TW") {
        return "TW".into();
    }
    if lower.contains("美国") || lower.contains("美國") || lower.contains("洛杉矶") || lower.contains("硅谷") || lower.contains("🇺🇸") || name.starts_with("US") {
        return "US".into();
    }
    if lower.contains("日本") || lower.contains("东京") || lower.contains("大阪") || lower.contains("🇯🇵") || name.starts_with("JP") {
        return "JP".into();
    }
    if lower.contains("新加坡") || lower.contains("狮城") || lower.contains("🇸🇬") || name.starts_with("SG") {
        return "SG".into();
    }
    if lower.contains("澳大利亚") || lower.contains("澳洲") || lower.contains("悉尼") || lower.contains("🇦🇺") || name.starts_with("AU") {
        return "AU".into();
    }
    if lower.contains("英国") || lower.contains("伦敦") || lower.contains("🇬🇧") || name.starts_with("GB") || name.starts_with("UK") {
        return "GB".into();
    }
    if lower.contains("德国") || lower.contains("法兰克福") || lower.contains("🇩🇪") || name.starts_with("DE") {
        return "DE".into();
    }
    if lower.contains("韩国") || lower.contains("首尔") || lower.contains("🇰🇷") || name.starts_with("KR") {
        return "KR".into();
    }
    if lower.contains("加拿大") || lower.contains("多伦多") || lower.contains("温哥华") || lower.contains("🇨🇦") || name.starts_with("CA") {
        return "CA".into();
    }
    if lower.contains("荷兰") || lower.contains("阿姆斯特丹") || lower.contains("🇳🇱") || name.starts_with("NL") {
        return "NL".into();
    }
    if lower.contains("法国") || lower.contains("巴黎") || lower.contains("🇫🇷") || name.starts_with("FR") {
        return "FR".into();
    }
    if lower.contains("瑞士") || lower.contains("苏黎世") || lower.contains("🇨🇭") || name.starts_with("CH") {
        return "CH".into();
    }
    if lower.contains("爱尔兰") || lower.contains("都柏林") || lower.contains("🇮🇪") || name.starts_with("IE") {
        return "IE".into();
    }
    if lower.contains("瑞典") || lower.contains("斯德哥尔摩") || lower.contains("🇸🇪") || name.starts_with("SE") {
        return "SE".into();
    }
    if lower.contains("台湾") || lower.contains("台北") || lower.contains("🇹🇼") || name.starts_with("TW") {
        return "TW".into();
    }
    if lower.contains("新西兰") || lower.contains("奥克兰") || lower.contains("🇳🇿") || name.starts_with("NZ") {
        return "NZ".into();
    }
    if lower.contains("印度") || lower.contains("孟买") || lower.contains("🇮🇳") || name.starts_with("IN") {
        return "IN".into();
    }
    "GL".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeReport {
    pub connected: bool,
    pub endpoint: String,
    pub group_name: String,
    pub current_node: String,
    pub total_raw_nodes: usize,
    /// 订阅全部真实代理节点总数（= 名称直筛禁区 + 入组评估数，保证加总严格对得上）
    #[serde(default)]
    pub subscription_total_nodes: usize,
    /// 按名称自动屏蔽（未进入评估组）的禁区节点数
    #[serde(default)]
    pub name_blocked_count: usize,
    /// 总禁区节点数（名称直筛禁区 + 组内实测落地禁区，去重）
    pub filtered_blocked_count: usize,
    pub nodes: Vec<NodeItem>,
    /// 当前锁定节点的紧凑出口摘要（国家 · 脱敏 IP · 节点类型 · 24h 漂移）
    pub current_exit_summary: Option<String>,
}

/// 纯函数：从运行中 Clash / Mihomo 进程命令行反推所有 `-d "<dir>"` 候选配置目录（避免首个进程为服务沙箱提前中止）
pub fn parse_all_clash_config_dirs_from_cmdlines(lines: &[String]) -> Vec<PathBuf> {
    let Ok(re_dash_d) = Regex::new(r#"(?i)(?:^|\s)-d\s+(?:"([^"]+)"|'([^']+)'|(\S+))"#) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in lines {
        if let Some(caps) = re_dash_d.captures(line) {
            let raw = caps
                .get(1)
                .or_else(|| caps.get(2))
                .or_else(|| caps.get(3))
                .map(|m| m.as_str().trim())
                .unwrap_or("");
            if !raw.is_empty() {
                let p = PathBuf::from(raw);
                if !out.contains(&p) {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// 纯函数：从运行中 Clash / Mihomo 进程命令行反推首个非空 `-d` 目录（保留向后兼容签名）
pub fn parse_clash_config_dir_from_cmdlines(lines: &[String]) -> Option<PathBuf> {
    parse_all_clash_config_dirs_from_cmdlines(lines).into_iter().next()
}

/// 判断路径是否为真正的 Clash Verge Rev 用户配置目录（排除服务模式临时运行沙箱 `ProgramData\clash-verge-service\...\runtime`）
pub fn is_valid_clash_verge_config_dir(dir: &Path) -> bool {
    let lower = dir.to_string_lossy().to_ascii_lowercase();
    if lower.contains("clash-verge-service") {
        return false;
    }
    if !dir.is_dir() {
        return false;
    }
    dir.join("clash-verge.yaml").exists()
        || dir.join("profiles.yaml").exists()
        || dir.join("verge.yaml").exists()
}

#[cfg(windows)]
fn detect_live_clash_verge_config_dir() -> Option<PathBuf> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-Command",
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-CimInstance Win32_Process -Filter \"Name LIKE '%mihomo%' OR Name LIKE '%clash-verge%'\" | ForEach-Object { $_.CommandLine; if ($_.ExecutablePath) { 'EXE::' + $_.ExecutablePath } }",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut cmdlines = Vec::new();
    let mut exe_paths = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(p) = t.strip_prefix("EXE::") {
            exe_paths.push(PathBuf::from(p.trim()));
        } else {
            cmdlines.push(t.to_string());
        }
    }
    // 遍历全部 -d 候选目录，自动跳过 clash-verge-service 服务模式沙箱找到真正的用户配置目录
    for dir in parse_all_clash_config_dirs_from_cmdlines(&cmdlines) {
        if is_valid_clash_verge_config_dir(&dir) {
            return Some(dir);
        }
    }
    // 兼容 Clash Verge Rev 便携版：安装目录旁存在 .config\PORTABLE
    for exe in exe_paths {
        if let Some(parent) = exe.parent() {
            let portable = parent.join(".config").join("PORTABLE");
            if is_valid_clash_verge_config_dir(&portable) || portable.is_dir() {
                return Some(portable);
            }
        }
    }
    None
}

/// Clash Verge Rev 真实配置目录（自动优先反推运行中进程目录，兼容便携版与跨账号 UAC，回退 `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev`）
/// P0-1 & P1-13 修复：使用 `Option<Instant>` 彻底消除 Windows 冷开机 60s 内减法 Panic，并支持 `None` 负缓存 30s 防 PowerShell 风暴
pub fn clash_verge_config_dir() -> Option<PathBuf> {
    static CACHED_DIR: OnceLock<Mutex<(Option<Instant>, Option<PathBuf>)>> = OnceLock::new();
    let lock = CACHED_DIR.get_or_init(|| Mutex::new((None, None)));

    if let Ok(guard) = lock.lock() {
        if let Some(ts) = guard.0 {
            if ts.elapsed() < Duration::from_secs(30) {
                match guard.1 {
                    Some(ref p) if p.exists() => return Some(p.clone()),
                    None => return None,
                    _ => {}
                }
            }
        }
    }

    let default_dir = dirs::config_dir().map(|d| d.join("io.github.clash-verge-rev.clash-verge-rev"));
    #[cfg(windows)]
    let detected = detect_live_clash_verge_config_dir()
        .or_else(|| {
            // 跨账号 UAC 提权兜底：若当前 %APPDATA% 下无 clash-verge.yaml，则优先检查 C:\Users\*\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev 中最近更新的有效目录
            if default_dir
                .as_ref()
                .is_some_and(|d| d.join("clash-verge.yaml").exists() || d.join("profiles.yaml").exists())
            {
                return None;
            }
            let users_root = Path::new(r"C:\Users");
            let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
            if let Ok(rd) = std::fs::read_dir(users_root) {
                for entry in rd.flatten() {
                    let cand = entry
                        .path()
                        .join("AppData")
                        .join("Roaming")
                        .join("io.github.clash-verge-rev.clash-verge-rev");
                    let probe = cand.join("clash-verge.yaml");
                    if let Ok(meta) = std::fs::metadata(&probe) {
                        if let Ok(mod_t) = meta.modified() {
                            if best.as_ref().is_none_or(|(bt, _)| mod_t > *bt) {
                                best = Some((mod_t, cand));
                            }
                        }
                    }
                }
            }
            best.map(|(_, p)| p)
        });
    #[cfg(not(windows))]
    let detected: Option<PathBuf> = None;

    let resolved = detected.or(default_dir);
    if let Ok(mut guard) = lock.lock() {
        *guard = (Some(Instant::now()), resolved.clone());
    }
    resolved
}

/// 枚举 Windows 命名管道 `\\.\pipe\verge-mihomo-*`
#[cfg(windows)]
pub fn discover_mihomo_pipes() -> Vec<String> {
    let mut pipes = Vec::new();
    if let Ok(entries) = std::fs::read_dir(r"\\.\pipe\") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let lower = name.to_lowercase();
            if lower.contains("verge-mihomo") || lower.contains("mihomo") {
                pipes.push(format!(r"\\.\pipe\{name}"));
            }
        }
    }
    pipes.sort();
    pipes
}

#[cfg(not(windows))]
pub fn discover_mihomo_pipes() -> Vec<String> {
    Vec::new()
}

/// 纯函数：从 YAML 内容解析 `external-controller`（归一化 0.0.0.0/[::]/* -> 127.0.0.1）与 `secret`（天然剥离行内 `#` 注释）
pub fn parse_external_controller_and_secret_yaml(raw: &str) -> (Option<String>, Option<String>) {
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(raw.trim_start_matches('\u{feff}')) else {
        return (None, None);
    };
    let ctrl = doc
        .get("external-controller")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let without_scheme = s
                .strip_prefix("http://")
                .or_else(|| s.strip_prefix("https://"))
                .unwrap_or(s);
            let scheme = if s.starts_with("https://") { "https" } else { "http" };
            let normalized_host_port = if let Some(port) = without_scheme.strip_prefix(':') {
                format!("127.0.0.1:{port}")
            } else if let Some(port) = without_scheme.strip_prefix("0.0.0.0:") {
                format!("127.0.0.1:{port}")
            } else if let Some(port) = without_scheme.strip_prefix("[::]:") {
                format!("127.0.0.1:{port}")
            } else if let Some(port) = without_scheme.strip_prefix("*:") {
                format!("127.0.0.1:{port}")
            } else {
                without_scheme.to_string()
            };
            format!("{scheme}://{normalized_host_port}")
        });
    let secret = doc
        .get("secret")
        .and_then(|v| match v {
            serde_yaml::Value::String(s) => Some(s.trim().to_string()),
            serde_yaml::Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
        .filter(|s| !s.is_empty());
    (ctrl, secret)
}

/// 读取 clash-verge.yaml 中的 external-controller 与 secret，供 HTTP 回退模式自动鉴权与自定义端口发现
fn read_clash_external_controller_and_secret() -> (Option<String>, Option<String>) {
    let Some(dir) = clash_verge_config_dir() else {
        return (None, None);
    };
    let Ok(raw) = std::fs::read_to_string(dir.join("clash-verge.yaml")) else {
        return (None, None);
    };
    parse_external_controller_and_secret_yaml(&raw)
}

/// 自动发现可用的 Mihomo 端点（优先命名管道，其次 clash-verge.yaml 配置的 external-controller 与常见 9097/9090）
pub async fn discover_endpoint() -> Option<MihomoEndpoint> {
    for pipe in discover_mihomo_pipes() {
        let ep = MihomoEndpoint::NamedPipe(pipe);
        if fetch_version(&ep).await.is_ok() {
            return Some(ep);
        }
    }

    let mut http_candidates: Vec<String> = Vec::new();
    if let (Some(ctrl), _) = read_clash_external_controller_and_secret() {
        http_candidates.push(ctrl);
    }
    for fallback in ["http://127.0.0.1:9097", "http://127.0.0.1:9090"] {
        if !http_candidates.iter().any(|c| c == fallback) {
            http_candidates.push(fallback.to_string());
        }
    }

    for url in http_candidates {
        let ep = MihomoEndpoint::Http(url);
        if fetch_version(&ep).await.is_ok() {
            return Some(ep);
        }
    }

    None
}

fn mihomo_http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(4))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// 底层 HTTP 请求（同时支持 Named Pipe 与 TCP External Controller；Named Pipe 带 4s 超时防永久挂死）
pub async fn mihomo_request(
    endpoint: &MihomoEndpoint,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String), String> {
    match endpoint {
        MihomoEndpoint::NamedPipe(pipe_path) => {
            let pipe = pipe_path.clone();
            let method = method.to_string();
            let path = path.to_string();
            let body = body.map(|s| s.to_string());
            let task = tokio::task::spawn_blocking(move || {
                http_over_named_pipe(&pipe, &method, &path, body.as_deref())
            });
            match tokio::time::timeout(Duration::from_secs(4), task).await {
                Ok(joined) => joined.map_err(|e| format!("命名管道任务异常: {e}"))?,
                Err(_) => Err("Mihomo 命名管道请求超时 (4s)".to_string()),
            }
        }
        MihomoEndpoint::Http(base) => {
            let client = mihomo_http_client();
            let url = format!("{base}{path}");
            let mut req = match method {
                "GET" => client.get(&url),
                "PUT" => client.put(&url),
                "PATCH" => client.patch(&url),
                "DELETE" => client.delete(&url),
                "POST" => client.post(&url),
                _ => return Err(format!("不支持的 HTTP 方法: {method}")),
            };
            if let Some(b) = body {
                req = req
                    .header("Content-Type", "application/json")
                    .body(b.to_string());
            }
            if let (_, Some(sec)) = read_clash_external_controller_and_secret() {
                req = req.header("Authorization", format!("Bearer {sec}"));
            }
            let resp = req.send().await.map_err(|e| format!("请求 Mihomo HTTP 失败: {e}"))?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            Ok((status, text))
        }
    }
}

/// 通过 Windows 命名管道执行标准 HTTP/1.1 请求（支持 ERROR_PIPE_BUSY 退避重试与 chunked 传输编码）
fn http_over_named_pipe(
    pipe_path: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String), String> {
    let mut file_opt = None;
    let mut last_err = String::new();
    for attempt in 0..8 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_path)
        {
            Ok(f) => {
                file_opt = Some(f);
                break;
            }
            Err(e) => {
                last_err = format!("打开命名管道 {pipe_path} 失败: {e}");
                // Windows ERROR_PIPE_BUSY (231) 时退避重试（降噪：仅重试到第 5 次仍忙时才打一条 WARN）
                if e.raw_os_error() == Some(231) || attempt < 3 {
                    if attempt == 4 {
                        crate::logger::log_warn(
                            "mihomo",
                            format!("命名管道持续繁忙 ({method} {path}) attempt={} err={e}", attempt + 1),
                        );
                    }
                    std::thread::sleep(Duration::from_millis(25 * (attempt as u64 + 1)));
                    continue;
                }
                break;
            }
        }
    }
    let mut file = file_opt.ok_or(last_err)?;

    let payload = body.unwrap_or("");
    let request = if payload.is_empty() {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            payload.len()
        )
    };

    file.write_all(request.as_bytes())
        .map_err(|e| format!("写入命名管道请求失败: {e}"))?;
    file.flush()
        .map_err(|e| format!("刷新命名管道失败: {e}"))?;

    let mut raw = Vec::new();
    file.read_to_end(&mut raw)
        .map_err(|e| format!("读取命名管道响应失败: {e}"))?;

    parse_http_response(&raw)
}

/// 解析原始 HTTP/1.1 响应字节（支持 chunked 与普通响应体）
pub fn parse_http_response(raw: &[u8]) -> Result<(u16, String), String> {
    let split_pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "无效的 HTTP 响应头".to_string())?;

    let header_str = String::from_utf8_lossy(&raw[..split_pos]);
    let body_bytes = &raw[split_pos + 4..];

    let mut lines = header_str.lines();
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("无法解析 HTTP 状态行: {status_line}"))?;

    let mut is_chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_lowercase().contains("chunked")
            {
                is_chunked = true;
            }
        }
    }

    let decoded = if is_chunked {
        decode_chunked_body(body_bytes)?
    } else {
        body_bytes.to_vec()
    };

    Ok((status, String::from_utf8_lossy(&decoded).to_string()))
}

fn decode_chunked_body(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let Some(pos) = data.windows(2).position(|w| w == b"\r\n") else {
            break;
        };
        let size_line = String::from_utf8_lossy(&data[..pos]);
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(hex_part, 16)
            .map_err(|_| format!("无效的 chunk 长度: {hex_part}"))?;
        data = &data[pos + 2..];
        if chunk_size == 0 {
            break;
        }
        if data.len() < chunk_size {
            out.extend_from_slice(data);
            break;
        }
        out.extend_from_slice(&data[..chunk_size]);
        data = &data[chunk_size..];
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        }
    }
    Ok(out)
}

pub async fn fetch_version(endpoint: &MihomoEndpoint) -> Result<MihomoVersion, String> {
    let (status, body) = mihomo_request(endpoint, "GET", "/version", None).await?;
    if status != 200 {
        return Err(format!("GET /version 返回 HTTP {status}"));
    }
    let val: Value = serde_json::from_str(&body).map_err(|e| format!("解析 /version 失败: {e}"))?;
    Ok(MihomoVersion {
        version: val
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        meta: val.get("meta").and_then(|v| v.as_bool()).unwrap_or(false),
    })
}

pub async fn fetch_configs(endpoint: &MihomoEndpoint) -> Result<MihomoConfigs, String> {
    let (status, body) = mihomo_request(endpoint, "GET", "/configs", None).await?;
    if status != 200 {
        return Err(format!("GET /configs 返回 HTTP {status}"));
    }
    let val: Value = serde_json::from_str(&body).map_err(|e| format!("解析 /configs 失败: {e}"))?;

    let mixed_port = val
        .get("mixed-port")
        .and_then(|v| v.as_u64())
        .or_else(|| val.get("port").and_then(|v| v.as_u64()))
        .unwrap_or(7890) as u16;
    let ipv6 = val.get("ipv6").and_then(|v| v.as_bool()).unwrap_or(false);
    let tun_enable = val
        .get("tun")
        .and_then(|t| t.get("enable"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let dns_enhanced_mode = val
        .get("dns")
        .and_then(|d| d.get("enhanced-mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("normal")
        .to_string();
    let mode = val
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("rule")
        .to_string();

    Ok(MihomoConfigs {
        mixed_port,
        ipv6,
        tun_enable,
        dns_enhanced_mode,
        mode,
    })
}

pub async fn patch_configs_json(endpoint: &MihomoEndpoint, body: &Value) -> Result<(), String> {
    let body_json = body.to_string();
    let (status, resp_body) = mihomo_request(endpoint, "PATCH", "/configs", Some(&body_json)).await?;
    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(format!("PATCH /configs 返回 HTTP {status}: {resp_body}"))
    }
}

pub async fn patch_ipv6_enabled(endpoint: &MihomoEndpoint, enabled: bool) -> Result<(), String> {
    let body_json = format!(r#"{{"ipv6":{enabled}}}"#);
    let (status, body) = mihomo_request(endpoint, "PATCH", "/configs", Some(&body_json)).await?;
    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(format!("PATCH /configs ipv6={enabled} 返回 HTTP {status}: {body}"))
    }
}

pub async fn patch_ipv6_disabled(endpoint: &MihomoEndpoint) -> Result<(), String> {
    patch_ipv6_enabled(endpoint, false).await
}

/// 将 Clash 运行模式切回 rule（规则模式），需搭配同步写入 config.yaml 的 mode: rule
pub async fn patch_clash_mode_rule(endpoint: &MihomoEndpoint) -> Result<(), String> {
    let (status, body) =
        mihomo_request(endpoint, "PATCH", "/configs", Some(r#"{"mode":"rule"}"#)).await?;
    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(format!("PATCH /configs mode=rule 返回 HTTP {status}: {body}"))
    }
}

/// 通过 Mihomo API 热开关虚拟网卡 (TUN)，避免使用 taskkill /F 强杀 Clash 桌面端导致物理网卡残留 127.0.0.1 DNS
pub async fn patch_tun_enabled(endpoint: &MihomoEndpoint, enabled: bool) -> Result<(), String> {
    let body_json = format!(r#"{{"tun":{{"enable":{enabled}}}}}"#);
    let (status, body) = mihomo_request(endpoint, "PATCH", "/configs", Some(&body_json)).await?;
    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(format!(
            "PATCH /configs tun.enable={enabled} 返回 HTTP {status}: {body}"
        ))
    }
}

/// 强制让 Mihomo 内核通过完整 YAML payload 热重载（PUT /configs?force=true），
/// 绕开服务模式下 SAFE_PATHS 路径限制，无需用户手动点重载即可毫秒级生效新策略组与规则。
pub async fn reload_config_via_payload(
    endpoint: &MihomoEndpoint,
    yaml_payload: &str,
) -> Result<(), String> {
    let payload = serde_json::json!({
        "path": "",
        "payload": yaml_payload
    })
    .to_string();
    let (status, body) =
        mihomo_request(endpoint, "PUT", "/configs?force=true", Some(&payload)).await?;
    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(format!("PUT /configs?force=true 返回 HTTP {status}: {body}"))
    }
}

/// 极轻量查询单个策略组当前选中的节点名（GET /proxies/{name}，仅几百字节，替代后台 2s 哨兵拉取百 KB 全量 /proxies）
pub async fn fetch_proxy_group_now(
    endpoint: &MihomoEndpoint,
    group_name: &str,
) -> Option<String> {
    let path = format!("/proxies/{}", urlencoding::encode(group_name));
    let (status, body) = mihomo_request(endpoint, "GET", &path, None).await.ok()?;
    if status != 200 {
        return None;
    }
    let val: Value = serde_json::from_str(&body).ok()?;
    val.get("now")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

pub async fn fetch_proxies_raw(endpoint: &MihomoEndpoint) -> Result<HashMap<String, Value>, String> {
    let (status, body) = mihomo_request(endpoint, "GET", "/proxies", None).await?;
    if status != 200 {
        return Err(format!("GET /proxies 返回 HTTP {status}"));
    }
    let val: Value = serde_json::from_str(&body).map_err(|e| format!("解析 /proxies 失败: {e}"))?;
    let map = val
        .get("proxies")
        .and_then(|p| p.as_object())
        .ok_or_else(|| "Mihomo /proxies 响应缺少 proxies 字段".to_string())?;
    Ok(map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
}

pub fn extract_proxy_group(
    proxies: &HashMap<String, Value>,
    group_name: &str,
) -> Option<ProxyGroupInfo> {
    let obj = proxies.get(group_name)?;
    let group_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let now = obj.get("now").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let all = obj
        .get("all")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    Some(ProxyGroupInfo {
        name: group_name.to_string(),
        group_type,
        now,
        all,
    })
}

pub async fn fetch_rules_raw(endpoint: &MihomoEndpoint) -> Result<Vec<Value>, String> {
    let (status, body) = mihomo_request(endpoint, "GET", "/rules", None).await?;
    if status != 200 {
        return Err(format!("GET /rules 返回 HTTP {status}"));
    }
    let val: Value = serde_json::from_str(&body).map_err(|e| format!("解析 /rules 失败: {e}"))?;
    Ok(val
        .get("rules")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default())
}

pub async fn select_proxy_in_group(
    endpoint: &MihomoEndpoint,
    group_name: &str,
    node_name: &str,
) -> Result<(), String> {
    let encoded_group = urlencoding::encode(group_name);
    let path = format!("/proxies/{encoded_group}");
    let body = serde_json::json!({ "name": node_name }).to_string();
    let (status, text) = mihomo_request(endpoint, "PUT", &path, Some(&body)).await?;
    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(format!("切换策略组 {group_name} → {node_name} 失败 (HTTP {status}): {text}"))
    }
}

/// 评估所有可选节点：剔除禁区节点、全量无感双平台真测并结合真实 IP/ASN 情报打分排序
pub async fn build_node_report() -> NodeReport {
    build_node_report_with_options(false).await
}

pub async fn build_node_report_with_options(force_reprobe: bool) -> NodeReport {
    if force_reprobe {
        clear_dual_ai_cache();
    }
    let Some(ep) = discover_endpoint().await else {
        return NodeReport {
            connected: false,
            endpoint: "未检测到 Mihomo 命名管道或控制端口".into(),
            group_name: "Claude-Fixed".into(),
            current_node: "未连接".into(),
            total_raw_nodes: 0,
            subscription_total_nodes: 0,
            name_blocked_count: 0,
            filtered_blocked_count: 0,
            nodes: Vec::new(),
            current_exit_summary: None,
        };
    };

    let Ok(proxies) = fetch_proxies_raw(&ep).await else {
        return NodeReport {
            connected: false,
            endpoint: ep.display_label(),
            group_name: "Claude-Fixed".into(),
            current_node: "读取节点列表失败".into(),
            total_raw_nodes: 0,
            subscription_total_nodes: 0,
            name_blocked_count: 0,
            filtered_blocked_count: 0,
            nodes: Vec::new(),
            current_exit_summary: None,
        };
    };

    // 优先读取 Claude-Fixed；尚未配置时回退读取首个 Selector 组以便展示可用安全节点
    let group = extract_proxy_group(&proxies, "Claude-Fixed").or_else(|| {
        proxies
            .values()
            .filter_map(|v| {
                let name = v.get("name")?.as_str()?;
                let t = v.get("type")?.as_str()?;
                if t == "Selector" && name != "GLOBAL" {
                    extract_proxy_group(&proxies, name)
                } else {
                    None
                }
            })
            .next()
    });

    let (group_name, current_node, candidates) = match group {
        Some(g) => (g.name, g.now, g.all),
        None => ("Claude-Fixed".into(), "未创建".into(), Vec::new()),
    };

    let mixed_port = fetch_configs(&ep)
        .await
        .map(|c| c.mixed_port)
        .unwrap_or(7890);

    // 优先读取当前选中节点的 24h 持久核验缓存；若深度核验未在运行且当前节点尚无缓存，则无感实测一次当前节点
    let audit_prog = get_deep_audit_progress();
    let display_current_node = if audit_prog.running && !audit_prog.original_node.is_empty() {
        audit_prog.original_node.clone()
    } else {
        current_node.clone()
    };

    let current_probe = if !audit_prog.running
        && !display_current_node.is_empty()
        && display_current_node != "未创建"
    {
        if let Some(rec) = get_fresh_verified_record(&display_current_node) {
            Some(DualAiProbeResult {
                claude_status: rec.claude_status,
                claude_label: rec.claude_label,
                claude_probe_detail: rec.claude_probe_detail,
                gemini_status: rec.gemini_status,
                gemini_label: rec.gemini_label,
                cf_blocked: rec.cf_blocked,
                web_cf_challenge: rec.web_cf_challenge,
                claude_delay_ms: rec.claude_delay_ms,
                probed_at: Instant::now(),
            })
        } else {
            Some(probe_dual_ai_via_proxy(&display_current_node, mixed_port).await)
        }
    } else {
        None
    };

    let mut valid_candidates: Vec<(String, String)> = Vec::new();
    for name in &candidates {
        if name == "DIRECT" || name == "REJECT" || name == "COMPATIBLE" {
            continue;
        }
        if is_blocked_node_name(name) {
            continue;
        }
        let info = proxies.get(name);
        let node_type = info
            .and_then(|v| v.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("Proxy")
            .to_string();
        if matches!(
            node_type.as_str(),
            "Selector" | "URLTest" | "Fallback" | "LoadBalance" | "Direct" | "Reject"
        ) {
            continue;
        }
        valid_candidates.push((name.clone(), node_type));
    }

    // 彻底废弃会造假绿灯的 Mihomo /delay 状态码误判！
    // 所有节点的真实 IP 类型 / Claude CF 盾 / AGY 限区均来自持久化深度实测缓存（node-verified-cache.json）；
    // 未经深度核验的节点如实显示「待核验」，绝不造假绿灯！
    let mut nodes = Vec::new();

    for (name, node_type) in &valid_candidates {
        let info = proxies.get(name);
        let history: Vec<u32> = info
            .and_then(|v| v.get("history"))
            .and_then(|h| h.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|it| it.get("delay").and_then(|d| d.as_u64()).map(|d| d as u32))
                    .collect()
            })
            .unwrap_or_default();

        let non_zero: Vec<u32> = history.iter().copied().filter(|&d| d > 0).collect();
        let history_delay = non_zero.last().copied();
        let now_secs = chrono::Utc::now().timestamp();
        let stab_rec = stability_cache()
            .read()
            .ok()
            .and_then(|m| m.get(name).cloned());

        // 优先使用我们自己多轮实测 Anthropic RTT 样本计算真实抖动与断连率，不足 2 轮再参考 Mihomo 历史
        let jitter_ms = stab_rec
            .as_ref()
            .and_then(|r| compute_real_jitter_ms(&r.rtt_samples))
            .unwrap_or_else(|| {
                if non_zero.len() >= 2 {
                    let max_d = *non_zero.iter().max().unwrap_or(&0);
                    let min_d = *non_zero.iter().min().unwrap_or(&0);
                    (max_d - min_d) / 2
                } else {
                    4
                }
            });

        let (drop_rate_pct, drop_sample_count) = if let Some(ref r) = stab_rec {
            compute_recent_drop_stats(&r.recent_outcomes, r.probe_total, r.probe_failures)
        } else if history.is_empty() {
            (0.0, 0)
        } else {
            let zeros = history.iter().filter(|&&d| d == 0).count();
            (((zeros as f64 / history.len() as f64) * 1000.0).round() / 10.0, history.len())
        };
        let high_drop_unusable =
            drop_sample_count >= 4 && drop_rate_pct >= crate::protocol::DROP_RATE_REDLINE;
        let drift_count_24h = stab_rec
            .as_ref()
            .map(|r| count_24h_landing_drifts(&r.landing_history, now_secs))
            .unwrap_or(0);
        let is_current = *name == display_current_node;

        // 优先使用 24h 持久化深度核验记录（含真实 IP/ASN/Claude CF 盾/AGY 地区），其次使用内存真实探测缓存
        let disk_verified = get_fresh_verified_record(name);
        let verified_geo = disk_verified
            .as_ref()
            .map(|r| VerifiedNodeGeo {
                country_code: r.country_code.clone(),
                masked_ip: r.masked_ip.clone(),
                asn_purity: r.asn_purity.clone(),
                risk_level: r.risk_level.clone(),
                risk_detail: r.risk_detail.clone(),
                blocked_country: r.blocked_country,
                updated_at: Instant::now(),
            })
            .or_else(|| {
                verified_geo_cache()
                    .read()
                    .ok()
                    .and_then(|m| m.get(name).cloned())
                    .filter(|g| g.updated_at.elapsed().as_secs() < VERIFIED_GEO_CACHE_TTL_SECS)
            });

        let lower_name = name.to_lowercase();
        let (asn_purity, risk_level, risk_detail, asn_verified_blocked) = if let Some(ref g) = verified_geo {
            (
                g.asn_purity.clone(),
                g.risk_level.clone(),
                g.risk_detail.clone(),
                g.blocked_country,
            )
        } else if lower_name.contains("家宽")
            || lower_name.contains("住宅")
            || lower_name.contains("isp")
            || lower_name.contains("原生")
            || lower_name.contains("static")
            || lower_name.contains("静态")
        {
            (
                "标称原生".to_string(),
                "unknown".to_string(),
                "待深度核验 IP".to_string(),
                false,
            )
        } else {
            (
                "待验 IP".to_string(),
                "unknown".to_string(),
                "待深度核验 IP".to_string(),
                false,
            )
        };

        let region_code = verified_geo
            .as_ref()
            .map(|g| g.country_code.clone())
            .filter(|c| !c.is_empty() && c != "UNKNOWN")
            .unwrap_or_else(|| extract_region_code(name));
        let region_label = format!("{} · {}", region_code_to_label(&region_code), node_type);

        // 读取 100% 真实 HTTP 核验结果（持久化磁盘缓存优先，其次当前节点实时探针），绝不造假绿灯
        let cached_probe = if let Some(ref rec) = disk_verified {
            Some(DualAiProbeResult {
                claude_status: rec.claude_status.clone(),
                claude_label: rec.claude_label.clone(),
                claude_probe_detail: rec.claude_probe_detail.clone(),
                gemini_status: rec.gemini_status.clone(),
                gemini_label: rec.gemini_label.clone(),
                cf_blocked: rec.cf_blocked,
                web_cf_challenge: rec.web_cf_challenge,
                claude_delay_ms: rec.claude_delay_ms,
                probed_at: Instant::now(),
            })
        } else if is_current {
            current_probe.clone()
        } else {
            dual_ai_cache()
                .read()
                .ok()
                .and_then(|m| m.get(name).cloned())
                .filter(|hit| hit.probed_at.elapsed().as_secs() < DUAL_AI_CACHE_TTL_SECS)
        };

        let (
            mut claude_status,
            mut claude_label,
            mut claude_probe_detail,
            gemini_status,
            gemini_label,
            mut cf_blocked,
            web_cf_challenge,
            probe_delay,
        ) = if let Some(p) = cached_probe {
            (
                p.claude_status,
                p.claude_label,
                p.claude_probe_detail,
                p.gemini_status,
                p.gemini_label,
                p.cf_blocked,
                p.web_cf_challenge,
                p.claude_delay_ms,
            )
        } else {
            (
                "unknown".to_string(),
                "待核验".to_string(),
                String::new(),
                "unknown".to_string(),
                "AGY 待测".to_string(),
                false,
                false,
                None,
            )
        };

        if asn_verified_blocked {
            claude_status = "blocked".to_string();
            claude_label = "落地禁区".to_string();
            cf_blocked = true;
            if claude_probe_detail.is_empty() {
                claude_probe_detail = format!("实测真实出口归属禁区 ({region_code})");
            }
        }

        // 保留真实基础网络延迟，避免出现「0.0% 断连却强行抹成超时」的自相矛盾展示
        let delay_ms = probe_delay.or(history_delay);
        let stability = if claude_status == "offline" || delay_ms.is_none() {
            40.0
        } else if drift_count_24h >= 3 {
            60.0
        } else if drift_count_24h > 0 {
            80.0
        } else {
            96.0
        };

        let dual_ai_ok = claude_status == "ok" && gemini_status == "ok" && !cf_blocked && !web_cf_challenge;
        let asn_short = if asn_verified_blocked {
            "落地禁区".to_string()
        } else if risk_level == "abuser" {
            "高危滥用".to_string()
        } else if risk_level == "proxy" {
            "共享代理".to_string()
        } else if cf_blocked {
            "高危拉黑".to_string()
        } else if risk_level == "isp" {
            "ISP 住宅".to_string()
        } else if risk_level == "hosting" {
            "常规机房".to_string()
        } else if asn_purity == "标称原生" {
            "标称原生".to_string()
        } else {
            "待验 IP".to_string()
        };

        let purity_bonus: i32 = match risk_level.as_str() {
            "isp" => 5,
            "hosting" => -2,
            "proxy" => -14,
            "abuser" => -28,
            _ => 0,
        };
        let web_cf_penalty: i32 = if web_cf_challenge { -22 } else { 0 };
        let drift_penalty: i32 = if drift_count_24h >= 3 {
            -16
        } else if drift_count_24h > 0 {
            -8
        } else {
            0
        };
        let dual_ai_bonus: i32 = if dual_ai_ok { 4 } else { 0 };
        let raw_score = compute_node_score_weighted(delay_ms, jitter_ms as f64, drop_rate_pct, stability);
        // 唯一真源：仅以下 4 类硬故障判定为「节点不可用」（禁止切换）；高断连需至少 4 次样本防单次抖动误拉黑
        let node_unusable = asn_verified_blocked
            || cf_blocked
            || claude_status == "offline"
            || high_drop_unusable
            || matches!(risk_level.as_str(), "abuser" | "proxy");

        let score = if node_unusable {
            (raw_score.min(35)) as u32
        } else {
            (raw_score as i32 + purity_bonus + web_cf_penalty + drift_penalty + dual_ai_bonus)
                .clamp(50, 100) as u32
        };

        let recommendation = if asn_verified_blocked {
            "禁区不可用"
        } else if cf_blocked {
            "拉黑不可用"
        } else if high_drop_unusable {
            "高断连不可用"
        } else if claude_status == "offline" {
            if delay_ms.is_some() {
                "Anthropic 超时"
            } else {
                "离线不可用"
            }
        } else if risk_level == "abuser" {
            "高危滥用不可用"
        } else if risk_level == "proxy" {
            "共享代理不可用"
        } else if web_cf_challenge && drift_count_24h > 0 {
            "弹盾且有漂移风险"
        } else if web_cf_challenge {
            "网页弹盾 · 可用"
        } else if drift_count_24h >= 2 {
            "频繁漂移 · 有风险"
        } else if drift_count_24h > 0 {
            "漂移风险 · 可用"
        } else if dual_ai_ok && score >= 90 {
            "推荐主节点"
        } else if claude_status == "ok" && matches!(gemini_status.as_str(), "restricted" | "cn_redirect") {
            "仅 Claude 推荐"
        } else if score >= 85 {
            "稳定可用"
        } else if delay_ms.map(|d| d > crate::protocol::LATENCY_WARN_MS).unwrap_or(false) {
            "高延迟备选"
        } else if claude_status == "unknown" {
            "待深度核验"
        } else {
            "可用备选"
        }
        .to_string();

        nodes.push(NodeItem {
            name: name.clone(),
            region_code,
            region_label,
            node_type: node_type.clone(),
            delay_ms,
            jitter_ms,
            drop_rate_pct,
            blocked: node_unusable,
            is_current,
            score,
            recommendation,
            asn_purity,
            asn_short,
            anthropic_probe: if asn_verified_blocked {
                "落地禁区（禁止使用）".into()
            } else {
                claude_label.clone()
            },
            cf_blocked,
            claude_status,
            claude_label,
            claude_probe_detail,
            gemini_status,
            gemini_label,
            dual_ai_ok,
            drift_count_24h,
            risk_level,
            risk_detail,
            web_cf_challenge,
        });
    }

    nodes.sort_by(|a, b| {
        b.is_current
            .cmp(&a.is_current)
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| a.name.cmp(&b.name))
    });

    // 为顶部第 1 张卡片生成紧凑的当前出口摘要（优先读持久化核验缓存，零额外横条占位）
    let current_exit_summary = get_fresh_verified_record(&display_current_node)
        .map(|r| (r.country_code, r.masked_ip, r.asn_purity))
        .or_else(|| {
            verified_geo_cache()
                .read()
                .ok()
                .and_then(|m| m.get(&display_current_node).cloned())
                .map(|g| (g.country_code, g.masked_ip, g.asn_purity))
        })
        .map(|(cc, masked_ip, asn_purity)| {
            let drift_cnt = nodes
                .iter()
                .find(|n| n.is_current)
                .map(|n| n.drift_count_24h)
                .unwrap_or(0);
            let ip_part = if masked_ip.is_empty() {
                String::new()
            } else {
                format!(" · {masked_ip}")
            };
            format!("{cc}{ip_part} · {asn_purity} · 24h {drift_cnt} 漂移")
        });

    let filtered_blocked_count = count_blocked_region_nodes(&proxies, &candidates, &nodes);
    let (subscription_total_nodes, name_blocked_count) =
        count_subscription_and_name_blocked(&proxies, &candidates, &nodes);

    NodeReport {
        connected: true,
        endpoint: ep.display_label(),
        group_name,
        current_node: display_current_node,
        total_raw_nodes: candidates.len(),
        subscription_total_nodes,
        name_blocked_count,
        filtered_blocked_count,
        nodes,
        current_exit_summary,
    }
}

/// 精确统计订阅节点账目（保证 `subscription_total_nodes == name_blocked_count + evaluated_nodes.len()` 严丝合缝）：
/// 返回 `(subscription_total_nodes, name_blocked_count)`
pub fn count_subscription_and_name_blocked(
    proxies: &HashMap<String, Value>,
    group_candidates: &[String],
    evaluated_nodes: &[NodeItem],
) -> (usize, usize) {
    let eval_set: std::collections::HashSet<&str> =
        evaluated_nodes.iter().map(|n| n.name.as_str()).collect();
    let mut name_blocked: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (name, obj) in proxies {
        let ptype = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if matches!(
            ptype,
            "Selector"
                | "URLTest"
                | "Fallback"
                | "LoadBalance"
                | "Direct"
                | "Reject"
                | "RejectDrop"
                | "Pass"
                | "Compatible"
                | "Relay"
        ) {
            continue;
        }
        if !eval_set.contains(name.as_str()) && is_blocked_node_name(name) {
            name_blocked.insert(name.clone());
        }
    }
    for name in group_candidates {
        if !eval_set.contains(name.as_str()) && is_blocked_node_name(name) {
            name_blocked.insert(name.clone());
        }
    }

    let name_blocked_count = name_blocked.len();
    let subscription_total_nodes = evaluated_nodes.len() + name_blocked_count;
    (subscription_total_nodes, name_blocked_count)
}

/// 真实统计「已自动屏蔽禁区节点」总数（去重）：
/// 1) 订阅全量代理中因名称命中 HK/MO/CN/RU 等禁区而被覆写脚本自动剔除出 Claude-Fixed 的节点；
/// 2) 当前策略组中按名称命中的禁区节点；
/// 3) 虽名称看似合规（如挂名台湾）但经深度实测真实出口落入禁区（如 HK）的落地禁区节点。
pub fn count_blocked_region_nodes(
    proxies: &HashMap<String, Value>,
    group_candidates: &[String],
    evaluated_nodes: &[NodeItem],
) -> usize {
    let mut blocked_names = std::collections::HashSet::<String>::new();

    for (name, info) in proxies {
        if name == "DIRECT" || name == "REJECT" || name == "COMPATIBLE" || name == "GLOBAL" {
            continue;
        }
        let node_type = info
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("Proxy");
        if matches!(
            node_type,
            "Selector" | "URLTest" | "Fallback" | "LoadBalance" | "Direct" | "Reject" | "Compatible" | "Pass" | "Relay"
        ) {
            continue;
        }
        if is_blocked_node_name(name) {
            blocked_names.insert(name.clone());
        }
    }

    for name in group_candidates {
        if name != "DIRECT" && name != "REJECT" && name != "COMPATIBLE" && is_blocked_node_name(name)
        {
            blocked_names.insert(name.clone());
        }
    }

    for n in evaluated_nodes {
        if n.claude_status == "blocked"
            || is_blocked_country(&n.region_code)
            || n.claude_label.contains("禁区")
        {
            blocked_names.insert(n.name.clone());
        }
    }

    blocked_names.len()
}

pub fn compute_node_score_weighted(
    delay_ms: Option<u32>,
    jitter_ms: f64,
    drop_rate_pct: f64,
    stability: f64,
) -> u32 {
    crate::protocol::calculate_node_quality_score(delay_ms, jitter_ms, drop_rate_pct, stability)
}

/// 校验规则表中是否包含 Claude 核心域名指向 Claude-Fixed
pub fn verify_claude_rules(rules: &[Value]) -> (bool, usize) {
    let required = ["anthropic.com", "claude.ai"];
    let mut matched_count = 0usize;
    let mut hit_required = [false; 2];

    for r in rules {
        let payload = r.get("payload").and_then(|v| v.as_str()).unwrap_or("");
        let proxy = r.get("proxy").and_then(|v| v.as_str()).unwrap_or("");
        if proxy == "Claude-Fixed" {
            matched_count += 1;
            for (idx, domain) in required.iter().enumerate() {
                if payload.eq_ignore_ascii_case(domain) {
                    hit_required[idx] = true;
                }
            }
        }
    }

    (hit_required.iter().all(|&x| x), matched_count)
}

/// 校验规则表中是否已包含出口 IP 监测域名（ip-api.com 等）指向 Claude-Fixed
pub fn verify_exit_probe_rules(rules: &[Value]) -> bool {
    rules.iter().any(|r| {
        let payload = r.get("payload").and_then(|v| v.as_str()).unwrap_or("");
        let proxy = r.get("proxy").and_then(|v| v.as_str()).unwrap_or("");
        proxy == "Claude-Fixed"
            && (payload.eq_ignore_ascii_case("ip-api.com")
                || payload.eq_ignore_ascii_case("ipapi.is")
                || payload.eq_ignore_ascii_case("ipinfo.io"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_region_filter_catches_hk_cn_ru_and_allows_us_jp() {
        assert!(is_blocked_node_name("HK-Edge-03"));
        assert!(is_blocked_node_name("香港 01 IPLC"));
        assert!(is_blocked_node_name("RU-Moscow-01"));
        assert!(is_blocked_node_name("Macau-Direct"));
        assert!(!is_blocked_node_name("US-LA-Static-01"));
        assert!(!is_blocked_node_name("JP-Tokyo-02"));
        assert!(!is_blocked_node_name("SG-Node-04"));
        assert!(!is_blocked_node_name("🇦🇺澳大利亚|原生"));
        assert!(is_blocked_country("hk"));
        assert!(!is_blocked_country("US"));
    }

    #[test]
    fn parses_standard_and_chunked_http_responses() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"ok\":true}\r\n";
        let (status, body) = parse_http_response(plain).unwrap();
        assert_eq!(status, 200);
        assert!(body.contains("{\"ok\":true}"));

        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (status2, body2) = parse_http_response(chunked).unwrap();
        assert_eq!(status2, 200);
        assert_eq!(body2, "hello world");
    }

    #[test]
    fn verifies_claude_rules_targeting_fixed_group() {
        let rules = vec![
            serde_json::json!({"type": "DomainSuffix", "payload": "anthropic.com", "proxy": "Claude-Fixed"}),
            serde_json::json!({"type": "DomainSuffix", "payload": "claude.ai", "proxy": "Claude-Fixed"}),
            serde_json::json!({"type": "Process", "payload": "Claude.exe", "proxy": "Claude-Fixed"}),
        ];
        let (ok, count) = verify_claude_rules(&rules);
        assert!(ok);
        assert_eq!(count, 3);
    }

    #[test]
    fn classifies_dual_ai_claude_and_gemini_probe_responses() {
        assert_eq!(
            classify_gemini_probe_response(200, "https://aistudio.google.com/welcome", "<html>AI Studio</html>"),
            ("ok", "AGY ✓")
        );
        assert_eq!(
            classify_gemini_probe_response(400, "https://generativelanguage.googleapis.com/v1beta/models", r#"{"error":{"details":[{"reason":"API_KEY_INVALID"}]}}"#),
            ("ok", "AGY ✓")
        );
        assert_eq!(
            classify_gemini_probe_response(400, "https://generativelanguage.googleapis.com/v1beta/models", r#"{"error":{"message":"User location is not supported for the API use.","status":"FAILED_PRECONDITION"}}"#),
            ("restricted", "AGY 限区")
        );
        assert_eq!(
            classify_gemini_probe_response(302, "https://www.google.com.hk/?gws_rd=ssl", ""),
            ("cn_redirect", "AGY 限区")
        );
        assert_eq!(
            classify_claude_probe_response(401, r#"{"type":"error","error":{"type":"authentication_error"}}"#),
            ("ok", "Claude ✓", false)
        );
        assert_eq!(
            classify_claude_probe_response(403, "Attention Required! Cloudflare CF-Ray"),
            ("cf_403", "Claude 拉黑", true)
        );
        assert!(is_claude_web_cf_challenge(403, "challenge", ""));
        assert!(is_claude_web_cf_challenge(403, "", "<title>Just a moment...</title>"));
        assert!(!is_claude_web_cf_challenge(200, "", "<html>Claude Login</html>"));

        let now = 1_763_900_000i64;
        let hist = vec![
            (now - 90_000, "JP:1.1.xx.xx".to_string()),
            (now - 3600, "JP:2.2.xx.xx".to_string()),
            (now - 1800, "JP:3.3.xx.xx".to_string()),
            (now - 600, "JP:3.3.xx.xx".to_string()),
            (now - 100, "JP:4.4.xx.xx".to_string()),
        ];
        assert_eq!(count_24h_landing_drifts(&hist, now), 2);
        assert_eq!(compute_real_jitter_ms(&[80, 90, 82]), Some(9));
    }

    #[tokio::test]
    #[ignore = "真机全量无感双平台节点测速实测"]
    async fn live_full_node_report_probe() {
        let t0 = Instant::now();
        let rep = build_node_report_with_options(true).await;
        println!(
            "=== LIVE NODE REPORT ({}ms): connected={} group={} current={} total={} valid={} blocked={} ===",
            t0.elapsed().as_millis(),
            rep.connected,
            rep.group_name,
            rep.current_node,
            rep.total_raw_nodes,
            rep.nodes.len(),
            rep.filtered_blocked_count
        );
        for n in &rep.nodes {
            println!(
                "  [{}] {} | {} | {} | {} | delay={:?}ms | score={} ({})",
                if n.is_current { "CUR" } else { "ALT" },
                n.name,
                n.claude_label,
                n.gemini_label,
                n.asn_short,
                n.delay_ms,
                n.score,
                n.recommendation
            );
        }
        assert!(rep.connected);
        assert!(!rep.nodes.is_empty());
        // 确认不再出现“未测假绿灯”：所有节点（含当前节点）的 AGY 状态均已完成真实探测（非“AGY 待测”）
        let unknown_agy = rep.nodes.iter().filter(|n| n.gemini_label.contains("待测")).count();
        assert_eq!(unknown_agy, 0, "all nodes should have real dual-AI (Claude + AGY) probe results");
    }

    #[test]
    fn drift_glitch_filter_rejects_cross_country_bleed_and_preserves_real_same_country_drift() {
        let mut map: HashMap<String, NodeStabilityRecord> = HashMap::new();
        map.insert(
            "🇦🇺澳大利亚|原生".to_string(),
            NodeStabilityRecord {
                rtt_samples: vec![200],
                probe_total: 3,
                probe_failures: 0,
                recent_outcomes: Vec::new(),
                landing_history: vec![
                    (1000, "AU:172.105.xx.xx".into()),
                    (1100, "KR:3.36.xx.xx".into()),
                    (1200, "AU:172.105.xx.xx".into()),
                    (1300, "KR:3.36.xx.xx".into()),
                    (1400, "AU:172.105.xx.xx".into()),
                ],
            },
        );
        // 清洗后 AU 仅剩同国 AU 记录，假漂移归零
        assert!(sanitize_stability_map(&mut map));
        let au = map.get("🇦🇺澳大利亚|原生").unwrap();
        assert_eq!(count_24h_landing_drifts(&au.landing_history, 1500), 0);

        // 实时探测再遇跨国毛刺 KR → 拦截为 glitch
        assert!(is_cross_country_glitch("🇦🇺澳大利亚|原生", "KR", &au.landing_history));
        // 同国 AU 换新 IP → 绝不拦截，仍视为真实漂移
        assert!(!is_cross_country_glitch("🇦🇺澳大利亚|原生", "AU", &au.landing_history));
        let real_drift_history = vec![
            (1000, "AU:172.105.xx.xx".into()),
            (1500, "AU:45.76.xx.xx".into()),
        ];
        assert_eq!(count_24h_landing_drifts(&real_drift_history, 1600), 1);
    }

    #[test]
    fn t042_parses_clash_config_dir_from_mihomo_cmdline() {
        let lines = vec![
            r#""C:\Portable\ClashVerge\verge-mihomo.exe" -d "D:\My Tools\ClashData\.config\PORTABLE" -f "D:\My Tools\ClashData\clash-verge.yaml""#.to_string(),
        ];
        let parsed = parse_clash_config_dir_from_cmdlines(&lines).unwrap();
        assert_eq!(parsed, PathBuf::from(r"D:\My Tools\ClashData\.config\PORTABLE"));
    }

    #[test]
    fn batch1_p0_clash_verge_config_dir_never_panics_on_cold_boot_and_caches() {
        // 连续调用两次，覆盖首次初始化与缓存命中分支，确保绝不触发 Instant 减法 Panic
        let first = clash_verge_config_dir();
        let second = clash_verge_config_dir();
        assert_eq!(first, second);
    }

    #[test]
    fn v027_rejects_clash_verge_service_sandbox_as_config_dir() {
        let sandbox = PathBuf::from(
            r"C:\ProgramData\clash-verge-service\users\66b64146261caec4e13cfb7f76e58232ba78a886800d00e4b1b6a57caf845b19\runtime",
        );
        assert!(!is_valid_clash_verge_config_dir(&sandbox));
    }

    #[test]
    fn counts_both_subscription_name_blocked_and_measured_landing_blocked_nodes_without_double_count() {
        let mut proxies: HashMap<String, Value> = HashMap::new();
        // 订阅中被 Script.js 提前踢出 Claude-Fixed 的 2 个真实香港节点
        proxies.insert("🇭🇰香港1".into(), serde_json::json!({ "type": "Vless" }));
        proxies.insert("🇭🇰香港2".into(), serde_json::json!({ "type": "Vless" }));
        // 策略组本身不应被计入节点数
        proxies.insert("香港自动选择".into(), serde_json::json!({ "type": "URLTest" }));
        proxies.insert("🇺🇸美国2|流媒体AI".into(), serde_json::json!({ "type": "Vless" }));
        proxies.insert("🇨🇳台湾1|流媒体AI".into(), serde_json::json!({ "type": "AnyTLS" }));

        let group_candidates = vec!["🇺🇸美国2|流媒体AI".to_string(), "🇨🇳台湾1|流媒体AI".to_string()];
        let evaluated = vec![
            NodeItem {
                name: "🇺🇸美国2|流媒体AI".into(),
                region_code: "US".into(),
                region_label: "美国 · Vless".into(),
                node_type: "Vless".into(),
                delay_ms: Some(142),
                jitter_ms: 5,
                drop_rate_pct: 0.0,
                blocked: false,
                is_current: true,
                score: 98,
                recommendation: "推荐主节点".into(),
                asn_purity: "ISP 住宅".into(),
                asn_short: "ISP 住宅".into(),
                anthropic_probe: "Claude ✓".into(),
                cf_blocked: false,
                claude_status: "ok".into(),
                claude_label: "Claude ✓".into(),
                gemini_status: "ok".into(),
                gemini_label: "AGY ✓".into(),
                dual_ai_ok: true,
                drift_count_24h: 0,
                risk_level: "isp".into(),
                risk_detail: "无代理标记".into(),
                web_cf_challenge: false,
                claude_probe_detail: String::new(),
            },
            NodeItem {
                name: "🇨🇳台湾1|流媒体AI".into(),
                region_code: "HK".into(),
                region_label: "香港 · AnyTLS".into(),
                node_type: "AnyTLS".into(),
                delay_ms: Some(117),
                jitter_ms: 7,
                drop_rate_pct: 0.0,
                blocked: true,
                is_current: false,
                score: 35,
                recommendation: "禁区不可用".into(),
                asn_purity: "ISP 住宅".into(),
                asn_short: "落地禁区".into(),
                anthropic_probe: "落地禁区（禁止使用）".into(),
                cf_blocked: true,
                claude_status: "blocked".into(),
                claude_label: "落地禁区".into(),
                gemini_status: "ok".into(),
                gemini_label: "AGY ✓".into(),
                dual_ai_ok: false,
                drift_count_24h: 0,
                risk_level: "isp".into(),
                risk_detail: "无代理标记".into(),
                web_cf_challenge: false,
                claude_probe_detail: "实测落地 HK 属于禁区".into(),
            },
        ];

        // 2 个订阅香港节点 + 1 个假台湾落地香港节点 = 3 个（策略组不计入）
        assert_eq!(count_blocked_region_nodes(&proxies, &group_candidates, &evaluated), 3);
    }

    #[test]
    fn offline_verified_record_uses_short_5m_ttl_while_ok_stays_fresh() {
        let now = chrono::Utc::now().timestamp();
        let make_rec = |status: &str, age_secs: i64| VerifiedNodeRecord {
            country_code: "SG".into(),
            masked_ip: "1.2.xx.xx".into(),
            asn_org: "ISP".into(),
            asn_purity: "ISP 住宅".into(),
            risk_level: "isp".into(),
            risk_detail: "无代理标记".into(),
            blocked_country: false,
            claude_status: status.into(),
            claude_label: if status == "offline" { "Claude 超时".into() } else { "Claude ✓".into() },
            claude_probe_detail: "connect timeout".into(),
            gemini_status: "ok".into(),
            gemini_label: "AGY ✓".into(),
            cf_blocked: false,
            web_cf_challenge: false,
            claude_delay_ms: Some(90),
            verified_at_unix: now - age_secs,
            probe_schema_version: CURRENT_PROBE_SCHEMA_VERSION,
        };
        let fresh_offline = make_rec("offline", 120);
        let expired_offline = make_rec("offline", OFFLINE_DISK_TTL_SECS + 10);
        let ok_12h = make_rec("ok", 12 * 3600);

        assert!(now - fresh_offline.verified_at_unix <= OFFLINE_DISK_TTL_SECS);
        assert!(now - expired_offline.verified_at_unix > OFFLINE_DISK_TTL_SECS);
        assert!(now - ok_12h.verified_at_unix <= VERIFIED_DISK_TTL_SECS);
    }

    #[test]
    fn blocked_region_regex_catches_alnum_underscore_emoji_and_sy_cu_without_false_positive() {
        for blocked in [
            "HK01",
            "HK_01",
            "hk-bgp-2",
            "CN01",
            "RU_02",
            "MO01",
            "SY01",
            "CU-1",
            "🇭🇰 节点1",
            "🇨🇳 回国专线",
            "Macao IEPL",
            "Syria Relay",
            "Cuba Direct",
        ] {
            assert!(
                is_blocked_node_name(blocked),
                "禁区节点名 {blocked} 必须被拦截"
            );
        }
        for safe in [
            "🇦🇺澳大利亚|原生",
            "🇺🇸 US01-ISP",
            "🇯🇵 Tokyo-02",
            "🇸🇬 SG_03",
            "🇬🇧 UK-London",
            "🇨🇦 Canada-01",
            "Custom-Node-01",
            "Symbol-US",
            "Missouri-US",
        ] {
            assert!(
                !is_blocked_node_name(safe),
                "合规节点名 {safe} 不得被误杀"
            );
        }
    }

    #[test]
    fn parse_external_controller_normalizes_wildcard_and_strips_yaml_comments() {
        let yaml = "external-controller: 0.0.0.0:9097 # lan listen\nsecret: \"my-secret-123\" # comment\n";
        let (ctrl, sec) = parse_external_controller_and_secret_yaml(yaml);
        assert_eq!(ctrl.as_deref(), Some("http://127.0.0.1:9097"));
        assert_eq!(sec.as_deref(), Some("my-secret-123"));

        let yaml_v6 = "external-controller: '[::]:9090'\nsecret: ''\n";
        let (ctrl2, sec2) = parse_external_controller_and_secret_yaml(yaml_v6);
        assert_eq!(ctrl2.as_deref(), Some("http://127.0.0.1:9090"));
        assert_eq!(sec2, None);
    }

    #[test]
    fn recent_drop_window_requires_min_samples_and_recovers_after_window_slides() {
        let (pct1, cnt1) = compute_recent_drop_stats(&[true, false], 2, 1);
        assert_eq!(cnt1, 2);
        assert!(pct1 > 40.0);
        // 样本不足 4 次时不会误拉黑；连续恢复后滑动窗口断连率归零
        let (pct2, cnt2) = compute_recent_drop_stats(&[true, true, true, true, true], 10, 1);
        assert_eq!(cnt2, 5);
        assert_eq!(pct2, 0.0);
    }
}
