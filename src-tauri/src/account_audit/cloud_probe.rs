//! 按需一次性 `sessionKey` 只读云端核验引擎（严格不耦合 Tauri `AppHandle`，供桌面端与外部 `POST /v1/audit/check-sk` 复用）。
//!
//! 核心安全与工程红线：
//! 1. 只发送 HTTP `GET` 只读请求，严禁调用任何写操作/吊销/刷新 KYC 接口；
//! 2. 支持直接粘贴 `sk-ant-sid...` 或整段 `Copy as cURL`，正则提取并立即丢弃其余内容；
//! 3. 通过 Windows 原生 `curl.exe` (Schannel) + 动态代理端口发起请求（绝不写死 7890）；
//! 4. `/api/organizations` 智能选主：优先选含 `capabilities: ["chat"]` 的主组织，绝不拿 Console API 组织查 `/usage`；
//! 5. 防串号保护：若本地已有主组织 `orgId` 且云端查回主组织不一致，拒绝覆盖并返回明确错误；
//! 6. 60 秒内存冷却锁（仅存短时 SHA-256 指纹，不落盘明文 `sk`）；
//! 7. `sessionKey` 与 `proxyUrl` 明文用完即焚，绝不打印进日志或报错信息。

use super::local_scan::{format_merchant_channel, normalize_plan_label};
use super::mask_email_readable;
use chrono::DateTime;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_BASE_URL: &str = "https://claude.ai";
const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";
const COOLDOWN_SECONDS: u64 = 60;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 外部 API 与桌面端统一错误码
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloudProbeErrorCode {
    InvalidSkOrProxy,
    CfChallengeOrAuthExpired,
    RateLimited,
    ProxyOrUpstreamFailed,
    OrgMismatch,
}

/// 云端核验结构化错误（严禁包含明文 `sk` 或代理账密）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudProbeError {
    pub code: CloudProbeErrorCode,
    pub http_status: u16,
    pub message: String,
    pub retry_after_secs: Option<u64>,
}

impl std::fmt::Display for CloudProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// 云端核验脱敏结果（可安全序列化与持久化至 `account-audit-cache.json`）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudProbeSnapshot {
    pub verified_at_ms: i64,
    pub checked_at_iso: String,
    pub email_masked: Option<String>,
    pub org_id_prefix8: Option<String>,
    pub plan: String,
    pub merchant_channel: Option<String>,
    pub workspace_geo: Option<String>,
    pub edge_country: Option<String>,
    pub edge_colo: Option<String>,
    pub account_age_days: Option<u64>,
    pub subscription_age_days: Option<u64>,
    pub subscription_ends_at: Option<String>,
    pub chat_available: bool,
    pub is_banned: bool,
    pub appeals_redirect_enabled: bool,
    pub has_monitoring_notice: bool,
    pub active_flag_types: Vec<String>,
    pub warning_summary_zh: Option<String>,
    pub persona_kyc_status: Option<String>,
    pub persona_kyc_completed_at: Option<String>,
    pub persona_kyc_age_hours: Option<u64>,
    pub portal_hold: bool,
    pub portal_state: String,
    pub five_hour_pct: Option<f64>,
    pub five_hour_resets_at: Option<String>,
    pub seven_day_pct: Option<f64>,
    pub seven_day_resets_at: Option<String>,
    pub warnings: Vec<String>,
}

/// 单次云端核验选项
#[derive(Debug, Clone, Default)]
pub struct CloudProbeOptions {
    pub proxy_url: Option<String>,
    /// 若本地已有主组织 8 位前缀，传入用于防串号校验
    pub expected_org_prefix8: Option<String>,
    pub base_url: Option<String>,
    pub timeout_secs: Option<u64>,
    /// 单测中可关闭冷却锁
    pub bypass_cooldown: bool,
}

/// 从任意原始粘贴文本（支持纯 `sk` 或整段 `Copy as cURL`）中正则提取有效 `sessionKey`
pub fn extract_session_key(raw: &str) -> Option<String> {
    static RE_SK: OnceLock<Regex> = OnceLock::new();
    let re = RE_SK.get_or_init(|| Regex::new(r"sk-ant-sid[0-9a-zA-Z_-]{16,}").unwrap());
    re.find(raw).map(|m| m.as_str().to_string())
}

/// 校验代理 URL 格式合法性（仅允许 `http://`、`https://`、`socks5://`、`socks5h://`，拒绝命令注入字符）
pub fn validate_proxy_url(raw: &str) -> Result<String, CloudProbeError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CloudProbeError {
            code: CloudProbeErrorCode::InvalidSkOrProxy,
            http_status: 400,
            message: "代理地址为空".into(),
            retry_after_secs: None,
        });
    }
    let lower = trimmed.to_ascii_lowercase();
    let scheme_ok = lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("socks5://")
        || lower.starts_with("socks5h://");
    let has_illegal = trimmed
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '|' | '&'));
    if !scheme_ok || has_illegal {
        return Err(CloudProbeError {
            code: CloudProbeErrorCode::InvalidSkOrProxy,
            http_status: 400,
            message: "代理地址格式不合法，仅支持 http:// 或 socks5:// 代理地址".into(),
            retry_after_secs: None,
        });
    }
    Ok(trimmed.to_string())
}

/// 标准 SHA-256 实现（零外部 crate 依赖，用于内存短时 `sk` 冷却指纹，绝不落盘）
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut hex = String::with_capacity(64);
    for word in h {
        hex.push_str(&format!("{word:08x}"));
    }
    hex
}

/// 内存 60s 防刷冷却锁（键为 SHA-256 指纹，不存任何明文）
fn check_and_record_cooldown(fingerprint: &str) -> Result<(), CloudProbeError> {
    static COOLDOWN_MAP: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let lock = COOLDOWN_MAP.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    // 清理过期条目
    guard.retain(|_, ts| now.duration_since(*ts) < Duration::from_secs(COOLDOWN_SECONDS * 2));
    if let Some(prev) = guard.get(fingerprint) {
        let elapsed = now.duration_since(*prev);
        if elapsed < Duration::from_secs(COOLDOWN_SECONDS) {
            let remain = COOLDOWN_SECONDS - elapsed.as_secs();
            return Err(CloudProbeError {
                code: CloudProbeErrorCode::RateLimited,
                http_status: 429,
                message: format!(
                    "同一 sessionKey 需冷却 60 秒以防高频触发风控，请 {remain} 秒后重试"
                ),
                retry_after_secs: Some(remain),
            });
        }
    }
    guard.insert(fingerprint.to_string(), now);
    Ok(())
}

/// 从 `cf-ray` 响应头推导边缘机场码与国家码
pub fn parse_cf_edge_colo(cf_ray: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(ray) = cf_ray else {
        return (None, None);
    };
    let Some(colo) = ray.trim().rsplit('-').next() else {
        return (None, None);
    };
    let upper = colo.to_ascii_uppercase();
    if upper.len() != 3 || !upper.chars().all(|c| c.is_ascii_uppercase()) {
        return (None, None);
    }
    let country = match upper.as_str() {
        "SJC" | "LAX" | "SEA" | "SFO" | "ORD" | "DFW" | "IAD" | "EWR" | "JFK" | "MIA"
        | "ATL" | "DEN" | "PHX" | "BOS" | "IAH" | "MSP" | "SLC" => Some("US"),
        "NRT" | "KIX" | "HND" | "FUK" => Some("JP"),
        "SIN" => Some("SG"),
        "HKG" => Some("HK"),
        "TPE" | "KHH" => Some("TW"),
        "ICN" => Some("KR"),
        "SYD" | "MEL" | "BNE" | "PER" | "ADL" => Some("AU"),
        "AKL" => Some("NZ"),
        "LHR" | "MAN" => Some("GB"),
        "FRA" | "MUC" | "DUS" | "TXL" => Some("DE"),
        "AMS" => Some("NL"),
        "CDG" | "MRS" => Some("FR"),
        "YYZ" | "YVR" | "YUL" => Some("CA"),
        _ => None,
    };
    (Some(upper), country.map(ToString::to_string))
}

/// 从 `/api/organizations` 列表中智能选主：优先含 `chat` 能力的 Claude.ai 聊天主组织，绝不误选 Console API 组织
pub fn select_primary_chat_org(orgs: &[Value]) -> Option<&Value> {
    if orgs.is_empty() {
        return None;
    }
    let mut best: Option<(i32, &Value)> = None;
    for (idx, org) in orgs.iter().enumerate() {
        let caps: Vec<String> = org
            .get("capabilities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect()
            })
            .unwrap_or_default();
        let has_chat = caps.iter().any(|c| c == "chat");
        let is_api_only =
            !has_chat && caps.iter().any(|c| c == "api" || c == "api_individual");
        let plan_rank = if caps.iter().any(|c| c == "claude_enterprise") {
            70
        } else if caps.iter().any(|c| c == "claude_team" || c == "raven") {
            60
        } else if caps.iter().any(|c| c == "claude_max") {
            40
        } else if caps.iter().any(|c| c == "claude_pro") {
            20
        } else if has_chat {
            10
        } else {
            0
        };
        let chat_bonus = if has_chat {
            1000
        } else if is_api_only {
            -500
        } else {
            0
        };
        let score = chat_bonus + plan_rank * 10 - (idx as i32);
        if best.map(|(s, _)| score > s).unwrap_or(true) {
            best = Some((score, org));
        }
    }
    best.map(|(_, o)| o)
}

#[derive(Debug, Clone, Default)]
pub struct RawHttpResponse {
    pub ok: bool,
    pub status_code: u16,
    pub cf_blocked: bool,
    pub network_error: bool,
    pub cf_ray: Option<String>,
    pub data: Option<Value>,
    pub error_message: Option<String>,
}

fn parse_header_block(raw_headers: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let last_block = raw_headers
        .trim()
        .rsplit("\r\n\r\n")
        .next()
        .or_else(|| raw_headers.trim().rsplit("\n\n").next())
        .unwrap_or("");
    for line in last_block.lines() {
        if let Some((k, v)) = line.split_once(':') {
            map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    map
}

fn detect_cf_challenge(status_code: u16, headers: &HashMap<String, String>, body: &str) -> bool {
    if headers
        .get("cf-mitigated")
        .map(|v| v.to_ascii_lowercase().contains("challenge"))
        .unwrap_or(false)
    {
        return true;
    }
    if (status_code == 403 || status_code == 503)
        && headers
            .get("server")
            .map(|v| v.to_ascii_lowercase().contains("cloudflare"))
            .unwrap_or(false)
        && headers
            .get("content-type")
            .map(|v| v.to_ascii_lowercase().contains("text/html"))
            .unwrap_or(false)
    {
        let snippet: String = body.chars().take(1200).collect::<String>().to_ascii_lowercase();
        if snippet.contains("just a moment")
            || snippet.contains("cf-browser-verification")
            || snippet.contains("challenge-platform")
            || snippet.contains("turnstile")
        {
            return true;
        }
    }
    false
}

/// 通过 Windows 原生 `curl.exe` (Schannel) 发送严格只读 HTTP `GET` 请求（绝不打印 `sk` 或代理账密）
fn curl_readonly_get(
    url: &str,
    session_key: &str,
    proxy_url: Option<&str>,
    timeout_secs: u64,
) -> RawHttpResponse {
    const MARKER: &str = "__FD_HTTP_META__";
    let mut cmd = Command::new("curl.exe");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.args([
        "--silent",
        "--show-error",
        "--location",
        "--max-redirs",
        "3",
        "--max-time",
        &timeout_secs.max(3).to_string(),
        "--compressed",
        "--include",
        "--request",
        "GET",
        "-H",
        &format!("Cookie: sessionKey={session_key}"),
        "-H",
        "anthropic-client-platform: web_claude_ai",
        "-H",
        &format!("User-Agent: {DEFAULT_USER_AGENT}"),
        "-H",
        "Accept: application/json, text/plain, */*",
        "-H",
        "Accept-Language: en-US,en;q=0.9",
        "-H",
        "Referer: https://claude.ai/",
        "-H",
        "Origin: https://claude.ai",
        "-w",
        &format!("\n{MARKER}%{{http_code}}"),
    ]);
    if let Some(proxy) = proxy_url {
        cmd.args(["--proxy", proxy]);
    }
    cmd.arg(url);

    let out = match cmd.output() {
        Ok(o) => o,
        Err(_) => {
            return RawHttpResponse {
                network_error: true,
                error_message: Some("调用系统 curl.exe 失败，请检查代理或网络环境".into()),
                ..Default::default()
            };
        }
    };

    if !out.status.success() && out.stdout.is_empty() {
        return RawHttpResponse {
            network_error: true,
            error_message: Some("经代理连接上游超时或网络不可达".into()),
            ..Default::default()
        };
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let (raw_resp, status_code) = match stdout.rfind(MARKER) {
        Some(idx) => {
            let code = stdout[idx + MARKER.len()..]
                .trim()
                .parse::<u16>()
                .unwrap_or(0);
            (&stdout[..idx], code)
        }
        None => (stdout.as_ref(), 0),
    };

    // 拆分多段代理 CONNECT 响应头与正文
    let parts: Vec<&str> = if raw_resp.contains("\r\n\r\n") {
        raw_resp.split("\r\n\r\n").collect()
    } else {
        raw_resp.split("\n\n").collect()
    };
    let mut body_start = 1usize;
    for (i, part) in parts.iter().enumerate() {
        if i + 1 < parts.len() && part.trim_start().to_ascii_uppercase().starts_with("HTTP/") {
            body_start = i + 1;
        } else {
            break;
        }
    }
    let header_part = if body_start <= parts.len() {
        parts[..body_start].join("\r\n\r\n")
    } else {
        String::new()
    };
    let body_text = if body_start < parts.len() {
        parts[body_start..].join("\r\n\r\n")
    } else {
        raw_resp.to_string()
    };
    let body_trimmed = body_text.trim();

    let headers = parse_header_block(&header_part);
    let cf_blocked = detect_cf_challenge(status_code, &headers, body_trimmed);
    let data = serde_json::from_str::<Value>(body_trimmed).ok();
    let is_html = !cf_blocked
        && data.is_none()
        && (headers
            .get("content-type")
            .map(|v| v.to_ascii_lowercase().contains("text/html"))
            .unwrap_or(false)
            || body_trimmed.to_ascii_lowercase().starts_with("<!doctype html")
            || body_trimmed.to_ascii_lowercase().starts_with("<html"));

    RawHttpResponse {
        ok: (200..300).contains(&status_code) && !cf_blocked && !is_html,
        status_code,
        cf_blocked,
        network_error: status_code == 0,
        cf_ray: headers.get("cf-ray").cloned(),
        data,
        error_message: if cf_blocked {
            Some("Cloudflare 人机拦截挑战".into())
        } else if is_html {
            Some("上游返回 HTML 而非 JSON".into())
        } else {
            None
        },
    }
}

/// 纯函数：将多端点 JSON 响应组装为脱敏 `CloudProbeSnapshot`（100% 可单测）
#[allow(clippy::too_many_arguments)]
pub fn assemble_cloud_snapshot(
    orgs_resp: &RawHttpResponse,
    account_resp: Option<&RawHttpResponse>,
    kyc_resp: Option<&RawHttpResponse>,
    usage_resp: Option<&RawHttpResponse>,
    chat_resp: Option<&RawHttpResponse>,
    sub_resp: Option<&RawHttpResponse>,
    portal_resp: Option<&RawHttpResponse>,
    expected_org_prefix8: Option<&str>,
    used_proxy: bool,
    now_ms: i64,
) -> Result<CloudProbeSnapshot, CloudProbeError> {
    if orgs_resp.cf_blocked {
        return Err(CloudProbeError {
            code: CloudProbeErrorCode::CfChallengeOrAuthExpired,
            http_status: 403,
            message: "请求被 Cloudflare 节点拦截盾拦截（非账号封禁），请切换干净节点后重试".into(),
            retry_after_secs: None,
        });
    }
    if orgs_resp.network_error {
        return Err(CloudProbeError {
            code: CloudProbeErrorCode::ProxyOrUpstreamFailed,
            http_status: 502,
            message: orgs_resp
                .error_message
                .clone()
                .unwrap_or_else(|| "代理或上游连接失败，请检查 Clash 是否在线".into()),
            retry_after_secs: None,
        });
    }

    let checked_at_iso = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(now_ms)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default();
    let (edge_colo, edge_country) = parse_cf_edge_colo(orgs_resp.cf_ray.as_deref());

    // 处理 401/403：区分实锤 account_banned 与普通凭据过期
    if orgs_resp.status_code == 401 || orgs_resp.status_code == 403 {
        let err_obj = orgs_resp.data.as_ref().and_then(|d| d.get("error"));
        let err_code = err_obj
            .and_then(|e| e.get("details"))
            .and_then(|d| d.get("error_code"))
            .and_then(|v| v.as_str())
            .or_else(|| err_obj.and_then(|e| e.get("message")).and_then(|v| v.as_str()))
            .unwrap_or("");
        let appeals = err_obj
            .and_then(|e| e.get("details"))
            .and_then(|d| d.get("appeals_redirect_enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if err_code.eq_ignore_ascii_case("account_banned") {
            return Ok(CloudProbeSnapshot {
                verified_at_ms: now_ms,
                checked_at_iso,
                email_masked: None,
                org_id_prefix8: None,
                plan: "未知".into(),
                merchant_channel: None,
                workspace_geo: None,
                edge_country,
                edge_colo,
                account_age_days: None,
                subscription_age_days: None,
                subscription_ends_at: None,
                chat_available: false,
                is_banned: true,
                appeals_redirect_enabled: appeals,
                has_monitoring_notice: false,
                active_flag_types: vec!["account_banned".into()],
                warning_summary_zh: Some("官方实锤封号 (account_banned)".into()),
                persona_kyc_status: None,
                persona_kyc_completed_at: None,
                persona_kyc_age_hours: None,
                portal_hold: false,
                portal_state: "banned".into(),
                five_hour_pct: None,
                five_hour_resets_at: None,
                seven_day_pct: None,
                seven_day_resets_at: None,
                warnings: Vec::new(),
            });
        }

        return Err(CloudProbeError {
            code: CloudProbeErrorCode::CfChallengeOrAuthExpired,
            http_status: 403,
            message: "sessionKey 无效或已过期（未命中 account_banned，未必代表封号），请在浏览器刷新后重新复制"
                .into(),
            retry_after_secs: None,
        });
    }

    if !orgs_resp.ok {
        return Err(CloudProbeError {
            code: CloudProbeErrorCode::ProxyOrUpstreamFailed,
            http_status: 502,
            message: format!("上游返回异常状态码 HTTP {}", orgs_resp.status_code),
            retry_after_secs: None,
        });
    }

    let orgs_arr = orgs_resp
        .data
        .as_ref()
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let primary_org = select_primary_chat_org(orgs_arr);
    let org_uuid = primary_org
        .and_then(|o| o.get("uuid"))
        .and_then(|v| v.as_str());
    let org_id_prefix8 = org_uuid.map(|u| u.chars().take(8).collect::<String>().to_ascii_lowercase());

    // 防串号保护
    if let (Some(expected), Some(actual)) = (
        expected_org_prefix8.filter(|s| !s.trim().is_empty()),
        org_id_prefix8.as_deref(),
    ) {
        if !expected.eq_ignore_ascii_case(actual) {
            return Err(CloudProbeError {
                code: CloudProbeErrorCode::OrgMismatch,
                http_status: 409,
                message: format!(
                    "检测到浏览器登录账号（组织 {actual}）与本机 CLI 主号（组织 {expected}）不一致，已阻止覆写以防串号"
                ),
                retry_after_secs: None,
            });
        }
    }

    let acct_data = account_resp.and_then(|r| if r.ok { r.data.as_ref() } else { None });
    let email_masked = acct_data
        .and_then(|a| {
            a.get("email_address")
                .or_else(|| a.get("email"))
                .and_then(|v| v.as_str())
        })
        .map(mask_email_readable);

    let matched_membership_org = acct_data
        .and_then(|a| a.get("memberships"))
        .and_then(|m| m.as_array())
        .and_then(|arr| {
            arr.iter()
                .filter_map(|m| m.get("organization"))
                .find(|o| o.get("uuid").and_then(|v| v.as_str()) == org_uuid)
        });

    let workspace_geo = matched_membership_org
        .and_then(|o| o.get("default_workspace_geo"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            primary_org
                .and_then(|o| o.get("default_workspace_geo"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.trim().to_ascii_uppercase())
        .filter(|s| !s.is_empty());

    let sub_data = sub_resp.and_then(|r| if r.ok { r.data.as_ref() } else { None });
    let plan = {
        let caps_joined = primary_org
            .and_then(|o| o.get("capabilities"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let tier = primary_org
            .and_then(|o| o.get("rate_limit_tier"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                sub_data
                    .and_then(|s| s.get("rate_limit_tier"))
                    .and_then(|v| v.as_str())
            });
        let raven = primary_org
            .and_then(|o| o.get("raven_type"))
            .and_then(|v| v.as_str());
        normalize_plan_label(Some(&caps_joined), raven, tier).unwrap_or_else(|| "Free".into())
    };

    let merchant_channel = format_merchant_channel(
        primary_org
            .and_then(|o| o.get("billing_type"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                sub_data
                    .and_then(|s| s.get("billing_type"))
                    .and_then(|v| v.as_str())
            }),
        primary_org
            .and_then(|o| o.get("merchant_of_record"))
            .and_then(|v| v.as_str())
            .or_else(|| {
                sub_data
                    .and_then(|s| s.get("merchant_of_record"))
                    .and_then(|v| v.as_str())
            }),
    );

    let parse_days = |iso: Option<&str>| -> Option<u64> {
        let dt = DateTime::parse_from_rfc3339(iso?).ok()?;
        let diff = now_ms - dt.timestamp_millis();
        Some(if diff > 0 {
            (diff / 86_400_000) as u64
        } else {
            0
        })
    };
    let account_age_days = parse_days(
        acct_data
            .and_then(|a| a.get("created_at"))
            .and_then(|v| v.as_str()),
    )
    .or_else(|| {
        parse_days(
            primary_org
                .and_then(|o| o.get("created_at"))
                .and_then(|v| v.as_str()),
        )
    });
    let subscription_age_days = parse_days(
        primary_org
            .and_then(|o| o.get("created_at"))
            .and_then(|v| v.as_str()),
    );
    let subscription_ends_at = sub_data
        .and_then(|s| {
            s.get("current_period_end")
                .or_else(|| s.get("ends_at"))
                .or_else(|| s.get("renewal_date"))
                .and_then(|v| v.as_str())
        })
        .map(|s| s.chars().take(10).collect::<String>());

    // 官方 4 大风控标记槽位 + active_flags
    let mut active_flag_types: Vec<String> = Vec::new();
    let check_truthy = |field: &str| -> bool {
        let v1 = primary_org.and_then(|o| o.get(field));
        let v2 = matched_membership_org.and_then(|o| o.get(field));
        [v1, v2].into_iter().flatten().any(|v| match v {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::String(s) => !s.trim().is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(m) => !m.is_empty(),
            Value::Number(_) => true,
        })
    };
    let mut warning_parts_zh: Vec<String> = Vec::new();
    if check_truthy("monitoring_notice") {
        active_flag_types.push("monitoring_notice".into());
        warning_parts_zh.push("后台观察标".into());
    }
    if check_truthy("billing_issue") {
        active_flag_types.push("billing_issue".into());
        warning_parts_zh.push("账单异常".into());
    }
    if check_truthy("subscription_pause") {
        active_flag_types.push("subscription_pause".into());
        warning_parts_zh.push("订阅暂停".into());
    }
    if check_truthy("access_block") {
        active_flag_types.push("access_block".into());
        warning_parts_zh.push("访问封锁".into());
    }
    if let Some(flags) = primary_org
        .and_then(|o| o.get("active_flags"))
        .and_then(|v| v.as_array())
    {
        for flag in flags {
            let ftype = flag
                .as_str()
                .or_else(|| flag.get("type").and_then(|v| v.as_str()))
                .or_else(|| flag.get("name").and_then(|v| v.as_str()))
                .unwrap_or("");
            let lower = ftype.to_ascii_lowercase();
            if lower.contains("ban")
                || lower.contains("restrict")
                || lower.contains("suspend")
                || lower.contains("abuse")
                || lower.contains("fraud")
                || lower.contains("kyc")
                || lower.contains("hold")
                || lower.contains("disable")
                || lower.contains("warn")
            {
                if !active_flag_types.iter().any(|x| x == ftype) {
                    active_flag_types.push(ftype.to_string());
                    warning_parts_zh.push(format!("风控标记({ftype})"));
                }
            }
        }
    }
    let has_monitoring_notice = !active_flag_types.is_empty();
    let warning_summary_zh = if warning_parts_zh.is_empty() {
        None
    } else {
        Some(warning_parts_zh.join(" · "))
    };

    // KYC 状态
    let kyc_data = kyc_resp.and_then(|r| if r.ok { r.data.as_ref() } else { None });
    let persona_kyc_status = kyc_data
        .and_then(|k| k.get("status"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase());
    let persona_kyc_completed_at = kyc_data
        .and_then(|k| k.get("completed_at").or_else(|| k.get("completedAt")))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let persona_kyc_age_hours = persona_kyc_completed_at
        .as_deref()
        .and_then(|iso| DateTime::parse_from_rfc3339(iso).ok())
        .map(|dt| {
            let diff = now_ms - dt.timestamp_millis();
            if diff > 0 {
                (diff / 3_600_000) as u64
            } else {
                0
            }
        });

    // Portal 挂起状态
    let (portal_hold, portal_state) = match portal_resp.and_then(|r| {
        if r.ok {
            r.data.as_ref().and_then(|d| d.as_object())
        } else {
            None
        }
    }) {
        Some(obj) if obj.contains_key("hold_notice") => {
            if obj.get("hold_notice").map(|v| v.is_null()).unwrap_or(true) {
                (false, "clear".into())
            } else {
                (true, "hold".into())
            }
        }
        _ => (false, "clear".into()),
    };

    // 对话域可读性
    let chat_available = chat_resp
        .map(|r| r.ok || (!r.cf_blocked && r.status_code != 403 && r.status_code != 400))
        .unwrap_or(true);

    // 实时用量窗口
    let usage_data = usage_resp.and_then(|r| if r.ok { r.data.as_ref() } else { None });
    let five_hour_pct = usage_data
        .and_then(|u| u.get("five_hour"))
        .and_then(|f| f.get("utilization"))
        .and_then(|v| v.as_f64());
    let five_hour_resets_at = usage_data
        .and_then(|u| u.get("five_hour"))
        .and_then(|f| f.get("resets_at"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let seven_day_pct = usage_data
        .and_then(|u| u.get("seven_day"))
        .and_then(|f| f.get("utilization"))
        .and_then(|v| v.as_f64());
    let seven_day_resets_at = usage_data
        .and_then(|u| u.get("seven_day"))
        .and_then(|f| f.get("resets_at"))
        .and_then(|v| v.as_str())
        .map(ToString::to_string);

    let mut warnings = Vec::new();
    if !used_proxy {
        warnings.push("未指定独立代理节点，当前请求走了默认出口，建议传入个人固定干净代理".into());
    }

    Ok(CloudProbeSnapshot {
        verified_at_ms: now_ms,
        checked_at_iso,
        email_masked,
        org_id_prefix8,
        plan,
        merchant_channel,
        workspace_geo,
        edge_country,
        edge_colo,
        account_age_days,
        subscription_age_days,
        subscription_ends_at,
        chat_available,
        is_banned: false,
        appeals_redirect_enabled: false,
        has_monitoring_notice,
        active_flag_types,
        warning_summary_zh,
        persona_kyc_status,
        persona_kyc_completed_at,
        persona_kyc_age_hours,
        portal_hold,
        portal_state,
        five_hour_pct,
        five_hour_resets_at,
        seven_day_pct,
        seven_day_resets_at,
        warnings,
    })
}

/// 异步执行按需只读云端核验（明文 `sessionKey` 用完即焚，支持整段 `Copy as cURL`）
pub async fn probe_session_key_readonly(
    raw_input: &str,
    opts: CloudProbeOptions,
) -> Result<CloudProbeSnapshot, CloudProbeError> {
    let mut sk = extract_session_key(raw_input).ok_or_else(|| CloudProbeError {
        code: CloudProbeErrorCode::InvalidSkOrProxy,
        http_status: 400,
        message: "未识别到有效的 sessionKey（需包含 sk-ant-sid...）".into(),
        retry_after_secs: None,
    })?;

    let validated_proxy = match opts.proxy_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(p) => Some(validate_proxy_url(p)?),
        None => None,
    };

    let fingerprint = sha256_hex(sk.as_bytes());
    if !opts.bypass_cooldown {
        if let Err(err) = check_and_record_cooldown(&fingerprint) {
            zeroize_string(&mut sk);
            return Err(err);
        }
    }

    let base_url = opts
        .base_url
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
        .trim_end_matches('/')
        .to_string();
    let timeout_secs = opts.timeout_secs.unwrap_or(15);
    let expected_org = opts.expected_org_prefix8.clone();

    let result = tokio::task::spawn_blocking(move || {
        let proxy_ref = validated_proxy.as_deref();
        let orgs_resp = curl_readonly_get(
            &format!("{base_url}/api/organizations"),
            &sk,
            proxy_ref,
            timeout_secs,
        );

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        // 若组织接口未 200，立即中止（绝不继续发多余请求），并立即焚毁 sk
        if !orgs_resp.ok {
            let out = assemble_cloud_snapshot(
                &orgs_resp,
                None,
                None,
                None,
                None,
                None,
                None,
                expected_org.as_deref(),
                proxy_ref.is_some(),
                now_ms,
            );
            zeroize_string(&mut sk);
            return out;
        }

        // 先做一次防串号早停校验：如不一致绝不继续查后续子接口
        let orgs_arr = orgs_resp
            .data
            .as_ref()
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let primary_org = select_primary_chat_org(orgs_arr);
        let org_uuid = primary_org
            .and_then(|o| o.get("uuid"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let actual_prefix = org_uuid
            .as_deref()
            .map(|u| u.chars().take(8).collect::<String>().to_ascii_lowercase());
        if let (Some(exp), Some(act)) = (
            expected_org.as_deref().filter(|s| !s.trim().is_empty()),
            actual_prefix.as_deref(),
        ) {
            if !exp.eq_ignore_ascii_case(act) {
                zeroize_string(&mut sk);
                return Err(CloudProbeError {
                    code: CloudProbeErrorCode::OrgMismatch,
                    http_status: 409,
                    message: format!(
                        "检测到浏览器登录账号（组织 {act}）与本机 CLI 主号（组织 {exp}）不一致，已阻止覆写以防串号"
                    ),
                    retry_after_secs: None,
                });
            }
        }

        let account_resp = curl_readonly_get(
            &format!("{base_url}/api/account"),
            &sk,
            proxy_ref,
            timeout_secs,
        );

        let mut kyc_resp = None;
        let mut usage_resp = None;
        let mut chat_resp = None;
        let mut sub_resp = None;
        let mut portal_resp = None;

        if let Some(ref oid) = org_uuid {
            let enc = urlencoding::encode(oid);
            kyc_resp = Some(curl_readonly_get(
                &format!("{base_url}/api/organizations/{enc}/kyc_status"),
                &sk,
                proxy_ref,
                timeout_secs,
            ));
            usage_resp = Some(curl_readonly_get(
                &format!("{base_url}/api/organizations/{enc}/usage"),
                &sk,
                proxy_ref,
                timeout_secs,
            ));
            chat_resp = Some(curl_readonly_get(
                &format!("{base_url}/api/organizations/{enc}/chat_conversations?limit=1"),
                &sk,
                proxy_ref,
                timeout_secs,
            ));
            let is_free = primary_org
                .and_then(|o| o.get("billing_type"))
                .and_then(|v| v.as_str())
                .map(|b| b.eq_ignore_ascii_case("none"))
                .unwrap_or(false);
            if !is_free {
                sub_resp = Some(curl_readonly_get(
                    &format!("{base_url}/api/organizations/{enc}/subscription_details"),
                    &sk,
                    proxy_ref,
                    timeout_secs,
                ));
            }
            portal_resp = Some(curl_readonly_get(
                &format!("{base_url}/edge-api/organizations/{enc}/billing_portal"),
                &sk,
                proxy_ref,
                timeout_secs,
            ));
        }

        // 用完即焚：显式覆写清零栈上明文 sessionKey
        zeroize_string(&mut sk);

        assemble_cloud_snapshot(
            &orgs_resp,
            Some(&account_resp),
            kyc_resp.as_ref(),
            usage_resp.as_ref(),
            chat_resp.as_ref(),
            sub_resp.as_ref(),
            portal_resp.as_ref(),
            expected_org.as_deref(),
            proxy_ref.is_some(),
            now_ms,
        )
    })
    .await
    .map_err(|_| CloudProbeError {
        code: CloudProbeErrorCode::ProxyOrUpstreamFailed,
        http_status: 502,
        message: "云端核验异步任务中断".into(),
        retry_after_secs: None,
    })?;

    result
}

/// 显式清零内存中的敏感字符串（防止残留堆内存）
fn zeroize_string(s: &mut String) {
    unsafe {
        let bytes = s.as_bytes_mut();
        for b in bytes.iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
    }
    s.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_sk_from_raw_and_copy_as_curl() {
        let curl_str = "curl 'https://claude.ai/api/organizations' -H 'cookie: cf_clearance=abc; sessionKey=sk-ant-sid01-DemoOnlyExampleToken9942a8f1; other=1'";
        assert_eq!(
            extract_session_key(curl_str).as_deref(),
            Some("sk-ant-sid01-DemoOnlyExampleToken9942a8f1")
        );
        assert!(extract_session_key("invalid-token").is_none());
    }

    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn select_primary_chat_org_skips_console_api_org() {
        let orgs = vec![
            json!({
                "uuid": "11111111-api-only",
                "capabilities": ["api", "api_individual"],
                "api_disabled_reason": "out_of_credits"
            }),
            json!({
                "uuid": "7aacf131-chat-main",
                "capabilities": ["chat", "claude_pro"],
                "billing_type": "stripe_subscription"
            }),
        ];
        let picked = select_primary_chat_org(&orgs).unwrap();
        assert_eq!(
            picked.get("uuid").and_then(|v| v.as_str()),
            Some("7aacf131-chat-main")
        );
    }

    #[test]
    fn org_mismatch_blocks_overwrite() {
        let orgs_resp = RawHttpResponse {
            ok: true,
            status_code: 200,
            cf_ray: Some("8f123456-SYD".into()),
            data: Some(json!([{
                "uuid": "bbbbbbbb-9999-8888-7777-666655554444",
                "capabilities": ["chat", "claude_pro"]
            }])),
            ..Default::default()
        };
        let err = assemble_cloud_snapshot(
            &orgs_resp,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("7aacf131"),
            true,
            1_795_500_000_000,
        )
        .unwrap_err();
        assert_eq!(err.code, CloudProbeErrorCode::OrgMismatch);
        assert!(err.message.contains("串号"));
    }

    #[test]
    fn assemble_snapshot_detects_banned_and_appeals() {
        let banned_resp = RawHttpResponse {
            ok: false,
            status_code: 403,
            cf_ray: Some("8f123456-SJC".into()),
            data: Some(json!({
                "error": {
                    "type": "permission_error",
                    "message": "account_banned",
                    "details": {
                        "error_code": "account_banned",
                        "appeals_redirect_enabled": true
                    }
                }
            })),
            ..Default::default()
        };
        let snap = assemble_cloud_snapshot(
            &banned_resp,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            true,
            1_795_500_000_000,
        )
        .unwrap();
        assert!(snap.is_banned);
        assert!(snap.appeals_redirect_enabled);
        assert!(!snap.chat_available);
    }
}
