use crate::maintenance::sanitize_sensitive_text;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 单条实时解析出的日志行为 / 异常归因事件
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    pub id: String,
    pub rule_id: Option<String>,
    pub anomaly: bool,
    #[serde(default)]
    pub simulated: bool,
    #[serde(default)]
    pub acked: bool,
    pub level: String, // "fail" | "warn" | "ok"
    pub tag: String,
    pub time: String,
    pub file: String,
    pub line: usize,
    pub title: String,
    pub cause: String,
    pub context: String,
    /// T-201：60 秒内同类重复刷屏折叠计数（默认 1）
    #[serde(default = "default_repeat_count")]
    pub repeat_count: usize,
    /// T-201：折叠合并包含的全部原始事件 ID（标为已读时整组同步推进游标）
    #[serde(default)]
    pub collapsed_ids: Vec<String>,
    /// T-301：高危异常展开时附带的紧凑 72h 前置线索（单行，不污染主列表）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution_clue: Option<String>,
}

fn default_repeat_count() -> usize {
    1
}

/// 已被自动过滤的无关噪音分类计数（供日志页折叠面板展示明细）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NoiseCategoryCount {
    pub label: String,
    pub count: usize,
}

/// 累计日志统计汇总
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogStats {
    pub total_anomalies: usize,
    /// T-202：未读高危异常数（level == "fail"）
    #[serde(default)]
    pub critical_count: usize,
    /// T-202：未读风险提醒数（level == "warn"）
    #[serde(default)]
    pub warning_count: usize,
    pub region_or_rate_count: usize,
    pub disconnect_count: usize,
    pub telemetry_or_device_count: usize,
    pub watching_files: Vec<String>,
    /// 已自动排除的无关噪音条数（如第三方 503、合盖休眠、VM 缺失、chrome-native-host 未运行等）
    #[serde(default)]
    pub ignored_noise_count: usize,
    /// 已自动排除的无关噪音分类明细（仅包含命中次数 > 0 的分类）
    #[serde(default)]
    pub ignored_noise_breakdown: Vec<NoiseCategoryCount>,
    /// 若日志中检测到剧烈系统时区跳变（如 UTC+8 -> UTC-7 跨 15h），输出风险提示
    #[serde(default)]
    pub timezone_jump_warning: Option<String>,
}

/// T-301：72h 封号前置 6 维行为归因快照（全匿名无隐私，用于诊断包导出、高危线索提示与云端封号归因分析）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BanAttributionSnapshot {
    pub schema_version: u32,
    pub generated_at: String,
    pub unique_org_hash_count: usize,
    pub restricted_org_hash_count: usize,
    pub cross_org_race_detected: bool,
    pub account_change_count: usize,
    pub disconnect_count: usize,
    pub disconnect_to_quit_403_count: usize,
    pub cookie_403_count: usize,
    pub rate_limit_429_count: usize,
    pub plan_changed_detected: bool,
    pub cf_403_shield_count: usize,
    pub region_unavailable_count: usize,
    pub tz_jump_detected: bool,
    pub exit_region_code: String,
    pub node_drift_warn: bool,
    pub kill_switch_active: bool,
    pub top_risk_factors: Vec<String>,
    pub summary_line: String,
}

/// 单条遥测缓存文件预览（用于日志页点击「遥测 / 设备记录」查看本地遥测详情）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryFilePreview {
    pub file_name: String,
    pub size_bytes: u64,
    pub size_label: String,
    pub modified_at: String,
    pub preview_text: String,
}

/// 本地遥测数据只读体检快照
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryInspection {
    pub telemetry_dir: String,
    pub total_files: usize,
    pub total_bytes: u64,
    pub total_size_label: String,
    pub explanation: String,
    pub files: Vec<TelemetryFilePreview>,
}

/// 日志账号与封禁只读审计摘要（供 preflight claude_acct 与排障包复用）
#[derive(Debug, Clone, Default)]
pub struct AccountLogAudit {
    pub scanned_files: usize,
    pub unique_org_ids: Vec<String>,
    pub unique_account_ids: Vec<String>,
    /// 命中过 Verification Portal、account_banned 或高危 403 permission_error 的关联 orgId 前缀
    pub restricted_org_ids: Vec<String>,
    pub cross_account_hits: Vec<String>,
    pub auth_403_hits: Vec<String>,
    pub account_change_count: usize,
}

/// 识别并返回已知无关噪音的分类标签（None 表示非噪音）
pub fn classify_ignored_log_noise(file_name: &str, lower: &str) -> Option<&'static str> {
    let fname = file_name.to_lowercase();
    if fname.contains("custom3p-setup")
        || (lower.contains("bootstrap request failed") && lower.contains("503 service unavailable"))
    {
        return Some("第三方引导页 503 (custom3p-setup)");
    }
    if fname.contains("cowork_vm_node") || lower.contains("sessiondata.vhdx") {
        return Some("本地 Cowork VM 镜像缺失 (sessiondata.vhdx)");
    }
    if fname.contains("chrome-native-host") || lower.contains("desktop not running") {
        return Some("Desktop 未运行时插件探活 (chrome-native-host)");
    }
    if lower.contains("err_network_io_suspended") {
        return Some("系统合盖休眠挂起 (ERR_NETWORK_IO_SUSPENDED)");
    }
    if lower.contains("maxlistenersexceededwarning") || lower.contains("intercom.io") {
        return Some("客服组件或监听器提示 (intercom / MaxListeners)");
    }
    None
}

/// 判断是否属于已知无关噪音（防止误报恐慌：第三方引导 503、合盖休眠、VM 镜像缺失、native-host 未运行等）
pub fn is_ignored_log_noise(file_name: &str, lower: &str) -> bool {
    classify_ignored_log_noise(file_name, lower).is_some()
}

fn is_real_rate_limit_or_high_concurrency(lower: &str) -> bool {
    static RE_429: OnceLock<Regex> = OnceLock::new();
    static RE_SIDE_SESSIONS: OnceLock<Regex> = OnceLock::new();

    if lower.contains("rate_limit_error") || lower.contains("too many requests") {
        return true;
    }
    let re_429 = RE_429.get_or_init(|| {
        Regex::new(r#"(?i)(?:http[/\s]+|status[_\s:=]+["']?)429\b"#).expect("valid 429 regex")
    });
    if re_429.is_match(lower) {
        return true;
    }
    // 仅当并发 sideSessions 明确 >= 3 时才预警，绝不因普通进程号或普通单会话误报
    let re_side = RE_SIDE_SESSIONS
        .get_or_init(|| Regex::new(r"sidesessions?\s*[:=]\s*(\d+)").expect("valid sidesession regex"));
    if let Some(caps) = re_side.captures(lower) {
        if let Some(n) = caps.get(1).and_then(|m| m.as_str().parse::<u32>().ok()) {
            return n >= 3;
        }
    }
    false
}

/// P0-3：基于文件名 + 时间戳 + 归一化内容生成稳定事件 ID（FNV-1a 64-bit），彻底根除 >512KB 日志截断后行号漂移导致已读失效与遥测风暴
pub fn stable_log_event_id(file_name: &str, time: &str, trimmed_line: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for part in [file_name, "|", time, "|", trimmed_line] {
        for b in part.as_bytes() {
            hash ^= *b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("log-{file_name}-{hash:016x}")
}

/// 单行日志解析与异常归因引擎（供实时 tail 与单元测试共用）
pub fn parse_log_line(file_name: &str, line_no: usize, raw_line: &str) -> Option<LogEvent> {
    parse_log_line_with_fallback_ts(file_name, line_no, raw_line, None)
}

/// 带上下文回退时间戳的单行日志解析器：
/// - 优先使用行首显式时间戳；
/// - 多行堆栈/属性子行（无行首时间戳，如 `[message]: 'net::ERR_CONNECTION_CLOSED'`）继承最近一条日志行的时间戳；
/// - 绝不回退为 `Local::now()` 参与稳定事件 ID 哈希，彻底根除跨秒重扫导致 ID 漂移与已读游标失效。
pub fn parse_log_line_with_fallback_ts(
    file_name: &str,
    line_no: usize,
    raw_line: &str,
    fallback_ts: Option<&str>,
) -> Option<LogEvent> {
    let trimmed = raw_line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_lowercase();
    if is_ignored_log_noise(file_name, &lower) {
        return None;
    }
    let extracted_ts = extract_timestamp(trimmed);
    let stable_ts = extracted_ts
        .as_deref()
        .or(fallback_ts)
        .unwrap_or("");
    let time = if stable_ts.is_empty() {
        "时间未知".to_string()
    } else {
        stable_ts.to_string()
    };
    let file_ref = format!("{file_name}:{line_no}");
    let id = stable_log_event_id(file_name, stable_ts, trimmed);

    // 0. 官方验证拦截门户（Verification Portal：高危风控待核验，与永久封号严格区分）
    if lower.contains("portal.anthropic.com/verify")
        || lower.contains("can't receive replies from claude")
    {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_pay".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "fail".into(),
            tag: "验证受限".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "触发官方验证门户限制（portal.anthropic.com/verify · 高危待核验）".into(),
            cause: "触发归因：属于高危风控升级（待核验），并非确认永久封号，核验/申诉后仍可能恢复。处理建议：请先通过纯净合规节点访问官方 Verification Portal 核实，严禁在未清理目录前直接同机切备用号以免连坐抬权。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    if lower.contains("region_unavailable") || lower.contains("claude isn't available in your region") {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_exit".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "fail".into(),
            tag: "地区封锁".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "触发 region_unavailable（服务端判定非支持地区）".into(),
            cause: "触发归因：出口 IP 漂移至禁区，或退出 Claude 时 onQuitCleanup 在代理断开后泄露真实 IP。处理建议：立即检查代理规则/TUN/IPv6，更换合规节点并清理本地污染记录。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 1. 确认封号 / 服务端强制吊销 Token（实锤红线：含 account_banned、forced_renewal、invalid_grant、OAuth token revoked 及 len=130/len=123 强吊响应）
    let is_confirmed_ban = lower.contains("account_banned")
        || lower.contains("account_suspended")
        || lower.contains("organization_disabled")
        || lower.contains("ban_evasion")
        || lower.contains("signups_disabled")
        || lower.contains("oauth token revoked")
        || (lower.contains("a live token was expired early") && lower.contains("forced_renewal"))
        || lower.contains("400 invalid_grant")
        || (lower.contains("permission_error")
            && (lower.contains("len=130") || lower.contains("len=123")));

    if is_confirmed_ban {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_pay".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "fail".into(),
            tag: "账号封禁".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "确认捕获账号封禁或 OAuth 强制吊销（高危红线）".into(),
            cause: "触发归因：服务端已明确返回封禁或强制吊销活跃 Token（非普通身份验证）。严禁立即在同一客户端直接切备用号，请先清零进程并点击「退出登录并清理（备份）本地污染目录」。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 2. 真正的跨账号混登 / 跨 Org 异步竞态（仅限多号交叉证据，不把单号 auth_error 误判为连坐）
    if lower.contains("sessionkey names a different account")
        || (lower.contains("orgid") && lower.contains("404"))
    {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_pay".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "fail".into(),
            tag: "账号连坐".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "检测到跨账号 Org 异步竞态请求（多号连坐高危）".into(),
            cause: "触发归因：同一客户端切换多个账号时，新号 Cookie 误请求了旧号 orgId。处理建议：停止同机切号，前往控制台「单号卫生锁」二选一确认或退出登录并备份清理目录。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 3A. 需身份验证（Persona KYC）或暂无有效订阅权限（仅匹配真实 403 + permission_error len=164 / len=156）
    //     绝不误判为永久封号，也不触发控制台红灯或单号卫生锁！
    if (lower.contains("authorize returned 403") && lower.contains("permission_error"))
        || (lower.contains("oauth failed") && lower.contains("status=403") && lower.contains("permission_error"))
        || (lower.contains("permission_error") && (lower.contains("len=164") || lower.contains("len=156")))
    {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_pay".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "warn".into(),
            tag: "身份验证/权限".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "OAuth 403 权限被拒（可能为 Free 号无 Pro 权限或待完成 KYC，保守标风险）".into(),
            cause: "风险原因：Claude 客户端在写入日志前已脱敏响应正文，仅保留 permission_error (len=164/len=156)，单凭日志无法 100% 区分「Free 账号缺少 Pro/Max 权限」与「账号触发 Persona KYC 身份验证/权限风控」，按防封安全红线保守标为风险（非确认永久封号）。处理建议：① 若确认是 Free 号未开通 Pro 且能正常网页对话，可点「全部标为已读」或升级套餐；② 若桌面端弹出身份验证提示，请保持稳定纯净节点完成认证；③ 若需换号重登，先点「退出登录并清理（备份）」。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 3B-OAuthV2（T-201）：独立拆出 [oauth-v2] fresh exchange failed (auth_error) 与 session_stale_relogin
    // 绝不张冠李戴套用 OAuth 403 / len=164 文案，归类为黄色风险提醒
    if (lower.contains("fresh exchange failed")
        && (lower.contains("auth_error") || lower.contains("session_stale_relogin")))
        || (lower.contains("oauth-v2")
            && (lower.contains("auth_error") || lower.contains("session_stale_relogin")))
    {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_pay".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "warn".into(),
            tag: "OAuth v2 鉴权".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "OAuth v2 令牌交换失败（auth_error，风险提醒 · 非 403）".into(),
            cause: "风险原因：桌面端后台尝试换取或刷新 OAuth v2 令牌时返回 auth_error（非 HTTP 403，非确认永久封号）。常见原因：① 当前套餐无对应功能权限（如 Free 号后台探测 Pro/Cowork Scope）；② 本地 sessionKey 过久触发 session_stale_relogin 需重新交互登录；③ 默认浏览器与桌面端登录了不同账号或本地凭据失步。处理建议：若日常对话正常可直接点「标为已读」；若反复提示重新登录，请确保浏览器与桌面端为同一账号后重新登录。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 3B. 带 Cookie / 凭证的脱敏 403（182 / 270 chars 等高危泄露特征）与未登录 credential: none 严格区分
    let has_cookie_403 = lower.contains("credentialed upload refused")
        || (lower.contains("403") && lower.contains("credential: cookie") && lower.contains("withheld"))
        || ((lower.contains("[plan-usage]")
            || lower.contains("[growthbook]")
            || (lower.contains("[account]") && lower.contains("bootstrap")))
            && lower.contains("returned 403"));
    if has_cookie_403 && !lower.contains("credential: none") {
        let len_hint = if lower.contains("182 chars") {
            "（响应体脱敏长度精确为 182 字符，与明文 region_unavailable JSON 一致，高度疑似代理断连或切直连导致带 Cookie 泄露）"
        } else if lower.contains("270 chars") {
            "（响应体脱敏 270 字符，疑似带 Cookie 退出回传或异常节点触发风控拒绝）"
        } else {
            ""
        };
        return Some(LogEvent {
            id,
            rule_id: Some("pb_exit".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "fail".into(),
            tag: "带凭证 403".into(),
            time,
            file: file_ref,
            line: line_no,
            title: format!("捕获带 Cookie / 凭证的 API 403 拒绝{len_hint}"),
            cause: "触发归因：客户端携带登录态请求 Anthropic 接口被拒，常见于代理突然断连、切回直连或退出清理回传瞬间。处理建议：确保开启「运行中自动 4 层热熔断」，切勿在断网或关闭 Clash 后手动关闭 Claude 窗口。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }
    if lower.contains("403") && lower.contains("credential: none") {
        return Some(LogEvent {
            id,
            rule_id: None,
            anomaly: false,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "ok".into(),
            tag: "未登录 403".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "未登录态轮询返回 403（credential: none · 低危非封号）".into(),
            cause: "说明：登出状态下后台接口（如 my-access）不带 Cookie 触发的普通 403，不代表账号被封禁。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 4. Apple App Store 与网页端订阅通道冲突
    if lower.contains("app store subscription conflict")
        || lower.contains("subscription through the app store has not fully ended")
    {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_pay".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "warn".into(),
            tag: "订阅冲突".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "检测到 Apple App Store 订阅通道冲突".into(),
            cause: "触发归因：此前通过 App Store 订阅尚未完全结束或处于待续费状态。处理建议：先在 Apple 订阅管理中取消待处理订阅，待周期结束后再通过网页端重新订阅。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 5. 网页端访问 claude.ai 遭遇 Cloudflare 403 拦截盾
    if lower.contains("navigation to https://claude.ai/ failed with status code 403") {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_node".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "warn".into(),
            tag: "网页 403 盾".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "访问 claude.ai 网页入口触发 Cloudflare 403 拦截".into(),
            cause: "触发归因：当前节点出口 IP 信誉分偏低触发 Cloudflare 盾。处理建议：前往「节点流量」查看无弹盾节点并切换至低风控纯净节点。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    if is_real_rate_limit_or_high_concurrency(&lower) {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_rate".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "warn".into(),
            tag: "高并发 429".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "检测到真实 HTTP 429 限流或高并发会话预警".into(),
            cause: "触发归因：短时间并发请求过高或额度触顶。处理建议：降低并行会话数量并静默冷却数分钟，避免自动化脚本高频重试。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 6. Anthropic 官方服务端过载 529 / 503（与本地封号无关）
    if lower.contains("overloaded_error")
        || lower.contains("status=529")
        || lower.contains("status code 529")
        || lower.contains("503 service unavailable")
    {
        return Some(LogEvent {
            id,
            rule_id: None,
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "warn".into(),
            tag: "官方过载".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "Anthropic 官方服务临时过载（HTTP 529 / overloaded_error）".into(),
            cause: "触发归因：属于 Anthropic 官方服务器高峰拥堵，与你的账号状态或代理无关。处理建议：无需切节点或清理目录，稍等数分钟重试即可。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 7A. 正常 5 小时周期限额提示（与封号无关，不计入高危异常）
    if lower.contains("5-hour limit") || lower.contains("hit your 5-hour") {
        return Some(LogEvent {
            id,
            rule_id: None,
            anomaly: false,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "ok".into(),
            tag: "额度提示".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "触发正常 5 小时对话周期限额（非封号）".into(),
            cause: "说明：属于官方套餐正常的 5 小时滚动限额，等待周期重置即可，与风控封号无关。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 7. 账户额度不足 / 账单待支付（非封号）
    if lower.contains("credit balance is too low")
        || lower.contains("billing_error")
        || lower.contains("usage limit reached")
        || lower.contains("exceeded your current quota")
    {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_pay".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "warn".into(),
            tag: "额度不足".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "账户额度用尽或账单受限（非封号）".into(),
            cause: "触发归因：当前套餐周期额度已达上限或 API 余额不足。处理建议：等待额度重置或检查官方账单页，切勿在短时间内反复换号登录同一设备。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    // 8. 本地登录态缺失 / 过期（未登录：属于正常状态，不计为异常或风险，仅在「全部行为」留档）
    if lower.contains("no sessionkey cookie found")
        || lower.contains("authentication_error")
        || lower.contains("invalid x-api-key")
    {
        return Some(LogEvent {
            id,
            rule_id: None,
            anomaly: false,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "ok".into(),
            tag: "未登录".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "本地会话未登录或凭证已过期（正常状态）".into(),
            cause: "说明：当前尚未登录 Claude 或刚清理完本地目录，属于正常未登录状态，不计为风控风险；确认代理合规后正常登录即可。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    if lower.contains("err_connection_closed")
        || lower.contains("err_connection_reset")
        || lower.contains("socket closed: 1006")
        || lower.contains("err_network_changed")
        || lower.contains("econnreset")
        || lower.contains("econnrefused")
        || lower.contains("etimedout")
        || lower.contains("unable_to_verify_leaf_signature")
    {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_node".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "warn".into(),
            tag: "网络断连".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "代理链路异常断连或 WebSocket 中断（ERR_CONNECTION_RESET / 1006）".into(),
            cause: "触发归因：节点高抖动、断流、切网或本地代理端口波动。处理建议：短时偶发先观望；切勿在断连状态下直接关闭 Claude 窗口（防止退出清理回传 Cookie 403），频繁断连请切同区低抖动热备。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    if lower.contains("plan_changed")
        || lower.contains("subscription_tier")
        || lower.contains("upgraded to max")
    {
        return Some(LogEvent {
            id,
            rule_id: Some("pb_24h".into()),
            anomaly: true,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "warn".into(),
            tag: "套餐变更".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "检测到订阅套餐变更，进入 24 小时支付复审高敏窗口".into(),
            cause: "触发归因：建议在「守卫配置」开启 24h 冷静保护模式，期间严禁切节点与高并发。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    if lower.contains("flusheventqueue") || lower.contains("onquitcleanup") {
        return Some(LogEvent {
            id,
            rule_id: None,
            anomaly: false,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "ok".into(),
            tag: "遥测".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "后台刷新 EventLogging 队列".into(),
            cause: "说明：Claude 会在运行期间和退出前上报客户端行为事件队列，请确保 Claude 彻底退出后再关闭代理。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    if lower.contains("get_device_info") {
        return Some(LogEvent {
            id,
            rule_id: None,
            anomaly: false,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "ok".into(),
            tag: "设备采集".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "响应 1 次设备信息采集（get_device_info）".into(),
            cause: "说明：Claude 桌面端/扩展上报操作系统、硬件或桥接状态元数据，已计入累计统计；未用浏览器桥接可关闭降噪。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    if lower.contains("token renewal") || lower.contains("oauth-v2") {
        return Some(LogEvent {
            id,
            rule_id: None,
            anomaly: false,
            simulated: false,
            acked: false,
            repeat_count: 1,
            collapsed_ids: Vec::new(),
            attribution_clue: None,
            level: "ok".into(),
            tag: "鉴权".into(),
            time,
            file: file_ref,
            line: line_no,
            title: "OAuth 令牌状态更新".into(),
            cause: "正常鉴权交互。".into(),
            context: sanitize_sensitive_text(trimmed),
        });
    }

    None
}

/// P0-2 修复：严格校验 UTF-8 字符边界与 ASCII 字节，杜绝含中文日志行 `&line[..19]` 切片 Panic
fn extract_timestamp(line: &str) -> Option<String> {
    if line.len() >= 19 && line.is_char_boundary(19) {
        let bytes = line.as_bytes();
        if bytes[..19].iter().all(|b| b.is_ascii())
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && (bytes[10] == b' ' || bytes[10] == b'T')
            && bytes[13] == b':'
            && bytes[16] == b':'
        {
            return Some(line[..19].replace('T', " "));
        }
    }
    None
}

/// 缓存本机 Claude 日志目录列表（60s TTL），避免 2s 后台哨兵反复遍历 Windows `LocalAppData\Packages` 上百个 UWP 目录
fn discover_claude_log_dirs_cached() -> Vec<PathBuf> {
    static CACHED_DIRS: OnceLock<Mutex<(Option<Instant>, Vec<PathBuf>)>> = OnceLock::new();
    let lock = CACHED_DIRS.get_or_init(|| Mutex::new((None, Vec::new())));
    if let Ok(guard) = lock.lock() {
        if let Some(ts) = guard.0 {
            if ts.elapsed() < Duration::from_secs(60) {
                return guard.1.clone();
            }
        }
    }

    let mut dirs_to_check = Vec::new();
    if let Some(local) = dirs::data_local_dir() {
        dirs_to_check.push(local.join("Claude").join("logs"));
        // 兼容 MSIX 新版 Claude 桌面端（%LOCALAPPDATA%\Claude-Data\claude_*\logs）
        let claude_data = local.join("Claude-Data");
        if let Ok(entries) = fs::read_dir(claude_data) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    dirs_to_check.push(p.join("logs"));
                }
            }
        }
        let packages = local.join("Packages");
        if let Ok(entries) = fs::read_dir(packages) {
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if n.contains("claude") || n.contains("anthropic") {
                    dirs_to_check.push(
                        e.path()
                            .join("LocalCache")
                            .join("Roaming")
                            .join("Claude")
                            .join("logs"),
                    );
                    dirs_to_check.push(
                        e.path()
                            .join("LocalCache")
                            .join("Local")
                            .join("Claude")
                            .join("logs"),
                    );
                }
            }
        }
    }
    if let Some(roaming) = dirs::config_dir() {
        dirs_to_check.push(roaming.join("Claude").join("logs"));
    }
    dirs_to_check.sort();
    dirs_to_check.dedup();

    if let Ok(mut guard) = lock.lock() {
        *guard = (Some(Instant::now()), dirs_to_check.clone());
    }
    dirs_to_check
}

/// 发现本机所有存在的 Claude 日志文件（兼容 Electron 与 MSIX LocalCache）
pub fn discover_claude_log_files() -> Vec<PathBuf> {
    let dirs_to_check = discover_claude_log_dirs_cached();

    let mut files = Vec::new();
    for dir in dirs_to_check {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_lowercase();
            if name == "main.log" || name == "claude.ai-web.log" || name.ends_with(".log") {
                files.push(path);
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

/// 计算本机 Claude 日志文件的指纹签名（总字节数 + 最新修改时间戳），供后台毫秒级增量变化监听
pub fn claude_logs_fingerprint() -> (u64, u64) {
    let mut total_bytes = 0u64;
    let mut latest_mtime = 0u64;
    for path in discover_claude_log_files() {
        if let Ok(meta) = fs::metadata(&path) {
            total_bytes = total_bytes.saturating_add(meta.len());
            if let Ok(mod_t) = meta.modified() {
                if let Ok(dur) = mod_t.duration_since(std::time::UNIX_EPOCH) {
                    latest_mtime = latest_mtime.max(dur.as_millis() as u64);
                }
            }
        }
    }
    (total_bytes, latest_mtime)
}

/// 纯函数：从日志文本提取唯一 orgId / accountId、关联受限号、跨号竞态与 403 权限拒绝特征（供生产与单元测试共用）
pub fn audit_log_text_for_accounts(text: &str, audit: &mut AccountLogAudit) {
    static RE_ORG: OnceLock<Regex> = OnceLock::new();
    static RE_ACCT: OnceLock<Regex> = OnceLock::new();
    let re_org = RE_ORG.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:orgId|organization_uuid|organizationId|[?&]org)["'=:\s]+([a-f0-9-]{8,36})"#,
        )
        .expect("valid orgId regex")
    });
    let re_acct = RE_ACCT.get_or_init(|| {
        Regex::new(r#"(?i)(?:accountId|account_uuid)["'=:\s]+([a-f0-9-]{8,36})"#)
            .expect("valid accountId regex")
    });

    let mut last_seen_org: Option<String> = None;
    for line in text.lines() {
        let lower = line.to_lowercase();
        let mut line_orgs: Vec<String> = Vec::new();
        for caps in re_org.captures_iter(line) {
            let prefix = caps[1].chars().take(8).collect::<String>();
            if !audit.unique_org_ids.contains(&prefix) {
                audit.unique_org_ids.push(prefix.clone());
            }
            if !line_orgs.contains(&prefix) {
                line_orgs.push(prefix.clone());
            }
            last_seen_org = Some(prefix);
        }
        for caps in re_acct.captures_iter(line) {
            let prefix = caps[1].chars().take(8).collect::<String>();
            if !audit.unique_account_ids.contains(&prefix) {
                audit.unique_account_ids.push(prefix);
            }
        }

        // 与 account_audit::disambiguate 100% 同源对齐：
        // len=156 / len=164 是 Free/普通号背景 OAuth 套餐权限边界 403（PlanBoundaryOAuth403），绝不视为受限或封号！
        // 仅明确封禁 / 门户核验 / len=130 / len=123 强吊才计入高危受限号。
        let is_restricted_hit = lower.contains("portal.anthropic.com/verify")
            || lower.contains("can't receive replies from claude")
            || lower.contains("account_banned")
            || lower.contains("account_suspended")
            || lower.contains("organization_disabled")
            || lower.contains("ban_evasion")
            || (lower.contains("permission_error")
                && (lower.contains("len=130") || lower.contains("len=123")));
        if is_restricted_hit {
            if !line_orgs.is_empty() {
                for o in &line_orgs {
                    if !audit.restricted_org_ids.contains(o) {
                        audit.restricted_org_ids.push(o.clone());
                    }
                }
            } else if let Some(ref last) = last_seen_org {
                if !audit.restricted_org_ids.contains(last) {
                    audit.restricted_org_ids.push(last.clone());
                }
            }
        }

        if lower.contains("sessionkey names a different account")
            || (lower.contains("orgid") && lower.contains("404"))
        {
            if audit.cross_account_hits.len() < 5 {
                audit
                    .cross_account_hits
                    .push(sanitize_sensitive_text(line.trim()));
            }
        }
        if (lower.contains("authorize returned 403") && lower.contains("permission_error"))
            || (lower.contains("fresh exchange failed") && lower.contains("auth_error"))
        {
            if audit.auth_403_hits.len() < 5 {
                audit.auth_403_hits.push(sanitize_sensitive_text(line.trim()));
            }
        }
        if lower.contains("refreshing for account change") {
            audit.account_change_count += 1;
        }
    }
}

/// 从本地 Claude 日志只读提取唯一 orgId / accountId、受限号关联、跨号竞态与 403 权限拒绝特征（供单号卫生锁使用）
/// 仅 seek 尾部最多 2MB 读取，避免超大日志文件整文件读入内存
pub fn audit_claude_logs_for_accounts() -> AccountLogAudit {
    let mut audit = AccountLogAudit::default();
    const MAX_AUDIT_TAIL_BYTES: u64 = 2 * 1024 * 1024;
    for path in discover_claude_log_files() {
        audit.scanned_files += 1;
        let Ok(mut file) = File::open(&path) else {
            continue;
        };
        let Ok(meta) = file.metadata() else {
            continue;
        };
        let start_offset = meta.len().saturating_sub(MAX_AUDIT_TAIL_BYTES);
        if start_offset > 0 {
            let _ = file.seek(SeekFrom::Start(start_offset));
        }
        let mut bytes = Vec::new();
        if file.read_to_end(&mut bytes).is_err() {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        audit_log_text_for_accounts(&text, &mut audit);
    }
    audit
}

/// 只读巡检本机 `~/.claude/telemetry/` 目录下的遥测缓存文件，供用户在日志页查看具体内容
pub fn inspect_local_telemetry() -> TelemetryInspection {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".claude")
        .join("telemetry");
    let dir_str = dir.to_string_lossy().to_string();

    let mut files = Vec::new();
    let mut total_bytes = 0u64;

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Ok(meta) = fs::metadata(&path) else {
                continue;
            };
            let size = meta.len();
            total_bytes = total_bytes.saturating_add(size);
            let modified_at = meta
                .modified()
                .ok()
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Local> = t.into();
                    dt.format("%Y-%m-%d %H:%M:%S").to_string()
                })
                .unwrap_or_else(|| "-".into());
            let raw_preview = fs::read(&path)
                .map(|b| {
                    let cut = b.len().min(1200);
                    sanitize_sensitive_text(&String::from_utf8_lossy(&b[..cut]))
                })
                .unwrap_or_else(|_| "(无法读取文件内容)".into());
            files.push(TelemetryFilePreview {
                file_name: entry.file_name().to_string_lossy().to_string(),
                size_bytes: size,
                size_label: format_bytes_short(size),
                modified_at,
                preview_text: raw_preview,
            });
        }
    }
    files.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));

    TelemetryInspection {
        telemetry_dir: dir_str,
        total_files: files.len(),
        total_bytes,
        total_size_label: format_bytes_short(total_bytes),
        explanation: "Claude 遥测与设备记录主要包含两类数据：① 运行与退出前的 EventLogging 事件队列（如操作耗时、错误堆栈、会话生命周期，落盘于 ~/.claude/telemetry/ 的失败重试缓存）；② 桌面端/扩展触发的 get_device_info（操作系统版本、硬件与桥接环境元数据）。开启「官方隐私降噪开关」后已大幅降低非必要上报，且所有预览内容均已自动脱敏。".into(),
        files,
    }
}

fn format_bytes_short(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn parse_naive_secs(ts: &str) -> Option<i64> {
    chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|dt| dt.and_utc().timestamp())
}

/// 从日志文本中交叉比对行首本地时间与 process_start_epoch_ms / quit_epoch_ms，检测剧烈系统时区跳变（>= 4h）
pub fn detect_timezone_jump_in_text(text: &str) -> Option<String> {
    static RE_EPOCH: OnceLock<Regex> = OnceLock::new();
    let re_epoch = RE_EPOCH.get_or_init(|| {
        Regex::new(r#"(?i)(?:process_start_epoch_ms|quit_epoch_ms)["'=:\s]+(\d{13})"#)
            .expect("valid epoch_ms regex")
    });
    let mut min_offset_h: Option<i32> = None;
    let mut max_offset_h: Option<i32> = None;
    for line in text.lines() {
        if let (Some(ts_str), Some(caps)) = (extract_timestamp(line), re_epoch.captures(line)) {
            if let (Some(local_secs), Ok(epoch_ms)) =
                (parse_naive_secs(&ts_str), caps[1].parse::<i64>())
            {
                let utc_secs = epoch_ms / 1000;
                let diff_h = ((local_secs - utc_secs) as f64 / 3600.0).round() as i32;
                if (-12..=14).contains(&diff_h) {
                    min_offset_h = Some(min_offset_h.map_or(diff_h, |m| m.min(diff_h)));
                    max_offset_h = Some(max_offset_h.map_or(diff_h, |m| m.max(diff_h)));
                }
            }
        }
    }
    if let (Some(lo), Some(hi)) = (min_offset_h, max_offset_h) {
        let span = (hi - lo).abs();
        if span >= 4 {
            let fmt = |h: i32| if h >= 0 { format!("UTC+{h}") } else { format!("UTC{h}") };
            return Some(format!(
                "检测到历史系统时区剧烈跳变：{} ↔ {}（跨 {} 小时），建议保持固定系统时区并选用近时区节点",
                fmt(lo),
                fmt(hi),
                span
            ));
        }
    }
    None
}

fn scan_log_text_with_context_detailed(
    file_name: &str,
    text: &str,
    max_events: usize,
) -> (Vec<LogEvent>, usize, std::collections::BTreeMap<&'static str, usize>, Option<String>) {
    let mut events = Vec::new();
    let mut ignored_noise = 0usize;
    let mut noise_map: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    let mut last_disconnect_secs: Option<i64> = None;
    let mut in_quit_after_disconnect = false;
    let mut last_seen_ts: Option<String> = None;

    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // 即使当前行随后会被噪音过滤跳过，只要行首带有有效时间戳就更新上下文游标，
        // 确保紧随其后的多行 Error 栈子行能准确继承原时间戳。
        let line_ts = extract_timestamp(trimmed);
        if let Some(ref ts) = line_ts {
            last_seen_ts = Some(ts.clone());
        }
        let lower = trimmed.to_lowercase();
        if let Some(cat) = classify_ignored_log_noise(file_name, &lower) {
            ignored_noise += 1;
            *noise_map.entry(cat).or_insert(0) += 1;
            continue;
        }
        let effective_ts = line_ts.as_deref().or(last_seen_ts.as_deref());
        let cur_secs = effective_ts.and_then(parse_naive_secs);
        let near_disconnect = match (last_disconnect_secs, cur_secs) {
            (Some(prev), Some(now)) => (now - prev).abs() <= 15,
            _ => false,
        };
        if lower.contains("beforequit")
            || lower.contains("onquitcleanup")
            || lower.contains("flusheventqueue")
        {
            if near_disconnect {
                in_quit_after_disconnect = true;
            }
        }

        if let Some(mut ev) = parse_log_line_with_fallback_ts(
            file_name,
            idx + 1,
            line,
            last_seen_ts.as_deref(),
        ) {
            if ev.tag == "网络断连" {
                last_disconnect_secs = cur_secs;
                in_quit_after_disconnect = false;
            } else if ev.tag == "带凭证 403" && (in_quit_after_disconnect || near_disconnect) {
                ev.tag = "退出回传 403".into();
                ev.level = "fail".into();
                ev.rule_id = Some("pb_exit".into());
                ev.title = "断连瞬间退出清理触发带 Cookie 403 回传（高危）".into();
                ev.cause = "触发归因：底层代理刚发生断连（ERR_CONNECTION_RESET / 1006）15 秒内即执行退出清理（onQuitCleanup / flushEventQueue），将本地 Cookie 裸连或异常路由打到 Anthropic 触发 403。处理建议：开启「运行中自动 4 层热熔断」，严禁在断网/关代理时手动关闭 Claude 窗口。".into();
            }
            events.push(ev);
        }
    }

    if events.len() > max_events {
        events = events.split_off(events.len() - max_events);
    }
    events.reverse();
    let tz_warn = detect_timezone_jump_in_text(text);
    (events, ignored_noise, noise_map, tz_warn)
}

/// 窗口级日志扫描（含断连瞬间退出回传 Cookie 403 上下文关联、噪音计数与时区跳变检测）
pub fn scan_log_text_with_context(
    file_name: &str,
    text: &str,
    max_events: usize,
) -> (Vec<LogEvent>, usize, Option<String>) {
    let (events, ignored_noise, _map, tz_warn) =
        scan_log_text_with_context_detailed(file_name, text, max_events);
    (events, ignored_noise, tz_warn)
}

/// 从指定文件尾部增量解析日志事件（最多读取尾部 512KB，毫秒级返回）
pub fn scan_log_file_tail(path: &Path, max_events: usize) -> Vec<LogEvent> {
    scan_log_file_tail_with_meta(path, max_events).0
}

fn scan_log_file_tail_with_meta(
    path: &Path,
    max_events: usize,
) -> (Vec<LogEvent>, usize, std::collections::BTreeMap<&'static str, usize>, Option<String>) {
    let Ok(mut file) = File::open(path) else {
        return (Vec::new(), 0, std::collections::BTreeMap::new(), None);
    };
    let Ok(meta) = file.metadata() else {
        return (Vec::new(), 0, std::collections::BTreeMap::new(), None);
    };
    let len = meta.len();
    let max_bytes = 512 * 1024u64;
    let start_offset = len.saturating_sub(max_bytes);
    if start_offset > 0 {
        let _ = file.seek(SeekFrom::Start(start_offset));
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).is_err() {
        return (Vec::new(), 0, std::collections::BTreeMap::new(), None);
    }
    let text = String::from_utf8_lossy(&buf);
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "main.log".into());

    scan_log_text_with_context_detailed(&file_name, &text, max_events)
}

/// T-201：60 秒内同一文件完全相同 tag + title 的连续刷屏异常/风险折叠合并（显示 ×N 及行号范围）
pub fn collapse_repeated_events(events: Vec<LogEvent>) -> Vec<LogEvent> {
    let mut out: Vec<LogEvent> = Vec::with_capacity(events.len());
    for mut ev in events {
        if ev.collapsed_ids.is_empty() {
            ev.collapsed_ids.push(ev.id.clone());
        }
        if !ev.anomaly || ev.simulated {
            out.push(ev);
            continue;
        }
        let base_file = ev.file.split(':').next().unwrap_or(&ev.file).to_string();
        let cur_secs = parse_naive_secs(&ev.time);

        let merged = out.iter_mut().find(|prev| {
            if !prev.anomaly || prev.simulated {
                return false;
            }
            if prev.tag != ev.tag || prev.title != ev.title {
                return false;
            }
            let prev_file = prev.file.split(':').next().unwrap_or(&prev.file);
            if prev_file != base_file {
                return false;
            }
            match (parse_naive_secs(&prev.time), cur_secs) {
                (Some(t1), Some(t2)) => (t1 - t2).abs() <= 60,
                _ => false,
            }
        });

        if let Some(prev) = merged {
            prev.repeat_count = prev.repeat_count.saturating_add(ev.repeat_count.max(1));
            for cid in ev.collapsed_ids {
                if !prev.collapsed_ids.contains(&cid) {
                    prev.collapsed_ids.push(cid);
                }
            }
            let min_line = prev.line.min(ev.line);
            let max_line = prev
                .file
                .split('~')
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(prev.line)
                .max(ev.line);
            prev.line = min_line;
            prev.file = format!("{base_file}:{min_line} ~ {max_line} (共 {} 次)", prev.repeat_count);
            if !prev.context.contains("60 秒内同类重复") {
                prev.context = format!(
                    "{}\n...（60 秒内同类重复 {} 次，合并行号范围：{} ~ {}）",
                    prev.context, prev.repeat_count, min_line, max_line
                );
            } else if let Some(first_line) = prev.context.lines().next() {
                prev.context = format!(
                    "{first_line}\n...（60 秒内同类重复 {} 次，合并行号范围：{} ~ {}）",
                    prev.repeat_count, min_line, max_line
                );
            }
        } else {
            out.push(ev);
        }
    }
    out
}

/// T-301：构建 72h 封号前置 6 维行为归因快照（纯匿名、不含任何明文 orgId/邮箱/Token/IP）
pub fn build_ban_attribution_snapshot(
    events: &[LogEvent],
    acct_audit: &AccountLogAudit,
    tz_jump_warning: Option<&str>,
    exit_region_code: &str,
    node_drift_warn: bool,
    kill_switch_active: bool,
) -> BanAttributionSnapshot {
    let disconnect_count = events
        .iter()
        .filter(|e| e.tag == "网络断连")
        .map(|e| e.repeat_count.max(1))
        .sum::<usize>();
    let disconnect_to_quit_403_count = events
        .iter()
        .filter(|e| e.tag == "退出回传 403")
        .map(|e| e.repeat_count.max(1))
        .sum::<usize>();
    let cookie_403_count = events
        .iter()
        .filter(|e| e.tag == "带凭证 403")
        .map(|e| e.repeat_count.max(1))
        .sum::<usize>();
    let rate_limit_429_count = events
        .iter()
        .filter(|e| e.tag == "高并发 429" && !e.simulated)
        .map(|e| e.repeat_count.max(1))
        .sum::<usize>();
    let plan_changed_detected = events.iter().any(|e| e.tag == "套餐变更");
    let cf_403_shield_count = events
        .iter()
        .filter(|e| e.tag == "网页 403 盾")
        .map(|e| e.repeat_count.max(1))
        .sum::<usize>();
    let region_unavailable_count = events
        .iter()
        .filter(|e| e.tag == "地区封锁")
        .map(|e| e.repeat_count.max(1))
        .sum::<usize>();
    let cross_org_race_detected = !acct_audit.cross_account_hits.is_empty()
        || events.iter().any(|e| e.tag == "账号连坐");
    let tz_jump_detected = tz_jump_warning.is_some();

    let mut top_risk_factors: Vec<String> = Vec::new();
    let mut clue_parts: Vec<String> = Vec::new();

    if cross_org_race_detected
        || (acct_audit.unique_org_ids.len() >= 2 && !acct_audit.restricted_org_ids.is_empty())
    {
        top_risk_factors.push("cross_org_ban_evasion".into());
        clue_parts.push(format!(
            "观测到 {} 个独立 orgHash（含受限号/跨号竞态）",
            acct_audit.unique_org_ids.len().max(2)
        ));
    } else if acct_audit.unique_org_ids.len() >= 2 {
        top_risk_factors.push("multi_org_same_machine".into());
        clue_parts.push(format!("同机观测到 {} 个独立 orgHash", acct_audit.unique_org_ids.len()));
    }
    if disconnect_to_quit_403_count > 0 || cookie_403_count > 0 {
        top_risk_factors.push("disconnect_quit_leak".into());
        clue_parts.push(format!(
            "断连退出/带 Cookie 403 共 {} 次",
            disconnect_to_quit_403_count + cookie_403_count
        ));
    }
    if region_unavailable_count > 0 || cf_403_shield_count > 0 || node_drift_warn {
        top_risk_factors.push("dirty_ip_or_geo_jump".into());
        clue_parts.push(format!(
            "地区/弹盾/漂移线索（区域 {}，弹盾 {} 次）",
            if exit_region_code.is_empty() { "GL" } else { exit_region_code },
            cf_403_shield_count
        ));
    }
    if rate_limit_429_count > 0 || plan_changed_detected {
        top_risk_factors.push("post_billing_or_burst_429".into());
        clue_parts.push(format!(
            "并发 429 {} 次{}",
            rate_limit_429_count,
            if plan_changed_detected { " + 近期套餐变更" } else { "" }
        ));
    }
    if tz_jump_detected {
        top_risk_factors.push("env_tz_jump".into());
        clue_parts.push("检测到系统时区剧烈跳变".into());
    }

    let summary_line = if clue_parts.is_empty() {
        String::new()
    } else {
        format!("72h 前置线索：{}", clue_parts.join(" · "))
    };

    BanAttributionSnapshot {
        schema_version: 2,
        generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        unique_org_hash_count: acct_audit.unique_org_ids.len(),
        restricted_org_hash_count: acct_audit.restricted_org_ids.len(),
        cross_org_race_detected,
        account_change_count: acct_audit.account_change_count,
        disconnect_count,
        disconnect_to_quit_403_count,
        cookie_403_count,
        rate_limit_429_count,
        plan_changed_detected,
        cf_403_shield_count,
        region_unavailable_count,
        tz_jump_detected,
        exit_region_code: exit_region_code.to_string(),
        node_drift_warn,
        kill_switch_active,
        top_risk_factors,
        summary_line,
    }
}

/// 扫描全部已知日志并按异常置顶排序 + 60s 同类折叠 + 已读游标过滤 + 分级统计摘要
pub fn collect_log_analysis_with_acked(
    extra_events: &[LogEvent],
    acked_ids: &[String],
) -> (Vec<LogEvent>, LogStats) {
    let files = discover_claude_log_files();
    let mut all: Vec<LogEvent> = extra_events.to_vec();
    let mut ignored_noise_count = 0usize;
    let mut noise_totals: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    let mut timezone_jump_warning: Option<String> = None;

    for f in &files {
        let (evs, noise, nmap, tz_warn) = scan_log_file_tail_with_meta(f, 40);
        all.extend(evs);
        ignored_noise_count = ignored_noise_count.saturating_add(noise);
        for (k, v) in nmap {
            *noise_totals.entry(k).or_insert(0) += v;
        }
        if timezone_jump_warning.is_none() && tz_warn.is_some() {
            timezone_jump_warning = tz_warn;
        }
    }

    // 异常置顶，其次按时间倒序，再执行 60 秒同类刷屏折叠
    all.sort_by(|a, b| b.anomaly.cmp(&a.anomaly).then_with(|| b.time.cmp(&a.time)));
    all = collapse_repeated_events(all);
    all.truncate(80);

    // 标记持久化已读状态：当条目自身 ID 或其全部折叠原始 ID 均在已读集合中时视为已读
    let ack_set: std::collections::HashSet<&str> = acked_ids.iter().map(|s| s.as_str()).collect();
    for ev in &mut all {
        if !ev.anomaly {
            ev.acked = false;
            continue;
        }
        let all_collapsed_acked = if ev.collapsed_ids.is_empty() {
            ack_set.contains(ev.id.as_str())
        } else {
            ev.collapsed_ids.iter().all(|cid| ack_set.contains(cid.as_str()))
        };
        ev.acked = ack_set.contains(ev.id.as_str()) || all_collapsed_acked;
    }

    // T-301：仅当存在未读高危异常（level == "fail"）时才按需计算 72h 前置线索，避免日常扫盘重复读 2MB
    let has_unread_fail = all.iter().any(|e| e.anomaly && !e.acked && e.level == "fail");
    if has_unread_fail {
        let acct_audit = audit_claude_logs_for_accounts();
        let attr = build_ban_attribution_snapshot(
            &all,
            &acct_audit,
            timezone_jump_warning.as_deref(),
            "",
            false,
            false,
        );
        if !attr.summary_line.is_empty() {
            for ev in &mut all {
                if ev.anomaly && ev.level == "fail" {
                    ev.attribution_clue = Some(attr.summary_line.clone());
                }
            }
        }
    }

    // T-202：严格按未读状态分开统计高危异常（fail）与风险提醒（warn）
    let critical_count = all
        .iter()
        .filter(|e| e.anomaly && !e.acked && e.level == "fail")
        .count();
    let warning_count = all
        .iter()
        .filter(|e| e.anomaly && !e.acked && e.level == "warn")
        .count();
    let total_anomalies = critical_count + warning_count;

    let region_or_rate_count = all
        .iter()
        .filter(|e| {
            matches!(
                e.tag.as_str(),
                "地区封锁"
                    | "高并发 429"
                    | "账号封禁"
                    | "账号连坐"
                    | "验证受限"
                    | "带凭证 403"
                    | "退出回传 403"
                    | "身份验证/权限"
                    | "OAuth v2 鉴权"
            )
        })
        .count();
    let disconnect_count = all.iter().filter(|e| e.tag == "网络断连").count();
    let telemetry_or_device_count = all
        .iter()
        .filter(|e| matches!(e.tag.as_str(), "遥测" | "设备采集"))
        .count();

    let mut ignored_noise_breakdown: Vec<NoiseCategoryCount> = noise_totals
        .into_iter()
        .filter(|(_, c)| *c > 0)
        .map(|(label, count)| NoiseCategoryCount {
            label: label.to_string(),
            count,
        })
        .collect();
    ignored_noise_breakdown.sort_by(|a, b| b.count.cmp(&a.count));

    let stats = LogStats {
        total_anomalies,
        critical_count,
        warning_count,
        region_or_rate_count,
        disconnect_count,
        telemetry_or_device_count,
        watching_files: files
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect(),
        ignored_noise_count,
        ignored_noise_breakdown,
        timezone_jump_warning,
    };

    (all, stats)
}

/// 兼容旧签名的日志分析汇总入口（不含已读过滤）
pub fn collect_log_analysis(extra_events: &[LogEvent]) -> (Vec<LogEvent>, LogStats) {
    collect_log_analysis_with_acked(extra_events, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn does_not_false_positive_pid_containing_429() {
        let normal = "2026-11-24 01:21:56 [info] [windows-app-job] first child process 14292 is in the job";
        assert!(parse_log_line("main.log", 625, normal).is_none());
    }

    #[test]
    fn parses_all_critical_ban_and_rate_limit_signals() {
        let e1 = parse_log_line(
            "main.log",
            44299,
            r#"2026-11-22 00:55:00 [error] {"error_code":"region_unavailable"}"#,
        )
        .unwrap();
        assert!(e1.anomaly);
        assert_eq!(e1.rule_id.as_deref(), Some("pb_exit"));
        assert_eq!(e1.tag, "地区封锁");

        let e2 = parse_log_line(
            "main.log",
            57151,
            "2026-11-23 13:00:24 [warn] sessionKey names a different account than flow orgId=7aacf131 (404)",
        )
        .unwrap();
        assert!(e2.anomaly);
        assert_eq!(e2.rule_id.as_deref(), Some("pb_pay"));

        let e3 = parse_log_line(
            "main.log",
            57688,
            "2026-11-23 18:10:02 [warn] HTTP 429 rate_limit_error (active sideSessions=4)",
        )
        .unwrap();
        assert!(e3.anomaly);
        assert_eq!(e3.rule_id.as_deref(), Some("pb_rate"));
        assert_eq!(e3.level, "warn");

        // 1) len=164 为 Persona KYC 身份验证或无有效订阅权限，归类为 warn「身份验证/权限」，绝不误判为封号
        let e4 = parse_log_line(
            "main.log",
            2270,
            "2026-11-24 01:42:49 [info] oauth failed: authorize returned 403 <json error=permission_error len=164>",
        )
        .unwrap();
        assert!(e4.anomaly);
        assert_eq!(e4.level, "warn");
        assert_eq!(e4.tag, "身份验证/权限");
        assert_eq!(e4.rule_id.as_deref(), Some("pb_pay"));

        let e5 = parse_log_line(
            "main.log",
            2271,
            "2026-11-24 01:42:49 [info] [oauth-v2] fresh exchange failed for orgId=11111111-2222-4333-8444-555555555555 (auth_error)",
        )
        .unwrap();
        assert!(e5.anomaly);
        assert_eq!(e5.level, "warn");
        assert_eq!(e5.tag, "OAuth v2 鉴权");
        assert!(!e5.title.contains("403 权限被拒"));
        assert!(!e5.cause.contains("len=164"));

        // 1b) session_stale_relogin 同样归类为 warn「OAuth v2 鉴权」
        let e5b = parse_log_line(
            "main.log",
            2272,
            "2026-11-24 01:43:00 [info] [oauth-v2] fresh exchange failed for orgId=11111111 (session_stale_relogin)",
        )
        .unwrap();
        assert_eq!(e5b.tag, "OAuth v2 鉴权");
        assert_eq!(e5b.level, "warn");

        // 2) len=130 / OAuth token revoked / account_banned 必须精准归类为 fail「账号封禁」
        let e6 = parse_log_line(
            "main.log",
            56272,
            "2026-11-23 12:54:05 [error] oauth failed: authorize returned 403 <json error=permission_error len=130> OAuth token revoked",
        )
        .unwrap();
        assert!(e6.anomaly);
        assert_eq!(e6.level, "fail");
        assert_eq!(e6.tag, "账号封禁");

        // 3) 官方过载 529、额度不足、未登录分别给出清晰 warn 归因
        let e7 = parse_log_line(
            "main.log",
            60001,
            "2026-11-24 10:10:00 [warn] Anthropic API overloaded_error status=529",
        )
        .unwrap();
        assert_eq!(e7.tag, "官方过载");
        assert_eq!(e7.level, "warn");

        let e8 = parse_log_line(
            "main.log",
            60002,
            "2026-11-24 10:11:00 [warn] Your credit balance is too low to access the API",
        )
        .unwrap();
        assert_eq!(e8.tag, "额度不足");
        assert_eq!(e8.level, "warn");
    }

    #[test]
    fn scans_mock_log_file_with_anomalies_sorted() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("main.log");
        fs::write(
            &p,
            "2026-11-23 10:00:00 [info] flushEventQueue ok\n2026-11-23 10:01:00 [error] HTTP 429 rate_limit_error\n",
        )
        .unwrap();
        let events = scan_log_file_tail(&p, 20);
        assert_eq!(events.len(), 2);
        assert!(events.iter().any(|e| e.rule_id.as_deref() == Some("pb_rate")));
    }

    #[test]
    fn v023_log_rules_cover_portal_cookie_403_quit_correlation_noise_json_org_and_tz_jump() {
        // 1. Verification Portal 与永久封号严格区分
        let vp = parse_log_line(
            "main.log",
            10,
            "2026-11-07 10:15:00 [warn] User redirected to https://portal.anthropic.com/verify",
        )
        .unwrap();
        assert_eq!(vp.tag, "验证受限");
        assert_eq!(vp.level, "fail");
        assert!(vp.cause.contains("非确认永久封号") || vp.cause.contains("并非确认永久封号"));

        // 2. len=156 归入身份验证/权限（warn），绝不判永久封号
        let l156 = parse_log_line(
            "main.log",
            11,
            "2026-10-25 09:00:00 [warn] oauth authorize returned 403 permission_error len=156",
        )
        .unwrap();
        assert_eq!(l156.tag, "身份验证/权限");
        assert_eq!(l156.level, "warn");

        // 3. credential: none 不误判为高危封号；182 chars 带 Cookie 403 精准标红
        let none_403 = parse_log_line(
            "main.log",
            12,
            "2026-11-09 10:00:00 [warn] [my-access] 403 | credential: none | response: (withheld, 120 chars)",
        )
        .unwrap();
        assert!(!none_403.anomaly);
        assert_eq!(none_403.tag, "未登录 403");

        let cookie_182 = parse_log_line(
            "main.log",
            13,
            "2026-11-05 10:27:06 [error] [EventLogging] 403 | credential: cookie | response: (withheld, 182 chars)",
        )
        .unwrap();
        assert!(cookie_182.anomaly);
        assert_eq!(cookie_182.tag, "带凭证 403");
        assert!(cookie_182.title.contains("182 字符"));

        // 4. 正常 5-hour limit 归为非异常提示
        let lim5 = parse_log_line(
            "main.log",
            14,
            "2026-11-10 12:00:00 [info] You have hit your 5-hour limit",
        )
        .unwrap();
        assert!(!lim5.anomaly);
        assert_eq!(lim5.tag, "额度提示");

        // 5. 无关噪音必须过滤（第三方 503、合盖休眠、VM 缺失、chrome-native-host）
        assert!(parse_log_line(
            "custom3p-setup.log",
            1,
            "2026-11-05 10:00:00 [error] Bootstrap request failed: 503 Service Unavailable"
        )
        .is_none());
        assert!(parse_log_line(
            "main.log",
            2,
            "2026-11-05 10:01:00 [warn] net::ERR_NETWORK_IO_SUSPENDED"
        )
        .is_none());
        assert!(parse_log_line(
            "cowork_vm_node.log",
            3,
            "2026-11-05 10:02:00 [error] sessiondata.vhdx missing"
        )
        .is_none());

        // 6. 断连瞬间 15 秒内退出回传 Cookie 403 上下文关联升级
        let combined = concat!(
            "2026-11-05 10:26:59 [warn] net::ERR_CONNECTION_RESET\n",
            "2026-11-05 10:27:04 [info] onQuitCleanup: flushEventQueue started\n",
            "2026-11-05 10:27:06 [error] [EventLogging] 403 | credential: cookie | response: (withheld, 182 chars)\n",
            "2026-11-05 10:28:00 [warn] net::ERR_NETWORK_IO_SUSPENDED\n"
        );
        let (evs, noise, _) = scan_log_text_with_context("main.log", combined, 20);
        assert_eq!(noise, 1);
        assert!(
            evs.iter().any(|e| e.tag == "退出回传 403" && e.level == "fail"),
            "disconnect + quit + cookie 403 must merge into 退出回传 403"
        );

        // 7. JSON 双引号 orgId/accountId 与 URL ?org= 正则修复：避免 portal.anthropic.com/verify?org=B 错归前文 A
        let json_logs = concat!(
            "2026-10-25 09:00:00 [info] {\"organization_uuid\": \"ce65bc28-1111-2222-3333-444455556666\", \"accountId\": \"bbbb1111-2222-3333-4444-555566667777\"}\n",
            "2026-10-25 09:00:02 [warn] Navigating to https://portal.anthropic.com/verify?org=bce33885-1111-2222-3333-444455556666\n",
            "2026-11-05 10:00:00 [info] {\"orgId\": \"ce65bc28-1111-2222-3333-444455556666\", \"account_uuid\": \"aaaa1111-2222-3333-4444-555566667777\"}\n"
        );
        let mut audit = AccountLogAudit::default();
        audit_log_text_for_accounts(json_logs, &mut audit);
        assert_eq!(audit.unique_org_ids, vec!["ce65bc28", "bce33885"]);
        assert_eq!(audit.unique_account_ids, vec!["bbbb1111", "aaaa1111"]);
        assert_eq!(
            audit.restricted_org_ids,
            vec!["bce33885"],
            "Portal URL 中自带 ?org=bce33885 时必须精准归因给 bce33885，绝不可张冠李戴到前文 ce65bc28"
        );

        // 8. 历史时区跳变检测（UTC+8 -> UTC-7 跨 15h）
        // 2026-11-11 08:00:00 UTC = 1794384000000 ms => UTC+8 本地 16:00:00; UTC-7 本地 01:00:00
        let tz_log = concat!(
            "2026-11-11 16:00:00 [info] process_start_epoch_ms=1794384000000\n",
            "2026-11-11 01:00:00 [info] quit_epoch_ms=1794384000000\n"
        );
        let tz_warn = detect_timezone_jump_in_text(tz_log).expect("15h jump must be detected");
        assert!(tz_warn.contains("15 小时"));

        // 9. T-037：未登录状态（no sessionkey cookie found / authentication_error）必须识别为正常状态，不计为异常或风险
        let unauth_ev = parse_log_line(
            "main.log",
            99,
            "2026-11-24 15:45:00 [info] No sessionKey cookie found, redirecting to login",
        )
        .expect("unauth line should be recorded in all events");
        assert!(!unauth_ev.anomaly);
        assert_eq!(unauth_ev.level, "ok");
        assert_eq!(unauth_ev.tag, "未登录");
    }

    #[test]
    fn t201_collapse_repeated_events_and_t301_ban_attribution_snapshot() {
        let lines = [
            (72, "2026-11-25 04:47:42 [info] [oauth-v2] fresh exchange failed for orgId=11111111-2222-4333-8444-555555555555 (auth_error)"),
            (73, "2026-11-25 04:47:42 [info] [oauth-v2] fresh exchange failed for orgId=11111111-2222-4333-8444-555555555555 (auth_error)"),
            (334, "2026-11-25 04:47:45 [info] [oauth-v2] fresh exchange failed for orgId=11111111-2222-4333-8444-555555555555 (auth_error)"),
            (335, "2026-11-25 04:47:45 [info] [oauth-v2] fresh exchange failed for orgId=11111111-2222-4333-8444-555555555555 (auth_error)"),
            (336, "2026-11-25 04:47:45 [info] [oauth-v2] fresh exchange failed for orgId=11111111-2222-4333-8444-555555555555 (auth_error)"),
        ];
        let raw: Vec<LogEvent> = lines
            .into_iter()
            .rev()
            .filter_map(|(ln, txt)| parse_log_line("main.log", ln, txt))
            .collect();
        let collapsed = collapse_repeated_events(raw);
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].tag, "OAuth v2 鉴权");
        assert_eq!(collapsed[0].repeat_count, 5);
        // 稳定内容哈希按 (file_name, time, trimmed) 计算：5 行分布在 04:47:42 与 04:47:45 两个唯一时间戳
        assert_eq!(collapsed[0].collapsed_ids.len(), 2);
        assert!(collapsed[0].file.contains("72 ~ 336"));

        // 验证 72h 前置归因快照正确识别断连泄露 + 多号因子
        let quit_ev = parse_log_line(
            "main.log",
            418,
            "2026-11-25 04:51:12 [error] [EventLogging] 403 | credential: cookie | response: (withheld, 182 chars)",
        )
        .unwrap();
        let mut audit = AccountLogAudit::default();
        audit.unique_org_ids = vec!["org11111".into(), "org22222".into()];
        audit.restricted_org_ids = vec!["org11111".into()];
        let attr = build_ban_attribution_snapshot(&[quit_ev], &audit, None, "SG", true, false);
        assert!(attr.top_risk_factors.contains(&"cross_org_ban_evasion".to_string()));
        assert!(attr.top_risk_factors.contains(&"disconnect_quit_leak".to_string()));
        assert!(attr.top_risk_factors.contains(&"dirty_ip_or_geo_jump".to_string()));
        assert!(attr.summary_line.contains("72h 前置线索："));
    }

    #[test]
    fn batch1_p0_utf8_extract_timestamp_no_panic_and_stable_event_id_ignores_line_number() {
        // 中文/多字节 UTF-8 字符跨越第 19 字节边界时绝不能 Panic
        let zh_lines = [
            "中文日志前缀测试不会导致字节切片越界异常",
            "[2026-11-25 04:47:42] 正常方括号时间",
            "短中文",
            "😀😀😀😀😀😀😀😀",
        ];
        for l in zh_lines {
            let _ = parse_log_line("main.log", 1, l);
        }
        // 不同行号、相同文件与内容必须生成完全一致的稳定 ID（根除 >512KB 截断导致已读与去重漂移）
        let line = "2026-11-25 04:47:42 [error] oauth failed: authorize returned 403 <json error=permission_error len=130> OAuth token revoked";
        let ev_a = parse_log_line("main.log", 12, line).unwrap();
        let ev_b = parse_log_line("main.log", 9981, line).unwrap();
        assert_eq!(ev_a.id, ev_b.id);
        assert!(ev_a.id.starts_with("log-main.log-"));
    }

    #[test]
    fn t055_multiline_stack_without_timestamp_inherits_parent_ts_and_keeps_stable_id() {
        // 复现真实 Claude main.log 第 3239~3244 行多行堆栈（子行无行首时间戳）
        let sample = "\
2026-11-25 15:51:27 [error] [growthbook] network error: Error: net::ERR_CONNECTION_CLOSED
    at SimpleURLLoaderWrapper.<anonymous> (node:internal/electron/js2c/browser_init:4:32600)
    at SimpleURLLoaderWrapper.emit (node:events:514:28) {
  [stack]: [Getter/Setter],
  [message]: 'net::ERR_CONNECTION_CLOSED'
}
";
        let (evs_1, _, _) = scan_log_text_with_context("main.log", sample, 40);
        let collapsed_1 = collapse_repeated_events(evs_1);
        assert_eq!(
            collapsed_1.len(),
            1,
            "子行继承主报错行时间戳后应自动 60s 折叠为同一次断连事件，不拆出幽灵未读条目"
        );
        assert_eq!(collapsed_1[0].time, "2026-11-25 15:51:27");
        assert_eq!(collapsed_1[0].repeat_count, 2);

        // 即使整份文本完全没有时间戳，也不得使用 Local::now() 参与哈希导致 ID 漂移
        let orphan_line = "  [message]: 'net::ERR_CONNECTION_CLOSED'";
        let ev_o1 = parse_log_line("main.log", 5, orphan_line).expect("orphan parsed");
        let ev_o2 = parse_log_line("main.log", 99, orphan_line).expect("orphan parsed");
        assert_eq!(ev_o1.id, ev_o2.id);
        assert_eq!(ev_o1.time, "时间未知");
    }

    #[test]
    #[ignore = "实机只读验收：扫描本机真实 Claude 日志、验证 OAuth v2 拆分折叠与 72h 前置归因快照"]
    fn live_v027_real_machine_log_audit() {
        let (events, stats) = collect_log_analysis_with_acked(&[], &[]);
        println!("=== 本机真实日志扫描结果 ===");
        println!(
            "watching_files={:?}\ntotal_anomalies={} critical(异常)={} warning(风险)={} ignored_noise={}",
            stats.watching_files,
            stats.total_anomalies,
            stats.critical_count,
            stats.warning_count,
            stats.ignored_noise_count
        );
        for ev in events.iter().filter(|e| e.anomaly).take(10) {
            println!(
                "  [{} | {} | ×{}] {} | {} | clue={:?}",
                ev.level, ev.tag, ev.repeat_count, ev.file, ev.title, ev.attribution_clue
            );
        }
        let audit = audit_claude_logs_for_accounts();
        let attr = build_ban_attribution_snapshot(
            &events,
            &audit,
            stats.timezone_jump_warning.as_deref(),
            "AU",
            false,
            false,
        );
        println!(
            "=== 72h 封号前置归因快照 ===\n{}",
            serde_json::to_string_pretty(&attr).unwrap()
        );
    }
}
