use crate::mihomo::{discover_endpoint, is_blocked_node_name, mihomo_request, MihomoEndpoint};
use crate::process::{kill_claude_process_tree, resolve_claude_exe_path};
use crate::protocol::FD_ERR_KILL_SWITCH;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Command;

/// 增量 15：本工具写入的全部 Windows Defender 防火墙规则统一固定前缀
pub const FIREWALL_RULE_PREFIX: &str = "FDClaudeGuard_KillSwitch_";
pub const FIREWALL_RULE_NAME: &str = "FDClaudeGuard_KillSwitch_BlockOut";
pub const FIREWALL_WAKE_RULE_NAME: &str = "FDClaudeGuard_KillSwitch_WakeWindow";
pub const FIREWALL_PROBE_RULE_NAME: &str = "FDClaudeGuard_KillSwitch_Probe";
pub const FIREWALL_HELPER_TASK_NAME: &str = "FDClaudeGuard_FirewallHelper";
/// 兼容旧版本可能遗留的规则名，清理时一并清除
const LEGACY_FIREWALL_RULE_NAME: &str = "FDGuard_Block_Claude_Out";

/// 单条 Claude 实时连接流记录（来自 Mihomo GET /connections）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeConn {
    pub id: String,
    pub anomaly: bool,
    pub process: String,
    pub host: String,
    pub rule: String,
    pub chain: String,
    pub action: String,
    pub time: String,
    /// 建连 Unix 毫秒时间戳（由 Mihomo RFC3339 `start` 解析，供前端实时计算连接持续时长）
    #[serde(default)]
    pub started_at_ms: Option<i64>,
    pub bytes_label: String,
    /// 域名业务分类（core_api / web_chat / feature_flag / asset_cdn / kyc_verify / cf_shield / payment / telemetry / update_status / oauth / local_ip / unknown_new）
    #[serde(default)]
    pub domain_category: String,
    /// 紧凑中文用途徽标（如 "核心 API" / "主站与会话" / "功能开关" / "遥测 · 行为监控" / "未收录新域"）
    #[serde(default)]
    pub purpose_label: String,
    /// 一句话大白话用途说明（供实时连接副文与悬停解释）
    #[serde(default)]
    pub purpose_detail: String,
    /// 是否为仅靠 PROCESS-NAME 兜底发现的未收录新域名（方案 B 纯自动只读雷达，零用户配置）
    #[serde(default)]
    pub is_unlisted_domain: bool,
}

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

fn is_ip_or_local_host(host: &str) -> bool {
    let trimmed = host.trim().trim_matches(|c| c == '[' || c == ']');
    trimmed.is_empty()
        || trimmed == "unknown"
        || trimmed == "localhost"
        || trimmed.ends_with(".local")
        || trimmed.ends_with(".lan")
        || trimmed.parse::<std::net::IpAddr>().is_ok()
}

/// 区分每个 Claude 相关连接域名的具体用途（唯一真源），并自动识别未收录新域（方案 B 自动雷达）
pub fn classify_claude_domain_purpose(
    host_raw: &str,
    is_rejected: bool,
    via_claude_fixed: bool,
) -> (&'static str, &'static str, &'static str, bool) {
    let h = host_raw
        .trim()
        .split(':')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();

    // 1. 第 3 层第三方遥测与埋点域
    if host_matches_suffix(&h, "sentry.io") {
        return (
            "telemetry",
            "遥测 · 崩溃上报",
            "Sentry 错误堆栈与异常遥测上报（建议 REJECT 拦截）",
            false,
        );
    }
    if host_matches_suffix(&h, "browser-intake-datadoghq.com")
        || host_matches_suffix(&h, "datadoghq.com")
        || host_matches_suffix(&h, "datadoghq.eu")
    {
        return (
            "telemetry",
            "遥测 · 行为监控",
            "Datadog 客户端/网页指纹与性能事件上报（建议 REJECT 拦截）",
            false,
        );
    }
    if host_matches_suffix(&h, "statsigapi.net")
        || host_matches_suffix(&h, "statsig.com")
        || host_matches_suffix(&h, "statsigcdn.com")
        || host_matches_suffix(&h, "featureassets.org")
        || host_matches_suffix(&h, "prodregistryv2.org")
    {
        return (
            "telemetry",
            "遥测 · 埋点配置",
            "第三方 Statsig 通用埋点与事件上报（建议 REJECT 拦截）",
            false,
        );
    }
    if host_matches_suffix(&h, "intercom.io") || host_matches_suffix(&h, "intercomcdn.com") {
        return (
            "telemetry",
            "客服与追踪",
            "Intercom 在线客服组件与会话埋点（建议 REJECT 拦截）",
            false,
        );
    }
    if host_matches_suffix(&h, "segment.io")
        || host_matches_suffix(&h, "api.segment.com")
        || host_matches_suffix(&h, "honeycomb.io")
    {
        return (
            "telemetry",
            "遥测 · 链路追踪",
            "Segment / Honeycomb 事件追踪与埋点（建议 REJECT 拦截）",
            false,
        );
    }

    // 2. Anthropic / Claude 官方细分业务域
    if h == "statsig.anthropic.com" {
        return (
            "feature_flag",
            "功能开关",
            "Claude 模型列表、Artifacts 与新特性灰度开关（刻意保留不拦截）",
            false,
        );
    }
    if h == "api.anthropic.com" || h == "a-api.anthropic.com" || h.ends_with("-api.anthropic.com") {
        return (
            "core_api",
            "核心 API",
            "Anthropic 官方模型推理、桌面端与 Claude Code 核心接口",
            false,
        );
    }
    if h == "portal.anthropic.com" || host_matches_suffix(&h, "withpersona.com") {
        return (
            "kyc_verify",
            "KYC 身份核验",
            "Anthropic 风控复审与 Persona 身份验证接口（需与主站同节点）",
            false,
        );
    }
    if h == "status.anthropic.com" {
        return (
            "update_status",
            "官方状态页",
            "Anthropic 服务可用性与宕机公告监测接口",
            false,
        );
    }
    if h == "console.anthropic.com" || h == "platform.anthropic.com" {
        return (
            "core_api",
            "开发者控制台",
            "Anthropic API 密钥、额度与组织管理控制台",
            false,
        );
    }
    if h == "downloads.claude.ai"
        || h == "assets.claude.ai"
        || h == "s-cdn.anthropic.com"
        || h == "assets-proxy.anthropic.com"
        || host_matches_suffix(&h, "servd-anthropic-website.b-cdn.net")
        || host_matches_suffix(&h, "claudeusercontent.com")
    {
        return (
            "asset_cdn",
            "资源 / 沙箱",
            "Artifacts 沙箱预览、客户端更新包与官方静态资源分发",
            false,
        );
    }
    if host_matches_suffix(&h, "mail.anthropic.com") {
        return (
            "web_chat",
            "官方邮件验证",
            "Anthropic 官方登录验证邮件与账号安全链接跳转",
            false,
        );
    }
    if host_matches_suffix(&h, "claude.ai")
        || host_matches_suffix(&h, "claude.com")
        || host_matches_suffix(&h, "clau.de")
    {
        return (
            "web_chat",
            "主站与会话",
            "Claude 网页端 / 桌面端主界面、账号鉴权与对话通信",
            false,
        );
    }
    if host_matches_suffix(&h, "anthropic.com") || host_matches_suffix(&h, "anthropic.org") {
        return (
            "web_chat",
            "官方站点",
            "Anthropic 官方主站、文档与认证关联服务",
            false,
        );
    }

    // 3. 关联基础设施（人机盾 / 支付 / OAuth / 出口探测）
    if host_matches_suffix(&h, "challenges.cloudflare.com") {
        return (
            "cf_shield",
            "CF 人机盾",
            "Cloudflare Turnstile 人机校验（与主站同节点可避免反复弹盾）",
            false,
        );
    }
    if host_matches_suffix(&h, "stripe.com") || host_matches_suffix(&h, "stripe.network") {
        return (
            "payment",
            "Stripe 支付",
            "Pro / Max 订阅绑卡与扣款反欺诈校验接口",
            false,
        );
    }
    if host_matches_suffix(&h, "accounts.google.com") {
        return (
            "oauth",
            "Google 登录",
            "第三方 Google OAuth 授权登录认证",
            false,
        );
    }
    if host_matches_suffix(&h, "ip-api.com")
        || host_matches_suffix(&h, "ipapi.is")
        || host_matches_suffix(&h, "ipinfo.io")
    {
        return (
            "update_status",
            "出口 IP 探测",
            "本工具出口合规性与 IP 纯净度实时自检探针",
            false,
        );
    }

    // 4. 纯 IP 或局域网地址
    if is_ip_or_local_host(&h) {
        return (
            "local_ip",
            "直连 IP / 本地",
            "按 IP 直连或本机回环通信（无域名 SNI）",
            false,
        );
    }

    // 5. 未收录新域名自动雷达（Claude 进程发出但不在已知业务/遥测清单中的外部域名）
    if is_rejected {
        (
            "unknown_new",
            "未收录新域",
            "Claude 进程访问的未收录外部域名（当前已被规则拦截）",
            true,
        )
    } else if via_claude_fixed {
        (
            "unknown_new",
            "未收录新域",
            "Claude 进程访问的新外部域名，已由进程规则兜底走 Claude-Fixed",
            true,
        )
    } else {
        (
            "unknown_new",
            "未收录新域",
            "Claude 进程访问的新外部域名且未走 Claude-Fixed，请排查逃逸风险",
            true,
        )
    }
}

/// 4 层紧急防回传 / 防火墙熔断状态
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KillSwitchState {
    pub active: bool,
    pub rule_name: String,
    pub target_exe: Option<String>,
    pub firewall_applied: bool,
    pub claude_connections_closed: usize,
    pub killed_processes: u32,
    pub telemetry_cleared_bytes: u64,
    pub reason: String,
    pub updated_at: String,
}

impl Default for KillSwitchState {
    fn default() -> Self {
        Self {
            active: false,
            rule_name: FIREWALL_RULE_NAME.to_string(),
            target_exe: None,
            firewall_applied: false,
            claude_connections_closed: 0,
            killed_processes: 0,
            telemetry_cleared_bytes: 0,
            reason: String::new(),
            updated_at: String::new(),
        }
    }
}

fn is_browser_process_name(proc_name: &str) -> bool {
    let lower = proc_name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
            | "brave.exe"
            | "opera.exe"
            | "arc.exe"
            | "vivaldi.exe"
            | "chromium.exe"
            | "chrome"
            | "msedge"
            | "firefox"
    )
}

fn is_self_guard_process_name(proc_name: &str) -> bool {
    let lower = proc_name.trim().to_ascii_lowercase();
    lower.contains("fd-claude-guard")
        || lower.contains("fd claude guard")
        || lower.contains("fd_claude_guard")
}

/// 格式化并规范化实时连接展示的来源进程（严禁在进程为空时假冒为 "Claude"）
/// 返回 None 表示属于本安全启动器自身进程应予以剔除
pub fn format_resolved_connection_process(
    raw_proc: &str,
    resolved_proc: Option<&str>,
) -> Option<String> {
    let chosen = raw_proc
        .trim()
        .is_empty()
        .then_some(resolved_proc.unwrap_or("").trim())
        .unwrap_or(raw_proc.trim());

    if is_self_guard_process_name(chosen) {
        return None;
    }
    if chosen.is_empty() {
        return Some("网页端 / 系统连接".into());
    }
    if is_browser_process_name(chosen) && !chosen.contains("网页端") {
        return Some(format!("{chosen} (网页端)"));
    }
    Some(chosen.to_string())
}

/// Windows 原生零子进程端口反查 PID/进程名映射（仅读 GetExtendedTcpTable / GetExtendedUdpTable + Toolhelp32）
#[cfg(windows)]
pub fn build_local_port_process_map(
) -> (std::collections::HashMap<u16, String>, std::collections::HashMap<u16, String>) {
    use std::collections::HashMap;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, INVALID_HANDLE_VALUE, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut pid_names: HashMap<u32, String> = HashMap::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap != INVALID_HANDLE_VALUE && !snap.is_null() {
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    let exe = String::from_utf16_lossy(&entry.szExeFile[..len]);
                    if !exe.is_empty() {
                        pid_names.insert(entry.th32ProcessID, exe);
                    }
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
    }

    let mut tcp_map: HashMap<u16, String> = HashMap::new();
    unsafe {
        let mut size: u32 = 0;
        let rc0 = GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if (rc0 == ERROR_INSUFFICIENT_BUFFER || size > 0) && size >= 4 {
            let mut buf = vec![0u8; size as usize];
            let rc1 = GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if rc1 == NO_ERROR {
                let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                let rows_ptr = buf.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
                let max_fit = buf.len().saturating_sub(4) / row_size;
                for i in 0..count.min(max_fit) {
                    let row = std::ptr::read_unaligned(rows_ptr.add(i));
                    let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                    if port > 0 {
                        if let Some(name) = pid_names.get(&row.dwOwningPid) {
                            tcp_map.entry(port).or_insert_with(|| name.clone());
                        }
                    }
                }
            }
        }
    }

    let mut udp_map: HashMap<u16, String> = HashMap::new();
    unsafe {
        let mut size: u32 = 0;
        let rc0 = GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if (rc0 == ERROR_INSUFFICIENT_BUFFER || size > 0) && size >= 4 {
            let mut buf = vec![0u8; size as usize];
            let rc1 = GetExtendedUdpTable(
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                &mut size,
                0,
                AF_INET as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
            if rc1 == NO_ERROR {
                let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                let row_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
                let rows_ptr = buf.as_ptr().add(4) as *const MIB_UDPROW_OWNER_PID;
                let max_fit = buf.len().saturating_sub(4) / row_size;
                for i in 0..count.min(max_fit) {
                    let row = std::ptr::read_unaligned(rows_ptr.add(i));
                    let port = u16::from_be((row.dwLocalPort & 0xFFFF) as u16);
                    if port > 0 {
                        if let Some(name) = pid_names.get(&row.dwOwningPid) {
                            udp_map.entry(port).or_insert_with(|| name.clone());
                        }
                    }
                }
            }
        }
    }

    (tcp_map, udp_map)
}

#[cfg(not(windows))]
pub fn build_local_port_process_map(
) -> (std::collections::HashMap<u16, String>, std::collections::HashMap<u16, String>) {
    (
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
    )
}

/// 解析 Mihomo /connections JSON，筛选所有 Claude 相关或 Anthropic 域名连接并标记异常流量
pub fn parse_claude_connections(raw_json: &str) -> Vec<ClaudeConn> {
    let empty = std::collections::HashMap::new();
    parse_claude_connections_with_port_lookup(raw_json, &empty, &empty)
}

/// 带本机 TCP/UDP 源端口反查表的 Mihomo 连接解析器（解决 TUN 模式下 metadata.process 为空问题）
pub fn parse_claude_connections_with_port_lookup(
    raw_json: &str,
    tcp_port_procs: &std::collections::HashMap<u16, String>,
    udp_port_procs: &std::collections::HashMap<u16, String>,
) -> Vec<ClaudeConn> {
    let Ok(val) = serde_json::from_str::<Value>(raw_json) else {
        return Vec::new();
    };
    let Some(arr) = val.get("connections").and_then(|c| c.as_array()) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for item in arr {
        let id = item
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let meta = item.get("metadata").unwrap_or(&Value::Null);
        let raw_process = meta
            .get("process")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let network = meta
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("tcp");
        let src_port = meta
            .get("sourcePort")
            .and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse::<u16>().ok())
                    .or_else(|| v.as_u64().and_then(|n| u16::try_from(n).ok()))
            });
        let resolved_proc = if raw_process.trim().is_empty() {
            src_port.and_then(|p| {
                if network.eq_ignore_ascii_case("udp") {
                    udp_port_procs.get(&p).or_else(|| tcp_port_procs.get(&p))
                } else {
                    tcp_port_procs.get(&p).or_else(|| udp_port_procs.get(&p))
                }
            })
            .map(String::as_str)
        } else {
            None
        };
        let Some(process_display) = format_resolved_connection_process(raw_process, resolved_proc)
        else {
            // 排除本安全启动器自身进程发起的 NTP/自检/更新探测
            continue;
        };

        let host_raw = meta
            .get("host")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| meta.get("destinationIP").and_then(|v| v.as_str()))
            .unwrap_or("unknown");
        let port = meta
            .get("destinationPort")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let host = if port.is_empty() {
            host_raw.to_string()
        } else {
            format!("{host_raw}:{port}")
        };

        let effective_proc_for_match = resolved_proc.unwrap_or(raw_process);
        let lower_proc = effective_proc_for_match.to_lowercase();
        let lower_host = host.to_lowercase();
        let host_only = lower_host.split(':').next().unwrap_or(&lower_host);
        let is_claude_exclusive_domain = host_only == "anthropic.com"
            || host_only.ends_with(".anthropic.com")
            || host_only == "claude.ai"
            || host_only.ends_with(".claude.ai")
            || host_only == "claude.com"
            || host_only.ends_with(".claude.com")
            || host_only == "claudeusercontent.com"
            || host_only.ends_with(".claudeusercontent.com")
            || host_only == "anthropic.org"
            || host_only.ends_with(".anthropic.org")
            || host_only == "clau.de"
            || host_only.ends_with(".clau.de")
            || host_only == "servd-anthropic-website.b-cdn.net"
            || host_only.ends_with(".servd-anthropic-website.b-cdn.net");
        let is_kyc_domain = host_only == "withpersona.com" || host_only.ends_with(".withpersona.com");
        let is_claude_proc = lower_proc.contains("claude")
            || (lower_proc == "chrome-native-host.exe" && (is_claude_exclusive_domain || is_kyc_domain));

        let chains: Vec<String> = item
            .get("chains")
            .and_then(|c| c.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .rev()
                    .collect()
            })
            .unwrap_or_default();
        let via_claude_fixed = chains.iter().any(|c| c == "Claude-Fixed");
        let is_cf_or_stripe_on_claude = via_claude_fixed
            && (host_matches_suffix(host_only, "challenges.cloudflare.com")
                || host_matches_suffix(host_only, "stripe.com")
                || host_matches_suffix(host_only, "stripe.network"));
        let is_claude =
            is_claude_proc || is_claude_exclusive_domain || is_kyc_domain || is_cf_or_stripe_on_claude;

        if !is_claude {
            continue;
        }

        let rule = item
            .get("rule")
            .and_then(|v| v.as_str())
            .unwrap_or("MATCH")
            .to_string();
        let chain_str = chains.join(" → ");

        let is_rejected = chains
            .iter()
            .any(|c| c.eq_ignore_ascii_case("REJECT") || c.eq_ignore_ascii_case("REJECT-DROP"));
        let blocked_chain = chains
            .iter()
            .any(|c| is_blocked_node_name(c) || c.eq_ignore_ascii_case("DIRECT"));
        // 修复 E2：不仅检测 MATCH 脱组；对于 Claude 专属域/KYC/Claude 进程，即便命中机场自带 DOMAIN-SUFFIX 规则走向其他代理组也判定为脱组异常
        let escaped_claude_group = !is_rejected && !via_claude_fixed;
        let anomaly = blocked_chain || escaped_claude_group;
        let (domain_category, purpose_label, purpose_detail, is_unlisted_domain) =
            classify_claude_domain_purpose(host_raw, is_rejected, via_claude_fixed);

        let upload = item.get("upload").and_then(|v| v.as_u64()).unwrap_or(0);
        let download = item.get("download").and_then(|v| v.as_u64()).unwrap_or(0);
        let bytes_label = format_bytes(upload + download);
        let start_raw = item.get("start").and_then(|v| v.as_str()).unwrap_or("");
        let time = start_raw
            .get(11..19)
            .unwrap_or("--:--:--")
            .to_string();
        let started_at_ms = parse_rfc3339_start_ms(start_raw);

        out.push(ClaudeConn {
            id,
            anomaly,
            process: process_display,
            host,
            rule,
            chain: if chain_str.is_empty() {
                "DIRECT".into()
            } else {
                chain_str
            },
            action: if anomaly {
                "风险连接（建议立即掐断）".into()
            } else if is_rejected {
                "已拦截（防回传）".into()
            } else if is_unlisted_domain {
                "进程兜底放行".into()
            } else {
                "正常放行".into()
            },
            time,
            started_at_ms,
            bytes_label,
            domain_category: domain_category.into(),
            purpose_label: purpose_label.into(),
            purpose_detail: purpose_detail.into(),
            is_unlisted_domain,
        });
    }

    out.sort_by(|a, b| b.anomaly.cmp(&a.anomaly));
    out
}

/// 解析 Mihomo /connections 的 RFC3339 `start` 字段为 Unix 毫秒时间戳（解析失败返回 None，不 panic）
pub fn parse_rfc3339_start_ms(start_raw: &str) -> Option<i64> {
    let trimmed = start_raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(trimmed)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

/// 在已发现的 Mihomo 端点上实时拉取 Claude 相关连接（避免哨兵循环重复 discover_endpoint，并在 TUN 下反查真实来源进程）
pub async fn get_live_claude_connections_on(ep: &MihomoEndpoint) -> Vec<ClaudeConn> {
    let Ok((200, body)) = mihomo_request(ep, "GET", "/connections", None).await else {
        return Vec::new();
    };
    let (tcp_map, udp_map) = build_local_port_process_map();
    parse_claude_connections_with_port_lookup(&body, &tcp_map, &udp_map)
}

/// 实时拉取 Mihomo 中的 Claude 相关连接
pub async fn get_live_claude_connections() -> Vec<ClaudeConn> {
    let Some(ep) = discover_endpoint().await else {
        return Vec::new();
    };
    get_live_claude_connections_on(&ep).await
}

/// 毫秒级掐断指定连接 ID (`DELETE /connections/{id}`)
pub async fn close_mihomo_connection(id: &str) -> Result<(), String> {
    let ep = discover_endpoint()
        .await
        .ok_or_else(|| "未检测到在线的 Clash Verge Mihomo 实例".to_string())?;
    let path = format!("/connections/{}", urlencoding::encode(id));
    let (status, body) = mihomo_request(&ep, "DELETE", &path, None).await?;
    if status >= 200 && status < 300 {
        Ok(())
    } else {
        Err(format!("掐断连接失败 (HTTP {status}): {body}"))
    }
}

/// 执行 4 层紧急防回传与熔断（Clash 掐流 + 防火墙封死出站 + 强杀进程跳过 onQuitCleanup + 清离线遥测）
pub async fn trigger_four_layer_killswitch(
    reason: &str,
    anti_upload_flush: bool,
) -> KillSwitchState {
    let started = std::time::Instant::now();
    // 第 1A 层：复用单个 Mihomo 端点毫秒级强掐所有 Claude 连接（避免 N 次重复 discover_endpoint）
    let mut closed = 0usize;
    if let Some(ep) = discover_endpoint().await {
        let conns = get_live_claude_connections_on(&ep).await;
        for c in &conns {
            let path = format!("/connections/{}", urlencoding::encode(&c.id));
            if let Ok((status, _)) = mihomo_request(&ep, "DELETE", &path, None).await {
                if (200..300).contains(&status) {
                    closed += 1;
                }
            }
        }
    }

    // 第 1B 层：追踪 Claude.exe 并写入 Windows Defender 防火墙出站阻断规则
    let target_exe = resolve_claude_exe_path().map(|p| p.to_string_lossy().to_string());
    let firewall_applied = apply_defender_block_rule(FIREWALL_RULE_NAME, target_exe.as_deref());
    if firewall_applied {
        crate::rollback::mark_firewall_touched(false, true);
    }

    // 第 2 层：循环强杀 Claude 进程树确认彻底归 0（跳过 onQuitCleanup 丢弃内存事件队列）+ 清空离线遥测缓存
    let (killed_processes, telemetry_cleared_bytes) = if anti_upload_flush {
        let mut total_killed = 0u32;
        let mut total_cleared = 0u64;
        for attempt in 0..8 {
            let rep = kill_claude_process_tree(attempt == 0);
            total_killed = total_killed.saturating_add(rep.before_count.saturating_sub(rep.after_count));
            total_cleared = total_cleared.saturating_add(rep.telemetry_cleared_bytes);
            if crate::process::list_claude_processes().is_empty() {
                break;
            }
            if attempt < 7 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        }
        (total_killed, total_cleared)
    } else {
        (0, 0)
    };

    let final_reason = if firewall_applied {
        reason.to_string()
    } else {
        format!("{reason}（提示：当前未获取到防火墙写入权限 fw=false，请以管理员身份运行；已先执行掐流与强杀盯防）")
    };

    crate::rollback::invalidate_rollback_overview_cache();
    crate::logger::log_event(
        "WARN",
        "killswitch",
        "killswitch_triggered",
        Some(started.elapsed().as_millis() as u64),
        format!(
            "[{FD_ERR_KILL_SWITCH}] 触发 4 层熔断: {final_reason} | closed={closed} killed={killed_processes} fw={firewall_applied}"
        ),
        Some(serde_json::json!({
            "rule": FIREWALL_RULE_NAME,
            "firewallApplied": firewall_applied,
            "closedConnections": closed,
            "killedProcesses": killed_processes,
            "telemetryClearedBytes": telemetry_cleared_bytes
        })),
    );

    KillSwitchState {
        active: true,
        rule_name: FIREWALL_RULE_NAME.to_string(),
        target_exe,
        firewall_applied,
        claude_connections_closed: closed,
        killed_processes,
        telemetry_cleared_bytes,
        reason: final_reason,
        updated_at: chrono::Local::now().format("%H:%M:%S").to_string(),
    }
}

/// 增量 13：休眠唤醒 / 切网临时预阻断规则挂起与释放
pub fn set_wake_preblock_rule(enable: bool) -> bool {
    let target_exe = resolve_claude_exe_path().map(|p| p.to_string_lossy().to_string());
    if enable {
        apply_defender_block_rule(FIREWALL_WAKE_RULE_NAME, target_exe.as_deref())
    } else {
        remove_defender_rule_by_name(FIREWALL_WAKE_RULE_NAME)
    }
}

/// 按风险确认解除 Windows 防火墙阻断规则
pub fn release_killswitch(confirmed: bool, bg_procs: u32) -> Result<KillSwitchState, String> {
    if !confirmed {
        return Err("必须先二次确认风险才允许解除防火墙熔断。".into());
    }
    cleanup_all_guard_firewall_rules()?;
    let note = if bg_procs > 0 {
        format!("已强制解除熔断（注意：当前仍有 {bg_procs} 个 Claude 进程运行，请勿在禁区节点继续操作）")
    } else {
        format!("已解除防火墙熔断规则 {FIREWALL_RULE_PREFIX}*。")
    };

    crate::rollback::invalidate_rollback_overview_cache();
    crate::logger::log_event(
        "INFO",
        "killswitch",
        "killswitch_released",
        None,
        &note,
        Some(serde_json::json!({ "bgProcs": bg_procs })),
    );

    Ok(KillSwitchState {
        active: false,
        rule_name: FIREWALL_RULE_NAME.to_string(),
        target_exe: resolve_claude_exe_path().map(|p| p.to_string_lossy().to_string()),
        firewall_applied: false,
        claude_connections_closed: 0,
        killed_processes: 0,
        telemetry_cleared_bytes: 0,
        reason: note,
        updated_at: chrono::Local::now().format("%H:%M:%S").to_string(),
    })
}

/// 增量 15：清除本工具写入的全部 `FDClaudeGuard_KillSwitch_*` 防火墙规则（防自锁救援 + 退出自愈）
/// 删除后真实复查是否仍有规则残留，权限不足无法删除时如实返回错误绝不报假成功
pub fn cleanup_all_guard_firewall_rules() -> Result<String, String> {
    #[cfg(windows)]
    {
        for rule in [
            FIREWALL_RULE_NAME,
            FIREWALL_WAKE_RULE_NAME,
            FIREWALL_PROBE_RULE_NAME,
            LEGACY_FIREWALL_RULE_NAME,
        ] {
            let _ = remove_defender_rule_by_name(rule);
        }
        if has_active_guard_firewall_rules() {
            let msg = format!(
                "[{FD_ERR_KILL_SWITCH}] 检测到仍有 {FIREWALL_RULE_PREFIX}* 防火墙规则未能移除（当前权限不足），请以管理员身份运行本工具后重试。"
            );
            crate::logger::log_warn("killswitch", &msg);
            return Err(msg);
        }
    }
    crate::logger::log_event(
        "INFO",
        "killswitch",
        "firewall_cleanup_all",
        None,
        format!("已执行防自锁救援：清空全部 {FIREWALL_RULE_PREFIX}* 防火墙规则"),
        None,
    );
    Ok(format!(
        "已清空全部 {FIREWALL_RULE_PREFIX}* 防火墙规则，Claude 出站连接已彻底恢复放行。"
    ))
}

/// 快速检测当前系统是否存在任何活跃的 `FDClaudeGuard_KillSwitch_*` 阻断规则
/// 使用轻量 `netsh show rule`（约 30ms），彻底替代会阻塞主线程 3~4 秒的 PowerShell Get-NetFirewallRule
pub fn has_active_guard_firewall_rules() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        for rule in [
            FIREWALL_RULE_NAME,
            FIREWALL_WAKE_RULE_NAME,
            LEGACY_FIREWALL_RULE_NAME,
        ] {
            let exists = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args([
                    "advfirewall",
                    "firewall",
                    "show",
                    "rule",
                    &format!("name={rule}"),
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if exists {
                return true;
            }
        }
        false
    }
    #[cfg(not(windows))]
    {
        false
    }
}

static FW_HELPER_CACHE: std::sync::OnceLock<
    std::sync::Mutex<Option<(std::time::Instant, (bool, bool, String))>>,
> = std::sync::OnceLock::new();

/// 增量 16（opt_fw）：实测免 UAC 守护计划任务是否已安装且具备读写 FDClaudeGuard_KillSwitch_* 规则能力
/// 60 秒缓存复用结果，避免每轮体检重复向 Windows 防火墙增删探针规则（安装守护任务后自动失效缓存）
pub fn check_firewall_helper_ready() -> (bool, bool, String) {
    let lock = FW_HELPER_CACHE.get_or_init(|| std::sync::Mutex::new(None));
    if let Ok(guard) = lock.lock() {
        if let Some((ts, ref cached)) = *guard {
            if ts.elapsed() < std::time::Duration::from_secs(60) {
                return cached.clone();
            }
        }
    }
    let result = check_firewall_helper_ready_uncached();
    if let Ok(mut guard) = lock.lock() {
        *guard = Some((std::time::Instant::now(), result.clone()));
    }
    result
}

pub fn invalidate_firewall_helper_cache() {
    if let Some(lock) = FW_HELPER_CACHE.get() {
        if let Ok(mut guard) = lock.lock() {
            *guard = None;
        }
    }
}

fn check_firewall_helper_ready_uncached() -> (bool, bool, String) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let task_installed = Command::new("schtasks")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["/Query", "/TN", FIREWALL_HELPER_TASK_NAME])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        // 轻量实测读写一条临时探针规则后立即删除（验证当前权限是否可直接写 Defender 规则）
        let probe_add = Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={FIREWALL_PROBE_RULE_NAME}"),
                "dir=out",
                "action=allow",
                "enable=no",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if probe_add {
            let _ = remove_defender_rule_by_name(FIREWALL_PROBE_RULE_NAME);
        }

        let helper_status = if task_installed {
            "Active"
        } else if probe_add {
            "管理员直写就绪（无需额外任务）"
        } else {
            "Not Installed"
        };
        let detail = format!(
            "Elevated Helper Task: {helper_status}\nRule Probe ({FIREWALL_RULE_PREFIX}*): {}",
            if probe_add { "Writable" } else { "Requires Admin / Helper" }
        );
        (task_installed, probe_add, detail)
    }
    #[cfg(not(windows))]
    {
        (false, false, "Non-Windows environment".into())
    }
}

/// 增量 16（opt_fw）：以管理员提权注册免 UAC 守护计划任务并实测读写一条探针规则
pub fn install_firewall_helper_task() -> Result<String, String> {
    #[cfg(windows)]
    {
        let exe_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "fd-claude-guard.exe".into());
        invalidate_firewall_helper_cache();

        // 管理员态直跑、非管理员态经 UTF-16LE EncodedCommand 提权并逐条严格校验原生命令 $LASTEXITCODE
        let safe_exe = exe_path.replace('\'', "''");
        let inner_cmd = format!(
            "schtasks /Create /F /RL HIGHEST /SC ONEVENT /EC Application /MO '*[System[EventID=0]]' /TN '{FIREWALL_HELPER_TASK_NAME}' /TR '\"{safe_exe}\" --autostart'; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; netsh advfirewall firewall add rule name={FIREWALL_PROBE_RULE_NAME} dir=out action=allow enable=no; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}; netsh advfirewall firewall delete rule name={FIREWALL_PROBE_RULE_NAME}; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}"
        );
        match crate::rollback::run_ps_elevated_checked(&inner_cmd, "安装免 UAC 防火墙守护计划任务") {
            Ok(_) => {
                crate::rollback::mark_firewall_touched(true, false);
                Ok(format!(
                    "已完成免 UAC 守护计划任务 ({FIREWALL_HELPER_TASK_NAME}) 安装与规则读写探针验证。"
                ))
            }
            Err(err) => Err(format!(
                "[{FD_ERR_KILL_SWITCH}] 安装免 UAC 守护计划任务未完成: {err}"
            )),
        }
    }
    #[cfg(not(windows))]
    {
        Err("仅 Windows 支持防火墙计划任务安装".into())
    }
}

#[cfg(windows)]
fn apply_defender_block_rule(rule_name: &str, exe_path: Option<&str>) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let Some(program) = exe_path else {
        return false;
    };

    let _ = remove_defender_rule_by_name(rule_name);

    let out = Command::new("netsh")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={rule_name}"),
            "dir=out",
            "action=block",
            &format!("program={program}"),
            "enable=yes",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            crate::logger::log_warn(
                "killswitch",
                format!("netsh 写入防火墙规则失败 (rule={rule_name}, program={program}): stdout={msg} stderr={err}"),
            );
            false
        }
        Err(e) => {
            crate::logger::log_warn(
                "killswitch",
                format!("调用 netsh 失败 (rule={rule_name}): {e}"),
            );
            false
        }
    }
}

#[cfg(not(windows))]
fn apply_defender_block_rule(_rule_name: &str, _exe_path: Option<&str>) -> bool {
    false
}

#[cfg(windows)]
fn remove_defender_rule_by_name(rule_name: &str) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new("netsh")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={rule_name}"),
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn remove_defender_rule_by_name(_rule_name: &str) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_rule_names_use_unified_prefix() {
        assert!(FIREWALL_RULE_NAME.starts_with(FIREWALL_RULE_PREFIX));
        assert!(FIREWALL_WAKE_RULE_NAME.starts_with(FIREWALL_RULE_PREFIX));
        assert!(FIREWALL_PROBE_RULE_NAME.starts_with(FIREWALL_RULE_PREFIX));
        assert_eq!(FIREWALL_RULE_PREFIX, "FDClaudeGuard_KillSwitch_");
    }

    #[tokio::test]
    #[ignore = "真机管理员权限实测 Defender 防火墙熔断规则真实写入与防自锁彻底清除"]
    async fn live_firewall_killswitch_write_and_cleanup_audit() {
        let ks = trigger_four_layer_killswitch("v0.2.5 真机防火墙写入与防自锁验收", false).await;
        println!(
            "=== LIVE KILLSWITCH: active={} fw={} target={:?} ===",
            ks.active, ks.firewall_applied, ks.target_exe
        );
        assert!(ks.active, "killswitch must be active");
        assert!(ks.firewall_applied, "Defender firewall rule must apply (fw=true)");
        assert!(has_active_guard_firewall_rules(), "netsh must report active guard rule");

        let rel = release_killswitch(true, 0).expect("release_killswitch must succeed");
        assert!(!rel.active, "killswitch must be released");
        assert!(
            !has_active_guard_firewall_rules(),
            "all FDClaudeGuard_KillSwitch_* rules must be cleaned up (zero self-lock)"
        );
    }

    #[test]
    fn identifies_anomalous_and_normal_claude_connections() {
        let sample = r#"{
            "connections": [
                {
                    "id": "conn-1",
                    "upload": 0,
                    "download": 0,
                    "start": "2026-11-23T20:54:02Z",
                    "rule": "MATCH",
                    "chains": ["HK-Edge-03", "PROXY"],
                    "metadata": { "process": "Claude.exe", "host": "api.anthropic.com", "destinationPort": "443" }
                },
                {
                    "id": "conn-2",
                    "upload": 2048,
                    "download": 1048576,
                    "start": "2026-11-23T20:52:18Z",
                    "rule": "DOMAIN-SUFFIX",
                    "chains": ["US-LA-Static-01", "Claude-Fixed"],
                    "metadata": { "process": "Claude.exe", "host": "claude.ai", "destinationPort": "443" }
                },
                {
                    "id": "conn-3",
                    "upload": 100,
                    "download": 100,
                    "start": "2026-11-23T20:50:00Z",
                    "rule": "DIRECT",
                    "chains": ["DIRECT"],
                    "metadata": { "process": "chrome.exe", "host": "example.com", "destinationPort": "443" }
                }
            ]
        }"#;

        let conns = parse_claude_connections(sample);
        assert_eq!(conns.len(), 2);
        assert!(conns[0].anomaly);
        assert_eq!(conns[0].id, "conn-1");
        assert!(!conns[1].anomaly);
        assert_eq!(conns[1].id, "conn-2");
    }

    #[test]
    fn release_requires_explicit_confirmation() {
        assert!(release_killswitch(false, 0).is_err());
    }

    #[test]
    fn v035_e2_detects_escaped_claude_and_kyc_connections_even_on_non_match_rules() {
        let sample = r#"{
            "connections": [
                {
                    "id": "c-kyc-escaped",
                    "upload": 100,
                    "download": 200,
                    "start": "2026-11-26T10:00:00Z",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国2", "天悦云"],
                    "metadata": { "process": "chrome.exe", "host": "inquiry.withpersona.com", "destinationPort": "443" }
                },
                {
                    "id": "c-claude-short-escaped",
                    "upload": 100,
                    "download": 200,
                    "start": "2026-11-26T10:00:01Z",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国2", "天悦云"],
                    "metadata": { "process": "chrome.exe", "host": "clau.de", "destinationPort": "443" }
                },
                {
                    "id": "c-ok",
                    "upload": 100,
                    "download": 200,
                    "start": "2026-11-26T10:00:02Z",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国1", "Claude-Fixed"],
                    "metadata": { "process": "chrome-native-host.exe", "host": "api.anthropic.com", "destinationPort": "443" }
                },
                {
                    "id": "c-rejected-telemetry",
                    "upload": 0,
                    "download": 0,
                    "start": "2026-11-26T10:00:03Z",
                    "rule": "DomainSuffix",
                    "chains": ["REJECT"],
                    "metadata": { "process": "Claude.exe", "host": "browser-intake-datadoghq.com", "destinationPort": "443" }
                }
            ]
        }"#;
        let conns = parse_claude_connections(sample);
        let by_id = |id: &str| conns.iter().find(|c| c.id == id).unwrap();
        assert!(by_id("c-kyc-escaped").anomaly, "KYC 域命中机场规则走非 Claude-Fixed 必须标异常");
        assert!(by_id("c-claude-short-escaped").anomaly, "clau.de 走非 Claude-Fixed 必须标异常");
        assert!(!by_id("c-ok").anomaly, "走 Claude-Fixed 的正常连接不得误报");
        assert!(!by_id("c-rejected-telemetry").anomaly, "已被 REJECT 拦截的遥测连接不得误报为异常放行");
        assert_eq!(by_id("c-kyc-escaped").purpose_label, "KYC 身份核验");
        assert_eq!(by_id("c-ok").purpose_label, "核心 API");
        assert_eq!(by_id("c-rejected-telemetry").purpose_label, "遥测 · 行为监控");
        assert_eq!(by_id("c-rejected-telemetry").action, "已拦截（防回传）");
    }

    #[test]
    fn v035_classifies_claude_domain_purposes_and_flags_unlisted_new_domains() {
        let sample = r#"{
            "connections": [
                {
                    "id": "c-flag",
                    "upload": 10,
                    "download": 20,
                    "start": "2026-11-26T10:10:00Z",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国1", "Claude-Fixed"],
                    "metadata": { "process": "Claude.exe", "host": "statsig.anthropic.com", "destinationPort": "443" }
                },
                {
                    "id": "c-cdn",
                    "upload": 10,
                    "download": 20,
                    "start": "2026-11-26T10:10:01Z",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国1", "Claude-Fixed"],
                    "metadata": { "process": "Claude.exe", "host": "downloads.claude.ai", "destinationPort": "443" }
                },
                {
                    "id": "c-cf",
                    "upload": 10,
                    "download": 20,
                    "start": "2026-11-26T10:10:02Z",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国1", "Claude-Fixed"],
                    "metadata": { "process": "chrome.exe", "host": "challenges.cloudflare.com", "destinationPort": "443" }
                },
                {
                    "id": "c-new-domain",
                    "upload": 10,
                    "download": 20,
                    "start": "2026-11-26T10:10:03Z",
                    "rule": "Process",
                    "chains": ["🇺🇸美国1", "Claude-Fixed"],
                    "metadata": { "process": "Claude.exe", "host": "new-agent-relay.anthropic-labs.dev", "destinationPort": "443" }
                },
                {
                    "id": "c-self-ntp",
                    "upload": 48,
                    "download": 48,
                    "start": "2026-11-26T10:10:04Z",
                    "rule": "Match",
                    "chains": ["🇺🇸美国1", "天悦云"],
                    "metadata": { "process": "fd-claude-guard.exe", "host": "time.cloudflare.com", "destinationPort": "123" }
                },
                {
                    "id": "c-mail",
                    "upload": 10,
                    "download": 20,
                    "start": "2026-11-26T10:10:05Z",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国1", "Claude-Fixed"],
                    "metadata": { "process": "Claude.exe", "host": "url8792.mail.anthropic.com", "destinationPort": "443" }
                }
            ]
        }"#;
        let conns = parse_claude_connections(sample);
        let by_id = |id: &str| conns.iter().find(|c| c.id == id).unwrap();

        assert_eq!(by_id("c-flag").purpose_label, "功能开关");
        assert!(!by_id("c-flag").is_unlisted_domain);

        assert_eq!(by_id("c-cdn").purpose_label, "资源 / 沙箱");
        assert!(!by_id("c-cdn").is_unlisted_domain);

        assert_eq!(by_id("c-cf").purpose_label, "CF 人机盾");
        assert!(!by_id("c-cf").is_unlisted_domain);

        assert_eq!(by_id("c-mail").purpose_label, "官方邮件验证");
        assert!(
            conns.iter().all(|c| c.id != "c-self-ntp"),
            "E8 回归：本安全启动器自身进程发起的 NTP 探测绝不得误报为 Claude 风险连接"
        );

        let new_c = by_id("c-new-domain");
        assert!(!new_c.anomaly, "已被 PROCESS-NAME 锁在 Claude-Fixed 的未收录新域不应判为高危异常");
        assert!(new_c.is_unlisted_domain, "未知新域名必须自动触发未收录新域雷达");
        assert_eq!(new_c.purpose_label, "未收录新域");
        assert!(new_c.action.contains("进程兜底"));
    }

    #[test]
    fn v036_parses_rfc3339_start_timestamp_to_ms() {
        // 标准 UTC Z 格式（2026-11-26T10:10:00Z）
        let utc_ms = parse_rfc3339_start_ms("2026-11-26T10:10:00Z");
        assert_eq!(utc_ms, Some(1_795_687_800_000));
        // 带 9 位纳秒小数与 +08:00 时区偏移（与 UTC 10:10:00.123 相同瞬时）
        assert_eq!(
            parse_rfc3339_start_ms("2026-11-26T18:10:00.123456789+08:00"),
            Some(1_795_687_800_123)
        );
        // 畸形或空字符串优雅返回 None
        assert_eq!(parse_rfc3339_start_ms(""), None);
        assert_eq!(parse_rfc3339_start_ms("not-a-timestamp"), None);

        // 端到端 parse_claude_connections 验证 started_at_ms 同步产出且保留向后兼容 time 字段
        let sample = r#"{
            "connections": [
                {
                    "id": "c-ts-1",
                    "upload": 64,
                    "download": 128,
                    "start": "2026-11-26T18:10:05.500123456+08:00",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国1", "Claude-Fixed"],
                    "metadata": { "process": "Claude.exe", "host": "api.anthropic.com", "destinationPort": "443" }
                }
            ]
        }"#;
        let conns = parse_claude_connections(sample);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].time, "18:10:05");
        assert_eq!(conns[0].started_at_ms, Some(1_795_687_805_500));
    }

    #[tokio::test]
    #[ignore = "真机只读实测：直连本机 Mihomo 管道拉取 /connections 并验证真实连接域名用途分类"]
    async fn live_v035_real_mihomo_connections_purpose_audit() {
        let ep = discover_endpoint().await.expect("本机 Clash Verge Mihomo 必须在线");
        let (status, raw) = mihomo_request(&ep, "GET", "/connections", None)
            .await
            .expect("GET /connections 必须成功");
        assert_eq!(status, 200);
        let raw_val: Value = serde_json::from_str(&raw).expect("valid connections json");
        let total_all = raw_val
            .get("connections")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let claude_conns = parse_claude_connections(&raw);
        println!(
            "=== LIVE MIHOMO /connections: endpoint={} total_all={} claude_matched={} ===",
            ep.display_label(),
            total_all,
            claude_conns.len()
        );
        for c in &claude_conns {
            println!(
                "  [anom={} unlisted={}] {} -> {} | {} ({}) | rule={} | chain={} | action={}",
                c.anomaly,
                c.is_unlisted_domain,
                c.process,
                c.host,
                c.purpose_label,
                c.domain_category,
                c.rule,
                c.chain,
                c.action
            );
            assert!(!c.purpose_label.is_empty(), "每条真实连接必须产出明确用途标签");
            assert!(!c.purpose_detail.is_empty(), "每条真实连接必须产出中文用途说明");
        }
    }

    #[test]
    fn v041_b6_resolves_empty_tun_process_via_port_lookup_and_never_fakes_claude() {
        let mut tcp = std::collections::HashMap::new();
        tcp.insert(51989u16, "chrome.exe".to_string());
        tcp.insert(52001u16, "fd-claude-guard.exe".to_string());
        let udp = std::collections::HashMap::new();

        let sample = r#"{
            "connections": [
                {
                    "id": "c-browser",
                    "upload": 5332,
                    "download": 2873,
                    "start": "2026-11-27T08:42:42.7916916-07:00",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国1|流媒体AI", "Claude-Fixed"],
                    "metadata": { "network": "tcp", "sourcePort": "51989", "process": "", "host": "claude.ai", "destinationPort": "443" }
                },
                {
                    "id": "c-closed",
                    "upload": 100,
                    "download": 200,
                    "start": "2026-11-27T08:42:45Z",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国1|流媒体AI", "Claude-Fixed"],
                    "metadata": { "network": "tcp", "sourcePort": "59999", "process": "", "host": "claude.ai", "destinationPort": "443" }
                },
                {
                    "id": "c-self",
                    "upload": 10,
                    "download": 10,
                    "start": "2026-11-27T08:42:46Z",
                    "rule": "DomainSuffix",
                    "chains": ["🇺🇸美国1|流媒体AI", "Claude-Fixed"],
                    "metadata": { "network": "tcp", "sourcePort": "52001", "process": "", "host": "api.anthropic.com", "destinationPort": "443" }
                }
            ]
        }"#;

        let conns = parse_claude_connections_with_port_lookup(sample, &tcp, &udp);
        assert_eq!(conns.len(), 2, "本工具自身端口连接应被剔除");
        let browser = conns.iter().find(|c| c.id == "c-browser").unwrap();
        assert_eq!(browser.process, "chrome.exe (网页端)");
        let closed = conns.iter().find(|c| c.id == "c-closed").unwrap();
        assert_eq!(closed.process, "网页端 / 系统连接");
        assert_ne!(closed.process, "Claude");
    }
}
