use crate::config::AppConfig;
use crate::maintenance::backup_and_clean_claude_dirs;
use crate::mihomo::{
    clash_verge_config_dir, discover_endpoint, extract_proxy_group, extract_region_code,
    fetch_configs, fetch_proxies_raw, fetch_rules_raw, fetch_version, is_blocked_country,
    is_blocked_node_name, patch_clash_mode_rule, patch_ipv6_disabled, patch_tun_enabled,
    reload_config_via_payload, select_proxy_in_group, verify_claude_rules, verify_exit_probe_rules,
    MihomoConfigs, MihomoEndpoint,
};
use crate::protocol::{
    FD_ERR_IPV6_LEAK, FD_ERR_LOG_POLLUTE, FD_ERR_PROXY_OFFLINE, FD_ERR_RULE_DRIFT,
    FULL_AUDIT_INTERVAL_MS,
};
use crate::startup_audit::audit_windows_startup_items;
use crate::state::{
    now_epoch_ms, CheckPart, CheckStatus, GuardSnapshot, HudEventLine, PreflightItem,
    PreflightReport,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixResult {
    pub item_id: String,
    pub success: bool,
    pub requires_manual_step: bool,
    pub message: String,
    pub report: PreflightReport,
    pub snapshot: GuardSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchFixResult {
    pub fixed_ids: Vec<String>,
    pub skipped_manual_id: Option<String>,
    pub summary: String,
    pub report: PreflightReport,
    pub snapshot: GuardSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnthropicServiceStatus {
    pub indicator: String,
    pub description: String,
}

pub struct PreflightBundle {
    pub report: PreflightReport,
    pub snapshot: GuardSnapshot,
    /// 本次实测检测到的脱敏出口 IP 签名（供持久化记录历史落地 IP 基线）
    pub detected_landing_sig: Option<String>,
    /// 本次检测到的主号 orgId 前缀
    pub detected_org_id: Option<String>,
}

pub fn is_fake_ip_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 198 && (o[1] == 18 || o[1] == 19)
}

pub fn mask_ip_address(ip: &str) -> String {
    let trimmed = ip.trim();
    if let Ok(v4) = trimmed.parse::<Ipv4Addr>() {
        let o = v4.octets();
        return format!("{}.{}.xx.xx", o[0], o[1]);
    }
    if trimmed.contains(':') {
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() >= 2 {
            return format!("{}:{}:****", parts[0], parts[1]);
        }
    }
    trimmed.to_string()
}

pub fn is_third_party_base_url(raw: &str) -> bool {
    let v = raw.trim().to_lowercase();
    if v.is_empty() {
        return false;
    }
    let normalized = v
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");
    !matches!(normalized, "api.anthropic.com" | "claude.ai" | "api.claude.ai")
}

pub fn merge_claude_privacy_settings(existing_json: Option<&str>) -> Result<String, String> {
    let mut root: Value = match existing_json {
        Some(raw) if !raw.trim().is_empty() => {
            serde_json::from_str(raw).map_err(|e| format!("解析现有 settings.json 失败: {e}"))?
        }
        _ => json!({}),
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
    let env_map = env_val.as_object_mut().expect("env object");
    env_map.insert(
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".to_string(),
        Value::String("1".to_string()),
    );
    env_map.insert(
        "DISABLE_ERROR_REPORTING".to_string(),
        Value::String("1".to_string()),
    );

    serde_json::to_string_pretty(&root).map_err(|e| format!("序列化 settings.json 失败: {e}"))
}

/// 精准扫描本地 Claude 日志中的「确认封禁 / 强制吊销 / 地区封锁」污染残留
/// 注：len=164（Persona 身份验证 KYC 或尚未开通付费订阅权限）绝不当作封号污染红灯！
pub fn scan_text_for_ban_contamination(text: &str) -> Vec<&'static str> {
    let lower = text.to_lowercase();
    let mut hits = Vec::new();
    let simple = [
        ("account_banned", "account_banned"),
        ("account_suspended", "account_suspended"),
        ("organization_disabled", "organization_disabled"),
        ("region_unavailable", "region_unavailable"),
        ("ban_evasion", "ban_evasion"),
        ("oauth token revoked", "oauth_token_revoked"),
        ("400 invalid_grant", "oauth_invalid_grant"),
    ];
    for (pat, label) in simple {
        if lower.contains(pat) {
            hits.push(label);
        }
    }
    if lower.contains("a live token was expired early") && lower.contains("forced_renewal") {
        hits.push("forced_token_revocation");
    }
    // 依据真实取证日志：封号强吊为 permission_error len=130/len=123；而 len=164 为身份验证(KYC)/未订阅，不计为封号污染
    if lower.contains("permission_error") && (lower.contains("len=130") || lower.contains("len=123"))
    {
        hits.push("oauth_403_revoked_permission");
    }
    hits
}

/// 检测本地日志中是否存在「需身份验证(KYC)/无有效订阅权限(len=164)」提醒记录（仅温和提示，绝不阻断控制台）
pub fn scan_text_for_kyc_or_perm_notice(text: &str) -> bool {
    let lower = text.to_lowercase();
    (lower.contains("permission_error") && lower.contains("len=164"))
        || (lower.contains("fresh exchange failed") && lower.contains("auth_error"))
}

pub fn parse_ntp_drift_seconds(packet: &[u8], now_unix_secs: f64) -> Result<f64, String> {
    if packet.len() < 48 {
        return Err("SNTP 响应包不足 48 字节".to_string());
    }
    let secs = u32::from_be_bytes([packet[40], packet[41], packet[42], packet[43]]) as f64;
    let frac = u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]) as f64;
    if secs < 2_208_988_800.0 {
        return Err("SNTP 返回无效时间戳".to_string());
    }
    let ntp_unix = (secs - 2_208_988_800.0) + (frac / 4_294_967_296.0);
    Ok(now_unix_secs - ntp_unix)
}

/// 将 Anthropic Statuspage 英文状态描述统一映射为清晰简体中文
pub fn translate_anthropic_status_zh(indicator: &str, raw_desc: &str) -> String {
    let trimmed = raw_desc.trim();
    if trimmed.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)) {
        return trimmed.to_string();
    }
    let lower = trimmed.to_lowercase();
    if lower.contains("all systems operational") {
        return "全部服务正常".into();
    }
    if lower.contains("partially degraded") || lower.contains("degraded") {
        return "部分服务降级".into();
    }
    if lower.contains("minor service outage") || lower.contains("minor") {
        return "轻微服务波动".into();
    }
    if lower.contains("partial system outage") || lower.contains("partial") {
        return "部分服务中断".into();
    }
    if lower.contains("major service outage") || lower.contains("major") || lower.contains("critical") {
        return "重大服务故障".into();
    }
    if lower.contains("maintenance") {
        return "系统维护中".into();
    }
    match indicator.to_ascii_lowercase().as_str() {
        "none" => "全部服务正常".into(),
        "minor" => "部分服务降级".into(),
        "major" => "部分服务中断".into(),
        "critical" => "重大服务故障".into(),
        _ => "官方状态暂未响应".into(),
    }
}

/// 增量 5：实时拉取 Anthropic 官方状态页 API，区分官方宕机/529 与本地风控
pub async fn fetch_anthropic_official_status(mixed_port: Option<u16>) -> AnthropicServiceStatus {
    let builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .user_agent("FD-Claude-Guard/0.1");

    let client = match mixed_port {
        Some(port) => {
            if let Ok(proxy) = reqwest::Proxy::all(format!("http://127.0.0.1:{port}")) {
                builder.proxy(proxy).build().ok()
            } else {
                None
            }
        }
        None => None,
    }
    .or_else(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .user_agent("FD-Claude-Guard/0.1")
            .build()
            .ok()
    });

    let Some(c) = client else {
        return AnthropicServiceStatus {
            indicator: "unknown".into(),
            description: "状态探测初始化失败".into(),
        };
    };

    if let Ok(resp) = c
        .get("https://status.anthropic.com/api/v2/summary.json")
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<Value>().await {
                let indicator = val
                    .get("status")
                    .and_then(|s| s.get("indicator"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("none")
                    .to_string();
                let desc = val
                    .get("status")
                    .and_then(|s| s.get("description"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("All Systems Operational");
                return AnthropicServiceStatus {
                    description: translate_anthropic_status_zh(&indicator, desc),
                    indicator,
                };
            }
        }
    }

    AnthropicServiceStatus {
        indicator: "unknown".into(),
        description: "官方状态页暂未响应".into(),
    }
}

/// 并行执行全部两级三大纯粹操作边界真实探针（11 项必须 + 6 项建议，共 17 项）
pub async fn run_all_preflight_checks(cfg: &AppConfig, bg_claude_procs: u32) -> PreflightBundle {
    let total_start = std::time::Instant::now();
    let endpoint = discover_endpoint().await;
    crate::logger::log_event(
        "INFO",
        "preflight",
        "preflight_start",
        None,
        format!(
            "开始执行 17 项真实探针（11必须+6建议） | mihomo_endpoint={} | bg_claude_procs={bg_claude_procs}",
            endpoint
                .as_ref()
                .map(|e| e.display_label())
                .unwrap_or_else(|| "NONE".into())
        ),
        Some(serde_json::json!({ "bgClaudeProcs": bg_claude_procs })),
    );

    // 命名管道请求串行执行（单次 <3ms），避免 Windows ERROR_PIPE_BUSY
    let (version_res, configs_res, proxies_res, rules_res) = match &endpoint {
        Some(ep) => {
            let v = fetch_version(ep).await;
            let c = fetch_configs(ep).await;
            let p = fetch_proxies_raw(ep).await;
            let r = fetch_rules_raw(ep).await;
            (v, c, p, r)
        }
        None => (
            Err(format!("[{FD_ERR_PROXY_OFFLINE}] 未发现 Clash Verge Mihomo 命名管道")),
            Err("未连接 Mihomo".into()),
            Err("未连接 Mihomo".into()),
            Err("未连接 Mihomo".into()),
        ),
    };

    let mihomo_cfg = configs_res.as_ref().ok().cloned();
    let mixed_port = mihomo_cfg.as_ref().map(|c| c.mixed_port).unwrap_or(7890);
    let clash_version = version_res
        .as_ref()
        .map(|v| format!("Mihomo {}", v.version))
        .unwrap_or_else(|_| "未在线".into());

    let (item_proxy, clash_online) =
        probe_proxy_and_ports(endpoint.as_ref(), &clash_version, mixed_port).await;

    let (item_group, current_node, group_ok, node_is_blocked) = probe_group_and_rules(
        proxies_res.as_ref().ok(),
        rules_res.as_ref().ok(),
        mihomo_cfg.as_ref(),
        cfg.locked_node_for_ip.as_deref(),
    );

    let (
        item_tun,
        item_dns,
        (
            item_geo,
            exit_ip_masked,
            exit_latency_ms,
            exit_latency_label,
            geo_country,
            geo_blocked,
            landing_sig,
            landing_drifted,
            cf_blocked,
        ),
        item_ipv6,
        (item_sys_env, oauth_triggered),
        item_location,
        (item_ban, ban_triggered),
        (item_acct, acct_conflict, detected_org_id),
        item_tel,
        (item_boot, boot_risk),
        item_ntp,
        item_fw,
        item_webrtc,
        item_browser_ext,
        anthropic_status,
    ) = tokio::join!(
        probe_tun_adapter(mihomo_cfg.as_ref()),
        probe_dns_fake_ip(mihomo_cfg.as_ref()),
        probe_exit_geo(mixed_port, clash_online, group_ok, &current_node, cfg),
        probe_ipv6_windows_only(),
        probe_system_proxy_and_env(mixed_port),
        probe_windows_location_privacy(),
        probe_local_ban_contamination(),
        probe_single_account_lock(cfg.bound_primary_org_id.as_deref()),
        probe_claude_privacy_settings(),
        async {
            let audit = audit_windows_startup_items(cfg.boot_start);
            let item = build_startup_item(&audit);
            (item, audit.claude_autostart_risk)
        },
        probe_ntp_drift(),
        probe_firewall_ready(),
        probe_browser_webrtc_policy(),
        probe_browser_proxy_extensions(),
        fetch_anthropic_official_status(if clash_online { Some(mixed_port) } else { None }),
    );

    let effective_region_for_tz = if !geo_country.is_empty() {
        geo_country.clone()
    } else {
        extract_region_code(&current_node)
    };
    let item_tz = probe_system_timezone_consistency(&effective_region_for_tz);

    // 严格按「修改对象」三大纯粹边界排序：改 Clash(5) + 改系统(3) + 改 Claude(3) + 建议优化(6)
    let items = vec![
        item_proxy,
        item_group,
        item_tun,
        item_dns,
        item_geo,
        item_ipv6,
        item_sys_env,
        item_location,
        item_ban,
        item_acct,
        item_tel,
        item_boot,
        item_ntp,
        item_fw,
        item_webrtc,
        item_tz,
        item_browser_ext,
    ];

    let must_all: Vec<&PreflightItem> = items.iter().filter(|i| i.part == CheckPart::Must).collect();
    let must_passed = must_all.iter().filter(|i| i.status == CheckStatus::Ok).count() as u32;
    let must_total = must_all.len() as u32;
    let opt_all: Vec<&PreflightItem> = items.iter().filter(|i| i.part == CheckPart::Opt).collect();
    let opt_passed = opt_all.iter().filter(|i| i.status == CheckStatus::Ok).count() as u32;
    let opt_total = opt_all.len() as u32;
    let must_fail = must_total.saturating_sub(must_passed);

    let mut triggered_playbook_ids = Vec::new();
    if cfg.calm_24h {
        triggered_playbook_ids.push("pb_24h".to_string());
    }
    if oauth_triggered {
        triggered_playbook_ids.push("pb_oauth".to_string());
    }
    if ban_triggered || acct_conflict {
        triggered_playbook_ids.push("pb_pay".to_string());
    }
    if boot_risk {
        triggered_playbook_ids.push("pb_boot".to_string());
    }
    if node_is_blocked || geo_blocked || cf_blocked {
        triggered_playbook_ids.push("pb_node".to_string());
    }

    let now = chrono::Local::now().format("%H:%M").to_string();
    let is_danger = node_is_blocked || geo_blocked || cf_blocked;
    let health_level = if is_danger {
        "danger"
    } else if must_fail > 0 || landing_drifted {
        "warn"
    } else {
        "ok"
    }
    .to_string();

    let status_label = if cf_blocked {
        "节点 CF 403 拉黑".to_string()
    } else if is_danger {
        "检测到禁区风险".to_string()
    } else if must_fail > 0 {
        format!("{must_fail} 项待办")
    } else if landing_drifted {
        "落地 IP 静默漂移".to_string()
    } else {
        "守护正常".to_string()
    };

    let region_code = if !geo_country.is_empty() {
        geo_country
    } else {
        extract_region_code(&current_node)
    };

    let mut hud_events = Vec::new();
    if cf_blocked {
        hud_events.push(HudEventLine {
            message: "当前节点被 Cloudflare 403 拉黑，请前往节点流量重选".into(),
            time: now.clone(),
            level: "danger".into(),
            target_tab: "nodes".into(),
        });
    } else if is_danger {
        hud_events.push(HudEventLine {
            message: format!("[{FD_ERR_RULE_DRIFT}] 出口或节点落入禁区，禁止启动 Claude"),
            time: now.clone(),
            level: "danger".into(),
            target_tab: "console".into(),
        });
    } else if must_fail > 0 {
        hud_events.push(HudEventLine {
            message: format!("启动前体检 {must_passed}/{must_total}，还有 {must_fail} 项待处理"),
            time: now.clone(),
            level: "warn".into(),
            target_tab: "console".into(),
        });
    } else {
        hud_events.push(HudEventLine {
            message: format!("{must_total} 项启动前真实探针与卫生检查全部通过"),
            time: now.clone(),
            level: "ok".into(),
            target_tab: "console".into(),
        });
    }

    if landing_drifted {
        hud_events.push(HudEventLine {
            message: format!("预警：节点名未变但落地 IP 发生静默漂移（{exit_ip_masked}）"),
            time: now.clone(),
            level: "warn".into(),
            target_tab: "console".into(),
        });
    } else if anthropic_status.indicator != "none" && anthropic_status.indicator != "unknown" {
        hud_events.push(HudEventLine {
            message: format!("Anthropic 官方状态异常：{}", anthropic_status.description),
            time: now.clone(),
            level: "warn".into(),
            target_tab: "logs".into(),
        });
    } else if boot_risk {
        hud_events.push(HudEventLine {
            message: "开机监测：Claude 设了自启，留意抢跑裸奔风险".into(),
            time: now.clone(),
            level: "warn".into(),
            target_tab: "config".into(),
        });
    } else if !group_ok {
        hud_events.push(HudEventLine {
            message: "尚未锁定 Claude-Fixed 策略组，请前往控制台处理".into(),
            time: now.clone(),
            level: "warn".into(),
            target_tab: "console".into(),
        });
    } else {
        hud_events.push(HudEventLine {
            message: format!("锁定节点 {current_node} · {exit_ip_masked}"),
            time: now.clone(),
            level: "ok".into(),
            target_tab: "nodes".into(),
        });
    }

    // 同步计算三方唯一真源：节点真正不可用 (node_down) vs 节点漂移风险 (node_drift_warn) vs 真实实时连接拦截数 (live_flow_anomalies)
    let geo_failed = items
        .iter()
        .any(|i| i.id == "node_geo" && i.status == CheckStatus::Fail);
    let node_unusable_now = geo_failed || node_is_blocked || geo_blocked || cf_blocked;
    let node_has_issue = node_unusable_now || landing_drifted;
    let live_flow_anomalies = if clash_online {
        crate::killswitch::get_live_claude_connections()
            .await
            .into_iter()
            .filter(|c| c.anomaly)
            .count()
    } else {
        0
    };

    let snapshot = GuardSnapshot {
        health_level,
        status_label,
        current_node,
        region_code,
        exit_ip_masked,
        latency_ms: exit_latency_ms,
        latency_label: exit_latency_label,
        bg_claude_procs,
        kill_switch_active: false,
        kill_hold_active: false,
        kill_hold_remaining_secs: 0,
        kill_hold_blocked_count: 0,
        kill_hold_tx_locked: false,
        kill_hold_reason: String::new(),
        node_down: node_unusable_now,
        node_drift_warn: landing_drifted,
        must_passed,
        must_total,
        opt_passed,
        opt_total,
        clash_version,
        clash_port: mixed_port,
        clash_online,
        anthropic_status_indicator: anthropic_status.indicator,
        anthropic_status_desc: anthropic_status.description,
        unread_log_anomalies: 0,
        unread_log_critical: 0,
        unread_log_warnings: 0,
        active_flow_anomalies: live_flow_anomalies + usize::from(node_has_issue),
        live_flow_anomalies,
        next_full_audit_epoch_ms: now_epoch_ms() + FULL_AUDIT_INTERVAL_MS,
        triggered_playbook_ids,
        hud_events,
    };

    let report = PreflightReport {
        checked_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        stage: "v1.6".to_string(),
        items,
    };

    let failed_ids: Vec<&str> = report
        .items
        .iter()
        .filter(|i| i.part == CheckPart::Must && i.status != CheckStatus::Ok)
        .map(|i| i.id.as_str())
        .collect();
    let elapsed_ms = total_start.elapsed().as_millis() as u64;
    crate::logger::log_event(
        "INFO",
        "preflight",
        "preflight_done",
        Some(elapsed_ms),
        format!(
            "{} 项真实探针完成 ({elapsed_ms}ms) | must={}/{} | opt={}/{} | node={} ({}) | ip={} | status={} | failed_must={:?}",
            report.items.len(),
            snapshot.must_passed,
            snapshot.must_total,
            snapshot.opt_passed,
            snapshot.opt_total,
            snapshot.current_node,
            snapshot.region_code,
            snapshot.exit_ip_masked,
            snapshot.anthropic_status_indicator,
            failed_ids
        ),
        Some(serde_json::json!({
            "mustPassed": snapshot.must_passed,
            "mustTotal": snapshot.must_total,
            "optPassed": snapshot.opt_passed,
            "optTotal": snapshot.opt_total,
            "region": snapshot.region_code,
            "landingDrifted": landing_drifted,
            "cfBlocked": cf_blocked,
            "failedMust": failed_ids
        })),
    );

    PreflightBundle {
        report,
        snapshot,
        detected_landing_sig: landing_sig,
        detected_org_id,
    }
}

async fn probe_proxy_and_ports(
    endpoint: Option<&MihomoEndpoint>,
    clash_version: &str,
    mixed_port: u16,
) -> (PreflightItem, bool) {
    let port_open = tokio::task::spawn_blocking(move || {
        TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], mixed_port)),
            Duration::from_millis(450),
        )
        .is_ok()
    })
    .await
    .unwrap_or(false);

    let conflict_ports = tokio::task::spawn_blocking(move || {
        let candidates = [12334u16, 10808, 10809, 7897];
        candidates
            .into_iter()
            .filter(|&p| p != mixed_port)
            .filter(|&p| {
                TcpStream::connect_timeout(
                    &SocketAddr::from(([127, 0, 0, 1], p)),
                    Duration::from_millis(200),
                )
                .is_ok()
            })
            .collect::<Vec<u16>>()
    })
    .await
    .unwrap_or_default();

    let ep_str = endpoint
        .map(|e| e.display_label())
        .unwrap_or_else(|| format!("[{FD_ERR_PROXY_OFFLINE}] 未检测到 Mihomo 管道或控制端口"));

    let online = endpoint.is_some() && port_open;
    let passed = online && conflict_ports.is_empty();

    let summary = if passed {
        format!("Clash Verge ({mixed_port}) 在线，未发现 12334 等冲突代理")
    } else if !online {
        format!("[{FD_ERR_PROXY_OFFLINE}] 未检测到 Clash Verge Mihomo 存活或本地混合代理端口未监听")
    } else {
        format!("检测到冲突代理端口监听：{conflict_ports:?}，可能与 {mixed_port} 争夺路由")
    };

    let evidence = format!(
        "Endpoint: {ep_str}\nKernel: {clash_version}\nPort {mixed_port}: {} | Conflict Ports: {}",
        if port_open { "Online" } else { "Offline" },
        if conflict_ports.is_empty() {
            "0".into()
        } else {
            format!("{conflict_ports:?}")
        }
    );

    let item = PreflightItem {
        id: "node_proxy".into(),
        part: CheckPart::Must,
        cat: "1. 代理与节点（改 Clash 配置）".into(),
        icon: "proxy".into(),
        mode: "自动一键".into(),
        title: "代理引擎在线与端口独占".into(),
        status: if passed {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        },
        summary,
        evidence,
        guide: if passed {
            "探针已直连 Mihomo 命名管道并确认代理端口独占无冲突。".into()
        } else {
            "仅检测 Mihomo 命名管道存活与代理端口独占；请先启动 Clash Verge Rev 并关闭 12334 / 10808 / 7897 等冲突代理。".into()
        },
        fix_label: if passed {
            None
        } else {
            Some("启动 / 重启 Clash Verge 并探测端口状态".into())
        },
        is_kill_item: false,
        is_failover: false,
    };

    (item, online)
}

fn probe_group_and_rules(
    proxies: Option<&std::collections::HashMap<String, Value>>,
    rules: Option<&Vec<Value>>,
    mihomo_cfg: Option<&MihomoConfigs>,
    _locked_baseline_node: Option<&str>,
) -> (PreflightItem, String, bool, bool) {
    let mihomo_ipv6_off = mihomo_cfg.map(|c| !c.ipv6).unwrap_or(false);
    let clash_mode = mihomo_cfg
        .map(|c| c.mode.to_ascii_lowercase())
        .unwrap_or_else(|| "rule".to_string());
    let Some(proxies_map) = proxies else {
        return (
            PreflightItem {
                id: "node_group".into(),
                part: CheckPart::Must,
                cat: "1. 代理与节点（改 Clash 配置）".into(),
                icon: "group".into(),
                mode: "向导 + 实测验收".into(),
                title: "策略组与全家桶规则锁死".into(),
                status: CheckStatus::Fail,
                summary: format!("[{FD_ERR_PROXY_OFFLINE}] 无法连接 Mihomo 查询策略组与规则表"),
                evidence: format!("Mihomo GET /proxies: Offline ({FD_ERR_PROXY_OFFLINE})"),
                guide: "仅操作 Clash 覆写配置；请先确保 Clash Verge 在线后再检查或写入 Claude-Fixed 覆写脚本。".into(),
                fix_label: Some("写入 Script.js 覆写脚本并实测验收".into()),
                is_kill_item: false,
                is_failover: false,
            },
            "未连接".into(),
            false,
            false,
        );
    };

    let group = extract_proxy_group(proxies_map, "Claude-Fixed");
    let global_group = extract_proxy_group(proxies_map, "GLOBAL");
    let global_now = global_group
        .as_ref()
        .map(|g| g.now.as_str())
        .unwrap_or("");
    let (rules_ok, rule_count) = rules.map(|r| verify_claude_rules(r)).unwrap_or((false, 0));
    let exit_probe_rule_ok = rules.map(|r| verify_exit_probe_rules(r)).unwrap_or(false);

    match group {
        Some(mut g) => {
            // 后台深度核验逐个试测备选节点期间，UI 与快照一律固定显示用户的 original_node，绝不闪现临时被测节点名
            let audit_prog = crate::mihomo::get_deep_audit_progress();
            if audit_prog.running && !audit_prog.original_node.is_empty() {
                g.now = audit_prog.original_node;
            }
            let is_selector = g.group_type.eq_ignore_ascii_case("Selector");
            let blocked = is_blocked_node_name(&g.now) || g.now.eq_ignore_ascii_case("DIRECT");

            // 严格策略组边界校验：
            // 1) Direct 模式直接禁行（全直连裸奔）；
            // 2) Global 模式下必须由 GLOBAL 指向 Claude-Fixed，若切到天悦云或其他非 Claude-Fixed 节点立刻标红（脱离策略组保护）；
            // 3) Rule 模式下必须命中 Claude 全家桶规则且覆盖出口 IP 监测域名（保证出口体检与 Claude 100% 同源）；
            // 4) 在 Claude-Fixed 内切换合规节点（软件内或 Clash 内均可）自动跟随生效，不重复卡死（3A）。
            let mode_direct_fail = clash_mode == "direct";
            let global_escaped = clash_mode == "global" && !global_now.eq_ignore_ascii_case("Claude-Fixed");
            let rule_missing_exit = clash_mode == "rule" && rules_ok && !exit_probe_rule_ok;

            let passed = is_selector
                && !blocked
                && !g.now.is_empty()
                && mihomo_ipv6_off
                && !mode_direct_fail
                && !global_escaped
                && (clash_mode == "global" || (rules_ok && exit_probe_rule_ok));

            let mode_label = match clash_mode.as_str() {
                "global" => format!("GLOBAL 全局模式 → {global_now}"),
                "direct" => "DIRECT 全局直连模式（高危）".into(),
                _ => format!("Rule 规则模式（命中 {rule_count} 条规则）"),
            };

            let summary = if mode_direct_fail {
                format!("[{FD_ERR_RULE_DRIFT}] Clash 当前处于全局直连模式（DIRECT），所有流量将裸奔出网！")
            } else if global_escaped {
                format!(
                    "[{FD_ERR_RULE_DRIFT}] Clash 全局模式当前指向「{}」，已脱离 Claude-Fixed 策略组保护！",
                    if global_now.is_empty() { "未选择" } else { global_now }
                )
            } else if blocked {
                format!("[{FD_ERR_RULE_DRIFT}] Claude-Fixed 当前落入禁区/直连节点：{}！请立即切换", g.now)
            } else if !is_selector {
                format!("[{FD_ERR_RULE_DRIFT}] Claude-Fixed 类型为 {}（必须为手动固定单节点策略组，防自动测速跳区）", g.group_type)
            } else if clash_mode != "global" && !rules_ok {
                format!("[{FD_ERR_RULE_DRIFT}] 已创建 Claude-Fixed，但规则表尚未覆盖 anthropic.com / claude.ai")
            } else if rule_missing_exit {
                format!("[{FD_ERR_RULE_DRIFT}] 覆写脚本为旧版本（未锁定出口 IP 监测域名到 Claude-Fixed），请一键更新 Script.js")
            } else if !mihomo_ipv6_off {
                format!("[{FD_ERR_IPV6_LEAK}] Mihomo 配置仍开启 ipv6: true（需关闭 Clash 内核代理隧道 IPv6）")
            } else {
                format!(
                    "手动固定单节点已锁定 {} · {} · ipv6:false",
                    g.now,
                    if clash_mode == "global" {
                        "GLOBAL → Claude-Fixed"
                    } else {
                        "Claude 全家桶 + 出口监测规则生效"
                    }
                )
            };

            let evidence = format!(
                "Clash Mode: {mode_label}\nGroup: Claude-Fixed (手动固定单节点={is_selector}) → {}\nNode Safe: {} | Claude Rules: {rule_count} | Exit Probe Rules: {}\nMihomo ipv6 (隧道层): {}",
                if g.now.is_empty() { "<empty>" } else { &g.now },
                if blocked { format!("BLOCKED ({FD_ERR_RULE_DRIFT})") } else { "Safe (合规范围)".into() },
                if exit_probe_rule_ok { "已锁死到 Claude-Fixed" } else if clash_mode == "global" { "GLOBAL 托管" } else { "未包含（旧版 Script.js）" },
                if mihomo_ipv6_off { "false (OK)" } else { "true (FAIL)" }
            );

            let fix_label = if passed {
                None
            } else if mode_direct_fail {
                Some("一键切回 Rule 规则模式并复测".into())
            } else if global_escaped {
                Some("一键将 GLOBAL 锁回 Claude-Fixed 策略组".into())
            } else if blocked {
                Some("一键切回安全节点并实测恢复".into())
            } else if !mihomo_ipv6_off && is_selector && (clash_mode == "global" || (rules_ok && exit_probe_rule_ok)) {
                Some("一键关闭 Mihomo IPv6 并复测".into())
            } else if rule_missing_exit {
                Some("一键直接更新策略组与规则并立即生效".into())
            } else {
                Some("一键直接写入策略组与规则并立即生效".into())
            };

            let can_auto_fix = true;

            (
                PreflightItem {
                    id: "node_group".into(),
                    part: CheckPart::Must,
                    cat: "1. 代理与节点（改 Clash 配置）".into(),
                    icon: "group".into(),
                    mode: if can_auto_fix {
                        "自动一键".into()
                    } else {
                        "向导 + 实测验收".into()
                    },
                    title: "策略组与全家桶规则锁死".into(),
                    status: if passed {
                        CheckStatus::Ok
                    } else {
                        CheckStatus::Fail
                    },
                    summary,
                    evidence,
                    guide: if mode_direct_fail {
                        "当前 Clash 为全局直连模式，Claude 流量未被策略组接管。点击下方按钮一键切回规则模式（同步更新内核与 config.yaml）并立即实测验收。".into()
                    } else if global_escaped {
                        format!(
                            "当前 Clash 为全局模式且选了「{global_now}」，已超出 Claude-Fixed 策略组范围。点击下方一键将 GLOBAL 切回 Claude-Fixed，此后在软件内或 Clash 的 Claude-Fixed 组内切节点均可自动同步识别。"
                        )
                    } else if rule_missing_exit {
                        "将直接注入新版规则到 Clash 生效配置并热重载 Mihomo（立即生效，无需手动点重载），同时同步写入全局 Script.js 保证更新订阅后持久有效（仅锁 Claude 全家桶与出口监测域名，不碰 AGY）。".into()
                    } else if passed {
                        "手动固定单节点策略组（防自动测速跳区）、Claude 全家桶规则与 Mihomo ipv6:false 均已实测生效；规则模式下 Clash 首页仍显示原订阅组（用于日常软件分流）属正常隔离，Claude 全家桶与本工具出口探针均已由顶部规则锁死至 Claude-Fixed，组内切合规节点会自动跟随同步。".into()
                    } else {
                        "点击下方直接向 Clash 生效配置注入 Claude-Fixed 策略组与规则并自动热重载内核（1 秒内立即生效，无需手动操作），同时写入全局 Script.js 与排雷损坏的订阅空脚本确保重启/更新订阅后永久保留。".into()
                    },
                    fix_label,
                    is_kill_item: blocked || mode_direct_fail || global_escaped,
                    is_failover: false,
                },
                if g.now.is_empty() {
                    "未选节点".into()
                } else {
                    g.now
                },
                passed,
                blocked || mode_direct_fail || global_escaped,
            )
        }
        None => {
            let fallback_node = proxies_map
                .values()
                .find(|v| {
                    v.get("type").and_then(|t| t.as_str()) == Some("Selector")
                        && v.get("name").and_then(|n| n.as_str()) != Some("GLOBAL")
                })
                .and_then(|v| v.get("now").and_then(|n| n.as_str()))
                .unwrap_or("未配置 Claude-Fixed")
                .to_string();

            (
                PreflightItem {
                    id: "node_group".into(),
                    part: CheckPart::Must,
                    cat: "1. 代理与节点（改 Clash 配置）".into(),
                    icon: "group".into(),
                    mode: "自动一键".into(),
                    title: "策略组与全家桶规则锁死".into(),
                    status: CheckStatus::Fail,
                    summary: format!("[{FD_ERR_RULE_DRIFT}] 尚未创建 Claude-Fixed 策略组（点击右侧按钮直接写入并立即生效）"),
                    evidence: format!(
                        "Mihomo GET /proxies: 未找到 Claude-Fixed ({FD_ERR_RULE_DRIFT})\nClash Mode: {clash_mode}\nMatched Claude Rules: {rule_count}\nMihomo ipv6: {}\nReference Active Node: {fallback_node}",
                        if mihomo_ipv6_off { "false" } else { "true" }
                    ),
                    guide: "点击下方按钮即可直接向 Clash 生效配置写入 Claude-Fixed 策略组与 Claude 全家桶规则，并通过 Mihomo API 自动热重载立即生效（同时持久化到 profiles\\Script.js 并自动修复可能阻断全局脚本的空订阅脚本，无需手动重载）。".into(),
                    fix_label: Some("一键直接写入策略组与规则并立即生效".into()),
                    is_kill_item: false,
                    is_failover: false,
                },
                fallback_node,
                false,
                false,
            )
        }
    }
}

/// 增量 11/12/16：出口节点合规与真实可达性（白名单 + 落地 IP 静默漂移 + ASN 纯净度 + Anthropic 无状态防 CF 403 探针）
async fn probe_exit_geo(
    mixed_port: u16,
    clash_online: bool,
    group_ok: bool,
    current_node: &str,
    cfg: &AppConfig,
) -> (
    PreflightItem,
    String,
    Option<u32>,
    String,
    String,
    bool,
    Option<String>,
    bool,
    bool,
) {
    if !clash_online {
        return (
            PreflightItem {
                id: "node_geo".into(),
                part: CheckPart::Must,
                cat: "1. 代理与节点（改 Clash 配置）".into(),
                icon: "geo".into(),
                mode: "自动一键".into(),
                title: "出口节点合规与真实可达性".into(),
                status: CheckStatus::Fail,
                summary: format!("[{FD_ERR_PROXY_OFFLINE}] 本地代理未就绪，无法经代理探测真实出口 IP 与 Anthropic 可达性"),
                evidence: format!("Proxy: http://127.0.0.1:{mixed_port} (Offline)"),
                guide: "请先确保 Clash Verge 在线后再重测出口归属地与可达性。".into(),
                fix_label: None,
                is_kill_item: false,
                is_failover: false,
            },
            "代理离线".into(),
            None,
            "离线".into(),
            String::new(),
            false,
            None,
            false,
            false,
        );
    }

    // 深度核验运行期间（后台正在逐个切 Claude-Fixed 核验节点）：严禁误把正在测的备选节点当成当前节点，也不允许此时放行启动
    let audit_prog = crate::mihomo::get_deep_audit_progress();
    if audit_prog.running {
        let target_node = if !audit_prog.original_node.is_empty() {
            audit_prog.original_node.as_str()
        } else {
            current_node
        };
        if let Some(rec) = crate::mihomo::get_fresh_verified_record(target_node) {
            let high_risk = matches!(rec.risk_level.as_str(), "abuser" | "proxy");
            let ok_base = !rec.blocked_country
                && !rec.cf_blocked
                && rec.claude_status != "offline"
                && !high_risk;
            let lat_label = rec
                .claude_delay_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "核验中".into());
            let summary = if !ok_base {
                format!(
                    "当前节点「{target_node}」核验未通过（{} · {}），后台正在继续核验其余备选节点 ({}/{})",
                    rec.country_code, rec.claude_label, audit_prog.current_index, audit_prog.total
                )
            } else {
                format!(
                    "当前主节点已核验合规（{} · {} · 后台静默评估其余备选节点 {}/{}）",
                    rec.country_code, rec.asn_purity, audit_prog.current_index, audit_prog.total
                )
            };
            return (
                PreflightItem {
                    id: "node_geo".into(),
                    part: CheckPart::Must,
                    cat: "1. 代理与节点（改 Clash 配置）".into(),
                    icon: "geo".into(),
                    mode: "深度核验中".into(),
                    title: "出口节点合规与真实可达性".into(),
                    status: if ok_base {
                        CheckStatus::Ok
                    } else {
                        CheckStatus::Fail
                    },
                    summary,
                    evidence: format!(
                        "目标锁定节点: {target_node}\n已实测出口: {} ({}) | ASN: {} ({})\nAnthropic 状态: {} | AGY 参考: {}\n后台核验进度: {}/{}（当前探测：{}）",
                        rec.masked_ip,
                        rec.country_code,
                        rec.asn_purity,
                        rec.risk_detail,
                        rec.claude_label,
                        rec.gemini_label,
                        audit_prog.current_index,
                        audit_prog.total,
                        audit_prog.current_node
                    ),
                    guide: "后台正在逐个核验备选节点的真实 IP 类型与风控状态，期间暂禁启动 Claude；全部完成并自动切回你的锁定节点后立刻恢复绿灯放行（也可点击停止核验）。".into(),
                    fix_label: None,
                    is_kill_item: rec.blocked_country || rec.cf_blocked || high_risk,
                    is_failover: false,
                },
                rec.masked_ip,
                rec.claude_delay_ms,
                lat_label,
                rec.country_code,
                rec.blocked_country || high_risk,
                None,
                false,
                rec.cf_blocked,
            );
        }

        return (
            PreflightItem {
                id: "node_geo".into(),
                part: CheckPart::Must,
                cat: "1. 代理与节点（改 Clash 配置）".into(),
                icon: "geo".into(),
                mode: "深度核验中".into(),
                title: "出口节点合规与真实可达性".into(),
                status: CheckStatus::Fail,
                summary: format!(
                    "正在优先深度核验当前锁定节点（{}，进度 {}/{}），请稍候...",
                    target_node, audit_prog.current_index, audit_prog.total
                ),
                evidence: format!(
                    "Deep Audit Running: {}/{}\nCurrent Probing: {}\nTarget Locked Node: {}",
                    audit_prog.current_index, audit_prog.total, audit_prog.current_node, target_node
                ),
                guide: "正在优先核验你当前选中的节点真实出口 IP、ASN 纯净度与 Claude 可达性，核验完成前暂不放行启动 Claude。".into(),
                fix_label: None,
                is_kill_item: false,
                is_failover: false,
            },
            "核验中".into(),
            None,
            "核验中".into(),
            String::new(),
            false,
            None,
            false,
            false,
        );
    }

    let proxy_url = format!("http://127.0.0.1:{mixed_port}");
    let start = std::time::Instant::now();
    let pure_rtt_fut = async {
        if let Some(ep) = discover_endpoint().await {
            crate::mihomo::probe_node_delay_via_mihomo(
                &ep,
                current_node,
                "http://cp.cloudflare.com/generate_204",
                3200,
                "204",
            )
            .await
        } else {
            None
        }
    };
    let (probe_res, anthropic_probe, web_cf_challenge, pure_rtt) = tokio::join!(
        probe_geo_via_proxy(&proxy_url),
        probe_anthropic_reachability(&proxy_url),
        probe_claude_web_cf_challenge(&proxy_url),
        pure_rtt_fut,
    );
    let elapsed_ms = pure_rtt.unwrap_or_else(|| start.elapsed().as_millis() as u32);

    match probe_res {
        Ok(geo) => {
            let ip = geo.ip;
            let country = geo.country;
            let asn_org = geo.asn_org;
            let source = geo.source;
            let masked = mask_ip_address(&ip);
            let blocked = is_blocked_country(&country);
            let lat_label = format!("{elapsed_ms} ms");

            // 结合真实 IP 风险情报（ip-api / ipapi.is 的 hosting / proxy / vpn / abuser + ASN 关键词）分级并回填节点表
            let (asn_purity, risk_level, risk_detail) = classify_ip_purity_and_risk(
                &asn_org,
                geo.is_datacenter,
                geo.is_vpn,
                geo.is_proxy,
                geo.is_abuser,
            );
            let drift_24h = crate::mihomo::record_verified_node_geo_guarded(
                current_node,
                &country,
                &masked,
                asn_purity,
                risk_level,
                risk_detail,
                blocked,
                group_ok,
            );

            // 落地 IP 静默漂移判定：
            // 仅当「节点名未变且 24h 历史中确实记录到 >= 1 次不同落地 IP」才触发漂移预警，彻底杜绝切节点误报「漂移 0 次预警」
            let landing_sig = format!("{country}:{masked}");
            let baseline_changed = match (&cfg.locked_node_for_ip, &cfg.locked_landing_ip) {
                (Some(prev_node), Some(prev_sig))
                    if prev_node == current_node && prev_sig != &landing_sig =>
                {
                    true
                }
                _ => false,
            };
            let landing_drifted = drift_24h > 0 || (baseline_changed && drift_24h > 0);
            if landing_drifted {
                crate::logger::log_event(
                    "WARN",
                    "preflight",
                    "landing_ip_drift",
                    Some(elapsed_ms as u64),
                    format!(
                        "检测到节点落地 IP 静默漂移: node={current_node} now={landing_sig} drift_24h={drift_24h}"
                    ),
                    Some(serde_json::json!({
                        "node": current_node,
                        "current": landing_sig,
                        "driftCount24h": drift_24h
                    })),
                );
            }

            let (anthropic_ok, cf_blocked, anthropic_label) = anthropic_probe;
            let high_risk_ip = matches!(risk_level, "abuser" | "proxy");

            // 严格三级合规与可用性标准（用户已确认 1A + 2B）：
            // - Fail（红灯阻断）：落入禁区 / Anthropic API 不可达或 CF 403 拉黑 / 高危滥用或公共代理 IP
            // - Warn（黄灯预警）：同一节点 24h 内真实发生落地 IP 静默漂移 (drift_24h >= 1)
            // - Ok（绿灯放行）：合规地区 + API 可达无拉黑 + 非高危代理/滥用 + 24h 0 漂移
            //   （1A：普通机房放行并在节点表标注「常规机房」；2B：仅 claude.ai 网页弹 CF 盾时控制台放行，在节点表标风险盾「Claude 弹盾」）
            let passed = !blocked && !cf_blocked && anthropic_ok && !high_risk_ip;

            // 仅在策略组已锁死 (group_ok == true) 时才将本次实测结果写入该节点的持久化核验缓存！
            // 严禁在未建组或 GLOBAL=DIRECT 脱组时，把本机直连 IP（如 CN）栽赃污染到正常海外节点缓存中！
            if group_ok {
                crate::mihomo::record_verified_node_claude_probe(
                    current_node,
                    anthropic_ok,
                    cf_blocked,
                    web_cf_challenge,
                    blocked,
                    Some(elapsed_ms),
                );
            }

            let cf_note = if web_cf_challenge {
                " · 网页有 CF 盾（节点表已标风险盾）"
            } else {
                ""
            };

            let summary = if !group_ok && (cf_blocked || blocked) {
                format!("策略组尚未锁死，当前走了默认/直连路由（{country} · {masked}），请先完成上方「策略组与全家桶规则锁死」后再复测")
            } else if cf_blocked {
                format!("当前出口被 Cloudflare 403 拉黑（{country} · {masked}），请立即前往节点流量更换纯净节点")
            } else if blocked {
                format!("[{FD_ERR_RULE_DRIFT}] 真实探测出口落入禁区 {country}（{masked}）！禁止启动 Claude")
            } else if high_risk_ip {
                format!("当前出口命中高危 IP 风险：{asn_purity}（{risk_detail} · {country} · {masked}），禁止启动")
            } else if !anthropic_ok {
                format!("当前节点无法连通 Anthropic API（{country} · {masked}），请切换可用节点")
            } else if landing_drifted {
                format!("{country} · {asn_purity} · 24h 落地 IP 漂移 {drift_24h} 次预警（{masked}）")
            } else {
                format!(
                    "{country} · {asn_purity} · Anthropic 可达（{masked} · 24h 0 漂移）{cf_note}"
                )
            };

            let evidence = format!(
                "Source: {source} (via {proxy_url}) | Latency: {elapsed_ms} ms\nExit IP: {masked} ({country} · {})\nASN / Org: {} → {asn_purity} ({risk_detail})\n24h Landing IP Drift: {} (count={drift_24h})\nAnthropic API (api.anthropic.com): {anthropic_label}\nClaude Web (claude.ai/login): {}",
                if blocked { format!("BLOCKED ({FD_ERR_RULE_DRIFT})") } else { "Whitelisted".into() },
                if asn_org.is_empty() { "Unknown".into() } else { asn_org },
                if landing_drifted { "DRIFT DETECTED (机场后台切换落地 IP)" } else { "Stable (24h 内未漂移)" },
                if web_cf_challenge { "触发 CF 人机盾（API 畅通，节点表已标风险盾）" } else { "无 CF 弹盾 (OK)" }
            );

            let item = PreflightItem {
                id: "node_geo".into(),
                part: CheckPart::Must,
                cat: "1. 代理与节点（改 Clash 配置）".into(),
                icon: "geo".into(),
                mode: "自动一键 / 选节点".into(),
                title: "出口节点合规与真实可达性".into(),
                status: if !passed {
                    CheckStatus::Fail
                } else if landing_drifted {
                    CheckStatus::Warn
                } else {
                    CheckStatus::Ok
                },
                summary,
                evidence,
                guide: if !group_ok && (cf_blocked || blocked) {
                    "当前检测到的是未建组/直连下的本机出口，不代表你的海外节点本身不可用；请先完成「策略组与全家桶规则锁死」后再重新实测。".into()
                } else if cf_blocked {
                    "当前节点出口 IP 已被 Cloudflare 403 拦截盾拉黑，请前往「节点流量」选择低风控 ISP/原生节点后重测。".into()
                } else if blocked {
                    "当前代理出口落入 Anthropic 不支持的禁区国家，请点击下方一键切回白名单安全节点后复测。".into()
                } else if high_risk_ip {
                    "当前出口 IP 命中高危公共代理或滥用标记，极易触发账号风控，请前往「节点流量」切换纯净节点。".into()
                } else if !anthropic_ok {
                    "当前节点无法连通 api.anthropic.com，请前往「节点流量」切换延迟稳定且可达的合规节点。".into()
                } else if landing_drifted {
                    "同一节点 24 小时内落地 IP 发生静默漂移（机场后台换了出口 IP），建议在「节点流量」重测核验或更换稳定节点。".into()
                } else if web_cf_challenge {
                    "合规地区、Anthropic API 真实可达且无高危代理标记（已放行）；检测到 claude.ai 网页触发 CF 人机盾，已在「节点流量」标注风险盾供参考。".into()
                } else {
                    "已实测验证出口合规、24h 0 漂移、非高危代理且 Anthropic 真实可达。".into()
                },
                fix_label: if !passed {
                    Some("节点不可用，前往「节点流量」手动更换节点 →".into())
                } else if landing_drifted {
                    Some("前往「节点流量」更换稳定节点 →".into())
                } else {
                    None
                },
                is_kill_item: blocked || cf_blocked || high_risk_ip,
                is_failover: !passed || landing_drifted,
            };

            (
                item,
                masked,
                Some(elapsed_ms),
                lat_label,
                country,
                blocked || high_risk_ip,
                Some(landing_sig),
                landing_drifted,
                cf_blocked,
            )
        }
        Err(err) => (
            PreflightItem {
                id: "node_geo".into(),
                part: CheckPart::Must,
                cat: "1. 代理与节点（改 Clash 配置）".into(),
                icon: "geo".into(),
                mode: "自动一键 / 选节点".into(),
                title: "出口节点合规与真实可达性".into(),
                status: CheckStatus::Fail,
                summary: "经代理探测真实出口 IP 超时或失败，当前节点可能不可用".into(),
                evidence: format!("Proxy: {proxy_url}\nError: {err}"),
                guide: "当前节点外网探测失败，请检查节点连通性或切换同地区热备节点后重新实测。".into(),
                fix_label: Some("重新探测出口或切换安全节点".into()),
                is_kill_item: false,
                is_failover: true,
            },
            "探测失败".into(),
            None,
            "超时".into(),
            String::new(),
            false,
            None,
            false,
            false,
        ),
    }
}

#[derive(Debug, Clone)]
pub struct GeoProbeInfo {
    pub ip: String,
    pub country: String,
    pub asn_org: String,
    pub source: &'static str,
    pub is_datacenter: Option<bool>,
    pub is_vpn: Option<bool>,
    pub is_proxy: Option<bool>,
    pub is_abuser: Option<bool>,
}

/// 综合 ASN 机构名与 IP 情报标记输出 4 档纯净度：(展示名, risk_level, 紧凑说明)
pub fn classify_ip_purity_and_risk(
    org: &str,
    is_datacenter: Option<bool>,
    is_vpn: Option<bool>,
    is_proxy: Option<bool>,
    is_abuser: Option<bool>,
) -> (&'static str, &'static str, &'static str) {
    if is_abuser == Some(true) {
        return ("高危滥用", "abuser", "命中滥用黑名单");
    }
    if is_vpn == Some(true) || is_proxy == Some(true) {
        return ("共享代理", "proxy", "公共 VPN / 代理段");
    }
    if is_datacenter == Some(true) {
        return ("常规机房", "hosting", "0 滥用记录");
    }
    let l = org.to_lowercase();
    let hosting_kw = [
        "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode", "akamai",
        "vultr", "hetzner", "ovh", "oracle", "alibaba", "tencent", "choopa", "m247", "datacamp",
        "hosting", "cloud", "vps", "server",
    ];
    if hosting_kw.iter().any(|k| l.contains(k)) {
        return ("常规机房", "hosting", "0 滥用记录");
    }
    if is_datacenter == Some(false) || !l.is_empty() {
        return ("ISP 住宅", "isp", "无代理标记");
    }
    ("待验 IP", "unknown", "未识别 ASN")
}

/// 增量 12：极轻量无状态只读探针（绝不带账号 Cookie/Token），校验 api.anthropic.com 可达性并识别 CF 403 拉黑
async fn probe_anthropic_reachability(proxy_url: &str) -> (bool, bool, String) {
    let Ok(proxy) = reqwest::Proxy::all(proxy_url) else {
        return (false, false, "代理配置错误".into());
    };
    let Ok(client) = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(4))
        .user_agent("FD-Claude-Guard-Probe/0.1")
        .build()
    else {
        return (false, false, "客户端初始化失败".into());
    };

    match client.get("https://api.anthropic.com/v1/models").send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let cf_mitigated = resp
                .headers()
                .get("cf-mitigated")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let server_hdr = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            // 无认证头访问 /v1/models 正常返回 401 (authentication_error)，说明 TLS/CF 通道完全畅通；
            // 若返回 403 且含 Cloudflare 特征则为 IP 被拉黑拦截盾
            if code == 403 && (!cf_mitigated.is_empty() || server_hdr.contains("cloudflare")) {
                (false, true, format!("CF 403 已拉黑 (HTTP 403, server={server_hdr})"))
            } else if code == 401 || code == 200 || code == 400 || code == 404 || code == 405 {
                (true, false, format!("可达 (TLS 正常 · 无认证响应 HTTP {code} · 非 CF 403)"))
            } else {
                (true, false, format!("响应 HTTP {code}"))
            }
        }
        Err(e) => (false, false, format!("连接异常: {e}")),
    }
}

/// 无状态真实探测 claude.ai/login 是否触发 Cloudflare 人机弹盾（用于节点表标注黄色风险盾）
async fn probe_claude_web_cf_challenge(proxy_url: &str) -> bool {
    let Ok(proxy) = reqwest::Proxy::all(proxy_url) else {
        return false;
    };
    let Ok(client) = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(4))
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36")
        .build()
    else {
        return false;
    };

    match client.get("https://claude.ai/login").send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let cf_mitigated = resp
                .headers()
                .get("cf-mitigated")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = resp.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(1200).collect();
            crate::mihomo::is_claude_web_cf_challenge(status, &cf_mitigated, &snippet)
        }
        Err(_) => false,
    }
}

pub async fn probe_geo_via_proxy(proxy_url: &str) -> Result<GeoProbeInfo, String> {
    let proxy = reqwest::Proxy::all(proxy_url).map_err(|e| format!("构造代理配置失败: {e}"))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(5))
        .user_agent("FD-Claude-Guard/0.1")
        .build()
        .map_err(|e| format!("构造探测客户端失败: {e}"))?;

    // 1. 优先 HTTPS：api.ipapi.is（返回完整 is_datacenter / is_vpn / is_proxy / is_abuser）
    if let Ok(resp) = client.get("https://api.ipapi.is/").send().await {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<Value>().await {
                let ip = val.get("ip").and_then(|v| v.as_str()).unwrap_or("");
                let country = val
                    .get("location")
                    .and_then(|l| l.get("country_code"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !ip.is_empty() && !country.is_empty() {
                    let asn_num = val
                        .get("asn")
                        .and_then(|a| a.get("asn"))
                        .and_then(|v| v.as_u64())
                        .map(|n| format!("AS{n}"))
                        .unwrap_or_default();
                    let asn_org_name = val
                        .get("asn")
                        .and_then(|a| a.get("org"))
                        .and_then(|v| v.as_str())
                        .or_else(|| val.get("company").and_then(|c| c.get("name")).and_then(|v| v.as_str()))
                        .unwrap_or("");
                    let org = format!("{asn_num} {asn_org_name}").trim().to_string();
                    return Ok(GeoProbeInfo {
                        ip: ip.to_string(),
                        country: country.to_uppercase(),
                        asn_org: org,
                        source: "api.ipapi.is",
                        is_datacenter: val.get("is_datacenter").and_then(|v| v.as_bool()),
                        is_vpn: val.get("is_vpn").and_then(|v| v.as_bool()),
                        is_proxy: val.get("is_proxy").and_then(|v| v.as_bool()),
                        is_abuser: val.get("is_abuser").and_then(|v| v.as_bool()),
                    });
                }
            }
        }
    }

    // 2. 备选 HTTPS：ipinfo.io（返回 country 与 org/ASN）
    if let Ok(resp) = client.get("https://ipinfo.io/json").send().await {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<Value>().await {
                if let (Some(ip), Some(country)) = (
                    val.get("ip").and_then(|v| v.as_str()),
                    val.get("country").and_then(|v| v.as_str()),
                ) {
                    let org = val
                        .get("org")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    return Ok(GeoProbeInfo {
                        ip: ip.to_string(),
                        country: country.to_uppercase(),
                        asn_org: org,
                        source: "ipinfo.io",
                        is_datacenter: None,
                        is_vpn: None,
                        is_proxy: None,
                        is_abuser: None,
                    });
                }
            }
        }
    }

    // 3. 兜底回退：ip-api.com（当 HTTPS 源限流或不可达时启用）
    if let Ok(resp) = client
        .get("http://ip-api.com/json/?fields=status,countryCode,query,org,isp,as,proxy,hosting,mobile")
        .send()
        .await
    {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<Value>().await {
                if val.get("status").and_then(|v| v.as_str()) == Some("success") {
                    let ip = val.get("query").and_then(|v| v.as_str()).unwrap_or("");
                    let country = val.get("countryCode").and_then(|v| v.as_str()).unwrap_or("");
                    if !ip.is_empty() && !country.is_empty() {
                        let as_str = val.get("as").and_then(|v| v.as_str()).unwrap_or("");
                        let org_str = val.get("org").and_then(|v| v.as_str()).unwrap_or("");
                        let asn_org = if !as_str.is_empty() {
                            as_str.to_string()
                        } else {
                            org_str.to_string()
                        };
                        return Ok(GeoProbeInfo {
                            ip: ip.to_string(),
                            country: country.to_uppercase(),
                            asn_org,
                            source: "ip-api.com",
                            is_datacenter: val.get("hosting").and_then(|v| v.as_bool()),
                            is_vpn: None,
                            is_proxy: val.get("proxy").and_then(|v| v.as_bool()),
                            is_abuser: None,
                        });
                    }
                }
            }
        }
    }

    if let Ok(resp) = client.get("https://api.country.is/").send().await {
        if resp.status().is_success() {
            if let Ok(val) = resp.json::<Value>().await {
                if let (Some(ip), Some(country)) = (
                    val.get("ip").and_then(|v| v.as_str()),
                    val.get("country").and_then(|v| v.as_str()),
                ) {
                    return Ok(GeoProbeInfo {
                        ip: ip.to_string(),
                        country: country.to_uppercase(),
                        asn_org: String::new(),
                        source: "api.country.is",
                        is_datacenter: None,
                        is_vpn: None,
                        is_proxy: None,
                        is_abuser: None,
                    });
                }
            }
        }
    }

    Err("多源出口 IP 探测均未成功响应（api.ipapi.is / ipinfo.io / api.country.is）".into())
}

/// 增量 16：仅检查并修复 Windows 物理网卡 IPv6 绑定与外网 IPv6 探针（自动排除受 Mihomo ipv6:false 管控的 Clash TUN 虚拟网卡）
async fn probe_ipv6_windows_only() -> PreflightItem {
    let (enabled_adapters, ignored_tun_adapters, reg_disabled_components) =
        tokio::task::spawn_blocking(inspect_windows_ipv6)
            .await
            .unwrap_or_else(|_| (Vec::new(), Vec::new(), None));

    let ipv6_reachable = tokio::task::spawn_blocking(|| {
        let target: SocketAddr = "[2606:4700:4700::1111]:443".parse().unwrap();
        TcpStream::connect_timeout(&target, Duration::from_millis(1200)).is_ok()
    })
    .await
    .unwrap_or(false);

    let layer_adapter_ok = enabled_adapters.is_empty();
    let layer_probe_ok = !ipv6_reachable;
    let passed = layer_adapter_ok && layer_probe_ok;

    let adapter_str = if enabled_adapters.is_empty() {
        "All Physical Adapters Disabled (OK)".into()
    } else {
        format!("Enabled on: {}", enabled_adapters.join(", "))
    };
    let tun_note = if ignored_tun_adapters.is_empty() {
        "无".into()
    } else {
        format!(
            "{}（Clash TUN 虚拟网卡受 ipv6:false 管控，已自动豁免）",
            ignored_tun_adapters.join(", ")
        )
    };
    let reg_str = reg_disabled_components
        .map(|v| format!("0x{v:02x} ({v})"))
        .unwrap_or_else(|| "Not Set".into());

    let summary = if passed {
        "物理网卡 IPv6 已禁用且真实外网 IPv6 探测不可达".into()
    } else if ipv6_reachable {
        format!("[{FD_ERR_IPV6_LEAK}] 严重：真实外网 IPv6 探针可直连出网，存在真实本地 IP 泄漏风险！")
    } else {
        format!(
            "[{FD_ERR_IPV6_LEAK}] 检测到 {} 个物理网卡仍启用 ms_tcpip6（{}），存在 IPv6 直连风险",
            enabled_adapters.len(),
            enabled_adapters.first().cloned().unwrap_or_default()
        )
    };

    let evidence = format!(
        "1. 物理网卡 ms_tcpip6: {}\n2. 虚拟网卡豁免: {}\n3. 注册表 Tcpip6 DisabledComponents: {}\n4. 外网 IPv6 连通探针 (2606:4700::1111): {}",
        adapter_str,
        tun_note,
        reg_str,
        if layer_probe_ok { "Blocked / Unreachable (OK)" } else { "REACHABLE (LEAK!)" }
    );

    PreflightItem {
        id: "sys_ipv6".into(),
        part: CheckPart::Must,
        cat: "2. Windows 系统环境（改系统）".into(),
        icon: "ipv6".into(),
        mode: "管理员一键 + 实测".into(),
        title: "Windows 网卡 IPv6 禁用".into(),
        status: if passed {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        },
        summary,
        evidence,
        guide: if passed {
            "Windows 物理网卡 ms_tcpip6 绑定与外网 IPv6 探针均已验证 0 泄漏（Mihomo 虚拟网卡由 Clash ipv6:false 独立管控，重载不会误报）。".into()
        } else {
            "仅对 Windows 物理网卡禁用 ms_tcpip6 绑定并设置 IPv4 优先（不改 Clash 规则、不碰 Claude 目录），随后真实发起外网 IPv6 探测确认无法出网才变绿。".into()
        },
        fix_label: if passed {
            None
        } else {
            Some("管理员一键禁用网卡 IPv6 并实测验收".into())
        },
        is_kill_item: false,
        is_failover: false,
    }
}

/// T-101 唯一端口真源：优先从在线 Mihomo GET /configs 读取真实 mixed-port（如 7897 / 7890），
/// 离线时回退解析 Clash Verge 的 verge.yaml，最后兜底 7890。严禁业务修复路径硬编码 7890。
pub async fn resolve_active_mixed_port() -> u16 {
    if let Some(ep) = discover_endpoint().await {
        if let Ok(cfg) = fetch_configs(&ep).await {
            if cfg.mixed_port > 0 {
                return cfg.mixed_port;
            }
        }
    }
    if let Some(dir) = clash_verge_config_dir() {
        if let Ok(raw) = fs::read_to_string(dir.join("verge.yaml")) {
            for line in raw.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("verge_mixed_port:") {
                    if let Ok(p) = rest.trim().parse::<u16>() {
                        if p > 0 {
                            return p;
                        }
                    }
                }
            }
        }
    }
    7890
}

/// 纯函数：判定单个代理环境变量是否与 Clash 当前真实端口冲突而需要备份清理（供生产与单元测试共用）
pub fn should_clear_proxy_env_var(key: &str, val: &str, expected_port: u16) -> bool {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return false;
    }
    let upper_k = key.to_uppercase();
    if upper_k == "ANTHROPIC_BASE_URL" || upper_k == "CLAUDE_API_BASE_URL" {
        is_third_party_base_url(trimmed)
    } else if upper_k == "NO_PROXY" {
        let l = trimmed.to_lowercase();
        l.contains("anthropic.com") || l.contains("claude.ai") || l.contains("claude.com")
    } else if matches!(upper_k.as_str(), "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY") {
        !trimmed.contains(&format!(":{expected_port}"))
    } else {
        false
    }
}

/// 增量 14 & 16：独立拆出「系统代理与环境变量冲突排查」（仅修冲突环境变量与 WinINET，绝不碰 Claude 目录）
async fn probe_system_proxy_and_env(mixed_port: u16) -> (PreflightItem, bool) {
    let expected_port = mixed_port;
    let (conflicts, oauth_relay_found, wininet_summary) =
        tokio::task::spawn_blocking(move || inspect_system_proxy_and_env_sync(expected_port))
            .await
            .unwrap_or_else(|_| (Vec::new(), false, "WinINET 查询异常".into()));

    let passed = conflicts.is_empty();
    let summary = if passed {
        format!("CLI 代理环境变量 0 冲突 · WinINET 端口与 {mixed_port} 一致（三端同 IP）")
    } else if oauth_relay_found {
        format!("[{FD_ERR_LOG_POLLUTE}] 检测到第三方反代地址（{}），严禁喂入 Pro/Max OAuth！", conflicts[0])
    } else {
        format!("检测到 {} 处环境变量或系统代理冲突（{}），可能导致 CLI 与桌面端不同 IP", conflicts.len(), conflicts[0])
    };

    let evidence = if passed {
        format!(
            "ANTHROPIC_BASE_URL: Default Official\nCLI Env (HTTP/HTTPS/ALL_PROXY & NO_PROXY): 0 冲突 / 无直连豁免\nWinINET: {wininet_summary}"
        )
    } else {
        format!(
            "Detected Conflicts:\n{}\nWinINET: {wininet_summary}",
            conflicts.join("\n")
        )
    };

    (
        PreflightItem {
            id: "sys_env".into(),
            part: CheckPart::Must,
            cat: "2. Windows 系统环境（改系统）".into(),
            icon: "startup".into(),
            mode: "自动一键".into(),
            title: "系统代理与环境变量冲突排查".into(),
            status: if passed {
                CheckStatus::Ok
            } else {
                CheckStatus::Fail
            },
            summary,
            evidence,
            guide: if passed {
                "系统代理与终端环境变量零冲突，确保桌面端、CLI、网页版三端同 IP；使用网页版时建议关闭浏览器独立分流插件与 WebRTC 暴露。".into()
            } else {
                "仅备份并清理冲突的 Windows 环境变量（HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY / 非官方 ANTHROPIC_BASE_URL）或校准 WinINET 端口，绝不碰 Claude 账号目录。".into()
            },
            fix_label: if passed {
                None
            } else {
                Some("一键备份并清理冲突环境变量".into())
            },
            is_kill_item: false,
            is_failover: false,
        },
        oauth_relay_found,
    )
}

/// 检测是否存在非虚拟物理网卡（如 以太网/WLAN）的 IPv4 DNS 被异常残留写死为 127.0.0.1
/// 返回 `(InterfaceIndex, InterfaceAlias)`，强制 UTF-8 输出并用纯数字索引修复，100% 免疫中文网卡名 GBK 乱码
#[cfg(windows)]
fn detect_physical_adapters_with_loopback_dns() -> Vec<(u32, String)> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-Command",
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -contains '127.0.0.1' -and $_.InterfaceAlias -notmatch 'Meta|Mihomo|Wintun|Clash|Loopback|vEthernet' } | ForEach-Object { \"$($_.InterfaceIndex)|$($_.InterfaceAlias)\" }",
        ])
        .output();
    let Ok(o) = out else {
        return Vec::new();
    };
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (idx_s, alias) = trimmed.split_once('|')?;
            let idx = idx_s.trim().parse::<u32>().ok()?;
            Some((idx, alias.trim().to_string()))
        })
        .collect()
}

#[cfg(not(windows))]
fn detect_physical_adapters_with_loopback_dns() -> Vec<(u32, String)> {
    Vec::new()
}

fn inspect_system_proxy_and_env_sync(expected_port: u16) -> (Vec<String>, bool, String) {
    let mut conflicts: Vec<String> = Vec::new();
    let mut oauth_relay = false;

    let mut check_pair = |scope: &str, key: &str, val: &str| {
        let trimmed = val.trim();
        if trimmed.is_empty() {
            return;
        }
        let upper_k = key.to_uppercase();
        if upper_k == "ANTHROPIC_BASE_URL" || upper_k == "CLAUDE_API_BASE_URL" {
            if is_third_party_base_url(trimmed) {
                oauth_relay = true;
                conflicts.push(format!("{scope} {key}={trimmed} (第三方反代高危)"));
            }
        } else if upper_k == "NO_PROXY" {
            let l = trimmed.to_lowercase();
            if l.contains("anthropic.com") || l.contains("claude.ai") || l.contains("claude.com") {
                conflicts.push(format!("{scope} NO_PROXY 包含 Anthropic 直连豁免: {trimmed}"));
            }
        } else if matches!(upper_k.as_str(), "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY") {
            let expected_suffix = format!(":{expected_port}");
            if !trimmed.contains(&expected_suffix) {
                conflicts.push(format!(
                    "{scope} {key}={trimmed} (与 Clash 端口 {expected_port} 冲突)"
                ));
            }
        }
    };

    let keys = [
        "ANTHROPIC_BASE_URL",
        "CLAUDE_API_BASE_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ];
    // 非 Windows 平台无注册表，退回检查当前进程环境；Windows 平台以持久化真源 HKCU/HKLM 为准，避免已清完注册表后自身进程旧快照永远卡红
    #[cfg(not(windows))]
    for k in keys {
        if let Ok(v) = std::env::var(k) {
            check_pair("Process ENV", k, &v);
        }
    }

    let mut wininet_summary = "未启用系统代理（TUN 模式接管）".to_string();

    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        use winreg::RegKey;
        if let Ok(env_key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey("Environment") {
            for k in keys {
                if let Ok(v) = env_key.get_value::<String, _>(k) {
                    check_pair("HKCU\\Environment", k, &v);
                }
            }
        }
        if let Ok(sys_env_key) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
        {
            for k in keys {
                if let Ok(v) = sys_env_key.get_value::<String, _>(k) {
                    check_pair("HKLM\\Environment", k, &v);
                }
            }
        }
        if let Ok(inet) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        {
            let enabled: u32 = inet.get_value("ProxyEnable").unwrap_or(0);
            let server: String = inet.get_value("ProxyServer").unwrap_or_default();
            if enabled == 1 && !server.trim().is_empty() {
                let expected_suffix = format!(":{expected_port}");
                if server.contains(&expected_suffix) {
                    wininet_summary = format!("{server} (端口一致 · 三端同 IP)");
                } else {
                    wininet_summary = format!("{server} (与 Clash 端口 {expected_port} 不一致)");
                    conflicts.push(format!(
                        "WinINET ProxyServer={server} (与 Clash 端口 {expected_port} 冲突)"
                    ));
                }
            }
        }
        // 检测物理网卡是否残留 127.0.0.1 DNS（会导致关闭 TUN 后全网无法访问且无法导入订阅）
        for (_if_idx, adapter) in detect_physical_adapters_with_loopback_dns() {
            conflicts.push(format!(
                "物理网卡「{adapter}」DNS 残留为 127.0.0.1（关闭 TUN 后会导致断网且无法导入订阅，一键修复可自动恢复 DHCP）"
            ));
        }
    }

    // 检查 ~/.claude/settings.json 中是否存在第三方 ANTHROPIC_BASE_URL
    if let Some(settings_path) = claude_settings_path() {
        if let Ok(raw) = fs::read_to_string(settings_path) {
            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                if let Some(base_url) = val
                    .get("env")
                    .and_then(|e| e.get("ANTHROPIC_BASE_URL"))
                    .and_then(|v| v.as_str())
                {
                    if is_third_party_base_url(base_url) {
                        oauth_relay = true;
                        conflicts.push(format!("settings.json ANTHROPIC_BASE_URL={base_url}"));
                    }
                }
            }
        }
    }

    conflicts.sort();
    conflicts.dedup();
    (conflicts, oauth_relay, wininet_summary)
}

fn fix_system_proxy_and_env(expected_port: u16) -> Result<String, String> {
    let mut backed_up = serde_json::Map::new();
    let keys = [
        "ANTHROPIC_BASE_URL",
        "CLAUDE_API_BASE_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ];

    // 仅备份当前进程观测到的冲突变量（多线程异步进程内严禁调用 std::env::remove_var，注册表清理 + WM_SETTINGCHANGE 已负责持久化生效）
    for k in keys {
        if let Ok(v) = std::env::var(k) {
            if should_clear_proxy_env_var(k, &v, expected_port) {
                backed_up.insert(format!("process:{k}"), Value::String(v));
            }
        }
    }

    let mut hkcu_orig_pairs: Vec<(String, String)> = Vec::new();
    let mut hklm_orig_pairs: Vec<(String, String)> = Vec::new();
    let mut wininet_orig_enable: Option<u32> = None;
    let mut wininet_orig_server: Option<String> = None;
    let mut settings_orig_base_url: Option<String> = None;
    let mut dns_fix_err: Option<String> = None;

    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
        use winreg::RegKey;
        let mut reg_changed = false;
        if let Ok(env_key) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
        {
            for k in keys {
                if let Ok(v) = env_key.get_value::<String, _>(k) {
                    if should_clear_proxy_env_var(k, &v, expected_port) {
                        hkcu_orig_pairs.push((k.to_string(), v.clone()));
                        backed_up.insert(format!("hkcu:{k}"), Value::String(v));
                        if env_key.delete_value(k).is_ok() {
                            reg_changed = true;
                        }
                    }
                }
            }
        }
        // T-101：管理员权限下同步清理 HKLM 系统级冲突代理环境变量，防止新开终端持续继承旧 7890 变量
        if let Ok(sys_env_key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            KEY_READ | KEY_WRITE,
        ) {
            for k in keys {
                if let Ok(v) = sys_env_key.get_value::<String, _>(k) {
                    if should_clear_proxy_env_var(k, &v, expected_port) {
                        hklm_orig_pairs.push((k.to_string(), v.clone()));
                        backed_up.insert(format!("hklm:{k}"), Value::String(v));
                        if sys_env_key.delete_value(k).is_ok() {
                            reg_changed = true;
                        }
                    }
                }
            }
        }
        if let Ok(inet) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            KEY_READ | KEY_WRITE,
        ) {
            let enabled: u32 = inet.get_value("ProxyEnable").unwrap_or(0);
            let server: String = inet.get_value("ProxyServer").unwrap_or_default();
            // 同步更新启用的代理端口或残留的旧本地代理端口（如 127.0.0.1:7890 -> 127.0.0.1:7897）
            let stale_local = server.trim().starts_with("127.0.0.1:")
                && !server.contains(&format!(":{expected_port}"));
            if (enabled == 1 || stale_local)
                && !server.trim().is_empty()
                && !server.contains(&format!(":{expected_port}"))
            {
                wininet_orig_enable = Some(enabled);
                wininet_orig_server = Some(server.clone());
                backed_up.insert("wininet:ProxyServer".into(), Value::String(server));
                if inet.set_value("ProxyServer", &format!("127.0.0.1:{expected_port}")).is_ok() {
                    reg_changed = true;
                }
            }
        }
        // 自动恢复物理网卡被 Clash 卸载残留写死的 127.0.0.1 DNS 为 DHCP 自动获取，按纯数字 InterfaceIndex 执行 100% 免疫中文乱码
        let broken_dns_adapters = detect_physical_adapters_with_loopback_dns();
        if !broken_dns_adapters.is_empty() {
            let mut cmds = Vec::new();
            for (if_idx, adapter) in &broken_dns_adapters {
                backed_up.insert(format!("dns:{adapter}({if_idx})"), Value::String("127.0.0.1".into()));
                cmds.push(format!(
                    "Set-DnsClientServerAddress -InterfaceIndex {if_idx} -ResetServerAddresses -ErrorAction Stop"
                ));
            }
            cmds.push("ipconfig /flushdns | Out-Null".into());
            if let Err(err) = crate::rollback::run_ps_elevated_checked(
                &cmds.join("; "),
                "重置物理网卡 127.0.0.1 DNS 为自动获取",
            ) {
                dns_fix_err = Some(err);
            }
        }
        if reg_changed {
            let mut cmd = std::process::Command::new("powershell");
            cmd.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition '[DllImport(\"user32.dll\", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'; $r=[UIntPtr]::Zero; [Win32.NativeMethods]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero, 'Environment', 2, 1000, [ref]$r) | Out-Null",
            ]);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                cmd.creation_flags(0x0800_0000);
            }
            let _ = cmd.output();
        }
    }

    // 同步移除 settings.json 中的第三方 ANTHROPIC_BASE_URL（不碰账号目录）
    if let Some(settings_path) = claude_settings_path() {
        if let Ok(raw) = fs::read_to_string(&settings_path) {
            if let Ok(mut val) = serde_json::from_str::<Value>(&raw) {
                if let Some(env_map) = val.get_mut("env").and_then(|e| e.as_object_mut()) {
                    if let Some(base_url) = env_map
                        .get("ANTHROPIC_BASE_URL")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                    {
                        if is_third_party_base_url(&base_url) {
                            settings_orig_base_url = Some(base_url.clone());
                            backed_up.insert("settings:ANTHROPIC_BASE_URL".into(), Value::String(base_url));
                            env_map.remove("ANTHROPIC_BASE_URL");
                            if let Ok(serialized) = serde_json::to_string_pretty(&val) {
                                let _ = fs::write(&settings_path, serialized);
                            }
                        }
                    }
                }
            }
        }
    }

    // 写入 First-Write-Wins 系统基线快照，供「撤回中心」精准还原
    crate::rollback::capture_sys_env_baseline_if_needed(
        &hkcu_orig_pairs,
        &hklm_orig_pairs,
        wininet_orig_enable,
        wininet_orig_server,
        settings_orig_base_url,
    );

    if !backed_up.is_empty() {
        if let Some(home) = dirs::home_dir() {
            let dir = home.join(".fd-claude-guard");
            let _ = fs::create_dir_all(&dir);
            let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
            let _ = fs::write(
                dir.join(format!("env-backup-{ts}.json")),
                serde_json::to_string_pretty(&Value::Object(backed_up)).unwrap_or_default(),
            );
        }
    }

    if let Some(err) = dns_fix_err {
        return Err(err);
    }

    Ok("已先备份并清理冲突代理环境变量 / 校准 WinINET 端口与物理网卡 DNS（可随时在环境维护撤回）。".into())
}

/// 纯函数判定 Windows 定位隐私隔离状态（供探针与单元测试共用）
pub fn evaluate_location_privacy(
    hklm_val: &str,
    hkcu_val: &str,
    non_packaged_val: &str,
    lfsvc_start: Option<u32>,
    lfsvc_running: bool,
) -> (bool, Vec<String>) {
    let mut issues = Vec::new();
    if hklm_val.eq_ignore_ascii_case("Allow") {
        issues.push("设备级定位开关（HKLM）处于 Allow 开启状态".to_string());
    }
    if hkcu_val.eq_ignore_ascii_case("Allow") {
        issues.push("当前用户定位权限（HKCU）处于 Allow 开启状态".to_string());
    }
    if non_packaged_val.eq_ignore_ascii_case("Allow") {
        issues.push("桌面应用（Claude / Electron NonPackaged）允许访问系统定位".to_string());
    }
    if lfsvc_running {
        issues.push("Windows 地理定位服务（lfsvc）仍在后台运行".to_string());
    } else if let Some(start) = lfsvc_start {
        if start != 4 {
            issues.push(format!(
                "Windows 地理定位服务（lfsvc）未禁用（Start={start}，可能被系统组件拉起）"
            ));
        }
    }
    (issues.is_empty(), issues)
}

#[derive(Debug, Clone)]
struct LocationPrivacyState {
    hklm_val: String,
    hkcu_val: String,
    non_packaged_val: String,
    lfsvc_start: Option<u32>,
    lfsvc_running: bool,
}

fn inspect_windows_location_privacy_sync() -> LocationPrivacyState {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        use winreg::RegKey;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const CONSENT_SUBKEY: &str =
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location";
        const NON_PACKAGED_SUBKEY: &str =
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged";

        let hklm_val = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(CONSENT_SUBKEY)
            .ok()
            .and_then(|k| k.get_value::<String, _>("Value").ok())
            .unwrap_or_else(|| "NotSet".into());
        let hkcu_val = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(CONSENT_SUBKEY)
            .ok()
            .and_then(|k| k.get_value::<String, _>("Value").ok())
            .unwrap_or_else(|| "NotSet".into());
        let non_packaged_val = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(NON_PACKAGED_SUBKEY)
            .ok()
            .and_then(|k| k.get_value::<String, _>("Value").ok())
            .unwrap_or_else(|| "NotSet".into());

        let lfsvc_start = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Services\lfsvc")
            .ok()
            .and_then(|k| k.get_value::<u32, _>("Start").ok());

        let lfsvc_running = Command::new("sc")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["query", "lfsvc"])
            .output()
            .ok()
            .map(|out| {
                let stdout = String::from_utf8_lossy(&out.stdout).to_uppercase();
                stdout.contains("RUNNING")
            })
            .unwrap_or(false);

        LocationPrivacyState {
            hklm_val,
            hkcu_val,
            non_packaged_val,
            lfsvc_start,
            lfsvc_running,
        }
    }

    #[cfg(not(windows))]
    {
        LocationPrivacyState {
            hklm_val: "Deny".into(),
            hkcu_val: "Deny".into(),
            non_packaged_val: "Deny".into(),
            lfsvc_start: Some(4),
            lfsvc_running: false,
        }
    }
}

/// 检查 Windows 系统定位权限与地理定位服务（lfsvc）是否已关闭，防止 Claude / Chromium 获取本地真实位置
async fn probe_windows_location_privacy() -> PreflightItem {
    let st = tokio::task::spawn_blocking(inspect_windows_location_privacy_sync)
        .await
        .unwrap_or(LocationPrivacyState {
            hklm_val: "Unknown".into(),
            hkcu_val: "Unknown".into(),
            non_packaged_val: "Unknown".into(),
            lfsvc_start: None,
            lfsvc_running: false,
        });

    let (passed, issues) = evaluate_location_privacy(
        &st.hklm_val,
        &st.hkcu_val,
        &st.non_packaged_val,
        st.lfsvc_start,
        st.lfsvc_running,
    );

    let start_label = match st.lfsvc_start {
        Some(4) => "Disabled (4 · 已禁用)".to_string(),
        Some(3) => "Manual (3 · 手动)".to_string(),
        Some(2) => "Automatic (2 · 自动)".to_string(),
        Some(other) => format!("Mode ({other})"),
        None => "NotFound".to_string(),
    };

    let summary = if passed {
        "Windows 系统/用户/桌面应用定位权限均已 Deny，且 lfsvc 地理定位服务已禁用停运".into()
    } else {
        format!(
            "存在 {} 项系统定位泄漏风险（{}），建议一键关闭防 Claude 获取本地位置",
            issues.len(),
            issues[0]
        )
    };

    let evidence = format!(
        "1. 设备级定位 (HKLM ConsentStore\\location): {}\n2. 当前用户定位 (HKCU ConsentStore\\location): {}\n3. 桌面应用定位 (HKCU ...\\NonPackaged): {}\n4. 地理定位服务 (lfsvc): {} | 状态: {}",
        st.hklm_val,
        st.hkcu_val,
        st.non_packaged_val,
        start_label,
        if st.lfsvc_running { "RUNNING (运行中!)" } else { "STOPPED (已停止)" }
    );

    PreflightItem {
        id: "sys_location".into(),
        part: CheckPart::Must,
        cat: "2. Windows 系统环境（改系统）".into(),
        icon: "location".into(),
        mode: "管理员一键 + 实测".into(),
        title: "Windows 系统定位服务关闭".into(),
        status: if passed {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        },
        summary,
        evidence,
        guide: if passed {
            "Windows 设备级、用户级、桌面应用定位权限与地理定位服务（lfsvc）均已彻底关闭，可防止 Electron/Chromium 经系统 Wi-Fi 定位暴露真实位置。".into()
        } else {
            "仅关闭 Windows 定位权限（HKLM/HKCU/NonPackaged 置为 Deny）并停止/禁用地理定位服务 lfsvc，绝不改 Clash 配置、绝不碰 Claude 目录；完成后自动复测变绿。".into()
        },
        fix_label: if passed {
            None
        } else {
            Some("管理员一键关闭系统定位并禁用 lfsvc".into())
        },
        is_kill_item: false,
        is_failover: false,
    }
}

fn fix_windows_location_privacy() -> Result<String, String> {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        // 先锁定 First-Write-Wins 基线快照，供用户随时一键撤回
        crate::rollback::capture_location_baseline_if_needed();

        const CONSENT_SUBKEY: &str =
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location";
        const NON_PACKAGED_SUBKEY: &str =
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged";

        // 1. 当前用户级与桌面应用级定位权限（无需 UAC，立即可写）
        if let Ok((key, _)) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(CONSENT_SUBKEY) {
            let _ = key.set_value("Value", &"Deny");
        }
        if let Ok((key, _)) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(NON_PACKAGED_SUBKEY) {
            let _ = key.set_value("Value", &"Deny");
        }

        // 2. 管理员态直跑、非管理员态提权并校验退出码，关闭设备级定位（HKLM）并停止/禁用 lfsvc
        let ps_inner = concat!(
            "$p = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\location'; ",
            "if (!(Test-Path $p)) { New-Item -Path $p -Force | Out-Null }; ",
            "Set-ItemProperty -Path $p -Name Value -Value 'Deny' -Force; ",
            "Stop-Service -Name lfsvc -Force -ErrorAction SilentlyContinue; ",
            "Set-Service -Name lfsvc -StartupType Disabled -ErrorAction SilentlyContinue"
        );
        crate::rollback::run_ps_elevated_checked(ps_inner, "关闭 Windows 设备定位权限与禁用 lfsvc")?;
    }
    Ok("已将系统/用户/桌面应用定位权限设为 Deny，并停止禁用 Windows 地理定位服务 lfsvc（可随时在环境维护一键撤回）。".into())
}

/// 判断网卡是否属于 Clash / Mihomo 动态创建的 TUN 虚拟网卡（每次开关 TUN/重载都会被系统重建并默认勾选 ms_tcpip6）
pub fn is_clash_tun_virtual_adapter(name: &str, description: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    let d = description.trim().to_ascii_lowercase();
    n == "mihomo"
        || n == "clash"
        || n == "meta"
        || n.starts_with("mihomo")
        || n.starts_with("clash")
        || d.contains("wintun")
        || d.contains("mihomo")
        || d.contains("clash")
}

#[cfg(windows)]
fn inspect_windows_ipv6() -> (Vec<String>, Vec<String>, Option<u32>) {
    use std::os::windows::process::CommandExt;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let reg_val = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters")
        .ok()
        .and_then(|k| k.get_value::<u32, _>("DisabledComponents").ok());

    let output = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true } | ForEach-Object { $a = Get-NetAdapter -Name $_.Name -ErrorAction SilentlyContinue; \"$($_.Name)|$($a.InterfaceDescription)\" }",
        ])
        .output();

    let mut physical_enabled = Vec::new();
    let mut tun_ignored = Vec::new();
    if let Ok(out) = output {
        if out.status.success() {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let (name, desc) = trimmed.split_once('|').unwrap_or((trimmed, ""));
                let name = name.trim();
                let desc = desc.trim();
                if name.is_empty() {
                    continue;
                }
                if is_clash_tun_virtual_adapter(name, desc) {
                    tun_ignored.push(name.to_string());
                } else {
                    physical_enabled.push(name.to_string());
                }
            }
        }
    }

    (physical_enabled, tun_ignored, reg_val)
}

#[cfg(not(windows))]
fn inspect_windows_ipv6() -> (Vec<String>, Vec<String>, Option<u32>) {
    (Vec::new(), Vec::new(), None)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClashServiceState {
    Running,
    Stopped,
    NotInstalled,
}

#[cfg(windows)]
fn inspect_clash_verge_service_state() -> ClashServiceState {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = Command::new("sc")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["query", "clash_verge_service"])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let txt = String::from_utf8_lossy(&o.stdout).to_uppercase();
            if txt.contains("RUNNING") {
                ClashServiceState::Running
            } else {
                ClashServiceState::Stopped
            }
        }
        _ => ClashServiceState::NotInstalled,
    }
}

#[cfg(not(windows))]
fn inspect_clash_verge_service_state() -> ClashServiceState {
    ClashServiceState::Running
}

/// 查找 Clash Verge Rev 自带的官方系统服务安装程序（clash-verge-service-install.exe）
fn find_clash_verge_service_installer() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let mut bases: Vec<PathBuf> = Vec::new();
        if let Ok(pf) = std::env::var("ProgramFiles") {
            bases.push(PathBuf::from(pf).join("Clash Verge"));
        }
        if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
            bases.push(PathBuf::from(pf86).join("Clash Verge"));
        }
        if let Some(local_app) = dirs::data_local_dir() {
            bases.push(local_app.join(r"Programs\Clash Verge"));
            bases.push(local_app.join("Clash Verge"));
        }
        for base in bases {
            for rel in [
                r"resources\clash-verge-service-install.exe",
                "clash-verge-service-install.exe",
            ] {
                let p = base.join(rel);
                if p.exists() {
                    return Some(p);
                }
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// 检测 Clash Verge 系统服务状态并仅在「已安装但停止」时尝试拉起；
/// 红线：若服务未安装 (`NotInstalled`)，严禁外部盲目硬调 `clash-verge-service-install.exe` 或提前改写 `verge.yaml` 强杀重启 Clash，
/// 必须明确引导用户先在 Clash Verge「设置 → 服务模式」完成官方安装，避免版本差异引发连续报错或破坏本机代理环境。
#[cfg(windows)]
fn ensure_clash_verge_service_ready() -> Result<bool, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    match inspect_clash_verge_service_state() {
        ClashServiceState::Running => Ok(false),
        ClashServiceState::Stopped => {
            // 进程本身在 Release 下已是管理员，先直接 sc start；若失败再尝试提权启动
            let direct_ok = Command::new("sc")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["start", "clash_verge_service"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !direct_ok {
                let _ = Command::new("powershell")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args([
                        "-NoProfile",
                        "-Command",
                        "Start-Process sc.exe -ArgumentList 'start clash_verge_service' -Verb RunAs -WindowStyle Hidden -Wait",
                    ])
                    .status();
            }
            std::thread::sleep(Duration::from_millis(800));
            if inspect_clash_verge_service_state() == ClashServiceState::Running {
                Ok(true)
            } else {
                Err("检测到 Clash Verge TUN 系统服务已安装但处于停止状态，且自动拉起未成功；请打开 Clash Verge「设置 → 服务模式」重新启动服务后再开启 TUN。".into())
            }
        }
        ClashServiceState::NotInstalled => Err(
            "检测到本机尚未安装 Clash Verge TUN 系统服务（clash_verge_service）。为避免版本不兼容导致反复报错，本工具不会强行盲装服务；请先打开 Clash Verge → 左侧「设置」→「服务模式」点击安装并等待生效，随后返回此处一键开启 TUN。"
                .into(),
        ),
    }
}

#[cfg(not(windows))]
fn ensure_clash_verge_service_ready() -> Result<bool, String> {
    Ok(false)
}

/// 增量 1：独立实测虚拟网卡接管（TUN 模式：Mihomo tun.enable + Wintun/Mihomo 网卡在线 + Clash 服务模式状态）
async fn probe_tun_adapter(mihomo_cfg: Option<&MihomoConfigs>) -> PreflightItem {
    let tun_enable = mihomo_cfg.map(|c| c.tun_enable).unwrap_or(false);
    let (wintun_adapter, svc_state, has_svc_installer) = tokio::task::spawn_blocking(|| {
        (
            inspect_wintun_adapter(),
            inspect_clash_verge_service_state(),
            find_clash_verge_service_installer().is_some(),
        )
    })
    .await
    .unwrap_or((None, ClashServiceState::NotInstalled, false));

    let passed = tun_enable && wintun_adapter.is_some();
    let adapter_txt = wintun_adapter
        .as_deref()
        .unwrap_or("Inactive / Not Found");
    let svc_txt = match svc_state {
        ClashServiceState::Running => "Running (clash_verge_service)",
        ClashServiceState::Stopped => "Installed but Stopped (clash_verge_service)",
        ClashServiceState::NotInstalled => "Not Installed (请先安装 Clash Verge 服务模式)",
    };

    let summary = if passed {
        format!("TUN 已激活 · 虚拟网卡 {adapter_txt} 在线接管全局流量")
    } else if svc_state == ClashServiceState::NotInstalled {
        "未安装 Clash Verge TUN 系统服务，无法接管虚拟网卡流量".into()
    } else if !tun_enable {
        "Mihomo TUN 虚拟网卡未开启，Electron 子进程与退出清理线程可能绕过代理".into()
    } else {
        "Mihomo 已设 tun.enable=true，但未检测到在线的 Wintun/Mihomo 虚拟网卡".into()
    };

    let evidence = format!(
        "Clash Verge Service: {svc_txt}\nMihomo tun.enable: {tun_enable}\nWintun / Mihomo Adapter: {}",
        if wintun_adapter.is_some() {
            format!("Online ({adapter_txt})")
        } else {
            "Inactive".into()
        }
    );

    let (guide, fix_label) = if passed {
        (
            "虚拟网卡已全面接管 Claude 子进程与退出清理线程流量，且与 Clash Verge 配置同步一致。".into(),
            None,
        )
    } else if svc_state == ClashServiceState::NotInstalled {
        let _ = has_svc_installer;
        (
            "检测到尚未安装 Clash Verge TUN 系统服务（clash_verge_service）。为避免版本差异导致反复报错，本工具不会越权盲装；请先打开 Clash Verge → 左侧「设置 → 服务模式」完成官方服务安装，装完后返回点击即可一键开启虚拟网卡。".into(),
            Some("请先在 Clash Verge 安装 TUN 服务（点此唤起 Clash Verge）".into()),
        )
    } else {
        (
            "检测到 Clash Verge 系统服务已就绪。点击下方按钮将自动关闭系统代理（防双开）、写入 verge.yaml 开启虚拟网卡并平滑重启 Clash Verge 一次，重启上线后自动将 GLOBAL 与节点锁回 Claude-Fixed。".into(),
            Some("关闭系统代理并一键开启 Clash TUN（同步锁回策略组）".into()),
        )
    };

    PreflightItem {
        id: "node_tun".into(),
        part: CheckPart::Must,
        cat: "1. 代理与节点（改 Clash 配置）".into(),
        icon: "fw".into(),
        mode: "自动一键".into(),
        title: "虚拟网卡接管（Clash TUN）".into(),
        status: if passed {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        },
        summary,
        evidence,
        guide,
        fix_label,
        is_kill_item: false,
        is_failover: false,
    }
}

#[cfg(windows)]
fn inspect_wintun_adapter() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { ($_.Status -eq 'Up') -and ($_.Name -match 'Mihomo|Clash|Meta|Wintun' -or $_.InterfaceDescription -match 'Wintun|Mihomo|Clash') } | Select-Object -First 1 -ExpandProperty Name",
        ])
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(not(windows))]
fn inspect_wintun_adapter() -> Option<String> {
    None
}

/// 增量 1：独立实测 DNS 防泄漏（Fake-IP：实测 claude.ai 解析落入 198.18.0.0/15）
async fn probe_dns_fake_ip(mihomo_cfg: Option<&MihomoConfigs>) -> PreflightItem {
    let enhanced_mode = mihomo_cfg
        .map(|c| c.dns_enhanced_mode.clone())
        .unwrap_or_else(|| "unknown".into());

    let resolved: Vec<IpAddr> = match tokio::net::lookup_host("claude.ai:443").await {
        Ok(iter) => iter.map(|sa| sa.ip()).collect(),
        Err(_) => Vec::new(),
    };

    let fake_ip_hit = resolved.iter().find_map(|ip| match ip {
        IpAddr::V4(v4) if is_fake_ip_v4(*v4) => Some(*v4),
        _ => None,
    });

    let passed = fake_ip_hit.is_some();
    let ips_preview = if resolved.is_empty() {
        "解析失败".into()
    } else {
        resolved
            .iter()
            .take(3)
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let summary = if passed {
        format!("Fake-IP 生效 · 实测 claude.ai 解析为 {}", fake_ip_hit.unwrap())
    } else {
        format!("实测 claude.ai 解析为 {ips_preview}（未落入 198.18.0.0/15 Fake-IP 网段）")
    };

    let evidence = format!(
        "Mihomo dns.enhanced-mode: {enhanced_mode}\nReal DNS Probe (claude.ai): {ips_preview}\nFake-IP (198.18.0.0/15): {}",
        if fake_ip_hit.is_some() { "MATCHED (OK)" } else { "NOT MATCHED" }
    );

    PreflightItem {
        id: "node_dns".into(),
        part: CheckPart::Must,
        cat: "1. 代理与节点（改 Clash 配置）".into(),
        icon: "dns".into(),
        mode: "向导 + 实测验收".into(),
        title: "DNS 防泄漏（Clash Fake-IP）".into(),
        status: if passed {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        },
        summary,
        evidence,
        guide: if passed {
            "已通过真实 DNS 解析探针验收，无本地宽带 DNS 泄漏。".into()
        } else {
            "仅将 Fake-IP DNS 段写入 Clash 覆写配置，重载后工具真实解析 claude.ai 确认返回 198.18.x.x 才变绿。".into()
        },
        fix_label: if passed {
            None
        } else {
            Some("写入 Fake-IP 配置并实测验收 DNS".into())
        },
        is_kill_item: false,
        is_failover: false,
    }
}

async fn probe_local_ban_contamination() -> (PreflightItem, bool) {
    let (scanned_files, hits, has_kyc_notice) =
        tokio::task::spawn_blocking(scan_claude_logs_for_ban)
            .await
            .unwrap_or_else(|_| (0, Vec::new(), false));

    let passed = hits.is_empty();
    let summary = if passed {
        if has_kyc_notice {
            format!("已扫描 {scanned_files} 份本地日志，0 确认封号残留（另有身份验证/权限暂限记录，详见日志分析）")
        } else if scanned_files == 0 {
            "未发现本地 Claude Desktop 日志污染残留（0 封号记录）".into()
        } else {
            format!("已扫描 {scanned_files} 份本地日志，0 封号污染残留")
        }
    } else {
        format!("[{FD_ERR_LOG_POLLUTE}] 检测到本地确认封号/地区封锁污染残留：{}", hits.join(", "))
    };

    let evidence = format!(
        "Scanned Log Files: {scanned_files} (Electron + MSIX LocalCache)\nConfirmed Ban / Region Contamination Hits: {}\nKYC / Permission-Pending (len=164) Notice: {}",
        if hits.is_empty() {
            "0 (Clean)".into()
        } else {
            format!("{} ({FD_ERR_LOG_POLLUTE})", hits.join(", "))
        },
        if has_kyc_notice {
            "存在身份验证/权限暂限记录（非封号，不阻断启动，详见日志分析）"
        } else {
            "无"
        }
    );

    (
        PreflightItem {
            id: "claude_ban".into(),
            part: CheckPart::Must,
            cat: "3. Claude 本机卫生（改 Claude）".into(),
            icon: "ban".into(),
            mode: "自动一键".into(),
            title: "本地封号污染残留审查".into(),
            status: if passed {
                CheckStatus::Ok
            } else {
                CheckStatus::Fail
            },
            summary,
            evidence,
            guide: if passed {
                if has_kyc_notice {
                    "本地未检出确认封号记录；日志中存在身份验证（KYC）或 OAuth 权限暂限（len=164）提示，请前往「日志分析」查看详情，或按需到「环境维护」退出登录并清理目录。".into()
                } else {
                    "本地 Claude 目录纯净，未发现确认封号、强制吊销或地区封锁污染残留。".into()
                }
            } else {
                "点击下方打开「透明分项清理确认弹窗」，可逐项勾选需备份并清理的 Cookie / 日志 / 缓存（默认保留 MCP 配置与 VM 镜像），清理一次即可同时消除封号残留与混号记录。".into()
            },
            fix_label: if passed {
                None
            } else {
                Some("预览并分项清理（备份）本地目录".into())
            },
            is_kill_item: false,
            is_failover: false,
        },
        !passed,
    )
}

fn scan_claude_logs_for_ban() -> (usize, Vec<String>, bool) {
    let mut log_paths: Vec<PathBuf> = Vec::new();
    if let Some(local) = dirs::data_local_dir() {
        log_paths.push(local.join("Claude").join("logs"));
        let packages = local.join("Packages");
        if let Ok(entries) = fs::read_dir(packages) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_lowercase();
                if name.contains("claude") || name.contains("anthropic") {
                    log_paths.push(e.path().join("LocalCache").join("Roaming").join("Claude").join("logs"));
                    log_paths.push(e.path().join("LocalCache").join("Local").join("Claude").join("logs"));
                }
            }
        }
    }
    if let Some(roaming) = dirs::config_dir() {
        log_paths.push(roaming.join("Claude").join("logs"));
    }

    let mut scanned = 0usize;
    let mut hit_set: Vec<String> = Vec::new();
    let mut has_kyc_notice = false;

    for dir in log_paths {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
                continue;
            };
            if !ext.eq_ignore_ascii_case("log") {
                continue;
            }
            scanned += 1;
            if let Ok(bytes) = fs::read(&path) {
                let slice = if bytes.len() > 2 * 1024 * 1024 {
                    &bytes[bytes.len() - 2 * 1024 * 1024..]
                } else {
                    &bytes
                };
                let text = String::from_utf8_lossy(slice);
                if scan_text_for_kyc_or_perm_notice(&text) {
                    has_kyc_notice = true;
                }
                for hit in scan_text_for_ban_contamination(&text) {
                    if !hit_set.iter().any(|x| x == hit) {
                        hit_set.push(hit.to_string());
                    }
                }
            }
        }
    }

    (scanned, hit_set, has_kyc_notice)
}

/// 增量 16：单号卫生锁（防混号与跨 orgId 竞态；仅当实测检出多个不同账号/跨号竞态时拦截，绝不因单号 KYC/auth_error 误杀）
async fn probe_single_account_lock(bound_primary_org: Option<&str>) -> (PreflightItem, bool, Option<String>) {
    let audit = tokio::task::spawn_blocking(crate::watchdog::audit_claude_logs_for_accounts)
        .await
        .unwrap_or_default();

    let latest_org = audit.unique_org_ids.last().cloned();
    let multi_orgs = audit.unique_org_ids.len() > 1 || audit.unique_account_ids.len() > 1;
    let bound_mismatch = match (bound_primary_org, latest_org.as_deref()) {
        (Some(bound), Some(cur)) if !bound.is_empty() && bound != cur => true,
        _ => false,
    };
    let has_cross_race = !audit.cross_account_hits.is_empty();
    let has_restricted_mix = multi_orgs && !audit.restricted_org_ids.is_empty();

    // 仅当真正出现多账号（>=2 个不同 orgId / accountId、与绑定主号不符、或跨号竞态）时才触发单号卫生锁！
    // 单号自己的 KYC / Verification Portal / OAuth 403 len=164/156 权限暂限绝不触发单号冲突！
    let conflict = multi_orgs || bound_mismatch || has_cross_race;

    let bound_display = bound_primary_org
        .filter(|s| !s.is_empty())
        .or(latest_org.as_deref())
        .unwrap_or("尚未登录");

    let summary = if !conflict {
        if latest_org.is_some() {
            format!("已锁定唯一主号 {bound_display}... · 无多号混登或跨 orgId 竞态")
        } else {
            "未检测到多账号混登或跨 orgId 竞态记录 · 单号状态纯净".into()
        }
    } else if has_cross_race {
        format!("[{FD_ERR_LOG_POLLUTE}] 检出跨账号 orgId 竞态请求，高危连坐风险！需二选一确认处理")
    } else if has_restricted_mix {
        format!(
            "[{FD_ERR_LOG_POLLUTE}] 最高危连坐预警：本机混登 {} 个账号且包含已受限/待验证号（{}），极易拖累主力号触发同款审核！",
            audit.unique_org_ids.len().max(audit.unique_account_ids.len()),
            audit.restricted_org_ids.join(", ")
        )
    } else if multi_orgs {
        format!(
            "[{FD_ERR_LOG_POLLUTE}] 同一本机日志检出多账号混登（orgId: {} / accountId: {}），需二选一确认",
            audit.unique_org_ids.len(),
            audit.unique_account_ids.len()
        )
    } else {
        format!(
            "[{FD_ERR_LOG_POLLUTE}] 当前登录 orgId（{}...）与已绑定主号（{}...）不一致，需二选一确认",
            latest_org.as_deref().unwrap_or("?"),
            bound_primary_org.unwrap_or("?")
        )
    };

    let mut ev_lines = vec![
        format!("Scanned Claude Log Files: {}", audit.scanned_files),
        format!("Bound Primary orgId: {bound_display}"),
        format!(
            "Observed Unique orgIds ({}): {}",
            audit.unique_org_ids.len(),
            if audit.unique_org_ids.is_empty() {
                "None".into()
            } else {
                audit.unique_org_ids.join(", ")
            }
        ),
        format!(
            "Observed Unique accountIds ({}): {}",
            audit.unique_account_ids.len(),
            if audit.unique_account_ids.is_empty() {
                "None".into()
            } else {
                audit.unique_account_ids.join(", ")
            }
        ),
        format!("Cross-orgId Race Hits: {}", audit.cross_account_hits.len()),
    ];
    if !audit.restricted_org_ids.is_empty() {
        ev_lines.push(format!(
            "Restricted / Portal-Verify orgIds: {}",
            audit.restricted_org_ids.join(", ")
        ));
    }
    if !audit.auth_403_hits.is_empty() {
        ev_lines.push(format!(
            "Single-Account KYC/Auth Notice (不计为混号冲突): {} 条，详见日志分析",
            audit.auth_403_hits.len()
        ));
    }
    if let Some(sample) = audit.cross_account_hits.first() {
        ev_lines.push(format!("Latest Cross-Account Sample: {sample}"));
    }

    (
        PreflightItem {
            id: "claude_acct".into(),
            part: CheckPart::Must,
            cat: "3. Claude 本机卫生（改 Claude）".into(),
            icon: "userLock".into(),
            mode: "引导确认".into(),
            title: "单号卫生锁（防混号与跨 orgId）".into(),
            status: if conflict {
                CheckStatus::Fail
            } else {
                CheckStatus::Ok
            },
            summary,
            evidence: ev_lines.join("\n"),
            guide: if has_restricted_mix {
                "最高危连坐警告：同一本机安装目录（含经典 Electron 与微软商店 MSIX 沙箱）内曾登录已触发验证限制/受限的旧号，同时混登了其他主力号，极易触发同机连坐！强烈建议立即点击下方二选一选择「退出登录并原子备份清理污染目录（含 MSIX）」，清理干净后再仅登录单一健康主力号；切勿轻易跳过或绑定。".into()
            } else if conflict {
                "检测到多账号混登或跨 orgId 竞态，绝不擅自乱删你的账号目录。点击下方二选一确认：① 退出登录并原子备份清理污染目录（含 MSIX）；② 明确永久更换主力新号且环境干净 → 更新绑定主号。".into()
            } else {
                "通过提取本机全部唯一 orgId 与跨号竞态记录验证当前为纯净单号；单号自身身份验证（KYC）不会误触此锁。".into()
            },
            fix_label: if conflict {
                Some("引导处理单号冲突（二选一确认）".into())
            } else {
                None
            },
            is_kill_item: false,
            is_failover: false,
        },
        conflict,
        latest_org,
    )
}

fn claude_settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude").join("settings.json"))
}

fn claude_telemetry_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude").join("telemetry"))
}

fn dir_size_bytes(path: &Path) -> u64 {
    dir_size_bytes_bounded(path, 0)
}

fn dir_size_bytes_bounded(path: &Path, depth: usize) -> u64 {
    if depth > 16 {
        return 0;
    }
    let Ok(root_meta) = fs::symlink_metadata(path) else {
        return 0;
    };
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return 0;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| {
            let p = e.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                return 0;
            };
            if meta.file_type().is_symlink() {
                return 0;
            }
            if meta.is_dir() {
                dir_size_bytes_bounded(&p, depth + 1)
            } else {
                meta.len()
            }
        })
        .sum()
}

async fn probe_claude_privacy_settings() -> PreflightItem {
    let settings_path = claude_settings_path();
    let telemetry_dir = claude_telemetry_dir();

    let (disable_nonessential, disable_err) = match &settings_path {
        Some(p) => match fs::read_to_string(p)
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        {
            Some(val) => {
                let env = val.get("env").and_then(|e| e.as_object());
                let v1 = env
                    .and_then(|m| m.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"))
                    .and_then(|v| v.as_str())
                    == Some("1");
                let v2 = env
                    .and_then(|m| m.get("DISABLE_ERROR_REPORTING"))
                    .and_then(|v| v.as_str())
                    == Some("1");
                (v1, v2)
            }
            None => (false, false),
        },
        None => (false, false),
    };

    let telemetry_bytes = telemetry_dir
        .as_deref()
        .map(dir_size_bytes)
        .unwrap_or(0);

    let passed = disable_nonessential && disable_err && telemetry_bytes == 0;

    let summary = if passed {
        "已写入官方降噪环境变量并清空 ~/.claude/telemetry/ 缓存".into()
    } else if !disable_nonessential || !disable_err {
        "~/.claude/settings.json 尚未关闭非必要遥测与错误上报".into()
    } else {
        format!("隐私开关已开启，但 ~/.claude/telemetry/ 仍有 {telemetry_bytes} B 离线缓存待清")
    };

    let evidence = format!(
        "File: ~/.claude/settings.json\nCLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: {}\nDISABLE_ERROR_REPORTING: {}\nTelemetry Cache (~/.claude/telemetry): {} B",
        if disable_nonessential { "\"1\" (OK)" } else { "Missing" },
        if disable_err { "\"1\" (OK)" } else { "Missing" },
        telemetry_bytes
    );

    PreflightItem {
        id: "claude_tel".into(),
        part: CheckPart::Must,
        cat: "3. Claude 本机卫生（改 Claude）".into(),
        icon: "privacy".into(),
        mode: "自动一键".into(),
        title: "官方隐私降噪开关 & 遥测缓存".into(),
        status: if passed {
            CheckStatus::Ok
        } else {
            CheckStatus::Fail
        },
        summary,
        evidence,
        guide: if passed {
            "官方隐私降噪环境变量与离线遥测清理已实测生效；未触碰账号登录态与聊天记录。".into()
        } else {
            "仅无损合并写入 ~/.claude/settings.json 官方降噪开关并清空 ~/.claude/telemetry/ 缓存，绝不碰账号登录态与聊天记录。".into()
        },
        fix_label: if passed {
            None
        } else {
            Some("一键写入隐私降噪并清空缓存".into())
        },
        is_kill_item: false,
        is_failover: false,
    }
}

fn build_startup_item(audit: &crate::state::StartupAuditReport) -> PreflightItem {
    let lines: Vec<String> = audit
        .entries
        .iter()
        .map(|e| format!("{}: {}", e.app, if e.enabled { "已开启自启" } else { "未开启" }))
        .collect();

    let risk = audit.claude_autostart_risk;
    PreflightItem {
        id: "opt_boot".into(),
        part: CheckPart::Opt,
        cat: "系统辅助优化".into(),
        icon: "startup".into(),
        mode: "只读风险监测".into(),
        title: "开机启动项顺序风险检查（Clash / Claude）".into(),
        status: if risk {
            CheckStatus::Warn
        } else {
            CheckStatus::Ok
        },
        summary: if risk {
            "检测到 Claude 已设开机自启（我们不删除启动项，仅提示早于代理启动的裸奔风险）".into()
        } else {
            "已只读审计 Windows 启动项，未发现 Claude 抢跑开机自启风险".into()
        },
        evidence: lines.join("\n"),
        guide: "我们绝不擅自修改或删除你的开机启动项；若需调整，可点击下方打开 Windows「启动应用」管理页手动关闭 Claude 自启。".into(),
        fix_label: if risk {
            Some("打开 Windows 启动应用管理页".into())
        } else {
            None
        },
        is_kill_item: false,
        is_failover: false,
    }
}

async fn probe_ntp_drift() -> PreflightItem {
    let res = tokio::task::spawn_blocking(query_sntp_drift)
        .await
        .unwrap_or_else(|_| Err("NTP 探测线程异常".into()));

    match res {
        Ok((drift, server)) => {
            let passed = drift.abs() <= 30.0;
            PreflightItem {
                id: "opt_ntp".into(),
                part: CheckPart::Opt,
                cat: "系统辅助优化".into(),
                icon: "clock".into(),
                mode: "管理员一键".into(),
                title: "系统时钟 NTP 同步偏差".into(),
                status: if passed {
                    CheckStatus::Ok
                } else {
                    CheckStatus::Warn
                },
                summary: format!("实测 UTC 偏差 {:+.2}s（正常范围 ±30s）", drift),
                evidence: format!("NTP Server: {server}\nUTC Drift: {:+.2} s", drift),
                guide: if passed {
                    "本机系统时钟与国际标准时间同步精准，无 OAuth/JWT 时间漂移风险。".into()
                } else {
                    "系统时钟偏差超过 ±30 秒，可能导致 Anthropic OAuth 令牌校验失败，请在 Windows 设置中立即同步时间。".into()
                },
                fix_label: if passed {
                    None
                } else {
                    Some("管理员一键 NTP 校准对时".into())
                },
                is_kill_item: false,
                is_failover: false,
            }
        }
        Err(err) => PreflightItem {
            id: "opt_ntp".into(),
            part: CheckPart::Opt,
            cat: "系统辅助优化".into(),
            icon: "clock".into(),
            mode: "管理员一键".into(),
            title: "系统时钟 NTP 同步偏差".into(),
            status: CheckStatus::Warn,
            summary: "NTP UDP 123 探测未响应（可点下方触发 Windows 自动对时）".into(),
            evidence: format!("SNTP Probe Error: {err}"),
            guide: "若网络拦截 UDP 123 端口，可点击下方调用 Windows w32tm /resync /force 执行系统对时。".into(),
            fix_label: Some("管理员一键 NTP 校准对时".into()),
            is_kill_item: false,
            is_failover: false,
        },
    }
}

fn query_sntp_drift() -> Result<(f64, &'static str), String> {
    let servers = ["time.cloudflare.com:123", "pool.ntp.org:123", "time.windows.com:123"];
    let mut packet = [0u8; 48];
    packet[0] = 0x1b;

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("绑定 UDP 失败: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_millis(1800)))
        .map_err(|e| format!("设置超时失败: {e}"))?;
    sock.set_write_timeout(Some(Duration::from_millis(1000)))
        .map_err(|e| format!("设置写超时失败: {e}"))?;

    for server in servers {
        if sock.send_to(&packet, server).is_ok() {
            let mut buf = [0u8; 48];
            if let Ok((len, _)) = sock.recv_from(&mut buf) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                if let Ok(drift) = parse_ntp_drift_seconds(&buf[..len], now) {
                    return Ok((drift, server));
                }
            }
        }
    }

    Err("所有 NTP 服务器均超时未响应".into())
}

/// 增量 16 & 问题 10：防火墙 Kill Switch 权限就绪（检测免 UAC 守护计划任务 + FDClaudeGuard_KillSwitch_* 规则读写闭环）
async fn probe_firewall_ready() -> PreflightItem {
    let (_task_installed, probe_writable, detail) =
        tokio::task::spawn_blocking(crate::killswitch::check_firewall_helper_ready)
            .await
            .unwrap_or_else(|_| (false, false, "Probe error".into()));

    // 必须实测当前进程真能写入 Defender 防火墙规则才报绿，绝不因历史计划任务存在而假绿
    let ready = probe_writable;

    PreflightItem {
        id: "opt_fw".into(),
        part: CheckPart::Opt,
        cat: "系统辅助优化".into(),
        icon: "fw".into(),
        mode: "管理员一键".into(),
        title: "防火墙 Kill Switch 权限就绪".into(),
        status: if ready {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        summary: if ready {
            "MSIX 路径已追踪 · 实测可无感读写 FDClaudeGuard_KillSwitch_* 规则".into()
        } else {
            "尚未安装免 UAC 守护计划任务，紧急断流可能触发系统弹窗确认".into()
        },
        evidence: detail,
        guide: if ready {
            "防火墙无感守护权限已就绪；卸载本工具或点击「防自锁救援」时会自动清空全部 FDClaudeGuard_KillSwitch_* 规则。".into()
        } else {
            "点击下方安装本地免 UAC 守护计划任务并实测读写一条探针规则，确保紧急断流可毫秒级无感封死出站；卸载软件时自动清空全部规则。".into()
        },
        fix_label: if ready {
            None
        } else {
            Some("安装免 UAC 守护权限并实测".into())
        },
        is_kill_item: false,
        is_failover: false,
    }
}

/// 检查本机已安装的 Chrome / Edge 是否已锁定 WebRTC 防泄露官方策略（disable_non_proxied_udp）
async fn probe_browser_webrtc_policy() -> PreflightItem {
    let report = tokio::task::spawn_blocking(inspect_browser_webrtc_sync)
        .await
        .unwrap_or_else(|_| (true, vec!["浏览器策略探测线程异常".into()], 0));
    let (all_locked, lines, unlocked_count) = report;

    PreflightItem {
        id: "opt_webrtc".into(),
        part: CheckPart::Opt,
        cat: "系统辅助优化".into(),
        icon: "privacy".into(),
        mode: "管理员一键".into(),
        title: "浏览器 WebRTC 防泄露策略".into(),
        status: if all_locked {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        summary: if all_locked {
            "本机已安装的 Chrome / Edge 均已锁定 WebRTC 防直连 UDP 泄露策略".into()
        } else {
            format!(
                "检测到 {unlocked_count} 款浏览器未锁定 disable_non_proxied_udp，网页登录存在 IP 泄露风险"
            )
        },
        evidence: lines.join("\n"),
        guide: if all_locked {
            "Chrome / Edge 已锁定 WebRtcIPHandling = disable_non_proxied_udp，OAuth 回调与网页版访问 claude.ai 不会经直连 UDP 暴露真实本地或公网 IP。".into()
        } else {
            "写入 Chrome / Edge 官方策略 WebRtcIPHandling = disable_non_proxied_udp（如 HKCU 受系统权限限制将自动提权写入 HKLM，重启浏览器即生效并自动复测变绿）。".into()
        },
        fix_label: if all_locked {
            None
        } else {
            Some("一键锁死 Chrome / Edge WebRTC 防泄露".into())
        },
        is_kill_item: false,
        is_failover: false,
    }
}

#[cfg(windows)]
fn detect_installed_chromium_browsers() -> Vec<(&'static str, &'static str)> {
    let mut found = Vec::new();
    let local_app = dirs::data_local_dir().unwrap_or_default();
    let prog_files = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
    let prog_x86 =
        std::env::var("ProgramFiles(x86)").unwrap_or_else(|_| r"C:\Program Files (x86)".into());

    let chrome_installed = local_app.join(r"Google\Chrome\User Data").exists()
        || Path::new(&prog_files).join(r"Google\Chrome\Application\chrome.exe").exists()
        || Path::new(&prog_x86).join(r"Google\Chrome\Application\chrome.exe").exists();
    if chrome_installed {
        found.push(("Google Chrome", r"Software\Policies\Google\Chrome"));
    }

    let edge_installed = local_app.join(r"Microsoft\Edge\User Data").exists()
        || Path::new(&prog_files).join(r"Microsoft\Edge\Application\msedge.exe").exists()
        || Path::new(&prog_x86).join(r"Microsoft\Edge\Application\msedge.exe").exists();
    if edge_installed {
        found.push(("Microsoft Edge", r"Software\Policies\Microsoft\Edge"));
    }
    found
}

#[cfg(windows)]
fn inspect_browser_webrtc_sync() -> (bool, Vec<String>, usize) {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    let browsers = detect_installed_chromium_browsers();
    if browsers.is_empty() {
        return (
            true,
            vec!["未检测到本机安装 Chrome 或 Edge，无需配置 WebRTC 策略。".into()],
            0,
        );
    }

    let mut lines = Vec::new();
    let mut unlocked = 0usize;
    for (idx, (label, subkey)) in browsers.iter().enumerate() {
        let hkcu_val = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(subkey)
            .ok()
            .and_then(|k| k.get_value::<String, _>("WebRtcIPHandling").ok());
        let hklm_val = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(subkey)
            .ok()
            .and_then(|k| k.get_value::<String, _>("WebRtcIPHandling").ok());
        let effective = hkcu_val.or(hklm_val);
        let ok = effective
            .as_deref()
            .map(|v| v.eq_ignore_ascii_case("disable_non_proxied_udp"))
            .unwrap_or(false);
        if !ok {
            unlocked += 1;
        }
        lines.push(format!(
            "{}. {label} (已安装): WebRtcIPHandling = {}",
            idx + 1,
            effective.unwrap_or_else(|| "Not Set (未锁定)".into())
        ));
    }
    lines.push(r"策略路径: HKLM / HKCU\Software\Policies\{Google\Chrome, Microsoft\Edge}".into());
    (unlocked == 0, lines, unlocked)
}

#[cfg(not(windows))]
fn inspect_browser_webrtc_sync() -> (bool, Vec<String>, usize) {
    (true, vec!["Non-Windows host".into()], 0)
}

fn fix_browser_webrtc_policy() -> Result<String, String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let browsers = detect_installed_chromium_browsers();
        if browsers.is_empty() {
            return Ok("未检测到需要配置的 Chromium 浏览器。".into());
        }

        // 先锁定 First-Write-Wins 基线快照，供用户随时一键清除组策略恢复浏览器原貌
        crate::rollback::capture_webrtc_baseline_if_needed(&browsers);

        // 1. 优先尝试无弹窗写入 HKCU\Software\Policies；若受系统 ACL 拒绝访问 (os error 5)，自动转管理员写 HKLM
        let mut hkcu_ok = Vec::new();
        let mut need_elevated: Vec<(&'static str, &'static str)> = Vec::new();
        for (label, subkey) in &browsers {
            let res = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(subkey)
                .and_then(|(key, _)| key.set_value("WebRtcIPHandling", &"disable_non_proxied_udp"));
            if res.is_ok() {
                hkcu_ok.push(*label);
            } else {
                need_elevated.push((*label, *subkey));
            }
        }

        if need_elevated.is_empty() {
            return Ok(format!(
                "已为 {} 写入官方防泄露策略 WebRtcIPHandling=disable_non_proxied_udp（重启浏览器即生效）。",
                hkcu_ok.join(" / ")
            ));
        }

        // 2. 通过无黑窗管理员提权写入 HKLM\Software\Policies（兼容 Windows 10/11 默认锁死 HKCU\Policies ACL 的场景）
        let mut ps_cmds = Vec::new();
        for (_, subkey) in &need_elevated {
            let reg_path = format!(r"HKLM:\{subkey}");
            ps_cmds.push(format!(
                "New-Item -Path '{reg_path}' -Force | Out-Null; Set-ItemProperty -Path '{reg_path}' -Name 'WebRtcIPHandling' -Value 'disable_non_proxied_udp' -Type String"
            ));
        }
        let inner = ps_cmds.join("; ");
        let elevated = format!(
            "Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile -Command \"{inner}\"'"
        );
        let status = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-NoProfile", "-Command", &elevated])
            .status()
            .map_err(|e| format!("拉起管理员权限写入浏览器策略失败: {e}"))?;

        // 3. 写入后立刻真实回读验证（若用户点取消 UAC 绝不报假成功）
        let (all_locked, _, remaining) = inspect_browser_webrtc_sync();
        if !status.success() || !all_locked {
            return Err(format!(
                "未能写入浏览器 WebRTC 策略（仍有 {remaining} 款浏览器未锁定，请确认已同意 UAC 管理员授权）。"
            ));
        }

        let names: Vec<&str> = browsers.iter().map(|(l, _)| *l).collect();
        Ok(format!(
            "已通过管理员权限为 {} 写入系统级策略 WebRtcIPHandling=disable_non_proxied_udp 并实测生效（重启浏览器生效）。",
            names.join(" / ")
        ))
    }
    #[cfg(not(windows))]
    {
        Ok("非 Windows 环境跳过注册表写入。".into())
    }
}

/// 返回指定国家常见的 UTC 偏移小时区间（用于评估系统时区与出口地区时差）
pub fn country_utc_offset_range(country_code: &str) -> Option<(i32, i32, &'static str)> {
    match country_code.trim().to_uppercase().as_str() {
        "JP" | "KR" => Some((9, 9, "UTC+9")),
        "SG" | "TW" | "MY" | "PH" => Some((8, 8, "UTC+8")),
        "AU" => Some((8, 11, "UTC+8 ~ UTC+11")),
        "NZ" => Some((12, 13, "UTC+12 ~ UTC+13")),
        "TH" | "VN" | "ID" => Some((7, 8, "UTC+7 ~ UTC+8")),
        "IN" => Some((5, 6, "UTC+5:30")),
        "GB" | "IE" | "PT" => Some((0, 1, "UTC+0 ~ UTC+1")),
        "DE" | "FR" | "NL" | "IT" | "ES" | "SE" | "CH" | "PL" | "NO" => Some((1, 2, "UTC+1 ~ UTC+2")),
        "US" | "CA" => Some((-8, -4, "UTC-8 ~ UTC-4")),
        "BR" | "AR" => Some((-4, -3, "UTC-4 ~ UTC-3")),
        _ => None,
    }
}

/// 计算本机 UTC 偏移小时与目标国家时区范围的最小绝对时差（纯函数，供单测复用）
pub fn compute_timezone_hour_gap(local_utc_hours: i32, country_code: &str) -> Option<(i32, &'static str)> {
    let (min_h, max_h, range_label) = country_utc_offset_range(country_code)?;
    let gap = if local_utc_hours < min_h {
        min_h - local_utc_hours
    } else if local_utc_hours > max_h {
        local_utc_hours - max_h
    } else {
        0
    };
    Some((gap, range_label))
}

/// 建议优化：只读检查 Windows 系统时区与当前出口国家时区是否差异过大（绝不强改用户时钟）
fn probe_system_timezone_consistency(region_code: &str) -> PreflightItem {
    let local_offset_secs = chrono::Local::now().offset().local_minus_utc();
    let local_hours = (local_offset_secs as f64 / 3600.0).round() as i32;
    let local_utc_str = if local_hours >= 0 {
        format!("UTC+{local_hours}")
    } else {
        format!("UTC{local_hours}")
    };

    #[cfg(windows)]
    let tz_name = {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        use winreg::RegKey;
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation")
            .ok()
            .and_then(|k| k.get_value::<String, _>("TimeZoneKeyName").ok())
            .unwrap_or_else(|| local_utc_str.clone())
    };
    #[cfg(not(windows))]
    let tz_name = local_utc_str.clone();

    let cc = region_code.trim().to_uppercase();
    match compute_timezone_hour_gap(local_hours, &cc) {
        Some((gap, range_label)) => {
            let matched = gap <= 4;
            PreflightItem {
                id: "opt_tz".into(),
                part: CheckPart::Opt,
                cat: "系统辅助优化".into(),
                icon: "clock".into(),
                mode: "只读风险监测".into(),
                title: "系统时区与出口地区一致性".into(),
                status: if matched {
                    CheckStatus::Ok
                } else {
                    CheckStatus::Warn
                },
                summary: if matched {
                    format!("本机 {local_utc_str} 与出口 {cc}（{range_label}）时差 {gap} 小时，无需调整系统时区")
                } else {
                    format!(
                        "本机 {local_utc_str} 与出口 {cc}（{range_label}）相差 {gap} 小时，新号敏感期建议选近时区节点"
                    )
                },
                evidence: format!(
                    "本机系统时区: {tz_name} ({local_utc_str})\n当前锁定出口: {cc} ({range_label})\n最小时差: {gap} 小时（≤ 4h 视为近时区匹配）"
                ),
                guide: if matched {
                    "当前系统时区与出口地区时差在合理范围内，Electron / 网页端读取的本地时区特征自然一致。".into()
                } else {
                    "仅做风险提示，强烈建议保持 Windows 系统时区固定、优先切换近时区合规节点（如新加坡 / 澳洲 / 台湾等）；切勿为了迎合远区节点频繁手动来回修改 Windows 系统时区（例如 UTC+8 与 UTC-7 剧烈跳变反而会触发异常风控特征）。".into()
                },
                fix_label: if matched {
                    None
                } else {
                    Some("打开 Windows 日期与时间设置".into())
                },
                is_kill_item: false,
                is_failover: false,
            }
        }
        None => PreflightItem {
            id: "opt_tz".into(),
            part: CheckPart::Opt,
            cat: "系统辅助优化".into(),
            icon: "clock".into(),
            mode: "只读风险监测".into(),
            title: "系统时区与出口地区一致性".into(),
            status: CheckStatus::Ok,
            summary: format!("本机时区 {local_utc_str}（出口地区待进一步识别，不影响使用）"),
            evidence: format!("本机系统时区: {tz_name} ({local_utc_str})\n当前出口地区码: {cc}"),
            guide: "待出口地区识别完成后将自动比对系统时区与出口时差。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
    }
}

/// 已知可能与 Clash 抢夺代理流量或造成网页端/桌面端不同 IP 的浏览器扩展白/黑特征库
pub fn match_proxy_extension_label(ext_id: &str, manifest_name: &str) -> Option<String> {
    let id_lower = ext_id.trim().to_ascii_lowercase();
    let known = match id_lower.as_str() {
        "padekgcemlokbadohgkifijomclgjgif" => Some("Proxy SwitchyOmega"),
        "pfnededegaaopdmhkdmcofjmoldfiped" => Some("Proxy SwitchyOmega (ZeroOmega)"),
        "dpplabbmogkhghncfbfdeeokoefdjegm" => Some("Proxy SwitchySharp"),
        "gcknhkkoolaabfmlnjonogaaifnjlfnp" => Some("FoxyProxy"),
        "eppiocemhmnlbhjplcgkofciiegomcon" => Some("Urban VPN Proxy"),
        "hnmpcagpplmpfojmgmnngilcnanddlhb" => Some("Windscribe VPN"),
        "majdfhpaihoncoakbjgbdhglocklcgno" => Some("VeePN Proxy"),
        "omghfjlpggmjjaagoclmmobgdodcjboh" => Some("Browsec VPN"),
        _ => None,
    };
    if let Some(label) = known {
        return Some(label.to_string());
    }
    let name_lower = manifest_name.to_ascii_lowercase();
    let keywords = [
        "switchyomega",
        "zeroomega",
        "switchysharp",
        "foxyproxy",
        "proxy switcher",
        "smartproxy",
        "vpn proxy",
    ];
    if keywords.iter().any(|k| name_lower.contains(k)) {
        return Some(manifest_name.trim().to_string());
    }
    None
}

/// 建议优化：只读扫描 Chrome / Edge 已安装扩展，检出独立代理/VPN 插件（绝不擅自删除用户插件）
async fn probe_browser_proxy_extensions() -> PreflightItem {
    let (hits, scanned_profiles) = tokio::task::spawn_blocking(scan_browser_proxy_extensions_sync)
        .await
        .unwrap_or_else(|_| (Vec::new(), 0));

    let clean = hits.is_empty();
    PreflightItem {
        id: "opt_browser_ext".into(),
        part: CheckPart::Opt,
        cat: "系统辅助优化".into(),
        icon: "group".into(),
        mode: "只读风险监测".into(),
        title: "浏览器独立代理插件冲突审计".into(),
        status: if clean {
            CheckStatus::Ok
        } else {
            CheckStatus::Warn
        },
        summary: if clean {
            format!("已只读审计 {scanned_profiles} 个 Chrome / Edge 配置档，未发现独立代理分流插件")
        } else {
            format!(
                "检出 {} 个浏览器代理插件（{}），请确认未对 claude.ai 单独分流",
                hits.len(),
                hits[0]
            )
        },
        evidence: if clean {
            format!("Scanned Browser Profiles: {scanned_profiles}\nProxy / VPN Extensions Found: 0")
        } else {
            format!(
                "Scanned Browser Profiles: {scanned_profiles}\nDetected Proxy Extensions:\n{}",
                hits.iter().map(|h| format!("• {h}")).collect::<Vec<_>>().join("\n")
            )
        },
        guide: if clean {
            "浏览器未安装独立代理/VPN 扩展，网页版与桌面端可保持统一走 Clash 出口（三端同 IP）。".into()
        } else {
            "我们绝不擅自删除你的浏览器扩展；请打开对应插件设置，确认未将 claude.ai / anthropic.com 指向与当前 Clash 本地代理不同的端口或独立 VPN。".into()
        },
        fix_label: None,
        is_kill_item: false,
        is_failover: false,
    }
}

fn scan_browser_proxy_extensions_sync() -> (Vec<String>, usize) {
    let mut hits = Vec::new();
    let mut profile_count = 0usize;
    let Some(local_app) = dirs::data_local_dir() else {
        return (hits, 0);
    };

    let roots = [
        ("Chrome", local_app.join(r"Google\Chrome\User Data")),
        ("Edge", local_app.join(r"Microsoft\Edge\User Data")),
    ];

    for (browser_name, user_data) in roots {
        if !user_data.exists() {
            continue;
        }
        let Ok(entries) = fs::read_dir(&user_data) else {
            continue;
        };
        for entry in entries.flatten() {
            let p_name = entry.file_name().to_string_lossy().to_string();
            if p_name != "Default" && !p_name.starts_with("Profile ") {
                continue;
            }
            let ext_dir = entry.path().join("Extensions");
            if !ext_dir.is_dir() {
                continue;
            }
            profile_count += 1;

            // 尝试读取 Preferences 排除已停用的扩展（state == 0）
            let disabled_ids: std::collections::HashSet<String> =
                fs::read_to_string(entry.path().join("Preferences"))
                    .ok()
                    .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
                    .and_then(|v| {
                        v.get("extensions")
                            .and_then(|e| e.get("settings"))
                            .and_then(|s| s.as_object())
                            .map(|obj| {
                                obj.iter()
                                    .filter_map(|(id, cfg)| {
                                        let st = cfg.get("state").and_then(|x| x.as_u64());
                                        if st == Some(0) {
                                            Some(id.to_ascii_lowercase())
                                        } else {
                                            None
                                        }
                                    })
                                    .collect()
                            })
                    })
                    .unwrap_or_default();

            let Ok(exts) = fs::read_dir(&ext_dir) else {
                continue;
            };
            for ext_entry in exts.flatten() {
                let ext_id = ext_entry.file_name().to_string_lossy().to_string();
                if disabled_ids.contains(&ext_id.to_ascii_lowercase()) {
                    continue;
                }
                let mut manifest_name = String::new();
                if let Ok(vers) = fs::read_dir(ext_entry.path()) {
                    for ver in vers.flatten() {
                        let mf = ver.path().join("manifest.json");
                        if let Ok(raw) = fs::read_to_string(mf) {
                            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                                if let Some(n) = v.get("name").and_then(|x| x.as_str()) {
                                    manifest_name = n.to_string();
                                    break;
                                }
                            }
                        }
                    }
                }
                if let Some(label) = match_proxy_extension_label(&ext_id, &manifest_name) {
                    hits.push(format!("{browser_name} ({p_name}): {label} [{ext_id}]"));
                }
            }
        }
    }

    hits.sort();
    hits.dedup();
    (hits, profile_count)
}

/// 执行单项修复并立刻重跑真实探针验证（严格遵守三大纯粹操作边界，互不误伤）
pub async fn execute_fix_item(
    item_id: &str,
    cfg: &AppConfig,
    bg_claude_procs: u32,
) -> Result<FixResult, String> {
    let started = std::time::Instant::now();
    let mut requires_manual_step = false;
    let message: String;

    match item_id {
        "claude_tel" => {
            fix_claude_privacy_and_telemetry()?;
            message = "已无损写入官方隐私降噪环境变量并清空 ~/.claude/telemetry/ 缓存（未碰登录态）。".into();
        }
        "claude_ban" => {
            let info = backup_and_clean_claude_dirs()?;
            message = format!(
                "已先原子备份至 {}（{}）并清理本地污染目录，正在重扫验收。",
                info.file_name, info.size_label
            );
        }
        "sys_env" => {
            let port = resolve_active_mixed_port().await;
            message = fix_system_proxy_and_env(port)?;
        }
        "claude_acct" => {
            // 绝不擅自乱删：交由前端引导二选一确认弹窗（备份清理目录 或 确认绑定新主号）
            requires_manual_step = true;
            message = "请通过二选一确认框选择「备份并重置污染目录」或「确认永久更换绑定主号」。".into();
        }
        "node_group" => {
            let mut handled_quick = false;
            let mut quick_msg = String::new();
            let ep_opt = discover_endpoint().await;
            if let Some(ep) = ep_opt.as_ref() {
                let m_cfg = fetch_configs(ep).await.ok();
                let clash_mode = m_cfg
                    .as_ref()
                    .map(|c| c.mode.to_ascii_lowercase())
                    .unwrap_or_else(|| "rule".to_string());
                if m_cfg.as_ref().map(|c| c.ipv6).unwrap_or(false) {
                    let _ = patch_ipv6_disabled(ep).await;
                    let _ = sync_clash_ipv6_to_disk(false);
                }
                if clash_mode == "direct" {
                    // 同时切回内核 mode=rule 并同步写入 config.yaml / clash-verge.yaml（内核与 Clash Verge 首页代理模式同步变回「规则」）
                    patch_clash_mode_rule(ep).await?;
                    let _ = sync_clash_mode_to_disk("rule");
                    handled_quick = true;
                    quick_msg = "已一键将 Clash 代理模式切回「规则 (Rule)」并同步写入配置文件，正在复测验收。".into();
                } else if let Ok(proxies) = fetch_proxies_raw(ep).await {
                    let rules = fetch_rules_raw(ep).await.ok();
                    let (rules_ok, _) = rules.as_deref().map(verify_claude_rules).unwrap_or((false, 0));
                    let exit_rule_ok = rules.as_deref().map(verify_exit_probe_rules).unwrap_or(false);

                    if let Some(g) = extract_proxy_group(&proxies, "Claude-Fixed") {
                        // 1) 若处于 GLOBAL 模式且指向了 Claude-Fixed 之外的组/节点，一键把 GLOBAL 锁回 Claude-Fixed
                        if clash_mode == "global" {
                            let global_now = extract_proxy_group(&proxies, "GLOBAL")
                                .map(|gg| gg.now)
                                .unwrap_or_default();
                            if !global_now.eq_ignore_ascii_case("Claude-Fixed") {
                                select_proxy_in_group(ep, "GLOBAL", "Claude-Fixed").await?;
                                handled_quick = true;
                                quick_msg = "已将 Clash GLOBAL 全局模式锁回「Claude-Fixed」策略组，正在复测验收。".into();
                            }
                        }

                        // 2) 若 Claude-Fixed 当前误选禁区或 DIRECT，自动切回首个安全白名单节点
                        if is_blocked_node_name(&g.now) || g.now.eq_ignore_ascii_case("DIRECT") {
                            if let Some(safe) = g.all.iter().find(|n| {
                                !is_blocked_node_name(n)
                                    && !n.eq_ignore_ascii_case("DIRECT")
                                    && !n.eq_ignore_ascii_case("REJECT")
                            }) {
                                select_proxy_in_group(ep, "Claude-Fixed", safe).await?;
                                handled_quick = true;
                                quick_msg = format!("已将 Claude-Fixed 自动切回安全节点 {safe} 并关闭 Mihomo IPv6。");
                            }
                        } else if !handled_quick
                            && !g.now.is_empty()
                            && g.group_type.eq_ignore_ascii_case("Selector")
                            && (clash_mode == "global" || (rules_ok && exit_rule_ok))
                        {
                            // 仅 ipv6:true 未关的场景可直接通过 API 关闭并同步写盘 config.yaml 防止重启/切服务模式反弹
                            let _ = sync_clash_ipv6_to_disk(false);
                            handled_quick = true;
                            quick_msg = "已通过 Mihomo API 关闭 ipv6:false 并同步写入 config.yaml 持久化，正在重跑实测验收。".into();
                        }
                    }
                }
            }
            if handled_quick {
                message = quick_msg;
            } else if let Some(ep) = ep_opt.as_ref() {
                // 直接持久化全局 Script.js + 自动排雷损坏的订阅空脚本 + 直接注入生效配置 clash-verge.yaml 并调用 Mihomo API 热重载（0 手动步骤立即生效！）
                match apply_clash_rules_directly_and_reload(ep).await {
                    Ok(ok_msg) => {
                        message = ok_msg;
                    }
                    Err(err) => {
                        let script_path = clash_verge_config_dir()
                            .map(|d| d.join("profiles").join("Script.js").to_string_lossy().to_string())
                            .unwrap_or_else(|| "%APPDATA%\\io.github.clash-verge-rev.clash-verge-rev\\profiles\\Script.js".into());
                        let _ = write_clash_override_script();
                        let _ = bring_clash_verge_to_front();
                        requires_manual_step = true;
                        message = format!(
                            "已写入全局覆写脚本（{script_path}），但自动热重载失败（{err}）。手动生效步骤：① 打开 Clash Verge → 左侧「订阅」；② 点击当前订阅右侧刷新/重载按钮（或右键当前订阅 → 编辑脚本确认有 return config;）；③ 返回此处点「重新实测」。"
                        );
                    }
                }
            } else {
                let backup_note = write_clash_override_script()?;
                let _ = bring_clash_verge_to_front();
                requires_manual_step = true;
                message = format!(
                    "{backup_note}。Clash Verge 当前未在线，请先启动 Clash Verge 后点击「重新实测」完成自动验收。"
                );
            }
        }
        "node_geo" => {
            if let Some(ep) = discover_endpoint().await {
                if let Ok(proxies) = fetch_proxies_raw(&ep).await {
                    if let Some(g) = extract_proxy_group(&proxies, "Claude-Fixed") {
                        if let Some(safe) = g.all.iter().find(|n| {
                            !is_blocked_node_name(n)
                                && !n.eq_ignore_ascii_case("DIRECT")
                                && !n.eq_ignore_ascii_case("REJECT")
                        }) {
                            select_proxy_in_group(&ep, "Claude-Fixed", safe).await?;
                            message = format!("已切换 Claude-Fixed 至白名单节点 {safe}，正在重测出口 IP 与 Anthropic 可达性。");
                        } else {
                            requires_manual_step = true;
                            message = "Claude-Fixed 中未找到非禁区候选节点，请在 Clash 订阅中检查可用白名单节点。".into();
                        }
                    } else {
                        requires_manual_step = true;
                        message = "请先完成「策略组与全家桶规则锁死」后再切换安全节点。".into();
                    }
                } else {
                    requires_manual_step = true;
                    message = "无法读取 Mihomo 节点列表，请确认 Clash Verge 已启动。".into();
                }
            } else {
                requires_manual_step = true;
                message = "未检测到 Clash Verge 运行，请先启动代理客户端。".into();
            }
        }
        "sys_ipv6" => {
            // 先锁定 First-Write-Wins 物理网卡 IPv6 与 DisabledComponents 原值基线，供随时撤回
            crate::rollback::capture_ipv6_baseline_if_needed();
            // 仅操作 Windows 物理网卡 IPv6 绑定并加固系统 IPv4 优先，不越界改 Clash 与 Claude
            let ipv6_res = crate::rollback::run_ps_elevated_checked(
                "Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object {$_.Enabled} | Disable-NetAdapterBinding -ComponentID ms_tcpip6 -Confirm:$false; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters' -Name 'DisabledComponents' -Value 32 -Type DWord -ErrorAction SilentlyContinue",
                "禁用物理网卡 IPv6 绑定",
            );
            match ipv6_res {
                Ok(_) => {
                    message = "已禁用 Windows 网卡 ms_tcpip6 绑定并设置 IPv4 优先（可随时在环境维护一键撤回）。".into();
                }
                Err(err) => {
                    requires_manual_step = true;
                    message = err;
                }
            }
        }
        "sys_location" => {
            // 仅关闭 Windows 定位权限与 lfsvc 服务，绝不碰 Clash 与 Claude 目录
            message = fix_windows_location_privacy()?;
        }
        "opt_boot" => {
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                let _ = Command::new("cmd")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args(["/C", "start", "", "ms-settings:startupapps"])
                    .spawn();
            }
            requires_manual_step = true;
            message = "已打开 Windows「启动应用」管理页，请手动关闭 Claude 自启（我们绝不擅自删除你的启动项），关闭后点「重新实测」即复扫变绿。".into();
        }
        "opt_ntp" => {
            #[cfg(windows)]
            let ntp_ok = {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                Command::new("powershell")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args([
                        "-NoProfile",
                        "-Command",
                        "$p = Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList '-NoProfile -Command \"net start w32time 2>$null; w32tm /resync /force\"'; exit $p.ExitCode",
                    ])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            };
            #[cfg(not(windows))]
            let ntp_ok = true;
            if ntp_ok {
                message = "已触发 Windows 时间服务 w32tm /resync /force 同步，正在重测 UTC 偏差。".into();
            } else {
                requires_manual_step = true;
                message = "未通过管理员授权或时间同步服务返回异常，请在 Windows「日期和时间」手动点击「立即同步」。".into();
            }
        }
        "opt_fw" => {
            let res = tokio::task::spawn_blocking(crate::killswitch::install_firewall_helper_task)
                .await
                .map_err(|e| format!("防火墙守护安装线程异常: {e}"))?;
            match res {
                Ok(ok_msg) => {
                    message = ok_msg;
                }
                Err(err) => {
                    requires_manual_step = true;
                    message = err;
                }
            }
        }
        "opt_webrtc" => {
            message = fix_browser_webrtc_policy()?;
        }
        "opt_tz" => {
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                let _ = Command::new("cmd")
                    .creation_flags(CREATE_NO_WINDOW)
                    .args(["/C", "start", "", "ms-settings:dateandtime"])
                    .spawn();
            }
            requires_manual_step = true;
            message = "已打开 Windows「日期和时间」设置页，我们绝不擅自改动你的系统时钟，请按需调整后点「重新实测」。".into();
        }
        "opt_browser_ext" => {
            requires_manual_step = true;
            message = "我们绝不擅自删除你的浏览器插件，请在浏览器扩展管理中确认未对 claude.ai 单独配置与当前 Clash 本地代理冲突的分流端口。".into();
        }
        "node_tun" => {
            // 1. 先检查并按需协助安装/拉起 Clash Verge TUN 系统服务（clash_verge_service）
            let svc_ready = tokio::task::spawn_blocking(ensure_clash_verge_service_ready)
                .await
                .unwrap_or_else(|_| Err("检查 Clash Verge 服务状态失败".into()));
            match svc_ready {
                Err(err_msg) => {
                    let _ = bring_clash_verge_to_front();
                    requires_manual_step = true;
                    message = err_msg;
                }
                Ok(svc_installed_now) => {
                    // 2. 重启前先快照当前 Claude-Fixed 选中的合规节点，避免重启后脱组/换节点
                    let prev_node = snapshot_current_claude_node().await;
                    // 3. 自动先关闭系统代理（enable_system_proxy: false + 清 WinINET ProxyEnable=0），再写 enable_tun_mode: true
                    let _ = sync_clash_verge_tun_yaml(true);
                    let online = restart_clash_and_wait_online(true).await;
                    if online {
                        // 4. 重启上线后自动把 GLOBAL 与策略组锁回 Claude-Fixed 及原合规节点
                        let relock_note =
                            ensure_claude_group_locked_after_restart(prev_node.as_deref()).await;
                        let tun_live = match discover_endpoint().await {
                            Some(ep) => fetch_configs(&ep).await.map(|c| c.tun_enable).unwrap_or(false),
                            None => false,
                        };
                        let adapter_live = tokio::task::spawn_blocking(inspect_wintun_adapter)
                            .await
                            .ok()
                            .flatten()
                            .is_some();
                        if tun_live && adapter_live {
                            let svc_prefix = if svc_installed_now {
                                "已协助安装并启动 Clash TUN 系统服务、"
                            } else {
                                ""
                            };
                            message = format!(
                                "{svc_prefix}已自动关闭系统代理并开启 Clash 虚拟网卡 (TUN)，首页开关/内核/网卡三端同步生效{relock_note}。"
                            );
                        } else {
                            let _ = bring_clash_verge_to_front();
                            requires_manual_step = true;
                            message = "已重启 Clash Verge，但系统未检测到在线虚拟网卡（可能未完成 Clash Verge 服务模式授权）。请在 Clash Verge「设置 → 服务模式」确认已安装运行后再开启虚拟网卡。".into();
                        }
                    } else {
                        let _ = bring_clash_verge_to_front();
                        requires_manual_step = true;
                        message = "已写入 verge.yaml（关系统代理 + 开 TUN），但自动重启 Clash Verge 超时，请手动打开 Clash Verge 确认「虚拟网卡模式 (TUN)」已开启。".into();
                    }
                }
            }
        }
        "node_proxy" => {
            // 优先先写入持久化配置再启动 / 重启 Clash Verge，并轮询等待直至 Mihomo 与本地端口就绪
            let mut online = wait_clash_online_brief(500).await;
            if !online {
                let launched = bring_clash_verge_to_front();
                if launched {
                    online = wait_clash_online_brief(6000).await;
                }
                if !online {
                    online = restart_clash_and_wait_online(false).await;
                }
            }
            if online {
                let relock_note = ensure_claude_group_locked_after_restart(None).await;
                message = format!(
                    "已成功启动 / 重启 Clash Verge，Mihomo 命名管道与本地代理端口已就绪{relock_note}。"
                );
            } else {
                let port = resolve_active_mixed_port().await;
                requires_manual_step = true;
                message = format!(
                    "已尝试启动 / 重启 Clash Verge，但未检测到 Mihomo 在线或 {port} 端口就绪，请检查 Clash Verge 安装状态或关闭冲突代理端口。"
                );
            }
        }
        "node_dns" => {
            let launched = bring_clash_verge_to_front();
            requires_manual_step = true;
            message = if launched {
                "已为你打开/唤起 Clash Verge，请按右侧指引完成后等待 3 秒自动识别或点击「重新实测」。".into()
            } else {
                "请先手动打开 Clash Verge，按右侧指引设置完成后点击「重新实测」。".into()
            };
        }
        _ => {
            requires_manual_step = true;
            message = "已刷新该项探测状态。".into();
        }
    }

    let bundle = run_all_preflight_checks(cfg, bg_claude_procs).await;
    let item_ok = bundle
        .report
        .items
        .iter()
        .find(|i| i.id == item_id)
        .map(|i| i.status == CheckStatus::Ok)
        .unwrap_or(false);

    crate::logger::log_event(
        if item_ok { "INFO" } else { "WARN" },
        "preflight",
        "fix_item",
        Some(started.elapsed().as_millis() as u64),
        format!("单项修复 item={item_id} ok={item_ok} msg={message}"),
        Some(serde_json::json!({
            "itemId": item_id,
            "ok": item_ok,
            "requiresManual": !item_ok && requires_manual_step
        })),
    );

    Ok(FixResult {
        item_id: item_id.into(),
        // 严格以二次复测真实结果 item_ok 为准，严禁自动项未通过仍报假成功
        success: item_ok,
        requires_manual_step: !item_ok && requires_manual_step,
        message,
        report: bundle.report,
        snapshot: bundle.snapshot,
    })
}

/// 一键顺序修复所有可自动处理的必须项，精准停在首个需手动/引导确认项
/// 单次重启合并策略：
/// - 若 Clash 离线 (node_proxy) 或 TUN 未开 (node_tun)，把所有持久化配置（verge.yaml 的 enable_tun_mode:true + Script.js + 空脚本排雷）先一次性落盘，
///   放在最前面仅启动/平滑重启 Clash Verge 一次（两个都有也只重启 1 次！），上线后三端（Clash 首页开关 / Mihomo / Wintun 网卡）同步到位；
/// - 若 Clash 与 TUN 均已正常，则绝不无故重启 Clash，直接走无感 API 热重载修复策略组、漂移基准与其他必须项。
pub async fn execute_one_click_fix_all(
    cfg: &AppConfig,
    bg_claude_procs: u32,
) -> Result<BatchFixResult, String> {
    let started = std::time::Instant::now();
    let mut current_bundle = run_all_preflight_checks(cfg, bg_claude_procs).await;
    let mut fixed_ids = Vec::new();

    let proxy_failed = current_bundle
        .report
        .items
        .iter()
        .any(|i| i.id == "node_proxy" && i.status != CheckStatus::Ok);
    let tun_failed = current_bundle
        .report
        .items
        .iter()
        .any(|i| i.id == "node_tun" && i.status != CheckStatus::Ok);
    let group_failed_init = current_bundle
        .report
        .items
        .iter()
        .any(|i| i.id == "node_group" && i.status != CheckStatus::Ok);

    // 1. 合并单次重启前置门禁：只要 Clash 离线或 TUN 未开，先统一落盘配置（关系统代理 + 开 TUN），再一次性启动/重启 Clash Verge
    if proxy_failed || tun_failed {
        // 先检查/协助安装 TUN 系统服务（仅当需要开启 TUN 时）
        let mut can_enable_tun = true;
        if tun_failed {
            let svc_ok = tokio::task::spawn_blocking(ensure_clash_verge_service_ready)
                .await
                .unwrap_or_else(|_| Err("检查 Clash Verge 服务状态失败".into()));
            if svc_ok.is_err() {
                can_enable_tun = false;
            }
        }
        let prev_node = snapshot_current_claude_node().await;
        if can_enable_tun {
            let _ = sync_clash_verge_tun_yaml(true);
        }
        if group_failed_init {
            let _ = write_clash_override_script();
            if let Some(dir) = clash_verge_config_dir() {
                let _ = repair_broken_active_profile_script(&dir);
            }
        }
        let online = if proxy_failed {
            // Clash 原本离线：直接启动（若进程僵死再重启）
            if bring_clash_verge_to_front() && wait_clash_online_brief(6500).await {
                tokio::time::sleep(Duration::from_millis(700)).await;
                true
            } else {
                restart_clash_and_wait_online(can_enable_tun).await
            }
        } else if can_enable_tun {
            // Clash 在线但 TUN 未开：平滑重启一次加载 verge.yaml 使界面开关与内核同步亮蓝（同时关闭系统代理防双开）
            restart_clash_and_wait_online(true).await
        } else {
            true
        };

        if online {
            // 重启上线后自动把 GLOBAL 与策略组锁回 Claude-Fixed 及重启前的合规节点
            let _ = ensure_claude_group_locked_after_restart(prev_node.as_deref()).await;
            current_bundle = run_all_preflight_checks(cfg, bg_claude_procs).await;
            if proxy_failed
                && current_bundle
                    .report
                    .items
                    .iter()
                    .any(|i| i.id == "node_proxy" && i.status == CheckStatus::Ok)
            {
                fixed_ids.push("node_proxy".to_string());
            }
            if tun_failed
                && current_bundle
                    .report
                    .items
                    .iter()
                    .any(|i| i.id == "node_tun" && i.status == CheckStatus::Ok)
            {
                fixed_ids.push("node_tun".to_string());
            }
            if group_failed_init
                && current_bundle
                    .report
                    .items
                    .iter()
                    .any(|i| i.id == "node_group" && i.status == CheckStatus::Ok)
            {
                fixed_ids.push("node_group".to_string());
            }
        }
    }

    // 2. 第二顺位：若策略组与规则仍未通过（例如 GLOBAL 脱组 / Direct 模式 / 未热重载），无感 API 立即修好（不重启 Clash）
    let group_failed = current_bundle
        .report
        .items
        .iter()
        .any(|i| i.id == "node_group" && i.status != CheckStatus::Ok);
    if group_failed {
        if let Ok(res) = execute_fix_item("node_group", cfg, bg_claude_procs).await {
            if res.success {
                if !fixed_ids.iter().any(|x| x == "node_group") {
                    fixed_ids.push("node_group".to_string());
                }
                current_bundle = run_all_preflight_checks(cfg, bg_claude_procs).await;
            }
        }
    }

    // 3. 第三顺位：其余必须项有序自动修复（漂移 Warn 默认重置基准 + 系统环境 + Claude 隐私/污染清理）
    let current_node_name = current_bundle.snapshot.current_node.clone();
    for item in current_bundle
        .report
        .items
        .iter()
        .filter(|i| i.part == CheckPart::Must && i.status != CheckStatus::Ok)
    {
        match item.id.as_str() {
            "node_geo" => {
                // 仅漂移风险提示 (Warn) 时按默认选项重置当前节点漂移基准并复测；
                // 真不可用 (Fail：禁区/CF 403/离线/高危黑名单) 绝不擅自跨洲乱切，保留给用户点备用项去「节点流量」更换
                if item.status == CheckStatus::Warn && !current_node_name.is_empty() {
                    crate::mihomo::reset_node_drift_history(&current_node_name);
                    fixed_ids.push("node_geo".to_string());
                }
            }
            "claude_tel" => {
                if fix_claude_privacy_and_telemetry().is_ok() {
                    fixed_ids.push("claude_tel".to_string());
                }
            }
            "sys_env" => {
                let active_port = resolve_active_mixed_port().await;
                if fix_system_proxy_and_env(active_port).is_ok() {
                    fixed_ids.push("sys_env".to_string());
                }
            }
            // claude_ban / claude_acct（涉及本地目录清理，必须弹出透明分项清单由用户勾选确认，绝不静默删文件）、sys_ipv6/sys_location（需 UAC）保留引导用户单独确认
            _ => {}
        }
    }

    let after = run_all_preflight_checks(cfg, bg_claude_procs).await;
    let first_remaining = after
        .report
        .items
        .iter()
        .find(|i| i.part == CheckPart::Must && i.status != CheckStatus::Ok);

    let skipped_manual_id = first_remaining.map(|i| i.id.clone());
    let summary = match first_remaining {
        Some(rem) => format!(
            "已完成 {} 项自动处理；已自动聚焦至「{}」，请按右侧指引操作后点击重新实测。",
            fixed_ids.len(),
            rem.title
        ),
        None => "全部 11 项必须门禁已通过真实探针验收，现可点击「安全启动 Claude」！".into(),
    };

    crate::logger::log_event(
        "INFO",
        "preflight",
        "one_click_fix_all",
        Some(started.elapsed().as_millis() as u64),
        &summary,
        Some(serde_json::json!({
            "fixedIds": fixed_ids,
            "skippedManualId": skipped_manual_id
        })),
    );

    Ok(BatchFixResult {
        fixed_ids,
        skipped_manual_id,
        summary,
        report: after.report,
        snapshot: after.snapshot,
    })
}

fn fix_claude_privacy_and_telemetry() -> Result<(), String> {
    let settings_path =
        claude_settings_path().ok_or_else(|| "无法定位用户主目录 ~/.claude".to_string())?;
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建 ~/.claude 目录失败: {e}"))?;
    }
    let existing = fs::read_to_string(&settings_path).ok();
    let merged = merge_claude_privacy_settings(existing.as_deref())?;
    fs::write(&settings_path, merged).map_err(|e| format!("写入 settings.json 失败: {e}"))?;

    if let Some(tel_dir) = claude_telemetry_dir() {
        if tel_dir.exists() {
            if let Ok(entries) = fs::read_dir(&tel_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        let _ = fs::remove_dir_all(&p);
                    } else {
                        let _ = fs::remove_file(&p);
                    }
                }
            }
        }
    }
    Ok(())
}

/// 与 clash-scripts/claude-verge-override.js 保持 100% 一致的 Claude 全家桶与出口监测规则（严禁干扰 AGY 或其他应用）
const FD_CLAUDE_FIXED_RULES: &[&str] = &[
    "DOMAIN-SUFFIX,sentry.io,REJECT",
    "DOMAIN-SUFFIX,datadoghq.com,REJECT",
    "DOMAIN-SUFFIX,statsigapi.net,REJECT",
    "DOMAIN-SUFFIX,statsig.com,REJECT",
    "DOMAIN-SUFFIX,intercom.io,REJECT",
    "DOMAIN-SUFFIX,intercomcdn.com,REJECT",
    "DOMAIN-SUFFIX,anthropic.com,Claude-Fixed",
    "DOMAIN-SUFFIX,claude.ai,Claude-Fixed",
    "DOMAIN-SUFFIX,claude.com,Claude-Fixed",
    "DOMAIN-SUFFIX,claudeusercontent.com,Claude-Fixed",
    "DOMAIN-SUFFIX,ip-api.com,Claude-Fixed",
    "DOMAIN-SUFFIX,ipapi.is,Claude-Fixed",
    "DOMAIN-SUFFIX,ipinfo.io,Claude-Fixed",
    "PROCESS-NAME,Claude.exe,Claude-Fixed",
    "PROCESS-NAME,claude.exe,Claude-Fixed",
    "PROCESS-NAME,FD Claude Guard.exe,Claude-Fixed",
    "PROCESS-NAME,fd-claude-guard.exe,Claude-Fixed",
];

/// 禁区节点 exclude-filter 正则（用于 proxy-providers 节点池订阅过滤 HK/MO/CN/RU/BY/KP/IR）
const CLAUDE_BLOCKED_EXCLUDE_FILTER: &str = r"(?i)(香港|Hong\s*Kong|\bHK\b|澳门|澳門|Macau|\bMO\b|中国|中國|国内|China|\bCN\b|俄罗斯|俄羅斯|俄国|Russia|\bRU\b|白俄|\bBY\b|朝鲜|朝鮮|\bKP\b|伊朗|\bIR\b)";

/// P0-6 安全修复：严禁在商业版中用 include_str! 嵌入明文覆写脚本绕过 AES-256-GCM 资产保护；
/// 所有覆写脚本必须且仅能来自 `licensing::get_override_script()` 解密后的受保护资产。
fn upgrade_override_script_compat(raw: &str) -> String {
    raw.to_string()
}

/// 检查并自动向 profiles.yaml 注册全局 `uid: Script`（解决全新安装 Clash Verge 从未启用过全局脚本导致更新/重导订阅后策略组丢失）
fn ensure_global_script_registered_in_profiles_yaml(dir: &Path) -> Result<bool, String> {
    let profiles_yaml_path = dir.join("profiles.yaml");
    if !profiles_yaml_path.exists() {
        return Ok(false);
    }
    let raw = fs::read_to_string(&profiles_yaml_path)
        .map_err(|e| format!("读取 profiles.yaml 失败: {e}"))?;
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&raw)
        .map_err(|e| format!("解析 profiles.yaml 失败: {e}"))?;
    let Some(map) = doc.as_mapping_mut() else {
        return Ok(false);
    };

    let items_key = serde_yaml::Value::String("items".into());
    let mut items = map
        .get(&items_key)
        .and_then(|v| v.as_sequence())
        .cloned()
        .unwrap_or_default();

    let already_has_script = items.iter().any(|it| {
        it.get("uid").and_then(|v| v.as_str()) == Some("Script")
            || (it.get("type").and_then(|v| v.as_str()) == Some("script")
                && it.get("file").and_then(|v| v.as_str()) == Some("Script.js"))
    });
    if already_has_script {
        return Ok(false);
    }

    let mut script_entry = serde_yaml::Mapping::new();
    script_entry.insert(
        serde_yaml::Value::String("uid".into()),
        serde_yaml::Value::String("Script".into()),
    );
    script_entry.insert(
        serde_yaml::Value::String("type".into()),
        serde_yaml::Value::String("script".into()),
    );
    script_entry.insert(
        serde_yaml::Value::String("name".into()),
        serde_yaml::Value::Null,
    );
    script_entry.insert(
        serde_yaml::Value::String("file".into()),
        serde_yaml::Value::String("Script.js".into()),
    );
    script_entry.insert(
        serde_yaml::Value::String("updated".into()),
        serde_yaml::Value::Number(serde_yaml::Number::from(chrono::Utc::now().timestamp())),
    );
    items.insert(0, serde_yaml::Value::Mapping(script_entry));
    map.insert(items_key, serde_yaml::Value::Sequence(items));

    let bak = dir.join("profiles.yaml.fd-bak");
    if !bak.exists() {
        let _ = fs::copy(&profiles_yaml_path, &bak);
    }
    let serialized = serde_yaml::to_string(&doc)
        .map_err(|e| format!("序列化 profiles.yaml 失败: {e}"))?;
    fs::write(&profiles_yaml_path, serialized)
        .map_err(|e| format!("写入 profiles.yaml 失败: {e}"))?;
    Ok(true)
}

fn write_clash_override_script() -> Result<String, String> {
    let dir = clash_verge_config_dir()
        .ok_or_else(|| "无法定位 Clash Verge Rev 配置目录".to_string())?;
    // First-Write-Wins：首次改动 Clash 配置前锁定原始状态，供用户随时精准撤回
    crate::rollback::capture_clash_rules_baseline_if_needed(&dir);
    let profiles_dir = dir.join("profiles");
    fs::create_dir_all(&profiles_dir).map_err(|e| format!("创建 profiles 目录失败: {e}"))?;

    // 先做授权解锁验证，再升级为支持 proxy-providers 与 find-process-mode 的新版脚本
    let unlocked_script = crate::licensing::get_override_script()?;
    let script_content = upgrade_override_script_compat(&unlocked_script);
    let target = profiles_dir.join("Script.js");
    let registered_script = ensure_global_script_registered_in_profiles_yaml(&dir).unwrap_or(false);
    let reg_note = if registered_script {
        "，并已自动在 profiles.yaml 中注册激活全局 Script.js"
    } else {
        ""
    };
    if target.exists() {
        if let Ok(existing) = fs::read_to_string(&target) {
            if existing == script_content {
                return Ok(format!("全局覆写脚本 Script.js 已是最新{reg_note}"));
            }
        }
        let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let backup_path = profiles_dir.join(format!("Script.js.bak-{ts}"));
        fs::copy(&target, &backup_path).map_err(|e| format!("备份原 Script.js 失败: {e}"))?;
        fs::write(&target, &script_content)
            .map_err(|e| format!("写入 Script.js 失败: {e}"))?;
        return Ok(format!(
            "已备份原脚本至 Script.js.bak-{ts} 并更新全局覆写脚本 Script.js{reg_note}"
        ));
    }
    fs::write(&target, &script_content).map_err(|e| format!("写入 Script.js 失败: {e}"))?;
    Ok(format!("已写入 Clash Verge 全局覆写脚本 profiles\\Script.js{reg_note}"))
}

/// 词法安全地剥离 JS 单行/块级注释（跳过字符串字面量，防止误截断 `https://...` URL）
fn strip_js_comments_preserving_strings(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(b as char);
                i += 1;
                out.push(bytes[i] as char);
                i += 1;
                continue;
            }
            if b == q {
                quote = None;
            }
            out.push(b as char);
            i += 1;
            continue;
        }
        if b == b'\'' || b == b'"' || b == b'`' {
            quote = Some(b);
            out.push(b as char);
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // 安全推进 UTF-8 字符
        if let Some(ch) = src[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

/// 检测损坏的订阅级扩展脚本（例如空模板 `function main(config) {}` 漏写 `return config;` 会吞掉全局 Script.js 导致 Claude-Fixed 彻底失效）
fn repair_broken_script_text(raw: &str) -> Option<String> {
    let stripped = strip_js_comments_preserving_strings(raw);
    let has_main = regex::Regex::new(r"function\s+main\s*\(")
        .ok()?
        .is_match(&stripped);
    let has_return = regex::Regex::new(r"\breturn\b").ok()?.is_match(&stripped);
    if has_main && !has_return {
        Some(
            "// FD Claude Guard 自动修复：补全缺失的 return config，防止吞掉全局 Script.js 的 Claude-Fixed 策略组\nfunction main(config) {\n  return config;\n}\n"
                .to_string(),
        )
    } else {
        None
    }
}

/// 检查当前激活订阅挂载的局部扩展脚本（option.script），若漏写 return config 则自动备份并修补，并顺便读取历史选中的安全节点
fn repair_broken_active_profile_script(dir: &Path) -> (Option<String>, Option<String>) {
    let profiles_yaml_path = dir.join("profiles.yaml");
    let Ok(raw) = fs::read_to_string(&profiles_yaml_path) else {
        return (None, None);
    };
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&raw) else {
        return (None, None);
    };
    let Some(current_uid) = doc.get("current").and_then(|v| v.as_str()) else {
        return (None, None);
    };
    let Some(items) = doc.get("items").and_then(|v| v.as_sequence()) else {
        return (None, None);
    };
    let active_item = items
        .iter()
        .find(|it| it.get("uid").and_then(|v| v.as_str()) == Some(current_uid));
    let Some(active) = active_item else {
        return (None, None);
    };

    // 读取该订阅历史记录的 Claude-Fixed 选中节点（热重载后自动还原，不让用户节点乱跳）
    let saved_node = active
        .get("selected")
        .and_then(|v| v.as_sequence())
        .and_then(|seq| {
            seq.iter().find_map(|s| {
                if s.get("name").and_then(|n| n.as_str()) == Some("Claude-Fixed") {
                    s.get("now")
                        .and_then(|n| n.as_str())
                        .filter(|n| !n.is_empty() && !is_blocked_node_name(n))
                        .map(|n| n.to_string())
                } else {
                    None
                }
            })
        });

    let script_uid = active
        .get("option")
        .and_then(|o| o.get("script"))
        .and_then(|v| v.as_str());
    let Some(s_uid) = script_uid else {
        return (None, saved_node);
    };
    let script_file = items.iter().find_map(|it| {
        if it.get("uid").and_then(|v| v.as_str()) == Some(s_uid) {
            it.get("file").and_then(|f| f.as_str()).map(|s| s.to_string())
        } else {
            None
        }
    });
    let Some(file_name) = script_file else {
        return (None, saved_node);
    };

    let script_path = dir.join("profiles").join(&file_name);
    let Ok(script_raw) = fs::read_to_string(&script_path) else {
        return (None, saved_node);
    };
    if let Some(fixed) = repair_broken_script_text(&script_raw) {
        let bak = dir.join("profiles").join(format!("{file_name}.fd-bak"));
        if !bak.exists() {
            let _ = fs::copy(&script_path, &bak);
        }
        if fs::write(&script_path, fixed).is_ok() {
            return (
                Some(format!("已自动修复当前订阅损坏的空脚本 {file_name}（补全 return config）")),
                saved_node,
            );
        }
    }
    (None, saved_node)
}

/// 纯函数：将 Claude-Fixed 手动选择策略组、Claude 全家桶与出口监测前置规则、以及 ipv6: false 直接注入 Clash 生效配置 YAML
fn inject_claude_fixed_into_yaml_value(doc: &mut serde_yaml::Value) -> Result<usize, String> {
    let map = doc
        .as_mapping_mut()
        .ok_or_else(|| "clash-verge.yaml 根节点不是有效的 YAML 映射".to_string())?;

    // 1. 提取订阅中的所有合法非禁区节点名，同时兼容 proxy-providers 外部节点池订阅
    let all_proxies: Vec<String> = map
        .get(&serde_yaml::Value::String("proxies".into()))
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let provider_names: Vec<String> = map
        .get(&serde_yaml::Value::String("proxy-providers".into()))
        .and_then(|v| v.as_mapping())
        .map(|m| {
            m.keys()
                .filter_map(|k| k.as_str().map(|s| s.to_string()))
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let mut safe_proxies: Vec<String> = all_proxies
        .iter()
        .filter(|n| !is_blocked_node_name(n))
        .cloned()
        .collect();
    if safe_proxies.is_empty() && provider_names.is_empty() {
        safe_proxies = all_proxies;
    }
    if safe_proxies.is_empty() && provider_names.is_empty() {
        return Err("当前 Clash 生效配置中未找到任何可用代理节点或 proxy-providers 节点池，无法构建 Claude-Fixed 策略组".into());
    }
    let safe_count = if !safe_proxies.is_empty() {
        safe_proxies.len()
    } else {
        provider_names.len()
    };

    // 2. 构建/更新 Claude-Fixed 策略组（type: select，严禁 url-test/fallback 自动跳区；兼容 proxy-providers）
    let mut group_map = serde_yaml::Mapping::new();
    group_map.insert(
        serde_yaml::Value::String("name".into()),
        serde_yaml::Value::String("Claude-Fixed".into()),
    );
    group_map.insert(
        serde_yaml::Value::String("type".into()),
        serde_yaml::Value::String("select".into()),
    );
    if !safe_proxies.is_empty() {
        group_map.insert(
            serde_yaml::Value::String("proxies".into()),
            serde_yaml::Value::Sequence(
                safe_proxies
                    .into_iter()
                    .map(serde_yaml::Value::String)
                    .collect(),
            ),
        );
    }
    if !provider_names.is_empty() {
        group_map.insert(
            serde_yaml::Value::String("use".into()),
            serde_yaml::Value::Sequence(
                provider_names
                    .into_iter()
                    .map(serde_yaml::Value::String)
                    .collect(),
            ),
        );
        group_map.insert(
            serde_yaml::Value::String("exclude-filter".into()),
            serde_yaml::Value::String(CLAUDE_BLOCKED_EXCLUDE_FILTER.into()),
        );
    }
    let fixed_group_val = serde_yaml::Value::Mapping(group_map);

    // 若订阅关闭了 find-process-mode，恢复为 strict 保证 PROCESS-NAME,Claude.exe 规则有效
    if map
        .get(&serde_yaml::Value::String("find-process-mode".into()))
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("off"))
    {
        map.insert(
            serde_yaml::Value::String("find-process-mode".into()),
            serde_yaml::Value::String("strict".into()),
        );
    }

    let pg_key = serde_yaml::Value::String("proxy-groups".into());
    let mut groups_seq = map
        .get(&pg_key)
        .and_then(|v| v.as_sequence())
        .cloned()
        .unwrap_or_default();
    if let Some(pos) = groups_seq
        .iter()
        .position(|g| g.get("name").and_then(|n| n.as_str()) == Some("Claude-Fixed"))
    {
        groups_seq[pos] = fixed_group_val;
    } else {
        groups_seq.insert(0, fixed_group_val);
    }
    map.insert(pg_key, serde_yaml::Value::Sequence(groups_seq));

    // 3. 在 rules 最顶部前置注入 FD_CLAUDE_FIXED_RULES（精确去重，确保最高优先级且不干扰其他应用/AGY）
    let rules_key = serde_yaml::Value::String("rules".into());
    let existing_rules: Vec<serde_yaml::Value> = map
        .get(&rules_key)
        .and_then(|v| v.as_sequence())
        .cloned()
        .unwrap_or_default();
    let fd_set: std::collections::HashSet<&str> = FD_CLAUDE_FIXED_RULES.iter().copied().collect();
    let mut new_rules: Vec<serde_yaml::Value> = FD_CLAUDE_FIXED_RULES
        .iter()
        .map(|r| serde_yaml::Value::String((*r).to_string()))
        .collect();
    for r in existing_rules {
        if let Some(s) = r.as_str() {
            if fd_set.contains(s) {
                continue;
            }
        }
        new_rules.push(r);
    }
    map.insert(rules_key, serde_yaml::Value::Sequence(new_rules));

    // 4. 强制关闭 Clash 内核 IPv6 隧道防泄漏
    map.insert(
        serde_yaml::Value::String("ipv6".into()),
        serde_yaml::Value::Bool(false),
    );

    Ok(safe_count)
}

/// T-102：从合规候选节点中挑选最佳节点（优先深度核验最优，其次按原生/ISP 与合规地区打分，绝不盲抄其他策略组旧节点）
pub fn pick_best_compliant_node(candidates: &[String]) -> Option<String> {
    if let Some(best) = crate::mihomo::pick_best_verified_node(candidates) {
        if !best.is_empty() && !is_blocked_node_name(&best) {
            return Some(best);
        }
    }
    let mut best_score = i32::MIN;
    let mut best_name: Option<String> = None;
    for name in candidates {
        if name.is_empty()
            || is_blocked_node_name(name)
            || name.eq_ignore_ascii_case("DIRECT")
            || name.eq_ignore_ascii_case("REJECT")
        {
            continue;
        }
        let lower = name.to_lowercase();
        let mut score = 0i32;
        if lower.contains("原生") || lower.contains("住宅") || lower.contains("isp") || lower.contains("家宽") {
            score += 40;
        }
        if lower.contains("ai") || lower.contains("claude") || lower.contains("流媒体") {
            score += 15;
        }
        if lower.contains("美国") || lower.contains("us") || lower.contains("日本") || lower.contains("jp")
            || lower.contains("新加坡") || lower.contains("sg") || lower.contains("澳大利亚") || lower.contains("au")
            || lower.contains("英国") || lower.contains("uk") || lower.contains("德国") || lower.contains("de")
        {
            score += 20;
        }
        if score > best_score {
            best_score = score;
            best_name = Some(name.clone());
        }
    }
    best_name
}

/// 纯函数（T-102）：更新 Clash Verge `profiles.yaml` 中当前活跃订阅的 `selected` 列表：
/// 1) 强制将 `{ name: "Claude-Fixed", now: target_node }` 写入首位（index 0）；
/// 2) 同步将 `synced_groups`（如订阅原主组「天悦云」）更新为同一 `target_node`，保持 Clash 客户端与工具 100% 一致。
pub fn patch_profiles_yaml_selected(
    raw: &str,
    target_node: &str,
    synced_groups: &[String],
) -> Result<String, String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(raw).map_err(|e| format!("解析 profiles.yaml 失败: {e}"))?;
    let current_uid = doc
        .get("current")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "profiles.yaml 缺少 current 活跃订阅字段".to_string())?;
    let items = doc
        .get_mut("items")
        .and_then(|v| v.as_sequence_mut())
        .ok_or_else(|| "profiles.yaml 缺少 items 列表".to_string())?;

    let mut updated = false;
    for item in items.iter_mut() {
        let uid = item.get("uid").and_then(|v| v.as_str()).unwrap_or("");
        if uid != current_uid {
            continue;
        }
        let map = item
            .as_mapping_mut()
            .ok_or_else(|| "活跃订阅节点不是有效映射".to_string())?;
        let sel_key = serde_yaml::Value::String("selected".into());
        let old_seq = map
            .get(&sel_key)
            .and_then(|v| v.as_sequence())
            .cloned()
            .unwrap_or_default();

        let mut new_seq: Vec<serde_yaml::Value> = Vec::new();
        let make_entry = |group_name: &str, now_node: &str| {
            let mut m = serde_yaml::Mapping::new();
            m.insert(
                serde_yaml::Value::String("name".into()),
                serde_yaml::Value::String(group_name.into()),
            );
            m.insert(
                serde_yaml::Value::String("now".into()),
                serde_yaml::Value::String(now_node.into()),
            );
            serde_yaml::Value::Mapping(m)
        };

        // 首位固定写入 Claude-Fixed
        new_seq.push(make_entry("Claude-Fixed", target_node));

        // 紧接着写入同步后的主策略组（去重）
        let mut seen = std::collections::HashSet::new();
        seen.insert("Claude-Fixed".to_string());
        for g in synced_groups {
            if g.is_empty() || seen.contains(g) {
                continue;
            }
            new_seq.push(make_entry(g, target_node));
            seen.insert(g.clone());
        }

        // 保留其余历史策略组选中项（不破坏用户其他分流组）
        for entry in old_seq {
            let name = entry
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() || seen.contains(&name) {
                continue;
            }
            seen.insert(name);
            new_seq.push(entry);
        }

        map.insert(sel_key, serde_yaml::Value::Sequence(new_seq));
        updated = true;
        break;
    }

    if !updated {
        return Err(format!("profiles.yaml 中未找到 current={current_uid} 对应订阅"));
    }
    serde_yaml::to_string(&doc).map_err(|e| format!("序列化 profiles.yaml 失败: {e}"))
}

/// 将 `Claude-Fixed` 置顶并同步选中节点写入磁盘 `profiles.yaml`
pub fn sync_clash_profiles_selected(dir: &Path, target_node: &str, synced_groups: &[String]) {
    let path = dir.join("profiles.yaml");
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(patched) = patch_profiles_yaml_selected(&raw, target_node, synced_groups) {
            let _ = fs::write(&path, patched);
        }
    }
}

/// T-102 核心双向同步引擎：
/// 1) 在 Mihomo 内核将 Claude-Fixed 切换到 `target_node`；
/// 2) 同步将包含 `target_node` 的顶层主 Selector 组（如「天悦云」）切到同一节点，确保 Clash 首页与工具显示 100% 一致；
/// 3) 若处于 GLOBAL 模式，自动把 GLOBAL 锁回 Claude-Fixed；
/// 4) 回写磁盘 `profiles.yaml`，将 `Claude-Fixed` 置于 `selected[0]`。
pub async fn sync_clash_selection_everywhere(
    endpoint: &MihomoEndpoint,
    target_node: &str,
) -> Vec<String> {
    let mut synced_groups = Vec::new();
    let _ = select_proxy_in_group(endpoint, "Claude-Fixed", target_node).await;

    if let Ok(proxies) = fetch_proxies_raw(endpoint).await {
        for (group_name, v) in &proxies {
            if group_name == "Claude-Fixed"
                || group_name == "GLOBAL"
                || group_name == "DIRECT"
                || group_name == "REJECT"
            {
                continue;
            }
            let is_sel = v.get("type").and_then(|t| t.as_str()) == Some("Selector");
            let is_hidden = v.get("hidden").and_then(|h| h.as_bool()).unwrap_or(false);
            if !is_sel || is_hidden {
                continue;
            }
            let contains_target = v
                .get("all")
                .and_then(|a| a.as_array())
                .map(|arr| arr.iter().any(|x| x.as_str() == Some(target_node)))
                .unwrap_or(false);
            if contains_target {
                let cur_now = v.get("now").and_then(|n| n.as_str()).unwrap_or("");
                if cur_now != target_node {
                    let _ = select_proxy_in_group(endpoint, group_name, target_node).await;
                }
                synced_groups.push(group_name.clone());
            }
        }
        if let Ok(m_cfg) = fetch_configs(endpoint).await {
            if m_cfg.mode.eq_ignore_ascii_case("global") {
                let global_now = extract_proxy_group(&proxies, "GLOBAL")
                    .map(|gg| gg.now)
                    .unwrap_or_default();
                if !global_now.eq_ignore_ascii_case("Claude-Fixed") {
                    let _ = select_proxy_in_group(endpoint, "GLOBAL", "Claude-Fixed").await;
                }
            }
        }
    }

    if let Some(dir) = clash_verge_config_dir() {
        sync_clash_profiles_selected(&dir, target_node, &synced_groups);
    }
    synced_groups
}

/// 一键直接将策略组与 Claude 全家桶规则写入 Clash 生效配置并热重载 Mihomo（0 手动重载、毫秒级生效 + 持久保留）
async fn apply_clash_rules_directly_and_reload(endpoint: &MihomoEndpoint) -> Result<String, String> {
    let dir = clash_verge_config_dir()
        .ok_or_else(|| "无法定位 Clash Verge Rev 配置目录".to_string())?;

    // 1. 持久化全局 Script.js（确保重启/更新订阅后继续生效）
    let _script_note = write_clash_override_script()?;

    // 2. 自动排查并修复当前订阅损坏的空扩展脚本（如缺 return config 的脚本会吞掉全局 Script.js）
    let (repaired_note, saved_profile_node) = repair_broken_active_profile_script(&dir);

    // 3. 仅当已存在 Claude-Fixed 历史合规节点时才保留；首次建组绝不盲抄其他策略组（如天悦云）节点，统一走最佳合规节点算法
    let proxies_before = fetch_proxies_raw(endpoint).await.ok();
    let preferred_node = proxies_before
        .as_ref()
        .and_then(|pm| {
            extract_proxy_group(pm, "Claude-Fixed")
                .map(|g| g.now)
                .filter(|n| !n.is_empty() && !is_blocked_node_name(n))
        })
        .or(saved_profile_node);

    // 4. 直接读取并合并写入 clash-verge.yaml
    let runtime_yaml = dir.join("clash-verge.yaml");
    if !runtime_yaml.exists() {
        return Err("未找到 clash-verge.yaml 生效配置文件".to_string());
    }
    let raw_yaml = fs::read_to_string(&runtime_yaml)
        .map_err(|e| format!("读取 clash-verge.yaml 失败: {e}"))?;
    let mut doc: serde_yaml::Value = serde_yaml::from_str(&raw_yaml)
        .map_err(|e| format!("解析 clash-verge.yaml 失败: {e}"))?;
    let safe_count = inject_claude_fixed_into_yaml_value(&mut doc)?;

    let bak_yaml = dir.join("clash-verge.yaml.fd-bak");
    if !bak_yaml.exists() {
        let _ = fs::copy(&runtime_yaml, &bak_yaml);
    }
    let merged_yaml = serde_yaml::to_string(&doc)
        .map_err(|e| format!("序列化 clash-verge.yaml 失败: {e}"))?;
    fs::write(&runtime_yaml, &merged_yaml)
        .map_err(|e| format!("写入 clash-verge.yaml 失败: {e}"))?;
    // 同步持久化关闭 config.yaml 顶层 ipv6: false，防止 Clash Verge 重启或开启 TUN 服务模式重载配置时覆盖回 ipv6: true
    let _ = sync_clash_ipv6_to_disk(false);

    // 5. 通过 Mihomo API 直接提交完整 YAML payload 强制热重载生效（兼容服务模式 SAFE_PATHS，0 手动重载）
    reload_config_via_payload(endpoint, &merged_yaml).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // 6. 恢复 Claude-Fixed 历史合规节点；若是首次建组，按最佳合规节点算法择优，并同步 Clash 主组与 profiles.yaml selected[0]=Claude-Fixed
    let mut chosen_node_note = String::new();
    if let Ok(proxies_after) = fetch_proxies_raw(endpoint).await {
        if let Some(g) = extract_proxy_group(&proxies_after, "Claude-Fixed") {
            let target_node = preferred_node
                .filter(|p| g.all.iter().any(|n| n == p))
                .or_else(|| pick_best_compliant_node(&g.all));
            if let Some(pref) = target_node.as_deref() {
                let synced = sync_clash_selection_everywhere(endpoint, pref).await;
                if g.now != pref {
                    crate::mihomo::reset_node_drift_history(pref);
                }
                let sync_hint = if synced.is_empty() {
                    String::new()
                } else {
                    format!("，已同步 Clash「{}」一致", synced.join(" / "))
                };
                chosen_node_note = format!("，默认锁定最佳合规节点「{pref}」{sync_hint}");
            }
        }
    }

    let extra = repaired_note
        .map(|n| format!("（{n}）"))
        .unwrap_or_default();
    crate::logger::log_info(
        "preflight",
        format!(
            "Clash 策略组注入完成: config_dir={} safe_count={safe_count} script_note={_script_note}",
            dir.display()
        ),
    );
    Ok(format!(
        "已直接写入 Claude-Fixed 策略组（{safe_count} 个合规节点/节点池{chosen_node_note}）与 Claude 全家桶规则并热重载立即生效{extra}，已同步持久化至 Script.js。"
    ))
}

/// 同步更新 Clash Verge 磁盘配置中的 mode 字段（config.yaml / clash-verge.yaml），确保重启后保持一致
fn sync_clash_mode_to_disk(mode: &str) -> Result<(), String> {
    let dir = clash_verge_config_dir()
        .ok_or_else(|| "无法定位 Clash Verge Rev 配置目录".to_string())?;
    for file_name in ["config.yaml", "clash-verge.yaml"] {
        let path = dir.join(file_name);
        if let Ok(raw) = fs::read_to_string(&path) {
            let mut replaced = false;
            let mut out: Vec<String> = raw
                .lines()
                .map(|line| {
                    if !replaced && line.starts_with("mode:") {
                        replaced = true;
                        format!("mode: {mode}")
                    } else {
                        line.to_string()
                    }
                })
                .collect();
            if !replaced {
                out.push(format!("mode: {mode}"));
            }
            let _ = fs::write(&path, out.join("\n") + "\n");
        }
    }
    Ok(())
}

/// 同步更新 Clash Verge 磁盘配置（config.yaml / clash-verge.yaml）顶层 ipv6 字段：
/// 先执行 First-Write-Wins 基线捕获，再仅改顶层 `ipv6:` 行，绝不触碰缩进子键 `dns.ipv6`。
fn sync_clash_ipv6_to_disk(ipv6_enabled: bool) -> Result<(), String> {
    let dir = clash_verge_config_dir()
        .ok_or_else(|| "无法定位 Clash Verge Rev 配置目录".to_string())?;
    crate::rollback::capture_clash_rules_baseline_if_needed(&dir);
    for file_name in ["config.yaml", "clash-verge.yaml"] {
        let path = dir.join(file_name);
        if let Ok(raw) = fs::read_to_string(&path) {
            if crate::rollback::read_top_level_yaml_bool(&raw, "ipv6") != Some(ipv6_enabled) {
                let updated =
                    crate::rollback::patch_top_level_yaml_bool(&raw, "ipv6", ipv6_enabled);
                let _ = fs::write(&path, updated);
            }
        }
    }
    Ok(())
}

/// 纯函数：更新 verge.yaml 的 enable_tun_mode，并在开启 TUN 时同步关闭 enable_system_proxy 防止双开
pub fn patch_verge_yaml_tun_and_sysproxy(
    raw: &str,
    tun_enabled: bool,
    disable_sysproxy: bool,
) -> String {
    let mut tun_replaced = false;
    let mut sys_replaced = false;
    let mut out: Vec<String> = raw
        .lines()
        .map(|line| {
            if !tun_replaced && line.starts_with("enable_tun_mode:") {
                tun_replaced = true;
                format!("enable_tun_mode: {tun_enabled}")
            } else if disable_sysproxy && !sys_replaced && line.starts_with("enable_system_proxy:") {
                sys_replaced = true;
                "enable_system_proxy: false".to_string()
            } else {
                line.to_string()
            }
        })
        .collect();
    if !tun_replaced {
        out.push(format!("enable_tun_mode: {tun_enabled}"));
    }
    if disable_sysproxy && !sys_replaced {
        out.push("enable_system_proxy: false".to_string());
    }
    out.join("\n") + "\n"
}

/// 关闭 Windows WinINET 系统代理开关（开启纯 TUN 模式前防系统代理与 TUN 双开残留）
fn disable_windows_system_proxy_registry() {
    #[cfg(windows)]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        if let Ok(inet) = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                winreg::enums::KEY_SET_VALUE,
            )
        {
            let _ = inet.set_value("ProxyEnable", &0u32);
        }
    }
}

/// 同步更新 Clash Verge verge.yaml 中的 enable_tun_mode（开启 TUN 时同步关闭系统代理防双开）
fn sync_clash_verge_tun_yaml(enabled: bool) -> Result<(), String> {
    let dir = clash_verge_config_dir()
        .ok_or_else(|| "无法定位 Clash Verge Rev 配置目录".to_string())?;
    crate::rollback::capture_clash_rules_baseline_if_needed(&dir);
    let path = dir.join("verge.yaml");
    if let Ok(raw) = fs::read_to_string(&path) {
        let updated = patch_verge_yaml_tun_and_sysproxy(&raw, enabled, enabled);
        fs::write(&path, updated).map_err(|e| format!("更新 verge.yaml 失败: {e}"))?;
    }
    if enabled {
        disable_windows_system_proxy_registry();
    }
    Ok(())
}

/// 重启 Clash Verge 前快照当前 Claude-Fixed 选中的合规节点，防止重启后换节点
async fn snapshot_current_claude_node() -> Option<String> {
    let ep = discover_endpoint().await?;
    let proxies = fetch_proxies_raw(&ep).await.ok()?;
    extract_proxy_group(&proxies, "Claude-Fixed")
        .map(|g| g.now)
        .filter(|n| !n.is_empty() && !is_blocked_node_name(n))
}

/// Clash Verge 重启上线后自动核查并锁回 GLOBAL → Claude-Fixed 与重启前合规节点（若策略组丢失则自动补注入）
async fn ensure_claude_group_locked_after_restart(preferred_node: Option<&str>) -> String {
    let Some(ep) = discover_endpoint().await else {
        return String::new();
    };
    let mut proxies_opt = fetch_proxies_raw(&ep).await.ok();
    let has_group = proxies_opt
        .as_ref()
        .and_then(|pm| extract_proxy_group(pm, "Claude-Fixed"))
        .is_some();

    if !has_group {
        if apply_clash_rules_directly_and_reload(&ep).await.is_ok() {
            proxies_opt = fetch_proxies_raw(&ep).await.ok();
        }
    }

    let mut notes: Vec<String> = Vec::new();
    if let Some(proxies) = proxies_opt {
        if let Some(g) = extract_proxy_group(&proxies, "Claude-Fixed") {
            let target = preferred_node
                .filter(|p| !p.is_empty() && !is_blocked_node_name(p) && g.all.iter().any(|n| n == p))
                .map(|s| s.to_string())
                .or_else(|| {
                    if !g.now.is_empty() && !is_blocked_node_name(&g.now) {
                        Some(g.now.clone())
                    } else {
                        crate::mihomo::pick_best_verified_node(&g.all)
                    }
                });
            if let Some(t) = target.as_deref() {
                let _ = sync_clash_selection_everywhere(&ep, t).await;
                if g.now != t {
                    crate::mihomo::reset_node_drift_history(t);
                    notes.push(format!("已恢复并同步锁定节点「{t}」"));
                }
            }
        }
        if let Ok(m_cfg) = fetch_configs(&ep).await {
            if m_cfg.mode.eq_ignore_ascii_case("global") {
                let global_now = extract_proxy_group(&proxies, "GLOBAL")
                    .map(|gg| gg.now)
                    .unwrap_or_default();
                if !global_now.eq_ignore_ascii_case("Claude-Fixed") {
                    if select_proxy_in_group(&ep, "GLOBAL", "Claude-Fixed")
                        .await
                        .is_ok()
                    {
                        notes.push("已自动将 GLOBAL 锁回 Claude-Fixed".to_string());
                    }
                }
            }
        }
    }

    if notes.is_empty() {
        String::new()
    } else {
        format!("（{}）", notes.join("，"))
    }
}

/// 轮询等待 Clash Verge Mihomo 管道与本地代理端口上线（最多等待 max_wait_ms 毫秒）
async fn wait_clash_online_brief(max_wait_ms: u64) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_millis(max_wait_ms);
    loop {
        if let Some(ep) = discover_endpoint().await {
            let port = fetch_configs(&ep)
                .await
                .map(|c| c.mixed_port)
                .unwrap_or(7890);
            let open = tokio::task::spawn_blocking(move || {
                TcpStream::connect_timeout(
                    &SocketAddr::from(([127, 0, 0, 1], port)),
                    Duration::from_millis(250),
                )
                .is_ok()
            })
            .await
            .unwrap_or(false);
            if open {
                return true;
            }
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(450)).await;
    }
}

/// 安全开启 Clash TUN（严禁使用 taskkill /F 强杀 Clash 进程导致物理网卡残留 127.0.0.1 DNS）：
/// 1) 若 Clash 在线，优先通过 Mihomo API `PATCH /configs {"tun":{"enable":true}}` 热开启 TUN；
/// 2) 若 Clash 未运行，则安全拉起 Clash Verge 进程加载已写入的 `verge.yaml`；
/// 3) 等待 Wintun 虚拟网卡与内核状态就绪。
async fn enable_clash_tun_safely_without_kill(wait_tun: bool) -> bool {
    if let Some(ep) = discover_endpoint().await {
        if wait_tun {
            let _ = patch_tun_enabled(&ep, true).await;
        }
    } else {
        if !bring_clash_verge_to_front() {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(1000)).await;
        if !wait_clash_online_brief(9000).await {
            return false;
        }
        if wait_tun {
            if let Some(ep) = discover_endpoint().await {
                let _ = patch_tun_enabled(&ep, true).await;
            }
        }
    }

    if wait_tun {
        let deadline = std::time::Instant::now() + Duration::from_millis(4000);
        loop {
            let tun_ok = match discover_endpoint().await {
                Some(ep) => fetch_configs(&ep).await.map(|c| c.tun_enable).unwrap_or(false),
                None => false,
            };
            let adapter_ok = tokio::task::spawn_blocking(inspect_wintun_adapter)
                .await
                .ok()
                .flatten()
                .is_some();
            if tun_ok && adapter_ok {
                break;
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(350)).await;
        }
    }
    true
}

/// 严禁再对第三方代理客户端执行 `taskkill /F` 强制硬杀，避免跳过退出钩子残留物理网卡 127.0.0.1 DNS。
async fn restart_clash_and_wait_online(wait_tun: bool) -> bool {
    enable_clash_tun_safely_without_kill(wait_tun).await
}

/// 真正启动或唤起已安装的 Clash Verge 主窗口到前台（绝不空弹窗欺骗用户）
fn bring_clash_verge_to_front() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(pf) = std::env::var("ProgramFiles") {
            candidates.push(PathBuf::from(pf).join(r"Clash Verge\clash-verge.exe"));
        }
        if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
            candidates.push(PathBuf::from(pf86).join(r"Clash Verge\clash-verge.exe"));
        }
        if let Some(local_app) = dirs::data_local_dir() {
            candidates.push(local_app.join(r"Programs\Clash Verge\clash-verge.exe"));
            candidates.push(local_app.join(r"Clash Verge\clash-verge.exe"));
        }

        // 先尝试从已安装的固定路径直接拉起（Clash Verge 单实例会自动把已有窗口提到前台！）
        for path in candidates {
            if path.exists() {
                if Command::new(&path).spawn().is_ok() {
                    return true;
                }
            }
        }

        // 兜底：从正在运行的 clash-verge 进程路径启动唤起前台
        let out = Command::new("powershell")
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                "-NoProfile",
                "-Command",
                "$p = (Get-Process -Name 'clash-verge' -ErrorAction SilentlyContinue | Select-Object -First 1).Path; if ($p) { Start-Process -FilePath $p; Write-Output 'OK' }",
            ])
            .output();
        if let Ok(o) = out {
            if String::from_utf8_lossy(&o.stdout).contains("OK") {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_ip_range_check_exact_cidr() {
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 18, 0, 14)));
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 19, 255, 254)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(198, 17, 255, 255)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(198, 20, 0, 1)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(104, 18, 32, 47)));
    }

    #[test]
    fn masks_ipv4_and_ipv6_without_leaking_full_ip() {
        assert_eq!(mask_ip_address("104.28.192.44"), "104.28.xx.xx");
        assert_eq!(mask_ip_address("2606:4700:4700::1111"), "2606:4700:****");
    }

    #[test]
    fn detects_third_party_anthropic_base_url() {
        assert!(!is_third_party_base_url(""));
        assert!(!is_third_party_base_url("https://api.anthropic.com"));
        assert!(!is_third_party_base_url("https://api.anthropic.com/v1"));
        assert!(is_third_party_base_url("https://relay.thirdparty-proxy.cc/v1"));
        assert!(is_third_party_base_url("http://127.0.0.1:8080"));
    }

    #[test]
    fn merges_privacy_settings_without_clobbering_user_keys() {
        let original = r#"{
            "theme": "dark",
            "permissions": {"allow": ["Read"]},
            "env": {"CUSTOM_FLAG": "keep"}
        }"#;
        let merged = merge_claude_privacy_settings(Some(original)).unwrap();
        let val: Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(val["theme"], "dark");
        assert_eq!(val["permissions"]["allow"][0], "Read");
        assert_eq!(val["env"]["CUSTOM_FLAG"], "keep");
        assert_eq!(val["env"]["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1");
        assert_eq!(val["env"]["DISABLE_ERROR_REPORTING"], "1");
    }

    #[test]
    fn detects_ban_contamination_keywords() {
        let log = "44299 [error] {\"error_code\":\"region_unavailable\"}\n57151 account_banned\n56272 OAuth token revoked <json error=permission_error len=130>";
        let hits = scan_text_for_ban_contamination(log);
        assert!(hits.contains(&"region_unavailable"));
        assert!(hits.contains(&"account_banned"));
        assert!(hits.contains(&"oauth_token_revoked"));
        assert!(hits.contains(&"oauth_403_revoked_permission"));

        // len=164（Persona 身份验证 KYC / 未订阅权限受限）绝不可误判为封号污染，但需被 KYC 提示检出
        let kyc_log = "2026-11-24 10:07:17 [info] oauth failed: authorize returned 403 <json error=permission_error len=164>";
        assert!(scan_text_for_ban_contamination(kyc_log).is_empty());
        assert!(scan_text_for_kyc_or_perm_notice(kyc_log));
        assert!(scan_text_for_ban_contamination("token renewal ok").is_empty());
    }

    #[test]
    fn parses_sntp_packet_drift_accurately() {
        let mut pkt = [0u8; 48];
        let unix_now = 1_763_900_000u32;
        let ntp_secs = unix_now + 2_208_988_800u32;
        pkt[40..44].copy_from_slice(&ntp_secs.to_be_bytes());
        let drift = parse_ntp_drift_seconds(&pkt, unix_now as f64 + 0.25).unwrap();
        assert!((drift - 0.25).abs() < 0.01);
    }

    #[test]
    fn evaluates_windows_location_privacy_strictly() {
        let (ok, issues) = evaluate_location_privacy("Deny", "Deny", "Deny", Some(4), false);
        assert!(ok, "all denied + lfsvc disabled should pass: {issues:?}");

        let (ok2, issues2) = evaluate_location_privacy("Deny", "Deny", "Deny", Some(3), true);
        assert!(!ok2, "running lfsvc must fail");
        assert!(issues2.iter().any(|s| s.contains("lfsvc")));

        let (ok3, issues3) = evaluate_location_privacy("Allow", "Deny", "Allow", Some(4), false);
        assert!(!ok3, "Allow in HKLM/NonPackaged must fail");
        assert_eq!(issues3.len(), 2);
    }

    #[test]
    fn evaluates_ip_purity_timezone_and_proxy_extensions() {
        assert_eq!(
            classify_ip_purity_and_risk("AS63949 Linode", Some(true), Some(false), Some(false), Some(false)),
            ("常规机房", "hosting", "0 滥用记录")
        );
        assert_eq!(
            classify_ip_purity_and_risk("AS1234 Residential", Some(false), Some(false), Some(false), Some(false)),
            ("ISP 住宅", "isp", "无代理标记")
        );
        assert_eq!(
            classify_ip_purity_and_risk("Any Org", Some(true), Some(true), Some(false), Some(false)),
            ("共享代理", "proxy", "公共 VPN / 代理段")
        );
        assert_eq!(
            classify_ip_purity_and_risk("Any Org", Some(true), Some(false), Some(false), Some(true)),
            ("高危滥用", "abuser", "命中滥用黑名单")
        );

        assert_eq!(compute_timezone_hour_gap(8, "AU"), Some((0, "UTC+8 ~ UTC+11")));
        assert_eq!(compute_timezone_hour_gap(8, "JP"), Some((1, "UTC+9")));
        assert_eq!(compute_timezone_hour_gap(8, "US"), Some((12, "UTC-8 ~ UTC-4")));

        assert_eq!(
            match_proxy_extension_label("padekgcemlokbadohgkifijomclgjgif", ""),
            Some("Proxy SwitchyOmega".to_string())
        );
        assert_eq!(match_proxy_extension_label("randomid123", "AdBlock"), None);
    }

    #[test]
    fn ipv6_virtual_adapter_filter_and_group_boundary_rules() {
        // 1. Clash TUN 虚拟网卡必须豁免，物理网卡严格保留
        assert!(is_clash_tun_virtual_adapter("Mihomo", "Wintun Userspace Tunnel"));
        assert!(is_clash_tun_virtual_adapter("Clash", "Meta Wintun Adapter"));
        assert!(is_clash_tun_virtual_adapter("tun0", "Wintun Userspace Tunnel"));
        assert!(!is_clash_tun_virtual_adapter("WLAN", "Intel(R) Wi-Fi 6 AX201"));
        assert!(!is_clash_tun_virtual_adapter("以太网", "Realtek PCIe GbE Family Controller"));

        // 2. 出口 IP 监测规则校验
        let old_rules = vec![
            json!({"payload": "anthropic.com", "proxy": "Claude-Fixed"}),
            json!({"payload": "claude.ai", "proxy": "Claude-Fixed"}),
        ];
        assert!(verify_claude_rules(&old_rules).0);
        assert!(!verify_exit_probe_rules(&old_rules));

        let new_rules = vec![
            json!({"payload": "anthropic.com", "proxy": "Claude-Fixed"}),
            json!({"payload": "claude.ai", "proxy": "Claude-Fixed"}),
            json!({"payload": "ip-api.com", "proxy": "Claude-Fixed"}),
        ];
        assert!(verify_exit_probe_rules(&new_rules));

        // 3. GLOBAL 模式脱组必须标红 Fail；GLOBAL -> Claude-Fixed 必须绿灯 Ok
        let mut proxies = std::collections::HashMap::new();
        proxies.insert(
            "Claude-Fixed".to_string(),
            json!({"name": "Claude-Fixed", "type": "Selector", "now": "🇯🇵日本2|流媒体AI", "all": ["🇯🇵日本1|流媒体AI", "🇯🇵日本2|流媒体AI"]}),
        );
        proxies.insert(
            "GLOBAL".to_string(),
            json!({"name": "GLOBAL", "type": "Selector", "now": "天悦云", "all": ["Claude-Fixed", "天悦云"]}),
        );
        let cfg_global = MihomoConfigs {
            mixed_port: 7890,
            ipv6: false,
            tun_enable: true,
            dns_enhanced_mode: "fake-ip".into(),
            mode: "global".into(),
        };
        let (escaped_item, _, escaped_ok, escaped_danger) =
            probe_group_and_rules(Some(&proxies), Some(&new_rules), Some(&cfg_global), Some("🇯🇵日本1|流媒体AI"));
        assert_eq!(escaped_item.status, CheckStatus::Fail);
        assert!(!escaped_ok);
        assert!(escaped_danger);
        assert!(escaped_item.summary.contains("脱离 Claude-Fixed"));

        // 切回 GLOBAL -> Claude-Fixed，且 Claude-Fixed 内从 日本1 切到了 日本2（符合 3A 自动跟随绿灯）
        proxies.insert(
            "GLOBAL".to_string(),
            json!({"name": "GLOBAL", "type": "Selector", "now": "Claude-Fixed", "all": ["Claude-Fixed", "天悦云"]}),
        );
        let (ok_item, cur_node, ok_pass, ok_danger) =
            probe_group_and_rules(Some(&proxies), Some(&new_rules), Some(&cfg_global), Some("🇯🇵日本1|流媒体AI"));
        assert_eq!(ok_item.status, CheckStatus::Ok);
        assert!(ok_pass);
        assert!(!ok_danger);
        assert_eq!(cur_node, "🇯🇵日本2|流媒体AI");
    }

    #[tokio::test]
    #[ignore = "实机只读探针自审验证"]
    async fn live_machine_preflight_audit() {
        let cfg = AppConfig::default();
        let bundle = run_all_preflight_checks(&cfg, 0).await;
        println!(
            "=== LIVE SNAPSHOT: {} | node={} ({}) | ip={} | lat={} | must={}/{} | opt={}/{} | status={} ===",
            bundle.snapshot.status_label,
            bundle.snapshot.current_node,
            bundle.snapshot.region_code,
            bundle.snapshot.exit_ip_masked,
            bundle.snapshot.latency_label,
            bundle.snapshot.must_passed,
            bundle.snapshot.must_total,
            bundle.snapshot.opt_passed,
            bundle.snapshot.opt_total,
            bundle.snapshot.anthropic_status_indicator
        );
        for item in &bundle.report.items {
            println!("[{:?}] {} => {}", item.status, item.id, item.summary);
        }
        assert_eq!(bundle.report.items.len(), 17);
        assert_eq!(bundle.snapshot.must_total, 11);
        assert_eq!(bundle.snapshot.opt_total, 6);
        assert!(bundle.snapshot.clash_online);
    }

    #[tokio::test]
    #[ignore = "真机全覆盖闭环验收（IPv6 豁免 Mihomo、策略组 GLOBAL 脱组识别、真实单节点深度核验落盘与恢复）"]
    async fn live_e2e_edge_cases_audit() {
        let ep = discover_endpoint().await.expect("Clash Verge Mihomo must be online");
        let cfg_before = fetch_configs(&ep).await.expect("fetch_configs ok");
        let proxies = fetch_proxies_raw(&ep).await.expect("fetch_proxies ok");
        let group = extract_proxy_group(&proxies, "Claude-Fixed").expect("Claude-Fixed exists");
        let orig_node = group.now.clone();
        println!(
            "=== [E2E-0] INITIAL: mode={} | tun_enable={} | Claude-Fixed={} ===",
            cfg_before.mode, cfg_before.tun_enable, orig_node
        );

        // 场景 A：真机核验 sys_ipv6 自动豁免 Mihomo 虚拟网卡（不误报 Mihomo）
        let ipv6_item = probe_ipv6_windows_only().await;
        println!(
            "=== [E2E-A] LIVE IPv6: status={:?} | summary={} ===\n{}",
            ipv6_item.status, ipv6_item.summary, ipv6_item.evidence
        );
        assert!(
            !ipv6_item.summary.contains("Mihomo"),
            "Mihomo Wintun virtual adapter must not trigger false IPv6 failure"
        );

        // 场景 B：真机执行一次当前锁定节点的真实 HTTP 深度核验，验证真实 IP / CF 盾 / AGY 落盘缓存
        let rec = crate::mihomo::probe_single_node_deep_via_proxy(&orig_node, cfg_before.mixed_port).await;
        println!(
            "=== [E2E-B] LIVE DEEP PROBE ({orig_node}): cc={} | ip={} | type={} ({}) | claude={} (cf_web={}) | agy={} ===",
            rec.country_code,
            rec.masked_ip,
            rec.asn_purity,
            rec.risk_detail,
            rec.claude_label,
            rec.web_cf_challenge,
            rec.gemini_label
        );
        assert!(!rec.country_code.is_empty());
        assert!(
            crate::mihomo::get_fresh_verified_record(&orig_node).is_some(),
            "verified record must be persisted to disk cache"
        );

        // 场景 C：验证全量体检 17 项输出中，node_geo 绝不出现「漂移 0 次预警」的假警告
        let b = run_all_preflight_checks(&AppConfig::default(), 0).await;
        let geo_item = b.report.items.iter().find(|i| i.id == "node_geo").unwrap();
        let grp_item = b.report.items.iter().find(|i| i.id == "node_group").unwrap();
        println!("=== [E2E-C] node_group ({:?}): {} ===", grp_item.status, grp_item.summary);
        println!("=== [E2E-C] node_geo ({:?}): {} ===\n{}", geo_item.status, geo_item.summary, geo_item.evidence);
        assert!(!geo_item.summary.contains("漂移 0 次预警"));
    }

    #[test]
    fn injects_claude_fixed_group_and_repairs_broken_empty_profile_script() {
        let sample_yaml = r#"
mode: rule
ipv6: true
proxies:
  - name: "🇭🇰香港1|流媒体AI"
    type: ss
  - name: "🇦🇺澳大利亚|原生"
    type: anytls
  - name: "🇯🇵日本3|流媒体AI"
    type: anytls
proxy-groups:
  - name: "天悦云"
    type: select
    proxies:
      - "🇦🇺澳大利亚|原生"
rules:
  - "DOMAIN-SUFFIX,claude.ai,天悦云"
  - "DOMAIN-SUFFIX,anthropic.com,Claude-Fixed"
  - "MATCH,天悦云"
"#;
        let mut doc: serde_yaml::Value = serde_yaml::from_str(sample_yaml).unwrap();
        let safe_cnt = inject_claude_fixed_into_yaml_value(&mut doc).unwrap();
        assert_eq!(safe_cnt, 2, "must exclude HK blocked region");
        assert_eq!(doc.get("ipv6").and_then(|v| v.as_bool()), Some(false));

        let groups = doc.get("proxy-groups").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(
            groups[0].get("name").and_then(|v| v.as_str()),
            Some("Claude-Fixed")
        );
        assert_eq!(
            groups[0].get("type").and_then(|v| v.as_str()),
            Some("select")
        );
        let group_proxies: Vec<&str> = groups[0]
            .get("proxies")
            .and_then(|v| v.as_sequence())
            .unwrap()
            .iter()
            .filter_map(|p| p.as_str())
            .collect();
        assert_eq!(group_proxies, vec!["🇦🇺澳大利亚|原生", "🇯🇵日本3|流媒体AI"]);

        let rules: Vec<&str> = doc
            .get("rules")
            .and_then(|v| v.as_sequence())
            .unwrap()
            .iter()
            .filter_map(|r| r.as_str())
            .collect();
        assert_eq!(rules[0], "DOMAIN-SUFFIX,sentry.io,REJECT");
        let claude_rule_idx = rules
            .iter()
            .position(|r| *r == "DOMAIN-SUFFIX,claude.ai,Claude-Fixed")
            .unwrap();
        let old_rule_idx = rules
            .iter()
            .position(|r| *r == "DOMAIN-SUFFIX,claude.ai,天悦云")
            .unwrap();
        assert!(
            claude_rule_idx < old_rule_idx,
            "Claude-Fixed rule must precede subscription fallback rule"
        );
        // 去重断言：anthropic.com 只出现一次
        assert_eq!(
            rules
                .iter()
                .filter(|r| **r == "DOMAIN-SUFFIX,anthropic.com,Claude-Fixed")
                .count(),
            1
        );

        // 坏脚本自动修复断言
        let broken = "// Define main function (script entry)\n\nfunction main(config) {\n  \n}\n";
        let repaired = repair_broken_script_text(broken).expect("broken script must be repaired");
        assert!(repaired.contains("return config;"));

        let healthy = "function main(config) {\n  config.ipv6 = false;\n  return config;\n}\n";
        assert!(
            repair_broken_script_text(healthy).is_none(),
            "healthy user script must not be overwritten"
        );
    }

    #[tokio::test]
    #[ignore = "真机一键直接写入策略组并热重载验收（直接把本机缺失的 Claude-Fixed 注入并验证立刻变绿）"]
    async fn live_direct_clash_rule_injection_audit() {
        let ep = discover_endpoint().await.expect("Clash Verge Mihomo must be online");
        let res = apply_clash_rules_directly_and_reload(&ep)
            .await
            .expect("direct rule injection & reload must succeed");
        println!("=== [DIRECT INJECT RESULT] {res} ===");

        let proxies = fetch_proxies_raw(&ep).await.expect("fetch proxies ok");
        let g = extract_proxy_group(&proxies, "Claude-Fixed")
            .expect("Claude-Fixed must exist immediately after hot reload");
        let rules = fetch_rules_raw(&ep).await.expect("fetch rules ok");
        let (rules_ok, rule_cnt) = verify_claude_rules(&rules);
        let exit_ok = verify_exit_probe_rules(&rules);
        println!(
            "=== [VERIFY] Claude-Fixed.now={} ({} nodes) | rules_ok={} ({rule_cnt}) | exit_ok={} ===",
            g.now,
            g.all.len(),
            rules_ok,
            exit_ok
        );
        assert!(g.group_type.eq_ignore_ascii_case("Selector"));
        assert!(!g.all.is_empty());
        assert!(rules_ok, "Claude rules must be active immediately");
        assert!(exit_ok, "Exit probe rules must be active immediately");

        let b = run_all_preflight_checks(&AppConfig::default(), 0).await;
        let grp_item = b.report.items.iter().find(|i| i.id == "node_group").unwrap();
        println!(
            "=== [PREFLIGHT node_group] status={:?} | summary={} ===",
            grp_item.status, grp_item.summary
        );
        assert_eq!(grp_item.status, CheckStatus::Ok);
    }

    #[tokio::test]
    #[ignore = "Stage 3 真机全场景交互验收：AGY 送中对比、Direct→Rule 切回、TUN 关→开闭环、真实日志 KYC/封号分离与通知去重"]
    async fn live_full_stage3_real_machine_audit() {
        let ep = discover_endpoint().await.expect("Clash Verge Mihomo must be online");
        let cfg_init = fetch_configs(&ep).await.expect("fetch_configs ok");
        let proxies_init = fetch_proxies_raw(&ep).await.expect("fetch_proxies ok");
        let group_init = extract_proxy_group(&proxies_init, "Claude-Fixed")
            .expect("Claude-Fixed must exist");
        let orig_mode = cfg_init.mode.to_ascii_lowercase();
        let orig_node = if group_init.now.contains("日本1") {
            group_init
                .all
                .iter()
                .find(|n| n.contains("澳大利亚"))
                .cloned()
                .unwrap_or_else(|| group_init.now.clone())
        } else {
            group_init.now.clone()
        };
        println!(
            "=== [STAGE3-0] 初始态: mode={orig_mode} | tun={} | restore_node={orig_node} ===",
            cfg_init.tun_enable
        );

        // 1) AGY 送中真探针对比：🇯🇵日本1|流媒体AI vs 🇦🇺澳大利亚|原生（测完立刻还原节点）
        if let Some(jp1) = group_init.all.iter().find(|n| n.contains("日本1")) {
            select_proxy_in_group(&ep, "Claude-Fixed", jp1).await.unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
            let rec_jp = crate::mihomo::probe_single_node_deep_via_proxy(jp1, cfg_init.mixed_port).await;
            println!(
                "=== [STAGE3-1A] AGY 日本1真测: cc={} | ip={} | claude={} | agy={} (status={}) ===",
                rec_jp.country_code, rec_jp.masked_ip, rec_jp.claude_label, rec_jp.gemini_label, rec_jp.gemini_status
            );
            assert!(
                matches!(rec_jp.gemini_status.as_str(), "restricted" | "cn_redirect"),
                "JP1 redirected to google.com.hk must be marked restricted/cn_redirect, got {}",
                rec_jp.gemini_status
            );
            assert_eq!(rec_jp.gemini_label, "AGY 限区");
        }
        // 立刻恢复原节点并测澳洲 AGY
        select_proxy_in_group(&ep, "Claude-Fixed", &orig_node).await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let rec_au = crate::mihomo::probe_single_node_deep_via_proxy(&orig_node, cfg_init.mixed_port).await;
        println!(
            "=== [STAGE3-1B] AGY 原节点真测 ({orig_node}): cc={} | ip={} | claude={} | agy={} (status={}) ===",
            rec_au.country_code, rec_au.masked_ip, rec_au.claude_label, rec_au.gemini_label, rec_au.gemini_status
        );
        if orig_node.contains("澳大利亚") {
            assert_eq!(rec_au.gemini_status, "ok", "AU native node must pass AGY ✓");
        }

        // 2) Direct 模式 → 一键 execute_fix_item("node_group") 切回 Rule 并同步写盘 → 测完还原用户原模式
        let _ = crate::mihomo::mihomo_request(&ep, "PATCH", "/configs", Some(r#"{"mode":"direct"}"#)).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        let cfg_direct = fetch_configs(&ep).await.unwrap();
        assert_eq!(cfg_direct.mode.to_ascii_lowercase(), "direct");

        let fix_mode = execute_fix_item("node_group", &AppConfig::default(), 0)
            .await
            .expect("execute_fix_item node_group must succeed");
        let cfg_after_rule = fetch_configs(&ep).await.unwrap();
        println!(
            "=== [STAGE3-2] Direct→Rule 一键修复: success={} | mode_now={} | msg={} ===",
            fix_mode.success, cfg_after_rule.mode, fix_mode.message
        );
        assert_eq!(cfg_after_rule.mode.to_ascii_lowercase(), "rule");
        // 验证 config.yaml 同步落盘
        if let Some(dir) = clash_verge_config_dir() {
            let cfg_disk = fs::read_to_string(dir.join("config.yaml")).unwrap_or_default();
            assert!(cfg_disk.contains("mode: rule"), "config.yaml must sync mode: rule");
        }
        // 还原用户原始 mode（例如 global）
        if orig_mode != "rule" {
            let body = format!(r#"{{"mode":"{orig_mode}"}}"#);
            let _ = crate::mihomo::mihomo_request(&ep, "PATCH", "/configs", Some(&body)).await;
            let _ = sync_clash_mode_to_disk(&orig_mode);
        }

        // 3) TUN 关闭 → 验证变红 → 一键 execute_fix_item("node_tun") 拉起并同步写 verge.yaml → 验证实测变绿
        let _ = crate::mihomo::mihomo_request(&ep, "PATCH", "/configs", Some(r#"{"tun":{"enable":false}}"#)).await;
        tokio::time::sleep(Duration::from_millis(450)).await;
        let tun_off_cfg = fetch_configs(&ep).await.unwrap();
        println!("=== [STAGE3-3A] TUN 已临时关闭验证: tun.enable={} ===", tun_off_cfg.tun_enable);
        assert!(!tun_off_cfg.tun_enable);

        let fix_tun = execute_fix_item("node_tun", &AppConfig::default(), 0)
            .await
            .expect("execute_fix_item node_tun must succeed");
        let tun_on_cfg = fetch_configs(&ep).await.unwrap();
        let tun_item = fix_tun.report.items.iter().find(|i| i.id == "node_tun").unwrap();
        println!(
            "=== [STAGE3-3B] TUN 一键开启验收: success={} | status={:?} | tun.enable={} | msg={} ===",
            fix_tun.success, tun_item.status, tun_on_cfg.tun_enable, fix_tun.message
        );
        assert!(tun_on_cfg.tun_enable, "Mihomo tun.enable must be true");
        assert_eq!(tun_item.status, CheckStatus::Ok, "node_tun must become Ok");
        if let Some(dir) = clash_verge_config_dir() {
            let verge_disk = fs::read_to_string(dir.join("verge.yaml")).unwrap_or_default();
            assert!(
                verge_disk.contains("enable_tun_mode: true"),
                "verge.yaml must persist enable_tun_mode: true"
            );
        }

        // 4) 本机真实日志 KYC (len=164) 与封号分离 + 通知去重稳定性验证
        let (events_1, _) = crate::watchdog::collect_log_analysis(&[]);
        let (events_2, _) = crate::watchdog::collect_log_analysis(&[]);
        let ids_1: std::collections::HashSet<String> = events_1
            .iter()
            .filter(|e| e.anomaly)
            .map(|e| e.id.clone())
            .collect();
        let ids_2: std::collections::HashSet<String> = events_2
            .iter()
            .filter(|e| e.anomaly)
            .map(|e| e.id.clone())
            .collect();
        let new_on_second_scan = ids_2.difference(&ids_1).count();

        let final_bundle = run_all_preflight_checks(&AppConfig::default(), 0).await;
        let ban_item = final_bundle.report.items.iter().find(|i| i.id == "claude_ban").unwrap();
        let acct_item = final_bundle.report.items.iter().find(|i| i.id == "claude_acct").unwrap();
        println!(
            "=== [STAGE3-4] 真实日志验收: total_events={} | unique_alert_ids={} | second_scan_new={} | claude_ban={:?} | claude_acct={:?} ===",
            events_1.len(),
            ids_1.len(),
            new_on_second_scan,
            ban_item.status,
            acct_item.status
        );
        assert_eq!(new_on_second_scan, 0, "stable log must produce 0 repeated notifications");
        assert_eq!(ban_item.status, CheckStatus::Ok, "KYC len=164 must not trigger ban fail");
        assert_eq!(acct_item.status, CheckStatus::Ok, "KYC single account must not trigger multi-account lock");
    }

    #[tokio::test]
    #[ignore = "v0.2.2 真机全链路验收：自动清洗 AU/GB 错国脏漂移、右上角一键处理串联拉起 TUN、策略组默认挑最优合规节点"]
    async fn live_v022_one_click_cascade_and_drift_clean_audit() {
        let ep = discover_endpoint().await.expect("Clash Verge Mihomo must be online");
        let proxies = fetch_proxies_raw(&ep).await.unwrap();
        let g = extract_proxy_group(&proxies, "Claude-Fixed").expect("Claude-Fixed exists");

        // 1) 验证最优合规节点选择器确实挑出了低延迟/ISP/非共享代理节点
        let best = crate::mihomo::pick_best_verified_node(&g.all);
        println!("=== [v0.2.2-1] pick_best_verified_node => {:?} ===", best);
        assert!(best.is_some(), "should pick a verified healthy node");
        assert!(
            !best.as_deref().unwrap().contains("台湾"),
            "must not pick shared-proxy TW node"
        );

        // 2) 临时关闭 TUN → 调用真实的右上角 execute_one_click_fix_all → 验证一键处理串联自动打开 TUN 且 AU 0 假漂移全 11/11 通过！
        let _ = crate::mihomo::mihomo_request(&ep, "PATCH", "/configs", Some(r#"{"tun":{"enable":false}}"#)).await;
        tokio::time::sleep(Duration::from_millis(450)).await;
        assert!(!fetch_configs(&ep).await.unwrap().tun_enable);

        let batch = execute_one_click_fix_all(&AppConfig::default(), 0)
            .await
            .expect("one_click_fix_all must succeed");
        let tun_item = batch.report.items.iter().find(|i| i.id == "node_tun").unwrap();
        let geo_item = batch.report.items.iter().find(|i| i.id == "node_geo").unwrap();
        println!(
            "=== [v0.2.2-2] one_click_fix_all: fixed={:?} | must={}/{} | tun={:?} | geo={:?} ({}) ===",
            batch.fixed_ids,
            batch.snapshot.must_passed,
            batch.snapshot.must_total,
            tun_item.status,
            geo_item.status,
            geo_item.summary
        );
        assert!(
            batch.fixed_ids.iter().any(|id| id == "node_tun"),
            "one_click_fix_all must automatically fix node_tun"
        );
        assert_eq!(tun_item.status, CheckStatus::Ok, "node_tun must be Ok after one-click");
        assert_eq!(
            geo_item.status,
            CheckStatus::Ok,
            "cleaned AU cross-country glitch must yield 0 false drift and Ok"
        );
        assert!(
            geo_item.summary.contains("24h 0 漂移"),
            "AU must report 24h 0 drift after cleaning KR bleed, got: {}",
            geo_item.summary
        );
    }

    #[test]
    fn v024_anthropic_zh_and_verge_yaml_disables_sysproxy_when_enabling_tun() {
        assert_eq!(
            translate_anthropic_status_zh("minor", "Partially Degraded Service"),
            "部分服务降级"
        );
        assert_eq!(
            translate_anthropic_status_zh("none", "All Systems Operational"),
            "全部服务正常"
        );
        assert_eq!(
            translate_anthropic_status_zh("major", "Partial System Outage"),
            "部分服务中断"
        );
        assert_eq!(
            translate_anthropic_status_zh("critical", "Major Service Outage"),
            "重大服务故障"
        );

        let before = "sysproxy_tray_icon: false\nenable_tun_mode: false\nenable_system_proxy: true\n";
        let after_on = patch_verge_yaml_tun_and_sysproxy(before, true, true);
        assert!(after_on.contains("enable_tun_mode: true"));
        assert!(after_on.contains("enable_system_proxy: false"));

        let after_off = patch_verge_yaml_tun_and_sysproxy(&after_on, false, false);
        assert!(after_off.contains("enable_tun_mode: false"));
        assert!(after_off.contains("enable_system_proxy: false"));
    }

    #[test]
    fn t042_profiles_yaml_registers_global_script_and_supports_proxy_providers() {
        // 1. 全新 profiles.yaml 缺少 uid: Script 时自动补全注册
        let dir = tempfile::tempdir().unwrap();
        let profiles_yaml = dir.path().join("profiles.yaml");
        fs::write(
            &profiles_yaml,
            "current: sub1\nitems:\n- uid: sub1\n  type: remote\n  file: sub1.yaml\n",
        )
        .unwrap();
        let inserted = ensure_global_script_registered_in_profiles_yaml(dir.path()).unwrap();
        assert!(inserted);
        let updated = fs::read_to_string(&profiles_yaml).unwrap();
        assert!(updated.contains("uid: Script"));
        assert!(updated.contains("file: Script.js"));
        // 二次执行幂等不重复插入
        assert!(!ensure_global_script_registered_in_profiles_yaml(dir.path()).unwrap());

        // 2. 纯 proxy-providers 节点池订阅（顶层 proxies 为空）且 find-process-mode: off
        let mut doc: serde_yaml::Value = serde_yaml::from_str(
            r#"
mode: rule
find-process-mode: off
proxy-providers:
  AirportPool:
    type: http
    url: https://example.com/sub
proxy-groups:
  - name: Proxy
    type: select
    use: [AirportPool]
rules:
  - MATCH,Proxy
"#,
        )
        .unwrap();
        let cnt = inject_claude_fixed_into_yaml_value(&mut doc).unwrap();
        assert_eq!(cnt, 1);
        assert_eq!(
            doc.get("find-process-mode").and_then(|v| v.as_str()),
            Some("strict")
        );
        let groups = doc.get("proxy-groups").and_then(|v| v.as_sequence()).unwrap();
        let cf = groups
            .iter()
            .find(|g| g.get("name").and_then(|n| n.as_str()) == Some("Claude-Fixed"))
            .unwrap();
        let use_list = cf.get("use").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(use_list[0].as_str(), Some("AirportPool"));
        assert!(cf.get("exclude-filter").and_then(|v| v.as_str()).is_some());
    }

    #[test]
    fn t101_sys_env_conflict_and_fix_logic_for_dynamic_port_7897() {
        // Clash 真实监听 7897 时，环境残留 7890 必须被判为需清理；7897 自身保留
        assert!(should_clear_proxy_env_var("HTTP_PROXY", "http://127.0.0.1:7890", 7897));
        assert!(should_clear_proxy_env_var("HTTPS_PROXY", "http://127.0.0.1:7890", 7897));
        assert!(should_clear_proxy_env_var("ALL_PROXY", "socks5://127.0.0.1:7890", 7897));
        assert!(!should_clear_proxy_env_var("HTTP_PROXY", "http://127.0.0.1:7897", 7897));
        assert!(should_clear_proxy_env_var("NO_PROXY", "localhost,anthropic.com", 7897));
        assert!(should_clear_proxy_env_var("ANTHROPIC_BASE_URL", "https://relay.evil.test", 7897));
        assert!(!should_clear_proxy_env_var("ANTHROPIC_BASE_URL", "https://api.anthropic.com", 7897));
    }

    #[test]
    fn t101_no_hardcoded_7890_in_fix_paths_audit() {
        // 永久反硬编码自检门禁：防止 execute_fix_item / execute_one_click_fix_all 再次写死 7890
        let src = include_str!("mod.rs");
        let fix_start = src
            .find("pub async fn execute_fix_item(")
            .expect("execute_fix_item must exist");
        let fix_end = src
            .find("/// 同步写入 Clash Verge 全局覆写脚本")
            .or_else(|| src.find("const FD_CLAUDE_FIXED_RULES"))
            .unwrap_or(src.len());
        let fix_region = &src[fix_start..fix_end];
        assert!(
            !fix_region.contains("fix_system_proxy_and_env(7890)"),
            "禁止在修复路径硬编码 fix_system_proxy_and_env(7890)，必须使用 resolve_active_mixed_port().await"
        );
        assert!(
            !fix_region.contains(".map(|_| 7890"),
            "禁止在修复路径丢弃 endpoint 并硬编码 7890"
        );
    }

    #[test]
    fn t102_patch_profiles_yaml_puts_claude_fixed_first_and_syncs_main_group() {
        let raw = r#"
current: RccF24o0kwqF
items:
- uid: RccF24o0kwqF
  type: remote
  name: 天悦云
  selected:
  - name: 天悦云
    now: 🇦🇺澳大利亚|原生
  - name: 其他分流
    now: 🇭🇰香港1
"#;
        let patched = patch_profiles_yaml_selected(
            raw,
            "🇸🇬新加坡1|流媒体AI",
            &["天悦云".to_string()],
        )
        .unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&patched).unwrap();
        let sel = doc["items"][0]["selected"].as_sequence().unwrap();
        assert_eq!(sel[0]["name"].as_str(), Some("Claude-Fixed"));
        assert_eq!(sel[0]["now"].as_str(), Some("🇸🇬新加坡1|流媒体AI"));
        assert_eq!(sel[1]["name"].as_str(), Some("天悦云"));
        assert_eq!(sel[1]["now"].as_str(), Some("🇸🇬新加坡1|流媒体AI"));
        // 保留其他分流组不丢失
        assert_eq!(sel[2]["name"].as_str(), Some("其他分流"));
        assert_eq!(sel[2]["now"].as_str(), Some("🇭🇰香港1"));
    }

    #[test]
    fn t102_pick_best_compliant_node_prefers_native_isp_over_blocked_or_plain() {
        let nodes = vec![
            "🇭🇰香港1|流媒体AI".to_string(),
            "🇸🇬新加坡1|常规".to_string(),
            "🇦🇺澳大利亚|原生".to_string(),
        ];
        let best = pick_best_compliant_node(&nodes).unwrap();
        assert_eq!(best, "🇦🇺澳大利亚|原生");
    }

    #[test]
    fn batch1_p0_commercial_build_never_embeds_plaintext_override_script() {
        let src = include_str!("mod.rs");
        let needle = concat!("include_str!(\"", "../../../clash-scripts/claude-verge-override.js\")");
        assert!(
            !src.contains(needle),
            "禁止在商业版 preflight/mod.rs 中明文 include_str! 嵌入覆写脚本"
        );
    }

    #[test]
    fn batch3_repair_broken_script_preserves_https_urls_in_strings() {
        // 含 https:// 字符串后接 return config 的合法脚本绝不可被误判为损坏
        let valid_with_url = r#"function main(config) { const url = "https://example.com/a"; return config; }"#;
        assert!(repair_broken_script_text(valid_with_url).is_none());

        // 真正缺失 return 的空模板仍必须识别并修复
        let broken = "function main(config) { // return config; \n }";
        assert!(repair_broken_script_text(broken).is_some());
    }
}
