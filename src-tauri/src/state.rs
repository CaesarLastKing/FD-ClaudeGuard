use crate::config::AppConfig;
use crate::killswitch::KillSwitchState;
use crate::process::KillHoldController;
use crate::protocol::FULL_AUDIT_INTERVAL_MS;
use crate::watchdog::LogEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::RwLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    Fail,
    Warn,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CheckPart {
    Must,
    Opt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightItem {
    pub id: String,
    pub part: CheckPart,
    pub cat: String,
    pub icon: String,
    pub mode: String,
    pub title: String,
    pub status: CheckStatus,
    pub summary: String,
    pub evidence: String,
    pub guide: String,
    pub fix_label: Option<String>,
    pub is_kill_item: bool,
    pub is_failover: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightReport {
    pub checked_at: String,
    pub stage: String,
    pub items: Vec<PreflightItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupEntry {
    pub app: String,
    pub enabled: bool,
    pub risk_level: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupAuditReport {
    pub entries: Vec<StartupEntry>,
    pub claude_autostart_risk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HudEventLine {
    pub message: String,
    pub time: String,
    pub level: String,
    pub target_tab: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardSnapshot {
    pub health_level: String,
    pub status_label: String,
    pub current_node: String,
    pub region_code: String,
    pub exit_ip_masked: String,
    pub latency_ms: Option<u32>,
    pub latency_label: String,
    pub bg_claude_procs: u32,
    pub kill_switch_active: bool,
    pub kill_hold_active: bool,
    pub kill_hold_remaining_secs: u32,
    pub kill_hold_blocked_count: u32,
    pub kill_hold_tx_locked: bool,
    pub kill_hold_reason: String,
    pub node_down: bool,
    #[serde(default)]
    pub node_drift_warn: bool,
    pub must_passed: u32,
    pub must_total: u32,
    pub opt_passed: u32,
    pub opt_total: u32,
    pub clash_version: String,
    pub clash_port: u16,
    pub clash_online: bool,
    #[serde(default)]
    pub clash_installed: bool,
    pub anthropic_status_indicator: String, // "none" | "minor" | "major" | "critical" | "unknown"
    pub anthropic_status_desc: String,
    pub unread_log_anomalies: usize,
    /// T-202：未读高危异常数（level == "fail"）
    #[serde(default)]
    pub unread_log_critical: usize,
    /// T-202：未读风险提醒数（level == "warn"）
    #[serde(default)]
    pub unread_log_warnings: usize,
    pub active_flow_anomalies: usize,
    #[serde(default)]
    pub live_flow_anomalies: usize,
    pub next_full_audit_epoch_ms: u64,
    pub triggered_playbook_ids: Vec<String>,
    pub hud_events: Vec<HudEventLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NavigatePayload {
    pub tab: String,
    pub sub_tab: Option<String>,
    pub focus_item_id: Option<String>,
    pub open_playbook: Option<bool>,
}

pub struct AppState {
    pub config_path: PathBuf,
    pub config: RwLock<AppConfig>,
    pub snapshot: RwLock<GuardSnapshot>,
    pub last_report: RwLock<PreflightReport>,
    pub last_preflight_at: RwLock<Option<Instant>>,
    pub preflight_gate: tokio::sync::Mutex<()>,
    pub killswitch: RwLock<KillSwitchState>,
    pub kill_hold: RwLock<KillHoldController>,
    pub injected_logs: RwLock<Vec<LogEvent>>,
    pub hud_move_seq: AtomicU64,
    pub alert_dedup: RwLock<HashMap<String, Instant>>,
    /// 是否已完成至少一轮真实启动体检（与 `last_preflight_at` 缓存 TTL 解耦，防止撤回/急救清空缓存后防裸奔失明）
    pub initial_preflight_done: std::sync::atomic::AtomicBool,
    /// 熔断通道是否已持有事务级 Kill-Hold 锁（防止并发或重复触发熔断导致 tx_lock_count 引用计数泄漏）
    pub killswitch_tx_held: std::sync::atomic::AtomicBool,
    /// 用户在「实时流量监控」中点击「全部标为已处理」的异常连接 ID 集合（同步清零侧边栏与 HUD 报警灯）
    pub acked_flow_ids: RwLock<std::collections::HashSet<String>>,
}

impl AppState {
    pub fn new(config_path: PathBuf, config: AppConfig) -> Self {
        let snapshot = build_initial_snapshot(&config);
        let report = build_m1_preflight_report();
        Self {
            config_path,
            config: RwLock::new(config),
            snapshot: RwLock::new(snapshot),
            last_report: RwLock::new(report),
            last_preflight_at: RwLock::new(None),
            preflight_gate: tokio::sync::Mutex::new(()),
            killswitch: RwLock::new(KillSwitchState::default()),
            kill_hold: RwLock::new(KillHoldController::default()),
            injected_logs: RwLock::new(Vec::new()),
            hud_move_seq: AtomicU64::new(0),
            alert_dedup: RwLock::new(HashMap::new()),
            initial_preflight_done: std::sync::atomic::AtomicBool::new(false),
            killswitch_tx_held: std::sync::atomic::AtomicBool::new(false),
            acked_flow_ids: RwLock::new(std::collections::HashSet::new()),
        }
    }
}

pub fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn build_initial_snapshot(cfg: &AppConfig) -> GuardSnapshot {
    let mut triggered = Vec::new();
    if cfg.calm_24h {
        triggered.push("pb_24h".to_string());
    }
    let now = chrono::Local::now().format("%H:%M").to_string();

    GuardSnapshot {
        health_level: "warn".to_string(),
        status_label: "正在实测".to_string(),
        current_node: "正在探测".to_string(),
        region_code: "GL".to_string(),
        exit_ip_masked: "待探测出口 IP".to_string(),
        latency_ms: None,
        latency_label: "待测".to_string(),
        bg_claude_procs: 0,
        kill_switch_active: false,
        kill_hold_active: false,
        kill_hold_remaining_secs: 0,
        kill_hold_blocked_count: 0,
        kill_hold_tx_locked: false,
        kill_hold_reason: String::new(),
        node_down: false,
        node_drift_warn: false,
        must_passed: 0,
        must_total: 12,
        opt_passed: 0,
        opt_total: 7,
        clash_version: "正在探测".to_string(),
        clash_port: 7890,
        clash_online: false,
        clash_installed: false,
        anthropic_status_indicator: "unknown".to_string(),
        anthropic_status_desc: "检测官方状态中".to_string(),
        unread_log_anomalies: 0,
        unread_log_critical: 0,
        unread_log_warnings: 0,
        active_flow_anomalies: 0,
        live_flow_anomalies: 0,
        next_full_audit_epoch_ms: now_epoch_ms() + FULL_AUDIT_INTERVAL_MS,
        triggered_playbook_ids: triggered,
        hud_events: vec![HudEventLine {
            message: "正在执行两级三防线真实探针实测...".to_string(),
            time: now,
            level: "warn".to_string(),
            target_tab: "console".to_string(),
        }],
    }
}

/// 初始诚实体检清单（v1.6 增量 16：三大纯粹操作边界 10 项必须 + 3 项建议，绝不伪造绿灯）
pub fn build_m1_preflight_report() -> PreflightReport {
    let items = vec![
        // 1. 代理与节点（改 Clash 配置 · 5 项）
        PreflightItem {
            id: "node_proxy".into(),
            part: CheckPart::Must,
            cat: "1. 代理与节点（改 Clash 配置）".into(),
            icon: "proxy".into(),
            mode: "自动一键".into(),
            title: "代理引擎在线与端口独占".into(),
            status: CheckStatus::Fail,
            summary: "正在连接 Clash Verge Mihomo 管道...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "node_group".into(),
            part: CheckPart::Must,
            cat: "1. 代理与节点（改 Clash 配置）".into(),
            icon: "group".into(),
            mode: "向导 + 实测验收".into(),
            title: "策略组与全家桶规则锁死".into(),
            status: CheckStatus::Fail,
            summary: "正在实查 Claude-Fixed 策略组与规则表...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "node_tun".into(),
            part: CheckPart::Must,
            cat: "1. 代理与节点（改 Clash 配置）".into(),
            icon: "fw".into(),
            mode: "向导 + 实测验收".into(),
            title: "虚拟网卡接管（Clash TUN）".into(),
            status: CheckStatus::Fail,
            summary: "正在实查 Mihomo TUN 与 Wintun 虚拟网卡...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "node_dns".into(),
            part: CheckPart::Must,
            cat: "1. 代理与节点（改 Clash 配置）".into(),
            icon: "dns".into(),
            mode: "向导 + 实测验收".into(),
            title: "DNS 防泄漏（Clash Fake-IP）".into(),
            status: CheckStatus::Fail,
            summary: "正在实测 claude.ai Fake-IP 解析...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "node_geo".into(),
            part: CheckPart::Must,
            cat: "1. 代理与节点（改 Clash 配置）".into(),
            icon: "geo".into(),
            mode: "自动一键".into(),
            title: "出口节点真实可达性".into(),
            status: CheckStatus::Fail,
            summary: "正在经代理探测出口 IP 白名单与 Anthropic 真实可达性...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        // 2. Windows 系统环境（改系统 · 3 项）
        PreflightItem {
            id: "sys_ipv6".into(),
            part: CheckPart::Must,
            cat: "2. Windows 系统环境（改系统）".into(),
            icon: "ipv6".into(),
            mode: "管理员一键 + 实测".into(),
            title: "Windows 网卡 IPv6 禁用".into(),
            status: CheckStatus::Fail,
            summary: "正在执行 Windows 网卡 IPv6 绑定与外网连通实测...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "sys_env".into(),
            part: CheckPart::Must,
            cat: "2. Windows 系统环境（改系统）".into(),
            icon: "startup".into(),
            mode: "自动一键".into(),
            title: "系统代理与环境变量冲突排查".into(),
            status: CheckStatus::Fail,
            summary: "正在扫描 CLI 代理环境变量与 WinINET 三端同 IP 一致性...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "sys_location".into(),
            part: CheckPart::Must,
            cat: "2. Windows 系统环境（改系统）".into(),
            icon: "location".into(),
            mode: "管理员一键 + 实测".into(),
            title: "Windows 系统定位服务关闭".into(),
            status: CheckStatus::Fail,
            summary: "正在检查 Windows 定位权限（HKLM/HKCU/NonPackaged）与 lfsvc 地理定位服务...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        // 3. Claude 本机卫生（改 Claude · 3 项）
        PreflightItem {
            id: "claude_ban".into(),
            part: CheckPart::Must,
            cat: "3. Claude 本机卫生（改 Claude）".into(),
            icon: "ban".into(),
            mode: "自动一键".into(),
            title: "本地封号污染残留审查".into(),
            status: CheckStatus::Fail,
            summary: "正在扫描本地污染残留...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "claude_acct".into(),
            part: CheckPart::Must,
            cat: "3. Claude 本机卫生（改 Claude）".into(),
            icon: "userLock".into(),
            mode: "引导确认".into(),
            title: "单号卫生锁（防混号与跨 orgId）".into(),
            status: CheckStatus::Fail,
            summary: "正在审计本机登录态与跨 orgId 竞态...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "claude_endpoint".into(),
            part: CheckPart::Must,
            cat: "3. Claude 本机卫生（改 Claude）".into(),
            icon: "endpoint".into(),
            mode: "自动一键".into(),
            title: "官方 API 端点防反代校验".into(),
            status: CheckStatus::Fail,
            summary: "正在核对 settings.json 与环境变量是否改写非官方 API 端点...".into(),
            evidence: "ANTHROPIC_BASE_URL / API_URL: 待检测".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "claude_tel".into(),
            part: CheckPart::Must,
            cat: "3. Claude 本机卫生（改 Claude）".into(),
            icon: "privacy".into(),
            mode: "自动一键".into(),
            title: "官方隐私降噪开关 & 遥测缓存".into(),
            status: CheckStatus::Fail,
            summary: "正在检查 ~/.claude/settings.json...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        // 二、建议优化（3 项）
        PreflightItem {
            id: "opt_boot".into(),
            part: CheckPart::Opt,
            cat: "系统辅助优化".into(),
            icon: "startup".into(),
            mode: "只读风险监测".into(),
            title: "开机启动项顺序风险检查（Clash / Claude）".into(),
            status: CheckStatus::Warn,
            summary: "正在只读审计 Windows 启动项...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "我们绝不擅自删除用户的启动项。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "opt_ntp".into(),
            part: CheckPart::Opt,
            cat: "系统辅助优化".into(),
            icon: "clock".into(),
            mode: "管理员一键".into(),
            title: "系统时钟 NTP 同步偏差".into(),
            status: CheckStatus::Warn,
            summary: "正在执行 NTP 时间偏差实测...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "opt_fw".into(),
            part: CheckPart::Opt,
            cat: "系统辅助优化".into(),
            icon: "fw".into(),
            mode: "管理员一键".into(),
            title: "防火墙 Kill Switch 权限就绪".into(),
            status: CheckStatus::Warn,
            summary: "正在检测免 UAC 守护任务与 FDClaudeGuard_KillSwitch_* 读写权限...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "opt_webrtc".into(),
            part: CheckPart::Opt,
            cat: "系统辅助优化".into(),
            icon: "privacy".into(),
            mode: "自动一键".into(),
            title: "浏览器 WebRTC 防泄露策略".into(),
            status: CheckStatus::Warn,
            summary: "正在检测 Chrome / Edge WebRTC 防泄露策略...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "opt_tz".into(),
            part: CheckPart::Opt,
            cat: "系统辅助优化".into(),
            icon: "clock".into(),
            mode: "只读风险监测".into(),
            title: "系统时区与出口地区一致性".into(),
            status: CheckStatus::Warn,
            summary: "正在比对本机系统时区与当前出口地区时差...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "opt_exit_geo".into(),
            part: CheckPart::Opt,
            cat: "系统辅助优化".into(),
            icon: "geo".into(),
            mode: "只读风险监测".into(),
            title: "出口节点合规性与属地一致性".into(),
            status: CheckStatus::Warn,
            summary: "正在比对账号归属地、24h IP 稳定性与网页端弹盾状态...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
        PreflightItem {
            id: "opt_browser_ext".into(),
            part: CheckPart::Opt,
            cat: "系统辅助优化".into(),
            icon: "group".into(),
            mode: "只读风险监测".into(),
            title: "浏览器独立代理插件冲突审计".into(),
            status: CheckStatus::Warn,
            summary: "正在只读审计 Chrome / Edge 代理类扩展...".into(),
            evidence: "Probe Status: Initializing".into(),
            guide: "正在执行真实探针检测。".into(),
            fix_label: None,
            is_kill_item: false,
            is_failover: false,
        },
    ];

    PreflightReport {
        checked_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        stage: "INIT".to_string(),
        items,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m1_preflight_never_fakes_green_light() {
        let report = build_m1_preflight_report();
        let must_items: Vec<_> = report
            .items
            .iter()
            .filter(|i| i.part == CheckPart::Must)
            .collect();
        let opt_items: Vec<_> = report
            .items
            .iter()
            .filter(|i| i.part == CheckPart::Opt)
            .collect();

        // 三大纯粹操作边界 12 项必须（改 Clash 5 + 改系统 3 + 改 Claude 4）+ 7 项建议（含时区下方的出口合规性）
        assert_eq!(must_items.len(), 12);
        assert_eq!(opt_items.len(), 7);
        let tz_idx = opt_items.iter().position(|i| i.id == "opt_tz").unwrap();
        let exit_geo_idx = opt_items.iter().position(|i| i.id == "opt_exit_geo").unwrap();
        assert_eq!(exit_geo_idx, tz_idx + 1, "出口合规性建议项必须紧跟系统时区下方");
        assert_eq!(
            must_items
                .iter()
                .filter(|i| i.cat.starts_with("1. 代理与节点"))
                .count(),
            5
        );
        assert_eq!(
            must_items
                .iter()
                .filter(|i| i.cat.starts_with("2. Windows 系统环境"))
                .count(),
            3
        );
        assert_eq!(
            must_items
                .iter()
                .filter(|i| i.cat.starts_with("3. Claude 本机卫生"))
                .count(),
            4
        );
        assert!(must_items.iter().any(|i| i.id == "claude_endpoint"));
        assert!(must_items.iter().any(|i| i.id == "node_tun"));
        assert!(must_items.iter().any(|i| i.id == "node_dns"));
        assert!(must_items.iter().any(|i| i.id == "sys_env"));
        assert!(must_items.iter().any(|i| i.id == "sys_location"));
        assert!(must_items.iter().all(|i| i.status != CheckStatus::Ok));
    }
}
