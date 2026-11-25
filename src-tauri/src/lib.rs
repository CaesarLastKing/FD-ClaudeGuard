pub mod config;
pub mod killswitch;
pub mod logger;
pub mod maintenance;
pub mod mihomo;
pub mod preflight;
pub mod process;
pub mod protocol;
pub mod rollback;
pub mod startup_audit;
pub mod state;
pub mod telemetry;
pub mod watchdog;

use crate::config::{
    default_config_path, load_config, save_config, should_start_hud_only, AppConfig,
    AppConfigPatch, WindowPos,
};
use crate::killswitch::{
    cleanup_all_guard_firewall_rules, close_mihomo_connection, get_live_claude_connections,
    get_live_claude_connections_on, has_active_guard_firewall_rules, release_killswitch,
    set_wake_preblock_rule, trigger_four_layer_killswitch, ClaudeConn, KillSwitchState,
};
use crate::maintenance::{
    backup_and_clean_claude_dirs_selected, backups_dir, clear_all_backups_in,
    create_manual_backup_snapshot, delete_backup_file_in, export_ai_diagnostic_bundle,
    list_backups_in, open_folder_and_select, preview_claude_cleanup_plan, restore_backup_file,
    BackupInfo, CleanupPlanPreview, DiagnosticBundleResult,
};
use crate::mihomo::{
    build_node_report, build_node_report_with_options, discover_endpoint, extract_proxy_group,
    fetch_configs, fetch_proxies_raw, fetch_proxy_group_now, get_deep_audit_progress,
    get_fresh_verified_record, invalidate_verified_node_record, is_blocked_node_name,
    is_deep_audit_cancelled, is_deep_audit_running, probe_single_node_deep_via_proxy,
    request_cancel_deep_audit, reset_deep_audit_cancel, select_proxy_in_group,
    set_deep_audit_progress, DeepAuditProgress, NodeReport,
};
use crate::preflight::{
    execute_fix_item, execute_one_click_fix_all, run_all_preflight_checks, BatchFixResult,
    FixResult,
};
use crate::process::{
    kill_claude_process_tree, list_claude_processes, KillHoldSnapshot, KillReport,
    KILL_HOLD_POLL_INTERVAL_MS,
};
use crate::protocol::{
    EVENT_DEDUP_WINDOW_MS, FD_ERR_KILL_SWITCH, FULL_AUDIT_INTERVAL_MS,
};
use crate::rollback::{
    inspect_rollback_status, rollback_all_changes, rollback_single_item,
    run_network_emergency_rescue, NetworkRescueReport, RollbackActionReport, RollbackBatchReport,
    RollbackOverview,
};
use crate::startup_audit::audit_windows_startup_items;
use crate::state::{
    AppState, CheckPart, CheckStatus, GuardSnapshot, HudEventLine, NavigatePayload,
    PreflightReport, StartupAuditReport,
};
use crate::watchdog::{
    claude_logs_fingerprint, collect_log_analysis, collect_log_analysis_with_acked,
    inspect_local_telemetry, LogEvent, LogStats, TelemetryInspection,
};
use crate::telemetry::{
    anonymous_install_short_id, build_anonymized_feedback_payload,
    flush_telemetry_events_if_enabled, submit_anonymous_feedback_report, telemetry_api_endpoint,
    FeedbackReportResult,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, Emitter, Manager, PhysicalPosition, PhysicalSize, Size, State, WebviewUrl,
    WebviewWindowBuilder, WindowEvent,
};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_notification::NotificationExt;

const HUD_WIDTH: f64 = 360.0; // 348px 卡片 + 两侧 6px 阴影留边
const HUD_EXPANDED_HEIGHT: f64 = 306.0;
const HUD_FOLDED_HEIGHT: f64 = 166.0;
const EDGE_TAB_WIDTH: f64 = 20.0;
const EDGE_TAB_HEIGHT: f64 = 84.0;
const HUD_RIGHT_MARGIN: f64 = 16.0;
const PREFLIGHT_CACHE_TTL_SECS: u64 = 6;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchNodeResult {
    pub switched: bool,
    pub node_name: String,
    pub message: String,
    pub report: PreflightReport,
    pub snapshot: GuardSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogAnalysisReport {
    pub events: Vec<LogEvent>,
    pub stats: LogStats,
}

/// 计算主控制台窗口默认展开尺寸（理想 1380x860，异常小屏或高缩放下自动夹紧到显示器 90% 宽 x 88% 高防超界）
fn compute_main_window_default_size(
    monitor_logical_w: Option<f64>,
    monitor_logical_h: Option<f64>,
) -> (f64, f64) {
    let target_w = 1380.0_f64;
    let target_h = 860.0_f64;
    let w = match monitor_logical_w {
        Some(mw) if mw > 0.0 => target_w.min((mw * 0.90).floor()).max(960.0),
        _ => target_w,
    };
    let h = match monitor_logical_h {
        Some(mh) if mh > 0.0 => target_h.min((mh * 0.88).floor()).max(640.0),
        _ => target_h,
    };
    (w, h)
}

/// 纯函数：判定 Claude 运行中（bg_claude_procs > 0）代理突然失守是否必须触发自动 4 层热熔断
/// 签名元组：(clash_online, tun_enable, clash_mode, global_now, claude_fixed_now)
fn evaluate_runtime_killswitch_trigger(
    prev: &(bool, bool, String, String, String),
    cur: &(bool, bool, String, String, String),
    bg_claude_procs: u32,
    auto_kill_switch: bool,
    deep_audit_running: bool,
    already_in_killswitch: bool,
) -> Option<&'static str> {
    // 严格防误杀红线：Claude 未运行、关闭自动熔断、后台深度核验期间、或已处于熔断态绝不触发
    if bg_claude_procs == 0 || !auto_kill_switch || deep_audit_running || already_in_killswitch {
        return None;
    }
    if prev.0 && !cur.0 {
        return Some("Claude 运行中检测到 Clash Verge 离线 / 命名管道断开，已自动 4 层热熔断防退出回传 403");
    }
    if prev.1 && !cur.1 {
        return Some("Claude 运行中检测到 Clash TUN 虚拟网卡被关闭，已自动 4 层热熔断防裸连泄露");
    }
    if cur.0 && cur.2.eq_ignore_ascii_case("direct") {
        return Some("Claude 运行中检测到 Clash 切换为全局直连（DIRECT）模式，已自动 4 层热熔断");
    }
    if cur.0
        && cur.2.eq_ignore_ascii_case("global")
        && !cur.3.is_empty()
        && !cur.3.eq_ignore_ascii_case("Claude-Fixed")
    {
        return Some("Claude 运行中检测到 Clash GLOBAL 模式脱离 Claude-Fixed 策略组，已自动 4 层热熔断");
    }
    if cur.0 && !cur.4.is_empty() && is_blocked_node_name(&cur.4) {
        return Some("Claude 运行中检测到 Claude-Fixed 切入禁区节点，已自动 4 层热熔断");
    }
    None
}

fn ensure_main_window(app: &AppHandle) -> Result<tauri::WebviewWindow, String> {
    if let Some(existing) = app.get_webview_window("main") {
        return Ok(existing);
    }

    let (mon_w, mon_h) = app
        .primary_monitor()
        .ok()
        .flatten()
        .map(|m| {
            let scale = m.scale_factor().max(1.0);
            let sz = m.size();
            (Some(sz.width as f64 / scale), Some(sz.height as f64 / scale))
        })
        .unwrap_or((None, None));
    let (init_w, init_h) = compute_main_window_default_size(mon_w, mon_h);

    logger::log_info(
        "window",
        format!("按需懒创建主控制台窗口 (main, {init_w:.0}x{init_h:.0})"),
    );
    let win = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("FD Claude 安全启动器 (FD Claude Guard)")
        .inner_size(init_w, init_h)
        .min_inner_size(900.0, 600.0)
        .resizable(true)
        .decorations(false)
        .center()
        .visible(false)
        .build()
        .map_err(|e| format!("创建主控制台窗口失败: {e}"))?;

    // 显式写入窗口图标（触发 Win32 WM_SETICON），确保动态创建的主窗口在任务栏与 Alt+Tab 立即显示最新图标
    if let Some(icon) = app.default_window_icon() {
        let _ = win.set_icon(icon.clone());
    }

    let w = win.clone();
    win.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            api.prevent_close();
            logger::log_info("window", "主控制台关闭请求已拦截，隐藏至系统托盘");
            let _ = w.hide();
        }
    });

    Ok(win)
}

/// 带 EVENT_DEDUP_WINDOW_MS (60489ms) 去重的系统原生高优/预警通知分发器
/// critical 级不可静音，即使悬浮窗隐藏也强制触发 Windows 原生通知
fn dispatch_native_alert(
    app: &AppHandle,
    state: &AppState,
    dedup_key: &str,
    critical: bool,
    title: &str,
    body: &str,
) {
    let notify_enabled = state
        .config
        .read()
        .map(|c| c.notify_enabled)
        .unwrap_or(true);

    if !critical && !notify_enabled {
        return;
    }

    let now = Instant::now();
    if let Ok(mut map) = state.alert_dedup.write() {
        if let Some(prev) = map.get(dedup_key) {
            if prev.elapsed().as_millis() < EVENT_DEDUP_WINDOW_MS as u128 {
                return;
            }
        }
        map.insert(dedup_key.to_string(), now);
    }

    logger::log_warn(
        "alert",
        format!("推送原生通知 critical={critical} key={dedup_key} title={title}"),
    );
    let _ = app
        .notification()
        .builder()
        .title(title)
        .body(body)
        .show();
}

#[tauri::command]
fn get_config(state: State<'_, AppState>) -> Result<AppConfig, String> {
    let guard = state
        .config
        .read()
        .map_err(|_| "读取配置锁失败".to_string())?;
    Ok(guard.clone())
}

#[tauri::command]
fn update_config(
    app: AppHandle,
    state: State<'_, AppState>,
    patch: AppConfigPatch,
) -> Result<AppConfig, String> {
    let boot_changed = patch.boot_start;
    let show_hud_changed = patch.show_hud;
    let hud_pinned_changed = patch.hud_pinned;
    let hud_folded_changed = patch.hud_folded;
    let hud_docked_changed = patch.hud_edge_docked;
    let patch_summary = format!("{patch:?}");

    let updated = {
        let mut guard = state
            .config
            .write()
            .map_err(|_| "写入配置锁失败".to_string())?;
        guard.apply_patch(patch);
        save_config(&state.config_path, &guard)?;
        guard.clone()
    };

    logger::log_info("config", format!("配置已更新并持久化: {patch_summary}"));

    if let Some(enable) = boot_changed {
        let autostart = app.autolaunch();
        let res = if enable {
            autostart.enable()
        } else {
            autostart.disable()
        };
        if let Err(err) = res {
            logger::log_warn("autostart", format!("同步 Windows 开机自启状态失败: {err}"));
        }
    }

    if let Some(show) = show_hud_changed {
        if let Some(hud) = app.get_webview_window("hud") {
            if show {
                if updated.hud_edge_docked {
                    apply_hud_edge_dock(&app, &updated, true, false);
                } else {
                    apply_hud_fold_size(&app, updated.hud_folded);
                }
                let _ = hud.show();
            } else {
                let _ = hud.hide();
            }
        }
    }

    if let Some(pinned) = hud_pinned_changed {
        if let Some(hud) = app.get_webview_window("hud") {
            let _ = hud.set_always_on_top(pinned);
        }
    }
    if let Some(folded) = hud_folded_changed {
        if !updated.hud_edge_docked {
            apply_hud_fold_size(&app, folded);
        }
    }
    if let Some(docked) = hud_docked_changed {
        apply_hud_edge_dock(&app, &updated, docked, false);
    }

    if let Ok(mut snap) = state.snapshot.write() {
        let has_24h = snap.triggered_playbook_ids.iter().any(|id| id == "pb_24h");
        if updated.calm_24h && !has_24h {
            snap.triggered_playbook_ids.push("pb_24h".to_string());
        } else if !updated.calm_24h && has_24h {
            snap.triggered_playbook_ids.retain(|id| id != "pb_24h");
        }
        let _ = app.emit("guard://snapshot", snap.clone());
    }

    let _ = app.emit("guard://config-changed", updated.clone());
    Ok(updated)
}

#[tauri::command]
fn save_hud_position(state: State<'_, AppState>, x: i32, y: i32) -> Result<(), String> {
    let mut guard = state
        .config
        .write()
        .map_err(|_| "写入配置锁失败".to_string())?;
    guard.hud_position = Some(WindowPos { x, y });
    save_config(&state.config_path, &guard)?;
    logger::log_info("hud", format!("悬浮窗坐标已保存: ({x}, {y})"));
    Ok(())
}

/// 读取 Windows「辅助功能 → 文本大小」缩放倍率（HKCU\Software\Microsoft\Accessibility\TextScaleFactor）
/// WebView2 会将该倍率叠加到页面整体缩放上，而 Win32/Tauri 的 scale_factor() 仅返回显示器 DPI 倍率，
/// 若不叠乘，100% DPI + 130% 文本大小时悬浮窗会被裁切约 25% 宽度与高度。
#[cfg(windows)]
fn read_windows_text_scale_factor() -> f64 {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey("Software\\Microsoft\\Accessibility")
        .ok()
        .and_then(|k| k.get_value::<u32, _>("TextScaleFactor").ok())
        .map(|pct| (pct as f64) / 100.0)
        .filter(|s| *s >= 1.0 && *s <= 2.5)
        .unwrap_or(1.0)
}

#[cfg(not(windows))]
fn read_windows_text_scale_factor() -> f64 {
    1.0
}

/// 计算悬浮窗真实有效缩放倍率：综合显示器 DPI、Windows 文本大小倍率与前端 devicePixelRatio
fn effective_hud_scale(hud: &tauri::WebviewWindow, reported_dpr: Option<f64>) -> f64 {
    let display_scale = hud
        .scale_factor()
        .ok()
        .filter(|s| *s > 0.5 && *s <= 4.0)
        .unwrap_or(1.0);
    let os_combined = display_scale * read_windows_text_scale_factor();
    let dpr = reported_dpr
        .filter(|d| d.is_finite() && *d > 0.5 && *d <= 4.0)
        .unwrap_or(1.0);
    os_combined.max(dpr)
}

/// 高 DPI + Windows 文本缩放安全窗口尺寸设置：杜绝 125%/150%/200% DPI 及文本大小缩放裁切
fn set_hud_physical_size(
    hud: &tauri::WebviewWindow,
    logical_w: f64,
    logical_h: f64,
    reported_dpr: Option<f64>,
) -> Result<(), String> {
    let scale = effective_hud_scale(hud, reported_dpr);
    let phys_w = (logical_w * scale).ceil().max(20.0) as u32;
    let phys_h = (logical_h * scale).ceil().max(64.0) as u32;
    hud.set_size(Size::Physical(PhysicalSize::new(phys_w, phys_h)))
        .map_err(|e| format!("调整悬浮窗物理尺寸失败: {e}"))
}

#[tauri::command]
fn resize_hud_height(
    app: AppHandle,
    state: State<'_, AppState>,
    height: f64,
    width: Option<f64>,
    dpr: Option<f64>,
) -> Result<(), String> {
    // 贴边收起耳标态不覆盖耳标高度
    let docked = state
        .config
        .read()
        .map(|c| c.hud_edge_docked)
        .unwrap_or(false);
    if docked {
        return Ok(());
    }
    let clamped_w = width.unwrap_or(HUD_WIDTH).clamp(HUD_WIDTH, 460.0);
    let clamped_h = height.clamp(96.0, 520.0);
    if let Some(hud) = app.get_webview_window("hud") {
        set_hud_physical_size(&hud, clamped_w, clamped_h, dpr)?;
    }
    Ok(())
}

#[tauri::command]
fn set_hud_edge_docked(
    app: AppHandle,
    state: State<'_, AppState>,
    docked: bool,
    expanded: Option<bool>,
) -> Result<AppConfig, String> {
    let cfg = {
        let mut guard = state
            .config
            .write()
            .map_err(|_| "写入配置锁失败".to_string())?;
        guard.hud_edge_docked = docked;
        save_config(&state.config_path, &guard)?;
        guard.clone()
    };
    apply_hud_edge_dock(&app, &cfg, docked, expanded.unwrap_or(false));
    let _ = app.emit("guard://config-changed", cfg.clone());
    Ok(cfg)
}

/// 单坐标零偏移贴边切换（固定态 ↔ 贴边滑出态共享同一纵坐标与右距，Δx = 0, Δy = 0）
fn apply_hud_edge_dock(app: &AppHandle, cfg: &AppConfig, docked: bool, expanded: bool) {
    let Some(hud) = app.get_webview_window("hud") else {
        return;
    };
    let Ok(Some(monitor)) = hud.primary_monitor() else {
        return;
    };
    let scale = effective_hud_scale(&hud, None);
    let mon_w = monitor.size().width as i32;
    let current_y = hud
        .outer_position()
        .map(|p| p.y)
        .or_else(|_| Ok::<i32, ()>(cfg.hud_position.map(|p| p.y).unwrap_or((64.0 * scale) as i32)))
        .unwrap_or((64.0 * scale) as i32)
        .max(0);

    let full_h = if cfg.hud_folded {
        HUD_FOLDED_HEIGHT
    } else {
        HUD_EXPANDED_HEIGHT
    };

    if docked && !expanded {
        let w_phys = (EDGE_TAB_WIDTH * scale).ceil() as i32;
        let _ = set_hud_physical_size(&hud, EDGE_TAB_WIDTH, EDGE_TAB_HEIGHT, None);
        let _ = hud.set_position(PhysicalPosition::new((mon_w - w_phys).max(0), current_y));
    } else {
        let w_phys = (HUD_WIDTH * scale).ceil() as i32;
        let right_margin = (HUD_RIGHT_MARGIN * scale).ceil() as i32;
        let _ = set_hud_physical_size(&hud, HUD_WIDTH, full_h, None);
        let _ = hud.set_position(PhysicalPosition::new(
            (mon_w - w_phys - right_margin).max(0),
            current_y,
        ));
    }
}

#[tauri::command]
fn set_hud_pinned(
    app: AppHandle,
    state: State<'_, AppState>,
    pinned: bool,
) -> Result<AppConfig, String> {
    update_config(
        app,
        state,
        AppConfigPatch {
            hud_pinned: Some(pinned),
            ..Default::default()
        },
    )
}

#[tauri::command]
fn set_hud_folded(
    app: AppHandle,
    state: State<'_, AppState>,
    folded: bool,
) -> Result<AppConfig, String> {
    update_config(
        app,
        state,
        AppConfigPatch {
            hud_folded: Some(folded),
            ..Default::default()
        },
    )
}

#[tauri::command]
fn show_main_window(
    app: AppHandle,
    tab: Option<String>,
    sub_tab: Option<String>,
    focus_item_id: Option<String>,
    open_playbook: Option<bool>,
) -> Result<(), String> {
    let win = ensure_main_window(&app)?;
    let _ = win.unminimize();
    win.show().map_err(|e| format!("显示主窗口失败: {e}"))?;
    let _ = win.set_focus();
    let payload = NavigatePayload {
        tab: tab.unwrap_or_else(|| "console".to_string()),
        sub_tab,
        focus_item_id,
        open_playbook,
    };
    logger::log_info("window", format!("唤起主控制台: tab={}", payload.tab));
    let _ = app.emit("guard://navigate", payload);
    Ok(())
}

#[tauri::command]
fn hide_main_window(app: AppHandle) -> Result<(), String> {
    if let Some(win) = app.get_webview_window("main") {
        win.hide().map_err(|e| format!("隐藏主窗口失败: {e}"))?;
        logger::log_info("window", "主控制台已隐藏至系统托盘");
    }
    Ok(())
}

#[tauri::command]
fn toggle_hud_window(
    app: AppHandle,
    state: State<'_, AppState>,
    visible: Option<bool>,
) -> Result<bool, String> {
    let target = match visible {
        Some(v) => v,
        None => !state.config.read().map(|c| c.show_hud).unwrap_or(true),
    };
    let _ = update_config(
        app,
        state,
        AppConfigPatch {
            show_hud: Some(target),
            ..Default::default()
        },
    )?;
    Ok(target)
}

/// 立即隐藏所有窗口与托盘图标并干净退出进程（避免 WebView2 / 防火墙同步清理造成 5~10 秒假死拖尾）
fn fast_hide_and_exit(app: &AppHandle, should_cleanup_fw: bool, log_msg: &str) {
    for label in ["main", "hud"] {
        if let Some(win) = app.get_webview_window(label) {
            let _ = win.hide();
        }
    }
    let _ = app.remove_tray_by_id("fd-claude-guard-tray");
    if should_cleanup_fw {
        let _ = cleanup_all_guard_firewall_rules();
    }
    logger::log_info("lifecycle", log_msg);
    app.exit(0);
    // 兜底硬退出：确保后台 tokio 协程与 WebView2 句柄不拖尾残留进程
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(250));
        std::process::exit(0);
    });
}

#[tauri::command]
fn quit_app(app: AppHandle, state: State<'_, AppState>, kill_claude_first: Option<bool>) {
    let ks_active = state
        .killswitch
        .read()
        .map(|k| k.active)
        .unwrap_or(false);
    // 先立即隐藏窗口与托盘，视觉 0ms 响应
    for label in ["main", "hud"] {
        if let Some(win) = app.get_webview_window(label) {
            let _ = win.hide();
        }
    }
    let _ = app.remove_tray_by_id("fd-claude-guard-tray");

    let app_clone = app.clone();
    std::thread::spawn(move || {
        if kill_claude_first == Some(true) {
            let _ = kill_claude_process_tree(true);
        }
        let need_fw_clean = ks_active || has_active_guard_firewall_rules();
        if need_fw_clean {
            let _ = cleanup_all_guard_firewall_rules();
        }
        logger::log_info(
            "lifecycle",
            format!(
                "应用即将安全退出 (kill_claude_first={:?}, fw_cleaned={need_fw_clean})",
                kill_claude_first
            ),
        );
        app_clone.exit(0);
        std::thread::sleep(Duration::from_millis(250));
        std::process::exit(0);
    });
}

#[tauri::command]
fn get_snapshot(state: State<'_, AppState>) -> Result<GuardSnapshot, String> {
    let snap = state
        .snapshot
        .read()
        .map_err(|_| "读取快照锁失败".to_string())?
        .clone();
    Ok(snap)
}

#[tauri::command]
async fn run_preflight_checks(
    app: AppHandle,
    state: State<'_, AppState>,
    force: Option<bool>,
) -> Result<PreflightReport, String> {
    let force_run = force.unwrap_or(true);
    // 单飞互斥锁：彻底消除冷启动时 setup 与 bootstrap 180ms 并发双跑
    let _gate = state.preflight_gate.lock().await;

    if !force_run {
        if let Ok(ts_guard) = state.last_preflight_at.read() {
            if let Some(last_at) = *ts_guard {
                if last_at.elapsed().as_secs() < PREFLIGHT_CACHE_TTL_SECS {
                    if let Ok(rep) = state.last_report.read() {
                        if rep.stage != "INIT" {
                            logger::log_info(
                                "preflight",
                                format!(
                                    "命中单飞缓存 ({}ms)，跳过启动重复双跑",
                                    last_at.elapsed().as_millis()
                                ),
                            );
                            return Ok(rep.clone());
                        }
                    }
                }
            }
        }
    }

    let cfg = state
        .config
        .read()
        .map_err(|_| "读取配置锁失败".to_string())?
        .clone();
    let bg_procs = list_claude_processes().len() as u32;

    let mut bundle = run_all_preflight_checks(&cfg, bg_procs).await;
    persist_baseline_if_needed(
        &state,
        &bundle.snapshot.current_node,
        bundle.detected_landing_sig.as_deref(),
        bundle.detected_org_id.as_deref(),
    );
    merge_killswitch_and_log_triggers(&state, &mut bundle.snapshot);

    if let Ok(mut rep) = state.last_report.write() {
        *rep = bundle.report.clone();
    }
    if let Ok(mut ts) = state.last_preflight_at.write() {
        *ts = Some(Instant::now());
    }
    if let Ok(mut snap) = state.snapshot.write() {
        *snap = bundle.snapshot.clone();
    }
    let _ = app.emit("guard://snapshot", bundle.snapshot);
    Ok(bundle.report)
}

#[tauri::command]
async fn fix_preflight_item(
    app: AppHandle,
    state: State<'_, AppState>,
    item_id: String,
) -> Result<FixResult, String> {
    let _gate = state.preflight_gate.lock().await;
    logger::log_info("fix", format!("开始执行单项修复: item_id={item_id}"));
    let cfg = state
        .config
        .read()
        .map_err(|_| "读取配置锁失败".to_string())?
        .clone();
    let bg_procs = list_claude_processes().len() as u32;

    let mut result = execute_fix_item(&item_id, &cfg, bg_procs).await?;
    merge_killswitch_and_log_triggers(&state, &mut result.snapshot);

    if let Ok(mut rep) = state.last_report.write() {
        *rep = result.report.clone();
    }
    if let Ok(mut ts) = state.last_preflight_at.write() {
        *ts = Some(Instant::now());
    }
    if let Ok(mut snap) = state.snapshot.write() {
        *snap = result.snapshot.clone();
    }
    let _ = app.emit("guard://snapshot", result.snapshot.clone());
    // L2 低频高价值遥测：仅在自动修复真实失败（!success）且非普通手动步骤引导时才上报故障卡点
    if !result.success && !result.requires_manual_step {
        let api_ep = telemetry_api_endpoint();
        let inst = anonymous_install_short_id();
        let snap_tel = result.snapshot.clone();
        let cfg_tel = cfg.clone();
        let tev = serde_json::json!({
            "category": "tool_diag",
            "event_type": "fix_item_failed",
            "level": "error",
            "tag": item_id,
            "signature": crate::maintenance::sanitize_for_telemetry(&result.message).chars().take(180).collect::<String>(),
            "repeat_count": 1,
            "pre_ban_factors": [],
            "env": {
                "clashPort": snap_tel.clash_port,
                "clashVersion": snap_tel.clash_version,
                "region": snap_tel.region_code,
            },
            "client_event_id": format!("fix:{}:{}", item_id, chrono::Local::now().format("%Y%m%d")),
        });
        tauri::async_runtime::spawn(async move {
            flush_telemetry_events_if_enabled(&cfg_tel, api_ep.as_deref(), &inst, &snap_tel, &[], vec![tev]).await;
        });
    }
    Ok(result)
}

#[tauri::command]
async fn one_click_fix_all(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BatchFixResult, String> {
    let _gate = state.preflight_gate.lock().await;
    logger::log_info("fix", "开始执行一键处理全部问题");
    let cfg = state
        .config
        .read()
        .map_err(|_| "读取配置锁失败".to_string())?
        .clone();
    let bg_procs = list_claude_processes().len() as u32;

    let mut result = execute_one_click_fix_all(&cfg, bg_procs).await?;
    merge_killswitch_and_log_triggers(&state, &mut result.snapshot);

    if let Ok(mut rep) = state.last_report.write() {
        *rep = result.report.clone();
    }
    if let Ok(mut ts) = state.last_preflight_at.write() {
        *ts = Some(Instant::now());
    }
    if let Ok(mut snap) = state.snapshot.write() {
        *snap = result.snapshot.clone();
    }
    let _ = app.emit("guard://snapshot", result.snapshot.clone());
    // L2 低频高价值遥测：仅在一键修复后仍有可自动修复项失败（非纯人工操作项）时上报
    let auto_failed_id = result
        .report
        .items
        .iter()
        .find(|i| {
            i.part == CheckPart::Must
                && i.status != CheckStatus::Ok
                && i.mode == "auto"
        })
        .map(|i| i.id.clone());
    if let Some(rem_id) = auto_failed_id {
        let api_ep = telemetry_api_endpoint();
        let inst = anonymous_install_short_id();
        let snap_tel = result.snapshot.clone();
        let cfg_tel = cfg.clone();
        let tev = serde_json::json!({
            "category": "tool_diag",
            "event_type": "one_click_fix_auto_failed",
            "level": "error",
            "tag": rem_id,
            "signature": crate::maintenance::sanitize_for_telemetry(&result.summary).chars().take(180).collect::<String>(),
            "repeat_count": 1,
            "pre_ban_factors": [],
            "env": {
                "clashPort": snap_tel.clash_port,
                "clashVersion": snap_tel.clash_version,
                "region": snap_tel.region_code,
            },
            "client_event_id": format!("oneclick:{}:{}", rem_id, chrono::Local::now().format("%Y%m%d")),
        });
        tauri::async_runtime::spawn(async move {
            flush_telemetry_events_if_enabled(&cfg_tel, api_ep.as_deref(), &inst, &snap_tel, &[], vec![tev]).await;
        });
    }
    Ok(result)
}

#[tauri::command]
async fn safe_launch_claude(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let audit_prog = get_deep_audit_progress();
    if audit_prog.running {
        let msg = format!(
            "当前正在深度核验节点（{}/{}：{}），为避免测速切换代理时串 IP，请等待核验结束自动恢复锁定节点后再启动 Claude，或点击停止核验。",
            audit_prog.current_index, audit_prog.total, audit_prog.current_node
        );
        logger::log_warn("launch", &msg);
        return Err(msg);
    }
    let _gate = state.preflight_gate.lock().await;
    logger::log_info("launch", "收到安全启动 Claude 请求，先解除盯防锁并执行启动前二次复核");
    // T-031：点击「安全启动 Claude」时第一时间取消 Kill-Hold 防复活盯防锁（非熔断态下绝不拦用户健康启动）
    let ks_active_now = state
        .killswitch
        .read()
        .map(|k| k.active)
        .unwrap_or(false);
    if !ks_active_now {
        release_kill_hold_internal(&app, &state, "用户点击安全启动 Claude，立即解除防复活盯防锁");
    }
    let cfg = state
        .config
        .read()
        .map_err(|_| "读取配置锁失败".to_string())?
        .clone();
    let bg_procs = list_claude_processes().len() as u32;

    let mut bundle = run_all_preflight_checks(&cfg, bg_procs).await;
    persist_baseline_if_needed(
        &state,
        &bundle.snapshot.current_node,
        bundle.detected_landing_sig.as_deref(),
        bundle.detected_org_id.as_deref(),
    );
    merge_killswitch_and_log_triggers(&state, &mut bundle.snapshot);

    if let Ok(mut rep) = state.last_report.write() {
        *rep = bundle.report.clone();
    }
    if let Ok(mut ts) = state.last_preflight_at.write() {
        *ts = Some(Instant::now());
    }
    if let Ok(mut snap) = state.snapshot.write() {
        *snap = bundle.snapshot.clone();
    }
    let _ = app.emit("guard://snapshot", bundle.snapshot.clone());

    let failed: Vec<String> = bundle
        .report
        .items
        .iter()
        .filter(|i| i.part == CheckPart::Must && i.status != CheckStatus::Ok)
        .map(|i| i.title.clone())
        .collect();
    if !failed.is_empty() {
        let msg = format!(
            "启动门禁拦截：仍有 {} 项必须项未通过（{}）",
            failed.len(),
            failed.join("、")
        );
        logger::log_warn("launch", &msg);
        return Err(msg);
    }

    #[cfg(windows)]
    {
        if let Some(exe) = crate::process::resolve_claude_exe_path() {
            // 增量 17：点击「安全启动 Claude」时在拉起前自动优雅释放 Kill-Hold 防复活锁
            release_kill_hold_internal(&app, &state, "安全启动 Claude 前自动优雅释放防复活盯防锁");
            std::process::Command::new(&exe)
                .spawn()
                .map_err(|e| format!("拉起 Claude Desktop 失败: {e}"))?;
            logger::log_info("launch", format!("安全拉起 Claude Desktop 成功: {}", exe.display()));
            return Ok("全部必须项复核通过，已优雅释放防复活盯防锁并安全拉起 Claude Desktop。".into());
        }
        return Err("全部必须项已通过，但本机未找到已安装的 Claude Desktop 可执行程序（可安全运行 Claude Code CLI）。".into());
    }

    #[cfg(not(windows))]
    {
        release_kill_hold_internal(&app, &state, "安全启动 Claude 前自动优雅释放防复活盯防锁");
        Ok("全部必须项复核通过。".into())
    }
}

#[tauri::command]
async fn get_nodes_and_quality(force: Option<bool>) -> NodeReport {
    build_node_report_with_options(force.unwrap_or(false)).await
}

static MANUAL_NODE_SWITCH_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[tauri::command]
async fn switch_locked_node(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    force_ignore_risk: bool,
) -> Result<SwitchNodeResult, String> {
    let _gate = state.preflight_gate.lock().await;
    logger::log_info(
        "nodes",
        format!("请求切换节点: target={name} force_ignore_risk={force_ignore_risk}"),
    );
    if is_blocked_node_name(&name) && !force_ignore_risk {
        return Err(format!("拒绝切换至禁区节点：{name}"));
    }

    let cfg = state
        .config
        .read()
        .map_err(|_| "读取配置锁失败".to_string())?
        .clone();
    let bg_procs = list_claude_processes().len() as u32;
    let node_down_now = state
        .snapshot
        .read()
        .map(|s| s.node_down)
        .unwrap_or(false);

    // T-035：开启 24h 冷静保护模式时，当前节点健康期间严禁主动切换节点（仅节点不可用或强制忽略风险时放行）
    if cfg.calm_24h && !node_down_now && !force_ignore_risk {
        return Err(
            "已开启「24h 冷静保护模式」，当前节点健康期间严禁切换节点（仅节点不可用时允许容灾切换）。"
                .into(),
        );
    }

    if bg_procs > 0 && !force_ignore_risk {
        return Err(format!(
            "检测到 {bg_procs} 个 Claude 后台进程运行中，请先清空进程或确认忽略风险。"
        ));
    }

    let ep = discover_endpoint()
        .await
        .ok_or_else(|| "未检测到在线的 Clash Verge Mihomo 实例".to_string())?;
    let report_before = build_node_report().await;
    let target_group = if report_before.group_name.is_empty() {
        "Claude-Fixed".to_string()
    } else {
        report_before.group_name
    };

    // P0-5：递增手动切节点代际号，确保后台旧深度核验即便晚于超时才退出，也绝不会把节点回切覆盖用户的最新选择
    MANUAL_NODE_SWITCH_GEN.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    // 若后台正在深度核验备选节点，先通知其停止并稍候归位，避免并发切换 Claude-Fixed
    if is_deep_audit_running() {
        request_cancel_deep_audit();
        for _ in 0..20 {
            if !is_deep_audit_running() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }

    // 增量 17：切节点期间启用事务级防复活锁定，切换完成后无缝衔接短时防复活盯防
    acquire_kill_hold_tx(&app, &state, &format!("正在切换锁定节点至 {name}"));
    let select_res = select_proxy_in_group(&ep, &target_group, &name).await;
    if let Err(err) = select_res {
        release_kill_hold_tx(&app, &state, Some(cfg.kill_hold_seconds));
        return Err(err);
    }
    // T-102：用户在软件内手动切换节点时，同步更新 Clash 顶层主策略组与 profiles.yaml selected[0]=Claude-Fixed，确保两端 100% 一致
    let _ = crate::preflight::sync_clash_selection_everywhere(&ep, &name).await;
    // 用户在软件内主动点击「切换锁定」时，同步更新主力节点基线、清空旧 IP 基线并校准新节点漂移历史（绝不把切节点算成漂移）
    crate::mihomo::reset_node_drift_history(&name);
    tokio::time::sleep(Duration::from_millis(350)).await;
    let mut cfg_updated = cfg.clone();
    cfg_updated.locked_node_for_ip = Some(name.clone());
    cfg_updated.locked_landing_ip = None;
    if let Ok(mut guard) = state.config.write() {
        guard.locked_node_for_ip = Some(name.clone());
        guard.locked_landing_ip = None;
        let _ = save_config(&state.config_path, &guard);
    }
    // 切换后立即对新锁定节点发起 100% 真实深度核验并落盘（让节点表与控制台数据同源）
    let mixed_port = fetch_configs(&ep).await.map(|c| c.mixed_port).unwrap_or(7890);
    tokio::time::sleep(Duration::from_millis(220)).await;
    let _ = probe_single_node_deep_via_proxy(&name, mixed_port).await;
    let mut bundle = run_all_preflight_checks(&cfg_updated, list_claude_processes().len() as u32).await;
    release_kill_hold_tx(&app, &state, Some(cfg.kill_hold_seconds));
    persist_baseline_if_needed(
        &state,
        &bundle.snapshot.current_node,
        bundle.detected_landing_sig.as_deref(),
        bundle.detected_org_id.as_deref(),
    );
    merge_killswitch_and_log_triggers(&state, &mut bundle.snapshot);

    if let Ok(mut rep) = state.last_report.write() {
        *rep = bundle.report.clone();
    }
    if let Ok(mut ts) = state.last_preflight_at.write() {
        *ts = Some(Instant::now());
    }
    if let Ok(mut snap) = state.snapshot.write() {
        *snap = bundle.snapshot.clone();
    }
    let _ = app.emit("guard://snapshot", bundle.snapshot.clone());

    Ok(SwitchNodeResult {
        switched: true,
        node_name: name.clone(),
        message: format!("已将 {target_group} 切换至 {name} 并完成真实出口与风控核验。"),
        report: bundle.report,
        snapshot: bundle.snapshot,
    })
}

/// 统一后台深度核验调度器：
/// - 仅在 Claude 进程 == 0 且存在 Claude-Fixed 时执行；
/// - 永远将当前选中节点排第 1 位优先核验，随后按 1.2s 慢速逐个实测其余节点并落盘；
/// - 全程仅临时切换 Claude-Fixed（绝不触碰天悦云等其他策略组），结束/取消/异常 100% 恢复原锁定节点并刷新控制台。
fn spawn_deep_node_audit_task(
    app: AppHandle,
    force_all: bool,
    target_node: Option<String>,
    auto_silent: bool,
) -> Result<DeepAuditProgress, String> {
    if is_deep_audit_running() {
        return Ok(get_deep_audit_progress());
    }
    let bg_procs = list_claude_processes().len() as u32;
    if bg_procs > 0 {
        let msg = format!(
            "检测到 {bg_procs} 个 Claude 进程运行中，为防止串 IP 封号已跳过深度核验；请先退出 Claude 后再核验。"
        );
        if auto_silent {
            logger::log_info("node_audit", &msg);
            return Ok(DeepAuditProgress {
                running: false,
                phase: "blocked".into(),
                message: msg,
                ..Default::default()
            });
        }
        return Err(msg);
    }

    reset_deep_audit_cancel();
    let initial = DeepAuditProgress {
        running: true,
        phase: "running".into(),
        current_index: 0,
        total: 0,
        current_node: String::new(),
        original_node: String::new(),
        current_node_verified: false,
        message: "正在初始化节点深度核验队列...".into(),
    };
    set_deep_audit_progress(initial.clone());
    let _ = app.emit("guard://node-audit-progress", initial.clone());

    let app_bg = app.clone();
    let audit_gen = MANUAL_NODE_SWITCH_GEN.load(std::sync::atomic::Ordering::SeqCst);
    tauri::async_runtime::spawn(async move {
        let Some(ep) = discover_endpoint().await else {
            let done = DeepAuditProgress {
                running: false,
                phase: "idle".into(),
                message: "Clash Verge 未在线，跳过节点核验".into(),
                ..Default::default()
            };
            set_deep_audit_progress(done.clone());
            let _ = app_bg.emit("guard://node-audit-progress", done);
            return;
        };

        let Ok(proxies) = fetch_proxies_raw(&ep).await else {
            let done = DeepAuditProgress {
                running: false,
                phase: "idle".into(),
                message: "读取 Mihomo 策略组失败".into(),
                ..Default::default()
            };
            set_deep_audit_progress(done.clone());
            let _ = app_bg.emit("guard://node-audit-progress", done);
            return;
        };

        // 仅针对本工具生成的 Claude-Fixed 策略组执行逐个核验（首次安装尚未建组时安静跳过）
        let Some(group) = extract_proxy_group(&proxies, "Claude-Fixed") else {
            let done = DeepAuditProgress {
                running: false,
                phase: "idle".into(),
                message: "尚未创建 Claude-Fixed 策略组，完成脚本配置后将自动核验".into(),
                ..Default::default()
            };
            set_deep_audit_progress(done.clone());
            let _ = app_bg.emit("guard://node-audit-progress", done);
            return;
        };

        let original_node = group.now.clone();
        let mixed_port = match fetch_configs(&ep).await {
            Ok(c) => c.mixed_port,
            Err(_) => crate::preflight::resolve_active_mixed_port().await,
        };

        let mut candidates: Vec<String> = group
            .all
            .iter()
            .filter(|n| {
                !n.eq_ignore_ascii_case("DIRECT")
                    && !n.eq_ignore_ascii_case("REJECT")
                    && !n.eq_ignore_ascii_case("COMPATIBLE")
                    && !is_blocked_node_name(n)
            })
            .filter(|n| {
                let t = proxies
                    .get(*n)
                    .and_then(|v| v.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Proxy");
                !matches!(
                    t,
                    "Selector" | "URLTest" | "Fallback" | "LoadBalance" | "Direct" | "Reject"
                )
            })
            .cloned()
            .collect();

        // 永远将当前锁定节点排在第 1 位优先核验
        if let Some(pos) = candidates.iter().position(|n| n == &original_node) {
            let cur = candidates.remove(pos);
            candidates.insert(0, cur);
        }

        let queue: Vec<String> = if let Some(ref single) = target_node {
            invalidate_verified_node_record(single);
            vec![single.clone()]
        } else if force_all {
            for n in &candidates {
                invalidate_verified_node_record(n);
            }
            candidates
        } else {
            // 增量核验：跳过已有 24h 有效缓存的节点；但若当前节点未缓存，一定排第 1 位
            candidates
                .into_iter()
                .filter(|n| get_fresh_verified_record(n).is_none())
                .collect()
        };

        if queue.is_empty() {
            let done = DeepAuditProgress {
                running: false,
                phase: "done".into(),
                current_index: 0,
                total: 0,
                current_node: String::new(),
                original_node: original_node.clone(),
                current_node_verified: get_fresh_verified_record(&original_node).is_some(),
                message: "全部合规节点均在 24h 实测有效期内，无需重复核验".into(),
            };
            set_deep_audit_progress(done.clone());
            let _ = app_bg.emit("guard://node-audit-progress", done);
            return;
        }

        let total = queue.len();
        let mut current_node_verified = get_fresh_verified_record(&original_node).is_some();
        let mut cancelled = false;
        let mut claude_interrupted = false;

        logger::log_info(
            "node_audit",
            format!(
                "开始逐个节点深度实测: total={total} original_node={original_node} force_all={force_all} auto_silent={auto_silent}"
            ),
        );

        for (idx, node_name) in queue.iter().enumerate() {
            if is_deep_audit_cancelled() {
                cancelled = true;
                break;
            }
            if !list_claude_processes().is_empty() {
                claude_interrupted = true;
                break;
            }

            let step_prog = DeepAuditProgress {
                running: true,
                phase: "running".into(),
                current_index: idx + 1,
                total,
                current_node: node_name.clone(),
                original_node: original_node.clone(),
                current_node_verified,
                message: format!("正在核验 {}/{total}：{node_name}（核验期间暂禁启动 Claude）", idx + 1),
            };
            set_deep_audit_progress(step_prog.clone());
            let _ = app_bg.emit("guard://node-audit-progress", step_prog);

            // 仅切换 Claude-Fixed 策略组，绝不触碰天悦云等其他主组
            if select_proxy_in_group(&ep, "Claude-Fixed", node_name).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(240)).await;
                let rec = probe_single_node_deep_via_proxy(node_name, mixed_port).await;
                if node_name == &original_node {
                    current_node_verified = true;
                }
                logger::log_info(
                    "node_audit",
                    format!(
                        "节点实测落盘 ({}/{total}): node={node_name} cc={} ip={} type={} claude={} agy={}",
                        idx + 1,
                        rec.country_code,
                        rec.masked_ip,
                        rec.asn_purity,
                        rec.claude_label,
                        rec.gemini_label
                    ),
                );
                let after_step = DeepAuditProgress {
                    running: true,
                    phase: "running".into(),
                    current_index: idx + 1,
                    total,
                    current_node: node_name.clone(),
                    original_node: original_node.clone(),
                    current_node_verified,
                    message: format!(
                        "已核验 {}/{total}：{node_name} → {} · {} · {}",
                        idx + 1,
                        rec.asn_purity,
                        rec.claude_label,
                        rec.gemini_label
                    ),
                };
                set_deep_audit_progress(after_step.clone());
                let _ = app_bg.emit("guard://node-audit-progress", after_step);
            }

            // 慢速间隔（1.25s），彻底规避 ip-api.com 免费接口 45次/分钟 限频
            if idx + 1 < total {
                for _ in 0..12 {
                    if is_deep_audit_cancelled() || !list_claude_processes().is_empty() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(105)).await;
                }
            }
        }

        // P0-5：仅当期间未发生用户手动切换节点（代际号一致）时才恢复 original_node，严禁覆盖用户新选节点
        let manual_switched =
            MANUAL_NODE_SWITCH_GEN.load(std::sync::atomic::Ordering::SeqCst) != audit_gen;
        if !manual_switched
            && !original_node.is_empty()
            && !original_node.eq_ignore_ascii_case("未创建")
        {
            let _ = select_proxy_in_group(&ep, "Claude-Fixed", &original_node).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let final_prog = DeepAuditProgress {
            running: false,
            phase: if cancelled || claude_interrupted {
                "cancelled".into()
            } else {
                "done".into()
            },
            current_index: total,
            total,
            current_node: String::new(),
            original_node: original_node.clone(),
            current_node_verified: get_fresh_verified_record(&original_node).is_some(),
            message: if claude_interrupted {
                format!("检测到 Claude 进程启动，已中止核验并恢复锁定节点「{original_node}」")
            } else if cancelled {
                format!("已停止核验并恢复锁定节点「{original_node}」")
            } else {
                format!("已完成 {total} 个节点真实深度核验并持久落盘，已恢复锁定节点「{original_node}」")
            },
        };
        set_deep_audit_progress(final_prog.clone());
        let _ = app_bg.emit("guard://node-audit-progress", final_prog);

        // 核验结束后立刻复跑一次控制台体检并推送刷新（解除启动锁定、呈现真实通过/阻断状态）
        if let Some(st) = app_bg.try_state::<AppState>() {
            if let Ok(_gate) = st.preflight_gate.try_lock() {
                let cfg = st.config.read().map(|c| c.clone()).unwrap_or_default();
                let cur_procs = list_claude_processes().len() as u32;
                let mut bundle = run_all_preflight_checks(&cfg, cur_procs).await;
                persist_baseline_if_needed(
                    &st,
                    &bundle.snapshot.current_node,
                    bundle.detected_landing_sig.as_deref(),
                    bundle.detected_org_id.as_deref(),
                );
                merge_killswitch_and_log_triggers(&st, &mut bundle.snapshot);
                if let Ok(mut rep) = st.last_report.write() {
                    *rep = bundle.report.clone();
                }
                if let Ok(mut ts) = st.last_preflight_at.write() {
                    *ts = Some(Instant::now());
                }
                if let Ok(mut snap) = st.snapshot.write() {
                    *snap = bundle.snapshot.clone();
                }
                let _ = app_bg.emit("guard://preflight-updated", bundle.report);
                let _ = app_bg.emit("guard://snapshot", bundle.snapshot);
            }
        }
    });

    Ok(initial)
}

#[tauri::command]
fn get_deep_audit_status() -> DeepAuditProgress {
    get_deep_audit_progress()
}

#[tauri::command]
async fn start_deep_node_audit(
    app: AppHandle,
    force_all: Option<bool>,
    target_node: Option<String>,
) -> Result<DeepAuditProgress, String> {
    spawn_deep_node_audit_task(app, force_all.unwrap_or(false), target_node, false)
}

#[tauri::command]
fn cancel_deep_node_audit(app: AppHandle) -> DeepAuditProgress {
    request_cancel_deep_audit();
    let mut cur = get_deep_audit_progress();
    cur.message = "正在停止核验并恢复原锁定节点...".into();
    let _ = app.emit("guard://node-audit-progress", cur.clone());
    cur
}

/// 重置当前锁定节点的 24h 落地 IP 漂移基准（用户确认漂移后的合规新 IP 已稳定时使用）
#[tauri::command]
async fn reset_node_drift_baseline(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let _gate = state.preflight_gate.lock().await;
    let cur_node = state
        .snapshot
        .read()
        .map(|s| s.current_node.clone())
        .unwrap_or_default();
    if !cur_node.is_empty() {
        crate::mihomo::reset_node_drift_history(&cur_node);
    }
    if let Ok(mut cfg) = state.config.write() {
        cfg.locked_landing_ip = None;
        let _ = save_config(&state.config_path, &cfg);
    }
    let cfg = state.config.read().map(|c| c.clone()).unwrap_or_default();
    let bg_procs = list_claude_processes().len() as u32;
    let mut bundle = run_all_preflight_checks(&cfg, bg_procs).await;
    persist_baseline_if_needed(
        &state,
        &bundle.snapshot.current_node,
        bundle.detected_landing_sig.as_deref(),
        bundle.detected_org_id.as_deref(),
    );
    merge_killswitch_and_log_triggers(&state, &mut bundle.snapshot);
    if let Ok(mut rep) = state.last_report.write() {
        *rep = bundle.report.clone();
    }
    if let Ok(mut ts) = state.last_preflight_at.write() {
        *ts = Some(Instant::now());
    }
    if let Ok(mut snap) = state.snapshot.write() {
        *snap = bundle.snapshot.clone();
    }
    let _ = app.emit("guard://preflight-updated", bundle.report);
    let _ = app.emit("guard://snapshot", bundle.snapshot);
    Ok(format!("已重置节点「{cur_node}」的漂移基准并完成复测验收。"))
}

#[tauri::command]
async fn get_live_connections(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<ClaudeConn>, String> {
    let conns = get_live_claude_connections().await;
    let live_anom = conns.iter().filter(|c| c.anomaly).count();
    if let Ok(mut snap) = state.snapshot.write() {
        let node_issue = usize::from(snap.node_down || snap.node_drift_warn);
        let new_total = live_anom + node_issue;
        if snap.live_flow_anomalies != live_anom || snap.active_flow_anomalies != new_total {
            snap.live_flow_anomalies = live_anom;
            snap.active_flow_anomalies = new_total;
            let _ = app.emit("guard://snapshot", snap.clone());
        }
    }
    Ok(conns)
}

#[tauri::command]
async fn close_connection(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> Result<(), String> {
    logger::log_warn("traffic", format!("手动掐断连接: id={id}"));
    close_mihomo_connection(&id).await?;
    let live_anom = get_live_claude_connections()
        .await
        .into_iter()
        .filter(|c| c.anomaly)
        .count();
    if let Ok(mut snap) = state.snapshot.write() {
        let node_issue = usize::from(snap.node_down || snap.node_drift_warn);
        snap.live_flow_anomalies = live_anom;
        snap.active_flow_anomalies = live_anom + node_issue;
        let _ = app.emit("guard://snapshot", snap.clone());
    }
    Ok(())
}

#[tauri::command]
async fn kill_claude_processes(
    app: AppHandle,
    state: State<'_, AppState>,
    clean_telemetry: bool,
) -> Result<KillReport, String> {
    let mut report = tokio::task::spawn_blocking(move || kill_claude_process_tree(clean_telemetry))
        .await
        .map_err(|e| format!("强杀进程任务调度失败: {e}"))?;
    let hold_secs = state
        .config
        .read()
        .map(|c| c.kill_hold_seconds)
        .unwrap_or(45);
    let hold = start_kill_hold_internal(
        &app,
        &state,
        hold_secs,
        "强杀 Claude 进程后自动启用防复活持续盯防",
    );
    report.kill_hold_active = hold.active;
    report.kill_hold_remaining_secs = hold.remaining_secs;
    if !report.message.contains("防复活盯防") {
        report.message = format!(
            "{} 已启动 {}s 防复活持续盯防锁。",
            report.message, hold.remaining_secs
        );
    }
    if let Ok(mut snap) = state.snapshot.write() {
        snap.bg_claude_procs = report.after_count;
        apply_kill_hold_to_snapshot(&mut snap, &hold);
        let _ = app.emit("guard://snapshot", snap.clone());
    }
    Ok(report)
}

#[tauri::command]
async fn start_kill_hold_cmd(
    app: AppHandle,
    state: State<'_, AppState>,
    duration_secs: Option<u32>,
    reason: Option<String>,
) -> Result<KillHoldSnapshot, String> {
    let _ = tokio::task::spawn_blocking(|| kill_claude_process_tree(false)).await;
    let default_secs = state
        .config
        .read()
        .map(|c| c.kill_hold_seconds)
        .unwrap_or(45);
    let secs = duration_secs.unwrap_or(default_secs).clamp(10, 300);
    Ok(start_kill_hold_internal(
        &app,
        &state,
        secs,
        reason.as_deref().unwrap_or("手动启用强杀防复活持续盯防锁"),
    ))
}

#[tauri::command]
fn release_kill_hold_cmd(app: AppHandle, state: State<'_, AppState>) -> KillHoldSnapshot {
    release_kill_hold_internal(&app, &state, "用户手动解除防复活持续盯防锁")
}

#[tauri::command]
async fn trigger_killswitch(
    app: AppHandle,
    state: State<'_, AppState>,
    reason: Option<String>,
) -> Result<KillSwitchState, String> {
    let anti_flush = state
        .config
        .read()
        .map(|c| c.anti_upload_flush)
        .unwrap_or(true);
    let reason_str = reason.as_deref().unwrap_or("手动触发 4 层紧急防回传与出站阻断");
    logger::log_warn(
        "killswitch",
        format!("[{FD_ERR_KILL_SWITCH}] 触发 4 层紧急熔断: {reason_str}"),
    );

    let ks = trigger_four_layer_killswitch(reason_str, anti_flush).await;
    // 增量 17：熔断激活期间保持事务级防复活锁定，严防 Claude 后台重启偷跑
    acquire_kill_hold_tx(&app, &state, &format!("熔断事务锁定: {reason_str}"));

    if let Ok(mut guard) = state.killswitch.write() {
        *guard = ks.clone();
    }
    if let Ok(mut snap) = state.snapshot.write() {
        snap.kill_switch_active = ks.active;
        snap.health_level = "danger".into();
        snap.status_label = "已自动熔断".into();
        snap.bg_claude_procs = list_claude_processes().len() as u32;
        if let Ok(mut kh) = state.kill_hold.write() {
            let hs = kh.snapshot_and_sweep(Instant::now());
            apply_kill_hold_to_snapshot(&mut snap, &hs);
        }
        snap.hud_events.insert(
            0,
            HudEventLine {
                message: format!(
                    "[{FD_ERR_KILL_SWITCH}] 防火墙已锁死出站（掐断 {} 条连接）",
                    ks.claude_connections_closed
                ),
                time: ks.updated_at.clone(),
                level: "danger".into(),
                target_tab: "console".into(),
            },
        );
        snap.hud_events.truncate(2);
        let _ = app.emit("guard://snapshot", snap.clone());
    }
    dispatch_native_alert(
        &app,
        &state,
        "critical:killswitch",
        true,
        "FD Claude Guard 危急熔断已触发",
        reason_str,
    );
    Ok(ks)
}

#[tauri::command]
async fn force_release_killswitch(
    app: AppHandle,
    state: State<'_, AppState>,
    confirmed: bool,
) -> Result<KillSwitchState, String> {
    let (bg_procs, ks) = tokio::task::spawn_blocking(move || {
        let bg = list_claude_processes().len() as u32;
        release_killswitch(confirmed, bg).map(|k| (bg, k))
    })
    .await
    .map_err(|e| format!("解除熔断任务调度失败: {e}"))??;
    logger::log_warn(
        "killswitch",
        format!("解除防火墙熔断: confirmed={confirmed} bg_procs={bg_procs}"),
    );
    if let Ok(mut guard) = state.killswitch.write() {
        *guard = ks.clone();
    }
    let hold_secs = state
        .config
        .read()
        .map(|c| c.kill_hold_seconds)
        .unwrap_or(45);
    release_kill_hold_tx(&app, &state, Some(hold_secs));
    if let Ok(mut snap) = state.snapshot.write() {
        snap.kill_switch_active = false;
        let _ = app.emit("guard://snapshot", snap.clone());
    }
    Ok(ks)
}

#[tauri::command]
fn get_killswitch_state(state: State<'_, AppState>) -> Result<KillSwitchState, String> {
    let guard = state
        .killswitch
        .read()
        .map_err(|_| "读取熔断状态失败".to_string())?;
    Ok(guard.clone())
}

#[tauri::command]
async fn get_log_analysis(state: State<'_, AppState>) -> Result<LogAnalysisReport, String> {
    let extra = state
        .injected_logs
        .read()
        .map(|v| v.clone())
        .unwrap_or_default();
    let acked_ids = state
        .config
        .read()
        .map(|c| c.acked_log_ids.clone())
        .unwrap_or_default();
    let (events, stats) =
        tokio::task::spawn_blocking(move || collect_log_analysis_with_acked(&extra, &acked_ids))
            .await
            .map_err(|e| format!("扫描日志任务调度失败: {e}"))?;
    Ok(LogAnalysisReport { events, stats })
}

/// T-202：持久化日志已读 ID 集合并立即重算 GuardSnapshot 广播至主窗口与悬浮窗（彻底解决已读后悬浮窗仍显异常与重启复发）
#[tauri::command]
async fn ack_log_events(
    app: AppHandle,
    state: State<'_, AppState>,
    ids: Vec<String>,
) -> Result<GuardSnapshot, String> {
    if !ids.is_empty() {
        if let Ok(mut cfg) = state.config.write() {
            for id in ids {
                if !id.is_empty() && !cfg.acked_log_ids.iter().any(|x| x == &id) {
                    cfg.acked_log_ids.push(id);
                }
            }
            if cfg.acked_log_ids.len() > 300 {
                let drop_n = cfg.acked_log_ids.len() - 300;
                cfg.acked_log_ids.drain(0..drop_n);
            }
            let _ = save_config(&state.config_path, &cfg);
        }
    }
    let extra = state
        .injected_logs
        .read()
        .map(|v| v.clone())
        .unwrap_or_default();
    let acked_ids = state
        .config
        .read()
        .map(|c| c.acked_log_ids.clone())
        .unwrap_or_default();
    let (events, stats) =
        tokio::task::spawn_blocking(move || collect_log_analysis_with_acked(&extra, &acked_ids))
            .await
            .map_err(|e| format!("刷新已读游标失败: {e}"))?;

    let updated = {
        let mut snap = state
            .snapshot
            .write()
            .map_err(|_| "写入快照锁失败".to_string())?;
        snap.unread_log_anomalies = stats.total_anomalies;
        snap.unread_log_critical = stats.critical_count;
        snap.unread_log_warnings = stats.warning_count;
        // 全部已读后清理仅由已读日志点亮的过期日志守则高亮，并保留 24h 冷静期等配置型守则
        if stats.total_anomalies == 0 {
            let calm_on = state.config.read().map(|c| c.calm_24h).unwrap_or(false);
            snap.triggered_playbook_ids
                .retain(|id| calm_on && id == "pb_24h");
            snap.hud_events.retain(|e| e.target_tab != "logs");
        } else {
            for ev in events.iter().filter(|e| e.anomaly && !e.acked) {
                if let Some(ref rid) = ev.rule_id {
                    if !snap.triggered_playbook_ids.iter().any(|x| x == rid) {
                        snap.triggered_playbook_ids.push(rid.clone());
                    }
                }
            }
        }
        snap.clone()
    };
    let _ = app.emit("guard://snapshot", updated.clone());
    Ok(updated)
}

#[tauri::command]
fn simulate_log_anomaly(app: AppHandle, state: State<'_, AppState>) -> Result<LogEvent, String> {
    let ev = LogEvent {
        id: format!("sim-{}", chrono::Local::now().timestamp_millis()),
        rule_id: Some("pb_rate".into()),
        anomaly: true,
        simulated: true,
        acked: false,
        level: "warn".into(),
        tag: "高并发 429".into(),
        time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        file: "simulated:57688".into(),
        line: 57688,
        title: "【模拟演示】检测到连续 429 限流与 4 个并行 sideSession".into(),
        cause: "模拟演示触发（非真实日志）：用于演练日志异常联动点亮安全守则的效果，随时可一键清空模拟记录。".into(),
        context: "57688 [warn] [SIMULATED] HTTP 429 rate_limit_error (active sideSessions=4)".into(),
        repeat_count: 1,
        collapsed_ids: Vec::new(),
        attribution_clue: None,
    };
    logger::log_info("watchdog", "注入模拟高并发 429 联动演示事件，点亮 pb_rate");
    if let Ok(mut list) = state.injected_logs.write() {
        list.insert(0, ev.clone());
        list.truncate(20);
    }
    let snap_to_emit = if let Ok(mut snap) = state.snapshot.write() {
        if !snap.triggered_playbook_ids.iter().any(|x| x == "pb_rate") {
            snap.triggered_playbook_ids.push("pb_rate".to_string());
        }
        snap.unread_log_anomalies = snap.unread_log_anomalies.saturating_add(1);
        snap.unread_log_warnings = snap.unread_log_warnings.saturating_add(1);
        snap.hud_events.insert(
            0,
            HudEventLine {
                message: "【模拟】守则联动：日志捕获连续 429 高并发限流".into(),
                time: chrono::Local::now().format("%H:%M").to_string(),
                level: "warn".into(),
                target_tab: "logs".into(),
            },
        );
        snap.hud_events.truncate(2);
        Some(snap.clone())
    } else {
        None
    };
    if let Some(s) = snap_to_emit {
        let _ = app.emit("guard://snapshot", s);
    }
    dispatch_native_alert(
        &app,
        &state,
        "warn:rate_429",
        false,
        "FD Claude Guard 预警（模拟）：高并发 429",
        "日志实时监听联动演示：已高亮安全守则。",
    );
    let _ = app.emit("guard://log-event", ev.clone());
    let _ = app.emit("guard://playbook-triggered", "pb_rate");
    Ok(ev)
}

#[tauri::command]
async fn clear_simulated_logs(app: AppHandle, state: State<'_, AppState>) -> Result<usize, String> {
    let removed = if let Ok(mut list) = state.injected_logs.write() {
        let len = list.len();
        list.clear();
        len
    } else {
        0
    };
    let acked_ids = state
        .config
        .read()
        .map(|c| c.acked_log_ids.clone())
        .unwrap_or_default();
    let (events, stats) =
        tokio::task::spawn_blocking(move || collect_log_analysis_with_acked(&[], &acked_ids))
            .await
            .map_err(|e| format!("清空模拟日志重扫任务失败: {e}"))?;

    let calm_on = state.config.read().map(|c| c.calm_24h).unwrap_or(false);
    let snap_to_emit = if let Ok(mut snap) = state.snapshot.write() {
        snap.unread_log_anomalies = stats.total_anomalies;
        snap.unread_log_critical = stats.critical_count;
        snap.unread_log_warnings = stats.warning_count;
        if stats.total_anomalies == 0 {
            snap.triggered_playbook_ids
                .retain(|id| calm_on && id == "pb_24h");
            snap.hud_events.retain(|e| e.target_tab != "logs");
        } else {
            for ev in events.iter().filter(|e| e.anomaly && !e.acked) {
                if let Some(ref rid) = ev.rule_id {
                    if !snap.triggered_playbook_ids.contains(rid) {
                        snap.triggered_playbook_ids.push(rid.clone());
                    }
                }
            }
        }
        Some(snap.clone())
    } else {
        None
    };
    if let Some(s) = snap_to_emit {
        let _ = app.emit("guard://snapshot", s);
    }
    Ok(removed)
}

/// T-303：生成当前环境与 72h 封号前置归因的脱敏载荷预览 JSON（供环境维护弹窗与守卫配置样本预览共用）
#[tauri::command]
async fn preview_anonymous_feedback_payload(state: State<'_, AppState>) -> Result<String, String> {
    let snap = state
        .snapshot
        .read()
        .map_err(|_| "读取快照锁失败".to_string())?
        .clone();
    let rep = state
        .last_report
        .read()
        .map_err(|_| "读取体检锁失败".to_string())?
        .clone();
    let extra = state
        .injected_logs
        .read()
        .map(|v| v.clone())
        .unwrap_or_default();
    let acked = state
        .config
        .read()
        .map(|c| c.acked_log_ids.clone())
        .unwrap_or_default();
    let install_short = anonymous_install_short_id();

    tokio::task::spawn_blocking(move || {
        let (events, stats) = collect_log_analysis_with_acked(&extra, &acked);
        let payload = build_anonymized_feedback_payload(
            &install_short,
            &snap,
            &rep,
            &events,
            stats.timezone_jump_warning.as_deref(),
        );
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".into())
    })
    .await
    .map_err(|e| format!("生成脱敏载荷预览失败: {e}"))
}

/// T-303：用户主动点击「一键匿名上报排障」异步提交脱敏诊断快照并生成唯一单号
#[tauri::command]
async fn submit_anonymous_feedback_report_cmd(
    state: State<'_, AppState>,
) -> Result<FeedbackReportResult, String> {
    let snap = state
        .snapshot
        .read()
        .map_err(|_| "读取快照锁失败".to_string())?
        .clone();
    let rep = state
        .last_report
        .read()
        .map_err(|_| "读取体检锁失败".to_string())?
        .clone();
    let extra = state
        .injected_logs
        .read()
        .map(|v| v.clone())
        .unwrap_or_default();
    let acked = state
        .config
        .read()
        .map(|c| c.acked_log_ids.clone())
        .unwrap_or_default();
    let install_short = anonymous_install_short_id();
    let api_endpoint = telemetry_api_endpoint();

    let (events, stats) =
        tokio::task::spawn_blocking(move || collect_log_analysis_with_acked(&extra, &acked))
            .await
            .map_err(|e| format!("采集脱敏日志失败: {e}"))?;

    submit_anonymous_feedback_report(
        api_endpoint.as_deref(),
        &install_short,
        &snap,
        &rep,
        &events,
        stats.timezone_jump_warning.as_deref(),
    )
    .await
}

#[tauri::command]
async fn inspect_telemetry_data() -> Result<TelemetryInspection, String> {
    tokio::task::spawn_blocking(inspect_local_telemetry)
        .await
        .map_err(|e| format!("遥测扫描调度失败: {e}"))
}

#[tauri::command]
async fn cleanup_all_guard_firewall_rules_cmd(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let msg = tokio::task::spawn_blocking(cleanup_all_guard_firewall_rules)
        .await
        .map_err(|e| format!("防火墙清理调度失败: {e}"))??;
    if let Ok(mut ks) = state.killswitch.write() {
        ks.active = false;
        ks.firewall_applied = false;
        ks.reason = msg.clone();
    }
    let hold_secs = state
        .config
        .read()
        .map(|c| c.kill_hold_seconds)
        .unwrap_or(45);
    release_kill_hold_tx(&app, &state, Some(hold_secs));
    if let Ok(mut snap) = state.snapshot.write() {
        snap.kill_switch_active = false;
        let _ = app.emit("guard://snapshot", snap.clone());
    }
    Ok(msg)
}

#[tauri::command]
async fn confirm_primary_org_binding(
    app: AppHandle,
    state: State<'_, AppState>,
    org_id: String,
) -> Result<PreflightReport, String> {
    let updated_cfg = {
        let mut guard = state
            .config
            .write()
            .map_err(|_| "写入配置锁失败".to_string())?;
        guard.bound_primary_org_id = if org_id.trim().is_empty() {
            None
        } else {
            Some(org_id.trim().to_string())
        };
        save_config(&state.config_path, &guard)?;
        guard.clone()
    };
    logger::log_event(
        "INFO",
        "preflight",
        "primary_org_rebound",
        None,
        format!("用户二次确认更新单号卫生锁绑定主号: {}", org_id.trim()),
        None,
    );
    let bg_procs = list_claude_processes().len() as u32;
    let mut bundle = run_all_preflight_checks(&updated_cfg, bg_procs).await;
    merge_killswitch_and_log_triggers(&state, &mut bundle.snapshot);
    if let Ok(mut rep) = state.last_report.write() {
        *rep = bundle.report.clone();
    }
    if let Ok(mut snap) = state.snapshot.write() {
        *snap = bundle.snapshot.clone();
    }
    let _ = app.emit("guard://config-changed", updated_cfg);
    let _ = app.emit("guard://preflight-updated", bundle.report.clone());
    let _ = app.emit("guard://snapshot", bundle.snapshot);
    Ok(bundle.report)
}

#[tauri::command]
async fn list_backups() -> Result<Vec<BackupInfo>, String> {
    tokio::task::spawn_blocking(|| list_backups_in(&backups_dir()))
        .await
        .map_err(|e| format!("读取备份列表失败: {e}"))
}

#[tauri::command]
async fn inspect_claude_data_roots() -> Result<maintenance::ClaudeDataRootsSummary, String> {
    tokio::task::spawn_blocking(maintenance::inspect_claude_data_roots_summary)
        .await
        .map_err(|e| format!("扫描目录摘要失败: {e}"))
}

#[tauri::command]
async fn preview_claude_cleanup_plan_cmd() -> Result<CleanupPlanPreview, String> {
    tokio::task::spawn_blocking(preview_claude_cleanup_plan)
        .await
        .map_err(|e| format!("预扫描清理清单失败: {e}"))
}

#[tauri::command]
async fn delete_backup(file_name: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || delete_backup_file_in(&backups_dir(), &file_name))
        .await
        .map_err(|e| format!("删除备份调度失败: {e}"))?
}

#[tauri::command]
async fn clear_all_backups() -> Result<usize, String> {
    tokio::task::spawn_blocking(|| clear_all_backups_in(&backups_dir()))
        .await
        .map_err(|e| format!("清空备份调度失败: {e}"))?
}

#[tauri::command]
async fn backup_and_clean_claude(
    app: AppHandle,
    state: State<'_, AppState>,
    selected_categories: Option<Vec<String>>,
) -> Result<BackupInfo, String> {
    acquire_kill_hold_tx(&app, &state, "原子备份清理期间防复活锁定");
    logger::log_info(
        "maintenance",
        format!(
            "开始执行异步原子 ZIP 备份并按勾选项清理本地目录: categories={:?}",
            selected_categories
        ),
    );
    let should_reset_primary_org = selected_categories
        .as_ref()
        .map(|cats| cats.iter().any(|c| c == "auth" || c == "logs"))
        .unwrap_or(true);
    let res = tokio::task::spawn_blocking(move || {
        backup_and_clean_claude_dirs_selected(selected_categories.as_deref())
    })
    .await
    .map_err(|e| format!("备份清理后台线程异常: {e}"))
    .and_then(|r| r);
    // T-031：清理事务完成后立即释放事务锁，不再强挂 45 秒长盯防拦用户重新打开 Claude 登录
    release_kill_hold_tx(&app, &state, None);
    let info = res?;
    // T-046：勾选清理登录态或日志后，自动解除旧主号绑定，重登新号自动重新绑定（免手工换绑）
    if should_reset_primary_org {
        if let Ok(mut cfg) = state.config.write() {
            if cfg.bound_primary_org_id.is_some() {
                cfg.bound_primary_org_id = None;
                let _ = save_config(&state.config_path, &cfg);
                let _ = app.emit("guard://config-changed", cfg.clone());
                logger::log_info("maintenance", "清理登录态/日志后已自动重置旧 bound_primary_org_id 绑定基线");
            }
        }
    }
    logger::log_info(
        "maintenance",
        format!("原子备份清理完成: {} ({})", info.file_name, info.size_label),
    );
    Ok(info)
}

#[tauri::command]
async fn create_manual_backup() -> Result<BackupInfo, String> {
    let info = tokio::task::spawn_blocking(create_manual_backup_snapshot)
        .await
        .map_err(|e| format!("手动备份线程异常: {e}"))??;
    logger::log_info(
        "maintenance",
        format!("已手动创建环境快照: {} ({})", info.file_name, info.size_label),
    );
    Ok(info)
}

#[tauri::command]
async fn restore_backup(
    app: AppHandle,
    state: State<'_, AppState>,
    file_name: String,
) -> Result<String, String> {
    acquire_kill_hold_tx(&app, &state, "原子快照还原期间防复活锁定");
    logger::log_info("maintenance", format!("开始执行异步原子事务快照还原: {file_name}"));
    let fname = file_name.clone();
    let res = tokio::task::spawn_blocking(move || restore_backup_file(&fname))
        .await
        .map_err(|e| format!("原子还原线程异常: {e}"))
        .and_then(|r| r);
    release_kill_hold_tx(&app, &state, None);
    let msg = res?;
    logger::log_info("maintenance", &msg);
    Ok(msg)
}

#[tauri::command]
async fn export_ai_diagnostic_bundle_cmd(
    state: State<'_, AppState>,
    context_item_id: Option<String>,
) -> Result<DiagnosticBundleResult, String> {
    let cfg = state
        .config
        .read()
        .map_err(|_| "读取配置失败".to_string())?
        .clone();
    let snap = state
        .snapshot
        .read()
        .map_err(|_| "读取快照失败".to_string())?
        .clone();
    let report = state
        .last_report
        .read()
        .map_err(|_| "读取体检报告失败".to_string())?
        .clone();
    let extra = state
        .injected_logs
        .read()
        .map(|v| v.clone())
        .unwrap_or_default();

    tokio::task::spawn_blocking(move || {
        let (logs, _) = collect_log_analysis(&extra);
        export_ai_diagnostic_bundle(context_item_id.as_deref(), &cfg, &snap, &report, &logs)
    })
    .await
    .map_err(|e| format!("导出诊断包线程异常: {e}"))?
}

#[tauri::command]
fn open_file_folder(path: String) -> Result<(), String> {
    open_folder_and_select(&path)
}

#[tauri::command]
async fn audit_startup_items(state: State<'_, AppState>) -> Result<StartupAuditReport, String> {
    let guard_enabled = state
        .config
        .read()
        .map(|c| c.boot_start)
        .unwrap_or(true);
    tokio::task::spawn_blocking(move || audit_windows_startup_items(guard_enabled))
        .await
        .map_err(|e| format!("启动项审计调度失败: {e}"))
}

#[tauri::command]
fn log_frontend_event(level: String, module: String, message: String) {
    let norm = match level.to_uppercase().as_str() {
        "ERROR" => "ERROR",
        "WARN" => "WARN",
        _ => "INFO",
    };
    logger::write_log(norm, &format!("ui:{module}"), &message);
}

#[tauri::command]
fn open_guard_logs_dir() -> Result<String, String> {
    logger::open_logs_directory()
}

#[tauri::command]
fn get_recent_guard_logs(limit: Option<usize>) -> Vec<String> {
    logger::read_recent_logs(limit.unwrap_or(100))
}

fn persist_baseline_if_needed(
    state: &AppState,
    current_node: &str,
    landing_sig: Option<&str>,
    org_id: Option<&str>,
) {
    // 深度核验运行期间切的是临时备选节点，绝不改写用户基线
    if is_deep_audit_running() {
        return;
    }
    if let Ok(mut cfg) = state.config.write() {
        let mut changed = false;
        let valid_node = !current_node.trim().is_empty()
            && current_node != "未连接"
            && current_node != "未选节点"
            && current_node != "未配置 Claude-Fixed"
            && !is_blocked_node_name(current_node);
        if let Some(sig) = landing_sig {
            // 符合 3A：当用户在 Clash 外部直接切换 Claude-Fixed 里的合规节点时，自动跟随更新基线并刷新对应 IP（绝不拿新节点对比旧节点报漂移）
            let node_changed = valid_node && cfg.locked_node_for_ip.as_deref() != Some(current_node);
            if cfg.locked_node_for_ip.is_none() || cfg.locked_landing_ip.is_none() || node_changed {
                if valid_node {
                    cfg.locked_node_for_ip = Some(current_node.to_string());
                    cfg.locked_landing_ip = Some(sig.to_string());
                    changed = true;
                }
            }
        }
        if let Some(org) = org_id {
            if cfg.bound_primary_org_id.is_none() && !org.is_empty() {
                cfg.bound_primary_org_id = Some(org.to_string());
                changed = true;
            }
        }
        if changed {
            let _ = save_config(&state.config_path, &cfg);
        }
    }
}

fn apply_kill_hold_to_snapshot(snap: &mut GuardSnapshot, hs: &KillHoldSnapshot) {
    snap.kill_hold_active = hs.active;
    snap.kill_hold_remaining_secs = hs.remaining_secs;
    snap.kill_hold_blocked_count = hs.blocked_count;
    snap.kill_hold_tx_locked = hs.tx_locked;
    snap.kill_hold_reason = hs.reason.clone();
}

fn start_kill_hold_internal(
    app: &AppHandle,
    state: &AppState,
    duration_secs: u32,
    reason: &str,
) -> KillHoldSnapshot {
    let hs = if let Ok(mut kh) = state.kill_hold.write() {
        let now = Instant::now();
        kh.start_hold(duration_secs, reason, now);
        kh.snapshot_and_sweep(now)
    } else {
        KillHoldSnapshot::default()
    };
    logger::log_event(
        "INFO",
        "kill_hold",
        "kill_hold_started",
        None,
        format!("启动防复活持续盯防锁: {}s ({reason})", hs.remaining_secs),
        Some(serde_json::json!({ "durationSecs": hs.remaining_secs, "reason": reason })),
    );
    if let Ok(mut snap) = state.snapshot.write() {
        apply_kill_hold_to_snapshot(&mut snap, &hs);
        let _ = app.emit("guard://snapshot", snap.clone());
    }
    hs
}

fn acquire_kill_hold_tx(app: &AppHandle, state: &AppState, reason: &str) {
    let hs = if let Ok(mut kh) = state.kill_hold.write() {
        let now = Instant::now();
        kh.acquire_tx_lock(reason, now);
        kh.snapshot_and_sweep(now)
    } else {
        KillHoldSnapshot::default()
    };
    logger::log_event(
        "INFO",
        "kill_hold",
        "kill_hold_tx_acquired",
        None,
        format!("开启事务级防复活锁定: {reason}"),
        None,
    );
    if let Ok(mut snap) = state.snapshot.write() {
        apply_kill_hold_to_snapshot(&mut snap, &hs);
        let _ = app.emit("guard://snapshot", snap.clone());
    }
}

fn release_kill_hold_tx(app: &AppHandle, state: &AppState, post_hold_secs: Option<u32>) {
    let hs = if let Ok(mut kh) = state.kill_hold.write() {
        let now = Instant::now();
        kh.release_tx_lock(post_hold_secs, now);
        kh.snapshot_and_sweep(now)
    } else {
        KillHoldSnapshot::default()
    };
    if let Ok(mut snap) = state.snapshot.write() {
        apply_kill_hold_to_snapshot(&mut snap, &hs);
        let _ = app.emit("guard://snapshot", snap.clone());
    }
}

fn release_kill_hold_internal(
    app: &AppHandle,
    state: &AppState,
    reason: &str,
) -> KillHoldSnapshot {
    let was_active = state
        .kill_hold
        .read()
        .map(|kh| kh.is_active_at(Instant::now()))
        .unwrap_or(false);
    let hs = if let Ok(mut kh) = state.kill_hold.write() {
        kh.release();
        kh.snapshot_and_sweep(Instant::now())
    } else {
        KillHoldSnapshot::default()
    };
    if was_active {
        logger::log_event(
            "INFO",
            "kill_hold",
            "kill_hold_released",
            None,
            format!("防复活持续盯防锁已释放: {reason}"),
            None,
        );
    }
    if let Ok(mut snap) = state.snapshot.write() {
        apply_kill_hold_to_snapshot(&mut snap, &hs);
        let _ = app.emit("guard://snapshot", snap.clone());
    }
    hs
}

fn merge_killswitch_and_log_triggers(state: &AppState, snap: &mut GuardSnapshot) {
    if let Ok(ks) = state.killswitch.read() {
        snap.kill_switch_active = ks.active;
        if ks.active {
            snap.health_level = "danger".into();
            snap.status_label = "已自动熔断".into();
        }
    }
    if let Ok(mut kh) = state.kill_hold.write() {
        let hs = kh.snapshot_and_sweep(Instant::now());
        apply_kill_hold_to_snapshot(snap, &hs);
    }
    let extra = state
        .injected_logs
        .read()
        .map(|v| v.clone())
        .unwrap_or_default();
    let acked_ids = state
        .config
        .read()
        .map(|c| c.acked_log_ids.clone())
        .unwrap_or_default();
    let (events, stats) = collect_log_analysis_with_acked(&extra, &acked_ids);
    snap.unread_log_anomalies = stats.total_anomalies;
    snap.unread_log_critical = stats.critical_count;
    snap.unread_log_warnings = stats.warning_count;
    for ev in events.iter().filter(|e| e.anomaly && !e.acked) {
        if let Some(ref rid) = ev.rule_id {
            if !snap.triggered_playbook_ids.iter().any(|x| x == rid) {
                snap.triggered_playbook_ids.push(rid.clone());
            }
        }
    }
}

fn apply_hud_fold_size(app: &AppHandle, folded: bool) {
    if let Some(hud) = app.get_webview_window("hud") {
        let height = if folded {
            HUD_FOLDED_HEIGHT
        } else {
            HUD_EXPANDED_HEIGHT
        };
        let scale = effective_hud_scale(&hud, None);
        let _ = set_hud_physical_size(&hud, HUD_WIDTH, height, None);
        logger::log_info(
            "hud",
            format!(
                "应用悬浮窗尺寸: folded={folded}, logical={HUD_WIDTH:.0}x{height:.0}, effective_scale={scale:.2}"
            ),
        );
    }
}

fn position_hud_on_startup(app: &AppHandle, cfg: &AppConfig) {
    let Some(hud) = app.get_webview_window("hud") else {
        return;
    };

    let _ = hud.set_always_on_top(cfg.hud_pinned);
    if !cfg.show_hud {
        let _ = hud.hide();
    }

    if cfg.hud_edge_docked {
        apply_hud_edge_dock(app, cfg, true, false);
        return;
    }

    apply_hud_fold_size(app, cfg.hud_folded);

    if let Some(pos) = cfg.hud_position {
        let clamped_x = pos.x.max(-100);
        let clamped_y = pos.y.max(0);
        let _ = hud.set_position(PhysicalPosition::new(clamped_x, clamped_y));
        logger::log_info("hud", format!("恢复上次悬浮窗坐标: ({clamped_x}, {clamped_y})"));
        return;
    }

    if let Ok(Some(monitor)) = hud.primary_monitor() {
        let size = monitor.size();
        let scale = effective_hud_scale(&hud, None);
        let hud_w = (HUD_WIDTH * scale).ceil() as i32;
        let margin = (HUD_RIGHT_MARGIN * scale).ceil() as i32;
        let top = (64.0 * scale).ceil() as i32;
        let x = (size.width as i32 - hud_w - margin).max(16);
        let _ = hud.set_position(PhysicalPosition::new(x, top));
        logger::log_info("hud", format!("首次定位悬浮窗至主屏右上角: ({x}, {top}) effective_scale={scale:.2}"));
    }
}

fn handle_tray_quit(app: &AppHandle) {
    let app_clone = app.clone();
    // 绝不在托盘 UI 主线程执行子进程检测，防止托盘假死数秒
    std::thread::spawn(move || {
        let (safe_prompt, ks_active) = app_clone
            .try_state::<AppState>()
            .map(|st| {
                let sp = st.config.read().map(|c| c.safe_exit_prompt).unwrap_or(true);
                let ks = st.killswitch.read().map(|k| k.active).unwrap_or(false);
                (sp, ks)
            })
            .unwrap_or((true, false));

        let bg_procs = list_claude_processes().len() as u32;
        let has_fw_rules = ks_active || has_active_guard_firewall_rules();

        if safe_prompt && (bg_procs > 0 || has_fw_rules) {
            logger::log_warn(
                "lifecycle",
                format!(
                    "安全退出防呆拦截：Claude 进程={bg_procs}, 活跃阻断规则={has_fw_rules}，唤起控制台二次确认"
                ),
            );
            if show_main_window(app_clone.clone(), Some("console".into()), None, None, None).is_ok()
            {
                let _ = app_clone.emit("guard://confirm-exit", bg_procs);
                return;
            }
        }

        fast_hide_and_exit(
            &app_clone,
            has_fw_rules,
            if has_fw_rules {
                "托盘菜单触发安全退出并已清理活跃防火墙规则"
            } else {
                "托盘菜单触发极速安全退出（无活跃防火墙规则）"
            },
        );
    });
}

fn setup_tray(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let open_main = MenuItem::with_id(app, "open_main", "打开控制台", true, None::<&str>)?;
    let toggle_hud = MenuItem::with_id(app, "toggle_hud", "显示 / 隐藏悬浮窗", true, None::<&str>)?;
    let open_playbook = MenuItem::with_id(app, "open_playbook", "查看安全守则", true, None::<&str>)?;
    let open_logs = MenuItem::with_id(app, "open_logs", "打开运行诊断日志目录", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "退出 FD Claude Guard", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[&open_main, &toggle_hud, &open_playbook, &open_logs, &sep, &quit],
    )?;

    let mut builder = TrayIconBuilder::with_id("fd-claude-guard-tray")
        .tooltip("FD Claude 安全启动器 (FD Claude Guard)")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open_main" => {
                let _ = show_main_window(app.clone(), Some("console".into()), None, None, None);
            }
            "toggle_hud" => {
                if let Some(st) = app.try_state::<AppState>() {
                    let next = !st.config.read().map(|c| c.show_hud).unwrap_or(true);
                    if let Ok(mut g) = st.config.write() {
                        g.show_hud = next;
                        let _ = save_config(&st.config_path, &g);
                        let _ = app.emit("guard://config-changed", g.clone());
                    }
                    if let Some(hud) = app.get_webview_window("hud") {
                        if next {
                            if let Ok(cfg) = st.config.read() {
                                if cfg.hud_edge_docked {
                                    apply_hud_edge_dock(app, &cfg, true, false);
                                } else {
                                    apply_hud_fold_size(app, cfg.hud_folded);
                                }
                            }
                            let _ = hud.show();
                        } else {
                            let _ = hud.hide();
                        }
                    }
                }
            }
            "open_playbook" => {
                let _ = show_main_window(app.clone(), Some("console".into()), None, None, Some(true));
            }
            "open_logs" => {
                let _ = logger::open_logs_directory();
            }
            "quit" => handle_tray_quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle().clone();
                let _ = show_main_window(app, Some("console".into()), None, None, None);
            }
        });

    if let Ok(tray_img) = tauri::image::Image::from_bytes(include_bytes!("../icons/32x32.png")) {
        builder = builder.icon(tray_img);
    } else if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder.build(app)?;
    Ok(())
}

/// 后台调度引擎：
/// - 250ms Kill-Hold 防复活高频押运协程（增量 17，仅锁激活时工作，复用 Win32 Toolhelp32）
/// - 2 秒 Win32 进程雷达 & 防裸奔接管
/// - LOCAL_HEARTBEAT_MS (29121ms) 本地管道心跳
/// - FULL_AUDIT_INTERVAL_MS (904543ms) 全量外网兜底巡检
fn spawn_background_engines(app: AppHandle) {
    // 0. 增量 17 & P0-4 修复：自适应 Kill-Hold 防复活盯防协程
    // - 未激活态按 1000ms 低频休眠（消灭空闲每秒 4 次写锁）；激活态切回 250ms 盯防
    // - 强杀放进 spawn_blocking 不阻塞 tokio worker；仅真实杀掉进程且未超最大顺延次数才 +15s，遇到杀不死的进程退避 2s 防无限活锁与日志风暴
    let app_kh = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut last_emitted = KillHoldSnapshot::default();
        let mut extend_times: u32 = 0;
        let mut unkillable_logged = false;
        loop {
            let sleep_ms = if last_emitted.active && !last_emitted.tx_locked {
                KILL_HOLD_POLL_INTERVAL_MS
            } else {
                1000
            };
            tokio::time::sleep(Duration::from_millis(sleep_ms)).await;

            let Some(state) = app_kh.try_state::<AppState>() else {
                continue;
            };

            let now = Instant::now();
            let mut cur_snap = if let Ok(mut kh) = state.kill_hold.write() {
                kh.snapshot_and_sweep(now)
            } else {
                continue;
            };

            if !cur_snap.active {
                extend_times = 0;
                unkillable_logged = false;
            } else if !cur_snap.tx_locked {
                let procs = tokio::task::spawn_blocking(list_claude_processes)
                    .await
                    .unwrap_or_default();
                if !procs.is_empty() {
                    let rep = tokio::task::spawn_blocking(|| kill_claude_process_tree(true))
                        .await
                        .ok();
                    let killed = rep
                        .as_ref()
                        .map(|r| r.before_count.saturating_sub(r.after_count))
                        .unwrap_or(0);
                    if killed > 0 {
                        unkillable_logged = false;
                        if extend_times < 6 {
                            extend_times += 1;
                            cur_snap = if let Ok(mut kh) = state.kill_hold.write() {
                                let t_now = Instant::now();
                                kh.record_respawn_blocked(killed, t_now);
                                kh.snapshot_and_sweep(t_now)
                            } else {
                                cur_snap
                            };
                        }
                        logger::log_event(
                            "WARN",
                            "kill_hold",
                            "kill_hold_respawn_blocked",
                            None,
                            format!(
                                "盯防期间捕获 Claude 复活进程 ({} 个)，已强杀 {} 个（剩余 {}s，累计拦截 {} 次）",
                                procs.len(),
                                killed,
                                cur_snap.remaining_secs,
                                cur_snap.blocked_count
                            ),
                            Some(serde_json::json!({
                                "killed": killed,
                                "remainingSecs": cur_snap.remaining_secs,
                                "blockedCount": cur_snap.blocked_count
                            })),
                        );
                    } else {
                        // 遇到提权/杀不死的残留进程：不再 .max(1) 无限顺延，退避 2s 且仅记 1 次诊断警告
                        if !unkillable_logged {
                            unkillable_logged = true;
                            logger::log_warn(
                                "kill_hold",
                                format!(
                                    "盯防期间发现 {} 个无法强杀的 Claude 进程（可能已提权或句柄锁定），已退避 2s 避免活锁刷屏",
                                    procs.len()
                                ),
                            );
                        }
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }

            if cur_snap != last_emitted {
                let snap_to_emit = if let Ok(mut snap) = state.snapshot.write() {
                    apply_kill_hold_to_snapshot(&mut snap, &cur_snap);
                    if cur_snap.active {
                        snap.bg_claude_procs = 0;
                    }
                    Some(snap.clone())
                } else {
                    None
                };
                if let Some(s) = snap_to_emit {
                    let _ = app_kh.emit("guard://snapshot", s);
                }
                last_emitted = cur_snap;
            }
        }
    });

    // 1. 休眠唤醒预阻断窗 + 实时日志变更 + 2 秒 Mihomo 状态哨兵（全路径非阻塞 + 轻量单组查询）
    let app_radar = app.clone();
    tauri::async_runtime::spawn(async move {
        let (mut last_log_fp, mut seen_anomaly_ids): ((u64, u64), std::collections::HashSet<String>) =
            tokio::task::spawn_blocking(|| {
                let fp = claude_logs_fingerprint();
                let (init_events, _) = collect_log_analysis(&[]);
                let ids = init_events
                    .into_iter()
                    .filter(|e| e.anomaly)
                    .map(|e| e.id)
                    .collect();
                (fp, ids)
            })
            .await
            .unwrap_or(((0, 0), std::collections::HashSet::new()));
        let mut last_mihomo_sig: Option<(bool, bool, String, String, String)> = None;
        let mut ticker = tokio::time::interval(Duration::from_secs(2));
        loop {
            let before_tick_wall = SystemTime::now();
            ticker.tick().await;

            let Some(state) = app_radar.try_state::<AppState>() else {
                continue;
            };

            // 1A. 增量 13：仅检测 tick 睡眠期间的墙钟跳变（>= 15s）判定休眠唤醒，彻底杜绝上轮 20s 体检把自身误判为系统休眠
            let now_wall = SystemTime::now();
            if let Ok(delta) = now_wall.duration_since(before_tick_wall) {
                if delta.as_secs() >= 15 {
                    let wake_guard = state
                        .config
                        .read()
                        .map(|c| c.wake_preblock_guard)
                        .unwrap_or(true);
                    if wake_guard {
                        let wake_start = Instant::now();
                        let applied = tokio::task::spawn_blocking(|| set_wake_preblock_rule(true))
                            .await
                            .unwrap_or(false);
                        logger::log_event(
                            "WARN",
                            "wake_guard",
                            "wake_preblock_window",
                            None,
                            format!(
                                "检测到系统休眠唤醒（墙钟跳变 {}s），已启动最长 15 秒预阻断安全窗 (fw={applied})",
                                delta.as_secs()
                            ),
                            Some(serde_json::json!({ "wallJumpSecs": delta.as_secs(), "firewallApplied": applied })),
                        );
                        // 等待 Clash 管道在线 + TUN 开启 + 非 Direct 模式就绪，最长保护 15 秒（防止超时裸放行）
                        let mut recovered = false;
                        for _ in 0..30 {
                            if let Some(ep) = discover_endpoint().await {
                                if let Ok(m_cfg) = fetch_configs(&ep).await {
                                    if m_cfg.tun_enable
                                        && !m_cfg.mode.eq_ignore_ascii_case("direct")
                                    {
                                        recovered = true;
                                        break;
                                    }
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        }
                        let wake_procs = tokio::task::spawn_blocking(|| list_claude_processes().len() as u32)
                            .await
                            .unwrap_or(0);
                        if !recovered && wake_procs > 0 {
                            let anti_flush = state
                                .config
                                .read()
                                .map(|c| c.anti_upload_flush)
                                .unwrap_or(true);
                            let ks = trigger_four_layer_killswitch(
                                "休眠唤醒 15 秒内代理 / TUN 仍未恢复且 Claude 进程存活，已自动转入正式 4 层熔断防裸连",
                                anti_flush,
                            )
                            .await;
                            let _ = tokio::task::spawn_blocking(|| set_wake_preblock_rule(false)).await;
                            if let Ok(mut guard) = state.killswitch.write() {
                                *guard = ks.clone();
                            }
                            let snap_emit = if let Ok(mut snap) = state.snapshot.write() {
                                snap.kill_switch_active = true;
                                snap.health_level = "danger".into();
                                snap.status_label = "已自动熔断".into();
                                snap.bg_claude_procs = 0;
                                Some(snap.clone())
                            } else {
                                None
                            };
                            if let Some(s) = snap_emit {
                                let _ = app_radar.emit("guard://snapshot", s);
                            }
                            let _ = app_radar.emit("guard://killswitch", ks.clone());
                            dispatch_native_alert(
                                &app_radar,
                                &state,
                                "wake_timeout_killswitch",
                                true,
                                "休眠唤醒代理未恢复：已自动转入 4 层熔断",
                                "15 秒安全窗内 Clash / TUN 未就绪，已自动强杀 Claude 并锁死出站，恢复代理后再解除熔断。",
                            );
                        } else {
                            let _ = tokio::task::spawn_blocking(|| set_wake_preblock_rule(false)).await;
                        }
                        logger::log_event(
                            "INFO",
                            "wake_guard",
                            "wake_preblock_released",
                            Some(wake_start.elapsed().as_millis() as u64),
                            format!(
                                "休眠唤醒安全窗复测完成 (clash_tun_recovered={recovered}, claude_procs={wake_procs})"
                            ),
                            Some(serde_json::json!({ "recovered": recovered, "claudeProcs": wake_procs })),
                        );
                    }
                }
            }
            // 1B. 事件级日志增量监听：磁盘指纹与扫盘全部移入 spawn_blocking；
            //     仅新增 level=="fail" 高危实锤事件时才重跑 17 项体检与触发 L2 遥测，普通 warn 仅刷新未读快照与本地提醒
            let cur_log_fp = tokio::task::spawn_blocking(claude_logs_fingerprint)
                .await
                .unwrap_or(last_log_fp);
            if cur_log_fp != last_log_fp {
                last_log_fp = cur_log_fp;
                let extra = state
                    .injected_logs
                    .read()
                    .map(|v| v.clone())
                    .unwrap_or_default();
                let acked_ids = state
                    .config
                    .read()
                    .map(|c| c.acked_log_ids.clone())
                    .unwrap_or_default();
                let (events, _) = tokio::task::spawn_blocking(move || {
                    collect_log_analysis_with_acked(&extra, &acked_ids)
                })
                .await
                .unwrap_or_default();
                let new_anomalies: Vec<LogEvent> = events
                    .into_iter()
                    .filter(|e| e.anomaly && !e.acked && !seen_anomaly_ids.contains(&e.id))
                    .collect();

                if !new_anomalies.is_empty() {
                    for ev in &new_anomalies {
                        seen_anomaly_ids.insert(ev.id.clone());
                    }
                    let has_critical = new_anomalies.iter().any(|e| e.level == "fail");
                    let latest_title = new_anomalies
                        .first()
                        .map(|e| e.title.clone())
                        .unwrap_or_else(|| "检测到新增日志异常".into());
                    logger::log_event(
                        if has_critical { "WARN" } else { "INFO" },
                        "watchdog",
                        "log_new_anomalies",
                        None,
                        format!(
                            "检测到 Claude 日志新增 {} 条事件（critical={}）：{}",
                            new_anomalies.len(),
                            has_critical,
                            latest_title
                        ),
                        None,
                    );
                    if has_critical {
                        if let Ok(_gate) = state.preflight_gate.try_lock() {
                            let cfg = state.config.read().map(|c| c.clone()).unwrap_or_default();
                            let cur_procs = tokio::task::spawn_blocking(|| list_claude_processes().len() as u32)
                                .await
                                .unwrap_or(0);
                            let mut bundle = run_all_preflight_checks(&cfg, cur_procs).await;
                            persist_baseline_if_needed(
                                &state,
                                &bundle.snapshot.current_node,
                                bundle.detected_landing_sig.as_deref(),
                                bundle.detected_org_id.as_deref(),
                            );
                            merge_killswitch_and_log_triggers(&state, &mut bundle.snapshot);
                            if let Ok(mut rep) = state.last_report.write() {
                                *rep = bundle.report.clone();
                            }
                            if let Ok(mut ts) = state.last_preflight_at.write() {
                                *ts = Some(Instant::now());
                            }
                            if let Ok(mut snap) = state.snapshot.write() {
                                *snap = bundle.snapshot.clone();
                            }
                            let _ = app_radar.emit("guard://preflight-updated", bundle.report);
                            let _ = app_radar.emit("guard://snapshot", bundle.snapshot.clone());
                        }
                    } else {
                        // 普通 warn（如 Free/KYC 403、OAuth v2、529 过载、普通断连）：仅原地刷新日志未读计数并推送快照，不重跑 17 项外网探针
                        let snap_updated = if let Ok(snap_cur) = state.snapshot.read() {
                            let mut next = snap_cur.clone();
                            drop(snap_cur);
                            merge_killswitch_and_log_triggers(&state, &mut next);
                            if let Ok(mut snap_w) = state.snapshot.write() {
                                *snap_w = next.clone();
                            }
                            Some(next)
                        } else {
                            None
                        };
                        if let Some(s) = snap_updated {
                            let _ = app_radar.emit("guard://snapshot", s);
                        }
                    }
                    let calm_24h_on = state
                        .config
                        .read()
                        .map(|c| c.calm_24h)
                        .unwrap_or(false);
                    // T-035：开启 24h 冷静期时，401/403、验证受限、身份验证/权限、高并发 429 均升级为最高级不可静音告警
                    let escalated_critical = has_critical
                        || (calm_24h_on
                            && new_anomalies.iter().any(|e| {
                                matches!(
                                    e.tag.as_str(),
                                    "验证受限"
                                        | "身份验证/权限"
                                        | "高并发 429"
                                        | "带凭证 403"
                                        | "退出回传 403"
                                )
                            }));
                    let alert_key = format!(
                        "log_anomaly:{}:{}",
                        if escalated_critical { "fail" } else { "warn" },
                        new_anomalies
                            .first()
                            .map(|e| e.id.as_str())
                            .unwrap_or("batch")
                    );
                    dispatch_native_alert(
                        &app_radar,
                        &state,
                        &alert_key,
                        escalated_critical,
                        if calm_24h_on && escalated_critical {
                            "FD Claude Guard 24h 冷静期最高级日志预警"
                        } else if escalated_critical {
                            "FD Claude Guard 高危日志预警"
                        } else {
                            "FD Claude Guard 日志提醒"
                        },
                        &format!(
                            "新增 {} 条{}：{}（点击日志分析查看详情与处理建议）",
                            new_anomalies.len(),
                            if has_critical { "日志异常" } else { "日志风险提醒" },
                            latest_title
                        ),
                    );
                    // L2 低频高价值遥测：仅在存在高危实锤事件（level == "fail"）时才静默上报，彻底隔离 Free/KYC warn 噪音
                    if has_critical {
                        let cfg_tel = state.config.read().map(|c| c.clone()).unwrap_or_default();
                        let snap_tel = state.snapshot.read().map(|s| s.clone()).ok();
                        if let Some(snap_tel) = snap_tel {
                            let api_ep = telemetry_api_endpoint();
                            let inst = anonymous_install_short_id();
                            let evs_clone = new_anomalies.clone();
                            tauri::async_runtime::spawn(async move {
                                flush_telemetry_events_if_enabled(
                                    &cfg_tel,
                                    api_ep.as_deref(),
                                    &inst,
                                    &snap_tel,
                                    &evs_clone,
                                    Vec::new(),
                                )
                                .await;
                            });
                        }
                    }
                }
            }

            // 1B-2. 超轻量 2 秒 Mihomo 状态哨兵：仅查 /configs + 单个策略组 /proxies/Claude-Fixed（仅 global 模式再查 /proxies/GLOBAL），替代百 KB 全量 /proxies
            if !is_deep_audit_running() {
                let ep_opt = discover_endpoint().await;
                let cur_sig = if let Some(ref ep) = ep_opt {
                    let m_cfg = fetch_configs(ep).await.ok();
                    let tun_on = m_cfg.as_ref().map(|c| c.tun_enable).unwrap_or(false);
                    let clash_mode = m_cfg
                        .as_ref()
                        .map(|c| c.mode.to_ascii_lowercase())
                        .unwrap_or_else(|| "rule".into());
                    let group_now = fetch_proxy_group_now(ep, "Claude-Fixed")
                        .await
                        .unwrap_or_default();
                    let global_now = if clash_mode == "global" {
                        fetch_proxy_group_now(ep, "GLOBAL")
                            .await
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    (true, tun_on, clash_mode, global_now, group_now)
                } else {
                    (false, false, String::new(), String::new(), String::new())
                };
                match &last_mihomo_sig {
                    None => {
                        last_mihomo_sig = Some(cur_sig);
                    }
                    Some(prev) if *prev != cur_sig => {
                        let prev_sig = prev.clone();
                        let node_changed_in_group = !cur_sig.4.is_empty() && prev_sig.4 != cur_sig.4;
                        logger::log_info(
                            "radar",
                            format!(
                                "检测到 Clash 实时状态变化: prev={:?} -> now={:?}，自动触发体检刷新",
                                prev_sig, cur_sig
                            ),
                        );
                        last_mihomo_sig = Some(cur_sig.clone());

                        // 接管原 29.1s 冗余心跳的离线告警职责（零重复轮询）
                        if prev_sig.0 && !cur_sig.0 {
                            logger::log_warn("radar", "2s 状态哨兵检测到 Clash Verge 管道断开！");
                            dispatch_native_alert(
                                &app_radar,
                                &state,
                                "critical:proxy_offline",
                                true,
                                "FD Claude Guard 危急告警：代理已断开",
                                "检测到 Clash Verge 离线，请立即检查代理并勿操作 Claude。",
                            );
                        }

                        // T-020：Claude 运行中代理失守（退出 Clash / 关 TUN / 切 Direct / GLOBAL 脱组 / 切禁区）2 秒自动 4 层热熔断
                        let cur_procs_hot = tokio::task::spawn_blocking(|| list_claude_processes().len() as u32)
                            .await
                            .unwrap_or(0);
                        let (auto_ks_on, anti_flush_on) = state
                            .config
                            .read()
                            .map(|c| (c.auto_kill_switch, c.anti_upload_flush))
                            .unwrap_or((true, true));
                        let already_ks = state
                            .killswitch
                            .read()
                            .map(|k| k.active)
                            .unwrap_or(false);
                        let mut hot_ks_triggered = false;
                        if let Some(hot_reason) = evaluate_runtime_killswitch_trigger(
                            &prev_sig,
                            &cur_sig,
                            cur_procs_hot,
                            auto_ks_on,
                            is_deep_audit_running(),
                            already_ks,
                        ) {
                            hot_ks_triggered = true;
                            logger::log_event(
                                "ERROR",
                                "killswitch",
                                "runtime_hot_killswitch_triggered",
                                None,
                                format!("运行中热熔断触发 ({cur_procs_hot} 个 Claude 进程存活): {hot_reason}"),
                                Some(serde_json::json!({
                                    "claudeProcs": cur_procs_hot,
                                    "prev": prev_sig,
                                    "cur": cur_sig
                                })),
                            );
                            let ks = trigger_four_layer_killswitch(hot_reason, anti_flush_on).await;
                            // 热熔断统一持有事务级防复活盯防锁，确保未手动解除熔断前绝不提前放行
                            acquire_kill_hold_tx(
                                &app_radar,
                                &state,
                                "运行中代理失守热熔断防复活盯防",
                            );
                            if let Ok(mut guard) = state.killswitch.write() {
                                *guard = ks.clone();
                            }
                            let snap_emit = if let Ok(mut snap) = state.snapshot.write() {
                                snap.kill_switch_active = true;
                                snap.health_level = "danger".into();
                                snap.status_label = "已自动熔断".into();
                                snap.bg_claude_procs = 0;
                                snap.kill_hold_active = true;
                                snap.kill_hold_tx_locked = true;
                                snap.hud_events.insert(
                                    0,
                                    HudEventLine {
                                        message: hot_reason.into(),
                                        time: chrono::Local::now().format("%H:%M").to_string(),
                                        level: "danger".into(),
                                        target_tab: "console".into(),
                                    },
                                );
                                snap.hud_events.truncate(4);
                                Some(snap.clone())
                            } else {
                                None
                            };
                            if let Some(ref s) = snap_emit {
                                let _ = app_radar.emit("guard://snapshot", s.clone());
                                // L2 低频高价值遥测：记录真实运行中热熔断事件
                                let cfg_tel = state.config.read().map(|c| c.clone()).unwrap_or_default();
                                let api_ep = telemetry_api_endpoint();
                                let inst = anonymous_install_short_id();
                                let snap_tel = s.clone();
                                let tev = serde_json::json!({
                                    "category": "tool_diag",
                                    "event_type": "runtime_hot_killswitch",
                                    "level": "error",
                                    "tag": "killswitch",
                                    "signature": hot_reason,
                                    "repeat_count": 1,
                                    "pre_ban_factors": [],
                                    "env": {
                                        "clashPort": snap_tel.clash_port,
                                        "region": snap_tel.region_code,
                                        "claudeProcs": cur_procs_hot,
                                    },
                                    "client_event_id": format!("ks:hot:{}", chrono::Local::now().format("%Y%m%d%H")),
                                });
                                tauri::async_runtime::spawn(async move {
                                    flush_telemetry_events_if_enabled(&cfg_tel, api_ep.as_deref(), &inst, &snap_tel, &[], vec![tev]).await;
                                });
                            }
                            let _ = app_radar.emit("guard://killswitch", ks.clone());
                            dispatch_native_alert(
                                &app_radar,
                                &state,
                                "runtime_hot_killswitch",
                                true,
                                "运行中代理失守：已自动 4 层热熔断",
                                hot_reason,
                            );
                        }

                        if !hot_ks_triggered {
                        if let Ok(_gate) = state.preflight_gate.try_lock() {
                            // 符合 3A：在 Clash 外部直接切换 Claude-Fixed 内的合法节点时，自动更新基线、重新校准漂移基准并等待 350ms 隧道稳定后再测
                            if node_changed_in_group && !is_blocked_node_name(&cur_sig.4) {
                                crate::mihomo::reset_node_drift_history(&cur_sig.4);
                                tokio::time::sleep(Duration::from_millis(350)).await;
                                if let Ok(mut guard) = state.config.write() {
                                    guard.locked_node_for_ip = Some(cur_sig.4.clone());
                                    guard.locked_landing_ip = None;
                                    let _ = save_config(&state.config_path, &guard);
                                }
                            }
                            let cfg = state.config.read().map(|c| c.clone()).unwrap_or_default();
                            let cur_procs = tokio::task::spawn_blocking(|| list_claude_processes().len() as u32)
                                .await
                                .unwrap_or(0);
                            let mut bundle = run_all_preflight_checks(&cfg, cur_procs).await;
                            persist_baseline_if_needed(
                                &state,
                                &bundle.snapshot.current_node,
                                bundle.detected_landing_sig.as_deref(),
                                bundle.detected_org_id.as_deref(),
                            );
                            merge_killswitch_and_log_triggers(&state, &mut bundle.snapshot);
                            if let Ok(mut rep) = state.last_report.write() {
                                *rep = bundle.report.clone();
                            }
                            if let Ok(mut ts) = state.last_preflight_at.write() {
                                *ts = Some(Instant::now());
                            }
                            if let Ok(mut snap) = state.snapshot.write() {
                                *snap = bundle.snapshot.clone();
                            }
                            let _ = app_radar.emit("guard://preflight-updated", bundle.report);
                            let _ = app_radar.emit("guard://snapshot", bundle.snapshot.clone());
                        }
                        }
                    }
                    _ => {}
                }

                // 1B-3. 实时连接异常轻量同步（复用已发现 ep，避免重复 discover_endpoint）
                if let Some(ref ep) = ep_opt {
                    let prev_live_anom = state
                        .snapshot
                        .read()
                        .map(|s| s.live_flow_anomalies)
                        .unwrap_or(0);
                    let procs_now = tokio::task::spawn_blocking(|| list_claude_processes().len())
                        .await
                        .unwrap_or(0);
                    if procs_now > 0 || prev_live_anom > 0 {
                        let live_anom = get_live_claude_connections_on(ep)
                            .await
                            .into_iter()
                            .filter(|c| c.anomaly)
                            .count();
                        if live_anom != prev_live_anom {
                            let snap_emit = if let Ok(mut snap) = state.snapshot.write() {
                                let node_issue =
                                    usize::from(snap.node_down || snap.node_drift_warn);
                                snap.live_flow_anomalies = live_anom;
                                snap.active_flow_anomalies = live_anom + node_issue;
                                Some(snap.clone())
                            } else {
                                None
                            };
                            if let Some(s) = snap_emit {
                                let _ = app_radar.emit("guard://snapshot", s);
                            }
                        }
                    }
                }
            }
        }
    });

    // 1C. T-033 独立 500ms 无阻塞 Win32 进程雷达 + 防裸奔接管（list_claude_processes 移入 spawn_blocking，彻底不阻塞 async 线程）
    let app_proc_radar = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut last_count: u32 = tokio::task::spawn_blocking(|| list_claude_processes().len() as u32)
            .await
            .unwrap_or(0);
        let mut ticker = tokio::time::interval(Duration::from_millis(500));
        loop {
            ticker.tick().await;
            let Some(state) = app_proc_radar.try_state::<AppState>() else {
                continue;
            };
            let count = tokio::task::spawn_blocking(|| list_claude_processes().len() as u32)
                .await
                .unwrap_or(last_count);
            if count == last_count {
                continue;
            }
            logger::log_event(
                "INFO",
                "radar",
                "process_count_changed",
                None,
                format!("Claude 进程数量变化: {last_count} -> {count}"),
                Some(serde_json::json!({ "prev": last_count, "now": count })),
            );
            let (anti_naked, auto_ks, anti_flush) = state
                .config
                .read()
                .map(|c| (c.anti_naked_guard, c.auto_kill_switch, c.anti_upload_flush))
                .unwrap_or((true, true, true));

            let preflight_ready = state
                .last_preflight_at
                .read()
                .ok()
                .and_then(|g| *g)
                .is_some();
            let env_not_ready = state
                .snapshot
                .read()
                .map(|s| s.must_passed < s.must_total || !s.clash_online)
                .unwrap_or(true);

            // 仅在冷启动首轮真实体检完成后才执行防裸奔自动拦截，彻底杜绝冷启动前 3 秒误杀 Claude
            if last_count == 0 && count > 0 && anti_naked && preflight_ready && env_not_ready {
                let in_kill_hold = state
                    .kill_hold
                    .read()
                    .map(|kh| kh.is_active_at(Instant::now()))
                    .unwrap_or(false);
                if in_kill_hold {
                    // Kill-Hold 250ms 押运协程正在强杀拦截，无需重复弹出防裸奔接管
                    last_count = count;
                    continue;
                }
                logger::log_warn(
                    "radar",
                    format!("[{FD_ERR_KILL_SWITCH}] 防裸奔自动接管触发：未通过必须项直接启动 Claude"),
                );
                if auto_ks {
                    let ks = trigger_four_layer_killswitch(
                        "防裸奔自动接管：检测到未通过必须项即直接启动 Claude",
                        anti_flush,
                    )
                    .await;
                    acquire_kill_hold_tx(&app_proc_radar, &state, "防裸奔熔断事务锁定");
                    if let Ok(mut guard) = state.killswitch.write() {
                        *guard = ks.clone();
                    }
                    if let Ok(mut snap) = state.snapshot.write() {
                        snap.kill_switch_active = true;
                        snap.health_level = "danger".into();
                        snap.status_label = "已自动熔断".into();
                        snap.bg_claude_procs = 0;
                        snap.hud_events.insert(
                            0,
                            HudEventLine {
                                message: "防裸奔自动接管：未全绿启动 Claude，已 4 层熔断并强杀".into(),
                                time: chrono::Local::now().format("%H:%M").to_string(),
                                level: "danger".into(),
                                target_tab: "console".into(),
                            },
                        );
                        snap.hud_events.truncate(4);
                        let _ = app_proc_radar.emit("guard://snapshot", snap.clone());
                    }
                    let _ = app_proc_radar.emit("guard://killswitch", ks);
                }
                dispatch_native_alert(
                    &app_proc_radar,
                    &state,
                    "critical:naked_launch",
                    true,
                    "FD Claude Guard 防裸奔拦截",
                    "检测到环境未全绿即启动 Claude，已自动触发 4 层熔断并唤起控制台。",
                );
                let _ = show_main_window(
                    app_proc_radar.clone(),
                    Some("console".into()),
                    None,
                    Some("__first_fail__".into()),
                    None,
                );
                let _ = app_proc_radar.emit("guard://naked-launch-intercepted", count);
                last_count = tokio::task::spawn_blocking(|| list_claude_processes().len() as u32)
                    .await
                    .unwrap_or(0);
                continue;
            }

            let snap_emit = if let Ok(mut snap) = state.snapshot.write() {
                snap.bg_claude_procs = count;
                Some(snap.clone())
            } else {
                None
            };
            if let Some(s) = snap_emit {
                let _ = app_proc_radar.emit("guard://snapshot", s);
            }
            last_count = count;
        }
    });

    // 2. FULL_AUDIT_INTERVAL_MS (904543ms ≈ 15 分钟) 全量外网巡检兜底（已移除与 2s 状态哨兵完全重叠的 29.1s 冗余心跳协程）
    let app_audit = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(FULL_AUDIT_INTERVAL_MS));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if is_deep_audit_running() {
                continue;
            }
            let Some(st) = app_audit.try_state::<AppState>() else {
                continue;
            };
            let _gate = st.preflight_gate.lock().await;
            let cfg = st.config.read().map(|c| c.clone()).unwrap_or_default();
            let bg_procs = list_claude_processes().len() as u32;
            let mut bundle = run_all_preflight_checks(&cfg, bg_procs).await;
            merge_killswitch_and_log_triggers(&st, &mut bundle.snapshot);
            if let Ok(mut rep) = st.last_report.write() {
                *rep = bundle.report;
            }
            if let Ok(mut ts) = st.last_preflight_at.write() {
                *ts = Some(Instant::now());
            }
            if let Ok(mut snap) = st.snapshot.write() {
                *snap = bundle.snapshot.clone();
            }
            let _ = app_audit.emit("guard://snapshot", bundle.snapshot);
        }
    });

    // 4. 启动自动静默节点预核验（首检完成后再触发，严禁在首检并发期间切用户 Clash 节点）
    let app_preaudit = app;
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_millis(4500)).await;
        if let Some(st) = app_preaudit.try_state::<AppState>() {
            let _gate = st.preflight_gate.lock().await;
            drop(_gate);
        }
        let _ = spawn_deep_node_audit_task(app_preaudit, false, None, true);
    });
}

/// Windows 单实例互斥锁：防止重复双击导致托盘双图标、悬浮窗重叠与退出残留
#[cfg(windows)]
struct SingleInstanceGuard(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

#[cfg(windows)]
fn acquire_single_instance_guard() -> Option<SingleInstanceGuard> {
    use std::ptr::null;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
    };

    let name: Vec<u16> = "Local\\FDClaudeGuard_SingleInstance_v1\0"
        .encode_utf16()
        .collect();
    let handle = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Some(SingleInstanceGuard(std::ptr::null_mut()));
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(handle);
            // 唤醒已运行的主控制台窗口并置前
            let title: Vec<u16> = "FD Claude 安全启动器 (FD Claude Guard)\0"
                .encode_utf16()
                .collect();
            let hwnd = FindWindowW(null(), title.as_ptr());
            if !hwnd.is_null() {
                ShowWindow(hwnd, SW_SHOW);
                ShowWindow(hwnd, SW_RESTORE);
                SetForegroundWindow(hwnd);
            }
        }
        return None;
    }
    Some(SingleInstanceGuard(handle))
}

#[cfg(not(windows))]
struct SingleInstanceGuard;

#[cfg(not(windows))]
fn acquire_single_instance_guard() -> Option<SingleInstanceGuard> {
    Some(SingleInstanceGuard)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// 查询系统基线快照与 6 项可撤回改动状态（免付费墙，任何激活状态均可查看）
#[tauri::command]
async fn inspect_rollback_status_cmd() -> Result<RollbackOverview, String> {
    Ok(inspect_rollback_status().await)
}

/// 单项精准撤回本工具对系统或 Clash 的改动（免付费墙，用户随时有权还原自己电脑）
#[tauri::command]
async fn rollback_single_item_cmd(
    state: State<'_, AppState>,
    item_id: String,
) -> Result<RollbackActionReport, String> {
    let report = rollback_single_item(&item_id).await;
    if let Ok(mut ts) = state.last_preflight_at.write() {
        *ts = None;
    }
    Ok(report)
}

/// 一键按安全逆序撤回全部由本工具改动的系统与 Clash 设置（免付费墙）
#[tauri::command]
async fn rollback_all_changes_cmd(
    state: State<'_, AppState>,
) -> Result<RollbackBatchReport, String> {
    let report = rollback_all_changes().await;
    if let Ok(mut ts) = state.last_preflight_at.write() {
        *ts = None;
    }
    Ok(report)
}

/// 无门槛「一键网络急救」（免付费墙，专治关 TUN 断网、无法导入订阅与防火墙残留）
#[tauri::command]
async fn run_network_emergency_rescue_cmd(
    state: State<'_, AppState>,
) -> Result<NetworkRescueReport, String> {
    let report = run_network_emergency_rescue().await;
    if let Ok(mut ts) = state.last_preflight_at.write() {
        *ts = None;
    }
    Ok(report)
}

pub fn run() {
    let Some(_instance_guard) = acquire_single_instance_guard() else {
        logger::log_info("lifecycle", "检测到已有 FD Claude Guard 实例运行，已尝试唤起原窗口并退出重复进程");
        return;
    };

    logger::cleanup_old_logs();
    let config_path = default_config_path();
    let existed = config_path.exists();
    let initial_cfg = load_config(&config_path);
    if !existed {
        let _ = save_config(&config_path, &initial_cfg);
    }

    let args: Vec<String> = std::env::args().collect();
    let start_hud_only = should_start_hud_only(&args, &initial_cfg);
    logger::log_info(
        "lifecycle",
        format!(
            "FD Claude Guard v{} 启动 | hud_only={start_hud_only} | show_hud={} | boot_start={} | theme={}",
            env!("CARGO_PKG_VERSION"),
            initial_cfg.show_hud,
            initial_cfg.boot_start,
            initial_cfg.theme
        ),
    );

    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--autostart"]),
        ))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new(config_path, initial_cfg.clone()))
        .setup(move |app| {
            let handle = app.handle();
            setup_tray(handle)?;
            position_hud_on_startup(handle, &initial_cfg);

            if !start_hud_only {
                if let Ok(main_win) = ensure_main_window(handle) {
                    let _ = main_win.show();
                    let _ = main_win.set_focus();
                }
            }

            // 持有单飞锁执行冷启动首轮真实探针，彻底消除 bootstrap 并发双跑
            let bg_handle = handle.clone();
            let bg_cfg = initial_cfg.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(st) = bg_handle.try_state::<AppState>() {
                    let _gate = st.preflight_gate.lock().await;
                    let bg_procs = list_claude_processes().len() as u32;
                    let mut bundle = run_all_preflight_checks(&bg_cfg, bg_procs).await;
                    merge_killswitch_and_log_triggers(&st, &mut bundle.snapshot);
                    if let Ok(mut rep) = st.last_report.write() {
                        *rep = bundle.report;
                    }
                    if let Ok(mut ts) = st.last_preflight_at.write() {
                        *ts = Some(Instant::now());
                    }
                    if let Ok(mut snap) = st.snapshot.write() {
                        *snap = bundle.snapshot.clone();
                    }
                    let _ = bg_handle.emit("guard://snapshot", bundle.snapshot);
                }
            });

            spawn_background_engines(handle.clone());

            if let Some(hud_win) = handle.get_webview_window("hud") {
                let w = hud_win.clone();
                let app_handle = handle.clone();
                hud_win.on_window_event(move |event| match event {
                    WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        logger::log_info("hud", "悬浮窗关闭请求已拦截，隐藏至托盘");
                        if let Some(st) = app_handle.try_state::<AppState>() {
                            if let Ok(mut g) = st.config.write() {
                                g.show_hud = false;
                                let _ = save_config(&st.config_path, &g);
                                let _ = app_handle.emit("guard://config-changed", g.clone());
                            }
                        }
                        let _ = w.hide();
                    }
                    WindowEvent::Moved(pos) => {
                        static HUD_MOVE_SCHEDULED: std::sync::atomic::AtomicBool =
                            std::sync::atomic::AtomicBool::new(false);
                        if let Some(state) = app_handle.try_state::<AppState>() {
                            let is_docked = state
                                .config
                                .read()
                                .map(|c| c.hud_edge_docked)
                                .unwrap_or(false);
                            if is_docked {
                                return;
                            }
                            if let Ok(mut guard) = state.config.write() {
                                guard.hud_position = Some(WindowPos { x: pos.x, y: pos.y });
                            }
                            state.hud_move_seq.fetch_add(1, Ordering::SeqCst);
                            // 单任务防抖合并：拖拽过程中绝不再按像素 spawn 数百个 Tokio 任务
                            if HUD_MOVE_SCHEDULED
                                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                                .is_ok()
                            {
                                let ah = app_handle.clone();
                                tauri::async_runtime::spawn(async move {
                                    loop {
                                        let observed = ah
                                            .try_state::<AppState>()
                                            .map(|st| st.hud_move_seq.load(Ordering::SeqCst))
                                            .unwrap_or(0);
                                        tokio::time::sleep(Duration::from_millis(400)).await;
                                        let Some(st) = ah.try_state::<AppState>() else {
                                            break;
                                        };
                                        if st.hud_move_seq.load(Ordering::SeqCst) == observed {
                                            let cfg_to_save = st.config.read().ok().map(|g| g.clone());
                                            let path = st.config_path.clone();
                                            if let Some(cfg) = cfg_to_save {
                                                let pos_opt = cfg.hud_position.clone();
                                                let saved = tokio::task::spawn_blocking(move || {
                                                    save_config(&path, &cfg).is_ok()
                                                })
                                                .await
                                                .unwrap_or(false);
                                                if saved {
                                                    if let Some(p) = pos_opt {
                                                        logger::log_info(
                                                            "hud",
                                                            format!("防抖落盘悬浮窗坐标: ({}, {})", p.x, p.y),
                                                        );
                                                    }
                                                }
                                            }
                                            break;
                                        }
                                    }
                                    HUD_MOVE_SCHEDULED.store(false, Ordering::SeqCst);
                                });
                            }
                        }
                    }
                    _ => {}
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_config,
            update_config,
            save_hud_position,
            resize_hud_height,
            set_hud_edge_docked,
            set_hud_pinned,
            set_hud_folded,
            show_main_window,
            hide_main_window,
            toggle_hud_window,
            quit_app,
            get_snapshot,
            run_preflight_checks,
            fix_preflight_item,
            one_click_fix_all,
            safe_launch_claude,
            get_nodes_and_quality,
            get_deep_audit_status,
            start_deep_node_audit,
            cancel_deep_node_audit,
            reset_node_drift_baseline,
            switch_locked_node,
            get_live_connections,
            close_connection,
            kill_claude_processes,
            start_kill_hold_cmd,
            release_kill_hold_cmd,
            trigger_killswitch,
            force_release_killswitch,
            get_killswitch_state,
            get_log_analysis,
            ack_log_events,
            simulate_log_anomaly,
            clear_simulated_logs,
            inspect_telemetry_data,
            preview_anonymous_feedback_payload,
            submit_anonymous_feedback_report_cmd,
            cleanup_all_guard_firewall_rules_cmd,
            confirm_primary_org_binding,
            list_backups,
            inspect_claude_data_roots,
            preview_claude_cleanup_plan_cmd,
            delete_backup,
            clear_all_backups,
            backup_and_clean_claude,
            create_manual_backup,
            restore_backup,
            export_ai_diagnostic_bundle_cmd,
            open_file_folder,
            audit_startup_items,
            log_frontend_event,
            open_guard_logs_dir,
            get_recent_guard_logs,
            inspect_rollback_status_cmd,
            rollback_single_item_cmd,
            rollback_all_changes_cmd,
            run_network_emergency_rescue_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("启动 FD Claude Guard 时发生错误");
}

#[cfg(test)]
mod window_size_tests {
    use super::compute_main_window_default_size;

    #[test]
    fn main_window_default_size_expands_on_large_screen_and_clamps_on_small_screen() {
        // 2K / 4K 大屏：完整展开 1380x860
        assert_eq!(
            compute_main_window_default_size(Some(2560.0), Some(1440.0)),
            (1380.0, 860.0)
        );
        // 1080p @ 150% 高缩放笔记本（逻辑 1280x720）：自动夹紧防超界
        assert_eq!(
            compute_main_window_default_size(Some(1280.0), Some(720.0)),
            (1152.0, 640.0)
        );
        // 极小屏 1024x600：不低于安全下限 960x640
        assert_eq!(
            compute_main_window_default_size(Some(1024.0), Some(600.0)),
            (960.0, 640.0)
        );
        // 显示器查询失败兜底：返回 1380x860
        assert_eq!(
            compute_main_window_default_size(None, None),
            (1380.0, 860.0)
        );
    }

    #[test]
    fn runtime_killswitch_trigger_covers_all_failure_modes_and_blocks_false_positives() {
        let healthy = (
            true,
            true,
            "rule".to_string(),
            "Claude-Fixed".to_string(),
            "🇦🇺澳大利亚|原生".to_string(),
        );
        let clash_down = (false, false, String::new(), String::new(), String::new());
        let tun_off = (true, false, "rule".into(), "Claude-Fixed".into(), "🇦🇺澳大利亚|原生".into());
        let direct_mode = (true, true, "direct".into(), "Claude-Fixed".into(), "🇦🇺澳大利亚|原生".into());
        let global_escaped = (true, true, "global".into(), "天悦云".into(), "🇦🇺澳大利亚|原生".into());
        let hk_node = (true, true, "rule".into(), "Claude-Fixed".into(), "🇭🇰香港1".into());
        let safe_switch = (true, true, "rule".into(), "Claude-Fixed".into(), "🇺🇸美国2|流媒体AI".into());

        // 正例：Claude 运行中（>0 进程）发生 5 类代理失守必须立刻触发热熔断
        assert!(super::evaluate_runtime_killswitch_trigger(&healthy, &clash_down, 3, true, false, false).is_some());
        assert!(super::evaluate_runtime_killswitch_trigger(&healthy, &tun_off, 2, true, false, false).is_some());
        assert!(super::evaluate_runtime_killswitch_trigger(&healthy, &direct_mode, 1, true, false, false).is_some());
        assert!(super::evaluate_runtime_killswitch_trigger(&healthy, &global_escaped, 1, true, false, false).is_some());
        assert!(super::evaluate_runtime_killswitch_trigger(&healthy, &hk_node, 1, true, false, false).is_some());

        // 反例防误杀：0 进程 / 关闭自动熔断 / 深度核验期间 / 已熔断 / 组内切合规节点绝不误触发
        assert!(super::evaluate_runtime_killswitch_trigger(&healthy, &clash_down, 0, true, false, false).is_none());
        assert!(super::evaluate_runtime_killswitch_trigger(&healthy, &clash_down, 3, false, false, false).is_none());
        assert!(super::evaluate_runtime_killswitch_trigger(&healthy, &clash_down, 3, true, true, false).is_none());
        assert!(super::evaluate_runtime_killswitch_trigger(&healthy, &clash_down, 3, true, false, true).is_none());
        assert!(super::evaluate_runtime_killswitch_trigger(&healthy, &safe_switch, 3, true, false, false).is_none());
    }

    /// T-041 工程自动化门禁：静态审计 src-tauri/src/lib.rs 中全部 #[tauri::command]
    /// 仅轻量内存读写/窗口状态切换允许同步 fn；所有重磁盘/子进程/网络命令必须为 async fn，杜绝 UI 主线程卡死回归
    #[test]
    fn tauri_commands_thread_isolation_audit() {
        let src = include_str!("lib.rs");
        let lines: Vec<&str> = src.lines().collect();
        let allowed_sync_commands: std::collections::HashSet<&str> = [
            "get_config",
            "update_config",
            "save_hud_position",
            "resize_hud_height",
            "set_hud_edge_docked",
            "set_hud_pinned",
            "set_hud_folded",
            "show_main_window",
            "hide_main_window",
            "toggle_hud_window",
            "quit_app",
            "get_snapshot",
            "get_deep_audit_status",
            "cancel_deep_node_audit",
            "release_kill_hold_cmd",
            "get_killswitch_state",
            "simulate_log_anomaly",
            "clear_simulated_logs",
            "open_file_folder",
            "log_frontend_event",
            "open_guard_logs_dir",
            "get_recent_guard_logs",
        ]
        .into_iter()
        .collect();

        let mut violations = Vec::new();
        for i in 0..lines.len() {
            if lines[i].trim() == "#[tauri::command]" {
                if let Some(sig) = lines.get(i + 1).map(|s| s.trim()) {
                    if let Some(rest) = sig.strip_prefix("fn ") {
                        let name = rest.split('(').next().unwrap_or("").trim();
                        if !allowed_sync_commands.contains(name) {
                            violations.push(name.to_string());
                        }
                    }
                }
            }
        }
        assert!(
            violations.is_empty(),
            "检测到未经白名单许可的同步 #[tauri::command]（存在阻塞 WebView2 UI 主线程卡死风险，请改为 async fn + spawn_blocking）: {:?}",
            violations
        );
    }

    /// T-044 回归断言：清理事务锁期间不顺延倒计时，解锁后 remaining_secs 立即归 0
    #[test]
    fn tx_locked_kill_hold_does_not_leave_post_countdown() {
        let mut ctrl = crate::process::KillHoldController::default();
        let t0 = std::time::Instant::now();
        ctrl.acquire_tx_lock("原子备份清理期间防复活锁定", t0);
        let during = ctrl.snapshot_and_sweep(t0);
        assert!(during.active && during.tx_locked);
        assert_eq!(during.remaining_secs, 0);
        ctrl.release_tx_lock(None, t0 + std::time::Duration::from_secs(2));
        let after = ctrl.snapshot_and_sweep(t0 + std::time::Duration::from_secs(2));
        assert!(!after.active);
        assert!(!after.tx_locked);
        assert_eq!(after.remaining_secs, 0);
    }
}
