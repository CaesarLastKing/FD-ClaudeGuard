use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// 悬浮窗坐标（物理像素）
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowPos {
    pub x: i32,
    pub y: i32,
}

/// 主控制台窗口几何尺寸与位置（物理像素，用于恢复用户上次手动拖拽/缩放的布局）
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MainWindowBounds {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    #[serde(default)]
    pub maximized: bool,
}

/// 全局守护配置（持久化至 ~/.fd-claude-guard/config.json）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct AppConfig {
    /// 界面主题："dark" | "light"
    pub theme: String,
    /// 显示桌面悬浮状态窗（默认开，与主窗顶栏开关/托盘四端同步）
    pub show_hud: bool,
    /// 桌面预警消息提醒（默认开，关闭仅静音普通预警，危急警报不可静音）
    pub notify_enabled: bool,
    /// 开机自动启动（默认开）
    pub boot_start: bool,
    /// 开机时仅显示桌面悬浮窗，不弹出主控制台（默认开）
    pub boot_hud_only: bool,
    /// 休眠唤醒 / 切网 5 秒预阻断安全窗（默认开，增量 13）
    pub wake_preblock_guard: bool,
    /// 防裸奔自动接管（默认开）
    pub anti_naked_guard: bool,
    /// 异常全自动紧急断流：Clash 掐流 + 防火墙封死出站（默认开）
    pub auto_kill_switch: bool,
    /// 熔断恢复前强杀进程丢弃内存队列 + 清离线遥测缓存（默认开）
    pub anti_upload_flush: bool,
    /// 安全退出防呆提醒（默认开）
    pub safe_exit_prompt: bool,
    /// 新号 / 刚付费 24h 冷静保护模式（默认关）
    pub calm_24h: bool,
    /// 悬浮窗是否固定置顶（默认开）
    pub hud_pinned: bool,
    /// 悬浮窗是否收起折叠（默认展开）
    pub hud_folded: bool,
    /// 悬浮窗是否靠右贴边自动隐藏（默认关）
    pub hud_edge_docked: bool,
    /// 上次拖拽保存的悬浮窗坐标
    pub hud_position: Option<WindowPos>,
    /// 上次手动缩放/拖拽保存的主控制台窗口几何尺寸与位置（恢复前会按当前显示器边界防呆校验）
    #[serde(default)]
    pub main_window_bounds: Option<MainWindowBounds>,
    /// 增量 11：上次锁定的节点名称（用于识别节点名未变但落地 IP 静默漂移）
    pub locked_node_for_ip: Option<String>,
    /// 增量 11：上次锁定节点的脱敏/前缀落地 IP（仅记录脱敏前两段或哈希，不存完整明文公网 IP）
    pub locked_landing_ip: Option<String>,
    /// 增量 16：单号卫生锁绑定的主号 orgId 前缀
    pub bound_primary_org_id: Option<String>,
    /// 增量 17：强杀防复活持续盯防锁时长（秒，允许 30 / 45 / 60，默认 45）
    pub kill_hold_seconds: u32,
    /// T-202：已读日志事件 ID 集合（持久化游标，防止标为已读后悬浮窗不消或重启复发，滚动保留最近 300 条）
    #[serde(default)]
    pub acked_log_ids: Vec<String>,
    /// T-302：上报本工具运行异常与一键修复诊断开关（严格脱敏，可随时关闭）
    #[serde(default = "default_true")]
    pub telemetry_tool_diag_enabled: bool,
    /// T-302：上报 Claude 报错类型与 72h 封号前置归因摘要开关（零隐私脱敏，可随时关闭）
    #[serde(default = "default_true")]
    pub telemetry_claude_summary_enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            show_hud: true,
            notify_enabled: true,
            boot_start: true,
            boot_hud_only: true,
            wake_preblock_guard: true,
            anti_naked_guard: true,
            auto_kill_switch: true,
            anti_upload_flush: true,
            safe_exit_prompt: true,
            calm_24h: false,
            hud_pinned: true,
            hud_folded: false,
            hud_edge_docked: false,
            hud_position: None,
            main_window_bounds: None,
            locked_node_for_ip: None,
            locked_landing_ip: None,
            bound_primary_org_id: None,
            kill_hold_seconds: 45,
            acked_log_ids: Vec::new(),
            telemetry_tool_diag_enabled: true,
            telemetry_claude_summary_enabled: true,
        }
    }
}

/// 局部配置更新补丁
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppConfigPatch {
    pub theme: Option<String>,
    pub show_hud: Option<bool>,
    pub notify_enabled: Option<bool>,
    pub boot_start: Option<bool>,
    pub boot_hud_only: Option<bool>,
    pub wake_preblock_guard: Option<bool>,
    pub anti_naked_guard: Option<bool>,
    pub auto_kill_switch: Option<bool>,
    pub anti_upload_flush: Option<bool>,
    pub safe_exit_prompt: Option<bool>,
    pub calm_24h: Option<bool>,
    pub hud_pinned: Option<bool>,
    pub hud_folded: Option<bool>,
    pub hud_edge_docked: Option<bool>,
    pub hud_position: Option<WindowPos>,
    pub bound_primary_org_id: Option<String>,
    pub kill_hold_seconds: Option<u32>,
    pub telemetry_tool_diag_enabled: Option<bool>,
    pub telemetry_claude_summary_enabled: Option<bool>,
}

impl AppConfig {
    pub fn apply_patch(&mut self, patch: AppConfigPatch) {
        if let Some(theme) = patch.theme {
            if theme == "dark" || theme == "light" {
                self.theme = theme;
            }
        }
        if let Some(v) = patch.show_hud {
            self.show_hud = v;
        }
        if let Some(v) = patch.notify_enabled {
            self.notify_enabled = v;
        }
        if let Some(boot_start) = patch.boot_start {
            self.boot_start = boot_start;
            if !boot_start {
                self.boot_hud_only = false;
            }
        }
        if let Some(boot_hud_only) = patch.boot_hud_only {
            self.boot_hud_only = boot_hud_only && self.boot_start;
        }
        if let Some(v) = patch.wake_preblock_guard {
            self.wake_preblock_guard = v;
        }
        if let Some(v) = patch.anti_naked_guard {
            self.anti_naked_guard = v;
        }
        if let Some(v) = patch.auto_kill_switch {
            self.auto_kill_switch = v;
        }
        if let Some(v) = patch.anti_upload_flush {
            self.anti_upload_flush = v;
        }
        if let Some(v) = patch.safe_exit_prompt {
            self.safe_exit_prompt = v;
        }
        if let Some(v) = patch.calm_24h {
            self.calm_24h = v;
        }
        if let Some(v) = patch.hud_pinned {
            self.hud_pinned = v;
        }
        if let Some(v) = patch.hud_folded {
            self.hud_folded = v;
        }
        if let Some(v) = patch.hud_edge_docked {
            self.hud_edge_docked = v;
        }
        if let Some(pos) = patch.hud_position {
            self.hud_position = Some(pos);
        }
        if let Some(org) = patch.bound_primary_org_id {
            self.bound_primary_org_id = if org.trim().is_empty() { None } else { Some(org) };
        }
        if let Some(secs) = patch.kill_hold_seconds {
            if matches!(secs, 30 | 45 | 60) {
                self.kill_hold_seconds = secs;
            }
        }
        if let Some(v) = patch.telemetry_tool_diag_enabled {
            self.telemetry_tool_diag_enabled = v;
        }
        if let Some(v) = patch.telemetry_claude_summary_enabled {
            self.telemetry_claude_summary_enabled = v;
        }
    }
}

pub fn default_config_path() -> PathBuf {
    let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join(".fd-claude-guard").join("config.json")
}

static CONFIG_WRITE_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
static CONFIG_TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub fn load_config(path: &Path) -> AppConfig {
    match fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<AppConfig>(raw.trim_start_matches('\u{feff}')) {
            Ok(cfg) => cfg,
            Err(_) => {
                // 损坏配置先备份留档，避免下次保存静默永久抹掉用户原配置
                let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
                let backup = path.with_extension(format!("json.corrupt-{ts}"));
                let _ = fs::copy(path, backup);
                AppConfig::default()
            }
        },
        Err(_) => AppConfig::default(),
    }
}

pub fn save_config(path: &Path, cfg: &AppConfig) -> Result<(), String> {
    let lock = CONFIG_WRITE_LOCK.get_or_init(|| std::sync::Mutex::new(()));
    let _guard = lock.lock().map_err(|_| "配置写盘锁异常".to_string())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建配置目录失败: {e}"))?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| format!("序列化配置失败: {e}"))?;
    let seq = CONFIG_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let tmp_path = path.with_extension(format!("json.tmp.{pid}.{seq}"));
    fs::write(&tmp_path, &json).map_err(|e| format!("写入临时配置失败: {e}"))?;
    if fs::rename(&tmp_path, path).is_err() {
        let write_res = fs::write(path, &json).map_err(|e| format!("保存配置文件失败: {e}"));
        let _ = fs::remove_file(&tmp_path);
        write_res?;
    }
    Ok(())
}

pub fn should_start_hud_only(args: &[String], cfg: &AppConfig) -> bool {
    let is_autostart = args.iter().any(|a| a == "--autostart" || a == "--hud-only");
    is_autostart && cfg.boot_hud_only
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_config_matches_security_baseline() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.theme, "dark");
        assert!(cfg.show_hud);
        assert!(cfg.notify_enabled);
        assert!(cfg.boot_start);
        assert!(cfg.boot_hud_only);
        assert!(cfg.wake_preblock_guard);
        assert!(cfg.anti_naked_guard);
        assert!(cfg.auto_kill_switch);
        assert!(cfg.anti_upload_flush);
        assert!(cfg.safe_exit_prompt);
        assert!(!cfg.calm_24h);
        assert!(cfg.hud_pinned);
        assert!(!cfg.hud_folded);
        assert!(!cfg.hud_edge_docked);
        assert!(cfg.hud_position.is_none());
    }

    #[test]
    fn config_roundtrip_and_hud_position_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".fd-claude-guard").join("config.json");

        assert_eq!(load_config(&path), AppConfig::default());

        let mut cfg = AppConfig::default();
        cfg.apply_patch(AppConfigPatch {
            theme: Some("light".into()),
            show_hud: Some(false),
            notify_enabled: Some(false),
            wake_preblock_guard: Some(false),
            calm_24h: Some(true),
            hud_edge_docked: Some(true),
            hud_position: Some(WindowPos { x: 1480, y: 64 }),
            bound_primary_org_id: Some("078cfdb1".into()),
            ..Default::default()
        });
        save_config(&path, &cfg).unwrap();

        let reloaded = load_config(&path);
        assert_eq!(reloaded, cfg);
        assert!(!reloaded.show_hud);
        assert!(!reloaded.notify_enabled);
        assert!(!reloaded.wake_preblock_guard);
        assert!(reloaded.hud_edge_docked);
        assert_eq!(reloaded.hud_position, Some(WindowPos { x: 1480, y: 64 }));
        assert_eq!(reloaded.bound_primary_org_id.as_deref(), Some("078cfdb1"));
    }

    #[test]
    fn disabling_boot_start_cascades_to_boot_hud_only() {
        let mut cfg = AppConfig::default();
        cfg.apply_patch(AppConfigPatch {
            boot_start: Some(false),
            ..Default::default()
        });
        assert!(!cfg.boot_start);
        assert!(!cfg.boot_hud_only);

        cfg.apply_patch(AppConfigPatch {
            boot_hud_only: Some(true),
            ..Default::default()
        });
        assert!(!cfg.boot_hud_only);
    }

    #[test]
    fn autostart_hud_only_detection() {
        let cfg = AppConfig::default();
        assert!(should_start_hud_only(
            &["fd-claude-guard.exe".into(), "--autostart".into()],
            &cfg
        ));
        assert!(!should_start_hud_only(&["fd-claude-guard.exe".into()], &cfg));

        let mut cfg_show_main = AppConfig::default();
        cfg_show_main.boot_hud_only = false;
        assert!(!should_start_hud_only(
            &["fd-claude-guard.exe".into(), "--autostart".into()],
            &cfg_show_main
        ));
    }
}
