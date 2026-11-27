//! 客户端自动检查与一键签名更新模块（T-059）
//!
//! 职责与安全边界：
//! - 复用 `tauri-plugin-updater` 官方 Ed25519 公钥验签（Key ID `524DD4CBF003E3FD`）；
//! - 若本机 Clash Verge 在线，优先经本机动态混合代理端口访问 GitHub Releases，失败后自动回退直连；
//! - 严禁静默强制重启打断用户正在进行的 Claude 会话，始终由用户主动确认下载安装。

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::UpdaterExt;

use crate::logger;
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static UPDATE_INSTALL_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
/// 全局持久化自动检查节流周期（4 小时）：未满 4h 时自动检查直接复用本地持久化状态，不重复请求 GitHub
pub const UPDATE_CHECK_INTERVAL_MS: i64 = 4 * 3_600_000;
/// 启动后延迟首次静默自检时间（3 分钟）：避开启动首秒抢跑，确保 Clash 代理与 19 项探针已就绪
pub const UPDATE_STARTUP_DELAY_SECS: u64 = 180;
/// 休眠唤醒 / 代理恢复在线后延迟补偿自检时间（60 秒，仍严格受 4h 节流约束）
pub const UPDATE_WAKE_RECOVERY_DELAY_SECS: u64 = 60;
/// 手动点击「检查更新」防连点短时单飞保护（15 秒）
const UPDATE_CHECK_CACHE_TTL_SECS: u64 = 15;
static UPDATE_CHECK_SINGLEFLIGHT: OnceLock<tokio::sync::Mutex<Option<(Instant, AppUpdateInfo)>>> =
    OnceLock::new();

/// 持久化更新状态文件结构（`%LOCALAPPDATA%\FDClaudeGuard\update-state.json`，零敏感信息）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedUpdateState {
    pub version: u32,
    pub last_checked_at_ms: i64,
    pub checked_app_version: String,
    pub available: bool,
    pub latest_version: Option<String>,
    pub published_at: Option<String>,
    pub notes: Option<String>,
    pub via_proxy: bool,
    pub message: String,
}

/// 持久化更新状态路径：`%LOCALAPPDATA%\FDClaudeGuard\update-state.json`
pub fn default_update_state_path() -> PathBuf {
    dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("FDClaudeGuard")
        .join("update-state.json")
}

/// 轻量 SemVer 比较：判断 `latest` 是否严格高于 `current`
pub fn is_semver_newer(latest: &str, current: &str) -> bool {
    let parse = |s: &str| -> (u64, u64, u64) {
        let trimmed = s.trim().trim_start_matches('v').trim_start_matches('V');
        let core = trimmed.split(['-', '+']).next().unwrap_or(trimmed);
        let mut it = core.split('.');
        let a = it.next().and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
        let b = it.next().and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
        let c = it.next().and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
        (a, b, c)
    };
    parse(latest) > parse(current)
}

/// 读取本地持久化更新状态（损坏或缺失时优雅返回 `None`）
pub fn load_persisted_update_state(path: &Path) -> Option<PersistedUpdateState> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str::<PersistedUpdateState>(raw.trim_start_matches('\u{feff}')).ok()
}

/// 原子保存持久化更新状态（仅在成功完成线上检查后调用，断网/超时失败绝不刷新 4h 冷却）
pub fn save_persisted_update_state(
    path: &Path,
    info: &AppUpdateInfo,
    checked_at_ms: i64,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("创建更新状态目录失败: {e}"))?;
    }
    let state = PersistedUpdateState {
        version: 1,
        last_checked_at_ms: checked_at_ms,
        checked_app_version: info.current_version.clone(),
        available: info.available,
        latest_version: info.latest_version.clone(),
        published_at: info.published_at.clone(),
        notes: info.notes.clone(),
        via_proxy: info.via_proxy,
        message: info.message.clone(),
    };
    let body = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("序列化更新状态失败: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, &body).map_err(|e| format!("写入更新状态临时文件失败: {e}"))?;
    if fs::rename(&tmp, path).is_err() {
        fs::write(path, &body).map_err(|e| format!("保存更新状态文件失败: {e}"))?;
        let _ = fs::remove_file(&tmp);
    }
    Ok(())
}

/// 纯函数：评估本地持久化更新状态 → 返回 `(可供 UI 零网络秒显的缓存状态, 本次静默自检是否需要发网络请求)`
pub fn evaluate_persisted_update_state(
    persisted: Option<&PersistedUpdateState>,
    current_version: &str,
    now_ms: i64,
) -> (Option<AppUpdateInfo>, bool) {
    let Some(st) = persisted else {
        return (None, true);
    };

    // 时钟回拨保护：若上次检查时间晚于当前时间，视作过期并触发重检
    if st.last_checked_at_ms > now_ms {
        return (None, true);
    }

    // 应用已完成升级（版本号变化）：旧缓存若指向已安装/更低版本则自动失效，不再残留假“发现新版本”
    let still_available = st.available
        && st
            .latest_version
            .as_deref()
            .map(|lv| is_semver_newer(lv, current_version))
            .unwrap_or(false);
    let version_changed = st.checked_app_version.trim() != current_version.trim();
    if version_changed && !still_available {
        return (
            Some(AppUpdateInfo {
                current_version: current_version.to_string(),
                available: false,
                latest_version: Some(current_version.to_string()),
                published_at: None,
                notes: None,
                via_proxy: st.via_proxy,
                message: format!("当前已是最新版本 v{current_version}。"),
            }),
            true,
        );
    }

    let elapsed_ms = now_ms.saturating_sub(st.last_checked_at_ms);
    let need_network = version_changed || elapsed_ms >= UPDATE_CHECK_INTERVAL_MS;
    let info = AppUpdateInfo {
        current_version: current_version.to_string(),
        available: still_available,
        latest_version: if still_available {
            st.latest_version.clone()
        } else {
            Some(current_version.to_string())
        },
        published_at: if still_available {
            st.published_at.clone()
        } else {
            None
        },
        notes: if still_available {
            st.notes.clone()
        } else {
            None
        },
        via_proxy: st.via_proxy,
        message: if still_available {
            st.message.clone()
        } else {
            format!("当前已是最新版本 v{current_version}。")
        },
    };
    (Some(info), need_network)
}

/// 零网络秒读本地持久化更新状态（供前端启动 0s 恢复顶栏微标，不发任何网络请求）
pub fn get_cached_update_info_for_current() -> Option<AppUpdateInfo> {
    let current_version = env!("CARGO_PKG_VERSION");
    let path = default_update_state_path();
    let persisted = load_persisted_update_state(&path);
    let (info, _) = evaluate_persisted_update_state(
        persisted.as_ref(),
        current_version,
        Utc::now().timestamp_millis(),
    );
    info
}

struct UpdateInstallGuard;
impl Drop for UpdateInstallGuard {
    fn drop(&mut self) {
        UPDATE_INSTALL_IN_FLIGHT.store(false, Ordering::SeqCst);
    }
}

/// 更新包下载进度事件载荷（`guard://update-progress`）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateProgressEvent {
    pub stage: String, // "downloading" | "verifying" | "installing"
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub percent: Option<u8>,
}

/// 自动更新检测结果 DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppUpdateInfo {
    pub current_version: String,
    pub available: bool,
    pub latest_version: Option<String>,
    pub published_at: Option<String>,
    pub notes: Option<String>,
    pub via_proxy: bool,
    pub message: String,
}

/// 清洗并裁剪 Release Notes，避免过长 Markdown 撑破前端更新卡片
pub fn sanitize_release_notes(raw: Option<&str>) -> Option<String> {
    let text = raw?.trim();
    if text.is_empty() {
        return None;
    }
    let normalized = text.replace("\r\n", "\n");
    let max_chars = 600;
    if normalized.chars().count() > max_chars {
        let head: String = normalized.chars().take(max_chars).collect();
        Some(format!("{head}..."))
    } else {
        Some(normalized)
    }
}

/// 构造可选代理 URL（仅允许本机回环代理端口）
pub fn build_local_proxy_url(clash_port: Option<u16>) -> Option<tauri::Url> {
    let port = clash_port.filter(|&p| p > 0)?;
    tauri::Url::parse(&format!("http://127.0.0.1:{port}")).ok()
}

/// 纯函数：判断缓存的自动更新检查结果是否仍在单飞去重 TTL 窗口内
pub fn should_reuse_cached_update(checked_at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(checked_at) < Duration::from_secs(UPDATE_CHECK_CACHE_TTL_SECS)
}

/// 检查 GitHub Releases 最新版本（优先代理、失败回退直连；静默模式严格遵守 4h 持久化节流，手动模式强制穿透刷新）
pub async fn check_for_app_update(
    app: &AppHandle,
    clash_port: Option<u16>,
    force: bool,
) -> Result<AppUpdateInfo, String> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
    let state_path = default_update_state_path();
    let lock = UPDATE_CHECK_SINGLEFLIGHT.get_or_init(|| tokio::sync::Mutex::new(None));
    let mut cache_guard = lock.lock().await;
    let now_inst = Instant::now();
    let now_ms = Utc::now().timestamp_millis();

    // 1. 静默模式优先命中 4 小时持久化节流缓存（未满 4h 直接复用本地状态，零网络请求、不刷日志）
    if !force {
        let persisted = load_persisted_update_state(&state_path);
        let (cached_opt, need_network) =
            evaluate_persisted_update_state(persisted.as_ref(), &current_version, now_ms);
        if !need_network {
            if let Some(cached) = cached_opt {
                return Ok(cached);
            }
        }
    } else if let Some((checked_at, cached)) = cache_guard.as_ref() {
        // 2. 手动点击模式穿透 4h 缓存，但保留 15s 并发/连点防抖保护
        if should_reuse_cached_update(*checked_at, now_inst) {
            return Ok(cached.clone());
        }
    }

    let proxy_url = build_local_proxy_url(clash_port);

    // 优先走本机 Clash 代理检测；若代理超时或失败，自动回退直连再尝试一次
    let (check_res, used_proxy) = if let Some(ref url) = proxy_url {
        let builder = app
            .updater_builder()
            .proxy(url.clone())
            .timeout(std::time::Duration::from_secs(12));
        match builder.build() {
            Ok(updater) => match updater.check().await {
                Ok(opt) => (Ok(opt), true),
                Err(proxy_err) => {
                    logger::log_warn(
                        "updater",
                        format!("经本机代理检查更新失败（{proxy_err}），自动回退直连重试"),
                    );
                    let direct_updater = app
                        .updater_builder()
                        .timeout(std::time::Duration::from_secs(12))
                        .build()
                        .map_err(|e| format!("初始化直连更新器失败：{e}"))?;
                    (direct_updater.check().await.map_err(|e| e.to_string()), false)
                }
            },
            Err(e) => {
                logger::log_warn("updater", format!("构建代理更新器失败：{e}，回退直连"));
                let direct_updater = app
                    .updater_builder()
                    .timeout(std::time::Duration::from_secs(12))
                    .build()
                    .map_err(|err| format!("初始化更新器失败：{err}"))?;
                (direct_updater.check().await.map_err(|err| err.to_string()), false)
            }
        }
    } else {
        let direct_updater = app
            .updater_builder()
            .timeout(std::time::Duration::from_secs(12))
            .build()
            .map_err(|e| format!("初始化更新器失败：{e}"))?;
        (direct_updater.check().await.map_err(|e| e.to_string()), false)
    };

    let update_opt = check_res.map_err(|e| format!("检查 GitHub Releases 更新失败：{e}"))?;
    let info = match update_opt {
        Some(update) => {
            let latest = update.version.clone();
            let published_at = update.date.map(|d| d.to_string());
            let notes = sanitize_release_notes(update.body.as_deref());
            logger::log_info(
                "updater",
                format!(
                    "检测到新版本 v{latest}（当前 v{current_version}，via_proxy={used_proxy}）"
                ),
            );
            AppUpdateInfo {
                current_version,
                available: true,
                latest_version: Some(latest.clone()),
                published_at,
                notes,
                via_proxy: used_proxy,
                message: format!("发现新版本 v{latest}（已启用 Ed25519 签名校验）。"),
            }
        }
        None => {
            logger::log_info(
                "updater",
                format!("当前已是最新版本 v{current_version}（via_proxy={used_proxy}）"),
            );
            AppUpdateInfo {
                current_version: current_version.clone(),
                available: false,
                latest_version: Some(current_version.clone()),
                published_at: None,
                notes: None,
                via_proxy: used_proxy,
                message: format!("当前已是最新版本 v{current_version}。"),
            }
        }
    };
    *cache_guard = Some((Instant::now(), info.clone()));
    let _ = save_persisted_update_state(&state_path, &info, Utc::now().timestamp_millis());
    let _ = app.emit("guard://update-available", info.clone());
    Ok(info)
}

/// 下载校验签名并安装更新（优先本机 Clash 代理，拉取或下载失败自动回退直连；含并发重入保护与 300s 下载超时）
pub async fn download_and_install_app_update(
    app: &AppHandle,
    clash_port: Option<u16>,
) -> Result<String, String> {
    if UPDATE_INSTALL_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("正在下载或安装更新包，请勿重复点击".into());
    }
    let _in_flight_guard = UpdateInstallGuard;

    let proxy_url = build_local_proxy_url(clash_port);
    let build_direct = || {
        app.updater_builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| format!("初始化直连更新器失败：{e}"))
    };

    let (update_opt, used_proxy) = if let Some(url) = proxy_url {
        match app
            .updater_builder()
            .proxy(url)
            .timeout(std::time::Duration::from_secs(300))
            .build()
        {
            Ok(proxy_updater) => match proxy_updater.check().await {
                Ok(opt) => (opt, true),
                Err(proxy_err) => {
                    logger::log_warn(
                        "updater",
                        format!("经本机代理拉取更新包元数据失败（{proxy_err}），自动回退直连重试"),
                    );
                    let direct_updater = build_direct()?;
                    let opt = direct_updater
                        .check()
                        .await
                        .map_err(|e| format!("获取更新包元数据失败：{e}"))?;
                    (opt, false)
                }
            },
            Err(e) => {
                logger::log_warn("updater", format!("构建代理更新器失败：{e}，回退直连"));
                let direct_updater = build_direct()?;
                let opt = direct_updater
                    .check()
                    .await
                    .map_err(|err| format!("获取更新包元数据失败：{err}"))?;
                (opt, false)
            }
        }
    } else {
        let direct_updater = build_direct()?;
        let opt = direct_updater
            .check()
            .await
            .map_err(|e| format!("获取更新包元数据失败：{e}"))?;
        (opt, false)
    };

    let Some(update) = update_opt else {
        return Ok(format!(
            "当前已是最新版本 v{}，无需更新。",
            env!("CARGO_PKG_VERSION")
        ));
    };

    let target_ver = update.version.clone();
    logger::log_info(
        "updater",
        format!("开始下载并校验签名更新包 v{target_ver}（via_proxy={used_proxy}）"),
    );

    let emit_progress_cb = |app_clone: AppHandle| {
        let downloaded = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let last_emitted_pct = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(255));
        let last_emitted_bytes = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        move |chunk_len: usize, content_len: Option<u64>| {
            let cur = downloaded.fetch_add(chunk_len as u64, std::sync::atomic::Ordering::Relaxed)
                + chunk_len as u64;
            let pct = content_len.filter(|&t| t > 0).map(|t| {
                ((cur.saturating_mul(100)) / t).min(100) as u8
            });
            let prev_pct = last_emitted_pct.load(std::sync::atomic::Ordering::Relaxed);
            let prev_bytes = last_emitted_bytes.load(std::sync::atomic::Ordering::Relaxed);
            let should_emit = match pct {
                Some(p) => prev_pct == 255 || p >= 100 || p.saturating_sub(prev_pct) >= 3,
                None => cur.saturating_sub(prev_bytes) >= 128 * 1024,
            };
            if should_emit {
                if let Some(p) = pct {
                    last_emitted_pct.store(p, std::sync::atomic::Ordering::Relaxed);
                }
                last_emitted_bytes.store(cur, std::sync::atomic::Ordering::Relaxed);
                let _ = app_clone.emit(
                    "guard://update-progress",
                    AppUpdateProgressEvent {
                        stage: "downloading".into(),
                        downloaded_bytes: cur,
                        total_bytes: content_len,
                        percent: pct,
                    },
                );
            }
        }
    };

    let app_for_finish = app.clone();
    let install_res = update
        .download_and_install(emit_progress_cb(app.clone()), move || {
            let _ = app_for_finish.emit(
                "guard://update-progress",
                AppUpdateProgressEvent {
                    stage: "verifying".into(),
                    downloaded_bytes: 0,
                    total_bytes: None,
                    percent: Some(100),
                },
            );
            logger::log_info("updater", "更新包 Ed25519 签名校验通过，正在准备安装");
        })
        .await;

    if let Err(first_err) = install_res {
        if used_proxy {
            logger::log_warn(
                "updater",
                format!("经本机代理下载更新包失败（{first_err}），自动回退直连重试"),
            );
            let direct_updater = build_direct()?;
            let Some(direct_update) = direct_updater
                .check()
                .await
                .map_err(|e| format!("直连重试获取更新元数据失败：{e}"))?
            else {
                return Ok(format!(
                    "当前已是最新版本 v{}，无需更新。",
                    env!("CARGO_PKG_VERSION")
                ));
            };
            let app_for_direct_finish = app.clone();
            direct_update
                .download_and_install(emit_progress_cb(app.clone()), move || {
                    let _ = app_for_direct_finish.emit(
                        "guard://update-progress",
                        AppUpdateProgressEvent {
                            stage: "verifying".into(),
                            downloaded_bytes: 0,
                            total_bytes: None,
                            percent: Some(100),
                        },
                    );
                    logger::log_info(
                        "updater",
                        "直连回退更新包 Ed25519 签名校验通过，正在准备安装",
                    );
                })
                .await
                .map_err(|e| format!("下载或安装更新包失败（请检查网络与签名）：{e}"))?;
        } else {
            return Err(format!(
                "下载或安装更新包失败（请检查网络与签名）：{first_err}"
            ));
        }
    }

    logger::log_info(
        "updater",
        format!("更新包 v{target_ver} 签名校验通过并已交由安装器执行覆盖升级"),
    );
    // Windows NSIS 目标由 tauri-plugin-updater 拉起新安装器覆盖安装并重启，绝不可在 400ms 后抢拉旧版 handle.restart() 导致文件锁冲突
    #[cfg(not(windows))]
    {
        let handle = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            handle.restart();
        });
    }

    Ok(format!("已下载并校验 v{target_ver} 更新包，安装程序正在覆盖升级..."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_release_notes_trims_and_truncates_safely() {
        assert_eq!(sanitize_release_notes(None), None);
        assert_eq!(sanitize_release_notes(Some("   \r\n  ")), None);
        assert_eq!(
            sanitize_release_notes(Some("  v0.3.0 更新说明\r\n- 新增账户审计  ")),
            Some("v0.3.0 更新说明\n- 新增账户审计".to_string())
        );

        let long_text = "测".repeat(700);
        let out = sanitize_release_notes(Some(&long_text)).expect("应返回截断文本");
        assert!(out.ends_with("..."));
        assert!(out.chars().count() <= 603);
    }

    #[test]
    fn build_local_proxy_url_validates_port() {
        assert!(build_local_proxy_url(None).is_none());
        assert!(build_local_proxy_url(Some(0)).is_none());
        let url = build_local_proxy_url(Some(7897)).expect("7897 应生成有效代理 URL");
        assert_eq!(url.as_str(), "http://127.0.0.1:7897/");
    }

    #[test]
    fn tauri_conf_contains_valid_updater_pubkey_and_endpoint() {
        let conf_str = include_str!("../../tauri.conf.json");
        let conf: serde_json::Value =
            serde_json::from_str(conf_str).expect("tauri.conf.json 必须为合法 JSON");
        assert_eq!(
            conf.pointer("/bundle/createUpdaterArtifacts")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        let pubkey = conf
            .pointer("/plugins/updater/pubkey")
            .and_then(|v| v.as_str())
            .expect("必须配置 updater pubkey");
        assert!(
            pubkey.starts_with("dW50cnVzdGVkIGNvbW1lbnQ6"),
            "pubkey 应为合法 minisign 公钥 base64"
        );
        let endpoints = conf
            .pointer("/plugins/updater/endpoints")
            .and_then(|v| v.as_array())
            .expect("必须配置 updater endpoints");
        assert!(
            endpoints.iter().any(|e| {
                e.as_str()
                    == Some("https://github.com/CaesarLastKing/FD-ClaudeGuard/releases/latest/download/latest.json")
            }),
            "updater endpoint 必须指向官方 GitHub Releases latest.json"
        );
    }

    #[test]
    fn v037_b3_update_check_cache_ttl_dedup() {
        let t0 = Instant::now();
        // 1.5s / 14s 内并发重复检查必须命中防抖缓存
        assert!(should_reuse_cached_update(t0, t0 + Duration::from_millis(1500)));
        assert!(should_reuse_cached_update(t0, t0 + Duration::from_secs(14)));
        // 超过 15s 防抖窗口后必须允许重新检查
        assert!(!should_reuse_cached_update(t0, t0 + Duration::from_secs(15)));
        assert!(!should_reuse_cached_update(t0, t0 + Duration::from_secs(60)));
    }

    #[test]
    fn v038_persisted_update_state_throttles_4h_handles_upgrade_clock_rollback_and_corrupt_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("update-state.json");
        let t0: i64 = 1_795_800_000_000;

        // 1. 损坏 JSON 优雅降级，要求重检不 panic
        fs::write(&path, "{ corrupt json").expect("write bad");
        assert!(load_persisted_update_state(&path).is_none());
        let (cached, need) = evaluate_persisted_update_state(None, "0.3.7", t0);
        assert!(cached.is_none());
        assert!(need);

        // 2. 保存发现新版 0.3.8 状态：2 小时内免网络请求且秒显新版微标
        let found = AppUpdateInfo {
            current_version: "0.3.7".into(),
            available: true,
            latest_version: Some("0.3.8".into()),
            published_at: None,
            notes: Some("智能更新调度".into()),
            via_proxy: true,
            message: "发现新版本 v0.3.8".into(),
        };
        save_persisted_update_state(&path, &found, t0).expect("save");
        let loaded = load_persisted_update_state(&path).expect("load");

        let (c_2h, need_2h) = evaluate_persisted_update_state(Some(&loaded), "0.3.7", t0 + 2 * 3_600_000);
        assert!(!need_2h, "2h 未满 4h 节流周期不应发网络请求");
        assert_eq!(c_2h.as_ref().and_then(|x| x.latest_version.as_deref()), Some("0.3.8"));
        assert!(c_2h.as_ref().map(|x| x.available).unwrap_or(false));

        // 3. 满 4 小时后仍先返回旧缓存秒显，同时标记需要后台刷新
        let (c_5h, need_5h) = evaluate_persisted_update_state(Some(&loaded), "0.3.7", t0 + 5 * 3_600_000);
        assert!(need_5h, "超 4h 应触发后台自检");
        assert!(c_5h.as_ref().map(|x| x.available).unwrap_or(false));

        // 4. 应用已升级至 0.3.8 后，旧缓存 available 自动失效不残留假红点
        let (c_upg, need_upg) = evaluate_persisted_update_state(Some(&loaded), "0.3.8", t0 + 60_000);
        assert!(need_upg);
        assert!(!c_upg.as_ref().map(|x| x.available).unwrap_or(true));

        // 5. 系统时钟回拨保护：last_checked_at_ms > now 时强制失效重检
        let (c_back, need_back) = evaluate_persisted_update_state(Some(&loaded), "0.3.7", t0 - 60_000);
        assert!(c_back.is_none());
        assert!(need_back);
    }
}
