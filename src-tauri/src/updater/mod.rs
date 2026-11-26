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
use std::sync::atomic::{AtomicBool, Ordering};

static UPDATE_INSTALL_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

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

/// 检查 GitHub Releases 最新版本（优先代理、失败回退直连）
pub async fn check_for_app_update(
    app: &AppHandle,
    clash_port: Option<u16>,
) -> Result<AppUpdateInfo, String> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();
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
    match update_opt {
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
            Ok(AppUpdateInfo {
                current_version,
                available: true,
                latest_version: Some(latest.clone()),
                published_at,
                notes,
                via_proxy: used_proxy,
                message: format!("发现新版本 v{latest}（已启用 Ed25519 签名校验）。"),
            })
        }
        None => {
            logger::log_info(
                "updater",
                format!("当前已是最新版本 v{current_version}（via_proxy={used_proxy}）"),
            );
            Ok(AppUpdateInfo {
                current_version: current_version.clone(),
                available: false,
                latest_version: Some(current_version.clone()),
                published_at: None,
                notes: None,
                via_proxy: used_proxy,
                message: format!("当前已是最新版本 v{current_version}。"),
            })
        }
    }
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
}
