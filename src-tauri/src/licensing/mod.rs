use crate::state::{GuardSnapshot, PreflightReport};
use serde::{Deserialize, Serialize};

/// 未激活免费体验态仅允许公开展示真实标题与状态的 3 项基础连通性探针；
/// 其余核心防封诊断（策略组/Fake-IP/出口合规/环境变量/系统定位/封号污染/单号锁/遥测/建议优化）
/// 在未激活态必须隐藏项目名称与实测状态，输入激活密钥后才开放实测与展示。
pub const FREE_PREVIEW_CHECK_IDS: &[&str] = &["node_proxy", "node_tun", "sys_ipv6"];

pub fn is_free_preview_check(id: &str) -> bool {
    FREE_PREVIEW_CHECK_IDS.contains(&id)
}

/// 对前端暴露的授权状态 DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseStatus {
    pub commercial_feature_enabled: bool,
    pub licensed: bool,
    pub activated_at: Option<String>,
    pub batch_id: Option<String>,
    pub install_id_short: Option<String>,
    pub machine_fp_short: Option<String>,
    pub api_endpoint: Option<String>,
}

/// 激活核销返回结果
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateLicenseResult {
    pub licensed: bool,
    pub activated_at: String,
    pub batch_id: String,
    pub message: String,
}

// ============================================================================
// 模式 A：商业授权模式（默认开启 commercial-license feature）
// ============================================================================
#[cfg(feature = "commercial-license")]
mod commercial {
    use super::*;
    use crate::logger;
    use crate::state::{CheckStatus, HudEventLine};
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{OnceLock, RwLock};
    use std::time::Duration;

    mod assets {
        include!(concat!(env!("OUT_DIR"), "/encrypted_commercial_assets.rs"));
    }

    const APP_DATA_SUBDIR: &str = "FDClaudeGuard";
    const INSTALL_ID_FILE: &str = "inst.id";
    const VAULT_FILE: &str = "vault.dat";

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OfflineCertPayload {
        pub v: u32,
        pub key_hash: String,
        pub batch_id: String,
        pub machine_fp_hash: String,
        pub install_id_hash: String,
        pub issued_at: String,
        #[serde(default)]
        pub app_version: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct VaultRecord {
        cert_b64: String,
        payload_key_hex: String,
        install_instance_id: String,
    }

    #[derive(Debug, Default, Clone)]
    struct UnlockedAssets {
        activated_at: String,
        batch_id: String,
        override_script: String,
        guides: HashMap<String, String>,
    }

    pub struct LicenseManager {
        data_dir: PathBuf,
        install_id: String,
        machine_fp_hash: String,
        api_endpoint: String,
        unlocked: RwLock<Option<UnlockedAssets>>,
    }

    static GLOBAL_MANAGER: OnceLock<LicenseManager> = OnceLock::new();

    pub fn global() -> &'static LicenseManager {
        GLOBAL_MANAGER.get_or_init(LicenseManager::load_or_init)
    }

    fn reconstruct_verifying_key() -> Result<VerifyingKey, String> {
        let mut raw = [0u8; 32];
        let parts = [
            assets::PUB_KEY_P0,
            assets::PUB_KEY_P1,
            assets::PUB_KEY_P2,
            assets::PUB_KEY_P3,
        ];
        for (chunk_idx, chunk) in parts.iter().enumerate() {
            for (i, b) in chunk.iter().enumerate() {
                let idx = chunk_idx * 8 + i;
                raw[idx] = b ^ assets::PUB_KEY_MASK[idx];
            }
        }
        VerifyingKey::from_bytes(&raw).map_err(|e| format!("内置 Ed25519 公钥无效: {e}"))
    }

    fn resolve_api_endpoint() -> String {
        if let Ok(env_url) = std::env::var("FD_LICENSE_API_URL") {
            let trimmed = env_url.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
        let decoded: Vec<u8> = assets::API_URL_XORED
            .iter()
            .map(|b| b ^ assets::API_URL_XOR_MASK)
            .collect();
        String::from_utf8(decoded)
            .unwrap_or_else(|_| "https://license.fdclaudeguard.workers.dev/api/v1/activate".into())
    }

    pub fn default_data_dir() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(APP_DATA_SUBDIR)
    }

    pub fn sha256_hex(input: &str) -> String {
        let digest = Sha256::digest(input.as_bytes());
        hex::encode(digest)
    }

    /// 读取或首次生成 256-bit 安装实例 ID（原子写盘，卸载时由 NSIS hooks.nsh 同步销毁）
    pub fn load_or_create_install_id(dir: &Path) -> String {
        let path = dir.join(INSTALL_ID_FILE);
        if let Ok(raw) = fs::read_to_string(&path) {
            let trimmed = raw.trim();
            if trimmed.len() >= 16 {
                return trimmed.to_string();
            }
        }
        if let Err(e) = fs::create_dir_all(dir) {
            logger::log_warn("license", format!("创建授权数据目录失败: {e}"));
        }
        let new_id = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
        let tmp_path = path.with_extension("id.tmp");
        if let Err(e) = fs::write(&tmp_path, &new_id).and_then(|_| fs::rename(&tmp_path, &path)) {
            let _ = fs::remove_file(&tmp_path);
            if let Err(e2) = fs::write(&path, &new_id) {
                logger::log_warn("license", format!("持久化 inst.id 失败: {e} / {e2}"));
            }
        }
        new_id
    }

    /// 计算脱敏硬件指纹哈希（MachineGuid + 计算机名 SHA-256，绝不外泄原始标识符）
    pub fn compute_machine_fp_hash() -> String {
        #[cfg(windows)]
        let machine_guid = {
            use winreg::enums::HKEY_LOCAL_MACHINE;
            use winreg::RegKey;
            RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
                .ok()
                .and_then(|k| k.get_value::<String, _>("MachineGuid").ok())
                .unwrap_or_else(|| "unknown-win-guid".to_string())
        };
        #[cfg(not(windows))]
        let machine_guid = "non-windows-host".to_string();

        let host = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown-host".to_string());
        sha256_hex(&format!("fd-claude-guard-fp:v1:{machine_guid}:{host}"))
    }

    /// Windows 原生 DPAPI 加密（绑定当前 Windows 登录用户，跨机器复制 vault.dat 直接失效）
    #[cfg(windows)]
    pub fn dpapi_protect(plain: &[u8]) -> Result<Vec<u8>, String> {
        use std::ptr::{null, null_mut};
        use windows_sys::Win32::Security::Cryptography::{
            CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        };
        use windows_sys::Win32::Foundation::LocalFree;

        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                null(),
                null(),
                null_mut(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 || out_blob.pbData.is_null() {
            return Err("Windows DPAPI CryptProtectData 加密失败".to_string());
        }
        let encrypted =
            unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) }
                .to_vec();
        unsafe {
            LocalFree(out_blob.pbData as _);
        }
        Ok(encrypted)
    }

    /// Windows 原生 DPAPI 解密
    #[cfg(windows)]
    pub fn dpapi_unprotect(cipher: &[u8]) -> Result<Vec<u8>, String> {
        use std::ptr::{null, null_mut};
        use windows_sys::Win32::Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        };
        use windows_sys::Win32::Foundation::LocalFree;

        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: cipher.len() as u32,
            pbData: cipher.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                null_mut(),
                null(),
                null_mut(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 || out_blob.pbData.is_null() {
            return Err("Windows DPAPI CryptUnprotectData 解密失败（凭证损坏或非本机用户）".into());
        }
        let plain =
            unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize) }
                .to_vec();
        unsafe {
            LocalFree(out_blob.pbData as _);
        }
        Ok(plain)
    }

    #[cfg(not(windows))]
    pub fn dpapi_protect(plain: &[u8]) -> Result<Vec<u8>, String> {
        Ok(plain.to_vec())
    }

    #[cfg(not(windows))]
    pub fn dpapi_unprotect(cipher: &[u8]) -> Result<Vec<u8>, String> {
        Ok(cipher.to_vec())
    }

    /// Ed25519 离线验签并校验本机指纹与安装实例绑定
    pub fn verify_offline_cert(
        verifying_key: &VerifyingKey,
        cert_b64: &str,
        expected_machine_fp_hash: &str,
        expected_install_id: &str,
    ) -> Result<OfflineCertPayload, String> {
        let (payload_b64, sig_b64) = cert_b64
            .trim()
            .split_once('.')
            .ok_or_else(|| "离线授权证书格式非法".to_string())?;
        let payload_bytes = B64
            .decode(payload_b64)
            .map_err(|_| "离线授权证书载荷解码失败".to_string())?;
        let sig_bytes = B64
            .decode(sig_b64)
            .map_err(|_| "离线授权证书签名解码失败".to_string())?;
        if sig_bytes.len() != 64 {
            return Err("Ed25519 签名长度异常".to_string());
        }
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "Ed25519 签名转换失败".to_string())?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify(&payload_bytes, &sig)
            .map_err(|_| "Ed25519 离线签名验证未通过".to_string())?;

        let payload: OfflineCertPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| format!("解析离线证书载荷失败: {e}"))?;

        if payload.machine_fp_hash != expected_machine_fp_hash {
            return Err("离线授权证书与当前设备硬件指纹不匹配".to_string());
        }
        let expected_install_hash = sha256_hex(expected_install_id);
        if payload.install_id_hash != expected_install_hash {
            return Err("离线授权证书与当前安装实例 inst.id 不匹配（疑似已卸载或迁移）".into());
        }
        Ok(payload)
    }

    /// 使用核销下发的 32 字节 payload_key 解密编译期 AES-256-GCM 加密资产（零明文驱动）
    pub fn decrypt_commercial_assets(
        payload_key_hex: &str,
    ) -> Result<(String, HashMap<String, String>), String> {
        let key_bytes = hex::decode(payload_key_hex.trim())
            .map_err(|_| "解密密钥 payload_key_hex 格式非法".to_string())?;
        if key_bytes.len() != 32 {
            return Err("AES-256-GCM 密钥长度必须为 32 字节".to_string());
        }
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|_| "初始化 AES-256-GCM 解密器失败".to_string())?;

        let script_plain = cipher
            .decrypt(
                Nonce::from_slice(&assets::OVERRIDE_SCRIPT_NONCE),
                assets::OVERRIDE_SCRIPT_CIPHERTEXT,
            )
            .map_err(|_| "核心覆写脚本密文解密校验失败（密钥不匹配）".to_string())?;
        let override_script = String::from_utf8(script_plain)
            .map_err(|_| "解密后的覆写脚本非 UTF-8".to_string())?;

        let guides_plain = cipher
            .decrypt(
                Nonce::from_slice(&assets::GUIDES_NONCE),
                assets::GUIDES_CIPHERTEXT,
            )
            .map_err(|_| "核心指南密文解密校验失败（密钥不匹配）".to_string())?;
        let guides: HashMap<String, String> = serde_json::from_slice(&guides_plain)
            .map_err(|e| format!("解析解密后的指南失败: {e}"))?;

        Ok((override_script, guides))
    }

    impl LicenseManager {
        pub fn load_or_init() -> Self {
            Self::load_from_dir(default_data_dir(), resolve_api_endpoint())
        }

        pub fn load_from_dir(data_dir: PathBuf, api_endpoint: String) -> Self {
            let install_id = load_or_create_install_id(&data_dir);
            let machine_fp_hash = compute_machine_fp_hash();
            let mgr = Self {
                data_dir,
                install_id,
                machine_fp_hash,
                api_endpoint,
                unlocked: RwLock::new(None),
            };
            if let Err(reason) = mgr.try_load_vault_offline() {
                logger::log_info(
                    "license",
                    format!("启动离线验签未激活（进入免费体检体验态）: {reason}"),
                );
            }
            mgr
        }

        fn try_load_vault_offline(&self) -> Result<(), String> {
            let vault_path = self.data_dir.join(VAULT_FILE);
            if !vault_path.exists() {
                return Err("本地尚无授权金库 vault.dat".to_string());
            }
            let raw_cipher = fs::read(&vault_path)
                .map_err(|e| format!("读取授权金库失败: {e}"))?;
            let plain = dpapi_unprotect(&raw_cipher)?;
            let record: VaultRecord =
                serde_json::from_slice(&plain).map_err(|_| "解析授权金库结构失败".to_string())?;
            if record.install_instance_id != self.install_id {
                return Err("安装实例 ID 已变更，金库凭证失效".to_string());
            }
            let vk = reconstruct_verifying_key()?;
            let cert = verify_offline_cert(
                &vk,
                &record.cert_b64,
                &self.machine_fp_hash,
                &self.install_id,
            )?;
            let (override_script, guides) = decrypt_commercial_assets(&record.payload_key_hex)?;

            if let Ok(mut guard) = self.unlocked.write() {
                *guard = Some(UnlockedAssets {
                    activated_at: cert.issued_at.clone(),
                    batch_id: cert.batch_id.clone(),
                    override_script,
                    guides,
                });
            }
            logger::log_info(
                "license",
                format!(
                    "离线 Ed25519 验签 + AES-256-GCM 密文解锁成功 (batch={}, activated_at={})",
                    cert.batch_id, cert.issued_at
                ),
            );
            Ok(())
        }

        pub fn is_licensed(&self) -> bool {
            self.unlocked
                .read()
                .map(|g| g.is_some())
                .unwrap_or(false)
        }

        pub fn require_licensed(&self) -> Result<(), String> {
            if self.is_licensed() {
                Ok(())
            } else {
                Err("FD_ERR_LICENSE_REQUIRED: 请先输入一次性激活密钥解锁自动修复与守护功能".into())
            }
        }

        pub fn status(&self) -> LicenseStatus {
            let guard = self.unlocked.read().ok();
            let unlocked = guard.as_ref().and_then(|g| g.as_ref());
            LicenseStatus {
                commercial_feature_enabled: true,
                licensed: unlocked.is_some(),
                activated_at: unlocked.map(|u| u.activated_at.clone()),
                batch_id: unlocked.map(|u| u.batch_id.clone()),
                install_id_short: Some(self.install_id.chars().take(8).collect()),
                machine_fp_short: Some(self.machine_fp_hash.chars().take(10).collect()),
                api_endpoint: Some(self.api_endpoint.clone()),
            }
        }

        pub fn get_override_script(&self) -> Result<String, String> {
            let guard = self
                .unlocked
                .read()
                .map_err(|_| "读取授权状态锁失败".to_string())?;
            guard
                .as_ref()
                .map(|u| u.override_script.clone())
                .ok_or_else(|| "FD_ERR_LICENSE_REQUIRED: 未激活状态无法读取核心覆写脚本".into())
        }

        pub fn sanitize_preflight_report(&self, report: &mut PreflightReport) {
            let unlocked = self.unlocked.read().ok().and_then(|g| g.clone());
            match unlocked {
                None => {
                    // L1/L2 核心商业防线：
                    // 1) 未激活态全部检测项彻底剥离操作步骤明文 guide
                    // 2) 仅 3 项免费基础体验探针（node_proxy / node_tun / sys_ipv6）左右完整公开（标题、摘要、状态、evidence）
                    // 3) 其余核心防封项把左侧标题/类型与右侧状态、evidence 全部隐藏脱敏，防止未激活暴露检测内容与结果
                    let mut hidden_seq: usize = 0;
                    for item in &mut report.items {
                        item.guide.clear();
                        if !is_free_preview_check(&item.id) {
                            hidden_seq += 1;
                            item.title = format!("核心防封深度检测项 #{hidden_seq:02}");
                            item.mode = "激活后解锁".to_string();
                            item.status = CheckStatus::Warn;
                            item.summary = "输入激活密钥后解锁此项检测内容与实测状态".to_string();
                            item.evidence.clear();
                            item.fix_label = None;
                        }
                    }
                }
                Some(assets) => {
                    for item in &mut report.items {
                        if item.guide.trim().is_empty() {
                            if let Some(g) = assets.guides.get(&item.id) {
                                item.guide = g.clone();
                            }
                        }
                    }
                }
            }
        }

        pub fn sanitize_snapshot(&self, snapshot: &mut GuardSnapshot) {
            if self.is_licensed() {
                return;
            }
            snapshot.unread_log_anomalies = 0;
            snapshot.unread_log_critical = 0;
            snapshot.unread_log_warnings = 0;
            snapshot.active_flow_anomalies = 0;
            snapshot.live_flow_anomalies = 0;
            snapshot.node_drift_warn = false;
            snapshot.triggered_playbook_ids.clear();
            snapshot.exit_ip_masked = "激活后解锁出口检测".to_string();
            snapshot.status_label = "体验模式 · 待激活".to_string();
            snapshot.hud_events = vec![HudEventLine {
                message: "当前为未激活体验态，输入激活密钥后开启全量防封检测与自动修复".to_string(),
                time: "--:--".to_string(),
                level: "warn".to_string(),
                target_tab: "console".to_string(),
            }];
        }

        /// 将核销返回的 cert_b64 + payload_key_hex 校验、解密并经 DPAPI 写入金库
        pub fn install_verified_credential(
            &self,
            verifying_key: &VerifyingKey,
            cert_b64: &str,
            payload_key_hex: &str,
        ) -> Result<ActivateLicenseResult, String> {
            let cert = verify_offline_cert(
                verifying_key,
                cert_b64,
                &self.machine_fp_hash,
                &self.install_id,
            )?;
            let (override_script, guides) = decrypt_commercial_assets(payload_key_hex)?;

            let record = VaultRecord {
                cert_b64: cert_b64.to_string(),
                payload_key_hex: payload_key_hex.to_string(),
                install_instance_id: self.install_id.clone(),
            };
            let plain = serde_json::to_vec(&record)
                .map_err(|e| format!("序列化授权金库失败: {e}"))?;
            let cipher = dpapi_protect(&plain)?;
            fs::create_dir_all(&self.data_dir)
                .map_err(|e| format!("创建授权目录失败: {e}"))?;
            fs::write(self.data_dir.join(VAULT_FILE), &cipher)
                .map_err(|e| format!("写入加密金库 vault.dat 失败: {e}"))?;

            if let Ok(mut guard) = self.unlocked.write() {
                *guard = Some(UnlockedAssets {
                    activated_at: cert.issued_at.clone(),
                    batch_id: cert.batch_id.clone(),
                    override_script,
                    guides,
                });
            }

            logger::log_event(
                "INFO",
                "license",
                "license_activated",
                None,
                format!("一次性密钥核销成功并已写入 DPAPI 加密金库 (batch={})", cert.batch_id),
                Some(serde_json::json!({ "batchId": cert.batch_id })),
            );

            Ok(ActivateLicenseResult {
                licensed: true,
                activated_at: cert.issued_at,
                batch_id: cert.batch_id,
                message: "核销激活成功！解密密钥已加密存入本机 DPAPI 金库，后续永久离线可用。".into(),
            })
        }

        /// 调用 Cloudflare Workers + D1 一码一次原子核销接口
        pub async fn activate_online(&self, raw_key: &str) -> Result<ActivateLicenseResult, String> {
            let key = raw_key.trim().to_uppercase();
            if key.len() != 18 || !key.starts_with("FDG-") {
                return Err("激活密钥格式错误（应为 FDG-XXXX-XXXX-XXXX）".to_string());
            }

            let key_prefix: String = key.chars().take(8).collect();
            logger::log_info(
                "license",
                format!("开始在线核销密钥 ({key_prefix}-****-****) -> {}", self.api_endpoint),
            );

            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(12))
                .build()
                .map_err(|e| {
                    let msg = format!("初始化核销网络客户端失败: {e}");
                    logger::log_warn("license", &msg);
                    msg
                })?;

            let req_body = serde_json::json!({
                "license_key": key,
                "machine_fp_hash": self.machine_fp_hash,
                "install_instance_id": self.install_id,
                "app_version": env!("CARGO_PKG_VERSION"),
            });

            let resp = client
                .post(&self.api_endpoint)
                .json(&req_body)
                .send()
                .await
                .map_err(|e| {
                    let msg = format!("连接核销服务失败，请检查网络或代理状态: {e}");
                    logger::log_warn("license", &msg);
                    msg
                })?;

            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let val: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();

            if status == 409 {
                let msg = val
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("该一次性密钥不存在或已被核销作废，无法重复使用");
                logger::log_warn("license", format!("密钥核销被拒绝 (HTTP 409): {msg}"));
                return Err(msg.to_string());
            }
            if status < 200 || status >= 300 {
                let msg = val
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("核销服务返回异常，请稍后重试");
                let err = format!("核销失败 (HTTP {status}): {msg}");
                logger::log_warn("license", &err);
                return Err(err);
            }

            let cert_b64 = val
                .get("cert_b64")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    let msg = "核销响应缺少离线证书 cert_b64".to_string();
                    logger::log_warn("license", &msg);
                    msg
                })?;
            let payload_key_hex = val
                .get("payload_key_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    let msg = "核销响应缺少解密密钥 payload_key_hex".to_string();
                    logger::log_warn("license", &msg);
                    msg
                })?;

            let vk = reconstruct_verifying_key().map_err(|e| {
                logger::log_warn("license", &e);
                e
            })?;
            self.install_verified_credential(&vk, cert_b64, payload_key_hex)
                .map_err(|e| {
                    logger::log_warn("license", format!("本地验签/解密/入库失败: {e}"));
                    e
                })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ed25519_dalek::{Signer, SigningKey};
        use tempfile::tempdir;

        #[test]
        fn ed25519_offline_cert_sign_verify_and_tamper_rejection() {
            let signing_key = SigningKey::from_bytes(&[7u8; 32]);
            let verifying_key = signing_key.verifying_key();
            let fp = "abcdef1234567890abcdef1234567890";
            let inst_id = "11223344556677889900aabbccddeeff";

            let payload = OfflineCertPayload {
                v: 1,
                key_hash: sha256_hex("FDG-TEST-1234-ABCD"),
                batch_id: "B202611".into(),
                machine_fp_hash: fp.into(),
                install_id_hash: sha256_hex(inst_id),
                issued_at: "2026-11-24T00:00:00Z".into(),
                app_version: "0.1.0".into(),
            };
            let payload_bytes = serde_json::to_vec(&payload).unwrap();
            let sig = signing_key.sign(&payload_bytes);
            let cert_b64 = format!("{}.{}", B64.encode(&payload_bytes), B64.encode(sig.to_bytes()));

            let verified = verify_offline_cert(&verifying_key, &cert_b64, fp, inst_id).unwrap();
            assert_eq!(verified.batch_id, "B202611");

            // 不同硬件指纹应被拒绝
            assert!(verify_offline_cert(&verifying_key, &cert_b64, "other_fp_hash", inst_id).is_err());
            // 不同安装实例 inst.id（卸载重装）应被拒绝
            assert!(verify_offline_cert(&verifying_key, &cert_b64, fp, "new_inst_id_after_reinstall").is_err());
            // 篡改签名应被拒绝
            let bad_cert = format!("{}.{}", B64.encode(&payload_bytes), B64.encode([0u8; 64]));
            assert!(verify_offline_cert(&verifying_key, &bad_cert, fp, inst_id).is_err());
        }

        #[test]
        fn aes_256_gcm_asset_decryption_rejects_wrong_key() {
            let wrong_key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            assert!(decrypt_commercial_assets(wrong_key).is_err());
        }

        #[test]
        fn dpapi_vault_roundtrip_and_uninstall_destruction_loop() {
            let secret = b"fd-claude-guard-dpapi-vault-test-payload";
            let protected = dpapi_protect(secret).unwrap();
            #[cfg(windows)]
            assert_ne!(protected.as_slice(), secret);
            let plain = dpapi_unprotect(&protected).unwrap();
            assert_eq!(plain.as_slice(), secret);

            // 验证未激活时 sanitize_preflight_report 会彻底剥离 guide 明文
            let dir = tempdir().unwrap();
            let mgr = LicenseManager::load_from_dir(
                dir.path().to_path_buf(),
                "https://example.invalid/api/v1/activate".into(),
            );
            assert!(!mgr.is_licensed());
            assert!(mgr.require_licensed().is_err());
            let mut rep = crate::state::build_m1_preflight_report();
            assert!(rep.items.iter().any(|i| !i.guide.is_empty()));
            mgr.sanitize_preflight_report(&mut rep);
            assert!(rep.items.iter().all(|i| i.guide.is_empty()));
            // 未激活态仅 3 项基础体验探针保留真实标题与 evidence，其余核心项彻底隐藏标题、状态与 evidence 防止白嫖
            for item in &rep.items {
                if is_free_preview_check(&item.id) {
                    assert!(!item.evidence.is_empty(), "free preview item {} should keep evidence", item.id);
                    assert!(!item.title.starts_with("核心防封深度检测项"), "free preview item {} should keep title", item.id);
                } else {
                    assert!(
                        item.title.starts_with("核心防封深度检测项 #"),
                        "locked item {} must mask title, got: {}",
                        item.id,
                        item.title
                    );
                    assert!(item.evidence.is_empty(), "locked item {} must strip evidence", item.id);
                    assert!(item.fix_label.is_none());
                }
            }
        }

        #[tokio::test]
        #[ignore = "实机联调真实 Cloudflare Workers 在线核销接口（使用无效假码，不消耗真码）"]
        async fn live_online_activation_probe_rejects_dummy_key_with_409_message() {
            let dir = tempdir().unwrap();
            let ep = resolve_api_endpoint();
            println!("=== LIVE LICENSE ENDPOINT: {ep} ===");
            assert!(
                !ep.contains('<') && ep.starts_with("https://"),
                "embedded api endpoint must be real HTTPS URL: {ep}"
            );
            let mgr = LicenseManager::load_from_dir(dir.path().to_path_buf(), ep);
            let err = mgr
                .activate_online("FDG-0000-0000-0000")
                .await
                .expect_err("dummy key must be rejected");
            println!("=== LIVE LICENSE 409 RESPONSE: {err} ===");
            assert!(
                err.contains("不存在") || err.contains("作废") || err.contains("核销"),
                "unexpected error message: {err}"
            );
        }

        #[tokio::test]
        #[ignore = "真机完整商业授权全闭环实测（使用用户授权测试码 FDG-TEST-DEMO-0001）"]
        async fn live_real_key_full_lifecycle_activation_and_offline_reload() {
            let key = "FDG-TEST-DEMO-0001";
            let data_dir = default_data_dir();
            let ep = resolve_api_endpoint();
            let mgr = LicenseManager::load_from_dir(data_dir.clone(), ep.clone());
            // 1. 在线原子核销 + Ed25519 验签 + AES-256-GCM 解密 + DPAPI 写金库
            let res = mgr.activate_online(key).await.expect("real test key should activate cleanly");
            println!("=== [1] ACTIVATED OK: batch={} at={} msg={} ===", res.batch_id, res.activated_at, res.message);
            assert!(res.licensed);
            assert!(mgr.is_licensed());
            let script = mgr.get_override_script().expect("override script decrypted");
            assert!(script.contains("Claude-Fixed"), "decrypted script must contain Claude-Fixed");
            println!("=== [2] DECRYPTED SCRIPT LEN: {} bytes ===", script.len());

            // 2. 校验 DPAPI 密文落盘且不含明文 key
            let vault_bytes = fs::read(data_dir.join(VAULT_FILE)).expect("vault.dat written");
            assert!(!String::from_utf8_lossy(&vault_bytes).contains("payload_key_hex"));
            println!("=== [3] DPAPI VAULT.DAT WRITTEN: {} bytes (opaque cipher) ===", vault_bytes.len());

            // 3. 模拟完全重启 + 断网离线验签（传不可达端点确保纯离线！）
            let mgr_reloaded = LicenseManager::load_from_dir(
                data_dir.clone(),
                "https://offline.invalid/api/v1/activate".into(),
            );
            assert!(mgr_reloaded.is_licensed(), "offline reload must stay licensed");
            let mut rep = crate::state::build_m1_preflight_report();
            for i in &mut rep.items {
                i.guide.clear();
            }
            mgr_reloaded.sanitize_preflight_report(&mut rep);
            assert!(
                rep.items.iter().all(|i| !i.guide.is_empty()),
                "all 14 guides must be decrypted offline after reload"
            );
            println!("=== [4] OFFLINE RELOAD VERIFIED: {}/{} guides decrypted ===", rep.items.len(), rep.items.len());

            // 4. 防重放验证：再次提交同一枚一次性密钥必被 Cloudflare D1 返回 409 拒绝
            let replay_err = mgr
                .activate_online(key)
                .await
                .expect_err("reusing a consumed one-time key must fail with 409");
            println!("=== [5] REPLAY REJECTED AS EXPECTED: {replay_err} ===");
            assert!(replay_err.contains("不存在") || replay_err.contains("核销") || replay_err.contains("作废"));
        }
    }
}

// ============================================================================
// 模式 B：纯净开源版（关闭 commercial-license feature，零授权代码编译）
// ============================================================================
#[cfg(not(feature = "commercial-license"))]
mod opensource {
    use super::*;
    use std::sync::OnceLock;

    const OPEN_OVERRIDE_SCRIPT: &str =
        include_str!("../../../clash-scripts/claude-verge-override.js");

    pub struct LicenseManager;

    static GLOBAL_MANAGER: OnceLock<LicenseManager> = OnceLock::new();

    pub fn global() -> &'static LicenseManager {
        GLOBAL_MANAGER.get_or_init(|| LicenseManager)
    }

    impl LicenseManager {
        pub fn is_licensed(&self) -> bool {
            true
        }

        pub fn require_licensed(&self) -> Result<(), String> {
            Ok(())
        }

        pub fn status(&self) -> LicenseStatus {
            LicenseStatus {
                commercial_feature_enabled: false,
                licensed: true,
                activated_at: None,
                batch_id: Some("open-source".into()),
                install_id_short: None,
                machine_fp_short: None,
                api_endpoint: None,
            }
        }

        pub fn get_override_script(&self) -> Result<String, String> {
            Ok(OPEN_OVERRIDE_SCRIPT.to_string())
        }

        pub fn sanitize_preflight_report(&self, _report: &mut PreflightReport) {}

        pub fn sanitize_snapshot(&self, _snapshot: &mut GuardSnapshot) {}

        pub async fn activate_online(&self, _raw_key: &str) -> Result<ActivateLicenseResult, String> {
            Ok(ActivateLicenseResult {
                licensed: true,
                activated_at: chrono::Utc::now().to_rfc3339(),
                batch_id: "open-source".into(),
                message: "开源版本无需激活，全部功能默认开放。".into(),
            })
        }
    }
}

#[cfg(feature = "commercial-license")]
pub use commercial::global;
#[cfg(not(feature = "commercial-license"))]
pub use opensource::global;

pub fn is_licensed() -> bool {
    global().is_licensed()
}

pub fn require_licensed() -> Result<(), String> {
    global().require_licensed()
}

pub fn get_license_status() -> LicenseStatus {
    global().status()
}

pub fn get_override_script() -> Result<String, String> {
    global().get_override_script()
}

pub fn sanitize_preflight_for_license(report: &mut PreflightReport) {
    global().sanitize_preflight_report(report);
}

pub fn sanitize_snapshot_for_license(snapshot: &mut GuardSnapshot) {
    global().sanitize_snapshot(snapshot);
}

pub async fn activate_license_online(raw_key: &str) -> Result<ActivateLicenseResult, String> {
    global().activate_online(raw_key).await
}
