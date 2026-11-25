use std::env;
use std::fs;
use std::path::Path;

fn main() {
    #[cfg(windows)]
    {
        // T-034：为正式桌面主程序嵌入管理员 UAC 清单（requireAdministrator），确保 Defender 防火墙熔断规则 100% 可写（fw=true）
        // 仅在 Release 发行构建中注入，避免日常 cargo test 单元测试二进制触发 UAC 弹窗
        if env::var("PROFILE").as_deref() == Ok("release") {
            let windows = tauri_build::WindowsAttributes::new().app_manifest(
                r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
</assembly>
"#,
            );
            tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
                .expect("failed to run tauri-build with admin manifest");
        } else {
            tauri_build::build();
        }
    }
    #[cfg(not(windows))]
    {
        tauri_build::build();
    }

    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=icons/icon.ico");
    println!("cargo:rerun-if-changed=icons/32x32.png");
    println!("cargo:rerun-if-changed=icons/128x128.png");
    println!("cargo:rerun-if-changed=icons/128x128@2x.png");
    println!("cargo:rerun-if-changed=../.local-private/build-secrets.json");
    println!("cargo:rerun-if-changed=../clash-scripts/claude-verge-override.js");
    println!("cargo:rerun-if-env-changed=FD_LICENSE_API_URL");

    if env::var_os("CARGO_FEATURE_COMMERCIAL_LICENSE").is_some() {
        generate_encrypted_commercial_assets();
    }
}

fn generate_encrypted_commercial_assets() {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    use sha2::{Digest, Sha256};

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR missing");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR missing");
    let workspace_root = Path::new(&manifest_dir).parent().unwrap_or(Path::new(".."));

    // 默认开发/CI 占位公钥与密钥（仅用于无 .local-private/ 时的编译与单测；正式发行自动读取 .local-private/build-secrets.json）
    let mut pub_key_hex =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".to_string();
    let mut payload_key_hex =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string();
    let mut api_url = "https://license.fdclaudeguard.workers.dev/api/v1/activate".to_string();

    let secrets_path = workspace_root.join(".local-private").join("build-secrets.json");
    if let Ok(raw) = fs::read_to_string(&secrets_path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(pk) = val.get("ed25519_public_key_hex").and_then(|v| v.as_str()) {
                if pk.len() == 64 {
                    pub_key_hex = pk.to_string();
                }
            }
            if let Some(ak) = val.get("payload_key_hex").and_then(|v| v.as_str()) {
                if ak.len() == 64 {
                    payload_key_hex = ak.to_string();
                }
            }
            if let Some(u) = val.get("license_api_url").and_then(|v| v.as_str()) {
                if !u.trim().is_empty() {
                    api_url = u.trim().to_string();
                }
            }
        }
    }

    if let Ok(env_url) = env::var("FD_LICENSE_API_URL") {
        if !env_url.trim().is_empty() {
            api_url = env_url.trim().to_string();
        }
    }

    assert!(
        !api_url.contains('<') && !api_url.contains('>'),
        "license_api_url 仍包含未替换的占位符: {api_url}，请先在 .local-private/build-secrets.json 中填写实际 Workers 域名"
    );

    let pub_bytes = hex::decode(&pub_key_hex).expect("invalid ed25519_public_key_hex");
    assert_eq!(pub_bytes.len(), 32, "Ed25519 public key must be 32 bytes");
    let key_bytes = hex::decode(&payload_key_hex).expect("invalid payload_key_hex");
    assert_eq!(key_bytes.len(), 32, "AES-256 payload key must be 32 bytes");

    let script_path = workspace_root
        .join("clash-scripts")
        .join("claude-verge-override.js");
    let script_plain = fs::read_to_string(&script_path)
        .expect("missing clash-scripts/claude-verge-override.js");

    let guides_json = serde_json::json!({
        "node_proxy": "仅检查 Clash Verge Rev 管道与本地端口独占，不改系统代理；检测到多代理端口冲突时按指引关闭多余客户端后重新实测。",
        "node_group": "先备份现有配置再写入 Clash Verge profiles\\Script.js，锁死 Claude-Fixed (select) 策略组、10+ 全家桶域名与 Mihomo ipv6:false，重载配置后复测验收。",
        "node_tun": "在 Clash Verge 首页启用虚拟网卡模式（TUN）并确认 Wintun 驱动在线，防止 Electron / Node 子进程绕过代理直连。",
        "node_dns": "在 Clash 覆写配置写入 dns.enhanced-mode: fake-ip，重载后实测 claude.ai 解析落入 198.18.0.0/15 网段即通过。",
        "node_geo": "强制经本地代理探测出口国家、ASN 纯净度（ISP/机房）与 api.anthropic.com 无状态可达性，剔除禁区与 CF 403 拉黑节点。",
        "sys_ipv6": "仅对 Windows 活跃网卡禁用 ms_tcpip6 绑定（绝不改 Clash 配置、绝不碰 Claude 目录），实测外网 IPv6 不可达后自动变绿。",
        "sys_env": "仅备份并清理冲突的 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY / ANTHROPIC_BASE_URL，并校准 WinINET 端口与 Clash 一致。",
        "sys_location": "仅关闭 Windows 系统/用户/桌面应用定位权限（HKLM/HKCU/NonPackaged 置为 Deny）并停止禁用 lfsvc 地理定位服务，防止 Claude / Chromium 通过系统定位暴露真实地理位置。",
        "claude_ban": "检出封号或 OAuth 403 残留时，自动强杀 Claude 进程树、启动防复活盯防、原子 ZIP 备份并纯净清理本地污染目录。",
        "claude_acct": "绝不擅自乱删账号目录：检出跨 orgId 混号或 OAuth 403 时引导二选一确认（原子备份重置目录 或 二次确认更换主号）。",
        "claude_tel": "仅向 ~/.claude/settings.json 合并写入官方隐私降噪环境变量并清空 ~/.claude/telemetry/ 缓存，绝不触碰登录态与聊天记录。",
        "opt_boot": "只读审计 Windows 启动项顺序，绝不擅自删除开机自启；点击打开系统启动应用管理页关闭 Claude 自启后复扫变绿。",
        "opt_ntp": "检测到系统时钟与 UTC 偏差超出 ±30 秒时，管理员一键执行 w32tm /resync /force 完成对时并复测验收。",
        "opt_fw": "一键安装免 UAC 本地守护计划任务（FDClaudeGuard_FirewallHelper）并实测读写 FDClaudeGuard_KillSwitch_* 规则，卸载自动清空。",
        "opt_webrtc": "零 UAC 为本机 Chrome / Edge 写入官方防泄露策略 WebRtcIPHandling = disable_non_proxied_udp，防止网页登录与 OAuth 回调经直连 UDP 暴露真实 IP。",
        "opt_tz": "只读比对本机系统时区与出口国家时差，绝不强改电脑时钟；新号敏感期建议选用近时区节点（日/台/新/澳）或按需手动调整。",
        "opt_browser_ext": "只读审计 Chrome / Edge 已安装扩展，绝不擅自删除插件；检出独立代理插件时请确认未对 claude.ai 单独分流。"
    })
    .to_string();

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).expect("AES-256-GCM init");

    // 为两份密文各自派生独立 12 字节 nonce
    let script_nonce_hash = Sha256::digest(b"fd-claude-guard:v1:override-script-nonce");
    let script_nonce: [u8; 12] = script_nonce_hash[..12].try_into().unwrap();
    let script_ct = cipher
        .encrypt(Nonce::from_slice(&script_nonce), script_plain.as_bytes())
        .expect("encrypt override script");

    let guides_nonce_hash = Sha256::digest(b"fd-claude-guard:v1:guides-nonce");
    let guides_nonce: [u8; 12] = guides_nonce_hash[..12].try_into().unwrap();
    let guides_ct = cipher
        .encrypt(Nonce::from_slice(&guides_nonce), guides_json.as_bytes())
        .expect("encrypt guides");

    // 轻度分片 XOR 混淆公钥与默认 API URL（消除二进制中的直观连续明文字符串）
    let pub_mask: [u8; 32] = Sha256::digest(b"fd-guard-pub-mask-v1").into();
    let pub_xored: Vec<u8> = pub_bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ pub_mask[i])
        .collect();

    let url_mask_byte: u8 = 0x5A;
    let url_xored: Vec<u8> = api_url.as_bytes().iter().map(|b| b ^ url_mask_byte).collect();

    let generated = format!(
        r#"// 由 build.rs 编译期自动生成的商业加密资产（无明文）
pub const PUB_KEY_MASK: [u8; 32] = {pub_mask:?};
pub const PUB_KEY_P0: [u8; 8] = {p0:?};
pub const PUB_KEY_P1: [u8; 8] = {p1:?};
pub const PUB_KEY_P2: [u8; 8] = {p2:?};
pub const PUB_KEY_P3: [u8; 8] = {p3:?};

pub const API_URL_XOR_MASK: u8 = {url_mask_byte};
pub const API_URL_XORED: &[u8] = &{url_xored:?};

pub const OVERRIDE_SCRIPT_NONCE: [u8; 12] = {script_nonce:?};
pub const OVERRIDE_SCRIPT_CIPHERTEXT: &[u8] = &{script_ct:?};

pub const GUIDES_NONCE: [u8; 12] = {guides_nonce:?};
pub const GUIDES_CIPHERTEXT: &[u8] = &{guides_ct:?};
"#,
        p0 = &pub_xored[0..8],
        p1 = &pub_xored[8..16],
        p2 = &pub_xored[16..24],
        p3 = &pub_xored[24..32],
    );

    let dest = Path::new(&out_dir).join("encrypted_commercial_assets.rs");
    fs::write(dest, generated).expect("write encrypted_commercial_assets.rs");
}
