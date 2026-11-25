# FD Claude 安全启动器 · 阶段性商业授权与抗逆向加密规划（v1.0）

> **商业策略**：前几个月以「免费真实体检 + 一次性付费密钥解锁一键修复与守护」模式发行闭源 Release 安装包，回补 AI 开发消耗；后续时机成熟时，通过移除 Cargo `commercial-license` feature 与私有授权模块，优雅发布干净的开源版本。

---

## 1. 核心业务规则（不可偏离）

1. **免费体验边界（建立强信任）**：
   - 未激活用户可免费安装、运行全部 **10 项必须 + 3 项建议** 真实探针体检，看清本机真实泄漏与风险；
   - 未激活态下，右侧详情卡 **「处理方式与验证说明」** 仅呈现干净的毛玻璃斜纹马赛克遮罩（前端无明文，**遮罩内不叠加多余文字胶囊**），**同时隐藏底部「无法自动解决？导出脱敏问题包给 AI 分析」链接**；唯一行动焦点落在下方高对比白色主按钮 **`输入激活密钥 · 解锁步骤并一键处理`**（以及顶部锁定态一键按钮）；同步屏蔽自动熔断、节点切换与环境维护执行类 IPC；
   - **售后与购码直达入口**：主窗口顶栏悬浮窗按钮旁新增同风格纯图标「售后」按钮，弹窗清晰展示官方售后 **QQ：`2568515327`**（含一键复制 QQ 号与快捷去激活）；「激活密钥弹窗」底部同步提供 QQ 号一键复制入口。
2. **一码一次作废（不可复用、不可共享）**：
   - 激活码经在线核销成功后，服务端原子标记为 `used` 永久作废；任何机器（含本人卸载重装）再次输入同一密钥均直接拒绝。
3. **不卸载永久离线用，卸载即销毁**：
   - 激活成功后，客户端离线验签 + 本地硬件与安装实例绑定，**后续无需联网即可永久使用**；
   - 一旦执行卸载，NSIS 卸载钩子彻底销毁本地授权凭证与安装实例 ID，重装后无法复用旧密钥。

---

## 2. 零成本在线核销服务端架构（Cloudflare Workers + D1）

- **部署成本**：Cloudflare Workers + Cloudflare D1 免费套餐（每日 10 万次免费请求，HTTPS 全球加速，**0 元/月**）。
- **数据表结构（D1 SQLite）**：
  ```sql
  CREATE TABLE licenses (
    key_hash TEXT PRIMARY KEY,          -- SHA-256(key + server_salt)，不存明文密钥
    batch_id TEXT NOT NULL,             -- 发卡批次号
    status TEXT NOT NULL DEFAULT 'unused', -- 'unused' | 'used' | 'revoked'
    activated_at TEXT,                  -- UTC ISO8601 核销时间
    machine_fp_hash TEXT,               -- 客户端硬件指纹哈希（脱敏）
    install_id_hash TEXT                -- 本次安装实例 ID 哈希
  );
  ```
- **原子一次性核销接口（`POST /api/v1/activate`）**：
  - 请求体：`{ license_key, machine_fp_hash, install_instance_id, app_version }`
  - 核心 SQL（利用 SQLite 原子写防并发重放）：
    ```sql
    UPDATE licenses
    SET status = 'used',
        activated_at = datetime('now'),
        machine_fp_hash = ?2,
        install_id_hash = ?3
    WHERE key_hash = ?1 AND status = 'unused'
    RETURNING batch_id, activated_at;
    ```
  - 若受影响行数为 `0` → 返回 `409 Conflict`（密钥不存在或已使用作废）；
  - 若核销成功 → Workers 使用服务端保密的 **Ed25519 私钥** 签发离线证书 `cert_b64`（载荷含 `machine_fp_hash + install_id_hash + key_hash + issued_at`），并**随响应一次性下发用于解密核心修复文案与规则模板的 `payload_key_hex`**。

---

## 3. 本地永久离线授权与卸载销毁闭环

1. **安装实例标识（`install_instance_id`）**：首次安装或首次启动时生成 256-bit 随机 UUID，存于软件专属数据目录 `%LOCALAPPDATA%\FDClaudeGuard\inst.id`。
2. **Windows DPAPI 加密金库（`vault.dat`）**：
   - 激活成功后，Rust 后端调用 Windows 原生 **`CryptProtectData`（DPAPI，绑定当前 Windows 用户）**，将 `{ cert_b64, payload_key_hex, install_instance_id }` 加密写入 `%LOCALAPPDATA%\FDClaudeGuard\vault.dat`。
   - 即使有人将 `vault.dat` 复制到其他电脑，DPAPI 与本机硬件指纹（`MachineGuid` + 主板 UUID 哈希）双重校验均直接失败。
3. **启动离线验签**：
   - 每次启动，Rust 后端解密 `vault.dat` → 用编译期内置的 **Ed25519 公钥** 校验 `cert_b64` 签名 → 比对当前硬件指纹与 `inst.id` → 全部通过即在内存加载 `payload_key` 解密核心规则与修复步骤，**全程 0 联网、不卸载永久可用**。
4. **NSIS 卸载销毁钩子**：
   - 在 Windows 安装包卸载脚本（NSIS Uninstall Hook）中，与清空 `FDClaudeGuard_KillSwitch_*` 防火墙规则同步执行：强制删除 `%LOCALAPPDATA%\FDClaudeGuard\vault.dat` 与 `inst.id`。

---

## 4. 抗 AI 逆向与防破解 5 道核心防线

| 防线层级 | 工程手段 | 防御目标 |
| :--- | :--- | :--- |
| **L1 · 密文驱动解锁** | 所有「详细操作步骤文案」与核心 `Script.js` 覆写模板均以 **`AES-256-GCM` 密文**形式打包（安装包内零明文），**必须依赖激活下发的 `payload_key` 才能在内存解密** | 彻底防住“改一行 `if is_licensed` 爆破”和“用 IDA / AI 直接扒安装包明文” |
| **L2 · 全鉴权下沉 Rust** | React 前端严禁存放明文指南与鉴权开关；未激活时 Rust IPC 仅返回脱敏占位符，所有修复/切节点/维护类命令在 Rust 入口层强制校验签名与 `payload_key` | 彻底防住 WebView F12 / 前端 JS 修改绕过 |
| **L3 · Rust 编译加固** | `Cargo.toml` Release 启用 `strip = true`、`lto = "fat"`、`codegen-units = 1`、`panic = "abort"`；用 `obfstr` 混淆关键接口域名、公钥拼接片段与校验字符串 | 打散函数边界、消除符号表与明文字符串，大幅拉高 AI 反编译分析成本 |
| **L4 · 前端打包封锁** | 生产包关闭 DevTools、禁用右键审查、禁用 `sourcemap`、启用 Terser 混淆压缩，且由 Tauri v2 内嵌进单一原生 EXE | 无 Electron 裸露 `app.asar` 风险 |
| **L5 · 一键开源隔离** | 全部授权逻辑收敛于 `src-tauri/src/licensing/`，受 Cargo 条件编译 **`#[cfg(feature = "commercial-license")]`** 控制 | 商业版编译成单一机器码 EXE，用户电脑无 `licensing/` 目录可删；日后作者自己在私有仓库移除该模块即可体面开源 |

---

## 5. 建议实施节奏
- **M1–M4**：先聚焦主功能真机跑通与稳定性验收；
- **M5（商业封包阶段）**：接入 `commercial-license` Feature、未激活马赛克与激活弹窗 UI、部署免费 Cloudflare Workers 核销服务 + 本地离线发卡器脚本（存 `.local-private/` 绝不入库）。
