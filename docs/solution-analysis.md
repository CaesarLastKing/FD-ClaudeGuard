# FDtools 结论分析与最佳实施方案

> 基于历史对话 [ca8f12fa-abdb-4bc2-ba54-58da1c11e989](./research-source-ca8f12fa.md) 的取证数据与本机环境实测整理。

---

## 一、历史对话核心结论复盘

从原对话的 5 轮分析（覆盖 2026-08-21 至 2026-11-23 的 50MB+ Claude Desktop 日志）可以明确，账号被封的根因按真实权重可分为 **两类**：

### 1. 工具无法替代的“账号与支付卫生”（必须靠使用纪律解决）
- **同一设备目录历史污染 + 高频切号连坐（Ban Evasion）**：同一 `%APPDATA%\Claude` 目录在 9 月、10 月已多次出现 `account_banned`；随后 1 个月内在同一主机上高频轮换 3 个账号超 15 次，且每次切号瞬间都会触发异步竞态（带着新号 Cookie 请求旧号 `orgId`），叠加 `get_device_info` 上报，服务端可直接实锤同设备规避封禁。
- **支付/订阅关联**：出现 App Store 订阅挂起冲突，新号开通 Pro 后 79 分钟在对话中途被 `401` 强制吊销 Token，符合支付反欺诈/关联复审时间特征。
- **结论**：这部分**不能靠“关闭遥测”或“改指纹/Hook 客户端”解决**，核心做法是**清理污染目录 + 单机单号 + 干净支付方式**；工具层能做的是**单号绑定告警**和**安全清理向导**。

### 2. 工具与网络规则可以彻底根治的“IP 暴露与分流泄漏”（FDtools 主战场）
- **实锤红线**：封号前一天两次触发 `region_unavailable`（均发生在启动/退出刷新 `EventLogging` 时），并出现首页 `403` 与累计 **308 次**网络断连（`ERR_CONNECTION_CLOSED` / `ERR_NETWORK_CHANGED` / `ECONNRESET`）。
- **代理侧隐患**：日志中混用过 `7890`（Clash 系）与 `12334`（Hiddify/v2rayN 系）两个代理端口，且大量请求走 TUN `direct` 解析，一旦 TUN 瞬间断开或节点自动故障切换到 HK/MO/CN/RU，客户端立刻裸奔泄漏。
- **时区/语言/遥测的定位**：`zh-CN` 与 `Asia/Shanghai` 只是软加权信号（切忌手动把系统时间调错），关闭非必要遥测（`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`、`DISABLE_ERROR_REPORTING=1`）属于锦上添花的辅助手段，但**不能替代网络层锁死**。

---

## 二、候选方案对比（结合本机实测环境）

本机开发工具链实测结果（2026-11-23）：
- **已就绪**：`Git 2.46.0`、`Node.js v24.14.0`、`npm 11.9.0`、`Python 3.12.10`（`py`）。
- **未安装 SDK**：`.NET SDK`（`dotnet --list-sdks` 为空）、`Go`、`Rust / Cargo`。
- **Claude 目录**：`%LOCALAPPDATA%\Claude` 与 `%APPDATA%\Claude` 均存在（MSIX 动态安装路径形态）。

| 维度 | 方案 A：双层组合（Clash 覆写 Fail-Closed + Python/Node 轻量自研 FDtools） | 方案 B：Fork `Deldar/VpnKillSwitch`（C# / .NET 10）二开 | 方案 C：Tauri v2 (Rust) / Wails (Go) 从零自研 |
| :--- | :--- | :--- | :--- |
| **落地速度** | ⭐⭐⭐⭐⭐ **最快**（零新环境依赖，当天即可跑通 MVP） | ⭐⭐⭐ 中等（需先装 `.NET 10 SDK` 并通读源码审计） | ⭐⭐ 较慢（需先配 Rust/Go 工具链） |
| **防泄漏强度** | ⭐⭐⭐⭐⭐ **同等顶格**（Clash 规则锁死 + 调用 Windows 原生防火墙规则熔断 + MSIX 路径自动解析） | ⭐⭐⭐⭐⭐ **顶格**（原生 Windows 防火墙 + MSIX 路径追踪底座现成） | ⭐⭐⭐⭐⭐（需自行实现防火墙与 MSIX 逻辑） |
| **贴合痛点程度** | ⭐⭐⭐⭐⭐ **100% 定制**（内置日志分析、切号锁、Clash API、清理向导） | ⭐⭐⭐⭐ 需在其上补写「国家白名单熔断 + `main.log` 监控 + 单号锁」 | ⭐⭐⭐⭐⭐ 100% 定制 |
| **常驻内存占用** | ⭐⭐⭐⭐ 极低（Python/Node 后台常驻约 25~50MB，远低于 Electron） | ⭐⭐⭐⭐⭐ 极低（原生 .NET 托盘约 20~35MB） | ⭐⭐⭐⭐⭐ 极低（15~30MB） |

---

## 三、目前最适合的实施方案（强烈推荐：双层防线 + 方案 A 优先）

综合投入产出比、安全边界与你本机现有环境，**最适合的策略不是“只写工具”也不是“从零造重型轮子”，而是「规则层立即止血 + FDtools 轻量精准守卫」的双层架构**：

### 第 0 步：零代码立即止血（先补最大漏洞）
1. **代理规则层 Fail-Closed**：按原对话提供的 Clash JavaScript 覆写脚本建立纯手动锁死的 `Claude-Fixed` 策略组（仅保留受支持地区稳定节点 + `REJECT`，彻底剔除 HK/MO/CN/RU 和 `DIRECT`），同时锁定全家桶域名与 `Claude.exe` / `claude.exe` 进程，关闭 IPv6，避免双代理软件同时开启。
2. **隐私与卫生复位**：
   - 在 `%USERPROFILE%\.claude\settings.json` 启用 `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` 与 `DISABLE_ERROR_REPORTING=1`，并清空 `~/.claude/telemetry/`。
   - 换用新合规账号前，彻底退出并清理已被污染的 `%APPDATA%\Claude` 与 `%LOCALAPPDATA%\Claude`，严格执行**单机单号**。

### 第 1 步：`FDtools` 核心架构（推荐 Python 3.12 优先，或 Node.js 24）
直接利用本机已有的 **Python 3.12**（`pystray` 托盘 + 轻量本地 Web/Tk 面板 + 调用系统 `netsh`/PowerShell 防火墙），融合 `justwjx/claude-proxy-guard`（启动前门禁）和 `Deldar/VpnKillSwitch`（MSIX 防火墙断网）两大核心能力，按 **3 个阶段**交付：

1. **MVP（阶段 1 — 核心防线）**：
   - **Pre-flight 启动门禁**：通过代理检测当前出口 IP / 国家（白名单 + 基准国家锁死）、检测双代理端口冲突（7890/12334 等）、检查 Clash API 中 `Claude-Fixed` 当前锁定节点、校验 NTP 时钟偏差与 `settings.json` 开关，全部通过才放行启动 Claude。
   - **系统托盘看门狗**：每 15~30 秒巡检出口国家与代理存活，绿/黄/红三色托盘图标实时指示状态。
2. **强保护（阶段 2 — 防火墙熔断 + 实时日志监控）**：
   - **MSIX 防火墙级 Kill Switch**：通过系统命令自动解析 `Claude.exe` 真实安装路径；一旦检测到代理断开或出口漂移到禁区，直接下发 Windows 防火墙出站阻断规则（比杀进程更彻底，阻止退出 flush 泄漏），环境恢复后自动放行。
   - **实时日志告警 & 单号锁**：持续 `tail` `%LOCALAPPDATA%\Claude\logs\main.log` 与 `claude.ai-web.log`，捕获 `region_unavailable` / `403` / `OAuth token revoked` / `account_banned` 立刻弹窗告警并触发熔断；监测活跃 `accountId` 变化，防止误切号导致连坐。
3. **运维工具箱（阶段 3 — 可视化体检与一键重置）**：
   - **日志诊断报告**：复用原对话的取证规则，一键统计历史断连次数、403、地区报错与账号切换时间线。
   - **安全清理向导**：确认 `Claude.exe` 完全退出后，带自动备份地清理 `%APPDATA%\Claude`、`%LOCALAPPDATA%\Claude` 及 `~/.claude/telemetry`。

> **何时改选方案 B（Fork `Deldar/VpnKillSwitch`）？**
> 如果你更倾向使用现成的 Windows 桌面托盘外壳且愿意安装 `.NET 10 SDK`，可以直接将 `Deldar/VpnKillSwitch` 克隆至本仓库二次开发，在其防火墙与 MSIX 底座上补齐「国家白名单熔断 + `main.log` 告警 + 单号锁」三个模块即可。
