# 02 · FDtools 单账户与多账户演进规划、客群分层与底层架构蓝图

> **核心定位**：**「同一套代码 · 渐进式披露」**——默认开箱为极简强化的单账户防封启动器（服务 90% 客户端用户），按需一键开启多账户隔离模式（服务 10% 重度多号 / `T3 Code` / CLI 开发者），绝不分裂为两套代码库。

---

## 一、面向 3 类不同客户的产品分层设计

| 客户画像 | 占比预期 | 核心诉求 | 在 `FDtools` 中看到的默认体验 |
| :--- | :---: | :--- | :--- |
| **L1 · 普通单账户客户端用户**（主力 Claude Desktop / Web） | ~70% | 怕封号、怕关 TUN 断网、怕 Free 403 报错吓人、充值怕被封 | **极简开箱态**：5 项精简侧栏（控制台 / 节点流量 / 账号与审计 / 环境维护 / 守卫配置），完全不暴露 `T3 Code`、多端口、目录沙箱等极客概念；开箱即享 17 项环境门禁、403 自动降噪、充值前风险门禁与一键网络急救。 |
| **L2 · 重度写代码开发者**（Desktop + Claude Code / 官方 IDE 扩展 / Codex） | ~20% | 要图形化好用、要看 5h/7d 消耗、防止第三方插件劫持 OAuth | 在默认单号基础上，自动启用离线 `.jsonl` 燃烧速率监控、跨端（CLI vs Desktop）串号提醒、`ANTHROPIC_BASE_URL` 防劫持审计，推荐配合 **路线 1（`T3 Code` / `Zed ACP` / 官方 IDE 扩展）** 跨厂家互补。 |
| **L3 · 多账号重度运维 / 工作室 / 开发者**（手握 2+ Claude 订阅） | ~10% | 多号同时在线免反复登出、5h 额度用完安全接力、单号封禁绝不连坐 | 在「账号与审计」点击 **`+ 添加隔离账号`**（或在守卫配置开启多号模式）后渐进展开：顶部多账号档案条 + **Mihomo 专属端口编排（`7891/7892…`）** + 独立目录沙箱 + 一键隔离启动 `T3 Code` / `CLI` / `Desktop`。 |

---

## 二、为什么「阶段 1（单账户配置审计）」与「阶段 2（多账户架构）」零无用功？

### 1. 架构复用的本质
多账户不是重写一套风控系统，而是把阶段 1 的 **单账户审计引擎（配置解析 + 日志 403 消歧 + 14 项行为风控 + 充值前门禁）** 套上一个 `for profile in profiles` 循环。

### 2. 防止返工的唯一工程铁律（写阶段 1 时零额外成本）
从第一行 Rust 代码开始，所有本地审计与状态结构体**必须接收 `ProfileContext` 参数，而非读取硬编码全局路径**：

```rust
pub struct ProfileContext {
    pub profile_id: String,                   // 单号态固定 "default"
    pub alias: String,                        // 如 "默认主号" / "主力-Pro-US"
    pub cli_config_dir: Option<PathBuf>,      // 单号态 Some(~/.claude)，纯 Desktop 用户可为 None
    pub claude_json_path: Option<PathBuf>,    // 单号态 Some(~/.claude.json)，多号态独立目录内 .claude.json
    pub desktop_data_dir: Option<PathBuf>,    // 单号态 Some(%LOCALAPPDATA%\Claude + MSIX)，纯 CLI 多号可为 None
    pub bound_proxy_port: Option<u16>,        // 单号态 None（走全局 TUN/主端口），多号态 7891/7892...
    pub expected_geo: Option<String>,         // 如 Some("us")
}
```

- **阶段 1（单号优化）**：系统仅构造 1 个默认 `ProfileContext("default", ...)`；所有解析、403 消歧、风险评分、充值门禁与前端详情卡**100% 跑通并立刻交付价值**；
- **阶段 2（多号隔离）**：只需新增 `ProfileManager` 管理多份 `ProfileContext` + `MihomoListenerOrchestrator` 编排专属端口，**阶段 1 的全部业务与 UI 代码零重写直接复用**！

---

## 三、多账户 5 层全链路风险隔离架构（Phase 2 核心壁垒）

相比 GitHub 开源工具（如 `cpm`、`claude-profile` 仅做文件目录隔离），`FDtools` 串联成 5 层隔离闭环：

1. **第 1 层 · 目录与指纹隔离**：每号独立 `CLAUDE_CONFIG_DIR`（独立 `.claude.json`、`machineID`、`userID`、`projects/`）+ 独立 Desktop 数据目录（传统 EXE 版 `--user-data-dir` / 开源沙箱 `Sandboxie-Plus`；微软商店 MSIX 版采用清零进程后的原子目录冷切换）。
2. **第 2 层 · 进程清零隔离**：切号或清理前强制走既有 **Kill-Hold 45s 押运锁**，杜绝 `onQuitCleanup` 退出队列带旧 Cookie 裸奔回传。
3. **第 3 层 · Mihomo 多端口专属节点绑定（免反复切换核心）**：
   - 利用 Mihomo 原生 `listeners` 为每号分配专属本地端口（如 `127.0.0.1:7891 → US-ISP-01`、`127.0.0.1:7892 → US-ISP-02`）；
   - 自动校验 **`账号 default_workspace_geo == 专属节点国家`**；
   - 一键复制专属代理喂给指纹浏览器（AdsPower/BitBrowser）或 Sandboxie，实现 Web + CLI + Desktop 同号同专属 IP 且多号并行免反复登出。
4. **第 4 层 · 封号熔断与冷却隔离**：任一账号命中 `account_banned` 或 `portal.anthropic.com/verify` 立刻标红锁死并切断其专属端口，**严禁其他健康号复用其节点与目录**，其余健康账号零受影响。
5. **第 5 层 · 充值前安全门禁（Pre-Payment Check）**：
   - 自动拦截 4 项可测风险：`geo` 地区错配、跨端串号/封号残留、刚过 KYC/注册冷静窗（24~72h）、遥测降噪漏配；
   - **诚实明示支付黑盒红线**：本地无法检测 U 卡 BIN 在 Stripe Radar 的黑名单分，显式提醒禁用高危 U 卡直充 Stripe，优先干净美区 Apple ID 内购。

---

## 四、UI 合并与重构定稿方向（已出高保真效果图）

- **侧边栏保持 5 项极简**：`控制台` → `节点流量` → **`账号与审计`（原「日志分析」合并升级）** → `环境维护` → `守卫配置`。
- **`账号与审计`**（[account-audit-merged-preview.html](../../docs/mockups/account-audit-merged-preview.html)）：3 分段（`账号体检与门禁` | `客户端日志` | `SessionKey 核验`）+ 顶部渐进式账号切换栏（单号极简、多号可扩展）。
- **`环境维护`**（[maintenance-refactored-preview.html](../../docs/mockups/maintenance-refactored-preview.html)）：彻底消灭 6 块文字墙，重构为 3 分段（`急救与撤回` | `备份与清理` | `紧急熔断与排障`），0 功能丢失，未激活态急救与撤回永久免费。

---

## 五、单账户 Desktop 与多账户 CLI 底层防冲突注意事项（系统级架构红线）

> 当项目从 Phase 1（单账户）演进到 Phase 2（多账户）时，必须严守以下 **4 条底层解耦红线**，确保单账户 Desktop 体系与多账户 CLI/`T3 Code` 体系共存不打架、老用户平滑升级无感知：

### 1. 网络路由解耦：全局 TUN（单号）与 Mihomo 多端口（多号）互不干扰
- **单账户默认态**：完整保留现有 **全局 Clash TUN + `Claude-Fixed` 单策略组锁死**，确保普通 Desktop 用户零配置防裸奔。
- **多账户进阶态**：为每个多号档案分配独立的 Mihomo `listeners` 本地回环端口（如 `127.0.0.1:7891 / 7892`，各绑死独立固定节点）；
  - 子进程显式通过 `HTTPS_PROXY=http://127.0.0.1:7891` 发往本地回环，**天然不被全局 TUN 二次劫持**；
  - **禁止**在多号模式下关闭或破坏全局 TUN 对宿主机其他进程和默认 Desktop 的兜底防裸奔保护；
  - 写入 Mihomo `listeners` 时须遵循可逆快照原则（仅管理固定命名/端口段，撤回时绝不破坏用户原有订阅和规则）。

### 2. 进程管控解耦：全局按名强杀 vs 按 PID/进程树精准止损
- **单账户默认态**：保持现有 **按进程名全杀（`Claude.exe` / `claude.exe`）+ 45s Kill-Hold 押运锁**，彻底杜绝残留与复活。
- **多账户并行态**：**严禁一刀切按进程名全杀！** 否则当账号 B 异常熔断或切节点时，会把并行正常工作的账号 A 的 `claude.exe` 误杀。
  - 多号模式启动的子进程（CLI / `T3 Code` / 传统 EXE Desktop）必须按 `profile_id -> Vec<PID>` 记录进程树；
  - 异常止损优先 **掐断该档案对应的专属 Mihomo 端口（如仅停 `7892`）+ 仅终止该档案记录的 PID 进程树**，做到单号隔离零波及。

### 3. 客户端形态边界解耦：不强行破解微软商店 MSIX 多开
- **Claude Desktop（MSIX 商店版）**：受 Windows AppContainer 单实例与目录虚拟化限制，定位为 **单号默认主力（或多号冷切换隔离）**，不强行做高风险的 MSIX 注入多开；
- **多号并行主力**：明确面向天生支持独立环境变量与代理端口的 **Claude Code CLI（`CLAUDE_CONFIG_DIR`）**、**`T3 Code`**、**官方 IDE 扩展**、**传统 EXE 版 Desktop（`--user-data-dir`）** 及 **指纹浏览器**。

### 4. 配置文件与 UI 向后兼容平滑升级
- **配置结构兼容**：`AppConfig` 扩展 `multi_account_enabled: bool`（默认 `false`）与 `profiles: Vec<AccountProfile>` 时必须全部标注 `#[serde(default)]`；老单号用户升级新版后自动无感映射为唯一 `"default"` 档案，不丢失既有绑定节点、激活密钥与已读日志游标。
- **UI 渐进披露红线**：当 `profiles.len() <= 1 && !multi_account_enabled` 时，主界面与控制台隐藏一切多端口/多档案复杂控件，保持面向普通单号用户的极致简洁。

