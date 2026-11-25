# FDtools 产品定位升级调研：多账户监测与全链路风险隔离架构

> **研究主题**：产品核心需求收敛、GitHub 成熟多账户 Claude 项目隔离机制调研，以及 `FDtools` 面向“多账户安全运行与防连坐隔离”的差异化架构设计。  
> **关联文档**：[开源对标与并入规划](./account-analyzer-benchmark-and-integration.md) · [Claude Desktop 安全审计与 12 槽位](./claude-desktop-audit-and-risk-slots.md) · [产品与架构设计](./architecture-and-design.md)

---

## 一、产品核心定位收敛：面向什么真实需求？

将你梳理的三大能力收拢后，`FDtools` 的真实产品定位应当从“单机防封启动器”升级为：

> **Windows 平台 Claude 多账户安全运营与防封工作台**  
> 面向同时持有 **2 个及以上 Claude 账号**（如主力 Pro/Max + 备用号、个人号 + 工作号、Desktop + Claude Code 开发者）的用户，提供 **「网络节点管控 × 本机沙箱隔离 × 多账户风控监测」** 三位一体的安全工作台。

| 产品支柱 | 解决的核心用户痛点 | 核心能力边界 |
| :--- | :--- | :--- |
| **1. 节点分析与管控（网络层）** | 防止跨洲跳变、机房脏 IP、CF 403 拉黑、裸奔漏包 | Clash TUN / Fake-IP / 固定单节点锁 / 双平台评估 / 落地 IP 漂移 / 休眠唤醒预阻断 / 4 层热熔断 |
| **2. 本地环境与沙箱管理（系统层）** | 防止多号同目录串登、封号残留连坐、退出回传、环境冲突 | IPv6 禁用 / 环境变量冲突清理 / Kill-Hold 45s 押运 / 原子 ZIP 备份 / **多账户独立目录沙箱与绑定节点切换事务** |
| **3. 多账户监测与风险管控（账号层）** | 看不清账号底牌、充值前踩雷、误判 403、不了解燃烧节奏 | 多账户状态看板 / 离线 5h-7d 用量与行为风控 / 7 维只读底牌核验（`geo`、KYC、原生 4 槽位、`account_banned`） / 充值前风险门禁 |

---

## 二、GitHub 多账户 Claude 开源项目调研（机制与风控短板）

### 1. 两大主流技术流派对比

| 流派 | 代表 GitHub 项目 | 实现机制 | 优点 | 致命防封缺陷 |
| :--- | :--- | :--- | :--- | :--- |
| **流派 A：凭据原地替换型**（❌ 防封不推荐） | `realiti4/claude-swap`<br>`edglz/ccswitch` / `nhtera/ccswitch`<br>`uwuclxdy/clauth` | 备份多个账号的 `.credentials.json` / `.claude.json`，切换时原地覆盖同一个 `~/.claude` 目录；部分支持限流后自动轮询切号（fallback chain） | 切换快、支持自动接力 | 1. **目录与指纹污染**：共享缓存/日志，极易触发跨 `orgId` 404 竞态<br>2. **同 IP 瞬切高危**：同一出口 IP 在限流瞬间自动切号狂刷，是典型的多号套利 / Ban Evasion 特征 |
| **流派 B：目录沙箱隔离型**（✅ 防封必选基础） | `diranged/claude-profile`<br>`jakubkontra/claude-profile-manager` (`cpm`)<br>`jmdarre-v/claude-multiprofile`<br>`jspanji/Swivel` | **Claude Code CLI**：通过官方环境变量 `CLAUDE_CONFIG_DIR` 指向独立目录（每个目录独立 `.claude.json`、`machineID`、`.credentials.json`、项目日志与 Keychain 哈希命名空间）<br>**Claude Desktop**：通过 Electron 原生参数 `claude.exe --user-data-dir=<独立目录>` 隔离 Chromium Cookies、Local Storage 与 `main.log` | 官方机制兼容、凭证与日志彻底隔离、互不覆盖 | **只做了“文件隔离”，没做“网络/进程/风控隔离”**：<br>- 所有账号仍共用同一个代理 IP<br>- 切号时不检查旧进程残留（容易退出回传）<br>- 不校验 `workspaceGeo` 与节点地区一致性<br>- 某号被封后无自动隔离锁防止连坐 |

### 2. Windows 平台特别工程注意（Desktop EXE vs MSIX）
- **Claude Code CLI**：Windows 上完美支持通过设置进程级环境变量 `CLAUDE_CONFIG_DIR=%LOCALAPPDATA%\FDClaudeGuard\profiles\<id>\claude-cli` 启动完全隔离的 CLI 实例。
- **Claude Desktop**：
  - **传统安装版（Squirrel/EXE）**：原生支持 `claude.exe --user-data-dir=<独立目录>` 做到账号级完全沙箱隔离；
  - **微软商店 MSIX 版**：因 Windows AppContainer 虚拟化重定向 `LocalCache\Roaming\Claude`，直接传 `--user-data-dir` 存在兼容性差异，需通过「清零进程（Kill-Hold）→ 原子快照切换 Profile 目录（或引导使用独立桌面目录）」实现冷切换隔离，并在实机上做双形态兼容验证。

---

## 三、`FDtools` 多账户全链路「5 层风险隔离模型」（核心护城河）

相比 GitHub 开源工具仅做第 1 层，`FDtools` 能够把现有能力串联为市面上独一无二的 **5 层隔离闭环**：

```mermaid
flowchart LR
  P["选择目标账号 Profile\n(如: 主力-Pro-US)"] --> S1["1. 进程清零隔离\nKill-Hold 事务锁确保旧进程 0 残留"]
  S1 --> S2["2. 封号与冷却门禁\n检查是否关联封号节点/同 IP 切号冷却"]
  S2 --> S3["3. 网络节点绑定隔离\nClash 切至该号专属固定节点\n实测出口国家 == workspaceGeo"]
  S3 --> S4["4. 沙箱目录隔离\n独立 CLAUDE_CONFIG_DIR\n独立 Desktop DataDir / machineID"]
  S4 --> S5["5. 安全拉起与持续监测\n绑定日志流 + 离线用量 + 风险槽位归档"]
```

1. **第 1 层 · 目录与指纹隔离**：每个账号 Profile 拥有独立的 CLI 目录（`CLAUDE_CONFIG_DIR`）与独立的 Desktop 数据目录，独立 `machineID`、`userID`、`settings.json` 与日志路径，杜绝跨 `orgId` 404 竞态。
2. **第 2 层 · 进程清零隔离**：切换账号时强制先走 `FDtools` 既有的 **Kill-Hold 押运锁**，彻底清零旧账号后台进程与 `chrome-native-host`，杜绝退出回传（`onQuitCleanup`）在切节点瞬间带旧 Cookie 裸奔。
3. **第 3 层 · 专属节点与地区隔离（最核心差异化）**：每个账号 Profile 绑定一个**专属固定节点**（例如账号 A 永远绑定 `US-美西-ISP-01`，账号 B 永远绑定 `JP-日本-ISP-02`），并自动核对 `账号 default_workspace_geo == 绑定节点国家`。
4. **第 4 层 · 封号熔断与切号冷却隔离**：
   - 一旦某账号 Profile 命中 `account_banned` 或 `portal.anthropic.com/verify`，立刻标为「隔离态」，**禁止其他健康账号复用其绑定节点与目录**；
   - 如果用户确实需要让两个健康账号共用同一地区节点，切换时提示等待冷静期，拒绝 `claude-swap` 式“1 秒自动无缝接力刷量”。
5. **第 5 层 · 多账户统一监测与充值门禁**：
   - 一屏监测所有账号的实时风险槽位、离线 5h/7d 用量、KYC 状态、地区匹配度与历史状态跃迁 Diff；
   - 每个账号独立评估「充值/升级前门禁」，避免重演 U 卡 + 跨区 + 串号导致的异步封号。

---

## 四、对既有 UI 方案的平滑演化建议

只需在刚才设计的「账号体检」页面上做极克制的升级，即可无痛支持多账户：
- 导航项命名可从 `账号体检` 升级为 **`多号管理`** 或 **`账号管控`**；
- 在顶部 4 格 KPI 卡上方增加一条紧凑的 **「多账户 Profile 横向切换条 / 列表」**（如 `[主力 · Pro · US ✓]`、`[备用 · Free · US ⚠]`、`[已封 · 隔离中 ✕]` + `+ 新建隔离档案`），选中任意账号即可查看该账号的专属体检、绑定节点、离线用量，并支持一键 **「安全隔离切换并启动」**。
