# FD Claude Guard 研发、测试与验收工程规范体系（v2.2）

> **适用范围**：`FDtools`（FD Claude Guard）全部功能迭代、体验优化、Bug 修复、应急插单与版本发布。  
> **总纲**：**任务全登记、边界先划清、异常前置想、多端同兼容、联动全回归、1 秒契约防错、双速分级验收、确认才打包**。

---

## 一、核心原则 1：热冷分层台账、需求细节落盘与断点续传机制（`v3.0`）

> **全仓文档地图**：[docs/README.md](README.md)。严禁将已发布关闭的历史记录堆积在活跃待办表中浪费上下文！

1. **三表分流 + 严守热冷分层（有提必记、先记后做）**：
   - **活跃需求表**（[docs/active/feature-backlog.md](active/feature-backlog.md)）：只登记未完成/进行中的新功能、产品重构、体验优化、技术调研与生态规划；
   - **活跃 Bug 表**（[docs/active/bug-tracker.md](active/bug-tracker.md)）：只登记未发布关闭的缺陷、跨界契约问题与代码已完待真机验收项；
   - **待拍板决策表**（[docs/active/decisions-open.md](active/decisions-open.md)）：统一收敛所有卡住推进的产品/设计二选一开放问题，拍板即移出；
   - **冷归档区**（[docs/archive/](archive/README.md)）：任何需求或 Bug 一旦随正式版发布关闭，**必须立刻从 `docs/active/` 移出并归档至 `docs/archive/` 与 `CHANGELOG.md`**；AI 日常开工**严禁主动读取 `docs/archive/`**，将上下文占用压至最低。
2. **需求方案与讨论细节防压缩失忆机制（[docs/specs/](specs/README.md)）**：
   - 凡进入多轮讨论或含 3 个以上细节的复杂需求，**开工/深入讨论前必须复制 [`docs/specs/_TEMPLATE-spec.md`](specs/_TEMPLATE-spec.md) 创建专属 `SPEC-<编号>-<主题>.md`**；
   - **边聊边落盘铁律**：每轮讨论中凡是新敲定的需求点/细节、明确不做的保护边界、已否决的备选方案与否决理由、以及未决问题，必须当轮原地更新进对应 `SPEC-*.md`；
   - **压缩与跨会话零损耗续传**：触发上下文压缩（`/compact`）前或结束长讨论前，务必同步 `SPEC-*.md`；恢复讨论或交接开发时，只需读取该份几 KB 的 `SPEC-*.md` + `docs/active/` 对应表，即可 100% 恢复细节、杜绝失忆返工。
3. **标准状态流转（严禁跳步）**：
   - `待确认` → `待排期` → `方案定稿(Spec)` → `开发中` → `代码已完·待真机验收` → `待打包确认` → `移出热表并归档关闭`
4. **打断与续传规则**：
   - 任何时候被新问题、紧急插单、额度耗尽、会话压缩打断时，先将状态与讨论细节落盘至 `docs/active/` 或对应 `docs/specs/SPEC-*.md`；
   - 恢复工作时**第一动作就是读取 `docs/active/` 与当前活跃 `SPEC-*.md`**，清点未完成项按优先级续跑。

---

## 二、核心原则 2：需求边界与防回归准则（开发基本准则）

开发动手前必须先对照历史文档（`docs/task-ledger.md`、`docs/dev-issues-log.md`、`docs/protocol-constants.md`）做**需求边界审查**，写清以下 3 条再改代码：

1. **本次改动范围（In-Scope）**：明确要新增或修改的模块、页面、IPC 命令或配置项。
2. **既有已完成边界（Protected / Out-of-Scope）**：明确哪些已完成能力**严禁被顺带改坏或回退**（例如：未激活 3 项公开/14 项隐藏边界、主窗副标题 `Fuck Dario！！！`、不碰 AGY 分流、不擅自跨洲切节点、悬浮窗自适应尺寸等）。
3. **修改旧逻辑 vs 新增能力决策**：
   - 只有当旧逻辑与新需求冲突或存在实锤缺陷时，才允许改旧逻辑，且必须先验证对既有调用方的影响；
   - 严禁把用户反馈的“某功能改不了/有 Bug”误解为“删掉或禁止该功能”；能修到位就修到位，受系统底层限制真做不到必须用实测证据说清原因并给替代方案。

---

## 三、核心原则 3：影响面分析与跨模块联动测试

每次改完代码，**绝不能只测“主功能本身能不能跑”**，必须显式列出并验证周边影响面与联动链路：

1. **状态与角标联动矩阵**（涉及节点/网络/日志/熔断改动必查）：
   - 控制台 17 项状态 ↔ 侧边栏「控制台 / 节点流量 / 日志分析」红黄角标 ↔ 节点流量表评分/操作禁用 ↔ 桌面悬浮窗（国码、副标题、三微卡片、底部 CTA 跳转）
2. **外部系统双向同步矩阵**（涉及 Clash / Windows / Claude 目录改动必查）：
   - 内存态（Mihomo API） ↔ 持久化配置（`Script.js` / `profiles.yaml` / `clash-verge.yaml` / `config.yaml` / `verge.yaml`） ↔ 重载/重启后的持久性 ↔ 2 秒哨兵外部同步
3. **样式与状态切换残留矩阵**（涉及 UI 改动必查）：
   - 默认态 → 激活态 → 解除/还原态（严禁混用 CSS 简写与细分属性导致还原残留白边/错色）
   - 暗色/亮色主题、高 DPI / 130% Windows 文本缩放、空数据态 vs 满数据态

---

## 四、核心原则 4：代码级防呆铁律与多客户环境兼容矩阵（`v2.1` 融入项目门禁）

为彻底杜绝“本机空目录能跑、客户真机卡死或失效”的回归，以下 4 条必须落实到代码与自动化测试中（而非停留在口头）：

1. **Tauri 线程隔离铁律（杜绝主线程 UI 假死）**：
   - 所有涉及磁盘遍历/压缩/解压、外部子进程（`taskkill` / `netsh` / `powershell` / `explorer`）、注册表重操作或网络 I/O 的 `#[tauri::command]` **一律强制 `async fn` + `tokio::task::spawn_blocking`**。
   - **自动化门禁**：Rust 测试 `lib::tests::tauri_commands_thread_isolation_audit` 会静态扫描 `src-tauri/src/lib.rs` 中全部同步 `#[tauri::command] fn`，超出轻量白名单即直接红灯失败。
2. **大体积、软链与防错删红线（杜绝客户大目录压垮或误删）**：
   - 所有文件树扫描、打包与清理强制使用 `fs::symlink_metadata` 检测并跳过软链接 / NTFS Junction，严禁跟随；
   - 打包强制流式 `std::io::copy` + ZIP64，禁止 `read_to_end` 整文件读入内存；可再生浏览器大缓存仅清理不入 ZIP，GB 级 VM 镜像（`vm_bundles` / `claude-code-vm`）与程序本体（`WindowsApps` / `Local\Claude\app-*` / `Update.exe` / `packages` / `Local\AnthropicClaude`）必须硬保护；
   - 清理操作前必须先异步扫描并弹出**透明分项勾选清单**，个人 MCP 配置（`claude_desktop_config.json`）与本地工作会话默认不勾选防错删；
   - **自动化门禁**：维护单测必须包含仿真多形态目录 + 大文件 + 软链测试，断言外部软链目标、程序本体与未勾选项 0 改动。
3. **多客户安装形态兼容矩阵（Clash + Claude 同类根治）**：
   - **Clash Verge**：优先从运行中 `clash-verge.exe` / `verge-mihomo` 进程反推真实配置目录（兼容便携版 Portable、自定义数据目录、跨账号 UAC 提权，再回退 `%APPDATA%`）；写 `Script.js` 时同步确保 `profiles.yaml` 注册 `uid: Script`；策略组同时支持 `proxies` 与 `proxy-providers`（`use` + `exclude-filter`，绝不退化 `DIRECT`）。
   - **Claude**：统一识别并区分微软商店 MSIX（含 `LocalCache\{Roaming,Local}\Claude` 与 `Local\Claude-Data`）、经典安装版（`%APPDATA%\Claude` / `%LOCALAPPDATA%\Claude` / `%LOCALAPPDATA%\AnthropicClaude`）与 Claude Code CLI（`~/.claude`）。
4. **并发互斥与可观测性门禁**：
   - 后台长任务（`node_audit` 深度核验、事务锁 `tx_locked`）必须与前台触发操作（`preflight`、250ms `kill_hold`）明确互斥，严禁核验试测节点污染主节点 `node_geo` 或事务锁期间误顺延盯防；
   - 运行日志启动版本号强制使用 `env!("CARGO_PKG_VERSION")`，长耗时操作必须输出「真实命中目录 / 识别形态 / 跳过保护项 / 阶段耗时」。
5. **跨界静态防错与持久化安全门禁（`v2.2` 新增）**：
   - **1 秒静态契约检查**：`npm run check:contracts`（[check-contracts.mjs](../scripts/check-contracts.mjs)）固化 9 维静态红线（Command/参数、Event 收发、Worker D1 SQL 列名、CSS 变量、多端版本/GPL-3.0 协议、废弃文案与死页面/归档隔离、防 `sk` 裸连代理、禁 `taskkill` 强杀 Clash、关键 JSON 原子写与 PowerShell UTF-8 编码头）；
   - **防 `sk` 裸连红线**：桌面端及后端核验真实外部域名（非本机回环测试地址）时，强制要求代理地址非空；无在线 Clash 代理端口时必须直接拦截报错，严禁直连暴露本机真实公网 IP；
   - **关键 JSON 唯一临时文件原子写 + 版本锁定**：写 `~/.claude/settings.json`、`~/.claude.json`、`account-audit-cache.json`、`update-state.json` 及节点缓存时，必须使用带 `pid/seq` 的唯一临时文件 + `rename` 原子替换；更新器代理失败回退直连重检时，必须校验版本号仍等于用户已确认目标版本。

---

## 五、核心原则 5：6 维深度审查法 + 双速分级验收 + 打包前确认门禁

开发阶段即必须主动设计并覆盖**异常与边界场景**（代理离线、权限拒绝/取消 UAC、订阅脚本损坏、节点送中/超时/漂移、高并发日志心跳、重复点击、小屏超界等），并严格区分**日常迭代轻量化校验**与**发版前正式门禁**，拒绝盲目高频全量跑测试与私自打包：

### 双速分级验证策略（`v2.2` 核心机制）
| 场景阶段 | 必跑轻量化校验（秒级反馈） | 严禁擅自执行的重操作 |
| :--- | :--- | :--- |
| **日常改代码 / 修 Bug / UI 调优期间** | 1. `npm run check:contracts`（< 1 秒拦 9 维跨界低级 Bug）<br>2. `npx tsc --noEmit` + `cargo check`<br>3. 仅针对改动文件跑定向 Vitest / `cargo test <filter>` | ❌ 禁止高频盲跑全量单测<br>❌ 禁止未经允许执行 `npm run tauri build` |
| **发版前正式收敛与真机验收阶段** | 按下方 Layer 1 ~ Layer 4 逐层打勾留证 | 未全部通过或未获用户确认，严禁构建安装包 |

### 防低级 / 跨界 Bug 自检表（6 维深度审查法，替代“只靠人肉点页面”）
1. **跨端契约核对**：Rust `#[tauri::command]` 参数键 ↔ `ipc.ts`、`emit` ↔ `listen`、`diag-worker` SQL 列名 ↔ `schema.sql`；
2. **样式与废弃代码核对**：CSS `var(--*)` 全量存在、`src/pages/` 零未挂载死页面、旧页面移入 `archive/` 隔离；
3. **持久化与并发核对**：所有配置文件写盘均为带 `pid/seq` 临时文件原子替换、文件尾读截断保护、前后端异步任务防重入；
4. **安全与隐私边界核对**：敏感凭据（`sk`）禁止无代理裸连外域、更新回退锁定版本号、命令行零泄露；
5. **Windows 宿主机兼容核对**：PowerShell/子进程前置 UTF-8 编码头、提权失败错误透传（严禁 `let _ =` 吞错）、高耗时探测加缓存；
6. **真机页面实操作巡检（CDP 逐页核查）**：在真实桌面程序或开发版窗口上逐页切换、悬停气泡、弹窗开合、双主题与极端窗口尺寸对照审视。

### Layer 1：前后端全量自动化单测（仅限收敛/发版门禁）
- 前置：`npm run check:contracts` 9 维门禁 100% 通过。
- 前端：`npx tsc --noEmit` 0 错误 + `npm test -- --run` 100% 通过（新修 Bug 与联动逻辑必须补对应回归用例）。
- 后端：`cargo test`（商业版）+ `cargo test --no-default-features`（开源版）**0 警告、0 失败**。

### Layer 2：网页开发态 / CDP 逐页快速验收（`npm run dev`，秒级热更新，不走打包）
- 在浏览器实看主窗口全部活跃页面、模态弹窗、抽屉与悬浮窗，核对排版、对齐、角标、文案、交互态、异常态与 Console 0 报错。

### Layer 3：全栈真机实机验收（真实桌面程序 + 真实 Clash Verge / Mihomo / Windows 环境）
- 使用调试态或待验收窗实机逐页排查，**亲手实测并截屏审图**，逐条核验：
  - 正常主流程 + 故障注入 → 点击执行 → 生效验证 → 重载/还原持久化；
  - 真实窗口视觉（主窗尺寸、边距、边框、角标、实时节点表、悬浮窗尺寸与 RTT）；
  - 测完必须无损还原用户的原始节点与代理模式。

### Layer 4：清点任务表 + 用户确认门禁 → 最终打包与产物验真
1. **铁律：严禁未经用户确认私自执行 `npm run tauri build`！**
2. 每次完成 Layer 1~3 后，核对 [task-ledger.md](task-ledger.md) 中全部未关闭项，向用户汇报实测证据，询问是否还有遗漏/顺手改项；
3. 获用户明确同意后（确认版本号已递增且产物目录不覆盖旧包）再打包，并核验安装包版本号、大小、嵌入图标与覆盖升级行为，最后将任务表对应项更新为 `已发布关闭`。
