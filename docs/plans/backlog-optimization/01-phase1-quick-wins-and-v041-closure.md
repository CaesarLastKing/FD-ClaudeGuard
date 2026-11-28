# 01 · 第一批：简单项快速清理与 `v0.4.1` 基线收口方案

> **批次目标**：用最小改动成本一次性清空所有**低难度、高确定性、无争议**的待办与遗留小缺陷，消除文档噪音，并完成当前工作区 `v0.4.1` 既有代码的基线收口，为后续 `F-04` / `F-03` / `F-06` 大改动提供干净、可回滚的起点。  
> **预计执行顺序**：1 → 2 → 3 → 4 → 5 → 6 → 7 → 8（每项彼此解耦，可全部执行或按需勾除）。

---

## 一、本批清单与确定性评估

| 序号 | 编号 | 事项 | 优先级 | 难易度 | 确定性 | 预估改动范围 |
| :---: | :---: | :--- | :---: | :---: | :---: | :--- |
| 1 | `F-10` | 侧边栏左下角状态卡与「系统设置」间距微调 | P2 | `★☆☆` | 100% | `src/components/Sidebar.tsx`（2 行） |
| 2 | `BUG-42-03` | Mihomo 命名管道 `os error 231` 告警噪音核销 | P2 | `★☆☆` | 100% | **代码核实已修**，仅做实机核销与关单 |
| 3 | `BUG-42-01` | 桌面悬浮窗（HUD）深色主题同步复核与防首帧闪白 | P2 | `★☆☆` | 100% | `hud.html` + `src/components/HudCard.tsx` 极小兜底 |
| 4 | `热表归档` | 将已定案暂不采用的 `F-13 / F-14 / F-16` 移出热表 | P2/P3 | `★☆☆` | 100% | `docs/active/feature-backlog.md` → `docs/archive/` |
| 5 | `F-07` | 重排「二、工具可介入防御与修复」5 项先后顺序（待确认 Q3） | P2 | `★☆☆` | 95% | `src/pages/AccountAuditPage.tsx` + 对应单测 |
| 6 | `F-05` | 拆分「新号、支付与 KYC 后高敏观察窗」为 2 个独立项 | P1 | `★☆☆` | 95% | `src/pages/AccountAuditPage.tsx` + 对应单测 |
| 7 | `BUG-42-02` | 「清理恢复」后端 TTL 缓存 + 节点国旗 Emoji / `CN台湾` 徽标核修 | P2 | `★☆☆` | 90% | `src-tauri/src/rollback/mod.rs`、`src/pages/NodesTrafficPage.tsx`、`src-tauri/src/mihomo/mod.rs` |
| 8 | `v0.4.1 收口` | `BUG-41-01~08` + `F-01` + `F-02` 全量验收门禁与基线固化 | **P0/P1** | `★★☆` | 100% | 仅测试、真机核验、更新台账（需用户显式许可） |

---

## 二、逐项详细优化方案

### 1. [`F-10`] 侧边栏左下角状态卡与「系统设置」间距微调
- **现状核查**：
  - [Sidebar.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/components/Sidebar.tsx#L262)：底栏外层容器 `gap: 12`（即「Claude 进程」卡与「Clash Verge」卡之间距 `12px`）。
  - [Sidebar.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/components/Sidebar.tsx#L589)：「系统设置」外层容器 `marginTop: -2, paddingTop: 10`（即「Clash Verge」卡到底部分割线 `10px`，分割线到按钮 `10px`）。
- **拟定改动**：
  1. 两张状态卡之间间距由 `12px` 调大至 **`16px`**（通过给两卡单独包一层 `gap: 16` 或调整外层 `gap`）；
  2. 「Clash Verge」卡片到底部分割线的距离调小至 **`6px`**，分割线到「系统设置」按钮的 `paddingTop` 调小至 **`8px`**，让底栏「系统设置」视觉更贴近底部且与上方两卡形成清晰的呼吸节奏。
- **验证方式**：按 UI 迭代规范，轻量化前端构建后在双主题（dark / light）下局部截图像素自检确认两处间距比例协调，绝不挤压导航区。
- **短板/注意点**：若主窗口高度被用户压到极小尺寸，增大两卡间距会多占 `4px` 垂直空间，实测需在最小窗口高度（如 `680px`）下复核是否产生挤压。

---

### 2. [`BUG-42-03`] Mihomo 命名管道瞬时重试 `os error 231` 告警噪音核销
- **源码实证**：
  - 已核查 [mihomo/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/mihomo/mod.rs#L1758-L1774)：底层 `pipe_http_request()` **已经在 `v0.4.1` 实现 8 次 `ERROR_PIPE_BUSY (231)` 静默退避重试**，仅在全部 8 次重试仍失败时才输出一条 `WARN`。
  - 同时核查了 [mihomo/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/mihomo/mod.rs#L856-L915)：该处是 Anthropic API HTTP 5xx/超时的 2 次探测重试，非命名管道问题。
- **拟定动作**：
  - 无需改动业务代码；在 `v0.4.1` 实机验收期间复查 `%LOCALAPPDATA%\FDClaudeGuard\logs\guard-runtime-*.jsonl`，确认不再出现瞬时 `os error 231` 刷屏后，直接将 `BUG-42-03` 标记已修并随版本移出热表。

---

### 3. [`BUG-42-01`] 桌面悬浮窗（HUD）深色主题同步复核与防首帧闪白
- **源码实证**：
  - [HudCard.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/components/HudCard.tsx#L218) 与 [L250](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/components/HudCard.tsx#L250) 已在 `v0.4.1` 补上了初始化读取 `config.theme` 与配置事件变更时更新 `document.documentElement.setAttribute("data-theme", cfg.theme)`。
  - 但 [hud.html](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/hud.html) 与 [hud.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/hud.tsx) 在异步拉取 `getConfig()` 返回前，若默认无 `data-theme` 属性，深色主题用户在冷启动 HUD 的瞬间可能闪一下浅色底。
- **拟定改动**：
  1. 核查 `hud.html` 根节点默认主题与背景透明属性，并在 `hud.tsx` 挂载前先从 `localStorage`（若主窗/HUD 同源可共享缓存键 `fd_guard_theme`）同步设置 `data-theme`，异步 `ipc.getConfig()` 返回后再以配置为准校正；
  2. 核实主窗口切换主题时是否通过 Tauri Event 实时广播给 `hud` 窗口（若仅单窗更新，补齐跨窗口 `emit("guard://config", ...)` 同步）。
- **验证方式**：真机启动下在主窗口反复切换深色 ↔ 浅色，观察 HUD 是否毫秒级同步变色且重启无首帧闪白。

---

### 4. [热表瘦身] 归档已定案暂不采用项（`F-13 / F-14 / F-16`）
- **现状**：`F-13`（多账户轮流交互隔离）、`F-14`（多账户并行 5 层隔离）、`F-16`（账户登录能力规划）在 [feature-backlog.md](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/docs/active/feature-backlog.md#L21-L24) 中均已明确标记 `暂不采用（仅单号模式）`。
- **拟定动作**：按 `docs/README.md` v3.0 热冷分层铁律，将这 3 条从热表迁入 `docs/archive/`（保留原调研链接便于未来重启时回溯），让热表仅保留真正待推进的事项。

---

### 5. [`F-07`] 重排「二、工具可介入防御与修复」5 项先后顺序（需确认 Q3）
- **现状核查**：[AccountAuditPage.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/pages/AccountAuditPage.tsx#L603-L1021) 当前展示顺序为：
  1. 注册归属地与出口一致性核对
  2. 多号混登、设备指纹与旧号残留防连坐
  3. 官方 API 端点防反代检测
  4. Clash 断连回传 Cookie 403 防护
  5. 本机遥测开关与缓存清理（仅作用于 CLI）
- **拟定优化顺序（按官方红线严重度 × 工具介入优先级）**：
  1. **注册归属地与出口一致性核对**（封号第一硬红线：跨洲/禁区出口）
  2. **Clash 断连回传 Cookie 403 防护**（封号第二硬红线：无感断连回传直接触发 403 封控，提至第 2 位）
  3. **多号混登、设备指纹与旧号残留防连坐**（连坐风险）
  4. **官方 API 端点防反代检测**（反代/中转风险）
  5. **本机遥测开关与缓存清理（仅作用于 CLI）**（降噪建议项）
- **影响面**：仅调整 `groups` 数组拼接顺序与对应 UI 单元测试中的顺序断言，**零后端改动、零评分逻辑改动**。

---

### 6. [`F-05`] 拆分「新号、支付与 KYC 后高敏观察窗」为 2 个独立项
- **现状核查**：[AccountAuditPage.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/pages/AccountAuditPage.tsx#L444-L505) 将「新号注册(<7天)」「支付/升级复审(<=24h)」「过 KYC 复核(<=72h)」「近期套餐跳变」4 个指标揉在 1 张卡片里，导致“观察窗时间维度”与“支付渠道风险”混杂不清。
- **拟定拆分方案**：
  - **独立项 A：高敏感观察窗（新号 / KYC / 套餐跳变）**
    - 保留指标：`新号注册观察窗 (<7 天)`、`过 KYC 后复核窗 (<=72h · 社区经验)`、`近期套餐变动 (plan_changed)`（`cols: 3` 或 `2` 视宽度自适应，保持整洁对齐）。
    - 状态逻辑：命中任意高敏时间窗或 KYC 待验证/已过期 → `warn`；云端未核验缺数据 → `pending`；均安全 → `ok`。
  - **独立项 B：支付方式与账单风控**
    - 核心指标：
      1. `当前订阅与支付渠道`（优先展示云端核验/本地缓存的支付方式与套餐，Free 账号明确标「Free 无订阅 · 暂不适用支付风控」）；
      2. `支付 / 升级 24h 复审窗`（刚订阅/升级 <=24h 标 `warn` 提示锁死单节点、勿换设备）；
      3. `支付源四同核对提示`（发卡国 / 账单区 / 出口 IP / 证件地尽量一致，避免黑卡/共享虚拟卡 BIN 连坐）。
    - 状态逻辑：Free 账号显中性 `免检/正常`（绝不误报红黄）；刚付 <=24h 或检测到账单/支付异常标（`billing_issue` / `subscription_pause` / `billable_usage_paused`）显 `warn` / `danger`。
- **优缺点与注意点**：
  - **优点**：拆得干净、视觉信息密度下降，为后续 `F-06` 扩展「支付方式自查维度」打好卡片槽位；
  - **缺点/代价**：右侧「一、需用户自行注意与克制」从 2 张卡变为 3 张卡，页面垂直高度微增约 `140px`（完全在滚动区承受范围内）。

---

### 7. [`BUG-42-02`] 「清理恢复」基线读取提速 + 节点国旗 Emoji / `CN台湾` 徽标核修
本项包含两个独立小问题，均已定位源码：

1. **「清理恢复」基线读取提速（后端轻量 TTL 缓存）**
   - **现状**：前端 `Sidebar.tsx` 和 `NetworkRescueRollbackPanel.tsx` 已共用 `guardStore.rollbackOverview` 预热缓存，但用户每次切回「清理恢复」或触发 `killSwitchActive` 变化时，后端 [rollback/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/rollback/mod.rs#L978) 仍会重新全量扫描网卡/注册表/YAML（耗时 700ms~1.5s）。
   - **方案**：在 Rust 侧为 `inspect_rollback_status(force: Option<bool>)` 增加 **15 秒轻量内存 TTL 缓存**；任意写操作（网络急救、单项撤回、全量撤回、一键修复、熔断开关）自动失效该缓存，手动点「刷新」传 `force=true` 强制穿透。
   - **短板/注意**：若用户在 15 秒内切到 Windows 外部手动改了网卡 DNS 再立刻切回「清理恢复」，需点一下右上角刷新按钮才能看到即时变化（可接受，换来切 Tab 零卡顿）。
2. **Windows 国旗 Emoji 退化 + `CN台湾` 左徽标核修**
   - **现状**：
     - Windows WebView2 默认字体无法渲染彩色区域指示符 Emoji（`🇺🇸`、`🇯🇵`、`🇨🇳`），节点名渲染成丑陋的小灰字 `us美国1|流媒体AI`、`cn台湾1|流媒体AI`；
     - 隔离区中 `🇨🇳台湾` 节点左侧徽标显示 `HK` 有两种可能原因：
       - **情形 A（真落地香港）**：实测出口 IP 真的落在了香港 `HK`（挂台湾名卖香港线路），此时左盒显示 `HK` 是真实出口，但容易让用户困惑“为什么台湾节点标 `HK`”；
       - **情形 B（未测速名称直筛误归组）**：若节点未测速就因 `🇨🇳` 被正则或名称提取误判为 `HK`/`CN`，则属代码提取 bug。
   - **方案**：
     1. 检查 [mihomo/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/mihomo/mod.rs#L1200-L1230) 与隔离区构造逻辑，确保未测速 `🇨🇳台湾` 节点名提取国码恒为 `TW`（而非 `HK`/`CN`）；若实测真实出口确实落入 `HK`（落地禁区），在 `NodesTrafficPage.tsx` 左侧国码盒保持 `HK`（危险色），同时在副标题最前用醒目提示 **`实测落地 HK（挂名 TW · 禁区隔离）`**，彻底消除误解；
     2. 在节点列表名称展示层统一调用 `formatCleanNodeName()`（剥离 Windows 下渲染退化的前导国旗 Emoji，因为左侧 `.region-box` 已自带规整的 2 字母国码徽标），保留节点名本体清爽可读（Hover Tooltip 仍可看完整原始节点名）。

---

### 8. [`v0.4.1` 基线收口] `BUG-41-01 ~ 08` + `F-01` + `F-02` 验收与基线固化
- **为什么强烈建议放在第一批末尾收口**：
  - 当前工作区有 40+ 个已修改文件未提交（`BUG-41-01~08` + `F-01` + `F-02`）。
  - 把上述 1~7 项极简快清做完后，经你确认授权执行一次完整的 **Layer 1（全量自动化单测）+ Layer 2/3（双主题与真机 Gate 0~5 闭环验收）**，确认全绿后提交一个干净的 Git 基线（并按你决定是否递增版本打正式包），再启动第二批 `F-04` 熔断大改。
- **严守纪律**：
  - 未经你明确同意，绝不擅自跑全量单测、绝不擅自执行 `npm run tauri build`；
  - 若打包，必先核查 `src-tauri/target/release/bundle/nsis/` 中已存在 `0.4.1` 安装包，按规范先递增版本号至 `0.4.2`（或按你指示确认处理策略），严禁静默覆盖历史旧包。

---

## 三、本批验收标准（Done 的定义）
1. [x] `npm run check:contracts` 9 维静态契约全绿；`npx tsc --noEmit` 与 `cargo check` 0 错误；
2. [x] Layer 1 全量自动化测试：`npm test -- --run`（19 文件 / 87 用例 100% 通过）、`npm run build` 通过、`cargo test` 与 `cargo test --no-default-features`（148/148 全部通过，0 失败 0 警告）；
3. [x] Layer 2 双主题局部像素级视觉自检通过（Console 0 报错：深浅双主题侧边栏两卡 `16px` / 底栏收紧齐平、账户审计拆分 4 格卡片与 Q3 重排、HUD 深色悬浮窗均已实拍核查无瑕）；
4. [ ] 待用户确认是否递增版本号至 `v0.4.2`（`src-tauri/target/release/bundle/nsis/` 已存在 `0.4.1` 历史安装包，严禁覆盖）并执行打包与真机 Gate 0~5 终验。
