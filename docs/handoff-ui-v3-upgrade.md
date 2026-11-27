# FD Claude 安全启动器 · UI v3.0 商业级视觉升级开发交接文档与执行提示词

> **文档角色**：本次已完成视觉封板的 **「全站 UI 基建 + 账户审计 + 控制台 + 节点流量（质量与实时流量）」** 转化为生产代码落地的**唯一开发交接真源**。  
> **配套权威规范**：[docs/ui-design-system.md](./ui-design-system.md)（v3.0 终稿）  
> **定稿 1:1 交互原型（已归档在仓库内，开工前必读）**：
> 1. 账户审计：[docs/mockups/ui-v3-audit-final.html](./mockups/ui-v3-audit-final.html)
> 2. 控制台：[docs/mockups/ui-v3-console-final.html](./mockups/ui-v3-console-final.html)
> 3. 节点流量：[docs/mockups/ui-v3-nodes-final.html](./mockups/ui-v3-nodes-final.html)
>
> **不在本次视觉重构范围内（严禁擅自大改布局）**：`MaintenancePage.tsx`（环境维护）、`SettingsPage.tsx`（守卫配置）、`HudApp.tsx`（悬浮窗）。这两页的专项重构将在下一批次出图确认后再做；本次只需确保它们在继承新的全局 CSS Token 后保持清晰可读、零样式崩坏。

---

## 0. 仓库当前基线与绝对防冲突红线（开工第一秒必读！）

1. **当前工作区状态（极重要）**：
   - 当前 Git HEAD 为 `bd57072`，工作区中已存在 **v0.3.5 Clash 规则加固的未提交改动**（涉及 `package.json`、`src-tauri/src/killswitch/mod.rs`、`src-tauri/src/mihomo/mod.rs`、`src-tauri/src/preflight/mod.rs`、`src-tauri/src/lib.rs`、`src/pages/NodesTrafficPage.tsx`、`src/__tests__/v035_clash_hardening.test.tsx` 等）。
   - **严禁执行 `git checkout`、`git reset`、`git clean` 或覆盖未提交的 v0.3.5 业务逻辑**！一切改动必须在当前工作树基础上小心增量完成。
2. **严禁擅自改动已定稿设计**：
   - 如开发中发现原型与后端真实数据存在歧义、测试断言冲突或边界态缺失，**禁止自行脑补改设计**，必须列出《待确认问题清单》（场景、根因、方案利弊）汇报给用户确认。
3. **保护全部既有测试契约（`data-testid` 与核心业务）**：
   - `src/__tests__/` 下已有 `v023` ~ `v035` 多套 Vitest 回归测试。重构组件 DOM 时，必须尽量保留既有 `data-testid`（如 `window-chrome`、`nav-badge-nodes`、`btn-filter-unlisted-domains`、`conn-purpose-*`、`btn-reprobe-node-*` 等）；若因交互结构变化（如移除单行「重测」改按类型批量重测、移除控制台页头「安全守则」按钮）导致旧测试需要同步更新，必须在汇报中逐条明示原因并补齐新单测。
4. **必须保留 3 处“文档高于旧原型”的终审覆盖点**：
   - **覆盖点 A（全局色板）**：`ui-v3-audit-final.html` 中早期的绿红色变量，生产落地一律统一使用 [docs/ui-design-system.md](./ui-design-system.md) **2.2 节** 最终封板的**浅色莫兰迪苔绿/柔丹红 + 暗色 v5.7 压暗柔化**色板。
   - **覆盖点 B（控制台必须项计数文案）**：`ui-v3-console-final.html` 中的 `已通过 10/12` 按用户最终拍板改为 **`通过 {mustOk}/{mustAll.length} 后安全启动`**；当 `mustOk === mustAll.length`（打满）时数字不加彩色，未打满时**仅数字 `X/Y` 标 `--bad-fg` 柔丹红**，不加红框胶囊。
   - **覆盖点 C（节点页 Mihomo 管道防歧义文案）**：`ui-v3-nodes-final.html` 第 4 格中的“管道已直连”在生产代码中必须沿用防歧义规范写 **`管道已连接`**（防止用户误解为 `DIRECT` 裸连），副行保持 `Claude-Fixed · v1.19.33 · :7890`（取真实动态版本/端口与策略组名）。

---

## 1. 本次开发转化总览（5 大模块清单）

| 里程碑 | 涉及文件 | 核心交付目标 | 强验证门禁 |
| :---: | :--- | :--- | :--- |
| **M1** | `src/styles/theme.css`<br>`src/components/WindowChrome.tsx`<br>`src/components/Sidebar.tsx`<br>`src/components/ThinScrollArea.tsx`（新增）<br>`src/components/HoverTooltip.tsx`（新增） | 升级全站双主题 Token（浅莫兰迪 / 暗 v5.7）、`FD-Fine` 纤细字阶、微色差 6 层表面、柔和冷灰圆头短竖条选中态、统一按钮/胶囊、自定义 `3×46px` 悬浮细滑块与 `0ms` 悬停气泡组件、壳层顶栏与侧边栏同步精修 | `tsc --noEmit` 0 错 + 存量页双主题抽查无崩坏 |
| **M2** | `src/styles/account-audit.css`<br>`src/pages/AccountAuditPage.tsx` | 1:1 对齐 `ui-v3-audit-final.html` 视觉与展开态（冰蓝雾展开底、7 项结构化子卡、防封宝典白皮书去套娃、顶部 4 格正常态绿点+主文字），全面接入 M1 最终红绿色板与 `ThinScrollArea` | `vitest run` 全绿 + 双主题真机截图核验 |
| **M3** | `src/pages/ConsolePage.tsx` | 1:1 对齐 `ui-v3-console-final.html` + 终审微调（去页头安全守则按钮、保留原位守护状态灯、`通过 X/Y 后安全启动` 配色规则、详情去重复状态胶囊与精简文案、异常行降噪、全态统一边框按钮、双栏独立 `3×46px` 细滑块） | `vitest run` 全绿 + 多态（全绿/1 待办/多待办/熔断）截图核验 |
| **M4** | `src-tauri/src/lib.rs`<br>`src-tauri/src/mihomo/mod.rs`<br>`src-tauri/src/killswitch/mod.rs`<br>`src/types/guard.ts`<br>`src/lib/ipc.ts`<br>`src/stores/guardStore.ts`<br>`src/pages/NodesTrafficPage.tsx` | **后端 2 项轻量增量**：① `start_deep_node_audit` 兼容支持按分类/节点列表批量重测；② `ClaudeConn` 补传建连时间戳 `startedAtMs`（或 `durationSecs`）用于实时计算连接持续时长。<br>**前端深度重构**：单列全宽通透布局、节点质量 4 段统计条 + 分类胶囊 + 按类型批量重测 + 6 列实宽等距表；实时流量 4 等分统计条 + 7 列实宽等距合并表（去 `:443`、意图直出、规则去重、隐藏常规 `Claude-Fixed`、实时持续时长） | `cargo test` 0 警告 + 新增 Rust/Vitest 单测 + 双主题双子页截图逐列验间距 |
| **M5** | 全仓 QA 与回归 | 跑通全量 `tsc`、`vitest`、`vite build`、`cargo test`，在 `1280×800` 与 `1360×900` 浅/暗双主题下真实渲染截图自检并输出验收报告（**本次不触发发版打包，除非用户另行要求**） | 18 项 QA 门禁逐项实证打钩 |

---

## 2. 逐模块详细开发改造规格

### M1：全站样式基础层、通用微组件与窗口壳层

#### 1. `src/styles/theme.css`（重构唯一样式真源）
- 新增 `@font-face` 定义 `FD-Fine`（`400` 映射 Semilight/DemiLight/Light，`500` 映射 Regular），在 `html, body` 上启用 `font-synthesis: none; font-weight: 400;`。
- 完整落地 [docs/ui-design-system.md](./ui-design-system.md) 2.2 节的 `[data-theme="light"]`（莫兰迪苔绿 / 柔丹红）与 `[data-theme="dark"]`（v5.7 压暗柔化）两套完整变量。
- **向后兼容映射（必做，防存量页面失色）**：
  - `--success: var(--ok-fg)` / `--success-soft: var(--ok-bg)`
  - `--danger: var(--bad-dot)` / `--danger-bright: var(--bad-fg)` / `--danger-soft: var(--bad-bg)`
  - `--warning: var(--warning-fg)`
  - `--border: var(--border-card)` / `--border-strong: var(--divider-strong)`
  - `--card-shadow: var(--shadow-card)` / `--bg-selected: var(--sel-bar-bg)`
- 同步升级公共样式类：
  - `.guard-card`（单层 `1px solid var(--border-card)` + `var(--r-card: 10px)` + `var(--shadow-card)`）；
  - `.guard-btn` / `.guard-btn-primary` / `.guard-btn-flat` / `.guard-btn-danger-soft` / `.guard-btn-xs`（统一高度 `31px` / `25px`、圆角 `7px` / `6px`、纤细 `400/500` 字重、微阴影）；
  - `.guard-chip` 系列（`21px` 高、`5px` 圆角、带 `1px` 柔和语义描边，新增 `.guard-chip-pass` 供列表低调「已通过」使用）；
  - `.guard-row.selected`：移除旧版生硬 `inset 2.5px 0 0 var(--text-1)`，改为 `::before` **左侧柔和冷灰圆头短竖条**（`left: 4.5px; width: 2.5px; height: 19px; border-radius: 99px; background: var(--sel-bar-color)`）+ `background: var(--sel-bar-bg)`；
  - 统一新增一体化 4 段统计条基础类 `.metric-strip-nodes`、`.metric-strip-equal`、`.metric-cell` 与分段切换器 `.in-seg` / `.filter-tab`。

#### 2. 新增公共微组件（零重依赖、全站复用）
- **`src/components/ThinScrollArea.tsx`**：
  - 封装与原型 1:1 一致的自定义悬浮极细短滑块（隐藏原生滚动条，右侧 `5px` 放置 `3×46px` 圆头细滑块，静默 `--thumb-idle` / 悬停与滚动 `--thumb-active` / 拖拽宽 `4px`）；
  - **关键工程健壮性**：必须使用 `ResizeObserver` + `MutationObserver` 监听内部滚动高度变化（避免切换 Tab、展开手风琴或异步数据到达后滑块位置/显隐滞后），且不阻断鼠标滚轮、触控板与键盘方向键滚动。
- **`src/components/HoverTooltip.tsx`**（或 Hook `useHoverTooltip`）：
  - 封装 `0ms` 即时浮现的固定定位解释气泡（`position: fixed; z-index: 9999; max-width: 288px; white-space: pre-line; pointer-events: none`），自动判断 `rect.top < 140` 决定朝下或朝上弹出，滚动时自动隐藏，供节点流量与账户审计共用。

#### 3. `src/components/WindowChrome.tsx` 与 `src/components/Sidebar.tsx`
- **`WindowChrome.tsx`**：背景改用 `var(--bg-chrome)`、底部描边 `var(--divider)`；图标大小与字阶向 v3.0 对齐（`17px` 品牌图、`12.5px` 标题、`28×25px` 纯图标键、线宽 `1.4~1.5`）；保留全部窗口拖拽、双击最大化、新版本徽标与 `data-testid`。
- **`Sidebar.tsx`**：宽度升级至 `212px`，背景 `var(--bg-sidebar)`，右描边 `var(--divider)`；导航项高 `33px`、字号 `12.5px`、激活底色 `var(--bg-nav-active)`；左下角「Claude 进程」「Clash Verge」状态卡改用微间距紧凑卡样式，保留全部 Kill-Hold `45s` 蓝态、脉冲闪烁与强杀逻辑。

---

### M2：账户审计页视觉与展开态精修

- **涉及文件**：`src/styles/account-audit.css`、`src/pages/AccountAuditPage.tsx`
- **对照原型**：`docs/mockups/ui-v3-audit-final.html`（叠加 2.2 节最终莫兰迪/v5.7 红绿色板）
- **核心改动**：
  1. 将 `account-audit.css` 中的硬编码色值（如过亮绿/红、旧灰底）全面切换为 `theme.css` v3.0 Token，确保与控制台、节点流量视觉 100% 一体；
  2. 落实展开态防撞灰：`--bg-row-open`（冰蓝雾底）+ `--border-row-open` + 内部子指标卡片 `--bg-card`，与 `--bg-canvas` 彻底划界；
  3. 核查全部 7 项手风琴展开内容，确保每项展开均具备完整的结构化子指标卡、说明与操作位（不出现空旷单行）；
  4. 顶部 4 格纯云端状态栏核查：正常态一律绿点 + `--text-strong`/`--text-1` 主文字，仅异常/警告项文字上色；
  5. 滚动容器接入 `ThinScrollArea`（左栏、右栏、防封宝典抽屉均告别原生粗灰条）；
  6. 保持所有云端只读核验、`sk` 正则提取与清零、7 天衰减缓存、100 分评分逻辑与「实时异常日志流」子页 100% 功能不变。

---

### M3：控制台页 1:1 精修落地

- **涉及文件**：`src/pages/ConsolePage.tsx`
- **对照原型**：`docs/mockups/ui-v3-console-final.html` + 终审微调（覆盖点 B）
- **核心改动**：
  1. **页头精简**：
     - 高度 `58px`，背景 `var(--bg-header)`，标题 `16.5px / 500` 与精简副标题同排；
     - **移除页头「安全守则」按钮**（保留 `PlaybookDrawer` 组件供日志页/异常定位等其他入口唤起，不删抽屉本身）；
     - 保留原位状态指示（`● 守护正常` / `● N 项待办` / `● 节点不可用` / `● 已自动熔断`）+ `重新实测` + 一屏唯一主蓝 CTA。
  2. **左侧必须项汇总文案（严格按终审拍板）**：
     - 「一、必须通过」标题右侧展示：**`通过 {mustOk}/{mustAll.length} 后安全启动`**；
     - 样式逻辑：
       - 若 `mustOk === mustAll.length`：整句均为 `--text-3`，数字不加彩色；
       - 若 `mustOk < mustAll.length`：仅 `{mustOk}/{mustAll.length}` 着色为 `var(--bad-fg)`（不加背景框/红边框胶囊），其余文字为 `--text-3`。
  3. **列表项降噪与选中态**：
     - 选中行统一使用柔和冷灰圆头短竖条（`2.5×19px`）+ 极淡底色；
     - 异常行不铺粉红整行底、标题不额外加粗；
     - 右侧「已通过」胶囊采用低压迫 `--pass-fg / --pass-bg / --pass-border`，异常采用 `--bad-*` / `--warning-*`。
  4. **右侧详情卡精修**：
     - **移除详情头右上角重复的状态胶囊**（状态信息合并在副标题/引导文案中，精简直观）；
     - 实测值卡片保持中性 `--text-1`（异常时不整段染红），去掉冗余的悬停复制小图标；
     - 底部排障操作（`导出脱敏诊断包`）始终使用标准边框按钮 `.guard-btn.guard-btn-flat`，严禁退化成裸文字链接；
     - 核心修复按钮始终保持一致的主蓝 `.guard-btn-primary`（不再在多异常时变成深灰黑高反差块）。
  5. **左右双栏独立接入 `ThinScrollArea`**（3×46px 悬浮细滑块），同时完整保留未激活/全部真实探针、全量巡检倒计时、单号卫生锁确认弹窗与 Kill-Hold 联动逻辑。

---

### M4：节点流量页深度重构 + 2 处轻量后端增强

#### A. 后端轻量增强（必须保持 100% 向后兼容）

1. **增强 ①：`start_deep_node_audit` 支持按分类/节点列表批量重测**
   - 涉及文件：`src-tauri/src/lib.rs`（`start_deep_node_audit` / `spawn_deep_node_audit_task`）、`src-tauri/src/mihomo/mod.rs`、`src/lib/ipc.ts`、`src/stores/guardStore.ts`
   - 现状：`start_deep_node_audit(force_all: Option<bool>, target_node: Option<String>)` 目前仅支持全量或单节点重测。
   - 改造方案：向后兼容新增可选参数 **`target_nodes: Option<Vec<String>>`**（若前端传入非空列表，后端只对该子集依次执行深度核验并上报 `DeepAuditProgress`，且 `force_all = true` 跳过该子集缓存；保留旧参数 `target_node` 兼容既有测试与调用）。
   - 前端映射：
     - 在「可用节点」Tab 点 `重测可用节点` → 传入当前所有可用节点名列表；
     - 在「同区热备」Tab 点 `重测同区热备` → 传入同区可用节点名列表；
     - 在「隔离区」Tab 点 `重测隔离区` → 传入全部隔离节点名列表；点 `重测超时类` → 仅传入 `claudeStatus === "offline"`（超时类）节点名列表。
   - 同步补 1 个 Rust 单测验证 `target_nodes` 子集过滤逻辑。

2. **增强 ②：`ClaudeConn` 补传建连毫秒时间戳以实时计算持续时长**
   - 涉及文件：`src-tauri/src/killswitch/mod.rs`、`src/types/guard.ts`
   - 现状：`src-tauri/src/killswitch/mod.rs` 第 403–408 行目前仅对 Mihomo `/connections` 的 RFC3339 `start` 字段切片取了 `HH:MM:SS`（存入 `time`）。
   - 改造方案：保留 `time: String` 字段不变（向后兼容旧测试），新增可选字段：
     ```rust
     /// 建连 Unix 毫秒时间戳（由 Mihomo RFC3339 `start` 解析，供前端实时计算连接持续时长）
     #[serde(default)]
     pub started_at_ms: Option<i64>,
     ```
     在 Rust 侧使用 `chrono::DateTime::parse_from_rfc3339`（检查 `Cargo.toml` 是否已有 `chrono`，已有则直接用，没有则写轻量零依赖 RFC3339 解析函数）算出毫秒时间戳；前端 `ClaudeConn` 新增 `startedAtMs?: number`。
   - 前端每秒 `setInterval` 原地刷新 `Math.max(0, Math.floor((now - startedAtMs) / 1000))` 格式化为 `14s` / `15m 47s` / `1h 04m`（若为 `REJECT` 阻断连接则固定显示 `已阻断`；若缺少 `startedAtMs` 则优雅兜底回退显示 `c.time`）；悬停气泡展示 `建连时刻：{c.time}` 与累计流量。
   - 同步补 1 个 Rust 单测验证 RFC3339 `start` → `started_at_ms` 解析（含带纳秒小数位与 `Z` / `+08:00` 时区场景）。

#### B. 前端深度重构：`src/pages/NodesTrafficPage.tsx`
- **对照原型**：`docs/mockups/ui-v3-nodes-final.html`（+ 覆盖点 C：`管道已连接`）
- **全面清理旧版内联样式**，全部改为规范的 CSS 类与 `theme.css` 变量，整体采用单列全宽通透布局 + `ThinScrollArea` + `HoverTooltip`：
  1. **页头（`58px`）**：左 `节点流量` + 简短副标题；右动态操作组（质量页：`深度核验全部`/`核验中 X/Y · 停止` + `刷新列表`；流量页：`全部已处理`（有未确认异常时显示）+ `刷新连接`）+ 竖线 + 分段切换器（`节点质量与容灾` | `实时流量分析`）。
  2. **子页 A：节点质量与容灾**：
     - 顶部 4 段一体化统计条（`.metric-strip-nodes`）：4 格顶线齐平，`Claude-Fixed` 归位至第 4 格 `Mihomo 管道` 副行，状态文案为 **`管道已连接`**（未连接时标红 `管道未连接`）；
     - 过滤胶囊：`可用节点 (N)` / `同区热备 (N)` / `隔离区 (N)` + 右侧按类型批量重测按钮（**彻底移除每行单独的「重测」按钮**）；
     - 6 列实宽紧贴 + `space-between` 等距列表（`238px 136px 104px 160px 114px 76px`）：全部数据直出（无点击展开抽屉），当前锁定行左侧带柔和冷灰短竖条，全部风控标签与稳定性带 `0ms` 悬停解释，保留全部同区/跨洲/冷静期 `requestSwitch` 弹窗逻辑。
  3. **子页 B：实时流量分析**：
     - 顶部严格 4 等分统计条（`.metric-strip-equal`）：`12h 未确认异常` | `活跃安全连接` | `Claude 总连接` | `锁定策略组`；
     - 过滤胶囊：`全部连接 (N)` / `仅看异常 (N)` / `遥测拦截 (N)`（存在 `unlistedDomainCount > 0` 时保留 `未收录新域 (N)` 及 `data-testid="btn-filter-unlisted-domains"`）；
     - 7 列实宽紧贴 + `space-between` 等距列表（`164px 140px 66px 76px 108px 66px 48px`）：
       - **目标 / 进程**：合并 `host` 与 `process`，使用 `formatDisplayHost` 自动省略 `:443`（非 443 端口保留），禁用等宽字体改用 `FD-Fine`；
       - **链路意图**：主行 `c.purposeLabel`、副行精炼摘要（或截断 `c.purposeDetail`），悬停看完整 `c.purposeDetail`，保留 `data-testid="conn-purpose-${c.id}"`；
       - **状态**：`脱组风险`（未确认异常）/ `已确认`（已确认异常）/ `已拦截`（`REJECT` 防回传）/ `安全放行`；
       - **命中规则**：将 Mihomo 原始 `rule` 映射为简洁中文标签（如 `DomainSuffix` → `域名规则` / 防回传态 → `防回传拦截`、`ProcessName` → `进程兜底`、`Match` → `兜底直连`）+ 副行原始规则类型码（不重复抄写主机域名），悬停看完整原始规则；
       - **出口 / 异常链路**：解析 `c.chain`（按 `→` 拆分），**正常经 `Claude-Fixed` 放行的连接默认省略 `Claude-Fixed` 前缀只显示最终落地节点**；**异常连接标红展示真实异常路径与副注（如 `DIRECT` / `脱出 Claude-Fixed`）**，遥测拦截展示 `REJECT-DROP` / `防回传已阻断`；悬停看完整原始 `c.chain`；
       - **时长 / 流量**：**左对齐与表头齐平**，主行实时持续时长（或 `已阻断`），副行 `c.bytesLabel`，悬停看建连时刻 `c.time`；
       - **操作**：右对齐 `掐断` 按钮（保留 `closingConnId` 加载防连点）。

---

## 3. 客观风险、边界与避坑提示（先亮短板）

开发 AI 在落地前必须清楚以下 5 个真实技术坑点并提前做好防护：

1. **窄窗口下的 7 列实时流量宽度溢出风险**：
   - `164 + 140 + 66 + 76 + 108 + 66 + 48 = 668px`，加上 `6 × 12px` 最小列间距需要 `740px` 卡片净宽（即桌面窗口宽 `≥ 1030px`）。
   - **防护措施**：若用户把 Tauri 窗口拖窄到 `< 1030px`，给列表卡片包一层 `overflow-x: auto`（或 `@media` 适度收缩前两列宽），防止最右侧「掐断」按钮被裁切。
2. **自定义 `ThinScrollArea` 的高度同步与可访问性坑**：
   - 仅监听 `window.resize` 会导致切换子 Tab 或展开账户审计手风琴时滑块不更新。
   - **防护措施**：必须同时绑定 `ResizeObserver`（监听容器和内容元素）并在 React `children` 变更时触发一次 `requestAnimationFrame(sync)`。
3. **旧 Vitest 单测断言同步成本**：
   - 既有测试（如 `v023_ui.test.tsx`、`v032_audit_node_fixes.test.tsx`、`v035_clash_hardening.test.tsx`）可能断言了旧文本（如单行 `btn-reprobe-node-*`、旧控制台「安全守则」按钮或旧规则字符串）。
   - **防护措施**：运行 `npm test` 逐一核对失败用例，区分“真 Bug”与“预期 UI 升级导致的旧断言过时”；仅更新确实因本次已定稿设计变更而过时的断言，并在交接验收报告中逐条列出。
4. **存量未改页面（环境维护 / 守卫配置）的视觉过渡落差**：
   - 本次只改全局 Token + 前 3 页，后 2 页暂未重排布局，短时间内可能出现卡片间距/内联字重略不一致。
   - **防护措施**：严格通过 `theme.css` 兼容变量映射保证后 2 页在浅/暗双主题下文字、按钮、开关、报错框全部高可读零崩坏，严禁顺手擅自重构后 2 页。
5. **Rust 后端 `start` 时间戳解析边界**：
   - Mihomo 不同版本的 `start` 字段可能包含 9 位纳秒精度或本地时区偏移（如 `+08:00`），且极端情况下系统时钟微调可能出现 `now < started_at_ms`。
   - **防护措施**：后端用成熟 RFC3339 解析（解析失败优雅返回 `None` 不 panic），前端做 `Math.max(0, ...)` 钳制与 `c.time` 回退兜底。

---

## 4. 可直接复制交给开发 AI 的完整任务提示词

> 将下方分隔线内的完整内容直接复制给接手开发的 AI 即可开始按里程碑严格落地。

---

```markdown
你现在接手「FD Claude 安全启动器（FDTools）」的 **UI v3.0 商业级视觉升级工程落地任务**（工作区：`<WORKSPACE>`）。

### 一、开工前必读真源（先完整阅读后再写任何代码）
1. 全局 UI 规范 v3.0：`docs/ui-design-system.md`
2. 完整开发交接文档与模块改造清单：`docs/handoff-ui-v3-upgrade.md`
3. 已封板 1:1 交互原型（均已归档在仓库内）：
   - 账户审计：`docs/mockups/ui-v3-audit-final.html`
   - 控制台：`docs/mockups/ui-v3-console-final.html`
   - 节点流量：`docs/mockups/ui-v3-nodes-final.html`
4. 历史防坑日志：`docs/dev-issues-log.md`

### 二、绝对红线与边界约束
1. **保护工作区未提交代码**：当前工作区包含 v0.3.5 Clash 规则加固的未提交改动，**严禁执行 `git checkout` / `git reset` / `git clean` 或破坏任何既有防封业务逻辑**。
2. **严格遵守本次改造边界**：
   - 本次落地范围：**M1 全局样式令牌与公共微组件/壳层 + M2 账户审计页 + M3 控制台页 + M4 节点流量页（含 2 处向后兼容 Rust 轻量增量）+ M5 全量测试与真机截图验收**；
   - **严禁擅自大改** `MaintenancePage.tsx`（环境维护）、`SettingsPage.tsx`（守卫配置）与 `HudApp.tsx`（悬浮窗）的布局结构，仅确保其通过 `theme.css` 兼容变量平滑继承新双主题色板且可读无错。
3. **强制遵循 3 处终审覆盖点（以 `docs/ui-design-system.md` v3.0 与 `docs/handoff-ui-v3-upgrade.md` 为准）**：
   - 全站红绿色板统一采用 **浅色莫兰迪苔绿/柔丹红 + 暗色 v5.7 压暗柔化**（覆盖 `ui-v3-audit-final.html` 早期绿红）；
   - 控制台左侧「一、必须通过」右侧统一显示 **`通过 {mustOk}/{mustAll.length} 后安全启动`**（打满无色、未打满仅数字 `X/Y` 标 `--bad-fg` 柔丹红、不加红框胶囊）；
   - 节点流量页第 4 格 Mihomo 管道状态文字沿用防歧义文案 **`管道已连接`**（严禁写“已直连”），副行归位显示策略组 `Claude-Fixed` + 版本 + 端口。
4. **禁止脑补与先斩后奏**：遇到任何规范未覆盖的边界、接口歧义或与 v0.3.5 代码冲突处，先暂停并输出《待确认问题清单》（含根因与备选方案利弊），确认后再改。

### 三、强制分里程碑执行与真实验收纪律（禁止口头验收）
请严格按 `docs/handoff-ui-v3-upgrade.md` 中定义的 **M1 → M2 → M3 → M4 → M5** 顺序推进，**每完成一个里程碑，输出简洁进度摘要并附上真实命令执行结果**，全部完成后执行 M5 终审验收：
- **M1**：更新 `src/styles/theme.css`（含 `FD-Fine` 字体、双主题新色板、兼容别名、冷灰圆头短竖条选中态、统计条与等距列表基类），新增 `src/components/ThinScrollArea.tsx`（`3×46px` 悬浮细滑块 + `ResizeObserver` 同步）与 `src/components/HoverTooltip.tsx`（`0ms` 悬停解释气泡），精修 `WindowChrome.tsx` 与 `Sidebar.tsx`。
- **M2**：按 `ui-v3-audit-final.html` + 最终双主题色板精修 `src/styles/account-audit.css` 与 `src/pages/AccountAuditPage.tsx`（冰蓝雾展开态、7 项结构化子卡、防封宝典去套娃、接入 `ThinScrollArea`）。
- **M3**：按 `ui-v3-console-final.html` + 终审微调精修 `src/pages/ConsolePage.tsx`（去页头安全守则按钮、保留原位守护状态灯、`通过 X/Y 后安全启动`、详情去重复状态胶囊、异常行降噪、全态统一边框按钮、双栏独立 `ThinScrollArea`）。
- **M4**：
  - 后端 2 项向后兼容增量：① `start_deep_node_audit` 新增可选 `target_nodes: Option<Vec<String>>` 支持按分类批量重测并补 Rust 单测；② `ClaudeConn` 新增 `started_at_ms: Option<i64>`（由 Mihomo RFC3339 `start` 解析）并补 Rust 单测；
  - 前端按 `ui-v3-nodes-final.html` 重构 `src/pages/NodesTrafficPage.tsx`（单列全宽、节点质量 4 段统计条 + 分类胶囊 + 按类型重测 + 6 列实宽等距表；实时流量 4 等分统计条 + 7 列实宽等距合并表：主机进程合并去 `:443`、直出 `purposeLabel/purposeDetail` 链路意图、规则去重复域名、常规隐藏 `Claude-Fixed` 仅异常/阻断显示异常链路、左对齐实时持续时长）。
- **M5（强制自动化 + 真实渲染截图终审）**：
  1. 实跑并贴出原始通过摘要：`npx tsc --noEmit`、`npm test`、`npm run build`、`cargo test`（均须 0 错误 0 警告；若因已定稿 UI 变更调整了旧测试断言，必须逐条说明原因）；
  2. 启动前端预览并用真实浏览器在标准桌面宽（`1280×800` / `1360×900`）下对 **浅色 / 暗色 × 账户审计 / 控制台 / 节点质量 / 实时流量** 实际截图并逐张肉眼核验：确认零 `console.error`、无大白沟左松右紧、无文字折行溢出、暗色护眼无荧光、存量「环境维护 / 守卫配置」双主题可读；
  3. 本次只完成代码开发与测试验收，**不要擅自修改版本号或执行打包发布**，待我最终复核后再安排打包。
```
