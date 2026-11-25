# FD Claude 安全启动器（v0.3.0）开发实施计划与完整交接文档

> **文档角色**：本项目下一阶段（`T-058` 账户审计 + 控制台同源联动 + `T-059` 自动更新 → `v0.3.0` 发版）的**唯一工程实施与交接真源**。  
> **当前仓库基线**：分支 `main`，commit `f92e0b7`（`v0.2.9` 免费开源无商业锁版本，Rust 67/67 0 警告 + Vitest 39/39 全过）。  
> **视觉定稿真源（已获用户终审确认）**：[docs/mockups/client-audit-v030-v12-final.html](./mockups/client-audit-v030-v12-final.html)  
> **配套必读规范**：
> - [docs/ui-design-system.md](./ui-design-system.md)（特别注意 **7.2 节** 新沉淀的 8 条红线）
> - [docs/design-lessons-and-reflections.md](./design-lessons-and-reflections.md)（**必读！** 12 轮打磨沉淀的 10 条产品与架构深度反思，防踩旧坑）
> - [docs/research/01-local-config-audit-and-403-disambiguation.md](./research/01-local-config-audit-and-403-disambiguation.md)（6 条 `ProfileContext` 防返工契约）
> - [docs/research/03-claude-web-session-probe-findings.md](./research/03-claude-web-session-probe-findings.md)（`sessionKey` 只读协议实测真源）
> - [docs/todo-v029-oss-and-audit.md](./todo-v029-oss-and-audit.md)（项目待办总表）

---

## 0. 给接手开发 AI 的强制协作守则与零应付开发流程（开工前必读）

1. **严禁擅自拍脑袋或私自改设计**：视觉、布局、文案语气与交互已历经 12 轮打磨定稿于 `v12`。如在编码过程中发现任何**需求歧义、接口返回异常、数据结构冲突、破坏性系统写操作取舍、或规范未覆盖的边界态**，**严禁自行假设并强行落地**，必须将全部问题整理为结构化《待确认问题清单》（含：具体场景、根因、备选方案及优缺点对比）交由用户转问原设计方确认后再动工。
2. **禁止制造“效果图与实现两张皮”**：必须 1:1 遵循 `v12` 视觉结构、控制台真实行高（`padding: 11px 14px`、`14px` 标题、`12px` 副标、`30×30` 灰色图标块）与深/浅双主题 CSS 变量（`src/styles/theme.css`）。
3. **强制严格开发 → 测试 → 验收全闭环（绝不允许应付、跳步或口头验收！）**：
   - 必须拆分为以下 **5 个硬里程碑** 依次交付，**每一个里程碑完成后必须向用户出示真实可复核证据**（命令原始输出、通过用例数与 0 warning、真机正反向实测日志、真实渲染 1:1 审图结论），绝不允许“改完直接说已完成”或“只测读不测修”：
     - **M1（后端核心与纯函数单测）**：落地 `account_audit/`（本地扫描、7 类 403 消歧、100 分纯函数评分、外部 `check-sk` 脱敏 API 契约 DTO、自适应脱敏邮箱），补齐 Rust 单测并实跑 `cargo test` 0 警告；
     - **M2（云端只读核验 + 控制台/维护同源改造）**：落地按需 `sessionKey` 只读探针（`orgId` 防串号 + 60s 冷却锁 + 7 天衰减缓存）、控制台 3 项同源升级 + `claude_endpoint` 新增、环境维护 CLI 原子备份清理与 `settings.json` First-Write-Wins 可撤回基线；**必须完成真机「初始态 → 正向修复验证生效 → 反向撤回 100% 干净还原」双向闭环实测**；
     - **M3（前端 `v12` 1:1 落地与双主题 QA）**：完成 `AccountAuditPage`（含白皮书级防封宝典、折叠权重表、实时异常日志流）、左侧导航与 HUD 跳转联动；实跑 `tsc --noEmit` + `vitest` + `vite build` 0 警告，并在深/浅双主题下做真实组件渲染审图确认 0 截断、0 套娃、0 设计术语泄漏、`console.error === 0`；
     - **M4（`T-059` 自动更新）**：接入 `tauri-plugin-updater`（已校验公钥）+ `.github/workflows/release.yml` 签名发布流水线与前端检查更新 UI；
     - **M5（Gate 0 ~ Gate 5 全量质检与 `v0.3.0` 发版）**：同步三处版本号至 `0.3.0`、更新 `CHANGELOG.md` 与待办表、过齐 6 道硬门禁后再构建安装包并推送。

---

## 1. 产品设计定稿规范（严格对齐 `v12`）

### 1.1 主导航与路由变更
- 左侧主导航顺序升级为：**`控制台` → `账户审计` → `节点流量` → `环境维护` → `守卫配置`**。
- 原「日志分析」独立页并入「账户审计」作为第 2 分段 **`实时异常日志流`**（前端 `NavTab` 可兼容旧 `"logs"` 别名映射至 `"audit"` + `subTab: "logs"`，防止悬浮窗 HUD 与托盘旧跳转逻辑断链）。
- 悬浮窗 HUD 与托盘中所有指向日志异常的快捷跳转，统一路由到 `账户审计 → 实时异常日志流`。

### 1.2 账户审计页整体双栏骨架（Master-Detail）
- **页头（`.page-hd`）**：
  - 标题：`账户审计`；副标题：`本地只读体检与按需云端核验，提前排查账号风控隐患`；
  - 右侧控制组从左到右严格为：**蓝色文档型按钮 `📖 防封宝典`** | **分段切换器 `账号安全审计` / `实时异常日志流 (N)`** | **平铺按钮 `重新审计`**。
- **左栏（宽 `244px`）**：
  - 标题栏：`当前档案 (1)` + 右侧静默字 `本机激活`（**严禁放置无实质功能的空壳 `+ 多账户` 按钮**）；
  - **极简账户卡片**（已按终稿大幅瘦身）：
    - 第 1 行：状态点 + **高辨识自适应脱敏邮箱**（见 3.4 节规则，如 `stev***88@gmail.com`）+ 右侧套餐标签（`Pro` / `Max` / `Free`）；
    - 第 2 行：左侧 `属地待核 · 出口 US` / `归属 US · 出口 US` / `归属 US · 出口 SYD`（错配时整句变柔红 `--danger-bright`），**右侧直接显示精简更新时间**（`9天前` / `12天前` / `刚刚`，悬浮 `title` 写完整来源如 `本地缓存 · 9 天前采样` / `云端核验 · 刚刚同步`）；
    - 第 3 块：紧凑 `5h 额度` 与 `7d 额度` 进度条（**严禁在下方再加冗余“官方实时/本地缓存”整行**；若缓存超 5h 且离线 `.jsonl` 推算近 5h 为 0 轮，可在 5h 数值或 tooltip 给出诚实校正提示）；
    - 底行：待处理计数 + 账号年龄（如 `33 天`）。
  - **实时异常日志流入口卡**：展示未读数与 403 消歧摘要，点击切至第 2 分段。
  - 底部免责淡框：`Anthropic 风控为黑盒模型，无“集齐必封”公式；本页仅保留经真机验证有效的防封项。`

### 1.3 右栏视图 A：账号安全审计
#### A. 顶部双层档案总览卡
- **第 1 层（身份名片 + 评分与核验操作区）**：
  - 左侧工整双行（严禁折行产生悬空 `·`）：
    - 上行：`stev***88@gmail.com` · `Pro` · **可点击原地切换按钮 `[订阅 33 天 ⇄]`**（点击切换：未输 `sk` 时诚实显 `预计续费 ~MM-DD`；输过 `sk` 后同步官方准确 `到期 YYYY-MM-DD`）· 商户渠道（`Stripe 直付` / `Apple 内购` / `Google Play` / `Enterprise`）；
    - 下行：`组织 7aacf131` · **`属地`轻胶囊**（未核显 `属地 待核`，输 `sk` 后高亮柔蓝 `属地 US`）· `注册 33 天` · `本机 28 天`。
  - 右侧操作组：
    - 未核验 / 超过 7 天过期态：显示带呼吸蓝点的**可点击柔蓝虚线引导胶囊**（`本地估上限85 · 补验云端更准 →` / `12天前核验 · 重验更新更准 →`，点击直达 `sk` 输入框）；有效期内显示静默文本 `刚刚同步`；
    - **动态风险评分徽章**（4 档颜色，点击打开「防封宝典」抽屉看逐条扣分明细）：如 `84 分 · 本地估` / `56 分 · 中高风险` / `98 分 · 低危稳健`；
    - **蓝色主 CTA 按钮**：未核验/超 7 天为实心蓝 **`云端核验`**，已核验有效期内弱化为描边 **`重验 sk`**。
- **第 2 层（4 等分纯云端账号本体状态栏，与下方 7 项零重复！）**：
  - **视觉统一铁律**：**正常态一律「绿点 + 主白字（`--text-1`）」；仅异常/警告项才给文字上色！**
  - **副标题铁律**：全部使用有价值的中文状态/含义说明，严禁裸露 `monitoring_notice / flags`、`portal.anthropic.com 挂起` 等生硬英文代码。
  - 4 格精确定义：
    1. **`对话可用状态`**：正常 `● 对话可用`（白字，`对话畅通 · 无封禁限制`）；封号 `● 账号已封禁`（红字）；未核 `待 sk 实证`（`本地 0 封号 · 待云端实证`）。
    2. **`官方警告与静默标 ?`**：干净 `● 0 警告 · 干净`（白字）；命中 `● 1 条静默监控`（琥珀字；若接口返回了具体 `billing_issue` / `subscription_pause` / `active_flags[].type` 则直接译出具体项，否则显示 `已进后台观察 · 疑跨区/高频诱发`）。
    3. **`Persona 实名 KYC ?`**：`● 已通过 (verified)`（白字，`已过实名 · 抗误杀能力提升 (+5)`）；`无需验证`；`待验证`（琥珀字）；未核 `待 sk 实证`（`敏感/付费抽检 · 过审抗风险提升`）。
    4. **`Portal 风控门户 ?`**：`● 无挂起 (clear)`（白字，`未被风控挂起 · 正常放行`）；`● 触发挂起`（红字，`风控极高危 · 已限制并需申诉`）；未核 `本地 0 拦截`（`风控强制挂起 · 触发即风险极高`）。
  - 点击任意 `?` 按钮展开/收起统一注释栏，解释 3 大官方风控标记的区别。
  - **7 天时效衰减规则**：本地持久化 `verifiedAt`；超过 **7 天**后，顶部 4 格云端结论自动弱化为灰字并标注 `（X 天前）`，提示按需重验；**但已绑定的账户属地（`default_workspace_geo`）永久有效不衰减**。

#### B. 上下两大责任段（7 项，严格单开互斥手风琴 `openGroupId: string | null`）
- **通用行样式（100% 对齐控制台）**：`padding: 11px 14px`，左 `30×30` 灰色线性图标块（仅告警/危险项柔色高亮，**无最左侧彩色圆点**），标题 `14px`、副标 `12px`，右侧统一 `74px` 等宽 4 字状态胶囊（正常静默灰框、仅异常上色）。
- **低噪音前置分层标签（位于标题正左侧）**：统一中性灰底暗标 + 左侧 `5px` 语义微色点（`● 官方红线` 红点 / `● 经验预警·经验防护` 琥珀点 / `● 隐私降噪` 灰点），严禁满屏彩色边框底色。
- **展开子类布局铁律**：**完全不需要操作的纯只读对照项统一前置到展开区顶部虚线只读条**；**支持修复动作、仅因当前状态正常无需操作的子格严格固定在下方原位不跳动**，哪项异常原地亮灯。
- **分段一：一、需用户自行注意与克制**（置顶，2 项）
  1. `[● 经验预警]` **新号、支付与 KYC 后高敏观察窗**：2×2 四格——`新号注册观察窗 (<7 天)`、`支付 / 升级复审窗 (<=24h)`、`过 KYC 后复核窗 (<=72h · 社区经验)`、`近期套餐变动 (plan_changed)`。
  2. `[● 官方红线]` **自动化机刷与人机节律监测**：2×2 四格——`离线 .jsonl 跨夜节律 & 子代理占比`、`无人值守脚本 (scheduled-tasks)`、`多开并发峰值 (sideSessions) & 429`、`缓存 5h / 7d 水位与软锁`。
- **分段二：二、工具可介入防御与修复**（置底，不同修复方式彻底拆分，5 项）
  3. `[● 官方红线]` **注册归属地与出口一致性核对**：
     - 未输 `sk` 时展开内嵌一次性 `sk` 输入框（支持整段 `Copy as cURL` 自动正则提取 `sk-ant-sid...` 并丢弃其余内容、含「怎么 10 秒复制？」折叠指引）；
     - 已核验态：顶部只读条展示 `出口 IP 纯净度（联动节点体检）` + `属地绑定状态`；下方操作格展示 `注册属地 × 当前出口节点`，跨洲错配时亮蓝按钮 **`前往切换同区节点 →`**；右下角提供 `重验 sk` 入口。
  4. `[● 官方红线]` **多号混登、设备指纹与旧号残留防连坐**：
     - 顶部只读条：`本机设备指纹（换号前后对照）：machineID <8位> · userID <8位>` | `跨组织 404 与封禁残留`；
     - 下方操作区（2 列固定位）：左 `桌面端残留组织（日志不含邮箱）` + `[前往清理桌面端 →]`；右 `CLI 备份识别到的账号（脱敏邮箱/套餐/商户）` + `[清理 CLI 凭据与备份]`。
  5. `[● 官方红线]` **官方 API 端点防反代检测**：2 列——`settings.json ANTHROPIC_BASE_URL` | `系统环境变量 API 端点冲突`（异常时提供一键备份还原官方端点）。
  6. `[● 经验防护]` **Clash 断连回传 Cookie 403 防护**：3 列固定位按需亮灯——`控制台代理状态`（异常亮前往控制台修复）| `环境守护（防复活盯防）`（有进程未盯防亮一键强杀盯防 45s）| `断连回传 Cookie 403`（命中亮查看日志异常）。
  7. `[● 隐私降噪]` **本机遥测开关与缓存清理**：2 列固定位按需亮灯——`settings.json 4 项降噪开关`（缺项亮一键补齐 4/4，存基线可撤回）| `~/.claude/telemetry 待传目录`（>0 B 亮一键清空）。
- **明确不纳入防封审计列表的项（已裁定去除）**：
  - ❌ 白名单明文凭据（Secret Sprawl）：属开发者代码防泄密，与 Claude 封号无关，**移除**；
  - ❌ 第三方 MCP 独立审计行：装正常 MCP 不会封号，**移除独立行**；仅在 `mcp.log` 出现极端高频报错风暴（如短时间 `>=50` 条循环错误）时静默吐 1 条提示到「实时异常日志流」，平时 0 噪音；
  - ❌ 个人 Pro 未开超额按量付费时的 `cachedExtraUsageDisabledReason: "org_level_disabled"`：**严禁误报为风控异常**。

#### C. 右侧滑出「防封宝典」抽屉（白皮书级去套娃排版）
- **严禁卡片套卡片**：顶部评分汇总卡为单层容器，内部扣分明细使用 `1px` 水平细分割线列表（**每条为粗体标题 + 一句通俗简述 + 右侧分值**）；评分卡右上角在未核验/超 7 天态紧挨 `本地评估` 胶囊放置蓝色可点击 **`立即云端核验 →`** 按钮及柔蓝提示条。
- **正文以通俗防封知识为绝对主角**（优雅扁平文档流 + 左侧 `2px` 语义细竖线 + `1.7` 行高）：
  1. `一、最易触发封号的 4 大核心雷区`（属地/IP/机房段、**虚拟 U 卡/封号卡复用/共享代充与多号指纹连坐**、第三方共享反代、机刷与 429）；
  2. `二、3 个关键防翻车阶段与护航习惯`（高敏观察窗、升级/换卡四码一致建议、Clash 断连回传防护）；
  3. `三、云端状态、403 报错与数据边界速查`（3 大云端状态白话解、4 类 403 速辨、工具能查与不能查透明说明）；
- **底部默认折叠区**：`查看 100 分制评分权重明细（8 项总分 = 100 分）▾`，点击展开完整权重表。

### 1.4 文案语气与纯净度铁律（已入 `docs/ui-design-system.md` 7.2 节）
- **0 设计术语 / 0 工单号 / 0 架构自白**：全页绝不可出现 `手风琴`、`T-058`、`同源`、`只读对照区`、`第 2 格`、`按需亮灯`、`哪项有隐患` 等开发/设计评审词。
- **3 级客观语气**（黑盒风控禁用“务必/绝对/必封”）：
  - L1 官方红线 → `强烈建议`；
  - L2 社区高频实证 → `建议 / 有助于降低概率`；
  - L3 经验观察窗 → `社区经验参考 / 倾向于 / 尽量`。

---

## 2. 100 分制安全评分引擎（纯函数核心）与 3 层零风控额度提精

### 2.1 严格 100 分权重模型（抽离为独立无状态纯模块 `account_audit::score`）

基准满分 **`100` 分**，8 项权重总和严格等于 **`100` 分**，另设致命熔断、实名缓冲与盲区封顶：

| # | 评估维度 | 满分权重 | 典型扣分规则 |
| :---: | :--- | :---: | :--- |
| 1 | **归属地 × 出口 IP 一致性** | **24 分** | 跨洲错配 `-24`；同国机房 IP 段或 7 天高频跳区 `-8`（取较大值，单项上限 `-24`） |
| 2 | **官方 API 端点纯净度（防反代）** | **16 分** | 检出非官方 `ANTHROPIC_BASE_URL` / `API_URL` `-16` |
| 3 | **多号隔离与设备指纹防连坐** | **16 分** | CLI ≠ Desktop 跨端混登 `-10`；存在本地封禁残留 / 跨组织 404 `-16`（单项上限 `-16`） |
| 4 | **官方警告与静默监控标** | **12 分** | 云端命中 `monitoring_notice` / `billing_issue` / 告警 `active_flags` `-12` |
| 5 | **高敏观察窗（新号/支付/过 KYC）** | **10 分** | 处于新号 `<7d`、支付/升级 `<=24h`、过 KYC `<=72h` 或近期套餐跳变 `-10` |
| 6 | **人机节律与 429 并发安全** | **10 分** | 存在定时脚本/跨夜机刷/高频 429 `-10`（轻度偶发 429 `-5`） |
| 7 | **Clash 断连回传 Cookie 403 防护** | **8 分** | 命中退出回传 Cookie 403 `-8`；TUN 离线或后台有进程未盯防 `-5`（单项上限 `-8`） |
| 8 | **本机隐私遥测与待传缓存** | **4 分** | `settings.json` 缺 4 项变量 `-3`；`telemetry/` 非空 `-1` |
| - | **致命熔断（一票触底）** | 覆盖 | 云端或日志实锤 `account_banned` 或 `portal_hold` → **总分直接锁死 `<= 15`（极危红）** |
| + | **Persona 实名护城河缓冲** | **+5 分** | `kyc_status == "verified"` 且 `completed_at > 72h` → `+5`（总分封顶 `100`） |
| 封顶 | **信息盲区诚实上限** | **≤ 85** | 未执行过 `sk` 核验，或 `verifiedAt > 7 天` 过期衰减 → **总分上限诚实封顶 `85`** |

- **4 档风险系数色阶**：
  - `85 – 100`：`低危稳健`（绿 `--success`）
  - `70 – 84`：`建议优化`（琥珀 `--warning`）
  - `45 – 69`：`中高风险`（橙红 `#fb923c`）
  - `0 – 44`：`高危警报`（红 `--danger-bright`）

### 2.2 零风控提升 5h / 7d 额度精确度的 3 层策略（用户已明确认可）
- **绝对红线**：严禁后台拿 `sessionKey` 定时轮询 `/api/organizations/:id/usage`；严禁解密桌面端 Chromium DPAPI `Cookies`。
- **3 层安全提精实现**：
  1. **层 1（被动监听本地写盘，0 联网）**：缓存文件监听 `(path, mtime, size)` 跟踪 `~/.claude.json` 与桌面日志（含 `5-hour limit` 软锁事件），CLI/桌面端写盘即即时刷新；
  2. **层 2（离线 `.jsonl` 增量校正，0 联网）**：当 `~/.claude.json` 的 `cachedUsageUtilization` 采样时间戳已过期（例如超过 `resets_at` 或超过 5 小时，本机实测常见滞后 9 天）时，结合 `~/.claude/projects/**/*.jsonl` 过去 5 小时内的真实对话轮次判断：若已过 `resets_at` 且近 5h 本地 0 轮对话，UI 标注 `0%（缓存过期·近5h本地0轮）` 或在 tooltip 给出估算说明，避免把 9 天前的旧 22% 当成当下实时额度；
  3. **层 3（手动按需云端校准 + 60 秒冷却锁）**：仅在用户主动点击「云端核验 / 重验 sk」时同步拉取一次 `/usage`，内置 **60 秒冷却锁**防连点刷接口，全程走本机固定 Clash 代理。

---

## 3. Rust 后端架构设计与 6 条 `ProfileContext` 契约

### 3.1 新建模块化目录 `src-tauri/src/account_audit/`
严格遵守 [文档 01](./research/01-local-config-audit-and-403-disambiguation.md) 第五节 6 条契约，**严禁在解析函数内硬编码 `~/.claude` 或 `%LOCALAPPDATA%\Claude`**：

```
src-tauri/src/account_audit/
├── mod.rs            # ProfileContext、统一对外聚合 API、持久化脱敏缓存（按 profile_id 命名空间）
├── local_scan.rs     # 共享只读扫描：.claude.json / 白名单 .credentials.json / settings.json / backups / .jsonl / Desktop 日志
├── cloud_probe.rs    # 按需一次性 sessionKey 只读 GET 核验（经 Clash/指定代理 + 原生 TLS/curl.exe，供桌面端与外部 API 复用）
├── disambiguate.rs   # 纯函数：7 类 403 精准消歧（结合套餐事实自动降噪背景 OAuth 403）
└── score.rs          # 纯函数无状态 100 分制评分引擎（标准 JSON 输入输出，供桌面端与外部 API 共用）
```

### 3.2 关键安全与工程实现细节
1. **白名单结构体解析 `.credentials.json`**：Rust `struct CredentialsMeta` **绝不定义** `accessToken` / `refreshToken` 字段，编译期彻底杜绝明文凭据进入内存、IPC 或日志。
2. **一次性 `sessionKey` 云端只读核验（`cloud_probe.rs`）**：
   - 支持直接粘贴 `sk-ant-sid...` 或整段浏览器 `Copy as cURL`（后端与前端均做正则提取 `sk-ant-sid[0-9a-zA-Z_-]{16,}`，立即丢弃其余内容）；
   - 通过本机 Clash 端口（从 `AppConfig` / 运行时端口读取，**支持非默认端口如 7897**，绝不写死 7890！）走 Windows 原生 TLS（Schannel，`curl.exe` 或等效原生 TLS 客户端，防止 Rustls JA3 被 Cloudflare 弹盾），附带头 `anthropic-client-platform: web_claude_ai`；
   - **只发只读 `GET`**，按序请求：`/api/organizations` → **智能选主（必须优先选含 `capabilities: ["chat"]` 的组织，绝不拿 Console API 组织查 `/usage`！）** → `/api/account`（拿 `default_workspace_geo`、`created_at`）→ `/api/organizations/:id/kyc_status`（拿 `status`、`completed_at`）→ `/api/organizations/:id/usage` → `/api/organizations/:id/chat_conversations?limit=1` → 付费号再查 `/api/organizations/:id/subscription_details`（Free 号返 403 静默处理）；同时读取响应头 `cf-ray` 推导当前边缘节点国家码；
   - **防串号保护**：若当前本地已存在主组织 `orgId`，且本次 `sk` 查回的 `chat` 主组织 `orgId` 与之不一致，**必须拒绝覆盖当前档案**并返回明确错误提示（“检测到浏览器登录账号与本机 CLI 主号不一致，已阻止覆写以防串号”）；
   - **明文用完即焚**：`sessionKey` 仅存活于当次异步函数栈内，结束后清零丢弃；持久化到本地（`%LOCALAPPDATA%\FDClaudeGuard\account-audit-cache.json`，主键按 `profile_id` 隔离，单号期固定 `"default"`）的**仅限脱敏摘要 + `verifiedAt` + 永久绑定的 `workspaceGeo`**。
3. **Windows 共享只读与大文件性能保护**：
   - 打开被 Claude 正在写入的 `main.log` / `.claude.json` / `.jsonl` 必须使用共享只读模式（`FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`）；
   - 单日志最多只读尾部 `2 MB`，扫描 `.jsonl` 必须带 `(path, mtime, size)` 内存缓存，并放进 `tokio::task::spawn_blocking` 严禁阻塞 Tauri 主线程；
   - `backups/.claude.json.backup.*` 实测可完整读出每份历史备份的脱敏邮箱、组织 ID、套餐与计费方式；用于给桌面端日志的残留 `orgId` 做反查匹配（若该 `orgId` 只在 Desktop 登录过则诚实标注日志不含邮箱）。
4. **自适应高辨识脱敏邮箱函数 `mask_email_readable(email: &str) -> String`**：
   - 取 `@` 前缀字符数 `len`（按 Unicode char 计）：
     - `len >= 8` → 前 4 + `***` + 后 2（如 `stev***88@gmail.com`）；
     - `5..=7` → 前 3 + `***` + 后 2；
     - `3..=4` → 前 2 + `***` + 后 1；
     - `<= 2` → 前 1 + `***`。

### 3.3 新增 Tauri IPC 命令建议清单（全部预留 `profileId?: string`）
- `audit_account_local(profile_id: Option<String>) -> AccountAuditReport`
- `verify_account_cloud_with_sk(profile_id: Option<String>, raw_input: String) -> AccountAuditReport`（含 60s 冷却锁 & `orgId` 串号校验）
- `fix_claude_telemetry_env(profile_id: Option<String>) -> AccountAuditActionResult`（First-Write-Wins 保存 `settings.json` 基线可精准撤回）
- `clean_claude_telemetry_dir(profile_id: Option<String>) -> AccountAuditActionResult`
- `restore_claude_official_endpoint(profile_id: Option<String>) -> AccountAuditActionResult`（First-Write-Wins 备份后移除非官方 `ANTHROPIC_BASE_URL` / `API_URL`）
- `clean_claude_cli_credentials_with_backup(profile_id: Option<String>) -> AccountAuditActionResult`（先 ZIP 原子备份再清理 CLI 登录态与历史旧备份）

---

## 4. 控制台 & 环境维护同源联动改造（必修旧隐藏 Bug！）

> **真机实测抓出的 2 个隐藏 Bug（详见用户截图反馈）**：
> 1. 当前控制台 `claude_acct`（单号卫生锁）只扫 Desktop 日志，未读 `~/.claude.json`，导致本机 `CLI=7aacf131 ≠ Desktop=a4722ea6` 真实跨端混登时控制台竟显示「已通过」；
> 2. 当前控制台 `claude_tel`（隐私降噪开关）未校验 `~/.claude/settings.json` 的 4 项 `env` 键值，导致本机实际仅开了 `2/4`（缺 `DISABLE_TELEMETRY` 与 `DISABLE_BUG_COMMAND`）时控制台竟显示「已通过」。

### 4.1 控制台（`src-tauri/src/preflight/mod.rs`）精准改造范围
严格遵守「**只加权重高且直接保障安全启动的项目，底层检测与修复 100% 与账户审计共用同一份函数**」：
1. **同源升级 `claude_acct`（单号卫生锁）**：直接调用 `account_audit::local_scan` 的双端组织扫描结果（CLI + Desktop + 备份），彻底消除控制台与账户审计口径打架；修复动作共用原子备份清理弹窗（新增勾选 CLI 清理选项）。
2. **同源升级 `claude_tel`（官方隐私降噪开关 & 遥测缓存）**：直接调用 `account_audit` 统一的 `settings.json` 4 项变量 + `telemetry/` 检测与 First-Write-Wins 基线修复函数。
3. **同源升级 `node_geo`（出口节点合规与真实可达性）**：当账户审计缓存中已绑定 `workspaceGeo`（如 `"us"`）时，启动前体检自动附加「出口国家 vs 绑定属地跨洲一致性」校验，跨洲错配直接标警告/失败并引导前往「节点流量」切回同区节点。
4. **仅新增 1 项高权重启动红线到「3. Claude 本机卫生」：`claude_endpoint`（官方 API 端点防反代校验）**：与账户审计第 5 项共用检测与一键备份还原逻辑；高敏观察窗、离线 `.jsonl` 节律、输 `sk` 云端核验**绝不塞入控制台**，避免阻断日常安全启动。

### 4.2 环境维护（`src-tauri/src/maintenance/mod.rs`）与撤回基线（`rollback/mod.rs`）补齐
- `maintenance/mod.rs` 的分项清理清单（`CleanupPlanPreview` 与 `backup_and_clean_claude_dirs_selected`）新增可选清理项：**`cli_auth_and_backups`（CLI 登录态与历史旧号备份：`~/.claude.json` 中 `oauthAccount` / `.credentials.json` / `~/.claude/backups/`）**，**清理前强制执行 ZIP 原子备份**，默认尊重用户勾选。
- `rollback/mod.rs` 的 `system-baseline.json` 增补 **`original_claude_settings_env`**（First-Write-Wins 首次基线快照），确保「一键补齐 4/4 隐私降噪」与「还原官方 API 端点」均支持 100% 干净精准撤回，**严禁粗暴覆盖整份 `settings.json` 抹掉用户自定义 hooks/permissions**！

---

## 5. 外部查分 API 预留契约（唯一极简方案：`POST /v1/audit/check-sk`）

> **最终产品决策（已确认）**：砍掉多余的本机回环桥接、网页问卷与浏览器插件。已装桌面端用户直接在软件界面看即可；**对外只预留一套极简纯 API 接口（`sk + 代理` 一次性只读脱敏查询）**，供未安装桌面软件的外部用户/平台调用一次查云端安全分。

### 5.1 架构复用意图（零重复开发）
- `account_audit::cloud_probe`（只读 GET 探针，支持传入 `proxyUrl`）与 `account_audit::score`（100 分纯函数评分引擎）在编写时**严格不耦合 Tauri `AppHandle`**；
- 桌面端直接调用它们完成按需云端核验；后续需对外开放查分服务时，直接包一层轻量 HTTP 服务暴露 **`POST /v1/audit/check-sk`** 即可零重构上线。

### 5.2 请求契约：`POST /v1/audit/check-sk`

```json
{
  "schemaVersion": "1.0",
  "sessionKey": "sk-ant-sid01-...（或直接传整段 Copy as cURL，服务端自动提取并丢弃其余内容）",
  "proxyUrl": "http://127.0.0.1:7890"
}
```

- `sessionKey`（必填）：明文仅存在于当次请求的栈内存中，请求结束立即清零销毁，**严禁落盘、严禁写入任何访问日志/错误日志**；
- `proxyUrl`（可选，强烈建议传入）：支持 `http://` / `socks5://`（含鉴权代理），用于走调用方指定的干净住宅代理节点，尽量降低公共出口 IP 弹盾与连坐风险；若未传则走服务端配置的默认出口代理并需在响应 `warnings` 中诚实提示风险。

### 5.3 响应契约（`200 OK`，全量脱敏）

```json
{
  "schemaVersion": "1.0",
  "checkedAt": "2026-11-26T09:05:00+11:00",
  "account": {
    "emailMasked": "stev***88@gmail.com",
    "orgIdPrefix": "7aacf131",
    "plan": "Pro",
    "merchantChannel": "Stripe 直付",
    "workspaceGeo": "US",
    "edgeCountry": "AU",
    "edgeColo": "SYD",
    "accountAgeDays": 33,
    "subscriptionAgeDays": 33,
    "subscriptionEndsAt": "2026-12-22"
  },
  "cloudStatus": {
    "chatAvailable": true,
    "isBanned": false,
    "appealsRedirectEnabled": false,
    "hasMonitoringNotice": true,
    "activeFlagTypes": ["monitoring_notice"],
    "personaKycStatus": "verified",
    "personaKycCompletedAt": "2026-10-24T00:00:00Z",
    "portalHold": false
  },
  "usage": {
    "fiveHourPct": 34,
    "sevenDayPct": 64
  },
  "scoreResult": {
    "score": 69,
    "maxScore": 100,
    "level": "mid_high",
    "levelLabel": "中高风险",
    "colorToken": "orange",
    "confidence": "cloud_only",
    "confidenceLabel": "云端评估（不含本机混登/日志项）",
    "disclaimer": "防御参考分（非 Anthropic 官方黑盒风控分）；外部 API 仅评估云端维度，不含本机环境审计。",
    "deductions": [
      {
        "id": "geo_mismatch",
        "weightMax": 24,
        "delta": -24,
        "tone": "danger",
        "title": "归属地与出口跨洲错配（权重 24 分）",
        "desc": "账号属地 US 与当前出口 AU(SYD) 跨洲，建议切回美区稳定节点"
      },
      {
        "id": "monitoring_notice",
        "weightMax": 12,
        "delta": -12,
        "tone": "warn",
        "title": "云端命中后台观察标（权重 12 分）",
        "desc": "对话仍可用，但账号已进观察队列，容错率下降"
      },
      {
        "id": "persona_kyc_buffer",
        "weightMax": 5,
        "delta": 5,
        "tone": "ok",
        "title": "已通过 Persona 实名认证（护城河缓冲）",
        "desc": "已过 72h 稳定期，账号抗误杀能力显著高于白号"
      }
    ]
  }
}
```

### 5.4 外部 API 强制安全与脱敏红线
1. **严格只读 GET**：绝不暴露或调用任何写操作/吊销会话（`/api/revoke`）或刷新 KYC 接口；
2. **明文用完即焚**：`sessionKey` 与 `proxyUrl`（可能含代理账密）绝不打印进日志、绝不落盘、绝不回显在响应体或报错信息中；
3. **全量脱敏响应**：仅返回前多后少脱敏邮箱（`stev***88@gmail.com`）与 8 位组织短前缀，绝不返回完整邮箱、完整 UUID、手机号、姓名或原始 Cookie；
4. **防刷限流与标准错误码**：对同一 `sk` 指纹（仅内存短时 SHA-256 哈希，不落盘）加 60 秒冷却防连点；标准错误码：`400 INVALID_SK_OR_PROXY`、`403 CF_CHALLENGE_OR_AUTH_EXPIRED`、`429 RATE_LIMITED`、`502 PROXY_OR_UPSTREAM_FAILED`。

---

## 6. 后续任务 `T-059`（方案 A 自动更新）交接要点

待 `T-058` 全部验收通过后立即执行 `T-059`：
- **已就绪公钥**（位于 `C:\Users\xujun\.tauri\fd-claude-guard.key.pub`，Key ID `524DD4CBF003E3FD`，**严禁读取或提交私钥**）：
  ```
  dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDUyNERENENCRjAwM0UzRkQKUldUOTR3UHd5OVJOVW1UdFBTTGN3R2h1L2FNZEx4aXFFT0xEYjcreDZ5aEhFeXhna1VoeUdGbTQK
  ```
- **GitHub Secrets**：用户已配置完毕；接入 `tauri-plugin-updater` 并在 `tauri.conf.json` 配置 `endpoints` 指向 `https://github.com/CaesarLastKing/FD-ClaudeGuard/releases/latest/download/latest.json` 与上述 `pubkey`；
- 编写 `.github/workflows/release.yml`（打 `v*` tag 自动构建 Windows 安装包、签名生成 `.sig` 与 `latest.json` 并发布 GitHub Release）；
- 同步 `package.json`、`src-tauri/Cargo.toml`、`src-tauri/tauri.conf.json` 三处版本号至 `0.3.0`，更新 `CHANGELOG.md`。

---

## 7. 真机实测避坑清单与 Gate 0 ~ Gate 5 发布硬门禁

### 7.1 本机已实证的 6 个真实坑点（严禁重踩）
1. **缓存额度滞后 9 天**：`~/.claude.json` 的 `cachedUsageUtilization` 极易陈旧，绝不可谎称“实时”，须结合采样时间 + `.jsonl` 校正。
2. **`org_level_disabled` 假阳性**：个人 Pro 未开按量付费时官方默认缓存 `cachedExtraUsageDisabledReason: "org_level_disabled"`，属正常态，**绝不能报警或扣分**。
3. **多组织误选 API 组织**：`/api/organizations` 可能同时返 API 与 Chat 组织，必须按 `capabilities.contains("chat")` 选主。
4. **非默认 Clash 端口**：客户机端口可能是 `7897` 或自定义端口，绝不可硬编码 `7890`。
5. **Windows 子进程中文编码与 Clash 保护红线**：凡调用 PowerShell/`netsh`/`sc` 必设 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`；**严禁对 `clash-verge.exe` 执行 `taskkill /F`**。
6. **Git 凭据提醒**：本地仓库推送 `origin/main` 时如遇凭据缺失，使用 `-c credential.helper= -c "credential.helper=!gh auth git-credential"`。

### 7.2 打包前 6 道硬门禁（Gate 0 ~ Gate 5）
- **Gate 0（写操作与可逆性评审）**：核查 `settings.json` 与 CLI 清理的 First-Write-Wins 基线快照、ZIP 原子备份与无损撤回；确认零明文凭据写盘。
- **Gate 1（全量自动化测试 0 警告）**：`cargo test`（0 warning，覆盖评分纯函数、7 类 403 消歧、脱敏邮箱、`orgId` 串号拦截、控制台同源回归单测）+ `npx tsc --noEmit` + `npx vitest run` + `npm run build` 全绿。
- **Gate 2（真机正向→反向双向闭环实测）**：实机验证「读出当前真实 2/4 降噪缺失与跨端混登 → 正向一键补齐 `settings.json` 并验证生效 → 反向撤回并验证 100% 还原原 `settings.json`」；严禁只测读不测修！
- **Gate 3（冷启动 / 缺文件边界矩阵）**：验证纯 Desktop 无 CLI、纯 CLI 无 Desktop、`.claude.json` 损坏/空文件、代理离线、无效 `sk`、串号 `sk` 均优雅降级零崩溃。
- **Gate 4（前端深/浅双主题与 1:1 真实组件审图）**：按 `docs/ui-design-system.md` 第 5 阶段做真实渲染审图，确认 0 截断、0 卡片套娃、0 设计术语泄漏、`console.error === 0`。
- **Gate 5（产物清单校验）**：核验安装包 `requireAdministrator` 清单、零私密脚本/明文密钥泄露与 SHA-256。

---

## 8. 接手开发 AI 的《待确认问题上报模板》

> 如你在实现上述任何环节遇到不确定项，请暂停该分支改动并按下方格式汇总，交给用户转问复核：
>
> ```markdown
> ### [Q-01] 简要问题标题
> - **涉及模块**：（如 `account_audit/cloud_probe.rs` / `ConsolePage.tsx`）
> - **发现的事实 / 冲突**：（贴出真实接口响应、源码行号或真机报错）
> - **备选方案与利弊对比**：
>   - 方案 1：...（优点 / 缺点）
>   - 方案 2：...（优点 / 缺点）
> - **我的倾向与阻塞点**：...
> ```
