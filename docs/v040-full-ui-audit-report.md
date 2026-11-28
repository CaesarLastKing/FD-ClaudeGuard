# FD Claude Guard v0.4.0 全页面实机使用效果审查报告

> 审查日期：2026-11-27  
> 审查对象：本机已安装的正式版 v0.4.0（`C:\Program Files\FD Claude Guard\fd-claude-guard.exe`）  
> **v0.4.1 修复收口状态**：已按用户拍板方案（全量修复、保留未读红标、调高设置弹窗、统一 `GPL-3.0`）完成代码落地与定向回归校验，并产出安装包 [FD Claude Guard_0.4.1_x64-setup.exe](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/target/release/bundle/nsis/FD%20Claude%20Guard_0.4.1_x64-setup.exe)（`4,726,044 B`，`SHA-256: ECF4E3F8EE683ACF5DDF606F0CAEB637AA2ED4611BAB0057B95BA62466A0D4F0`，内嵌 `requireAdministrator` 清单；因环境未配置 `TAURI_SIGNING_PRIVATE_KEY` 私钥，跳过更新 `.sig` 签名生成），待安装 `v0.4.1` 后做实机复验（其中 `P2-4 清理恢复快照缓存预热` 保留观察，其余全部 P0/P1/P2 项均已修复）。  
> 审查方式：通过 WebView2 CDP（`127.0.0.1:9222`）像真实用户一样逐页只读点击、截屏、DOM 几何碰撞与样式检测，配合查看运行时日志与本地缓存真源。  
> 安全边界：全程 **100% 只读审查**，未点任何写操作/修复/熔断/清理按钮，未覆盖或修改正式版安装目录，也未在审查中触发全量测试；主题切换对比后已第一时间还原为 `dark`。

---

## 一、实机覆盖清单与健康基线

- **视口与环境**：`1473 × 1040`（DPR `1.3`），系统深色主题启动，Mihomo v1.19.33 在线（`7890` 端口 + TUN 模式，锁定 `Claude-Fixed -> 🇺🇸美国1|流媒体AI (US · 140.235.xx.xx)`），桌面端主账号 `star***at@outlook.com`（`Free`，`0ffb0302`），历史归档 `jaso***11@gmail.com`（`a4722ea6`）。
- **页面与弹窗遍历（共采集 37 张实机截图）**：
  - 主窗口外壳 + 顶栏快捷切换 + 左下角进程/Clash 状态卡 + **桌面悬浮窗（HUD）**
  - **控制台**：左侧全部 19 项逐条点开并检测 KV 行几何、颜色与内容 + 「查看原始探针代码」展开
  - **账户审计**：主号概览、权重表、`sk` 说明、防封宝典抽屉、历史快照 `a4722ea6`、实时日志与噪点面板
  - **节点流量**：「节点质量」（可用 10 / 同区热备 3 / 隔离区 6）+「实时连接」（全部 / 仅看异常 / 遥测拦截）
  - **AI 工具箱**
  - **系统设置弹窗**：「常规开关」（含顶/底滚动与 ⓘ 说明浮层）、「安全策略」（上/下）、「清理恢复」、「版本更新」、以及「联系作者」弹窗
  - **双主题对照**：`dark` 与 `light` 关键页面交叉复拍
- **运行时零崩溃与日志健康**：
  - 审查期间 WebView2 `runtimeExceptions = 0`，`consoleErrors = 0`，`logErrors = 0`。
  - 今日日志 [guard-runtime-20261127.jsonl](file:///C:/Users/xujun/AppData/Local/FDClaudeGuard/logs/guard-runtime-20261127.jsonl) 自本次重启以来无 `ERROR`/`WARN` 输出，5.7s 完成 19 项真实探针并命中单飞缓存。

---

## 二、逐项问题清单（按严重程度分级）

### P0｜功能失效 / 严重视觉破坏 / 架构缺口（必修）

#### [P0-1] 控制台右侧「实测探针数据」多条长卡片行高被压扁，导致文字上下重叠
- **所在页面**：控制台 → 任意行数较多的检查项右侧详情区
- **复现操作**：依次点击「策略组与全家桶规则锁死」（13 行）、「单号卫生锁」（11 行）、「官方隐私降噪开关 & 遥测缓存」（7 行）、「系统时区与出口地区一致性」（5 行）。
- **实机现象与截图**：
  - 第 1 行与第 2 行文字直接垂直叠字撞车，后续多行也明显压缩；`196px` 固定最大高度将超长列表卡死在局部滚动盒内。
  - DOM 几何实测（见 [audit_summary.json](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/audit_summary.json)）：第 2 项行 2 `rowH=31.0px` 但内部 `vH=49.0px`；第 17 项行 4 `rowH=56.2px` 但 `vH=97.9px`。
  - 实机截图：[02_console_item_02.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_02.png)、[02_console_item_17.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_17.png)
- **根因**：`.c-kv-list` 设了 `display: flex; flex-direction: column; max-height: 196px`，但子元素 `.c-kv-row` 未设置 `flex-shrink: 0`，导致容器溢高时 Flexbox 强行把每一行压矮。

#### [P0-2] 开机自启安装即失效 + 新版默认关闭悬浮窗与桌面预警通知
- **所在页面**：系统设置 → 常规开关（[06_settings_general.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/06_settings_general.png)）
- **实机现象**：
  - 安装 `v0.4.0` 时 NSIS 安装器未创建计划任务，导致开关 `bootStart=true` 但实际「开机启动项检查」显示「未开启」（需手动关再开才会真建任务）。
  - 本机配置文件原本保留旧默认值，实机截图中上方「显示桌面悬浮状态窗」「桌面预警消息提醒」两个开关呈**关闭状态**，且右侧依旧显示绿色徽标「推荐开启」。

#### [P0-3] 无法识别 Clash Verge Rev「服务模式 / Admin」开机计划任务
- **所在页面**：控制台「开机启动项顺序风险检查」+ 系统设置「常规开关 → 开机启动项检查」
- **实机现象**：用户开启了 Clash Verge Rev 的高权限开机计划任务（如 `Clash Verge (Admin)`），但界面 [02_console_item_13.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_13.png) 与 [06_settings_general.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/06_settings_general.png) 均显示 `未开启`。
- **根因**：旧版自启检测只扫注册表 `Run` 键与启动文件夹，未扫 Windows 计划任务 XML。

#### [P0-4] 切换历史账号快照丢失曾用 `sk` 查出的云端字段
- **所在页面**：账户审计 → 左侧「历史归档 (1)」→ 点击 `jaso***11@gmail.com`
- **实机现象与截图**：[03_audit_history_a4722ea6.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/03_audit_history_a4722ea6.png) 中，属地、渠道、注册天数及 4 张核心云端状态卡全部降级成「属地 待核」「渠道未知」「待 sk 实证」。

#### [P0-5] 客户端主动上传日志字段与 Cloudflare Worker 不匹配 + 更新失败无退避
- **实机证据**：远端 D1 `feedback_reports` 成功收到工单 `FD-20261127-E70E6CB3`（`769 B`），但 `install_id_hash` 与 `app_version` 因驼峰/下划线字段名不匹配全部存成了 `anonymous` / `unknown`；此外后台静默检查更新失败时没有 10 分钟退避冷却。

---

### P1｜严重信息误导 / 逻辑与口径自相矛盾（高优处理）

#### [P1-1]【本次新发现】账户审计把美国洛杉矶节点误标为「出口 TPE」/「US(TPE)」
- **所在页面**：账户审计 → 左侧「当前档案 (1)」 & 右侧「注册归属地与出口一致性核对」
- **实机现象与截图**：
  - 控制台实测当前节点是 `140.235.xx.xx (US · California / Los Angeles)`；
  - 但在 [03_audit_main.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/03_audit_main.png) 左侧卡片却显示 **`归属 US · 出口 TPE`**（台北机场码），右侧又写 **`账号注册属地 US 与当前出口 US(TPE) 同区一致`**，令用户误以为流量绕道台湾或节点判错。
- **根因（已定位）**：[account_audit/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/account_audit/mod.rs#L1417-L1420) 中当本机实时探针未产出 `runtime.exit_colo`（当前走 `ip-api.com` 无 CF POP 码）时，代码直接 `.or_else()` 回退读取了历史上云端 `sk` 检测遗留的 `cloud_snap.edge_colo = "TPE"`，把旧快照的边缘节点拼到当前新节点头上。

#### [P1-2]【本次新发现】侧边栏「账户审计」未读红标与左下角「实时异常日志流 0 未读」前后打架
- **所在页面**：左侧主导航「账户审计」徽标 + 账户审计左下角「实时异常日志流」卡片
- **复现操作**：
  1. 停留在控制台时，观察侧边栏「账户审计」徽标为红色 **`2`**（见 [01_console_overview_theme1.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/01_console_overview_theme1.png)）；
  2. 点击进入「账户审计」主界面（**未点**「进入日志流」，也**未点**「全部标为已读」）。
- **实机现象与截图**：
  - 刚切进「账户审计」，侧边栏红标立刻变成绿色 **`OK`**（见 [03_audit_main.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/03_audit_main.png)）；
  - 与此同时，左侧脉冲卡片标题显示 **`实时异常日志流 0未读`**，正文却清清楚楚写着 **`捕获 2 条待核异常事件（含鉴权 / 403 预警，未降噪）`**，点进「实时日志」也确实有 `2` 条未核实事件（[03_audit_logs.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/03_audit_logs.png)）。标题说 `0 未读`、内容说 `2 条待核`、徽标又变 `OK`，体验明显自相矛盾；且卡片中「流」与「0」粘连缺空格。

#### [P1-3] 实时连接表在桌面端 0 进程时把浏览器 `claude.ai` 长连接强行显示为 `"Claude"`
- **所在页面**：节点流量 → 实时连接（[04_nodes_live_conns.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/04_nodes_live_conns.png)）
- **实机现象**：左下角 `Claude 进程 0 残留`，右边实时连接却显示 `claude.ai / Claude`，引起用户“明明没开客户端为什么还有 Claude 连接”的恐慌。实际是 `chrome.exe` 网页端复用 HTTP/2 长连接，而 TUN 模式下 Mihomo `metadata.process` 为空被后端兜底写死成了 `"Claude"`。

#### [P1-4] 控制台右侧探针安全值被误染红色警戒色，且部分文案自相矛盾
- **实机发现（4 处安全项误标红 + 1 处状态打架）**：
  1. [02_console_item_06.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_06.png)：IPv6 地址被冒号拆断为 `4. 外网 IPv6 连通探针 (2606` / `4700::1111): Blocked / Unreachable (OK)`，右侧**因为含 `blocked/unreachable` 被染成红色**；
  2. [02_console_item_07.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_07.png)：`0 冲突 / 无直连豁免` 被染成红色（`rgb(197, 107, 102)`）；
  3. [02_console_item_11.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_11.png)：`0 冲突 · 原生直连` 被染成红色；
  4. [02_console_item_09.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_09.png)：`KYC / Permission-Pending (len=164) Notice: ...` 被内部冒号拆分且整行泛红，即使提示明确说明「非封号，不阻断启动」；
  5. [02_console_item_15.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_15.png)：标题状态「已通过」，右侧首行 **`免 UAC 守护任务` 却标红显示 `未安装`**，下方验证说明却写「防火墙无感守护权限已就绪」。

#### [P1-5] 控制台及源码中仍残留大量 v2.0 已废弃页面名称，引导路径找不到
- **实机证据**：[02_console_item_09.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_09.png) 处理说明写道：`请前往「日志分析」查看详情，或按需到「环境维护」退出登录并清理目录`。
- **问题影响**：UI v3.0 左侧只有「控制台 / 账户审计 / 节点流量 / AI 工具箱」+ 左下「系统设置」，已无「日志分析」「环境维护」「守卫配置」三个页面入口，新用户照着提示根本找不到在哪。

---

### P2｜视觉错位 / 中英混杂 / 隐性交互阻断

#### [P2-1] 控制台「实测探针数据」左列中英混排、右列含代码噪声且长列表被截断
- **实机汇总（全量 19 项自动扫描发现 17 项存在展示可优化点）**：
  - **左列中英混排/路径直接外露**：如 `Claude 命中规则`、`核心与 KYC 分流`、`CF 盾与 Stripe 分流`、`Mihomo dns.enhanced-mode`、`Fake-IP (198.18.0.0/15)`、`Anthropic API 连通`、`1. 物理网卡 ms_tcpip6`、`3. 注册表 Tcpip6 DisabledComponents`、`CLI (~/.claude.json)`、`Observed Unique accountIds (1)`、`settings.json ANTHROPIC_BASE_URL / API_URL`、`System ENV (HKCU/HKLM) API Endpoints`、`Rule Probe (FDClaudeGuard_KillSwitch_*)`、`Exit IP & Purity`、`Claude Web (claude.ai/login)`。
  - **右列含技术原始值或冗长重复**：`\\.\pipe\verge-mihomo-production-<64位hash>` 换行 4 行（[02_console_item_01.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_01.png)）、`Claude-Fixed (手动固定单节点=true)`、`Safe (合规范围)`、`SingleSurfaceClean`、`未登录 [status=empty]`、`Single-Account KYC/Auth Notice`；且「单号卫生锁」里同一账号 `star***at@outlook.com (Free · 桌面端 · 0ffb0302)` 连着出现 **3 行**（桌面端账号数 / 已绑定主号 / 主号候选标识，见 [02_console_item_10.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_10.png)）。
  - **左列宽度略微溢出**：第 18 项 `账号属地与出口比对` 实测 `scrollW=104 > clientW=100`（[02_console_item_18.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/02_console_item_18.png)）。

#### [P2-2]【本次新发现】桌面悬浮窗（HUD）在主窗口深色模式下仍保持纯白浅色外观
- **实机截图**：对比 [01_console_overview_theme1.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/01_console_overview_theme1.png)（`dark`）与同时截取的 [07_hud_window.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/07_hud_window.png)（依然是纯白卡片）。
- **根因**：`src/hud.tsx` / `HudCard.tsx` 未从主配置同步 `data-theme="dark"` 并监听主题变更事件。

#### [P2-3]【本次新发现】系统设置「常规开关」首屏刚好把「手动排查与日志工具」压在底部折叠线外
- **实机截图**：对比首屏 [06_settings_general.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/06_settings_general.png) / 浅色 [07_theme_light_settings.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/07_theme_light_settings.png) 与滚到底的 [06_settings_general_bottom.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/06_settings_general_bottom.png)。
- **体验问题**：内容总高 `703px` vs 容器 `636px`，仅多出 `67px`，导致最关键的「日志目录 / 导出 AI 诊断包 / 主动上传」整块被藏在屏外，静止时右侧没有明显滚动条引导，用户很难找到主动上传入口；此外上方 4 个开关开或关全写绿标「推荐开启」、第 6 项 `敏感信息自动脱敏处理` 常驻禁用开关呈暗淡浅蓝，容易看成已关闭。

#### [P2-4]【本次新发现】系统设置「清理恢复」读取系统基线快照较慢且无增量提示
- **实机截图**：切到「清理恢复」等待 750ms 后，[06_settings_recovery.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/06_settings_recovery.png) 仍停留在 `正在读取系统与 Clash 首次基线快照...`。原因：`inspectRollbackStatus` 每次现扫注册表/网卡/YAML 耗时较长且未缓存最近结果。

#### [P2-5]【本次新发现】Windows 下国旗 Emoji 渲染退化 + `CN台湾` 节点左徽标显示为 `HK`
- **实机截图**：[04_nodes_quality.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/04_nodes_quality.png)、[04_nodes_quarantine.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/04_nodes_quarantine.png)、[07_hud_window.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/07_hud_window.png)。
- **体验细节**：Windows WebView2 默认字体下，`🇺🇸` 等国旗 Emoji 被渲染为小号灰色字母 `us` 紧贴中文（如 `us美国1|流媒体AI`），且部分字体下不够整洁；隔离区 `CN台湾1|流媒体AI` 左侧圆角徽标显示 `HK`（因为命中了中国大陆/港澳台区域规则归组）。

#### [P2-6]【本次新发现】开源协议标注前后不一致
- **实机截图**：系统设置 → 版本更新底部徽标明确写着 **`MIT 开源`**（[06_settings_update.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/06_settings_update.png)），但项目根 [package.json](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/package.json#L5) 声明为 `"license": "GPL-3.0"`。

---

### P3｜细节优化项（锦上添花）

- **[P3-1] 工具箱占用了顶层一级导航但尚无可用功能**：[05_ai_tools.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/05_ai_tools.png) 视觉非常克制且无假按钮，但占位页出现在 4 个核心一级导航中略显空旷，建议保持标注或后续尽早补齐 1~2 个高频小工具（如 MCP 检测/一键导出）。
- **[P3-2] 多处轻微排版拼写微瑕**：如「实时异常日志流`0未读`」缺空格；部分列表弹窗外沿点击（如开启 `ⓘ` 浮层时再次点击空白处，若事件冒泡到蒙层逻辑需确认只关闭浮层本身而非关掉整个设置窗）。

---

## 三、本次表现良好的部分（无需大动）

1. **双主题（Dark / Light）整体视觉与层级**：控制台、账户审计、节点质量与设置弹窗在深浅两套主题下对比度清晰、卡片边界克制（[07_theme_light_console.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/07_theme_light_console.png)、[07_theme_light_audit.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/07_theme_light_audit.png)、[07_theme_light_nodes.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/07_theme_light_nodes.png)）。
2. **「节点质量」与「隔离区」展示**：双平台（`✓ Claude` / `✓ AGY` / `AGY 限区`）、节点性质（ISP 住宅 vs 共享代理）、阻断原因标签（落地禁区 / Claude ✓）和评分条非常直观。
3. **「防封宝典」抽屉与「安全策略」L1–L4 分层**：结构清楚、图文并茂、可读性强（[03_audit_guide_drawer.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/03_audit_guide_drawer.png)、[06_settings_policy_top.png](file:///C:/Users/xujun/.gemini/antigravity/brain/e067a8a8-1069-4637-af2e-707e306c4297/scratch/v040_audit_shots/06_settings_policy_top.png)）。
4. **运行期稳定性**：19 项真实探针耗时 5.7s、单飞去重有效、Mihomo 进程守望与网卡监听 0 轮询，且全程 0 JS 运行时异常。

---

## 四、待你拍板决定的事项

请你审阅上述清单后，确认以下 4 个产品与交互取舍，我再按你定好的方案一次性落盘修改并出 `v0.4.1` 实机验收版：

1. **修复范围确认**：除了前面已定好的 **P0-1 ~ P0-5、P1-3、P1-4、P2-1**，本次新挖出的 **P1-1（`US(TPE)` 旧边缘码混入）、P1-2（未读数/OK 徽标打架）、P1-5（废弃老页面名字替换）、P2-2（HUD 深色模式同步）、P2-3（常规开关主动上传按钮露出）** 是否全部纳入 `v0.4.1` 一并解决？
2. **关于 P1-2（未读数与 `OK` 徽标）**：点进「账户审计」后是否应该**保持显示未读数字**，直到用户真正切到「实时日志」或点「全部标为已读」再归零变 `OK`？
3. **关于 P2-3（系统设置「常规开关」首屏折叠 `67px`）**：你是希望略微调高一点弹窗高度 / 紧凑行距，让最下面的「主动上传 / 导出 AI 诊断包 / 日志目录」一打开「常规开关」就能直接看到，还是在标题处增加显眼提示/跳转？
4. **关于 P2-6（开源协议统一）**：项目最终统一采用 **`GPL-3.0`** 还是 **`MIT`**？（当前 `package.json` 写 GPL-3.0，界面底标写 MIT 开源）
