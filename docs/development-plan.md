# FD Claude 安全启动器（FD Claude Guard）分阶段开发、测试与验收规格书

> **适用阶段**：正式开发执行基准（配合 [architecture-and-design.md](./architecture-and-design.md)、[anti-ban-playbook.md](./anti-ban-playbook.md) 与终版交互原型 [interactive-prototype.html](./mockups/interactive-prototype.html) 使用）  
> **核心工程原则**：零侵入、真实探针验收（绝不伪造绿灯）、测试先行、逐阶段自审验收、小问题写入 [dev-issues-log.md](./dev-issues-log.md)，重大不确定性暂停请示用户。

---

## 1. M0 · 开发环境前置检查与验收

### 1.1 本机已实测就绪环境（2026-11-23）
- **Git**：`2.46.0`
- **Node.js / npm**：`v24.14.0` / `11.9.0`
- **WebView2 Runtime**：`126.0.2592.68`
- **Rust / Cargo**：`rustup 1.29.3` / `rustc 1.100.0` / `cargo 1.100.0` (`stable-x86_64-pc-windows-msvc`)
- **Clash Verge Rev**：`Mihomo v1.19.33`，混合代理 `127.0.0.1:7890`，命名管道 `\\.\pipe\verge-mihomo-production-*`，配置目录 `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev\`

### 1.2 唯一待补齐编译依赖
- **Microsoft Visual Studio 2022 C++ Build Tools (MSVC + Windows SDK)**：
  ```powershell
  winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
  ```
  *(注：会弹一次 Windows UAC 管理员确认弹窗，需用户点击允许)*
- **M0 验收标准**：`vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath` 返回非空，且新初始化的 Tauri v2 模板能通过 `cargo check` 与 `npm run tauri build -- --debug`。

---

## 2. 技术栈与标准目录结构

### 2.1 选定依赖清单
- **前端**：`react@19`、`typescript`、`vite`、`tailwindcss@4`、`@heroui/react`、`framer-motion`、`lucide-react`、`zustand`、`@tauri-apps/api`、`@tauri-apps/plugin-notification`、`@tauri-apps/plugin-autostart`、`@tauri-apps/plugin-shell`
- **Rust 后端**：`tauri@2`、`tokio`（full）、`serde` / `serde_json`、`reqwest`（走本地代理探测出口 IP，支持 SOCKS5/HTTP）、`hyper` / `tokio-tungstenite`（支持 HTTP & WebSocket over Windows Named Pipe）、`notify`（日志文件监听）、`sysinfo`（进程树雷达）、`regex`、`chrono`、`zip`（备份与脱敏诊断包打包）、`windows` crate（Win32 进程终止、启动项只读检测、MSIX 路径解析）
- **测试工具**：前端 `vitest` + `@testing-library/react`；Rust 原生 `cargo test`（单测覆盖正则解析、脱敏逻辑、状态机、配置文件读写与策略判定）

### 2.2 代码目录结构
```text
FDtools/
├── docs/                                # 设计、防封知识库、开发计划与问题记录
├── clash-scripts/
│   └── claude-verge-override.js         # Clash Verge 全局扩展覆写脚本标准模板
├── src/                                 # React 19 + TS + HeroUI 前端
│   ├── main.tsx                         # 主控制台窗口入口 (window: "main")
│   ├── hud.tsx                          # 桌面悬浮状态卡入口 (window: "hud")
│   ├── styles/theme.css                 # HeroUI 语义色（标准警示红 #EF4444）与 4pt 字阶
│   ├── stores/guardStore.ts             # Zustand 全局态 + Tauri Event 订阅
│   ├── lib/ipc.ts                       # 类型安全的 Tauri invoke 封装
│   ├── components/
│   │   ├── WindowChrome.tsx             # Windows 11 原生右上角控制栏 (─ □ ✕)
│   │   ├── Sidebar.tsx                  # 控制台 / 节点流量 / 日志分析 / 环境维护 / 守卫配置
│   │   ├── PlaybookDrawer.tsx           # 联动式 8 大安全守则抽屉（支持定位 + 闪烁高亮）
│   │   └── RiskModal.tsx                # 三档节点容灾 / 风险解除确认弹窗
│   └── pages/
│       ├── ConsolePage.tsx              # 启动前两级三防线体检 + 一键处理全部 + AI 排障包导出
│       ├── NodesTrafficPage.tsx         # 主备节点质量锁 + 实时异常/正常流量监控
│       ├── LogAnalysisPage.tsx          # 异常置顶归因 + 展开前后文 + 定位守则
│       ├── MaintenancePage.tsx          # 强杀清队列 + ZIP 备份还原 + 脱敏诊断包
│       └── SettingsPage.tsx             # 全 Toggle 开关 + 开机启动项只读风险监测
└── src-tauri/
    ├── Cargo.toml
    ├── tauri.conf.json                  # 双窗口 (main + hud) + 系统托盘配置
    └── src/
        ├── lib.rs                       # 应用装配、托盘菜单、开机仅显悬浮窗逻辑
        ├── state.rs                     # 共享运行态、事件广播与防裸奔状态机
        ├── config/mod.rs                # ~/.fd-claude-guard/config.json 持久化
        ├── mihomo/                      # 命名管道自动发现 + REST/WS 客户端 + 掐流
        ├── preflight/                   # 两级三防线真实探针 + 一键/向导修复执行器
        ├── killswitch/                  # MSIX 路径追踪 + 防火墙规则 + 4 层防回传
        ├── process/                     # Claude 进程树雷达 + 防裸奔 <100ms 接管 + 强杀
        ├── watchdog/                    # main.log/web.log 增量 tail + 异常归因 + 守则联动
        ├── startup_audit/               # Clash/Claude 开机启动项只读检测（绝不修改）
        └── maintenance/                 # ZIP 备份管理 + 一键还原 + AI 脱敏排障包导出
```

---

## 3. 前后端核心 IPC 契约

### 3.1 Tauri Commands（前端 → Rust）
| Command | 功能说明 | 返回摘要 |
| :--- | :--- | :--- |
| `run_preflight_checks()` | 并行执行全部两级三防线真实探针 | `PreflightReport`（含每项实测证据、能力分级、状态） |
| `fix_preflight_item(item_id)` | 执行单项修复并立刻重跑该项真实探针 | `FixResult`（修复前/后探针值、是否需要手动步骤） |
| `one_click_fix_all()` | 顺序执行全部可自动修复必须项，停在首个需手动配合项并返回引导 | `BatchFixResult` |
| `safe_launch_claude()` | 再次复核全部必须项通过后拉起 Claude Desktop | `Result<(), String>` |
| `get_nodes_and_quality()` | 过滤禁区节点，输出节点评分、主备角色与 7 天切换次数 | `NodeReport` |
| `switch_locked_node(name, force_ignore_risk)` | 校验进程为 0 与冷却期（主节点故障自动豁免），切换 `Claude-Fixed` 并重测出口 | `SwitchResult` |
| `get_live_connections()` / `close_connection(id)` | 查询/掐断 Claude 实时连接 | `Vec<ClaudeConn>` |
| `kill_claude_processes(clean_telemetry)` | 强杀 Claude 进程树（跳过 `onQuitCleanup`），可选清 `~/.claude/telemetry/` | `KillReport` |
| `trigger_killswitch()` / `force_release_killswitch(confirmed)` | 触发/按风险确认解除 Windows 防火墙阻断 | `KillSwitchState` |
| `list_backups()` / `backup_and_clean_claude()` / `restore_backup(file)` | 污染目录备份管理、清理与一键还原 | `BackupInfo` |
| `export_ai_diagnostic_bundle(context_item_id?)` | 导出并复制**脱敏后的 AI 排障上下文**（Markdown + ZIP，自动打码邮箱/Token/完整 IP） | `{ zip_path, prompt_markdown }` |
| `get_config()` / `update_config(patch)` | 读写全部 Toggle 开关配置并同步开机自启注册状态 | `AppConfig` |
| `audit_startup_items()` | 只读检测 Clash Verge / Claude / FD Guard 开机启动项 | `StartupAuditReport` |
| `open_log_location(file, line)` | 在系统默认编辑器或资源管理器定位日志文件 | `Result<(), String>` |

### 3.2 Tauri Events（Rust → 双窗口实时推送）
- `guard://snapshot`：全局健康状态、当前节点/延迟/IP、后台进程数、熔断态、待处理项计数；
- `guard://log-event`：实时解析出的中文行为/异常事件（含关联 `playbook_rule_id`）；
- `guard://flow-anomaly`：实时捕获并已掐断的异常连接事件；
- `guard://naked-launch-intercepted`：防裸奔接管触发，自动唤起并聚焦控制台；
- `guard://playbook-triggered`：某条安全守则被实时命中，同步推送至悬浮窗与抽屉红点。

---

## 4. 分阶段开发、测试与严格验收计划

### 阶段 M1 · HeroUI 工程骨架 + 双窗口 + 托盘 + 守卫配置（预计第 1 里程碑）
- **开发范围**：
  1. 初始化 Tauri v2 + React 19 + Tailwind v4 + HeroUI + Lucide 项目；
  2. 实现 Windows 11 原生无边框窗口控制（`─` / `□` / `✕` 隐藏至托盘）与 5 大导航骨架（控制台 / 节点流量 / 日志分析 / 环境维护 / 守卫配置）；
  3. 实现桌面悬浮动态卡片独立窗口（`hud`）：默认展开、默认置顶、图钉纯图标变实无蓝底、Home 图标、窗口收折图标、关闭退回托盘，支持 **靠右贴边自动隐藏（Edge Dock，仅露 `14px` 状态耳标，鼠标悬浮滑出、移开缩回）**，底部**统一跳回控制台**；
  4. 实现 `config.json` 持久化、全部 Toggle 开关（含「开机启动」「开机仅显悬浮窗不弹控制台」、清晰区分「推荐开启 / 仅熔断生效 / 按需开启」、24h 冷静保护倒计时说明）以及「安全守则」8 项抽屉与定位闪烁动效；
  5. 控制台严格遵守「一屏唯一蓝色主按钮」层级，顶部接入「事件驱动 + 15 分钟全量巡检倒计时 + 手动重新实测」，导出 AI 脱敏排障包默认保存至 `%USERPROFILE%\Desktop\` 并复制到剪贴板、Toast 提供「打开所在文件夹」。
- **测试与验收标准**：
  - `cargo test`、`npm run test`、`npm run build` 全部通过；
  - 实测启动后主窗口与悬浮窗位置/显隐独立可控，拖拽悬浮窗重启后记住坐标；
  - 关闭主窗口与悬浮窗后系统托盘常驻、内存 `< 40MB`，右键托盘可随时呼出。

### 阶段 M2 · Clash Verge 管道联动 + 两级三防线真实探针 + 一键处理闭环（第 2 里程碑）
- **开发范围**：
  1. 实现 Windows 命名管道自动枚举 `\\.\pipe\verge-mihomo-*`（兼支持 External Controller 回退），打通 `GET /configs`、`GET /proxies`、`GET /rules`、`PUT /proxies/{group}`、`WS /connections`、`DELETE /connections/{id}`；
  2. 实现全部真实探针：
     - 代理端口与冲突扫描（7890 vs 12334/10808/7897）；
     - `Claude-Fixed (select)` 策略组与全家桶规则表实查 + `Script.js` 自动备份写入模板；
     - **经代理出口白名单、落地 IP 静默漂移、ASN 纯净度与 Anthropic 真实可达性探针**：记录历史锁定节点落地 IP 监测机场后台静默换落地；接入免费 IP 情报源识别 ISP 住宅 vs 机房/Proxy；发无状态只读 TLS/HTTP 探针校验 `api.anthropic.com / claude.ai` 真实可达（筛掉被 CF 403 拉黑的假在线节点）；
     - **IPv6 三层实测**（Mihomo 配置 + 网卡 `ms_tcpip6`/注册表 + 真实外网 IPv6 连通探针）；
     - **虚拟网卡接管（TUN）实测**（Mihomo `tun.enable` + Wintun 网卡在线）与 **DNS Fake-IP 实测**（独立拆项，实测 `claude.ai` 解析落入 `198.18.0.0/15`）；
     - 本地封号污染残留扫描、单号锁与 **全量代理环境变量审计**（`ANTHROPIC_BASE_URL`、`HTTP_PROXY / HTTPS_PROXY / ALL_PROXY / NO_PROXY` 冲突及直连豁免、Windows WinINET `ProxyServer` 一致性核验，确保桌面/CLI/网页三端同 IP）、官方 `settings.json` 隐私降噪读写；
     - **Anthropic 官方状态 API**（`status.anthropic.com/api/v2/summary.json`）接入，区分官方故障与本地风控；
     - 开机启动项只读检测（Clash / Claude，绝不修改启动项）与 NTP UTC 偏差实测；
  3. 实现控制台「一键处理全部问题」顺序执行流与单项失败时清晰引导。
- **测试与验收标准**：
  - 编写完整 Rust 单元测试覆盖策略组校验、Fake-IP 段判断、日志扫描与配置合并；
  - 真机实测：故意关闭 Clash 或切到 HK 节点或删掉 `settings.json` 开关，控制台必须真实变红并锁定启动；点「一键处理全部问题」后自动修完可修项并精准停在需手动重载项，重载后自动实测变绿。

### 阶段 M3 · 4 层紧急防回传 + 防裸奔接管 + 日志/流量异常归因联动（第 3 里程碑）
- **开发范围**：
  1. 实现 MSIX 动态路径追踪（解析 `AnthropicPBC.Claude*` 的 `Claude.exe`）与 Windows Defender 防火墙规则（统一命名 **`FDClaudeGuard_KillSwitch_*`**）的创建/验证/放行/一键全清救援，及免 UAC 计划任务安装向导；
  2. 实现 **休眠唤醒 / 切网 5 秒预阻断安全窗**：监听 Windows 原生电源事件（`PBT_APMSUSPEND` / `PBT_APMRESUMEAUTOMATIC`）与网卡变更，唤醒/切网瞬间先临时锁定出站，待代理管道与真实出口复测通过后毫秒级自动放行；
  3. 实现 **4 层紧急防回传**：自动 Clash 掐流 + 防火墙锁死 + 强杀 Claude 进程树（跳过 `onQuitCleanup`）+ 清空 `~/.claude/telemetry/`，以及熔断态风险操作严格隔离（运行中严禁直接推荐解除）；
  4. 实现 **Claude 进程雷达**、**「Kill-Hold 防复活持续盯防锁」**（手动/自动任意强杀后进入默认 `45s`（`30s/45s/60s` 可配）的 `250ms` 高频盯防，覆盖 `Claude.exe`/`claude-code`/Chrome 桥接进程，冒头即杀并记录拦截次数、每次复活顺延 `+15s`；备份/还原/切节点/熔断期间全程事务锁定；点「安全启动 Claude」或「解除盯防」自动优雅释放）与 **防裸奔 `<100ms` 自动接管**；
  5. 实现 `main.log` & `claude.ai-web.log` 毫秒级增量 `tail` + 异常置顶归因 + 精确行号定位 + 与「安全守则」双向高亮闪烁联动；
  6. 实现「节点流量」中 Claude 实时异常/正常连接流展示与自动掐断记录（含 12h 滚动拦截窗口与手动清角标）。
- **测试与验收标准**：
  - 用模拟日志文件注入 `region_unavailable`、`account_banned`、跨 `orgId`、`429` 测试，验证 `< 200ms` 触发告警、置顶归因、点亮对应守则并点击闪烁定位；
  - 实测在环境未全绿时直接启动测试进程/模拟切禁区，验证自动触发防火墙规则阻断并弹出原生通知。

### 阶段 M4 · 节点三档容灾 + 环境维护回滚 + AI 脱敏排障包 + Release 打包（第 4 里程碑）
- **开发范围**：
  1. 实现节点质量评分、**Claude + Gemini 双平台无状态可用性与 ASN 纯净度探测**（节点表格合理排布「平台支持 / 纯净度」列填补空白，清晰标识 `Claude ✓/✗` 与 `Gemini ✓/受限/送中`，双 AI 通优先推荐但不因不支持 Gemini 阻断 Claude；Mihomo 状态卡片文案改用「管道已连接」避免误解为“直连”）、主/备同区热备配置、三档容灾弹窗与 24h 冷静保护联动；
  2. 实现污染目录 **原子事务 ZIP 备份管理器**（唯一时间戳命名防覆盖、还原前自动建安全点、ZIP 完整性与 2 倍磁盘校验、先解压临时目录再原子切换防损坏、保留最近 10 份）与安全退出防呆提醒；
  3. 实现 **「导出脱敏 AI 排障包 / 一键复制排障提示词」**（汇聚探针快照 + Anthropic 官方状态 + Claude 官方诊断元数据 `system-info/vm-info/mcp-info` + 异常日志摘录；严格正则脱敏邮箱/Token/SessionKey/完整 IP）；
  4. 构建 Windows Release 安装包（NSIS / MSI），在 **NSIS Uninstall Hook 中自动清空全部 `FDClaudeGuard_KillSwitch_*` 防火墙残留规则（防卸载后自锁断网）**，并在「环境维护」内提供一键清除全部本工具防火墙规则救援按钮；执行全链路回归自审与内存占用压测。
- **测试与验收标准**：
  - 单元测试 100% 断言脱敏模块不会泄露任何 Token/邮箱/完整 IP；
  - 真机冷启动、重启开机仅显悬浮窗、全流程体检→一键处理→安全启动→模拟熔断→导出 AI 排障包全部无错通过，后台常驻内存 `< 40MB`。

---

## 5. 高标准 UX & QA 强制验收门禁与问题记录铁律

每次 UI/交互交付或里程碑收口，必须按以下 **5 道成熟桌面端 QA 门禁** 逐项实测并留痕，绝不凭直觉宣称完成：

1. **信息架构与图标统一审查**：全站严禁跨区信息重复（同一指标不在多处堆砌复述）；所有图标严格统一使用 `lucide-react` 标准几何路径与统一线宽（`1.75–1.85`）；选中态克制（悬浮窗开关图标禁止彩色底块与底部下划线，仅纯图标实心/加亮）；每屏仅保留一个主蓝色 CTA。
2. **几何与坐标零偏移断言（Pixel-Zero Drift）**：固定态 ↔ 贴边滑出态、展开 ↔ 折叠、拖拽更新纵坐标后切换贴边再取消，悬浮窗实测 `getBoundingClientRect()` 坐标偏移必须 `Δx ≤ 1px, Δy ≤ 1px`。
3. **热区边界多点防误触实测**：贴边收起态必须仅由 `20×84px` 边缘耳标响应鼠标；自动扫测距右边缘 `300px / 150px / 50px / 28px` 四点均 0 误触，仅进入 `≤ 20px` 耳标精准展开、移开平滑收回且无闪烁。
4. **改动影响面 + 局部 1:1 放大特写 + 全部弹窗/抽屉必审（绝不只看整屏缩略图）**：
   - 凡是改动过的区域（如顶栏图标间距/对齐/视觉重心、按钮边距、卡片排版），必须对**改动区域做 1:1 元素裁剪特写截图**并逐像素核验节奏与留白，主动检查对相邻元素的影响（如分割线两侧是否对称、是否压线、是否与其他控件节奏割裂）；
   - **所有模态弹窗（节点切换风险评估、强制解除熔断等）、右侧抽屉、Toast 与深浅主题均必须实拍 1:1 特写逐张审图**，严禁只断言“打开不报错”就跳过视觉验收！
5. **全路径交互与零报错门禁**：全程 `console.error === 0` / `pageerror === 0`；悬浮窗各模块点击回控制台精准定位，弹窗/开关/回滚全路径可跑通（并验证边界业务语义，如跨洲切换不得误判为同区热备）；每里程碑必跑 `cargo test` + `npm test`。
6. **问题记录与请示边界**：小问题（管道名差异、Windows 权限边界、UI 细微适配）一律记入 [dev-issues-log.md](./dev-issues-log.md) 并标注处理方案；仅遇到**重大架构取舍或高危系统改动不确定性**时暂停请示用户。
