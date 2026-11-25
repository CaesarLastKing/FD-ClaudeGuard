# FD Claude 安全启动器（FD Claude Guard）开发问题与决策记录

> 本文件用于记录 M0–M4 开发、测试与验收过程中遇到的技术小问题、环境差异、已落地的处理方案及需用户拍板的重大待决项。

---

## 待用户确认的重大不确定项（如有）
*（当前暂无，M0 编译工具链已安装就绪）*

---

## 开发过程记录日志

| 编号 | 阶段 | 发现时间 | 问题描述 | 处理方案 / 现状 | 状态 |
| :--- | :---: | :---: | :--- | :--- | :---: |
| `ISS-001` | M0 | 2026-11-23 | 本机尚未安装 Visual Studio 2022 C++ Build Tools (MSVC)；自动化子进程调用 `winget install` 触发退出码 `1602` | 用户已在管理员终端完成 VS 2022 C++ Build Tools 安装，MSVC 工具链就绪 | ✅ 已解决 |
| `ISS-002` | M0 | 2026-11-23 | 本机 Clash Verge Rev 默认未暴露 TCP 9090/9097，而是使用带哈希后缀命名管道 `\\.\pipe\verge-mihomo-production-<hash>` | M2 `mihomo` 客户端将实现动态枚举 `\\.\pipe\verge-mihomo-*` 零配置直连，同时保留 External Controller 回退 | ✅ 已纳入设计 |
| `ISS-003` | M0 | 2026-11-23 | 本机实测 `Tcpip6\Parameters\DisabledComponents = 8`，且 `Mihomo` 虚拟网卡 `ms_tcpip6` 为 Enabled | M2 IPv6 检测采用“Mihomo 配置 + 网卡绑定 + 真实外网 IPv6 探针”三层实测，避免误报绿灯 | ✅ 已纳入设计 |
| `ISS-004` | M1/M2 | 2026-11-23 | 实测本机已存在 `~/.claude/telemetry` 与 Clash Verge `profiles/Script.js`，但传统 `%APPDATA%\Claude` 与 MSIX 虚拟路径可能并存或为空 | M2/M3/M4 路径扫描同时兼容传统 Electron 路径、MSIX `LocalCache` 虚拟路径与 `~/.claude` CLI 路径，缺失时诚实展示状态 | ✅ 已纳入设计 |
| `ISS-005` | M2 | 2026-11-23 | 真机自审发现并发 `tokio::join!` 打开 4 条 Mihomo Named Pipe 请求时触发 Windows `ERROR_PIPE_BUSY (231)` 导致 `/proxies` 偶发失败 | 在 `http_over_named_pipe` 增加 `ERROR_PIPE_BUSY` 指数退避重试，并将本地 4 个管道 GET 改为串行（总耗时 <10ms） | ✅ 已修复并复测 |
| `ISS-006` | M2 | 2026-11-23 | 真机实测检出禁区节点正则中的单字 `澳` 误杀合法节点 `🇦🇺澳大利亚\|原生` | 精确化禁区正则（使用 `澳门\|澳門\|Macau\|\bMO\b` 替代单字 `澳`、`香港` 替代单字 `港`），同步更新 Rust 与 `claude-verge-override.js` 并补充回归单测 | ✅ 已修复并复测 |
| `ISS-007` | M4 | 2026-11-23 | 脱敏模块单测发现 `re_kv` 中的 `authorization` 与 `re_bearer` 重复匹配，导致 `Bearer [REDACTED_TOKEN]` 被二次覆写 | 调整 `re_kv` 职责范围仅匹配 `sessionKey/oauth_token/access_token/refresh_token/cookie`，`Bearer` 统一由 `re_bearer` 规范打码 | ✅ 已修复并复测 |
| `ISS-008` | M4 验收 | 2026-11-23 | 实测 `--autostart` 稳态主进程内存仅 `30.51 MB`（私有 `8.93 MB`），但静态预创建的双 WebView2 子进程占用 `113.66 MB` | 已改造为「主控制台窗口按需懒创建」：`--autostart` 开机仅创建单悬浮窗，WebView2 占用降至 `101.2 MB`，主进程私有内存仅 `10.9 MB` | ✅ 已修复并复测 |
| `ISS-009` | 运行态验收 | 2026-11-23 | 视觉验收发现 `ConsolePage.tsx` 当某项为 `fail/warn` 且 `fixLabel == null` 时，详情卡底部误显示绿字「该项已通过真实探针验收」，且隐藏了「导出脱敏问题包给 AI 分析」按钮 | 已修复为严格按 `status === "ok"` 判定；非 `ok` 项始终保留 AI 排障包导出按钮，并补充 Vitest 回归断言 | ✅ 已修复并复测 |
| `ISS-010` | 运行态验收 | 2026-11-23 | 悬浮窗展开态实测内容高度 `188px`（2 条事件约 `210px`），收折态 `107px`，原固定窗口高度 `236px` 底部略有透明留白 | 新增 `resize_hud_height` 与前端 `ResizeObserver` 动态精准贴合高度，实机复测自动贴合为 `376x220` | ✅ 已修复并复测 |
| `ISS-011` | 运行态验收 | 2026-11-23 | `lib.rs` 中 `WindowEvent::Moved` 在拖拽悬浮窗期间每移动 1px 即同步执行 `save_config` 写盘，高频拖拽易引起卡顿与文件锁竞争 | 已改为 `AtomicU64` 序号 + 400ms 异步防抖落盘，仅拖拽停止后写入 1 次 `config.json` | ✅ 已修复并复测 |
| `ISS-012` | 运行态验收 | 2026-11-23 | `spawn_process_radar` 每 2 秒拉起一次 `tasklist.exe` 子进程，存在周期性进程创建开销与句柄微抖动 | 已替换为 Win32 原生 `CreateToolhelp32Snapshot` / `Process32FirstW` 枚举（零子进程、耗时 `<0.2ms`）并新增 Rust 单测 | ✅ 已修复并复测 |
| `ISS-013` | 运行态验收 | 2026-11-23 | 冷启动时后端 `setup` 与前端 `bootstrap()` 连续各跑一遍 11 项探针，且首次启动未自动落盘默认 `config.json` | 已实现首次启动自动初始化落盘 `~/.fd-claude-guard/config.json`，并引入 6 秒探针结果缓存去重（手动点重新实测传 `force=true`） | ✅ 已修复并复测 |
| `ISS-014` | 运行态验收 | 2026-11-23 | 托盘右键点击「退出 FD Claude Guard」直接 `app.exit(0)`，未联动 `safe_exit_prompt` 开关防呆拦截 | 已补齐安全退出防呆闭环：检测到 Claude 存活时唤起控制台发 `guard://confirm-exit` 弹二次确认（先强杀再退出 / 忽略风险退出） | ✅ 已修复并复测 |
| `ISS-015` | 运行态验收 | 2026-11-23 | 缺少系统化、落盘、按日滚动的详细运行诊断日志，不利于后续持续优化产品问题 | 已落地 `src-tauri/src/logger/mod.rs`：脱敏落盘 `~/.fd-claude-guard/logs/guard-YYYY-MM-DD.log`（UTF-8 BOM/毫秒时间戳/14天滚动/前端错误上报/自动附入 AI 诊断包/界面一键打开日志目录） | ✅ 已修复并复测 |
| `ISS-016` | v1.5 QA 门禁 | 2026-11-24 | 浏览器独立预览 `hud.html?state=danger&theme=light` 时，第二个 `useEffect` 异步拉取默认配置覆写了 URL 预览参数 | 已在 `src/components/HudCard.tsx` 识别非 Tauri 预览覆写标志，避免覆写，复验深色守护正常态与浅色熔断危急态 1:1 全通过（`console.error = 0`） | ✅ 已修复并复测 |
| `ISS-017` | 用户真机验收 | 2026-11-24 | 环境维护页备份过多时外层 flex 容器挤压变形、未按创建时间排序（按字母序且缺秒级）、缺少单条/清空全部备份操作 | 为外层补齐 `flex: 1; minHeight: 0; overflowY: auto` 及卡片 `flexShrink: 0`；后端按实际时间戳降序返回精确到秒 `YYYY-MM-DD HH:mm:ss`；新增 `delete_backup` / `clear_all_backups`（含二次确认） | ✅ 已修复并复测 |
| `ISS-018` | 用户真机验收 | 2026-11-24 | Windows 高 DPI 缩放下悬浮窗右侧与底部被严重裁切（356 像素被当物理像素处理） | 在 `src-tauri/src/lib.rs` 统一按 `hud.scale_factor()` 设置精确 `PhysicalSize`，前端 `HudCard.tsx` 同步上报宽高，全 DPI 完整零裁切 | ✅ 已修复并复测 |
| `ISS-019` | 用户真机验收 | 2026-11-24 | `watchdog` 使用裸字符串 `"429"` 误将正常日志 PID `14292` 报为高并发 429，且模拟与真实日志不易区分 | 改为精确正则匹配 `http/status 429`、`rate_limit_error`、`sideSessions>=3` 并增加防 PID 误报单测；模拟事件标注 `模拟演示` 徽章并支持一键清空 | ✅ 已修复并复测 |
| `ISS-020` | 用户真机验收 | 2026-11-24 | 封号账号登录产生的真实 OAuth `authorize returned 403 (permission_error)` / `fresh exchange failed (auth_error)` 未实时触发控制台与单号卫生锁刷新 | 补全真实 403/auth_error 封号与 `orgId` 提取审计（单号卫生锁弹出二选一引导确认），后台每 2 秒监测 Claude 日志文件指纹变化事件驱动推送 `guard://preflight-updated` | ✅ 已修复并复测 |
| `ISS-021` | 用户真机验收 | 2026-11-24 | Claude 已有进程运行时控制台右上角仍显示「安全启动 Claude」；各耗时按钮缺加载态；`opt_fw` 无操作方法 | 有进程运行时主 CTA 自动切换为「安全退出 Claude（N 进程运行中）」；全站耗时按钮统一接入 `Loader2` 加载态；`opt_fw` 补齐「安装免 UAC 守护权限并实测」与防自锁救援闭环 | ✅ 已修复并复测 |
| `ISS-022` | 用户真机验收 | 2026-11-24 | 日志统计卡不可点击筛选、无法查看本地遥测数据具体内容 | 顶部 4 张统计卡支持点击高亮筛选；新增「本地遥测数据与设备采集详情（脱敏只读）」查看面板，支持读取 `~/.claude/telemetry/` 文件预览 | ✅ 已修复并复测 |

---

## v1.6 增量 11~16 + 结构化 JSONL 日志与真机复验汇总（2026-11-24）

- **启动前体检三分界（增量 16）**：严格重构为 **10 项必须 + 3 项建议 = 13 项**（改 Clash 5 项 / 改 Windows 系统 2 项含独立 `sys_env` / 改 Claude 3 项含单号二选一引导确认 / 建议优化 3 项独立闭环）。
- **防封深度加固（增量 11~15）**：落地 IP 静默漂移 + ASN 纯净度（ISP 住宅 vs 机房 Hosting）、Anthropic 无状态防 CF 403 探针与禁用切换、休眠唤醒 5 秒预阻断安全窗、全量 CLI/WinINET 代理审计、`FDClaudeGuard_KillSwitch_*` 防火墙统一前缀 + 防自锁救援 + NSIS 卸载自动清理钩子（`src-tauri/nsis/hooks.nsh`）。
- **日志可观测性升级**：按天滚动结构化 JSONL 落盘 `%LOCALAPPDATA%\FDClaudeGuard\logs\guard-runtime-YYYYMMDD.jsonl`（保留 14 天，全量 `<REDACTED:2W>` 脱敏）；导出诊断包自动打包最近 7 天脱敏 `logs/guard-runtime-*.jsonl` 与 `ai-review-prompt.md` 复盘模板。
- **全量验证**：Rust `28/28`（零编译警告）+ 实机 13 项探针通过（实机精准检出 `claude_ban` 与 `claude_acct`）；前端 Vitest `12/12` + `tsc --noEmit` + `vite build` 0 错误；v1.6 7 张 1:1 增量视觉审图全通过（`console.error = 0`）；Release NSIS 安装包（4.24 MiB）真机实测内存 `43.2 MB`、结构化 JSONL 日志落盘正常。

---

## v1.5 全量 10 项增量 + QA 门禁与真机复验汇总（2026-11-24）

- **协议常量与单测**：100% 锁定 `docs/protocol-constants.md` 全部常量（`FD_ERR_2152/3562/4649/5304/6817/7459`、`0x12708F87`、`<REDACTED:2W>`、`60489`/`29121`/`904543`、四维权重 `0.37/0.25/0.24/0.14`、`133`/`7.8` 与校准盾牌 SVG 路径）；Rust `26/26`、实机探针 `12/12`（9 必须 + 3 建议 + Anthropic 官方状态页 API）、前端 Vitest `11/11` 全绿。
- **QA 视觉与几何零偏移门禁**：主窗口顶栏双纯图标开关 + `Fuck Dario！！！` + 1px 细竖线、同区/跨洲现代三段式弹窗（496px）、安全守则抽屉（4A/4B 拆分）、环境维护应急风险提示、守卫配置全宽折行、深浅双主题与 HUD v2.2 展开/折叠/贴边耳标全量 1:1 审图通过；实测 `dx = 0px, dy = 0px` 零偏移，右边缘 `300/150/50/28px` 0 误触，`≤ 20px` 精准展开，`console.error = 0`。
- **Windows Release 真机复验**：`FD Claude Guard_0.1.0_x64-setup.exe`（4.14 MiB）构建通过；`--autostart` 内存 `41.3 MB` / CPU `0.14s`，正常模式内存 `41.6 MB` / CPU `0.09s`，`preflight_gate` 单飞缓存 `0ms` 消除启动双跑，运行日志具备 UTF-8 BOM 且中文无乱码。

### 增量 17 / 18 / 19 实施与终验记录（2026-11-24）
- **ISS-023 · 增量 17（Kill-Hold 防复活持续盯防锁）**：复用 Win32 原生 `CreateToolhelp32Snapshot` 关联进程树筛选（含 `Claude.exe`、`claude-code.exe` 与挂载在 Claude 树下的 `chrome-native-host.exe`），新增 250ms 高频盯防协程（默认 45s，支持 30s/45s/60s 配置；冒头即强杀并自动顺延 +15s；备份清理/快照还原/切节点/熔断期间事务级锁定；安全启动前自动优雅释放）。侧边栏进程卡与悬浮窗进程微卡片同步蓝态「盯防 Xs」，严格保留 `ISS-010/018` 动态高度与高 DPI 物理像素缩放。
- **ISS-024 · 增量 18（Claude + Gemini 双平台可用性与 5 列高密度节点表）**：新增无状态只读双平台探针（5 分钟缓存、双 AI 通加分标「双 AI 推荐」、Gemini 不可用不阻断 Claude）；重构节点表为 5 列无挤压排版；右上角状态卡由「已直连」改为无歧义的「管道已连接 (Claude-Fixed)」。
- **ISS-025 · 增量 19（商业授权 + 纯净毛玻璃体验态 + 顶栏售后入口 + UI 精致化）**：
  - 使用 Cargo `commercial-license` feature 隔离 `src-tauri/src/licensing/`（双模式 `cargo test` 商业版 34/34、开源版 `--no-default-features` 31/31 全绿）；实现 `build.rs` 编译期 AES-256-GCM 密文资产打包、Ed25519 离线验签、Windows DPAPI 金库绑定 `inst.id`、Cloudflare Workers + D1 一码一次原子核销服务（`license-server/`）与 `.local-private/generate-keys.mjs` 生码脚本；卸载销毁 `vault.dat` 与 `inst.id` 已直接追加进现有 `src-tauri/nsis/hooks.nsh`。
  - 未激活态右侧保留纯净毛玻璃斜纹马赛克（无居中文字胶囊、DOM 无明文）并隐藏排障包导出链接（已激活保留 `ISS-009`）；主窗口顶栏新增纯图标耳机「售后」按钮弹出官方售后 QQ `2568515327`；**严格遵照用户指示，激活弹窗底部 Footer 不显示 QQ 售后**。
  - 精致化「日志分析」与「节点流量」顶部统计卡字号（`18px` 主数字 + `12px` 轻单位）；完善环境维护页「4 层紧急防回传熔断控制」的 3 类自动触发场景说明及「防自锁救援」的 Windows 标准卸载路径说明。
- **全量回归与 1:1 截图自审**：Vitest 5 文件 16/16 通过、Rust 商业版 34/34 + 开源版 31/31 通过、浏览器 7 场景 1:1 截图人工审阅通过且 `console.error === 0`。

---

### 真机深度排查、退出/卸载加速、130% 文本缩放悬浮窗与方案 B 图标升级（2026-11-24）

| 编号 | 阶段 | 发现时间 | 问题描述 | 处理方案 / 现状 | 状态 |
| :--- | :---: | :---: | :--- | :--- | :---: |
| `ISS-026` | 用户真机反馈 | 2026-11-24 | 连续输入 4 枚激活码均核销失败，且云端 D1 120 枚激活码全部仍为 `unused` | `.local-private/build-secrets.json` 中的 `license_api_url` 仍为占位符 `https://fd-claude-guard-license.<你的子域>.workers.dev/api/v1/activate`。已替换为生产 Workers 域名（无损实测 `/api/v1/health` 200、假码 `/api/v1/activate` 409、Ed25519 公私钥配对 `true`、D1 120/120 哈希全命中），并在 `src-tauri/build.rs` 新增编译期占位符 `assert!` 门禁 | ✅ 已修复并实测 |
| `ISS-027` | 用户真机反馈 | 2026-11-24 | 激活核销失败时前端完全没有任何提示 | `LicenseModal.tsx` 中 `useEffect` 依赖数组包含 `submitting` 且无条件调用 `setErrorMsg(null)`，导致 `catch` 刚写入错误、`finally` 将 `submitting` 改回 `false` 的瞬间即清空提示。已拆分 `useEffect` 依赖、升级醒目红色错误提示框、补充 Rust 失败日志与 Vitest 回归单测；同时优化 `activate_license_cmd` 就地秒刷新解密指南（不再阻塞 4.5s 双跑探针） | ✅ 已修复并复测 |
| `ISS-028` | 用户真机反馈 | 2026-11-24 | 3440×1440 屏幕（DPI 100%，Windows 辅助功能「文本大小」`TextScaleFactor=130%`）下悬浮窗被裁切为 `354×163` 物理像素，右侧按钮与底部指标缺失、无法展开 | WebView2 将 `TextScaleFactor=130%` 叠乘到页面渲染，而 Win32 `hud.scale_factor()` 仅读显示器 DPI (`1.0`)。已在 `src-tauri/src/lib.rs` 新增读取注册表 `HKCU\Software\Microsoft\Accessibility\TextScaleFactor` 的 `effective_hud_scale()`，并与前端上报 `window.devicePixelRatio` 取最大值计算物理尺寸；补齐双击顶栏快捷展开/收起 | ✅ 已修复 |
| `ISS-029` | 用户真机反馈 | 2026-11-24 | 软件退出极慢（卡顿 6~11 秒）且存在双开残留进程，退出不利索 | 1）旧版退出在 UI 主线程同步启动 2 次 `powershell Get-NetFirewallRule`（实测单次 5194ms）+ 4 次 `netsh`；现改为后台线程 + 轻量 `netsh show/delete`（实测 345ms，仅在存在活跃规则时清理），且点退出 0ms 立即隐藏所有窗口与托盘图标 + 250ms 硬退出兜底；2）新增 Windows 原生 `Local\FDClaudeGuard_SingleInstance_v1` 单实例互斥锁，二次双击直接唤起已有主窗不再双开 | ✅ 已修复 |
| `ISS-030` | 用户真机反馈 | 2026-11-24 | NSIS 卸载进度条卡死在第一格，且覆盖升级新版时可能触发旧版卸载钩子销毁已激活的 `vault.dat` 与 `inst.id` | 旧版 `src-tauri/nsis/hooks.nsh` 中 PowerShell 命令引号转义错误（`\"` 非 NSIS 转义）导致卸载器挂起，且未区分 `$UpdateMode`。现彻底移除卸载 PowerShell、卸载/升级前先 `taskkill /F /IM fd-claude-guard.exe` 防止文件占用、并用 `${If} $UpdateMode <> 1` 严格保护覆盖升级不销毁授权凭证 | ✅ 已修复 |
| `ISS-031` | 用户需求升级 | 2026-11-24 | 更换更具 Claude 辨识度、体现工具感且带 `Fuck Dario` 恶趣味的应用图标 | 最终采用用户提供的矢量源文件 `single_fixed.svg` 超采样裁切并替换全端 4 处图标：任务栏/桌面/安装包（7 帧 `icon.ico` + PNG）、右侧系统托盘（显式内嵌 `32x32.png`）、控制台顶栏左上角与悬浮窗顶栏左侧（`public/app-icon.png`）；同步为 `sys_ipv6`/`opt_ntp`/`opt_boot` 补齐 `CREATE_NO_WINDOW` 防闪黑窗 | ✅ 已替换 |
| `ISS-032` | 真机核销复测 | 2026-11-24 | 真码 `FDG-TEST-DEMO-0001` 在线实测仍被 Cloudflare Worker 返回 409，尽管 D1 中状态为 `unused` | 排查定位线上 Worker Secrets（`SERVER_SALT` 等）此前通过 stdin 注入残留换行符/空白导致 HMAC 不一致。已在 `license-server/worker.js` 对 3 个 Secret 增加 `.trim()` 并通过无换行 JSON `wrangler secret bulk` 重新注入且重新部署（`dd7d71e0`）；复跑真码闭环实测 `1.00s` 通过（在线核销 → 2310 B 脚本 + 14 份指南解密 → DPAPI `vault.dat` 落盘 → 纯离线重载验签 → 二次重放 409 拒绝），云端 D1 精确更新为已核销 | ✅ 已修复并真机闭环 |
| `ISS-033` | 用户需求升级 | 2026-11-24 | 未激活态控制台和 4 个副页面暴露过多诊断信息；控制台隐藏项左侧检测标题与右侧状态均须隐藏 | 1）4 个副页面与对应后端 IPC 命令全部接入 `FeatureLockedGate` / `require_licensed()` 门禁，侧边栏隐藏红黄计数改显小锁；2）控制台仅公开 3 项免费体验项（`node_proxy`、`node_tun`、`sys_ipv6`）的左右标题、摘要、状态与实测数据；其余 11 项前后端双层脱敏，隐藏左侧原图标、真实检测名称、右侧状态与实测数据，仅显示中性锁与编号占位 | ✅ 已完成并单测+审图验收 |
| `ISS-034` | 用户需求升级 | 2026-11-24 | 节点流量页未测节点曾硬编码假 `Claude ✓`、Gemini 长期显示「待测」、仅凭节点名称关键词误标 ISP | 彻底移除假绿标；在 `src-tauri/src/mihomo/mod.rs` 实现 Mihomo 原生无感单节点双平台真测（`GET /proxies/{name}/delay`，`Semaphore(4)` 限流并发，零切流量不中断会话）：分别直测 `api.anthropic.com/v1/models (expected=401)` 与 `gemini.google.com/app (expected=200)`，失败补测 CF 区分 `CF 403/拦截` 与 `超时`；联动 `node_geo` 真实 GeoIP/ASN 缓存自动纠偏节点地区与纯净度。真机 16 节点全量实测通过（10.34s，0 待测） | ✅ 已升级并真机实测 |
| `ISS-035` | 用户需求升级 | 2026-11-24 | Windows 系统定位权限或 `lfsvc` 地理定位服务开启时，Claude Desktop / Chromium 可获取真实 Wi-Fi 地理位置与代理出口冲突 | 新增必须检测项 `sys_location`（「Windows 系统定位服务关闭」，归入「2. Windows 系统环境」，全站升级为 11 必须 + 3 建议 = 14 项）：4 层只读探测 `HKLM/HKCU/NonPackaged ConsentStore\location` 与 `lfsvc` 服务启动模式/运行态，并提供无黑窗管理员一键关闭与禁用 `lfsvc`。本机实测精准捕获到 `lfsvc` 仍在后台 `RUNNING` 状态 | ✅ 已新增并实机验证 |
| `ISS-036` | 用户需求升级 | 2026-11-24 | 控制台新增 3 项建议优化（WebRTC 防泄露、系统时区一致性、浏览器独立代理插件审计），统一放「二、建议优化」且右侧按钮严守单一蓝主焦点原则（建议项恒为高对比白色按钮） | 在 `preflight/mod.rs`、`build.rs`、`state.rs`、`ipc.ts`、`ConsolePage.tsx` 完整新增 `opt_webrtc`（零 UAC 写入 Chrome/Edge 官方 `WebRtcIPHandling=disable_non_proxied_udp`）、`opt_tz`（只读比对时差、绝不强改时钟）、`opt_browser_ext`（只读审计 Chrome/Edge 扩展目录、绝不删插件），全站升级为 11 必须 + 6 建议 = 17 项，实机 17 项探针验收通过 | ✅ 已落地并实机验收 |
| `ISS-037` | 用户真机反馈 | 2026-11-24 | 节点流量页升级：平台支持与节点类型独立分列、表头精确呈现「延迟 / 断连 / 稳定性」、评分与评价上下分层突出大号分数、当前锁定移至右侧操作列并让节点名变绿、大白话悬停解释拉黑/弹盾/限区、第二平台升级为 Google Antigravity (AGY) 风控规则 | 后端 `mihomo/mod.rs` 与 `preflight/mod.rs` 接入 `ip-api.com` 真实 `proxy/hosting` 脏度评级、`claude.ai` CF 防盾、24h 落地 IP 漂移与多轮抖动/断连持久化，并将第二平台升级为 `generativelanguage` 地区风控 + `daily-cloudcode-pa.sandbox.googleapis.com` 实测（`AGY ✓` / `AGY 限区`）；前端 `NodesTrafficPage.tsx` 重构 6 列表格与 0ms 悬停解释气泡，实机 16 节点 8.89s 零待测通过 | ✅ 已落地并真机验收 |
| `ISS-038` | 用户真机反馈 | 2026-11-24 | NSIS 安装包文件自身仍显示默认蓝箭头图标，且安装进度条完成后停在 Completed 页需多点一次 Next 才进完成页 | 在 `tauri.conf.json` 的 `bundle.windows.nsis` 显式配置 `installerIcon: "icons/icon.ico"` 与 `languages: ["SimpChinese"]`；在 `src-tauri/nsis/hooks.nsh` 的 `NSIS_HOOK_POSTINSTALL` 新增 `SetAutoClose true`，进度条到 100% 自动跳至中文「安装完成」页；PE 图标抽取验收确认已替换为最终版图标 | ✅ 已修复并验真 |
| `ISS-039` | 用户真机反馈 | 2026-11-24 | TUN 模式点击修复按钮既打不开 Clash 又误报成功；在 Clash 外部切换 TUN 开关或手动切换节点后，控制台无法自动识别刷新 | 1）新增 `patch_tun_enabled` 优先通过 Mihomo API 尝试 1 秒自动开启 TUN，失败则真正拉起 `clash-verge.exe` 到前台并返回 `requires_manual_step=true` 明确提醒手动开启（`guardStore.ts` 绝不报假成功）；2）在 `lib.rs` 后台雷达新增 2 秒超轻量 Mihomo 状态哨兵（Named Pipe `<2ms`），监听 `(online, tun_enable, Claude-Fixed.now)`，一旦外部变动秒级自动复测并推送前端刷新 | ✅ 已修复并真机验收 |
| `ISS-040` | 用户真机反馈 | 2026-11-24 | 在 Clash 外部手动切换节点后，策略组仍报绿「select 模式已锁死新节点」，未识别外部切偏也未给一键切回 | `probe_group_and_rules` 接入 `cfg.locked_node_for_ip` 基线比对：大白话化为「固定单节点已锁定（防自动跳区）」，当检测到外部手滑切偏节点时立刻标黄预警并提供「一键切回原锁定节点」；软件内主动点击「切换锁定」时同步更新基线。真机端到端测试 `live_e2e_edge_cases_audit` 完整跑通识别预警 → 一键切回变绿闭环 | ✅ 已修复并真机闭环 |
| `ISS-041` | 用户真机反馈 | 2026-11-24 | 点击「一键锁死 Chrome / Edge WebRTC 防泄露」报错 `写入 Google Chrome 策略注册表失败: 拒绝访问 (os error 5)` | Windows 10/11 默认锁死 `HKCU\Software\Policies` ACL；`fix_browser_webrtc_policy` 升级为先试 HKCU、遇拒绝访问自动无黑窗 UAC 提权写 `HKLM\Software\Policies\{Google\Chrome, Microsoft\Edge}` 并立即回读复测验收（取消 UAC 绝不报假成功） | ✅ 已修复并验证 |
| `ISS-042` | 用户真机反馈 | 2026-11-24 | 软件内切换可用节点后，出口合规反变黄灯报「24h 落地 IP 漂移 0 次预警」 | `switch_locked_node` 更新 `locked_node_for_ip` 时未同步清空旧 `locked_landing_ip`，导致新节点 IP 与旧节点 IP 对比误报漂移；现同步清空旧 IP 基线且严格仅在同节点 `drift_24h >= 1` 时预警，并落地明确的红/黄/绿三级合规标准（1A 机房放行、2B 网页弹盾节点表标风险盾） | ✅ 已修复并真机验收 |
| `ISS-043` | 用户真机反馈 | 2026-11-24 | 策略组与机场主组出口错位；GLOBAL 模式下外部选非 `Claude-Fixed` 节点未拦住，而在 `Claude-Fixed` 内切换合规节点反而反复卡死 | `Script.js` 新增出口 IP 监测域名（`ip-api.com`/`ipapi.is`/`ipinfo.io`）与本探针进程规则指向 `Claude-Fixed`（不含 AGY，严格隔离）；`probe_group_and_rules` 识别 Clash `mode`：`GLOBAL` 脱组即红灯阻断并给「一键锁回 Claude-Fixed」，在 `Claude-Fixed` 内切合规节点 2 秒自动跟随同步（3A） | ✅ 已修复并真机验收 |
| `ISS-044` | 用户真机反馈 | 2026-11-24 | Windows 网卡 IPv6 一键禁用后过几分钟又报 `[FD_ERR_4649] 检测到 1 个网卡仍启用 ms_tcpip6 (Mihomo)` | Clash Verge TUN 虚拟网卡 `Mihomo`（Wintun）每次重载都会重建并默认启用 `ms_tcpip6`，本身已由 Mihomo `ipv6: false` 管控；新增 `is_clash_tun_virtual_adapter` 豁免 `Mihomo`/`Wintun` 虚拟网卡，物理网卡与外网 IPv6 探针仍死守 0 泄漏，真机 `sys_ipv6` 稳绿 | ✅ 已修复并真机验收 |
| `ISS-045` | 用户真机反馈 | 2026-11-24 | 节点表大量 `待验 IP` 且未真实核验 `claude.ai` CF 盾与 AGY 地区风控（Mihomo `/delay` 伪造假绿灯） | 实机抓包查明 Mihomo `/delay` 对 401/403 均回 `delay>0` 造成假绿灯；彻底删除假绿灯逻辑，新建「逐个慢速真实 HTTP 深度核验 + 24h 持久化磁盘缓存（漂移自动失效重测）+ 优先核验选中节点 + 启动前预核验（4A）+ 核验期间暂禁启动 Claude」完整引擎，AGY 按真实 `FAILED_PRECONDITION / User location is not supported` 精准标 `AGY 限区` | ✅ 已修复并真机验收 |
| `ISS-046` | 用户真机反馈 | 2026-11-24 | 悬浮窗显示「已自动熔断」时，控制台顶栏看不到熔断状态也找不到解除入口；且悬浮窗熔断时澳洲节点左侧国码误显 `HK` | 控制台标题旁同步呈现红色 `已自动熔断` 胶囊与白色 `解除熔断` 快捷按钮（带确认弹窗直清防火墙规则），同步补充 `24h 冷静期` / `官方服务异常` / `核验节点进度` 按需呈现；移除 `HudCard.tsx` 熔断硬编码 `"HK"` 恢复真实国码 | ✅ 已修复并验证 |
| `ISS-047` | 用户真机反馈 | 2026-11-24 | Clash Verge 正常在线时，左侧底部 `Clash Verge` 指示灯却红色闪动 | `Sidebar.tsx` 误将 `Clash Verge` 圆点绑定了 `killSwitchActive` 与 `mustFail`；已解绑为纯粹反映代理内核在线态（在线恒绿不闪，仅离线红灯） | ✅ 已修复并验证 |
| `ISS-048` | 用户真机反馈 | 2026-11-24 | 控制台顶栏颜色杂乱（已激活/必须/建议彩色胶囊过多），以及「一、必须通过」右侧提示与左下角拦截动效优化 | 已激活态移除顶栏 `已激活` / `必须` / `建议` 杂色胶囊与左侧重复 `9/11`；右侧改为 `全部通过 9/11（未完成红/全过白）项后，健康（绿）启动 Claude`；左下角 `Claude 进程` 卡片拦截计数递增时边框脉冲闪烁 2 次并更新文案为 `已拦截 N 次 Claude 非安全启动` | ✅ 已修复并验证 |
| `ISS-049` | 用户真机反馈 + 源码取证 | 2026-11-24 | AGY 节点明明在客户端无法使用（如日本1流媒体AI），软件仍误报 `AGY ✓` | 实机取证发现该日本节点访问 `https://www.google.com/` 无跳转返回 `302 -> google.com.hk/...pref=hkredirect`（被 Google 地理库送中）；将该无跳转 `google.com` 探针写入 `mihomo::probe_dual_ai_via_proxy` 并将缓存版本升至 `probe_schema_version = 2` 自动失效重测，精准标 `AGY 限区` | ✅ 已修复并验证 |
| `ISS-050` | 用户真机日志取证 | 2026-11-24 | Persona KYC 身份验证阶段返回 `403 permission_error (len=164)` 与单号 `[oauth-v2] fresh exchange failed`，被误判为「本地封号污染」并误触发「单号卫生锁」拉红 | 依据 `docs/research-source-ca8f12fa.md` 与本机真实 `main.log` 全面升级 11 类错误码体系：`len=164` 精准识别为 KYC 身份验证/权限待处理（`warn`，不标封号红灯、不触发单号卫生锁）；仅确认封禁（`account_banned`/`OAuth token revoked`/`forced_renewal`/`invalid_grant`/`len=130|123`）与 `region_unavailable` 标红；操作按钮文案改为 `退出登录并清理（备份）本地污染目录` | ✅ 已修复并验证 |
| `ISS-051` | 用户真机反馈 | 2026-11-24 | Claude 正常运行时系统通知每分钟持续刷屏提醒 | 根因是 Claude Desktop 每 60s 向 `main.log` 写 `[process-memory]` 心跳导致旧版按字节数变化重复弹窗；`lib.rs` 改为 `seen_anomaly_ids: HashSet<String>` 精准追踪真正新增的异常 ID，彻底消除心跳刷屏 | ✅ 已修复并验证 |
| `ISS-052` | 用户真机反馈 | 2026-11-24 | 仅日志存在异常（如 KYC 身份验证）时，悬浮窗底部蓝色按钮仍导向控制台；节点不可用/漂移时侧边栏「节点流量」无角标且悬浮窗仍显示“稳定锁定 + 纯净” | 建立「节点不可用 vs 风险」唯一真源：仅 4 类硬故障（禁区/CF 403/离线断连/高危黑名单）标不可用，合规区漂移仅标黄风险可切换并支持「确认当前 IP 已稳定（重置漂移基准）」；三方联动同步更新控制台 + 节点表 + 侧边栏「节点流量」红/黄角标 + 悬浮窗状态/副标题/微卡片/底部智能按钮（熔断→控制台、节点不可用→节点流量、控制台待办→控制台、仅日志异常→日志分析） | ✅ 已修复并验证 |
| `ISS-053` | 用户真机反馈 | 2026-11-24 | 节点延迟虚高（显示 `948~1644 ms`）与跨节点残留脏漂移导致正常节点被 `score < 48` 误杀成“节点不可用” | 切换至 Mihomo 单次纯净 RTT（实测回归 `187~220 ms`）；启用独立稳定性记录 `node-stability-v2.json`；移除前端 `score < 48` 禁用切换误杀，严格按唯一真源 `blocked || cfBlocked` 判定不可用 | ✅ 已修复并验证 |
| `ISS-054` | 用户真机反馈 | 2026-11-24 | 环境维护页操作列未右对齐、「清空全部备份」位置偏远，且应用版本号需按语义化大/小版本递进 | 升级版本至 `v0.2.0`（`package.json`/`Cargo.toml`/`tauri.conf.json` 同步）；环境维护页 `操作` 列与按钮右对齐、「清空全部备份」移至标题左上角、主清理按钮改为 `退出登录并清理（备份）` | ✅ 已修复并验证 |
| `ISS-055` | 用户真机反馈 + 实机破案 | 2026-11-24 | 策略组按钮仅写 `Script.js` 并提示用户手动去 Clash Verge「重载配置」，既无操作教程又因当前订阅挂载了漏写 `return config;` 的空脚本（`sP1H8koxXSxN.js`）导致全局 `Script.js` 被吞而彻底无效；Clash 模式/TUN 一键修改未同步落盘 | 1) 策略组改为**一键直接注入生效**：自动排雷修复当前订阅缺 `return` 的空脚本 + 持久化全局 `Script.js`（内容相同不产生垃圾 `.bak`）+ 用 `serde_yaml` 注入 `Claude-Fixed` 与 17 条前置规则到 `clash-verge.yaml` 并调用 Mihomo `PUT /configs?force=true` 直接提交 YAML `payload`（绕开服务模式 `SAFE_PATHS` 限制，0 手动重载、毫秒级生效并自动锁回 `GLOBAL` 与原安全节点）；2) 恢复 `Direct -> Rule` 一键切回并同步更新 `config.yaml`/`clash-verge.yaml`；3) `node_tun` 同步更新 `verge.yaml` `enable_tun_mode: true` 并调 Mihomo 开启且实测虚拟网卡在线（失败则诚实红灯并拉起 Clash Verge 给出清晰服务模式指引） | ✅ 已修复并真机验收 |
| `ISS-056` | 用户真机反馈 + 网页验收 | 2026-11-24 | 1) 左下角「Claude 进程」盯防卡片在开启并解除盯防后残留一圈刺眼亮白边；2) 日志分析页顶栏在出现清空模拟按钮时略显挤压；3) 侧边栏「节点流量」角标需双重关联 `node_geo` 防漏标 | 定位到 React 混用 `border` 简写与 `borderColor` 细分属性：解除盯防删除 `borderColor` 时浏览器回落为 `currentColor` (`#fafafa` 纯白)；在 `Sidebar.tsx` 与 `LogAnalysisPage.tsx` 彻底统一双分支显式样式杜绝白边，侧边栏 `nav-badge-nodes` 双重关联 `snapshot` 与 `node_geo`，新增 Vitest 回归单测并升级版本至 `v0.2.1` | ✅ 已修复并验证 |
| `ISS-057` | 用户真机反馈（v0.2.2） | 2026-11-24 | 1) 漂移历史混入脱组/切节点跨国毛刺（AU 记入 KR 致假漂移 4 次）；2) 右上角一键处理漏调 Clash 唤醒、策略组与 TUN；3) 策略组首次创建未默认挑最优节点；4) 开 TUN 后 Clash 首页开关未同步亮蓝；5) 漂移 Warn 默认主按钮应为重置漂移基准 | 1) `mihomo/mod.rs` 增加脱组禁记门禁 + 跨国毛刺过滤与历史自动清洗 + 切节点自动重新校准；2) `pick_best_verified_node` 优先选无 CF 盾 + Claude/AGY 双通 + ISP 低延迟最优节点；3) `ConsolePage.tsx` 将漂移 Warn 蓝色主按钮设为「确认当前 IP 已稳定（重置漂移基准）」，备用按钮为去节点流量；4) `execute_one_click_fix_all` 合并 `node_proxy` 与 `node_tun` 为前置单次「写配置 → 启动/平滑重启 Clash Verge 一次」链路，三端（Clash 首页开关/Mihomo/Wintun）100% 同步亮蓝，再无感串联 `node_group` 与 `node_geo(Warn)` | ✅ 已修复并真机验收 |
