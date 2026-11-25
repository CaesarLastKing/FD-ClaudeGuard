# FD Claude 安全启动器 · 开发阶段标准化规范（Development Standard）

> **文档编号**：`FD-STD-001`  
> **所属总纲**：[`docs/standards/engineering-lifecycle-sop.md`](./engineering-lifecycle-sop.md)（对应门禁 `G0` 与 `G1`）  
> **适用技术栈**：Tauri v2 · Rust 2021 · Windows Win32 API · React 19 · TypeScript · Tailwind CSS v4 · HeroUI · Zustand · NSIS · Cloudflare Workers/D1。

---

## 1. 动手写代码前的强制准备（G0 准入纪律）

在修改任何源码前，开发者必须完成以下 4 项检查：

1. **必读防冲突台账**：快速查阅 [`docs/dev-issues-log.md`](../dev-issues-log.md) 中与本次改动相关的历史条目，严禁为了合入新需求而回退已有真机优化（如 Win32 原生进程树、单飞锁、高 DPI+文本缩放、NSIS `$UpdateMode` 保护、`ISS-009` 非 `ok` 项导出逻辑等）。
2. **锁定单一事实源**：
   - 协议常量、错误码、时序、四维权重与脱敏占位符（`<REDACTED:2W>`）以 [`docs/protocol-constants.md`](../protocol-constants.md) 为唯一基准，**严禁自行取整或擅自改动**；
   - 视觉令牌、间距、按钮高度与单一蓝色主 CTA 规则以 [`docs/ui-design-system.md`](../ui-design-system.md) 为准。
3. **修改对象边界清晰**：所有体检项与修复动作严格按作用对象划分（改 Clash 配置 / 改 Windows 系统 / 改 Claude 本机目录），单一修复按钮不得越界误伤其他目录或配置。
4. **状态穷举表先行**：改动任一功能或页面前，显式确认其 **8 种状态** 行为：初始化/加载态、空数据态、正常通过态、失败/报错态、极端多数据态、未激活体验态、已激活态、深/浅双主题态。

---

## 2. Rust 后端与 Windows 原生开发规范

### 2.1 零子进程与无黑窗铁律（防 `ISS-012` / `ISS-031`）
- **高频轮询严禁拉起外部命令行**：250ms Kill-Hold 与 2s 进程雷达必须复用 Win32 原生 `CreateToolhelp32Snapshot` / `Process32FirstW`（耗时 `< 0.2ms`），严禁调用 `tasklist.exe` 或 `powershell.exe`。
- **所有必需的外部进程调用强制静默**：凡是在 Windows 下调用 `Command::new(...)`（如 `netsh`、`taskkill`、`w32tm`、`schtasks`、`powershell` 等），**必须**链式设置 `.creation_flags(0x0800_0000)`（`CREATE_NO_WINDOW`），杜绝运行时闪现控制台黑窗。
- **Shell 命令规范**：Windows 本机自动化命令与脚本遵循 PowerShell 5.1 兼容写法（条件链用 `; if ($LASTEXITCODE -eq 0)` 而非 `&&`）。

### 2.2 管道通信、并发与防抖性能规范（防 `ISS-005` / `ISS-011` / `ISS-013`）
- **Mihomo Named Pipe 串行与退避**：打开 Windows 命名管道 `\\.\pipe\verge-mihomo-*` 必须内置 `ERROR_PIPE_BUSY (231)` 指数退避重试；同一轮探针内对本地命名管道的多次轻量 GET 顺序执行，单节点多并发探测（如 `GET /proxies/{name}/delay`）必须通过 `tokio::sync::Semaphore` 限流（推荐并发度 `≤ 4`）。
- **单飞互斥与短期缓存**：全量体检入口必须持有 `tokio::sync::Mutex` 单飞锁（`preflight_gate`）并具备短期 TTL 缓存（冷启动防双跑，手动点「重新实测」传 `force = true` 绕过缓存）。
- **写盘防抖与原子落盘**：窗口拖拽移动坐标等高频事件必须采用 `AtomicU64` 序号 + `≥ 400ms` 异步防抖落盘；所有配置文件写入采用「先写 `.tmp` 再 `rename` 原子替换」防止半写损坏。

### 2.3 诚实探针、外部哨兵与防误报规范（防 `ISS-006` / `ISS-019` / `ISS-020` / `ISS-034` / `ISS-039` / `ISS-040`）
- **绝不伪造绿灯，绝不返回假成功**：
  - 未实测的节点/检测项严禁硬编码 `✓` 或 `ok`；
  - 需要用户手动完成的修复项（如拉起 Clash 开启 TUN），若自动 API 调用失败，必须返回 `requires_manual_step: true` 与清晰引导，前端严禁弹“修复成功”绿吐司。
- **正则必须防边界误报**：
  - 禁区匹配严禁用单字（如用 `澳门|澳門|Macau|\bMO\b` 而非单字 `澳`，避免误杀「澳大利亚」）；
  - HTTP 状态码/限流日志匹配必须限定上下文边界（如 `http/status 429`、`rate_limit_error`），严禁裸匹配 `"429"` 导致正常 PID `14292` 误报。
- **外部状态变动秒级哨兵**：
  - 凡用户可能在软件外部修改的关键状态（Clash 在线态、TUN 开关、`Claude-Fixed` 当前节点、Claude 日志文件指纹、Claude 进程树），后台必须有超轻量哨兵（Named Pipe `< 2ms` / 文件大小+mtime 指纹 / Win32 Snapshot）自动识别漂移并主动推送 `guard://preflight-updated` 与 `guard://snapshot`。
- **操作基线比对**：软件内锁定的节点、落地 IP 前缀、主号 `orgId` 持久化为基线；外部切偏必须触发明确预警并提供一键切回。

### 2.4 应用生命周期、单实例与极速退出规范（防 `ISS-008` / `ISS-029`）
- **单实例互斥锁**：应用启动第一时间创建 Windows 命名互斥体（`Local\FDClaudeGuard_SingleInstance_v1`）；若检测到已有实例运行，直接激活已有窗口并静默退出，杜绝进程双开。
- **主窗口按需懒创建**：`--autostart` 开机自启仅创建悬浮窗（`hud`），不预创建主窗口 WebView2，保证后台常驻内存 `< 50MB`。
- **极速退出红线（`< 500ms` 感知退出）**：
  - 点击退出时 **0ms 立即隐藏所有窗口与系统托盘图标**；
  - 严禁在 UI 主线程同步启动 `powershell.exe`（单次冷启动可达 `5s+`）；防火墙规则清理必须在后台线程使用轻量 `netsh`（且仅在存在活跃规则时执行），并设置 `250ms~500ms` 兜底硬退出。

### 2.5 高 DPI 与 Windows 辅助功能文本缩放规范（防 `ISS-010` / `ISS-018` / `ISS-028`）
- 桌面独立悬浮窗（`hud`）的物理窗口尺寸计算，**严禁仅使用 `window.scale_factor()`**（其仅反映显示器 DPI，忽略 Windows「辅助功能 → 文本大小」的 `TextScaleFactor`）。
- 必须同时读取注册表 `HKCU\Software\Microsoft\Accessibility\TextScaleFactor`（百分比除以 100）与前端上报的 `window.devicePixelRatio`，取有效缩放系数 `effective_scale = max(monitor_dpi, text_scale, dpr)` 计算 `PhysicalSize`，并配合前端 `ResizeObserver` 联合上报宽高，确保 `100%/125%/150% DPI` 与 `130% 文本缩放` 均零裁切。

### 2.6 日志可观测性与零泄露脱敏规范（防 `ISS-007` / `ISS-015`）
- 运行日志按天滚动落盘至 `%LOCALAPPDATA%\FDClaudeGuard\logs\guard-runtime-YYYYMMDD.jsonl`（默认保留 14 天，单文件 `10MB` 轮转，文本日志带 UTF-8 BOM 防 Windows 记事本乱码）。
- 每次核心探针耗时/失败原因、修复结果、熔断/休眠安全窗/Kill-Hold 时间轴、落地 IP 静默漂移、激活失败原因、前端未捕获错误均需写入结构化日志。
- **脱敏单一通道**：一切落盘日志与导出诊断包必须经过统一的 `sanitize_sensitive_text()`，占位符统一使用 `<REDACTED:2W>`；禁止多个正则对同一字段重复覆盖（`Bearer` 仅由 `re_bearer` 处理，不与 `re_kv` 重叠）；严禁记录明文 Token、邮箱、SessionKey、明文激活码与完整公网 IP。

---

## 3. React / TypeScript 前端开发规范

### 3.1 React 副作用与状态安全红线（防 `ISS-016` / `ISS-027`）
- **`useEffect` 最小依赖原则**：严禁把提交中状态（如 `submitting`）放进「初始化/重置错误信息」的 `useEffect` 依赖数组，避免请求失败写入错误后在 `finally` 切回 `false` 的瞬间把错误提示清空。
- **预览覆写隔离**：非 Tauri 浏览器预览态若通过 URL 参数（如 `?qa=1&state=danger&theme=light`）指定了视觉状态，异步默认拉取逻辑不得覆写 URL 指定的预览态。
- **异步防连点与统一加载态（防 `ISS-021`）**：所有 IPC 耗时按钮（重新实测、一键处理、单项修复、安全启动/退出、切换节点、激活核销、导出诊断包、备份/还原）必须绑定专属 `busy` 状态并展示统一的 `<Loader2 className="guard-spin" />` 旋转图标与进行中文案。

### 3.2 布局、滚动与视觉精致化规范（防 `ISS-017` / `ISS-037`）
- **弹性滚动容器铁律**：所有包含可变长列表（备份快照列表、日志列表、节点表格）的页面主容器必须显式设置 `flex: 1; minHeight: 0; overflowY: auto`，且上方操作卡片必须加 `flexShrink: 0`，杜绝列表条目增多时上方卡片被挤压变形。
- **视觉令牌化与单色克制**：严禁散落硬编码深/浅色冲突颜色，统一使用 `src/styles/theme.css` 中的 CSS Variables；数据统计卡主数字与单位分层排版（主数 `18px`，轻单位 `12px`），表格不超载不折行挤压，复杂术语提供 `0ms` 大白话悬停提示。
- **用户导向文案**：界面严禁出现“已直连”（易与直连裸奔混淆，统一用「管道已连接」）、严禁出现“已按文档同步”等内部批注；涉及自动触发与卸载清理的机制，应在对应卡片旁给出一句话大白话说明（自动触发条件 / Windows 卸载入口）。

### 3.3 商业授权前后端双层一致性规范（防 `ISS-033`）
- **后端是唯一信任边界**：所有受保护的修复、切节点、备份还原、熔断、导出、副页面数据查询 IPC 命令必须在 Rust 入口调用 `licensing::require_licensed()?`；未激活态下，Rust 返回给前端的体检报告必须对非免费项在后端直接脱敏（隐藏真实标题、图标、状态、实测数据与操作指南），确保前端 DOM 和抓包均零泄密。
- **前端体验态严格对应**：未激活态控制台仅展示允许的免费体验项，其余项显中性锁与编号占位；4 个受控副页面统一展示门禁锁引导；激活弹窗严格遵循最新 UI 定稿（Footer 左侧留空不放 QQ 售后，售后入口收敛于主窗顶栏耳机纯图标按钮）。

---

## 4. 商业封包、云端 Secrets 与 NSIS 安装脚本规范

### 4.1 Feature 隔离与编译期防呆门禁（防 `ISS-026`）
- 商业授权代码全部收敛在 `src-tauri/src/licensing/`，受 Cargo `#[cfg(feature = "commercial-license")]` 隔离；任何改动后必须保证**商业版（默认）与开源版（`--no-default-features`）均可独立编译且单测全绿**。
- `src-tauri/build.rs` 必须包含**编译期占位符硬拦截断言**：在打包商业版时，若 `license_api_url` 仍包含 `<`、`>`、`placeholder`、`example.invalid` 或缺失 `https://`，直接 `panic!` 中断编译，彻底杜绝半成品地址被打进 Release 安装包。
- `[profile.release]` 固定启用 `strip = true`、`lto = "fat"`、`codegen-units = 1`、`panic = "abort"`；前端 `vite.config.ts` 固定 `sourcemap: false`。

### 4.2 云端 Workers Secrets 与发卡纪律（防 `ISS-032`）
- 严禁通过可能夹带 Windows `\r\n` 换行符的交互式管道直接写入 Cloudflare Workers Secrets；统一通过无换行 JSON 批量导入（`wrangler secret bulk`），且 `license-server/worker.js` 读取所有 Secret 环境变量时强制执行 `.trim()` 防御。
- `.local-private/` 下的所有私钥、构建机密、明文卡密批次严禁提交至 Git（提交前必核 `git status`）。

### 4.3 NSIS 安装、升级与卸载钩子规范（防 `ISS-030` / `ISS-038`）
- `src-tauri/tauri.conf.json` 的 `bundle.windows.nsis` 必须显式配置：
  - `installerIcon` 指向最新多帧 `icons/icon.ico`（确保安装程序 EXE 自身图标一致）；
  - `languages: ["SimpChinese"]`；
  - `installerHooks: "./nsis/hooks.nsh"`。
- `src-tauri/nsis/hooks.nsh` 强制红线：
  1. **禁止写复杂 PowerShell 嵌套转义命令**（NSIS 不支持 `\"` 转义，极易造成卸载进度条永久卡死），防火墙与计划任务清理统一用轻量 `netsh` / `schtasks`；
  2. **安装/卸载前先静默终止驻留进程**：`nsExec::ExecToLog 'taskkill /F /T /IM fd-claude-guard.exe'`，防止文件被占用导致覆盖升级失败；
  3. **严格区分覆盖升级与真实卸载**：仅在 `${If} $UpdateMode <> 1`（非覆盖升级）分支中才销毁 `%LOCALAPPDATA%\FDClaudeGuard\vault.dat` 与 `inst.id`，**严禁在覆盖升级新版时误删老用户已激活凭证**；
  4. **安装完成自动跳转**：在 `NSIS_HOOK_POSTINSTALL` 中配置 `SetAutoClose true`，进度条到 100% 自动进入完成页，减少无意义点击。

---

## 5. 代码提交前自检速查表（G1 出口卡）

提交进入测试门禁前，逐条打勾：
- [ ] 是否核对过 `docs/dev-issues-log.md`，确认未回退任何历史真机优化？
- [ ] Windows 子进程调用是否 100% 带 `CREATE_NO_WINDOW`？是否引入了高频外部进程调用？
- [ ] 所有正则与状态判断是否有防误报边界（如禁区、429、假成功）？
- [ ] `useEffect` 与异步按钮是否无“错误闪没 / 连点重复提交 / 假成功提示”隐患？
- [ ] 商业版与开源版双 Feature 是否均通过编译，`build.rs` 占位符断言是否生效？
- [ ] 若改动图标、窗口尺寸或 NSIS 脚本，是否同步检查了 4 处图标、`TextScaleFactor` 与 `$UpdateMode <> 1`？
