# FD Claude Guard 运行态验收、Bug 修复记录与非新需求优化方案（v0.3.2+）

> **更新时间**：2026-11-26（`v0.3.2` 全量实机验收、前端逐项复验与 Gate 5 产物校验完成）  
> **最新验证基线**：
> - `npm run build`（`tsc --noEmit && vite build`）：**0 错误 / 0 警告**（已移除 237 个空挂 npm 包，生产产物确认 **0 `HeroUIProvider`**、**0 `模拟高并发 429` 调试按钮**）
> - `npm test`（Vitest）：**12 文件 / 60 用例全绿，0 `act(...)` stderr 警告**
> - `cargo test --lib`：**105 通过 / 0 失败 / 11 忽略**（含新增真实 ZIP Zip Slip 拦截、Windows `curl.exe --config -`、`open_external_url`、`validate_main_window_bounds`、DST 夏令时 6 组回归单测）
> - `cargo clippy --lib -- -D clippy::correctness -W clippy::suspicious -W clippy::perf`：**0 警告**
> - **真机实测**：
>   - Windows 原生 `curl 8.13.0 (Schannel)` 实测 `--config -` 经 stdin 传参：`HTTP=200 (exit=0)`；
>   - `live_machine_preflight_audit`：19 项真机探针（12/12 必须项全绿 + 6/7 建议项，`opt_tz` 精准识别本机 `US Mountain Standard Time (UTC-7)` vs `California / Los Angeles (UTC-8)`）；
>   - `live_v027_real_machine_log_audit`：真机 5 份日志扫描通过（0 误判封号、4 warn、6 噪音过滤）；
>   - `live_windows_ntfs_junction_and_300mb_stress_audit`：32ms 完成 300MB VM + NTFS Junction 安全保护压测、677ms 完成本机 MSIX/经典版/CLI 三形态只读预扫描；
>   - `settings.json` First-Write-Wins 基线快照撤回实测生效，且已无损恢复本机 `~/.claude/settings.json` 至测试前 `4/4` 状态。
> - **浏览器运行态复验**（`http://localhost:1420/` + `/hud.html`）：**6/6 项全部通过，全程 0 console error / 0 pageerror**。
> - **Gate 5 Release 产物校验（`v0.3.2`）**：
>   - 安装包：`src-tauri/target/release/bundle/nsis/FD Claude Guard_0.3.2_x64-setup.exe`（`4.08 MB`，未覆盖 `0.3.1` 旧包）
>   - Setup SHA-256：`25E7EEDFBADAAEFBB1F8222322F50A7C606301880E2C9914EB0BBA74AD81B47D`
>   - EXE SHA-256：`D5E5DF43406E6FDAE7B302158F7CECFA6A54D814C83B6F73EBE839D4F621B326`
>   - Manifest `requireAdministrator`：`true`；个人机场名残留：`false`；调试按钮残留：`false`；版本号三处同步：`0.3.2`。
>
> **范围约束（已对齐用户指令）**：
> - `O-02`（遥测开关与一键匿名上报排障）：**已暂停，未做任何改动**（下方第 1 节已完整解释改动范围）；
> - 涉及 UI 页面重新设计的项（`O-05`、`O-07` 等）：**延后，先不动**；
> - 非 Clash 客户端兼容（`O-11`）及多账户/外部 API 等新需求（`O-12`~`O-14`）：**明确暂不做**；
> - **当前最高优先级**：先解决全部真实 Bug 与低级错误，其次按优先级推进不新增需求的稳定性/安全/工程优化。

---

## 一、`O-02`（遥测开关与一键匿名上报排障）暂停说明：如果改，会动哪里？

你问 `O-02` 会改动哪些位置、是否涉及 UI 页面——**是的，它确实会改到 2 个前端 UI 页面 + 1 个后端只读字段**，因此已按你的指示完全暂停、一字未动。如果后续要改，具体改动面如下：

1. **后端（仅只读状态暴露，不改逻辑）**：
   - `src-tauri/src/state.rs` / `src-tauri/src/lib.rs`：暴露一个布尔只读字段（如 `telemetryConfigured: bool`），反映 `telemetry_api_endpoint().is_some()`（开源默认构建下恒为 `false`）。
2. **UI 页面 1 — 环境维护页（`src/pages/MaintenancePage.tsx:286-298`）**：
   - 现状：页头直接放着「一键匿名上报排障」按钮，用户点提交后会弹红错 `当前版本未配置云端遥测服务地址，请改用「导出脱敏 AI 诊断包」手动发送`。
   - 改动：当 `telemetryConfigured === false` 时，隐藏或替换该按钮（避免用户点完必报错）。
3. **UI 页面 2 — 守卫配置页（`src/pages/SettingsPage.tsx:523-573`）**：
   - 现状：「匿名诊断与封号归因遥测」卡片里两个开关默认 `checked = true` 且标绿「推荐开启」，但开源默认态没有后端接收地址，开关形同空转。
   - 改动：未配置端点时收口为“当前开源版本未配置云端遥测地址，全部诊断仅留存本机”只读说明，或改为默认关闭并标灰。

---

## 二、本次代码审查 & 运行态验收已直接修复的 Bug 与纯工程优化（已完成并验证通过）

### 2.1 已修复的 8 个真实 Bug / 低级错误（零 UI 页面重构）

| 编号 | 严重度 | 发现来源 | 问题根因与真实危害 | 修复落点与验证 | 状态 |
| :--- | :---: | :--- | :--- | :--- | :---: |
| `BUG-01` | **P0** | 逻辑审查 | `SettingsPage.tsx:126-130` 挂载自动检查更新的 `useEffect` 依赖了 `updateChecking`；离线/GitHub 失败时静默请求不写 `updateInfo` 也不写 `updateError`，`updateChecking` 变回 `false` 后立刻重入触发**无限请求死循环** | 引入 `autoUpdateCheckedRef` 保证单次挂载最多自动检查 1 次 + 判 `!updateError`；补 Vitest 回归单测实证失败后只调 1 次 | `已完成` |
| `BUG-02` | **P0** | 逻辑审查 | `src-tauri/src/updater/mod.rs` 的 `check_for_app_update` 支持代理失败回退直连，但 `download_and_install_app_update` 仅在 `build()` 失败时回退，**实际拉取元数据或下载安装包经代理失败时直接报错中断** | 补齐 `check()` 与 `download_and_install()` 两段经代理失败自动回退直连重试，与检查更新逻辑 100% 一致 | `已完成` |
| `BUG-03` | **P1** | 逻辑审查 | `preflight/mod.rs` 的 `probe_system_timezone_consistency` 将 IANA 州时区写死为标准冬令时偏移（如悉尼 `+10`、美西 `-8`），但与含夏令时 DST 的本机偏移相减，导致**夏令时期间同城（如悉尼 UTC+11 对 +10）误报差 1 小时** | 新增 `compute_precise_state_hour_gap`，优先比对 Windows 注册表 `TimeZoneKeyName` 与推荐 Windows 时区键名，精确命中即判 `0` 差值；补 3 组 Rust 回归单测 | `已完成` |
| `BUG-04` | **P1** | 安全审查 | `src-tauri/src/lib.rs:2377` `open_external_url` 用裸 `starts_with("https://github.com/CaesarLastKing/FD-ClaudeGuard")`，可被 `...-evil` 或 `...@evil.com` 后缀绕过 | 抽取严格校验函数 `is_allowed_official_github_url`（精确限定根路径或 `/`/`?`/`#`，禁空白/控制字符/`@`/引号）；补 7 组正反 Rust 单测 | `已完成` |
| `BUG-05` | **P1** | 逻辑审查 | `NodesTrafficPage.tsx:266-267` 悬浮提示 tooltip 固定向上弹出 `translate(-50%, -100%)`，悬停表格顶部标签时会被窗口上边缘裁剪 | 新增 `placeBelow = rect.top < 160` 自动向下翻转定位 | `已完成` |
| `BUG-06` | **P1** | 运行态验收 | 环境维护页 `CleanConfirmModal.tsx` 缺少 `Escape` 键盘事件监听，无法按 `Esc` 关闭（与其它弹窗/抽屉行为不一致） | 补齐 `Escape` 监听（执行清理期间禁用防误中断）；补 Vitest 回归单测 | `已完成` |
| `BUG-07` | **P1** | 运行态验收 | `NodesTrafficPage.tsx` 在未连接 Mihomo（0 节点）时仍显示 `评估 0（全部可用）` 以及实时流量页显示 `全部连接均纯净通过锁定节点`，状态文案误导用户 | 0 节点诚实显示 `（暂无评估节点）`，未连接 Mihomo 时实时流量空态改为 `尚未连接 Clash Verge Mihomo 命名管道，暂无法采集实时连接流量`；补单测 | `已完成` |
| `BUG-08` | **P2** | 静态扫描 | 1) 前端 `ipc.ts` 残留旧硬编码版本号 `"0.2.7"`/`"0.3.0"`、脱敏示例滞后为 `11` 项必检、`SettingsPage.tsx` 兜底版本硬编码 `"0.3.1"`；2) 源码注释与测试夹具残留作者真实机场名；3) `rollback/mod.rs:810` Clippy `manual_contains` 告警 | 1) `vite.config.ts` / `vitest.config.ts` 注入单一真源 `__APP_VERSION__` 彻底消灭硬编码；脱敏示例同步为 `12/12`；2) 机场名全面替换为 `DemoAirport`；3) 修复 Clippy 至 0 警告 | `已完成` |
| `BUG-09` | **P0 安全** | 第二轮深审 | `account_audit/cloud_probe.rs:413-432` 将 `Cookie: sessionKey=...` 与 `--proxy` 直接拼进 `curl.exe` 命令行参数，运行期间在 Windows `PEB.CommandLine` / WMI / 任务管理器中明文暴露 `sessionKey` 与代理账密 | 改用 `curl.exe --config -` 经 stdin 管道传入敏感配置（`build_curl_stdin_config` 严格转义引号/反斜杠并剔除换行控制字符防配置注入），命令行 0 明文泄露；补 Rust 回归单测 | `已完成` |
| `BUG-10` | **P1 安全** | 第二轮深审 | `maintenance/mod.rs:1560 & 1711` 备份 ZIP 校验与还原仅检查 `name.contains("..")`，未防 Windows 盘符绝对路径（`C:\...`）、反斜杠与 UNC 前缀穿越（Zip Slip 变体） | 新增 `is_safe_zip_entry_name` 严格校验 `Path::components()` 全为 `Normal` 且禁 `\ / : \0 .. .`，在校验与解压两处双重阻断；补 11 组正反 Rust 单测 | `已完成` |
| `FIX-01` | **P1** | 静态审计 | 4 个 Rust 发射事件前端 0 监听（`guard://naked-launch-intercepted` 等） | `ipc.ts` + `App.tsx` 接入 `guard://naked-launch-intercepted` 拦截即时危险 Toast 提醒；清理 `lib.rs` 中 2 个无人消费的模拟演示死发射 | `已完成` |
| `FIX-02` | **P1** | 运行态验收 | 生产态日志台暴露调试按钮 `+ 模拟高并发 429 异常`；HUD 未连接 Mihomo 时仍亮绿灯写「稳定锁定」；防封宝典抽屉缺 `role="dialog"` | 模拟按钮限定 `DEV / test` 可见；`HudCard` 未连接态诚实改「等待连接 Clash · 尚未锁定」+ 预警态；抽屉补齐 `role="dialog" aria-modal="true"`；补 Vitest 单测 | `已完成` |
| `FIX-03` | **P2** | 运行态验收 | 浏览器预览 Mock 态下 `ackAllLogEvents` 未联动 `getLogAnalysis`、`currentNode` 残留 `US-LA-Static-01`、本地分写死 `84` 与扣分项不自洽 | 引入 `MOCK_ACKED_LOG_IDS` 同步内存态、未连接节点改为 `未连接`、Mock 本地分按公式 `min(85, 100-10-3)=85` 严格对齐 | `已完成` |
| `OPT-01` | **P2** | 工程质量 | Vitest 输出二十余条 React `not wrapped in act(...)` stderr 噪音 | 全量收口 `v027`/`v028`/`v029`/`v17_v18_v19`/`protocol_and_v15` 测试异步状态更新，实现 `0 act(...) 警告` | `已完成` |
| `BUG-11` | **P0** | 真实用户日志排查 (`v0.3.3`) | `cloud_probe` 请求非原生 `billing_portal` 且将 404/无字段兜底假绿为 `clear`；漏检 `chat_conversations` 错误体、`kyc_status` 阻塞态与 `active_flags` 扩展词；未与本地同 `orgId` Portal 日志融合 | 消灭假绿改为诚实返回 `unknown`（前端灰字「接口未返回」无绿点），多路响应体全扫描 + 按精确 `orgId` 融合本地 Portal 实锤为 `local_hold` 并熔断 `≤ 15` | `已完成` |
| `BUG-12` | **P1** | 真实用户日志排查 (`v0.3.3`) | `watchdog` / `local_scan` 的 `RE_ORG` 未匹配 URL 参数 `[?&]org=`，导致 `portal.anthropic.com/verify?org=B` 错归前文 `last_seen_org`（A）；`score.rs` 未对 `chat_restricted`（`!chat_available && !is_banned`）触发熔断；`maintenance::sanitize_sensitive_text` 对已脱敏邮箱二次截断域名 | `RE_ORG` 扩展匹配 `[?&]org=`；`RiskScoreInput` 新增 `chat_restricted` 致命熔断并同步外部 API；`RE_EMAIL` 纳入 `*` 跳过含 `***` 的脱敏邮箱 | `已完成` |

### 2.2 已落地的无 UI 设计变动工程优化

| 编号 | 项 | 实际落地内容与验证结果 | 状态 |
| :--- | :--- | :--- | :---: |
| `O-04` | 卸载空挂重依赖 | 移除 `App.tsx` 多余 `<HeroUIProvider>`，卸载 `@heroui/react` 与 `framer-motion`；**共移除 237 个冗余 npm 包**，零视觉变动，全量构建与单测通过 | `已完成` |
| `O-06` | 主窗口几何尺寸记忆 | `AppConfig` 增 `mainWindowBounds`（`#[serde(default)]`），`lib.rs` 增 `validate_main_window_bounds` 多屏可见性校验（防副屏拔插窗口丢失）+ 600ms 异步防抖落盘；补 4 组 Rust 边界单测 | `已完成` |
| `O-03a` | 工程卫生（非协议部分） | 新增 `.gitattributes` 统一换行符；更新过时的 `README.md` 与 `docs/task-ledger.md`（开源 `LICENSE` 选型与旧目录清理待你拍板） | `已完成` |
| `O-08a` | PR / Push CI 门禁 | 新增 `.github/workflows/ci.yml`，在 `push main` 与 PR 时自动跑前端构建 + Vitest + Rust 单测 + Clippy 门禁 | `已完成` |
| `OPT-02` | Tauri 安全收紧 | `tauri.conf.json` 配置精确 WebView CSP，移除 `capabilities/default.json` 中前端未使用的 `"shell:allow-open"`，经 Release 构建核验通过 | `已完成` |
| `OPT-03` | 开源合规与发版收口 | 同步三处版本至 `0.3.2`、补齐 `CHANGELOG.md`、引入标准 `GNU GPL-3.0` (`LICENSE`)、从主分支清理早已留档于 `origin/main` 历史的 `license-server/` 与 `session-analyzer-mvp/`，完成 `FD Claude Guard_0.3.2_x64-setup.exe` 构建校验并推送 `main` + `v0.3.2` Tag 触发云端 Ed25519 签名发布 | `已完成` |

---

## 三、后续低优先备忘（当前版本全部收口完毕）

> **说明**：`v0.3.2` 版本内的全部 Bug 修复、安全加固、真机实测、开源合规（`GPL-3.0` + 历史旧目录清理）与签名发版收口已全部完成。

- **长期架构减负（`OPT-04`，低优先）**：5 个 2500~6400 行巨型文件建议结合后续功能迭代渐进拆分，不专门停工重构。

---

## 四、明确暂缓 / 不做的项（按用户要求冻结）

| 编号 | 项目 | 冻结原因 |
| :--- | :--- | :--- |
| `O-02` | 遥测开关与一键匿名上报排障处理 | 涉及 2 个 UI 页面改造，按用户指示暂停待后续统一看 UI |
| `O-05` | 节点流量页一键筛选与排序 | 涉及 UI 交互新增，晚一点统一设计 |
| `O-07` | 环境维护页 3 分段重构 | 涉及 UI 架构大改，晚一点统一设计 |
| `O-11` | 非 Clash Verge 客户端兼容 | 用户明确暂不做 |
| `O-12` / `O-13` / `O-14` | 多账户 Phase 2 / 外部查分 API / 代码签名与赞助位 | 属于新需求或外部商业流程，当前不做 |
