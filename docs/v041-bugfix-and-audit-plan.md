# FD Claude Guard v0.4.1 Bug 排查报告与系统性实机验收方案

- **目标版本**：`v0.4.1`（当前产物目录 `src-tauri/target/release/bundle/nsis/` 最高版本为 `FD Claude Guard_0.4.0_x64-setup.exe`，后续构建将严格按规范递增至 `0.4.1`）
- **排查日期**：2026-11-27
- **文档用途**：先沉淀全部日志审计、本机运行态取证与源码根因分析，经用户确认方案后按待办项逐一编码、补齐回归单测并执行端到端真机验收；过程中在本文档原地更新每项状态。
- **实机与日志取证来源**：
  - 运行日志：`%LOCALAPPDATA%\FDClaudeGuard\logs\guard-runtime-20261124.jsonl` ～ `guard-runtime-20261127.jsonl`
  - 持久化配置：`~/.fd-claude-guard/config.json`、`~/.fd-claude-guard/system-baseline.json`
  - 账户审计缓存：`%LOCALAPPDATA%\FDClaudeGuard\account-audit-cache.json`
  - 更新状态缓存：`%LOCALAPPDATA%\FDClaudeGuard\update-state.json`
  - Clash Verge 配置：`%APPDATA%\io.github.clash-verge-rev.clash-verge-rev\verge.yaml` 与 `clash-verge.yaml`
  - Windows 系统态：计划任务（`schtasks` / `Get-ScheduledTask`）、启动项注册表（`HKCU/HKLM Run` 与 `StartupApproved`）、Mihomo 命名管道 `/connections` 与 TCP 端口反查（`Get-NetTCPConnection`）

---

## 一、用户反馈 6 项问题：实机取证、代码根因与修复方案

### B1. 开机自启安装后显示未开启，且上方开关与下方检查状态割裂

| 属性 | 内容 |
| --- | --- |
| **当前状态** | `代码已完·待实机验收` |
| **优先级** | P0 |
| **涉及文件** | `src-tauri/nsis/hooks.nsh`、`src-tauri/src/lib.rs`、`src-tauri/src/startup_audit/mod.rs`、`src/components/SettingsModal.tsx` |

1. **实机取证**
   - `~/.fd-claude-guard/config.json` 中 `"bootStart": true`、`"bootHudOnly": true`；
   - 安装 v0.4.0 后在首次运行未手动开关前，Windows 计划任务 `FDClaudeGuard_AutoStart` 并不存在，只有手动点关再点开（见 `guard-runtime-20261127.jsonl` L132-135 `boot_start=false` -> `boot_start=true`）才通过 `update_config` 注册了该任务。
2. **代码根因**
   - `AppConfig::default()` 将 `boot_start` 设为 `true`（`src-tauri/src/config/mod.rs:93`），但 `src-tauri/nsis/hooks.nsh` 的 `NSIS_HOOK_POSTINSTALL` 宏（第 36-41 行）没有任何创建 `FDClaudeGuard_AutoStart` 计划任务的逻辑。
   - `src-tauri/src/lib.rs` 的 `setup()`（第 4847-4899 行）在启动时既没有检查 `initial_cfg.boot_start` 与真实 Windows 计划任务是否一致，也没有在首次启动时补注册计划任务。
   - 而 `audit_startup_items`（`lib.rs:2848`）如实调用 `is_windows_autostart_task_enabled()` 查询 `schtasks /Query /TN FDClaudeGuard_AutoStart`，因此出现“上方配置开关亮蓝，下方开机启动项检查显示未开启”的自相矛盾现象；必须关闭再开启触发 `update_config` 才真正写入计划任务。
3. **修复方案**
   - **安装包钩子默认注册（双保险之一）**：在 `src-tauri/nsis/hooks.nsh` 的 `NSIS_HOOK_POSTINSTALL` 中，仅当全新安装或覆盖安装完成且未处于禁用态时，在非静默异常前提下调用 `schtasks /Create /F /SC ONLOGON /RL HIGHEST /TN "FDClaudeGuard_AutoStart" /TR "\"$INSTDIR\fd-claude-guard.exe\" --autostart"`（当 `$UpdateMode <> 1` 时直接注册；覆盖升级 `$UpdateMode == 1` 则交由程序启动时按用户配置 `initial_cfg.boot_start` 决定是否保留/注册，避免强行覆盖已手动关闭开机自启的老用户配置）。
   - **启动期幂等对齐（双保险之二）**：在 `lib.rs` 的 `setup()` 后台初始化中，若 `initial_cfg.boot_start == true` 且 `!is_windows_autostart_task_enabled()`，自动调用 `sync_windows_autostart_task(true)` 补注册（需在子线程执行，避免阻塞 UI）；若当前非管理员权限导致注册失败，记录 WARN 并推送错误状态，或将 `startupAudit` 与配置异常如实汇报，**严禁静默假绿**。
   - **安装向导兜底**：若用户主动将 `bootStart` 关掉并保存，重启时严格尊重 `initial_cfg.boot_start == false`，绝不私自重新打开。
4. **影响半径与可撤回性**
   - 仅新增/同步 Windows 计划任务 `FDClaudeGuard_AutoStart`；用户在设置页关闭开关即调用 `schtasks /Delete /F /TN FDClaudeGuard_AutoStart`，且 `NSIS_HOOK_PREUNINSTALL` 已有卸载自动清理该任务的逻辑，100% 可撤回。

---

### B2. 查不到 Clash Verge Rev 的开机自启状态

| 属性 | 内容 |
| --- | --- |
| **当前状态** | `代码已完·待实机验收` |
| **优先级** | P1 |
| **涉及文件** | `src-tauri/src/startup_audit/mod.rs`、`src/components/SettingsModal.tsx` |

1. **实机取证**
   - `verge.yaml` 中为 `enable_auto_launch: false`；
   - `HKCU\...\Run`、`HKLM\...\Run` 与系统/用户 `Startup` 文件夹均无 Clash 项；
   - 但本机 `Get-ScheduledTask` 实测存在已启用且正在运行的计划任务：
     - `TaskName`: `Clash Verge (Admin)`
     - `State`: `Running`
     - `Actions`: `C:\Program Files\Clash Verge\clash-verge.exe`
     - `Triggers`: `MSFT_TaskLogonTrigger`
2. **代码根因**
   - `detect_clash_autostart()`（`src-tauri/src/startup_audit/mod.rs:152-170`）只检查了两部分：`verge.yaml` 的 `enable_auto_launch: true` 与 Run 注册表/Startup 目录，**完全遗漏了 Windows 任务计划程序（Task Scheduler）**。Clash Verge Rev 在开启“管理员权限自启”或以计划任务方式启动时，正是通过创建 `Clash Verge (Admin)` 计划任务实现的，且会把 `verge.yaml` 里的 `enable_auto_launch` 设为 `false`（或不使用 Run 项），导致恒定误报「未开启」。
3. **修复方案**
   - 在 `src-tauri/src/startup_audit/mod.rs` 新增纯只读 Windows 计划任务审计函数 `detect_scheduled_task_autostart(keywords: &[&str], exclude_self: bool)`：
     - 严格遵守 Windows 编码红线：通过 PowerShell 显式设置 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8`，使用 `Get-ScheduledTask`（兼容中文系统语言）只读枚举 `State -ne 'Disabled'`、触发器包含开机/登录（`LogonTrigger` / `BootTrigger`）且 `Actions`（`Execute`）或 `TaskName` 命中关键词的任务（或直接兜底解析 `schtasks /Query /FO CSV /V` 并在非英文系统下兼容），优先快速探测 `schtasks /Query /TN "Clash Verge (Admin)"`（或 XML/State 判断非 Disabled）；
     - 同步将其纳入 `detect_clash_autostart()` 与 `detect_claude_autostart()`（排己逻辑沿用 `is_self_guard_startup_entry` 防误伤 `FDClaudeGuard_AutoStart`）。
   - 前端打开「系统设置 → 常规开关」标签时自动异步调用一次 `auditStartupItems()` 刷新最新状态（解决在 Clash 里刚打开自启后设置页仍显示旧缓存的问题）。
4. **影响半径与可撤回性**
   - 100% 只读检测，绝不创建、修改或删除任何第三方计划任务。

---

### B3. 上方的悬浮窗和桌面预警消息默认关闭原因说明与优化

| 属性 | 内容 |
| --- | --- |
| **当前状态** | `代码已完·待实机验收`（已按方案 B 一次性迁移恢复默认开启 + 升级动态徽标） |
| **优先级** | P1 |
| **涉及文件** | `src-tauri/src/config/mod.rs`、`src/components/SettingsModal.tsx` |

1. **实机取证**
   - 源码 `AppConfig::default()`（`src-tauri/src/config/mod.rs:91-92`）默认本就是 `show_hud: true`、`notify_enabled: true`；
   - 检索历史日志 `guard-runtime-20261125.jsonl` L1195-1200：用户在 2026-11-25 19:53（当时运行 `v0.2.8`）曾手动关闭过悬浮窗与桌面提醒（`show_hud: Some(false)`、`notify_enabled: Some(false)`），该设置持久化在 `~/.fd-claude-guard/config.json`；今日（2026-11-27 08:29）在 `v0.4.0` 也再次关闭过（`guard-runtime-20261127.jsonl` L137-143）。因此升级安装 `v0.4.0` 时沿用了用户电脑上已有的 `config.json`，看起来像是“默认关闭”。
   - 同时界面上 `SettingsModal.tsx:781,790` 无论开关是否打开，右侧胶囊都硬编码显示苔绿色静态标签 `推荐开启`，导致用户看到“写着推荐开启但开关却是关的”会产生误解。
2. **修复方案（需用户拍板）**
   - **方案 A（推荐 · 尊重既有偏好 + 动态状态明确提示）**：
     1. 新用户全新安装保持 `showHud: true`、`notifyEnabled: true` 默认开启不变；
     2. 不强行覆写老用户 `~/.fd-claude-guard/config.json` 中的既有开关；
     3. 将 `SettingsModal.tsx` 中 `showHud`、`notifyEnabled`、`bootStart`、`bootHudOnly` 的静态「推荐开启」徽标升级为动态状态徽标：开启时显示绿底 `已开启`，关闭时显示琥珀提醒色 `建议开启`（明确告知当前处于关闭状态但推荐开启）。
   - **方案 B（强制复位迁移）**：
     - 在 `AppConfig` 增加配置版本字段（如 `configVersion`），升级到 `v0.4.1` 时一次性把旧配置中的 `showHud` 与 `notifyEnabled` 强制置回 `true`。
     - **缺点**：会把确实不想要悬浮窗、主动关闭过它的老用户设置强行改回去，违背配置持久化预期。

---

### B4. 控制台：左侧显示中文、右侧显示简约数据，解决文字重叠与误标红

| 属性 | 内容 |
| --- | --- |
| **当前状态** | `代码已完·待实机验收` |
| **优先级** | P1 |
| **涉及文件** | `src/styles/theme.css`、`src/pages/ConsolePage.tsx` |

1. **实机取证与逐项定位（对照用户截图 2、3、4）**
   - **排版重叠 Bug（截图 4 明确可见）**：`src/styles/theme.css:1341-1351` 中 `.c-kv-list` 设有 `display: flex; flex-direction: column; max-height: 196px; overflow-y: auto;`，但 `.c-kv-row` 缺少 `flex-shrink: 0`，导致当行数多于 5~6 行触发滚动时，浏览器 Flex 布局把每一行强行压缩低于内容高度，右侧多行文本直接上下重叠撞字（如截图 4 第一二行“规则)...”与“Claude-Fixed...”重叠）。
   - **安全值误标红 Bug（截图 2 明确可见）**：`src/pages/ConsolePage.tsx:178` 判定颜色的正则把 `/conflict|冲突|blocked|.../i` 放在最前面且没有排除安全前缀，导致：
     - `0 冲突 · 原生直连` 被判为 `"bad"`（红字）；
     - `0 项跨组双 IP 冲突` 被判为 `"bad"`（红字）；
     - `Blocked / Unreachable (OK)`（IPv6 外网已阻断，属于安全态）被判为 `"bad"`（红字）。
   - **左侧未翻译英文键（对照全部 19 项探针穷举）**：
     - `settings.json ANTHROPIC_BASE_URL / API_URL`（截图 2）
     - `System ENV (HKCU/HKLM) API Endpoints`（截图 2）
     - `CLI (~/.claude.json)`（截图 3）
     - `Mihomo dns.enhanced-mode`、`Fake-IP (198.18.0.0/15)`
     - `Exit IP & Purity`、`Claude Web (claude.ai/login)`
     - `Observed Unique accountIds (N)`、`Single-Account KYC/Auth Notice (...)`
     - `Rule Probe (FDClaudeGuard_KillSwitch_*)`
     - 带序号前缀的键名：`1. 物理网卡 ms_tcpip6`、`2. 虚拟网卡豁免`、`3. 注册表 Tcpip6 DisabledComponents`、`4. 外网 IPv6 连通探针 (2606:4700::1111)`、`1. 设备级定位 (...)`、`2. 当前用户定位 (...)`、`3. 桌面应用定位 (...)`、`4. 地理定位服务 (lfsvc)`、`1. Google Chrome (已安装)` 等
     - 错译/不准确：`Desktop Accounts` 被译成「桌面端账号数」，实际值是一长串脱敏邮箱列表；`Primary Candidate Label` / `Bound Primary Account` 对应的右侧长串重复出现。
   - **右侧冗长 / 暴露技术枚举原文（对照截图 3、4）**：
     - `SingleSurfaceClean` → 应简约显示为 `单端纯净`；
     - `未登录 [status=empty]` → 应简约显示为 `未登录`（`stale_or_polluted` → `存在旧残留`、`active` → `已登录`）；
     - `Rule 规则模式（命中 19 条规则）` / `Claude-Fixed (手动固定单节点=true) → 🇺🇸美国1|流媒体AI` → 应简约为 `规则模式`、`🇺🇸美国1|流媒体AI（单节点锁定）`；
     - `Safe (合规范围)` → `合规地区`；
     - `Named Pipe \\.\pipe\verge-mihomo-production-<64位哈希>` → 简约显示 `命名管道（已连接）`（完整管道名仍保留在折叠的「查看原始探针代码」与「复制诊断」中）；
     - 账号显示：去掉冗余重复的 `(Free · 桌面端 · 0ffb0302)` 三行连刷，主号展示 `star***at@outlook.com（桌面端 · 0ffb0302）`，主号候选仅在有多个不同号或与已绑定不一致时展示，且格式精简；
     - 其他如 `Whitelisted` → `白名单放行`、`Stable (24h 内未漂移)` → `24h 稳定（0 漂移）`、`strict/always (OK)` → `已开启`、`false (OK)` → `已关闭`、`Disabled (4 · 已禁用)` → `已禁用`、`STOPPED (已停止)` → `已停止`、`Active` → `已激活`、`Writable` → `可正常读写` 等统一中文简约化。
2. **修复方案**
   - CSS 修复 `src/styles/theme.css`：`.c-kv-row` 增加 `flex-shrink: 0; align-items: flex-start;`、合理分配左右列宽比例（左侧 `flex: 0 0 auto; max-width: 48%;`、右侧 `flex: 1 1 auto; min-width: 0; text-align: right;`），适当放宽 `.c-kv-list` 高度或内部舒适间距，彻底消灭行间重叠。
   - 完善 `ConsolePage.tsx` 中的 `formatEvidenceKeyZh()`、`formatEvidenceValueZh()` 与 `parseEvidenceKv()`：
     - 全仓穷举 19 项探针输出的全部键名与动态格式（含序号前缀 stripping/映射、括号说明精简），保证左侧 **100% 中文**；
     - 右侧执行简约值映射与括号降噪，保证一眼读懂、无 `SingleSurfaceClean` / `status=empty` / `=true` 等代码味；
     - 修正状态色优先级：先匹配安全表述（`^0\s*(冲突|项|条)`、`(OK)`、`已阻断`、`安全`、`已禁用`、`已停止`、`原生直连`、`单端纯净`、`合规`、`已开启降噪`），再匹配失败/警告；
     - 「查看原始探针代码」折叠区与「复制诊断」按钮仍完整保留 100% 原始底层英文探针数据，方便排障与提交给 AI 分析。

---

### B5. 账户审计：查过 `sk` 的历史账户必须完整保留云端核验快照

| 属性 | 内容 |
| --- | --- |
| **当前状态** | `代码已完·待实机验收` |
| **优先级** | P1 |
| **涉及文件** | `src-tauri/src/account_audit/mod.rs`、`src/pages/AccountAuditPage.tsx` |

1. **实机取证（对照用户截图 5 与 `%LOCALAPPDATA%\FDClaudeGuard\account-audit-cache.json`）**
   - 实查缓存文件：`knownAccounts` 中存在 `"a4722ea6": { "emailMasked": "jaso***11@gmail.com", "plan": "Free", "source": "云端已识" }`，证明该账号确实曾通过云端 `sk` 查出过邮箱和套餐；
   - 但 `orgSnapshots` 与 `accountHistory` 里只有当前主号 `0ffb0302`（`star***at@outlook.com`），完全没有 `a4722ea6` 的云端快照！
   - 因此点击左栏历史归档 `jaso***11@gmail.com` 时，后端 `load_account_history_report` 只能退化调用 `synthesize_legacy_history_report("a4722ea6", None, Some(known))`，导致详情页全部显示 `待 sk 实证`、`属地 待核`、`85 分·本地估`、`注册 未知`。
2. **代码根因（3 处逻辑断链）**
   - **断链 1**：`run_desktop_cloud_verify`（`src-tauri/src/account_audit/mod.rs:2585-2626`）查完 `sk` 拿到 `CloudProbeSnapshot` 后，先写入了 `knownAccounts`，紧接着就校验本机 CLI 组织一致性；如果命中跨号（抛出 `ORG_MISMATCH_CONFIRM`），函数直接 `return Err` 退出，**根本没有把刚花成本探测到的 `CloudProbeSnapshot` 存入 `org_snapshots` 和 `account_history`**！一旦用户没点“确认切主号”或只查了一下号，所有云端详情当场丢光。
   - **断链 2**：当用户本机桌面端登录的是新号 `0ffb0302`，而在账户审计页输入老号或小号 `a4722ea6` 的 `sk` 核验时，虽然写入了 `profiles["default"]` 和 `org_snapshots["a4722ea6"]`，但紧接着调用 `build_account_audit_report_with_known`（第 1419 行）：因为 `desktop_first_org` 是本机桌面端的 `0ffb0302`，`cloud_matches_desktop` 为 `false`，`cloud_applies_to_primary` 被算成 `false`，结果刚探测完的 `a4722ea6` 云端快照在构造报告时**被强行置为 `None`**，随后 `upsert_account_history_from_report` 拿到的是未核验报告或写入到了 `0ffb0302` 名下，`a4722ea6` 的完整 `AccountHistoryRecord` 从未被保存！
   - **断链 3**：`load_account_history_report`（第 689-709 行）若命中 `account_history` 中早先在未查 `sk` 时写入的本地扫描记录，不会自动合并 `org_snapshots` 里已经存在的云端快照。
3. **修复方案**
   - **任何成功的 `sk` 云端探测，第一步立即持久化云端快照与历史档案**：在 `run_desktop_cloud_verify` 拿到 `snap` 后（在任何 `ORG_MISMATCH_CONFIRM` 分支判断之前），立即将该账号的 `ProfileCloudCache` 写入 `org_snapshots[org_key]`（保留递增的 `verify_count` 与永久 `bound_workspace_geo`），并同步构造以该 `snap` 为核心的云端审计报告写入 `account_history[org_key]`。
   - **构建专门的云端视角归档报告**：新增辅助函数 `build_cloud_snapshot_report(...)`，当用户查询的 `sk` 属于历史号/非本机当前桌面端号时，在确认切号前不覆盖 `profiles["default"]`，但必须把完整云端核验报告写入 `account_history[org_key]`；若用户确认查询/核验（未切号但查询成功，或通过 `allow_switch_primary` 查询），直接向前端返回完整云端数据并即时刷新左栏历史归档摘要（显示云端实测分、属地、KYC 状态、警告标、额度等完整数据）。
   - **历史读取自动融合**：`load_account_history_report` 与 `load_archived_account_summaries` 读取 `account_history[key]` 时，若其 `cloud_verified == false` 而 `org_snapshots[key]` 存在云端快照，自动融合补全并回写，彻底消除“明明查过 `sk` 却显待核验”。
   - **实机历史数据诚实说明**：本地已经丢失的 `jaso***11@gmail.com` (`a4722ea6`) 历史详情字段（注册时间/属地/KYC/警告标）在磁盘上原本就只剩邮箱与套餐，升级后只需再查一次该账号 `sk`，此后即永久完整保留。

---

### B6. 为什么「Claude 进程 0 残留」但「节点流量 → 实时连接」仍有连接

| 属性 | 内容 |
| --- | --- |
| **当前状态** | `代码已完·待实机验收` |
| **优先级** | P1 |
| **涉及文件** | `src-tauri/src/killswitch/mod.rs`、`src/pages/NodesTrafficPage.tsx` |

1. **实机取证（对照用户截图 6 与命名管道实测）**
   - 本机当前进程中 `claude.exe` 确实为 **0 个**；
   - 通过 Mihomo 命名管道读取 `GET /connections`，当前存在 1 条连接：
     ```json
     "id": "d21992e5-54c1-4de2-98bf-463f8d3dd54e",
     "metadata": {
       "type": "Tun",
       "inboundName": "DEFAULT-TUN",
       "sourcePort": "51989",
       "host": "claude.ai",
       "destinationPort": "443",
       "process": ""
     },
     "chains": ["🇺🇸美国1|流媒体AI", "Claude-Fixed"],
     "rule": "DomainSuffix",
     "rulePayload": "claude.ai"
     ```
   - 在 Windows 上反查本机 TCP 端口 `51989`（`Get-NetTCPConnection -LocalPort 51989`）：归属进程为 **`chrome.exe`（PID 158884）**！
   - 也就是说，用户电脑上打开着 Google Chrome 访问过 `claude.ai` 网页端，浏览器保持着 HTTPS/HTTP2 长连接走 TUN 网卡。
2. **代码根因**
   - Mihomo TUN 模式下，部分连接在特定时刻 `metadata.process` 为空字符串 `""`；
   - `src-tauri/src/killswitch/mod.rs:434-438` 写了错误兜底：
     ```rust
     process: if process.is_empty() {
         "Claude".into()
     } else {
         process
     }
     ```
   - 这直接把浏览器网页端连接（`chrome.exe`）伪装显示成了进程名 `Claude`！用户看到「目标/进程」写着 `Claude`，左下角却写着「Claude 进程 0 残留」，产生“工具测不准进程”的严重误导。
3. **修复方案**
   - **Windows 原生零子进程端口反查 PID/进程名**：在 `killswitch/mod.rs` 解析 Mihomo `/connections` 时，若 `metadata.process` 为空且存在 `metadata.sourcePort`（TCP/UDP），调用 Windows 原生 `iphlpapi` (`GetExtendedTcpTable` / `GetExtendedUdpTable`) + Toolhelp32（或缓存进程 PID→名称映射表，单次解析耗时 `< 0.5ms`）精准反查本地端口所属进程（如识别出 `chrome.exe` / `msedge.exe` 等）。
   - **严禁假冒 `"Claude"`**：
     - 反查出浏览器进程时，清晰标注为 `chrome.exe (网页端)` / `msedge.exe (网页端)`；
     - 即使 socket 已处于半关闭状态无法反查出 PID，也诚实回退为 `网页端 / 未知进程`（并附提示“含浏览器网页端与后台连接，非仅桌面端进程”），**绝对不再硬编码显示为 `"Claude"`**。
   - **前端说明对齐**：在「节点流量 → 实时连接」页面副文案中明确标注「监控桌面端、CLI 与浏览器网页端全部 Claude 相关流量（仅桌面端/CLI 计入左下角进程数）」。

---

## 二、日志全量审计与运行态系统性排查：新发现的 5 项隐藏 Bug

除用户点出的 1~6 项外，我们逐行审计了 `2026-11-24 ~ 2026-11-27` 运行日志与全部前后端核心模块，新定位出以下 5 个影响真实守护可靠性与用户体验的运行态 Bug：

| 编号 | 严重度 | 问题现象与代码根因 | 修复方案 |
| --- | --- | --- | --- |
| **R1** | **P0（致命防漏失明）** | **冷启动「防裸奔自动接管」前 15 分钟处于失明状态**：`lib.rs:4863-4895` 的 `setup()` 后台首检跑完 19 项探针后，更新了 `last_report`、`last_preflight_at` 和 `snapshot`，但**漏掉了 `st.initial_preflight_done.store(true, Ordering::Release)`**！随后前端 `bootstrap()` 调用 `run_preflight_checks(false)` 时命中 6s 单飞缓存（`lib.rs:1018-1029`）直接提前 `return`，同样没把 `initial_preflight_done` 设为 `true`。结果在冷启动后的前 15 分钟内（直到第一轮定时全量巡检触发），500ms 进程雷达（`lib.rs:4125`）读取 `initial_preflight_done` 恒为 `false`，即使代理全红未就绪时直接启动 Claude，防裸奔拦截也完全不会触发！ | 在 `lib.rs` `setup()` 后台首检写入 `last_report` 后立即设置 `st.initial_preflight_done.store(true, Ordering::Release)`，确保冷启动首检一结束（约 5 秒）防裸奔雷达即 100% 激活。 |
| **R2** | **P1** | **设置弹窗开机启动项建议前缀键名不匹配**：`SettingsModal.tsx:69-82` 中 `STARTUP_ADVICE_MAP` 使用的键名是 `"Clash Verge"` 和 `"FD Claude 安全启动器"`，而后端 `startup_audit/mod.rs:103,117` 返回的 `entry.app` 是 `"FD Claude Guard"` 和 `"Clash Verge Rev"`，导致两项均未命中“建议开启 · ”提示前缀。 | 将 `STARTUP_ADVICE_MAP` 键名对齐为 `"FD Claude Guard"` 与 `"Clash Verge Rev"`，并去重避免拼接出“建议开启 · 已开启开机自启...”。 |
| **R3** | **P1** | **历史日志 `20261126` 曾单日暴涨 15,323 条更新器 WARN**：`2026-11-26` 共产生 `16,367` 行日志（3.6MB），其中 `15,323` 行为 `updater` 报错重试（根因是旧版无 4h 节流且代理检查失败时未记失败冷却时间）。`v0.4.0` 已加上成功后的 4h 持久化节流，但当**持续断网或 GitHub 不可达**时，失败分支（`updater/mod.rs:286-318`）既不落盘也不设内存退避冷却，仍存在短周期内反复失败重试风险。 | 在 `updater/mod.rs` 为非强制检查（`force == false`）增加至少 **10 分钟内存级失败退避冷却**，避免断网环境下连续尝试与日志刷屏。 |
| **R4** | **P2** | **打开「系统设置 → 常规开关」时未即时重扫开机启动项**：目前仅在软件启动时扫一次，或在本软件内开关 `bootStart` 时重扫。用户切去 Clash Verge 里刚打开自启后再点开「系统设置」，看到的仍是启动时的旧状态。 | 在 `SettingsModal.tsx` 打开弹窗且 `tab === "general"` 时异步触发一次 `ipc.auditStartupItems()` 并更新 store 中的 `startupAudit`。 |
| **R5** | **P2** | **Mihomo 命名管道并发竞争瞬时重连告警噪音**：`2026-11-24/25` 日志中频繁出现 `WARN | mihomo | 命名管道忙/瞬时异常 attempt=1 err=所有的管道范例都在使用中 (os error 231)`，且多轮探测都已在第 2 次重试立即自愈成功。 | 若 retry 后恢复成功，将 `attempt=1` 的瞬时 `os error 231` 降级为静默或 `INFO`/`DEBUG`（或仅在重试仍失败时记 `WARN`），保持运行日志干净且有真实信号。 |

*(注：排查中还发现 `guard-runtime-20261126.jsonl` 有约 15 条 `测试临时目录 system-baseline.json 损坏` 的 WARN，核查发现是运行单元测试时写进了同一个 `%LOCALAPPDATA%\FDClaudeGuard\logs` 日志目录所致，非线上生产问题；后续单测可按需隔离或保留无碍。)*

---

## 三、待办清单与系统性实机全流程验收矩阵

### 3.1 开发修复待办表

| 编号 | 模块 | 任务内容 | 状态 |
| --- | --- | --- | --- |
| T-01 | 自启 & 安装包 | `hooks.nsh` 全新安装注册 `FDClaudeGuard_AutoStart` + `lib.rs` 启动幂等对齐 `boot_start` + `SettingsModal.tsx` 修复 `STARTUP_ADVICE_MAP` 键名（B1 / R2） | `代码已完·待实机验收` |
| T-02 | 启动项审计 | `startup_audit/mod.rs` 增加只读 Windows 计划任务检测（UTF-8 编码安全），识别 `Clash Verge (Admin)` 等自启任务 + 打开设置常规页自动刷新（B2 / R4） | `代码已完·待实机验收` |
| T-03 | 默认开关策略 | 落地一次性迁移恢复默认开启 + 动态状态徽标优化（开显「已开启」、关显「建议开启」）（B3） | `代码已完·待实机验收` |
| T-04 | 控制台 KV 显示 | `theme.css` 修复 `.c-kv-row` 挤压重叠 + `ConsolePage.tsx` 全量探针键左中文/右简约改造 + 修正 `0 冲突`/`0 项跨组双 IP 冲突`/`(OK)` 误标红 + 管理员直写状态对齐（B4） | `代码已完·待实机验收` |
| T-05 | 账户审计历史 | `account_audit/mod.rs` 修复 `sk` 查验无论是否跨号/切号都完整保存 `orgSnapshots` 与 `accountHistory`、支持历史回显融合，且实时出口不再混入旧 `TPE` 边缘码（B5 / P1-1） | `代码已完·待实机验收` |
| T-06 | 实时连接溯源 | `killswitch/mod.rs` 新增 Windows 原生 TCP/UDP 端口反查真实进程，消除无进程却伪装成 `Claude` 进程显示 + 前端文案说明（B6） | `代码已完·待实机验收` |
| T-07 | 冷启动护航 & 日志 | `lib.rs` 修复 `setup()` 首检后置位 `initial_preflight_done = true`（R1）；`updater/mod.rs` 增加失败退避冷却（R3）；`mihomo/mod.rs` 命名管道瞬时重试完全降噪（R5）；`telemetry/mod.rs` & `diag-worker` 统一上报字段契约 | `代码已完·待实机验收` |
| T-08 | 定向回归与 `0.4.1` 打包 | 按用户指令跳过冗长全量测试，已完成定向回归验证：`npx vitest run src/__tests__/v041_fixes.test.tsx`（5/5 通过）、`tsc --noEmit && vite build`（0 错误）、`cargo test v041_`（7/7 通过）；完成线上 `diag-worker` 部署与 D1 实库端到端验收；已产出安装包 `FD Claude Guard_0.4.1_x64-setup.exe`（`4,726,044 B`，`SHA-256: ECF4E3F8EE683ACF5DDF606F0CAEB637AA2ED4611BAB0057B95BA62466A0D4F0`，含 `requireAdministrator` 清单，未配置私钥仅跳过更新 `.sig`），待安装新包执行 Gate 0~4 实机验收 | `已打包·待安装实机验收` |

### 3.2 系统性实机全流程验收矩阵（Gate 0 ～ Gate 5）

待上述代码落地并打包 `FD Claude Guard_0.4.1_x64-setup.exe` 后，逐项真机实测以下全流程链路：

1. **Gate 0：安装与升级闭环实测（正向 + 反向）**
   - 验证安装包全新安装/升级后，系统计划任务 `FDClaudeGuard_AutoStart` 自动存在；
   - 打开「系统设置 → 常规开关」：上方 `开机自动启动` 与下方 `FD Claude Guard` 同步显示 `已开启`；
   - 反向操作：点击关闭开机自启 → 实测 `schtasks /Query /TN FDClaudeGuard_AutoStart` 已彻底删除且下方同步变 `未开启`；再点开 → 计划任务恢复创建；
   - 验证 `Clash Verge Rev` 计划任务 `Clash Verge (Admin)` 真实被识别为 `已开启`；验证动态徽标与静态文案同步正确。
2. **Gate 1：冷启动与防裸奔 500ms 雷达实测**
   - 模拟代理异常（如暂停 TUN 或断开规则组），重启应用刚完成首检（5 秒内，不手动点刷新），验证 `initial_preflight_done == true`；
   - 启动 Claude Desktop 测试是否**立即**被防裸奔雷达拦截并触发 4 层熔断，随后解除熔断、跑通「一键网络急救」与「安全启动 Claude」恢复正常。
3. **Gate 2：控制台 19 项逐项视觉与文案核验（深色 + 浅色双主题）**
   - 逐一点击控制台全部 19 项检查条目，核查右侧「真实探针实测数据」：
     - 左侧 100% 中文无英文键漏翻；
     - 右侧简约无 `SingleSurfaceClean` / `[status=empty]` / `=true` / 64 位管道哈希；
     - 多行列表无任何文字压缩重叠；
     - `0 冲突 · 原生直连`、`0 项跨组双 IP 冲突`、`Blocked / Unreachable (OK)` 显示正常绿色而非误标红；
     - 展开「查看原始探针代码」与「复制诊断」仍保留完整原始探针数据。
4. **Gate 3：账户审计 `sk` 查验与历史归档持久化实测**
   - 在本机已登录账号 A 的情况下，分别输入同号/异号 `sk`（含命中切换确认与直接查验两种场景），验证 `%LOCALAPPDATA%\FDClaudeGuard\account-audit-cache.json` 中 `orgSnapshots` 与 `accountHistory` 完整落盘；
   - 切换或清理登录态后，点击左栏历史归档卡片，确认云端实测评分、注册天数、属地、KYC 状态、官方警告标与额度完整留存回显；
   - 验证删除单条历史档案仅删目标号、其余历史号完好。
5. **Gate 4：节点质量、实时连接与进程雷达实测**
   - 0 个 Claude 进程但 Chrome 打开 `claude.ai` 时：左下角显示 `0 残留`，节点流量 → 实时连接显示真实来源进程 `chrome.exe (网页端)`，绝不假冒为 `Claude`；
   - 启动真实 Claude Desktop 后：左下角实时变为真实进程数，实时连接准确显示 `Claude.exe`，点击「安全退出 Claude」强杀并激活 45s 防复活盯防，倒计时结束归零。
6. **Gate 5：全量自动化测试与发布安全门禁**
   - `cargo test` 全量 Rust 单测 0 失败、0 警告；`npm test` 与 `npm run build` 全量前端测试与构建通过；
   - 验证安装包清单（`requireAdministrator`、SHA-256、无未清理调试痕迹、版本真源全同步 `0.4.1`）。
