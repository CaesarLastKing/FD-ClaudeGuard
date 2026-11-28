# FD Claude Guard 全仓 5 维只读深度排查报告（隐性契约与工程盲区）

> 排查日期：2026-11-27  
> 排查与落盘状态：已完成两轮全仓深度排查，**第一轮 9 项 + 第二轮 3 项已全部按用户拍板方案修复**，并完成废弃页面归档、8 份测试迁移及 9 维 `check:contracts` 防错升级与工程规范（`v2.2`）融入。  
> 安全边界：**严格执行轻量化验证**，严禁擅自打包（`tauri build`）、严禁高频盲跑全量单测。

---

## 一、全仓扫描覆盖率与健康基线

- **覆盖文件**：Rust 后端 `21` 个源码文件 + 前端 TS/TSX/CSS `51` 个源码文件 + `diag-worker` + `nsis/hooks.nsh` + `clash-scripts/claude-verge-override.js`。
- **交叉比对总量**：`70` 个已注册 Tauri Command ↔ `70` 次前端 `invoke` 调用、`72` 处后端 `emit` ↔ `10` 个前端 `listen`、`103` 个已定义 CSS 变量 ↔ `1,343` 处 CSS 使用。
- **已验证健康的重点边界（可放心）**：
  1. **Tauri Command 参数名与必需字段 100% 匹配**：`70/70` 命令全部与 `src/lib/ipc.ts` 精确匹配，无拼错/漏传的参数键（`commandMismatches = 0`，`unusedRegisteredCommands = 0`）。
  2. **Preflight 图标映射 100% 对齐**：Rust 全部 `PreflightItem.icon` 都在 `CheckIcon.tsx` 有定义（`missingIcons = 0`）。
  3. **Clash 覆写规则双向 100% 同步**：[claude-verge-override.js](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/clash-scripts/claude-verge-override.js#L23-L62) 与 [preflight/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/preflight/mod.rs#L5041-L5080) 的 14 条 `REJECT` 遥测域、8 条官方/KYC 域、3 条 CF/Stripe 域、3 条出口 IP 监测域、5 条 `PROCESS-NAME` 规则完全一致。
  4. **核心配置原子持久化**：[config/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/config/mod.rs#L247-L264) 的 `save_config` 带锁 + 临时文件重命名原子写入，断电不易写坏 `config.json`。
  5. **NSIS 卸载规则清单完整**：[hooks.nsh](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/nsis/hooks.nsh#L54-L74) 完整清理全部 4 条防火墙规则及 `FDClaudeGuard_FirewallHelper`、`FDClaudeGuard_AutoStart` 计划任务，无残留漏网。

---

## 二、新挖出的 9 项隐性问题（人肉点界面查不出的跨界 Bug）

### [P0-契约崩溃] `diag-worker` 查询 `?kind=events` SQL 引用了 D1 表中不存在的列
- **所属维度**：维度 1（跨端 / SQL 契约漂移）
- **问题位置**：[diag-worker/src/index.js](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/diag-worker/src/index.js#L224-L230) vs [diag-worker/schema.sql](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/diag-worker/schema.sql#L17-L29)
- **问题说明**：
  - `schema.sql` 中 `telemetry_events` 表的实际列名是 `(id, client_event_id, install_id_hash, app_version, category, event_type, level, tag, signature, event_json, created_at_unix)`；
  - 但在 `index.js` 查询 `?kind=events` 时，SQL 却写成了 `SELECT id, install_id_hash, app_version, os_build, event_type, error_code, summary_zh, occurred_at_iso, created_at_iso ...`，**`os_build`、`error_code`、`summary_zh`、`occurred_at_iso`、`created_at_iso` 5 个列根本不存在**，调用该管理员接口必 500 报错 `no such column`。
- **为何人工点 UI 查不出**：只有管理员带 Bearer 密钥请求 `GET /api/v1/admin/ticket?kind=events` 才触发。
- **修复方案**：改为只查询 `telemetry_events` 真实存在的列（`id, client_event_id, install_id_hash, app_version, category, event_type, level, tag, signature, created_at_unix`），并将 `created_at_unix` 格式化或交由查询端解析；可无需重发客户端直接热更新 Worker。

---

### [P1-失效死分支] `CleanConfirmModal` 仍按旧页面名称 `"环境维护"` 判断提示按钮去向
- **所属维度**：维度 2（字符串与路由漂移）
- **问题位置**：[CleanConfirmModal.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/components/CleanConfirmModal.tsx#L124-L141)
- **问题说明**：
  - 代码仍写着 `const fromMaintain = modal.sourceLabel?.includes("环境维护");`。UI v3.0 删除了旧「环境维护」入口（当前入口为「系统设置 → 清理恢复」或「账户审计」），若设置页未来传新的 `sourceLabel`，该判断将永远返回 `false`；
  - 同时，源码中仍遗留未删的 `LogAnalysisPage.tsx`、`MaintenancePage.tsx`、`SettingsPage.tsx` 三个废弃页面组件文件（仅被旧单测引用），导致全仓检索和语义替换时持续产生噪音与维护歧义。
- **修复方案**：在 `CleanConfirmModal` 中改为显式布尔/来源枚举参数替代中文子串硬匹配；若确定不再回退 v2 页面，归档或移除 3 个已淘汰旧页面并迁移对应测试（缺点：需同步改 2 个旧 test 文件；优点：彻底消除死代码干扰）。

---

### [P1-样式契约断链] `--danger-border` CSS 变量在全仓未定义
- **所属维度**：维度 2（前端样式契约）
- **问题位置**：[NetworkRescueRollbackPanel.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/components/NetworkRescueRollbackPanel.tsx#L400)
- **问题说明**：报错卡片 `rollback-load-error` 写着 `border: "1px solid var(--danger-border)"`，但 [theme.css](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/styles/theme.css) 定义的 103 个变量中根本没有 `--danger-border`（实际规范变量名为 `--bad-border` 或 `--danger`），导致报错状态下该警告框红色边框失效。
- **为何人工点 UI 查不出**：正常环境下不会触发“读取撤回基线失败”，只有在出错态时才显现。
- **修复方案**：统一替换为 `var(--bad-border)`（1 行改动，零风险）。

---

### [P1-单向丢失事件] 后端 `emit("guard://killswitch")` 发了 4 处，前端完全未监听
- **所属维度**：维度 1（Tauri Event 契约）
- **问题位置**：[lib.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/lib.rs#L302)（及第 `3623`、`3990`、`4177` 行）
- **问题说明**：4 处热熔断路径均 `emit("guard://killswitch", ks)`，但前端 [ipc.ts](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/lib/ipc.ts) 与 [App.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/App.tsx) 没有对应的 `listenKillswitch`。虽然同时会发送 `guard://snapshot` 让状态灯变红，但后端特意携带的 `KillSwitchStatus` 详细字段（触发时间、精确原因、阻断数、防壁规则状态）没有推送到前台界面或弹窗内即时反馈。
- **修复方案**：二选一：① 在 `ipc.ts` + `App.tsx` 接入 `listenKillswitch`，后台发生自动 4 层熔断时除系统通知外也在主窗立刻弹出明确 Toast 警告（推荐，增强主窗态即时感知；缺点：注意与 `dispatch_native_alert` 避免双倍重复打扰）；或 ② 删除无用的 `emit("guard://killswitch")` 保持契约极简。

---

### [P1-性能阻塞] 打开「系统设置 → 清理恢复」慢，因串行拉起多次冷启动 PowerShell / netsh
- **所属维度**：维度 5（Windows 宿主机边界）
- **问题位置**：[rollback/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/rollback/mod.rs#L985-L1007)
- **问题说明**：实机审查时就看到切到「清理恢复」750ms 后仍卡在 `正在读取系统与 Clash 首次基线快照...`。源码实锤原因：`inspect_rollback_status()` 每次打开都同步执行 `is_current_process_elevated()`（冷启动 PowerShell #1）+ `detect_loopback_dns_physical_adapters()`（冷启动 PowerShell #2）+ `has_active_guard_firewall_rules()`（3 次 `netsh`）+ `check_firewall_helper_ready()`，仅提权探测一次就要消耗 ~500ms+。
- **修复方案**：① `is_current_process_elevated()` 改用 Win32 原生 `OpenProcessToken + GetTokenInformation(TokenElevation)` 零子进程毫秒返回（当前进程权限生命周期内基本不变，还可 `OnceLock` 缓存）；② `SettingsModal` 切换前保留最近一份缓存先瞬间渲染，后台静默刷新。

---

### [P1-Windows 编码与错误吞没] PowerShell 提权输出缺 UTF-8 编码头 + `ClashService` 启动吞错
- **所属维度**：维度 5（Windows 编码与权限边界）
- **问题位置**：
  - [rollback/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/rollback/mod.rs#L423-L455) (`run_ps_encoded` / `run_ps_elevated_checked`)
  - [preflight/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/preflight/mod.rs#L2896-L2904) (`ensure_clash_verge_service_ready`)
- **问题说明**：
  - `run_ps_encoded` / `run_ps_elevated_checked` 未前置 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;` 却以 `String::from_utf8_lossy` 读取 stdout/stderr，在中文 Windows 下报错或返回含中文路径/网卡信息时会乱码；
  - `ensure_clash_verge_service_ready()` 提权拉起服务时使用 `let _ = Command::new("powershell")...` 丢弃了用户拒绝 UAC 或子进程失败的真实报错信息，且硬等 `800ms`，服务冷启慢于 `800ms` 时会被误判启动失败。
- **修复方案**：在 `run_ps_encoded` 与 `run_ps_elevated_checked` 前置 UTF-8 编码设置；服务拉起失败时明确传出管理员拒绝/退出码原因，轮询等待最长 2.5s（每 250ms 探测一次）。

---

### [P2-持久化非原子写] 节点 72h 质量缓存与稳定性缓存使用裸 `std::fs::write`
- **所属维度**：维度 3（磁盘持久化与损坏风险）
- **问题位置**：[mihomo/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/mihomo/mod.rs#L172-L180) 与 [490-499](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/mihomo/mod.rs#L490-L499)
- **问题说明**：`persist_verified_disk_map` 与 `persist_stability_map` 直接调用 `std::fs::write(path, json)` 原地覆写文件。若写盘瞬间进程崩溃、关机或防病毒软件短暂锁文件，目标 JSON 可能被截断一半，导致下次启动反序列化失败而整库回零丢失 72h 节点质量/24h IP 漂移基线。
- **修复方案**：复用类似 `config::save_config` 的写临时文件 `tmp + rename` 原子落盘模式。

---

### [P2-前后端类型声明补齐] `AppConfig` TS 类型缺 `configSchemaVersion` 字段定义
- **所属维度**：维度 1 & 3（结构体与迁移契约）
- **问题位置**：[config/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/config/mod.rs#L33) vs [guard.ts](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/types/guard.ts#L13-L35)
- **问题说明**：后端在 `AppConfig` 新增了 `config_schema_version: u32`（`camelCase` 输出为 `configSchemaVersion`），但前端 TS `AppConfig` 接口尚未补充 `configSchemaVersion?: number` 只读字段声明。
- **修复方案**：在 `src/types/guard.ts` 的 `AppConfig` 补上 `configSchemaVersion?: number;`（零风险）。

---

### [P2-异步静默吞错] 13 处前端 `.catch(() => {})` 与测试/注释残留清理
- **所属维度**：维度 2 & 4（吞错与代码整洁度）
- **问题位置**：[guardStore.ts](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/stores/guardStore.ts#L828)（后端更新节点列表失败静默）、[NodesTrafficPage.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/pages/NodesTrafficPage.tsx#L226)、[Sidebar.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/components/Sidebar.tsx#L110) 及 [claude-verge-override.js](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/clash-scripts/claude-verge-override.js#L48) 注释中仍写 `"守卫配置"`。
- **修复方案**：剪贴板写入类 `.catch` 属于合法静默降级（保留）；数据刷新失败的 `.catch` 建议记录至 `ipc.logFrontendEvent("WARN", ...)` 便于排障追踪；顺手修正 `override.js` 第 48 行注释。

---

## 三、推荐沉淀至仓库的「1 秒静态防错检查」清单

后续只需在仓库保存一份轻量 `scripts/check-contracts.mjs`（不跑全量单测、1 秒内完成），每次改完代码顺手执行一次，即可永久拦截本轮发现的全部跨界 Bug：

1. **Command & 参数对齐检查**：确保 `generate_handler![]` ↔ `ipc.ts` 100% 吻合（缺一个、多一个、参数名错一个立即红牌报错）。
2. **Event 收发检查**：检查每一个后端 `emit` 都有前端 `listen`（除非加入白名单），前端每个 `listen` 都能找到对应后端 `emit`。
3. **Worker D1 SQL 列名检查**：解析 `diag-worker/schema.sql` 真实建表列清单，校验 `diag-worker/src/index.js` 中每条 SQL 涉及的列名全部真实存在。
4. **CSS 变量检查**：扫描所有 `var(--xxx)`，确保均在 `theme.css` 定义（立刻能拦截 `--danger-border` 这类漏网）。
5. **多真源版本 & 协议 & 废弃词检查**：校验 `package.json` / `Cargo.toml` / `tauri.conf.json` / `Sidebar.tsx` / `SettingsModal.tsx` 版本完全一致，校验 `GPL-3.0` 协议全仓统一，拦截新增面向用户文案再出现已废弃页面名。

---

## 四、第一轮 9 项隐性问题修复落盘记录

| 问题编号 | 修复动作与验证状态 |
| :--- | :--- |
| **P0 `diag-worker` SQL 列名** | 已修复 `diag-worker/src/index.js:226` 并热部署线上（Version ID `b2691d95-0c92-4eb3-a050-08763fb092df`），D1 实库验证 SQL 0 报错 |
| **P1 `--danger-border`** | 已在 `NetworkRescueRollbackPanel.tsx:400` 改为 `var(--bad-border)`，`check:contracts` CSS 校验全绿 |
| **P1 `CleanConfirmModal` 死分支** | 已兼容 `"清理恢复"` 与 `"环境维护"`，`SettingsModal.tsx` 调用正常命中 |
| **P1 遗失事件 `guard://killswitch`** | 已在 `ipc.ts` 与 `App.tsx` 接入监听并弹高危告警 Toast，11 个事件 100% 双向闭合 |
| **P1 清理恢复打开慢** | `rollback/mod.rs:358` `is_current_process_elevated()` 改用 `OnceLock<bool>` + `net session` 替代重复冷启动 PowerShell |
| **P1 UTF-8 乱码与服务吞错** | `rollback/mod.rs:442` 补齐 UTF-8 编码头；`preflight/mod.rs:2887` 接入提权错误透传并改 2.5s 轮询 |
| **P2 缓存裸 `fs::write`** | `mihomo/mod.rs` 引入 `atomic_write_json`（临时文件+重命名原子替换） |
| **P2 类型/注释/静默 `.catch`** | 已补 `AppConfig.configSchemaVersion?`、修正 `claude-verge-override.js:48` 注释、非剪贴板 `.catch` 写入诊断日志 |
| **工程防错脚本沉淀** | 已创建 `scripts/check-contracts.mjs`（`npm run check:contracts` 1 秒拦截全仓跨界契约） |

---

## 五、第二轮深度源码排查新发现（`cloud_probe` / `watchdog` / `updater` / `maintenance`）

### 5.1 本轮新增确认健康的模块边界
- **大日志读取与内存膨胀安全**：`watchdog/mod.rs:1171` 单文件尾部截断 `512 KB`（账号审计限 `2 MB`），`discover_claude_log_dirs_cached` 缓存 60s；`config.acked_log_ids` 限制最多 `500` 条自动裁剪（`lib.rs:2241`）；`extract_timestamp` 校验 UTF-8 边界无 Panic 隐患。
- **`sk` 命令行隔离与内存清零**：`cloud_probe.rs:420-495` 通过 `curl.exe --config -` 经 stdin 传入敏感 Cookie 与代理密码，命令行零泄露，且调用 `zeroize_string` 覆写释放。
- **原子还原事务安全**：`maintenance/mod.rs:1723-1950` 严格校验 0 进程、ZIP 完整性、2 倍磁盘空间、建立 `pre-restore` 安全点、防 ZIP 穿越与软链覆盖，且跳过 `vm_bundles` 与程序本体。
- **前端定时器/事件清理**：全仓全部 `setInterval` 与 `window.addEventListener` 均有配对销毁清理。

### 5.2 第二轮 3 项深层隐患修复与流程升级落盘记录

#### 1. [P0-防裸奔盲区] 代理离线时禁止 `sk` 云端核验裸连 `claude.ai`（已按方案 A 修复）
- **所在文件**：[account_audit/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/account_audit/mod.rs#L2691-L2708) & [cloud_probe.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/account_audit/cloud_probe.rs#L1105-L1155)
- **修复结果**：
  - 在 `cloud_probe.rs` 新增严格域名匹配函数 `is_loopback_base_url`（仅放行本机单测 `127.0.0.1` / `localhost` / `[::1]`），当目标为真实外域且 `validated_proxy.is_none()` 时，立即 `zeroize_string(&mut sk)` 并拒绝请求；
  - 在 `account_audit/mod.rs` 的 `run_desktop_cloud_verify` 补齐 `if proxy_url.is_none()` 前置拦截报错；
  - **已固化入 1 秒防错门禁**：`check-contracts.mjs` 检查 7 永久校验该防线存在。

#### 2. [P2-原子写遗漏] 关键配置文件升级唯一临时文件（`pid/seq`）原子替换（已修复）
- **所在文件**：[account_audit/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/account_audit/mod.rs#L31-L49) & [maintenance/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/maintenance/mod.rs#L1591-L1605) & [updater/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/updater/mod.rs#L100-L114)
- **修复结果**：统一升级 `~/.claude/settings.json`、`~/.claude.json`、`account-audit-cache.json` 及 `update-state.json` 为带 `pid/seq` 唯一临时文件 + `rename` 原子写入，消除固定 `.json.tmp` 并发冲突与半写坏档风险。

#### 3. [P2-下载回退校验缺失] 更新包直连回退锁定已确认版本号（已修复）
- **所在文件**：[updater/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/updater/mod.rs#L555-L570)
- **修复结果**：代理下载失败回退直连 `direct_updater.check()` 后，强制校验 `direct_update.version == target_ver`，不一致则记 warn 日志并提示用户重新检查更新，禁止静默下载未预览版本。

---

## 六、废弃页面归档、测试无损迁移与流程体系融入

1. **旧页面精准归档（误删排雷实查）**：
   - 经全仓排查，原 `LogAnalysisPage.tsx` 仍作为「完整取证日志台」嵌入在现役 [AccountAuditPage.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/pages/AccountAuditPage.tsx#L19) 中实际使用，因此**保留在 `src/pages/` 未动**；
   - 真正不再挂载的 `MaintenancePage.tsx` 与 `SettingsPage.tsx` 已移入 [archive/legacy-v2-pages/](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/archive/legacy-v2-pages/README.md) 归档（`tsconfig.json` `include` 之外，不参与编译运行）；
   - 原引用这两个旧页面的 8 份测试文件（`v023`、`v027`、`v028`、`v029`、`v030`、`v032`、`v035`、`v038`）已全部无损迁移至现役 `SettingsModal` 与 `NetworkRescueRollbackPanel`。
2. **`guard://killswitch` 专项保留记录**：
   - 第一轮已为后端 4 处 `emit("guard://killswitch")` 接入前端 `App.tsx` 高危告警 Toast 兜底；按用户决定，后续专门做一次**熔断体系专项优化**（含触发详情弹窗、与原生系统通知去重、熔断恢复操作引导等），已独立登记至 [task-ledger.md](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/docs/task-ledger.md)（`T-062`）。
3. **审查与双速验证融入工程规范**：
   - [scripts/check-contracts.mjs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/scripts/check-contracts.mjs) 从 6 项升级为 **9 项 1 秒防错门禁**（新增防 `sk` 裸连、严禁强杀 Clash、原子写/UTF-8 编码防回潮、禁止死页面及引用 `archive/`）；
   - 已将「6 维深度审查法」与「日常轻量化校验 vs 发版全量门禁双速分级」写入 [engineering-workflow.md](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/docs/engineering-workflow.md)（v2.2）与 [reversible-safety-and-qa-plan.md](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/docs/reversible-safety-and-qa-plan.md)。


