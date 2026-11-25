# FD Claude Guard · `v0.2.3` 风控防御与真机补强优化方案计划

> **立项来源**：2026-11-24 真实外部用户（未使用本工具、微软商店 MSIX 版 Claude Desktop + Clash `127.0.0.1:7897`）完整日志取证复盘  
> **关联总表**：[`docs/task-ledger.md`](./task-ledger.md)（`T-018` ~ `T-023`）  
> **所属流程**：严格遵循 [`docs/standards/engineering-lifecycle-sop.md`](./standards/engineering-lifecycle-sop.md)（`G0–G6` 门禁）  
> **当前状态**：方案已定稿（待用户确认后分批进入 `G1` 编码与 `G2/G4` 验收）

---

## 1. 案例核心事实与工程边界（只吸收可验证机制，绝不过度推演）

| 维度 | 客观事实 / 高置信度结论 | 对应产品防线定性 |
| :--- | :--- | :--- |
| **故障时序** | 先发生底层断连（`net::ERR_CONNECTION_RESET` / `socket closed: 1006`），几秒后客户端退出执行 `onQuitCleanup: flushEventQueue` / `[plan-usage]`，携带本地 Cookie 连续打出 403（非 403 导致断连） | **必须在代理断连瞬间主动熔断强杀跳过 `onQuitCleanup`**，不能等用户看到通知后再手动关窗口 |
| **直连与代理关联** | 日志实锤存在 `proxied (127.0.0.1:7897) ↔ direct` 切换及未登录态明文 182 字符 `region_unavailable`；11-05 退出带 Cookie 403 脱敏长度恰好 182 字符，55 秒后 `direct` 模式重启立吃 `[growthbook]`/`Bootstrap` 403（高置信度指向代理中断/切直连泄露，因脱敏不宣称法院级 100% 实锤） | Clash 离线、关 TUN、切 `direct` 均属于运行中致命失守，必须触发 2 秒热熔断 |
| **Portal 验证定性** | `https://portal.anthropic.com/verify`（Verification Portal）属于 **风控升级 / 身份核验限制**，并非永久封号（`account_banned`），经官方核验/申诉仍可能恢复 | 日志分级必须**独立成类（高危风控提示 / 待核验）**，严禁与永久封号混为一谈 |
| **混登关联风险** | 同机同 MSIX 数据目录反复在已受限旧号与主力号间切换，不会 100% 必然秒封，但会通过 **跨 `orgId` 竞态** 或 **同设备指纹/遥测关联** 显著抬高风控权重，将主力号拖入同款 Portal 审核队列 | `claude_acct` 必须同时检出多 `orgId` / 多 `accountId` 并在命中「含受限号混登」时给出最高危关联提醒 |
| **MSIX 目录盲区** | 微软商店版（MSIX）启用 Windows VFS 重定向，Cookie / Session / LocalStorage / Logs 均在 `%LOCALAPPDATA%\Packages\*Claude*\LocalCache\{Roaming,Local}\Claude\`；当前代码仅扫 MSIX 日志，但清理/备份/还原漏掉了 MSIX 目录 | **P0 必补**：MSIX 全链路纳入原子备份、清理、还原与诊断采集 |

---

## 2. 分级优化清单与技术改造设计

### P0 级（核心防线与真机漏洞修复，第一批落地）

#### `T-018` · MSIX（微软商店版）污染目录全链路备份 / 清理 / 还原 / 诊断采集闭环
- **问题根因**：[maintenance/mod.rs](../src-tauri/src/maintenance/mod.rs) 当前 `backup_and_clean_claude_dirs`、`create_manual_backup_snapshot`、`restore_backup_file`、`atomic_extract_and_swap`、`collect_official_diag_metadata` 仅覆盖传统 `%APPDATA%\Claude` 与 `%LOCALAPPDATA%\Claude`，遗漏 MSIX `LocalCache`；若微软商店版用户点击「退出登录并清理污染目录」，Cookie 与日志仍残留原地。
- **改造设计**：
  1. 在 `maintenance/mod.rs` 新增统一目录发现函数 `discover_claude_data_roots() -> ClaudeDataRoots`：
     - `classic_roaming`: `%APPDATA%\Claude`
     - `classic_local`: `%LOCALAPPDATA%\Claude`
     - `msix_roots`: 扫描 `%LOCALAPPDATA%\Packages\*`（目录名小写含 `claude` 或 `anthropic`），采集 `LocalCache\Roaming\Claude` 与 `LocalCache\Local\Claude`（保留 `package_dir_name` 映射）。
     - `telemetry`: `%USERPROFILE%\.claude\telemetry`
  2. **原子 ZIP 备份升级**：除 `roaming/`、`local/`、`telemetry/` 外，新增 `msix/<package_dir_name>/roaming/...` 与 `msix/<package_dir_name>/local/...` 分桶，并写入 `backup-manifest.json`。
  3. **清理与原子还原同步升级**：
     - 清理阶段在先完成 ZIP 备份后，同步清空已发现的 MSIX `Roaming\Claude` 与 `Local\Claude` 内容（先强杀 Claude 进程树，绝不碰用户代码项目与云端聊天）；
     - 原子还原支持 `msix/<pkg>/{roaming,local}/` 分桶解压回原位，同时 **100% 向后兼容** 无 `msix/` 分桶的旧版备份 ZIP；
     - `collect_official_diag_metadata()` 同步扫描 MSIX 根目录与 `logs/`。
- **严禁动什么**：绝不删除 MSIX 安装包本体（`WindowsApps`），绝不绕过自动 ZIP 备份直接清理。

#### `T-019` · 修复账号审计正则 `&quot;` Bug & 升级「受限号混登」高危关联识别
- **问题根因**：[watchdog/mod.rs](../src-tauri/src/watchdog/mod.rs#L495-L500) 中 `re_org` 与 `re_acct` 误将双引号写成 HTML 实体 `&quot;`，导致 JSON 格式 `"orgId": "uuid"` 匹配失败。
- **改造设计**：
  1. 修正正则为真实引号字符集并兼容常见字段名：
     - `org`: `r#"(?i)(?:orgId|organization_uuid|organizationId)["'=:\s]+([a-f0-9-]{8,36})"#`
     - `account`: `r#"(?i)(?:accountId|account_uuid)["'=:\s]+([a-f0-9-]{8,36})"#`
  2. 扩展 `AccountLogAudit` 结构：新增 `restricted_org_ids: Vec<String>`（记录曾命中 `Verification Portal`、`account_banned` 或 `403 permission_error` 的 `orgId` 关联上下文）。
  3. `probe_single_account_lock`（[preflight/mod.rs](../src-tauri/src/preflight/mod.rs#L2405)）：
     - 同时综合 `unique_org_ids.len() > 1 || unique_account_ids.len() > 1`；
     - 若检测到「多号混登且其中包含已受限/待验证账号」，摘要与指南明确提示「同设备混登已受限账号会显著抬高关联风控（拉入同款验证审核），切勿继续来回切换」。
- **严禁动什么**：单号自身 KYC / Verification Portal 不触发「单号卫生锁」误报为多号混登，保持单号/多号职责边界清晰。

#### `T-020` · 运行中代理失守自动 4 层热熔断（堵死断连退出回传 Cookie 403）
- **问题根因**：[lib.rs](../src-tauri/src/lib.rs#L2386-L2568) 当前仅在「Claude 进程 `0 → >0` 且环境未全绿」时自动触发 `trigger_four_layer_killswitch`；若 Claude 已在运行中，代理突然离线、TUN 被关或模式切为 `direct`，哨兵仅刷新 UI，用户随后关闭 Claude 就会触发 `onQuitCleanup` 带 Cookie 裸连撞 403。
- **改造设计**：
  1. 在 2 秒 Mihomo 状态哨兵（`lib.rs`）中抽取纯函数判定 `evaluate_runtime_killswitch_trigger(prev_sig, cur_sig, bg_claude_procs, auto_kill_switch) -> Option<&'static str>`（便于 L1 完整单测）：
     - 前置门禁：`bg_claude_procs > 0 && auto_kill_switch && !is_deep_audit_running() && !already_in_killswitch`。
     - 触发条件（满足其一即毫秒级热熔断）：
       1. `clash_online: true → false`（Clash Verge 退出/崩溃/管道断开）；
       2. `tun_enable: true → false`（运行中 TUN 虚拟网卡被关闭）；
       3. `clash_mode` 变为 `"direct"`（运行中切到直连）；
       4. `clash_mode == "global"` 且 `global_now != "Claude-Fixed"`（GLOBAL 脱组）；
       5. `Claude-Fixed.now` 切到禁区节点（`is_blocked_node_name(&cur_sig.4)`）。
  2. 执行动作：立即调用 `trigger_four_layer_killswitch(reason, anti_upload_flush)`（Clash 掐流 → 防火墙写入 `FDClaudeGuard_KillSwitch_BlockOut` → 强杀 Claude 进程树跳过 `onQuitCleanup` → 清扫 `~/.claude/telemetry/`）+ 挂载 Kill-Hold 事务锁 + 发送危急原生通知并同步刷新控制台/悬浮窗红色「已自动熔断」状态。
  3. **防误杀红线**：
     - `bg_claude_procs == 0` 时绝不触发熔断；
     - 深度节点核验期间（`is_deep_audit_running()`）绝不误触发；
     - 在 `Claude-Fixed` 组内切到其他合规节点绝不触发。

---

### P1 级（日志归因引擎补全与噪音隔离，第一批或紧接落地）

#### `T-021` · 日志识别规则升级（Portal 验证 / 带 Cookie 脱敏 403 / 退出断连关联 / 噪音过滤）
对照 [watchdog/mod.rs](../src-tauri/src/watchdog/mod.rs) 与 [preflight/mod.rs](../src-tauri/src/preflight/mod.rs)，补全以下识别函数规则表：

| 序号 | 新增/修正规则 | 匹配特征（不区分大小写） | 分级与标签 | 联动守则 & 文案边界 |
| :---: | :--- | :--- | :--- | :--- |
| 1 | **Verification Portal 门户验证限制** | `portal.anthropic.com/verify` 或 `can't receive replies from claude` | `fail` · `验证受限` | `pb_pay`；明确写明「属于高危风控升级（待核验），非永久封号；请先访问官方 Portal 核实，切勿在同设备直接切备用号」 |
| 2 | **OAuth 403 `len=156` 归类** | `permission_error` + `len=156`（与 `len=164` 一致纳入权限/验证异常） | `warn` · `身份验证/权限` | `pb_pay`；与确认永封 `len=130/123` 严格隔离，不拉红 `claude_ban` 封号项 |
| 3 | **带 Cookie 脱敏 403（182/270 chars 等）** | `credentialed upload refused` 或 (`403` + `credential: cookie` + `withheld`) 或 (`[plan-usage]`/`[growthbook]`/`[account] bootstrap api` + `403`) | `fail` · `带凭证 403` | `pb_exit`；若含 `182 chars` 注明「与明文 `region_unavailable` JSON 长度一致，高度疑似代理中断泄露（属高置信度推断）」；`credential: none` 降级为低危提示，不与带 Cookie 混淆 |
| 4 | **断连瞬间退出回传上下文关联** | 窗口级后处理：若 `err_connection_reset` / `socket closed: 1006` 后 15 秒内出现 `beforequit` / `onquitcleanup` / `flusheventqueue` + `403` | `fail` · `退出回传 403` | `pb_exit`；自动合并提示「检测到断连后退出清理触发带 Cookie 403，请勿在断网/关代理时手动关闭 Claude」 |
| 5 | **补齐断连与正常限额关键词** | 断连新增 `err_connection_reset`、`socket closed: 1006`；额度新增 `5-hour limit` / `hit your 5-hour` | `warn` · `网络断连` / `额度提示` | `pb_node` / `None`（明确标注 5 小时限额为正常周期限流，与封号无关） |
| 6 | **无关噪音过滤（防误报恐慌）** | 排除 `custom3p-setup.log`（第三方引导页 `503`）、`cowork_vm_node.log`（`sessiondata.vhdx`）、`chrome-native-host.log`（`Desktop not running`）、`err_network_io_suspended`（Windows 合盖休眠）、`intercom.io`、`MaxListenersExceededWarning` | `anomaly: false`（独立计入 `ignored_noise_count`） | 绝不把未登录/第三方模式 503 误报为「官方过载异常」，也不把合盖休眠误报为代理断连 |

---

### P2 级（休眠安全窗、时区跳变核验与排障包结构化，第二批落地）

#### `T-022` · 休眠唤醒预阻断窗升级（防超时裸放行）
- **现状问题**：[lib.rs](../src-tauri/src/lib.rs#L2250-L2294) 休眠唤醒后仅等 5 秒且只查 `discover_endpoint().is_some()`，超时即使未恢复也无条件撤掉防火墙规则。
- **改造设计**：
  1. 就绪判定升级为：`discover_endpoint()` 在线 **且** `tun_enable == true` **且** `mode != "direct"`；
  2. 等待上限提升至 15 秒（每 500ms 复测一次，恢复即秒放行）；
  3. 若 15 秒后仍未恢复且 `bg_claude_procs > 0`，绝不盲目撤规则，直接转入正式熔断（强杀 Claude + 保持出站阻断并弹窗告警）；若 `bg_claude_procs == 0` 则安全放行。

#### `T-023` · 日志历史时区跳变核验 + `opt_tz` 反向引导优化 + 排障包时间线摘要
- **改造设计**：
  1. 解析日志中的 `process_start_epoch_ms` / `quit_epoch_ms` 与行首本地时间戳差值，自动检测是否存在剧烈系统时区跳变（如 `UTC+8 → UTC-7` 跨 15 小时），在日志分析页展示提示并校准跨时区事件排序；
  2. 优化 [opt_tz](../src-tauri/src/preflight/mod.rs#L3038) 指南文案：明确强调「优先选择近时区合规节点，**切勿频繁来回手动修改 Windows 系统时区**」；
  3. 脱敏 AI 排障包（[maintenance/mod.rs](../src-tauri/src/maintenance/mod.rs#L687)）新增「账号观测清单（脱敏前缀 + 是否关联受限事件）」「已排除噪音摘要」与 `main1.log` 轮转日志摘要，一键生成高可读性复盘上下文。

---

## 3. 运行中热熔断与 MSIX 专项真机验收剧本（门禁 `G4` 必过）

### 剧本 1：直接退出 Clash Verge（模拟代理崩溃 / 手误关代理）
- **前提**：11/11 全绿 → 启动 Claude Desktop（进程数 > 0），开启「自动 4 层熔断」与免 UAC 防火墙守护。
- **操作**：右键托盘**直接退出 Clash Verge**。
- **预期实测结果（≤ 2.5s）**：
  1. 2 秒哨兵捕获 `clash_online: true → false` 且 `bg_claude_procs > 0`，自动触发 `trigger_four_layer_killswitch`；
  2. 防火墙写入 `FDClaudeGuard_KillSwitch_BlockOut`，Claude 进程数在 1 秒内归 `0`；
  3. 控制台与悬浮窗同步变红「已自动熔断」，弹出危急通知；
  4. 检查 Claude `main.log` 尾部：**0 条** 退出瞬间 `onQuitCleanup` 带 Cookie 403 记录。

### 剧本 2：运行中手动切换 `直连 (Direct)` 或关闭 `TUN`
- **操作**：Claude 运行中，在 Clash Verge 界面切为 `直连`（或关闭 `TUN` 开关）。
- **预期实测结果（≤ 2.5s）**：先通过在线 Mihomo 执行 `DELETE /connections` 掐断全部 Claude 活跃流 → 写防火墙规则 → 强杀进程树 → 状态同步红灯熔断。

### 剧本 3：反例防误杀 & 防自锁
- **操作 A**：在 Claude 进程为 `0` 时退出 Clash / 关 TUN / 切 Direct → **严禁**触发熔断，仅正常更新控制台对应检测项为红灯。
- **操作 B**：熔断后在控制台点击「解除熔断」二次确认 → 运行 `netsh advfirewall firewall show rule name=FDClaudeGuard_KillSwitch_BlockOut` 确认规则已彻底清除、无自锁。

### 剧本 4：MSIX 备份 → 清理 → 还原闭环（L1 沙箱单测 + L4 真机校验）
- 构造模拟 `Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\{Network\Cookies, logs\main.log}` 与 `Local\Claude\Cache`：
  1. 执行清理前必须先生成含 `msix/Claude_pzs8sxrjxfjjc/roaming/...` 的有效 ZIP 备份；
  2. 清理后 MSIX `Cookies` 与污染日志全部清零（重扫 `claude_ban` 立刻转绿）；
  3. 执行原子还原后原 MSIX 文件 100% 字节级恢复，且对旧版不含 `msix/` 桶的 ZIP 还原不报错。
