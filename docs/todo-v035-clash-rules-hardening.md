# FDtools Clash 分流加固与控制台体检闭环优化方案与待办清单

> **依据来源**：[claude-clash-audit-and-console-integration.md](./claude-clash-audit-and-console-integration.md)（C1~C7）+ 对照当前仓库全链路源码交叉审计新发现的漏网缺口（E1~E6）。  
> **实施原则**：全部通过项目自身「检测 → 控制台/审计提示 → 一键可逆热修 + 持久化 → 双向闭环验证」落地；严禁直接手工修改本机 Clash 配置；严禁对 `clash-verge.exe` 执行 `taskkill /F`。

---

## 一、全链路交叉核查：除 C1~C7 外新发现的 6 处漏网缺口（E1~E6）

对照 `clash-scripts/claude-verge-override.js`、`mihomo/mod.rs`、`preflight/mod.rs`、`rollback/mod.rs`、`killswitch/mod.rs`、`account_audit/mod.rs`、`config/mod.rs` 及前端三页源码，新挖出以下 6 处联动缺口：

| 编号 | 级别 | 漏网缺口 | 源码定位 | 真实危害 |
| :-: | :-: | :--- | :--- | :--- |
| **E1** | **P0** | **`rollback` 撤回 Clash 规则时漏删 `REJECT` 遥测规则** | `src-tauri/src/rollback/mod.rs:941-953` | `strip_claude_from_clash_yaml()` 仅删除含 `Claude-Fixed` 的规则，**完全不删**本工具注入的 `sentry.io` / `datadoghq.com` 等 `REJECT` 规则。点撤回后遥测拦截永久残留，破坏反向 100% 还原闭环（且影响用户自建站点调试 Sentry/Datadog） |
| **E2** | **P1** | **`killswitch` 实时连接监控漏域 + 机场命中规则脱组漏判** | `src-tauri/src/killswitch/mod.rs:103-135` | ① 未识别 `anthropic.org`、`clau.de`、`servd-anthropic-website.b-cdn.net`、`withpersona.com`；② 仅在 `rule == "MATCH"` 时判脱组，若上述域命中机场自带 `DOMAIN-SUFFIX` 规则走了其他节点，`anomaly` 仍为 `false`，且 4 层熔断也不会掐断这些连接 |
| **E3** | **P1** | **DNS 加固缺少 `dns.ipv6: false` 与 `fallback-filter` / `fake-ip-filter` 兜底** | `clash-scripts/claude-verge-override.js:40-48` & `preflight/mod.rs:5538-5585` | ① 仅设顶层 `ipv6: false`，若订阅含 `dns.ipv6: true` 仍会发 AAAA 解析请求；② 未提供无 `fallback` 时的加密海外 DNS 兜底与 `geoip: true / CN` 过滤；③ 缺少基础 `fake-ip-filter`（如 `*.lan`、`time.windows.com`）保护局域网与 NTP 同步 |
| **E4** | **P1** | **运行态 `find-process-mode: off` 未纳入体检盲区** | `mihomo/mod.rs:1235-1241` & `preflight/mod.rs:703-805` | `MihomoConfigs` 未解析 `/configs` 中的 `find-process-mode` 与 `dns.ipv6`。若订阅关闭了进程匹配，运行态 `PROCESS-NAME,Claude.exe,Claude-Fixed` 实际已失效，但控制台仍显示全绿 |
| **E5** | **P1** | **控制台 `Must` 项 `Warn` 与“不卡死启动”的门禁语义冲突** | `preflight/mod.rs:391` & `ConsolePage.tsx:69-74` | 现有机制下，只要 `part == Must` 的项不是 `CheckStatus::Ok`（含 `Warn`），即计入 `mustFail` 并锁死「安全启动 Claude」。若将“用户主动关闭 CF/Stripe 锁定时的跨组提醒”放在 `node_group(Must)` 标 `Warn`，会反而卡死用户启动 |
| **E6** | **P2** | **规则写入与体检未接入 `AppConfig` 策略开关 + 槽位 12 细粒度缺失** | `preflight/mod.rs:4923,5453` & `account_audit/mod.rs:726-783` | `write_clash_override_script` 与热注入未读取用户配置开关；账户审计槽位 12（`RuntimeGuardContext`）仅接收布尔 `group_rules_ok`，无法透出遥测逃逸与 CF/KYC 跨组双 IP 冲突详情 |

---

## 二、方案设计与客观利弊（先亮短板，再做推荐）

### 1. 禁区正则修复（C7：放行 `🇨🇳台湾`，兼容 Go RE2）
- **方案**：
  - 从 `BLOCKED_REGION_RE`、`BLOCKED_EXCLUDE_FILTER`、`blocked_region_regex()` 中移除裸 `🇨🇳`；
  - 保留 `香港|Hong\s*Kong|🇭🇰|澳门|澳門|Macau|Macao|🇲🇴|中国|中國|国内|China|俄罗斯|...|古巴|Cuba|🇨🇺|(?:^|[^a-z])(HK|MO|CN|RU|BY|KP|IR|SY|CU)(?:[^a-z]|$)`，完全不使用 Go RE2 不支持的 `(?!)` 负向前瞻；
  - 在 Rust `is_blocked_node_name()` 与 JS `safeNodes` 过滤中额外增加显式兜底：若节点名含 `台湾|臺灣|Taiwan`（且不含香港/澳门/中国大陆/直连/中转等明确大陆/港澳字样），绝不误判为禁区。
- **真实短板**：若极端冷门机场把大陆节点只命名为 `🇨🇳01`（不含“中国/国内/China/CN”），名称初筛将放行该节点，需依赖项目既有的**真实出口 GeoIP 深度核验（实测 `country_code == CN`）**终裁拦截。

### 2. 分层规则真源统一（C1~C4 + Rust/JS 编译期单真源一致）
- **第一档（默认固定纳入，纯收益、低副作用）**：
  - 遥测 `REJECT` 补齐：`browser-intake-datadoghq.com`、`datadoghq.eu`、`statsigcdn.com`、`featureassets.org`、`prodregistryv2.org`、`segment.io`、`api.segment.com`、`honeycomb.io`（与原有 6 条合计 14 条；**明确不拦截 `statsig.anthropic.com`**）；
  - 官方关联与 KYC 域锁死 `Claude-Fixed`：`anthropic.org`、`clau.de`、`servd-anthropic-website.b-cdn.net`、`withpersona.com`；
  - 桥接进程补齐：`PROCESS-NAME,chrome-native-host.exe,Claude-Fixed`（**明确不锁 `node.exe`、不锁 `accounts.google.com`**）。
  - **短板**：若开发者本机访问自家 Sentry/Datadog/Segment/Honeycomb 后台会被全局 `REJECT` 拦截（可随时通过「撤回中心」100% 干净撤回）；极少数其他插件若恰好共用 `chrome-native-host.exe` 也会走 `Claude-Fixed` 合规节点。
- **第二档（可选二级开关：`lockCfAndStripeToClaude`，守卫配置可切）**：
  - 规则：`challenges.cloudflare.com`、`stripe.com`、`stripe.network` → `Claude-Fixed`。
  - **短板（必须先亮明）**：属于全局域名规则。开启后，浏览器中其他走 Cloudflare 盾的网站（如 ChatGPT、Perplexity）也会走 `Claude-Fixed`；若机场主组与 `Claude-Fixed` 选了不同国家节点，会反过来导致那些网站与 CF 盾跨国错位。
  - **推荐**：默认开启（面向主力 Claude 网页/付费用户，且 `FDtools` 切节点本身已联动同步主组），同时在「守卫配置」提供清晰开关与风险说明；关闭后不写入这 3 条规则，仅在跨组不同 IP 时给非阻断提示。

### 3. 运行态规则体检引擎升级 & 门禁分级（C6 + E4 + E5）
- 在 `mihomo/mod.rs` 新增结构化自上而下首命中审计 `audit_claude_rules(rules, proxies, mihomo_cfg, lock_cf_stripe)`，返回 `ClaudeRuleAuditReport`：
  1. `core_domains_missing / core_domains_hijacked`：按规则顺序模拟首个匹配（支持 `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `MATCH`），检查核心 6 域 + `withpersona.com` 是否首个命中即指向 `Claude-Fixed`（抓出被顶部 `DIRECT` 截胡的情况）；
  2. `exit_probe_ok`：`ip-api.com` / `ipapi.is` / `ipinfo.io` 首命中指向 `Claude-Fixed`；
  3. `telemetry_escape_items`：逐项检查 14 条遥测域是否首命中即 `REJECT`（精准抓出 `browser-intake-datadoghq.com` 落入机场规则逃逸）；
  4. `cross_group_conflicts`：对 `challenges.cloudflare.com`、`withpersona.com`、`stripe.com`、`stripe.network`，解析规则首命中的策略组链最终落地节点（递归解包 `Selector`/`URLTest`/`Fallback` 的 `now`）并与 `Claude-Fixed.now` 比对，一旦节点名不同立即报出具体冲突（例如：`challenges.cloudflare.com → 天悦云(🇺🇸美国2) ≠ Claude-Fixed(🇺🇸美国1)`）；
  5. `missing_processes`：`Claude.exe`、`claude.exe`、`chrome-native-host.exe`；
  6. `find_process_mode_off` / `dns_ipv6_enabled`。
- **门禁分级（解决 E5 语义冲突，既根治假绿灯又不暴力卡死办公）**：
  - **控制台 `node_group`（必须项）**：
    - 阻断（`Fail`）：策略组缺失/非 `Selector`、禁区/`DIRECT`、`GLOBAL` 脱组、`ipv6: true`、核心域缺失/被 `DIRECT` 截胡、出口探针未同源；
    - 需升级（`Warn`）：`find-process-mode: off`、第一档遥测逃逸、官方关联域/KYC/桥接进程缺失、或「已开启 CF/Stripe 同步锁但规则尚未升级」（**点击右侧唯一「一键升级策略组与规则」1 秒热修即变绿**）；
  - **控制台 `opt_exit_geo`（建议项，不阻断启动）**：
    - 当用户主动关闭 CF/Stripe 同步锁、但检测到 `challenges.cloudflare.com` / `stripe.com` 发生跨组双 IP 串线时，在此标黄提示（引导将主组与 `Claude-Fixed` 选同节点，或开启同步锁定开关），绝不卡死启动。
- **短板**：Mihomo `/rules` 接口返回的是解析后的规则列表，递归解包策略组 `now` 仅反映当前静态选择；对于 `GEOIP` / `RULE-SET` 动态匹配项无法 100% 离线求值，因此将规则模拟聚焦于明确的 `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `PROCESS-NAME` / `MATCH`（已完整覆盖实测 100% 场景）。

### 4. `Script.js` 标记块无损增量更新（保护用户自定义 AGY/Google 扩展段）
- **方案**：
  - 标准模板升级为 `// FD-CLAUDE-GUARD-SCHEMA: v2`，使用清晰起止标记：
    - `// === FD-CLAUDE-GUARD:BLOCKED-REGION:BEGIN ===` ... `END`
    - `// === FD-CLAUDE-GUARD:CLAUDE-RULES:BEGIN ===` ... `END`
  - 写入 `Script.js` 时的 3 级无损合并策略：
    1. 若已有 `BEGIN/END` 标记块：仅原地替换两个标记块内容，**100% 保留块外全部用户自定义代码**；
    2. 若无标记块但检测到用户自定义扩展（如存在 `AGY_TELEMETRY_RULES` / 自定义函数，且可安全定位顶层 `const BLOCKED_REGION_RE = ...;`, `const BLOCKED_EXCLUDE_FILTER = ...;`, `const CLAUDE_RULES = [...];`）：精准原地替换为带标记块的新常量声明（同步检查 `safeNodes` 台湾白名单兜底与 `dns.ipv6 = false`），**完整保留用户的 AGY/Google 规则与辅助函数**；
    3. 若为空白/标准旧版 FD 模板/结构损坏无法安全定位：先备份 `Script.js.bak-时间戳`，再写入完整新版 v2 模板。
  - **严格兼容 `rollback`**：首次写入前依然执行 First-Write-Wins 基线捕获，撤回时 100% 还原至首次改动前的原始 `Script.js` + 同步剥离 `clash-verge.yaml` 中的 `Claude-Fixed` 与全部 14 条本工具 `REJECT` 遥测规则（修复 E1）。
- **短板**：若用户手工改坏了标记块配对（如只删了 `END`），解析器会主动降级到“备份原文件 + 写完整模板”分支并在返回提示中标出 `.bak` 路径，避免生成语法错误的 JS 导致 Clash 加载失败。

### 5. 前端 UI 增量改动清单（严守 `docs/ui-design-system.md`，零新增页面）
- **改了哪里**：
  1. [ConsolePage.tsx](../src/pages/ConsolePage.tsx)：**不改布局、不增新卡片、不破坏一屏唯一主蓝 CTA**；仅通过后端 `node_group` 与 `opt_exit_geo` 的 `summary` / `evidence` / `guide` / `fixLabel` 精准展示遥测逃逸、跨组双 IP 冲突与一键升级按钮文案；
  2. [SettingsPage.tsx](../src/pages/SettingsPage.tsx)：在现有「紧急断流与 4 层防回传策略」分组下，新增 **1 行 `SwitchRow`**：「同步锁定 Cloudflare 人机盾与 Stripe 支付至 `Claude-Fixed`」（复用现成 `SwitchRow` 组件与设计令牌，说明跨站影响边界，副文完整折行，切换后可即时触发规则同步或提示生效）；
  3. [AccountAuditPage.tsx](../src/pages/AccountAuditPage.tsx)：在现有第 6 项（`g-disconnect`，槽位 12）中，复用现有 `runtimeDisconnectGaps` 透出后端新增的「遥测逃逸 / 跨组双 IP 串线」缺口提示，**不改 3 列卡片骨架**。
- **没动哪里**：顶栏、侧边栏、HUD 悬浮窗、节点流量 6 列表、日志分析页、环境维护页布局与样式令牌均保持原样不动。

---

## 三、分步实施待办清单与验收归档（全部已完成）

> **补充实测发现（E7 · 持久化 `Script.js` 版本漂移盲区）**：在真机实测本机环境时发现，当 Mihomo 运行态 `clash-verge.yaml` 暂时还保留着新规则、但磁盘 `profiles/Script.js` 已是旧版时，仅查 `/rules` 仍会报绿灯，导致下次更新订阅立即回退至漏洞态。已同步新增 `detect_script_js_drift()` 并在 `node_group` 体检与一键升级中彻底闭环。

| 序号 | 模块 / 文件 | 任务内容 | 状态 | 验证摘要 |
| :---: | :--- | :--- | :---: | :--- |
| 1 | `clash-scripts/claude-verge-override.js` | 升级 v2 标记块模板：修 `🇨🇳台湾` 误杀（兼容 Go RE2）、补齐 14 条遥测 `REJECT` + 关联/KYC 域 + `chrome-native-host.exe` + DNS(`dns.ipv6:false`/`fallback-filter`/`fake-ip-filter`) 加固 | 已完成 | 单测 `v035_rust_and_override_js_rules_stay_100_percent_synced_and_re2_filter_allows_taiwan` 逐条断言一致 |
| 2 | `src-tauri/src/config/mod.rs` & `src/types/guard.ts` | 新增 `lock_cf_and_stripe_to_claude: bool` 配置项（默认开启，前后端类型与默认值同步） | 已完成 | `cargo test --lib` + `tsc --noEmit` 通过 |
| 3 | `src-tauri/src/mihomo/mod.rs` | 修 `is_blocked_node_name` 台湾白名单；`MihomoConfigs` 补解析 `find-process-mode` 与 `dns.ipv6`；新增自上而下首命中审计 `audit_claude_rules()`（含遥测逃逸 + 跨组双 IP 冲突雷达 + `script_drift_reason`） | 已完成 | `v035_taiwan_flag_node_is_never_blocked_*` & `v035_audit_claude_rules_*` 通过 |
| 4 | `src-tauri/src/preflight/mod.rs` | 统一规则真源 `build_claude_fixed_rules()`；实现 4 态 `Script.js` 标记块无损增量合并与 `detect_script_js_drift()`；升级 `node_group` / `opt_exit_geo` / `node_dns` 体检与热注入；补 `sync_clash_rules_for_config()` | 已完成 | 4 态合并单测 + YAML 开关切换单测 + 真机双向闭环通过 |
| 5 | `src-tauri/src/rollback/mod.rs` | 修复 E1：`strip_claude_from_clash_yaml()` 同步精准剥离本工具注入的 14 条 `REJECT` 遥测规则，保留用户自有 `REJECT` 与订阅规则 | 已完成 | `v035_e1_strip_claude_from_clash_yaml_*` + 真机撤回验证通过 |
| 6 | `src-tauri/src/killswitch/mod.rs` | 修复 E2：`parse_claude_connections()` 补齐 `anthropic.org` / `clau.de` / `servd-anthropic-website.b-cdn.net` / `withpersona.com` / `chrome-native-host.exe` 与非 `MATCH` 脱组异常识别 | 已完成 | `v035_e2_detects_escaped_claude_and_kyc_connections_*` 通过 |
| 7 | `src-tauri/src/account_audit/mod.rs` & `lib.rs` | 槽位 12（`RuntimeGuardContext` & `evaluate_disconnect_guard_strict`）接入遥测逃逸与跨组双 IP 冲突信号；新增 `sync_clash_rule_policy` Tauri 命令 | 已完成 | `v035_disconnect_guard_surfaces_rule_audit_and_cross_group_gaps` 通过 |
| 8 | `src/pages/SettingsPage.tsx` & `src/stores/guardStore.ts` & `src/lib/ipc.ts` | 新增「同步锁定 Cloudflare 人机盾与 Stripe 支付至 `Claude-Fixed`」开关行，切换后自动热同步 Clash 规则并刷新控制台/审计与 Toast 反馈 | 已完成 | `v035_clash_hardening.test.tsx` + 68/68 前端单测 + `vite build` 通过 |
| 9 | Rust & 前端全量回归单测 + 真机双向闭环验收 | Rust 130/130（0 警告）、前端 68/68、`tsc --noEmit`、`vite build`、真机双向闭环实测（旧脚本漂移检出 + 模拟旧运行态检出 → 一键无损升级保留 `AGY_TELEMETRY_RULES` → 关闭开关热同步 → 撤回后 `Script.js` SHA-256 100% 字节级一致且清除 `REJECT` 残留） | 已完成 | 全部门禁实证通过（暂未打包） |
| 10 | `killswitch/mod.rs` & `NodesTrafficPage.tsx` | 零用户配置方案 A+B：实现全量 Claude/KYC/CF/Stripe/遥测域名用途精准分类 + `Claude.exe` 陌生外部域自动「未收录新域」雷达；实时连接页克制展示用途胶囊、中文解释、已拦截遥测态与按需新域筛选；修复真机活流量实测揪出的 **E8**（启动器自身 `fd-claude-guard.exe` 发起的 NTP 校时连接自报风险/新域误报）并细分 `s-cdn` / `assets-proxy` / `assets.claude.ai` / `mail.anthropic.com` | 已完成 | 真机活流量 `/connections` 10 条真实 Claude 连接精准分类 0 误报 + 双主题浏览器交互与复拍截图肉眼终审通过 + Rust 131/131（0 警告）+ 前端 69/69 |
| 11 | `v0.3.5` 正式打包与 Gate 5 校验 | 核查历史最高包为 `0.3.4` 后递增三方版本真源至 `0.3.5` 并更新 `CHANGELOG.md`；清零 2 条 Release 非 test 编译警告；产出 0 警告 `FD Claude Guard_0.3.5_x64-setup.exe`（4.36 MiB，SHA-256: `A1D472DAD637D8FDDB50CC0A2ECBCCB97D824788E0B79F096892A6A21A89FA28`），Gate 5 全绿 | 已完成 | Release 0 警告、`requireAdministrator=True`、零密钥/私钥泄露、真机双向闭环与活流量终检通过 |
