# Claude Desktop 运行时安全审计数据图谱与「账户风险 12 槽位」模型

> **文档定位**：为 `FD Claude 安全启动器（FDtools）` 设计面向 **Windows Claude Desktop（MSIX / Electron）+ Claude Code CLI** 的全链路、纯只读、零侵入安全审计数据采集方案，并建立统一的「账户风险 12 槽位」评估模型。  
> **关联文档**：[开源对标与并入规划](./account-analyzer-benchmark-and-integration.md) · [产品与架构设计](./architecture-and-design.md) · [防封实战守则](./anti-ban-playbook.md)

---

## 一、核心痛点：为什么单靠现有日志还不够？

`FDtools` 现有的 `src-tauri/src/watchdog/mod.rs` 已经把 **Claude Desktop 被动日志解析** 做得非常深（覆盖 `portal.anthropic.com/verify`、`account_banned`、跨 `orgId` 404 竞态、退出清理 Cookie 403、`sideSessions >= 3`、`429`、CF 403 盾等）。

但正如 `watchdog` 自身在 `OAuth 403 (len=164/156)` 处标注的现实瓶颈：
- **日志正文被客户端脱敏**：单靠 `main.log` 无法 100% 区分“Free 号无 Pro 权限”与“账号触发了 Persona KYC 身份验证”；
- **看不到账号底牌**：日志里看不到 `default_workspace_geo`（归属地区）、`access_block` / `billing_issue` / `monitoring_notice` 等原生风控槽位，也看不到 5 小时/7 天实时用量窗口；
- **看不到本机配置与 MCP 扩展的隐蔽风险**：如 `settings.local.json` 权限白名单明文泄漏凭据、异常 MCP Server 外联或降噪配置被静默篡改。

---

## 二、如何从 Claude Desktop 获取更多数据？（4 层合法只读数据源 + 3 条红线）

### 合法、纯只读、零侵入的 4 层数据源矩阵

| 层级 | 数据源位置 / 通道 | `FDtools` 现状 | 可新增挖掘的高价值审计数据 | 风控与性能开销 |
| :--- | :--- | :--- | :--- | :--- |
| **L1 · 客户端日志与进程层** | `%APPDATA%\Claude\logs\*.log`<br>MSIX `LocalCache\Roaming\Claude\logs\`<br>Windows 进程树 | 已解析 `main.log`、`claude.ai-web.log` | 1. **`mcp*.log` 审计**：第三方 MCP 插件报错风暴、异常外部请求或高频工具调用<br>2. **导航/弹窗重定向审计**：捕获跳转 `withpersona.com`、`/restricted`、`portal.anthropic.com/verify`<br>3. **`chrome-native-host.exe` 频次**：统计 Chrome 桥接与 `get_device_info` 触发频率<br>4. **版本/更新器变动**：监测 MSIX / `Update.exe` 静默更新是否重置配置 | **零网络开销**<br>纯本地读盘 |
| **L2 · 本机静态配置与离线行为层** | `claude_desktop_config.json`<br>`~/.claude/settings.json`<br>`.claude/settings.local.json`<br>`~/.claude/projects/*.jsonl`<br>`~/.claude.json`<br>官方诊断导出元数据 | 已读写 `~/.claude/settings.json` 降噪项与 `~/.claude/telemetry/` | 1. **MCP Server 清单审计**（`claude_desktop_config.json`）：识别未知命令、非官方转发网关与高风险本地权限<br>2. **权限白名单凭据泄漏扫描（Secret Sprawl）**：查 `.claude/settings*.json` 的 `allow` 列表是否明文固化了 `Bearer` / `sk-ant-` / 密码<br>3. **配置防篡改哈希**：监控降噪配置与 Clash 覆写脚本是否被外部静默覆盖<br>4. **离线 `.jsonl` 行为强度**（借鉴 `ccusage`）：零网络还原 5h 燃烧速率、突发脉冲与 Subagent 并发倍数<br>5. **账号跨号交叉核对**：比对 `~/.claude.json` 与桌面端日志 `orgId` 是否一致 | **零网络开销**<br>纯本地只读 |
| **L3 · 代理层连接元数据（Mihomo API）** | Mihomo 命名管道 `/connections` & 流量规则流（**不做 HTTPS 解密**） | 已有连接流监控与 12h 异常窗口 | 1. **敏感风控域名命中监测**：进程 `Claude.exe` 一旦请求 `withpersona.com` 或 `portal.anthropic.com`，即使日志没写明，也可即时感知账号进入核验流程<br>2. **遥测域名拦截验收**：验证 Sentry / Datadog / Statsig / Intercom 是否被规则层 100% `REJECT`<br>3. **三端同 IP 一致性**：实时核对 `Claude.exe`、`claude.exe`(CLI) 与浏览器访问 `claude.ai` 是否走同一策略组/同一落地 IP<br>4. **异常瞬时并发连接监控**：监测单分钟异常建连数与连接重置（RST）突增 | **零额外外网请求**<br>纯本地 IPC |
| **L4 · 账号侧只读体检层（显式授权/按需低频）** | 7 维只读接口（`/api/organizations`、`/api/account`、`/kyc_status`、`/usage`、`/chat_conversations?limit=1` 等）<br>*(未来可选 Manifest V3 伴侣扩展 / Tauri WebView 免抠 key)* | 已在 `session-analyzer-mvp` 实测验证 | 1. **彻底消除日志模糊告警**：实测确认 `kyc_status`（`verified` / `pending` / `not_required`）与套餐类型，秒解 `OAuth 403 len=164` 歧义<br>2. **抓取账号官方归属区** `default_workspace_geo`（如 `us`），与当前出口 `cf-ray` / 节点国家自动比对<br>3. **读取原生 4 大风控槽位 + 403 三分法**（精准识别 `account_banned` 与是否可申诉） | **低频按需**<br>仅用户主动触发或长周期低频采样 |

### 绝对禁止触碰的 3 条采集红线（为什么绝不能做）
1. **禁止本地 MITM 自签证书解密 `claude.ai` HTTPS 流量**：会破坏客户端 TLS 证书校验/改变指纹特征，极易直接触发 Anthropic 反篡改封号。
2. **禁止内存注入 / DLL Hook `Claude.exe`**：会被杀软判定为恶意软件，且触碰客户端完整度校验红线。
3. **禁止暴力解密 Chromium DPAPI `Cookies` 数据库**：易被 Windows Defender 报毒为凭据窃取木马（Stealer），违背 `FDtools` 零侵入安全底线；如需免手动复制 `sessionKey`，只应走**用户显式安装的 Manifest V3 浏览器伴侣扩展**或**官方 CLI 显式授权文件**。

---

## 三、统一「Claude 账户风险 12 槽位」全景模型

把账号的真实健康状态拆解为 **3 大组 × 12 个标准化风险槽位**（每个槽位均可独立点亮正常/预警/危急状态，并标注数据溯源 `官方实测` / `本地日志` / `离线估算` / `环境探针`）：

### A 组：账号主体与原生风控槽位（5 个 · 来自账号侧只读接口）

| # | 风险槽位名称 | 核心监测字段 / 信号 | 正常态 | 预警 / 危急态 |
| :-: | :--- | :--- | :--- | :--- |
| **01** | **会话存活与封禁态** | `/api/organizations` HTTP 状态 + `error.details.error_code` + `appeals_redirect_enabled` | HTTP `200` JSON | **危急**：`account_banned`（官方实锤封号，同步展示是否允许申诉）<br>**预警**：其他 `403/401`（会话过期/失效，未必封号）<br>**错误**：`cf-mitigated: challenge`（节点弹盾） |
| **02** | **组织原生 4 大风控槽位** | `org.access_block`、`org.billing_issue`、`org.subscription_pause`、`org.monitoring_notice` | 4 项全为 `null` | 任一字段非 `null` 即标黄/标红，提示账号已被后端风控或账单系统打标 |
| **03** | **API / 计费暂停与标记** | `org.api_disabled_reason`、`api_disabled_until`、`billable_usage_paused_until`、`active_flags` | 主聊天组织全空（注意排除纯 Console 组织的 `out_of_credits`） | 聊天主组织出现禁用原因、暂停截止时间或风险类 `active_flags` |
| **04** | **双路 KYC 核验态** | `/kyc_status`（`status`、`check_kind`、`completed_at`）+ Portal `hold_notice` | `not_required` / `verified` / `approved` / `completed` 且 `hold_notice === null` | `created` / `pending` / `needs_review` / `marked_for_review` / `expired` / `denied` 或 `hold_notice != null` |
| **05** | **对话域权限与模型降权** | `/chat_conversations?limit=1` + `claude_ai_bootstrap_models_config`（活跃模型数与 `hard_limit`） | 对话域 HTTP `200`，主流模型与上下文上限正常下发 | 能拉组织但对话域 `403/400`（局部功能封禁），或与历史快照对比出现模型/上限异常缩水 |

### B 组：账号底子与身份/地区一致性槽位（3 个 · 接口 × 环境联动）

| # | 风险槽位名称 | 核心监测字段 / 信号 | 正常态 | 预警 / 危急态 |
| :-: | :--- | :--- | :--- | :--- |
| **06** | **归属地 vs 出口地区一致性** | `default_workspace_geo`（如 `us`）vs Clash 锁定节点国家 & `cf-ray` 边缘地区（如 `SYD`） | 归属区与出口所在地区一致，且固定单节点无跳变 | **高价值预警**：跨区/跨洲不一致（如归属 `US` 但出口在 `SYD`），联动建议切换并锁定匹配地区节点 |
| **07** | **账号资历与信任背书** | `orgAgeDays`、`accountTotalAgeDays`、`is_verified`、`age_is_verified`、`verified_phone_number_last4`、`kyc.completedAt` | 老号、已完成邮箱/年龄/KYC 验证、无近期跨档跳变 | 新号（`<7天`）、刚过 KYC（`<7天`）或刚升降套餐（24h 高敏窗），自动建议开启 `FDtools` 24h 冷静保护 |
| **08** | **多组织与跨号连坐卫生** | `allOrgs` 列表 + 日志 `orgId` 唯一性锁 + `orgId 404` 竞态 + 本机受限/封号残留 | 单一主号、无跨 `orgId` 404 竞态、目录 0 污染 | 检测到多号轮换、受限号混登或被封账号残留，强制联动「环境维护 → 备份并纯净清理」 |

### C 组：运行时行为与客户端安全审计槽位（4 个 · 客户端 × 离线日志 × 代理联动）

| # | 风险槽位名称 | 核心监测字段 / 信号 | 正常态 | 预警 / 危急态 |
| :-: | :--- | :--- | :--- | :--- |
| **09** | **用量压力与异常并发** | 官方 `/usage`（5h/7d 利用率）+ 离线 `.jsonl` 燃烧速率/子代理并发 + 日志 `sideSessions` / `429` | 温和节奏、利用率 `<75%`、无高频 `429` | 利用率 `>=85%`、`sideSessions >= 3`、突发脉冲刷量或高频 `429`，点亮「守则 3」防自动化滥用预警 |
| **10** | **退出回传与隐性风控触发** | 日志 `带凭证 403 (len=182/270)`、`onQuitCleanup` 断连退错、`portal.anthropic.com/verify` + 代理命中 `withpersona.com` | 0 命中 | 命中即高危警报，提醒勿在断连瞬间手动退 Claude，并防止继续误操作扩大风控 |
| **11** | **本机配置与凭据卫生** | `claude_desktop_config.json`、`~/.claude/settings.json`、`.claude/settings.local.json`、`~/.claude/telemetry/` | 无明文凭据泄漏、无第三方 `ANTHROPIC_BASE_URL` 劫持、降噪配置哈希完好、遥测目录 `0 B` | 发现白名单明文凭据（Secret Sprawl）、异常转发 URL、未知 Hook/MCP 或降噪配置被篡改 |
| **12** | **环境防裸奔与三端同 IP** | `FDtools` 既有硬门禁：IPv6 泄漏、Fake-IP DNS、24h 落地 IP 漂移、桌面/CLI/网页三端代理一致、开机自启顺序 | 全项绿灯 | 任一不通过即触发控制台门禁或热熔断保护 |

---

## 四、如何在 `FDtools` UI 中克制呈现（不破坏现有简洁体验）

严格遵守 [`docs/ui-design-system.md`](./ui-design-system.md) 的**「静默正常、高亮异常」**原则：
1. **默认态不刷满屏红绿灯**：12 个槽位正常时仅显示精简汇总（如 `账号安全审计 · 12/12 正常 · 归属 US · KYC 已验`），**仅把命中预警/危急的槽位置顶展开并给出唯一动作按钮**；
2. **「日志分析」与「账号体检」互相消歧**：当日志捕获 `OAuth 403 (len=164)` 时，卡片内直接提供轻量按钮「校验当前账号 KYC/套餐归属」，一键把“疑似风控”变成“确定结论”；
3. **「诊断包」自动打通**：导出给 AI 的脱敏诊断包同步附带这 12 个槽位的脱敏摘要（所有敏感值统一按 `protocol-constants.md` 替换为 `<REDACTED:2W>`）。
