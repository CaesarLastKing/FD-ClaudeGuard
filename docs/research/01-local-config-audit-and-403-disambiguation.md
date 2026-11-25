# 01 · 本地识别 Claude 客户端配置、403 精准消歧与账户综合风控方案

> **适用阶段**：Phase 1（单账户工具立即可落地的账户审计与日志分析优化）  
> **核心原则**：100% 纯非侵入只读（零网络强依赖、零 DPAPI 解密、零 MITM、零进程注入）  
> **防返工契约（供 Phase 2 多账户 100% 复用）**：所有 Rust 扫描与风控函数统一接收 `ProfileContext { profile_id, cli_config_dir, desktop_data_dir, expected_geo, bound_proxy_port }`，严禁在解析函数内部硬编码全局 `~/.claude` 或 `%LOCALAPPDATA%\Claude` 路径。

---

## 一、纯非侵入识别本地配置，目前到底能识别到哪些东西？（Windows 真机实证）

已基于 Windows 真机实测脚本 [local-audit-probe.mjs](../../session-analyzer-mvp/scripts/local-audit-probe.mjs) 实证通过，无需联网、无需用户提供 `sessionKey`，纯读本机明文文件即可拿到以下 5 大类管控数据：

### 1. `%USERPROFILE%\.claude.json`（账号与管控元数据核心库）
- **账号与组织身份（`oauthAccount`）**：
  - `emailAddress`（脱敏展示）、`accountUuid`、`organizationUuid`、`organizationName`
  - `organizationType`（如 `claude_pro`）、`organizationRole`（`admin`）、`workspaceRole`、`seatTier`
  - `billingType`（如 `stripe_subscription` / `none`）、`organizationRateLimitTier`、`userRateLimitTier`
  - `hasExtraUsageEnabled`（是否开额外按量额度）
  - `accountCreatedAt`（账号注册年龄）、`subscriptionCreatedAt`（订阅时长，自动判定 **24h 支付复审高敏窗**）
- **官方本地缓存的用量与限制（零网络直读）**：
  - `cachedUsageUtilization.utilization.five_hour` / `seven_day`：百分比、`resets_at`、**`locked_reason`（是否被软锁）**
  - `seven_day_breakdown`：各端消耗占比（`Claude Code / Chats / Cowork / Other`）
  - `cachedExtraUsageDisabledReason`（如 `org_level_disabled`）
- **设备指纹与特性缓存**：`machineID`、`userID`（换号防连坐关键标识）、`modelAccessCache`、`groveConfigCache`。

### 2. `%USERPROFILE%\.claude\.credentials.json`（严格只抽非敏感元数据，绝不读明文 Token）
- `claudeAiOauth.subscriptionType`（`free` / `pro` / `max`）、`rateLimitTier`、`scopes`、`expiresAt`
- `mcpOAuth` 键列表（第三方 MCP 授权平台清单）
- **安全红线**：代码层面严禁读取、日志化或输出 `accessToken` 与 `refreshToken`。

### 3. `%USERPROFILE%\.claude\settings.json` 及辅助目录（卫生与防劫持）
- `env.ANTHROPIC_BASE_URL` / `ANTHROPIC_API_URL`：检测是否被第三方网关/反代劫持非官方端点；
- 隐私降噪变量：`DISABLE_TELEMETRY`、`DISABLE_ERROR_REPORTING`、`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`、`DISABLE_BUG_COMMAND`；
- `permissions.allow`（白名单明文凭据泄漏 Secret Sprawl 检查）与 `hooks` 事件清单；
- `~/.claude/backups/.claude.json.backup.*`（历史备份中出现过多少个不同 `organizationUuid`，识别历史切号与旧号残留）；
- `~/.claude/telemetry/`（待传遥测体积）与 `~/.claude/scheduled-tasks/`（无人值守定时脚本）。

### 4. `~/.claude/projects\**\*.jsonl`（纯离线行为强度，借鉴 `ccusage`，不读聊天正文）
- 统计近 `5h / 24h / 7d` 活跃会话数、调用轮次、Subagent（`isSidechain`）并发占比、模型分布与 Token 消耗；
- 检测是否存在长时间无人工停顿的 24×7 机器循环节奏。

### 5. Claude Desktop 日志与目录（`%LOCALAPPDATA%\Claude\logs\*.log` + MSIX 沙箱目录）
- 扫描 `main.log`、`claude.ai-web.log`、`cowork_vm_node.log`、`mcp.log`、`ssh.log` 及 `claude_desktop_config.json`；
- 提取全部出现过的 `orgId`（与 `~/.claude.json` 交叉比对是否跨端串号）、`account_banned`、`portal.anthropic.com/verify`、`withpersona.com`、跨 `orgId 404`、`oauth403`、`cookie403`、`cf403`、`429`、`plan_changed`、`sideSessions` 并发峰值、MCP 报错风暴。

---

## 二、核心痛点解决：HTTP 403 与日志异常精准消歧矩阵

> **现状痛点**：普通 Free 用户后台轮询 Pro/Cowork 接口时会频繁产生 `OAuth 403 (len=164/156)`，旧版日志页单看日志无法区分“Free 无权限”与“触发 KYC/封号”，极易误判制造焦虑。

通过将 **客户端日志特征 × 本地配置套餐（`~/.claude.json`） × 按需账号体检底牌** 联合交叉判定，把全部 `403` 彻底分清：

| 403 / 报错类型 | 日志 / 响应实证特征 | 真实风险级别 | 精准消歧依据与处理策略 |
| :--- | :--- | :---: | :--- |
| **1. 未登录态 403** | `403` + `credential: none`（如 `my-access`） | **无害（静默归档）** | 登出状态下的普通轮询，直接折叠不报警。 |
| **2. Free 号无订阅权限 403** | 日志 `authorize returned 403 permission_error (len=164/156)` 或 `/subscription_details` 返回 `Missing permissions` | **无害（自动降噪）** | 结合本地配置或账号体检确认当前为 **`Free` 且 `kyc_status` 为 `verified / not_required`** 时，自动归类为「Free 正常无权限」，**默认免打扰不亮红黄灯**。 |
| **3. Cloudflare 节点弹盾 403** | `navigation to https://claude.ai/ failed with status code 403` 或响应头含 `cf-mitigated: challenge` / HTML 挑战页 | **网络问题（非封号）** | 明确提示“节点 IP 被 CF 拦截，账号本身正常”，引导前往「节点流量」更换干净节点。 |
| **4. 会话过期 / 登出失效 403/401** | 接口 403/401 JSON 但 `error_code != "account_banned"`（如 `Invalid authorization`） | **低危（重新登录）** | 仅当前会话凭据失效，未必封号，提示重新登录即可。 |
| **5. 退出回传 / 带凭证 403（前兆）** | `403` + `credential: cookie` + `withheld (len=182/270)` 或 `onQuitCleanup` 断连退错 | **高危前兆（标黄/标红）** | 高度吻合断连/直连瞬间撞出 `region_unavailable`，常在 24~48h 后异步触发验证限制，点亮防裸奔与热熔断提示。 |
| **6. 官方门户验证受限（待核验）** | 日志命中 `portal.anthropic.com/verify` / `withpersona.com`，或 `/kyc_status` 为 `pending/created/needs_review` | **高危受限（未永封）** | 与永久封号严格区分！提示固定干净节点完成官方验证，**严禁直接同机切备用号**。 |
| **7. 官方实锤封号** | 日志或 `/api/organizations` 明确返回 `error.details.error_code === "account_banned"` | **危急（永久封号）** | 同步解析 `appeals_redirect_enabled` 提示是否允许官方申诉，并锁定切号入口，引导走「环境维护 → 原子备份并纯净清理目录」防连坐。 |

---

## 三、综合判断账户风险：6 大类 14 项用户行为风控指标

剔除纯运维噪音（如启动次数、功能开关总数），仅将以下 **14 项直接关联封号风控的行为指标** 纳入综合评估：

1. **多号混登与跨端连坐（3 项）**：CLI vs Desktop `orgId` 一致性、`machineID`/`userID` 污染检查、历史备份多 `orgId` 与日志 `orgId 404` 竞态。
2. **高敏时间窗（2 项）**：账号年龄 `<7 天` 或订阅开通 `<=24h`（含刚过 KYC `<3 天`）、日志 `plan_changed` 套餐跳变。
3. **自动化滥用与并发满载（4 项）**：离线 `.jsonl` 5h/24h 爆发轮次与子代理占比、`scheduled-tasks/` 无人值守脚本、日志 `sideSessions >= 3` & `429` 频次、`cachedUsageUtilization` 持续 `>=85%` 或 `locked_reason` 非空。
4. **违规第三方反代（1 项）**：消费级 `pro/max` 订阅叠加非官方 `ANTHROPIC_BASE_URL`。
5. **断连回传与遥测暴露（2 项）**：带 Cookie 403 / 退出回传报错、`DISABLE_TELEMETRY` 等降噪变量缺失或 `telemetry/` 非空。
6. **风控结果态铁证（2 项）**：`account_banned` / `portal.anthropic.com/verify` / `withpersona.com`、额外用量风控禁用原因。

---

## 四、采集安全红线（为什么绝不碰侵入式）
1. **禁止本地解密 Chromium DPAPI `Cookies`**：与 InfoStealer 窃密木马行为 100% 重合，杀软必报毒且破坏用户信任；
2. **禁止本地 MITM 自签根证书解密 HTTPS**：破坏客户端 TLS/JA3/JA4 指纹与证书校验，反而诱发风控；
3. **禁止进程注入 / 改 `app.asar`**：破坏 Windows MSIX 代码签名与客户端完整性校验，风险最高。

---

## 五、单用户编码实施必守清单（确保未来演进多用户零冲突、零返工）

> 现在开发单用户的非侵入配置识别与 403 消歧时，请严格遵守以下 **6 条代码级工程契约**（单号期零额外复杂度，多号期 100% 直接复用）：

1. **路径全部参数化且可选（严禁硬编码全局路径）**
   - 所有 Rust 扫描/解析函数统一接收 `ProfileContext`（含 `profile_id`、`cli_config_dir: Option<PathBuf>`、`claude_json_path: Option<PathBuf>`、`desktop_data_dir: Option<PathBuf>`），**禁止在解析逻辑内部写死 `~/.claude` 或 `%LOCALAPPDATA%\Claude`**。
   - 任意路径为 `None` 或磁盘不存在时静默跳过并标注 `unknown / 未安装`，保证“纯 Desktop 用户”“纯 CLI 用户”“双端用户”和“未来多号用户”共用同一套代码。
2. **所有持久化状态与已读游标必须带 `profile_id` 命名空间**
   - 日志已读游标（`ackedLogIds`）、403 降噪缓存、本地检测出的 `workspaceGeo` / `kyc_status`、离线用量统计缓存与历史时间线快照，**存储主键必须挂在 `profile_id` 下**（单号阶段固定用 `"default"`），绝不存成全局裸单例字段，避免以后加第 2 个账号时数据互相覆盖串账。
3. **凭据读取采用「白名单反序列化结构体」（类型级防泄密）**
   - 解析 `.credentials.json` 时，Rust 结构体**只声明非敏感字段**（`subscription_type`、`rate_limit_tier`、`expires_at`、`scopes`），**根本不定义 `access_token` / `refresh_token` 字段**，从编译期杜绝明文凭据进入内存结构体、IPC 或诊断日志；
   - 邮箱、UUID、`machineID` 等统一按 [protocol-constants.md](../protocol-constants.md) 规范脱敏（`<REDACTED:2W>` 或 8 位短前缀）。
4. **Windows 共享只读打开 + `mtime/size` 增量缓存**
   - 读取正在被 Claude 写入的 `main.log`、`.claude.json`、`.jsonl` 时，仅以共享只读方式打开（不抢独占锁、不修改文件时间戳）；
   - `.jsonl` 与大日志文件必须做 `(path, mtime, size)` 缓存与尾部截断上限（如单 log 最多读尾 2MB），防止未来扩展到 3~5 个账号档案并行扫描时拖慢界面。
5. **403 消歧器与数据来源解耦（纯函数 + 溯源标签）**
   - 日志 403 消歧函数应写成纯函数：`disambiguate_403(log_event, account_facts) -> DisambiguatedRisk`，不直接读磁盘也不发网；
   - 凡推导出的状态（套餐、KYC、用量）均显式附带数据来源标签（`local_config` / `official_probe` / `offline_jsonl` / `unknown`），严格遵守状态诚实原则，绝不把 `unknown` 误判为“Free 无害”。
6. **Tauri IPC 与前端 TS 契约预留 `profileId`**
   - 新增 Tauri 命令（如 `audit_local_account(profile_id: Option<String>)`）与返回 DTO 均预留 `profileId: String` 字段（单号期默认 `"default"`，前端 UI 无需显示多号切换条），确保后续加多号 UI 时前后端接口零破坏性变更。

