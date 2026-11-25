# 03 · Claude 网页端 `sessionKey` 探测原理、竞品拆解与真机实证记录

> **用途**：沉淀 `ssessionkeytester.zeabur.app` 逆向分析成果，以及自建独立只读原型 [session-analyzer-mvp](../../session-analyzer-mvp/README.md) 跑通真实账号（含正常 Free+KYC 已验多组织号、官方实锤封号 `account_banned` 号）的核心技术发现，作为未来并入 `FDtools` Rust 探针的协议真源。

---

## 一、竞品网站 `ssessionkeytester.zeabur.app` 逆向拆解结论

1. **架构**：React + Vite SPA，前端不直连 Anthropic，全部通过同源后端反代网关（单批 10,000、并发 30）以 NDJSON 流回传。
2. **存在 2 个未在首页展示的隐藏写操作路由**（安全警示：`sessionKey` 等价全权限网页登录态，切勿把主力号明文提交给第三方站点）：
   - `/sessionlogout` → `POST /api/revoke`（`scope: "current" | "all"`，一次性作废当前或全部设备会话，吊销后旧 key 立即失效）；
   - `/kycrefresh` → `POST /api/refresh-kyc`（针对已触发 KYC 但缺链接/过期的账号重新生成 Persona 链接，含 4 轮指数退避重试；不会重置已通过 KYC 的账号）。
3. **核心探测逻辑**：
   - 套餐分级（按优先级）：`Enterprise` → `Team` → `Max 20x` → `Max 5x` → `Max` → `Pro` → `Free`；
   - 双路 KYC 判定：订阅 KYC（`kyc_status`）+ Portal KYC（通过网关 `edge-api` 检查 `hold_notice === null`）；
   - 联合降级：即使接口 200，只要组织禁用/计费暂停/任意一路 KYC 未放行，即降级为 `alive-but-restricted`。

---

## 二、自建本地只读原型（`session-analyzer-mvp`）真机实测关键发现

通过 Windows 原生 `curl.exe`（Schannel）走本机代理直连 `https://claude.ai`（携带 `anthropic-client-platform: web_claude_ai`），零 Cloudflare 弹盾一次拿全真实数据，实证总结出 **5 条极高价值的工程校准规律**：

1. **多组织智能选主（致命避坑）**：
   - 同一个账号的 `GET /api/organizations` 可能同时返回 **Console API 组织**（`capabilities: ["api", "api_individual"]`，常见 `api_disabled_reason: "out_of_credits"`）与 **Claude.ai 聊天主组织**（`capabilities: ["chat"]`）；
   - **必须优先选择含 `chat` 能力的组织 UUID** 去查后续子接口，否则误拿 API 组织查 `/usage` 和 `/chat_conversations` 会全部报 403 误判。
2. **真实端点实测矩阵**：
   - `GET /api/organizations`：200，含原生 4 大风控槽位 **`access_block` / `billing_issue` / `subscription_pause` / `monitoring_notice`**、`rate_limit_tier`、`analytics_subscription_plan`、`billing_type`、`merchant_of_record`、`active_flags`。
   - `GET /api/account`：200，含 `created_at`（总账号年龄）、`is_verified`、`age_is_verified`、`verified_phone_number_last4`、`never_accepted_legal_document_types`、以及 `memberships[].organization.default_workspace_geo`（**官方工作区归属地如 `"us"`**）与 `claude_ai_bootstrap_models_config`（下发活跃模型与上下文 `hard_limit`）。
   - `GET /api/organizations/:id/kyc_status`：200，精准返回 `status`（**含 `"verified"` 放行态**）、`check_kind`、`created_at`、`completed_at`、`vendor_inquiry_id`。
   - `GET /api/organizations/:id/usage`：200，返回 `five_hour`、`seven_day`、`seven_day_opus` 等实时窗口。
   - `GET /api/organizations/:id/chat_conversations?limit=1`：200，验证对话域可读性（识别半封号）。
   - `GET /api/organizations/:id/subscription_details`：Free 账号（`billing_type: "none"`）返回 `403 Missing permissions`，属正常现象，UI 应静默标为 `Free 无订阅`。
3. **双年龄口径区分**：`account.created_at`（总账号年龄，如 84 天）与 `primaryOrg.created_at`（Claude.ai 主组织年龄，如 38 天）需同时保留，前者反映账号总资历，后者与原网站一致。
4. **实战级风控发现：`default_workspace_geo` vs `cf-ray` 地区错配**：
   - 实测账号 `default_workspace_geo: "us"`，而请求边缘 `cf-ray` 落在 `-SYD`（悉尼）；自动比对这两者可直接揪出跨洲代理隐患。
5. **HTTP 403 实锤封号精准识别**：
   - 真实封号样本在 `/api/organizations` 返回：
     ```json
     { "error": { "type": "permission_error", "message": "account_banned", "details": { "appeals_redirect_enabled": true, "error_code": "account_banned" } } }
     ```
   - 据此实现 403 三分法：**官方实锤封号（`account_banned` + 是否可申诉）** vs **普通凭据过期** vs **Cloudflare 弹盾**。

---

## 三、隐私与脱敏安全红线（已在 `sanitizer.mjs` 落地并单测验证）
- 服务端严格只发 `GET` 只读请求，绝不提供吊销/写接口；
- 本地快照永不落盘明文 `sessionKey`（仅存 SHA-256 16 位指纹 + 掩码 + 脱敏邮箱）；
- 提供一键「强脱敏诊断包」导出，递归清除 `sessionKey`、真实邮箱、姓名、手机号、URL Token 与可追踪 UUID。
