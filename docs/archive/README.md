# 已完成历史冷归档区（Archive · 日常严禁主动读取）

> **用途**：集中收纳已发布关闭的需求台账、历史 Bug 记录、过期阶段计划与已完成 Spec，**彻底将其与活跃工作区隔离**，避免 AI 每次开工白白消耗几十 KB 上下文。  
> **规则**：日常开发、排查、排期**禁止读取本目录**；仅在需要追溯早期决策原因或核查历史提交背景时按需定向查阅。

---

## 一、已归档历史总账

| 归档文件 | 覆盖范围 | 说明 |
| :--- | :--- | :--- |
| [`completed-tasks-v021-v040.md`](./completed-tasks-v021-v040.md) | `v0.2.1` ~ `v0.4.0`（`T-001` ~ `T-060`） | 从原 `docs/task-ledger.md` 完整迁出的 60 条已发布关闭历史记录 |
| [`declined-multi-account-v041.md`](./declined-multi-account-v041.md) | `F-13 / F-14 / F-16` | 已定案暂不采用的多账户隔离与账户登录规划冷归档（2026-11-28） |
| [`CHANGELOG.md`](../../CHANGELOG.md) | `v0.1.0` ~ 最新 | 按版本沉淀的正式发版日志（对外公开真源） |

---

## 二、仍保留在 `docs/` 顶层的历史已完成阶段文档索引（供回溯参考，日常免读）

> 为防止破坏仓库内既有引用链接，以下已完成的历史文档暂保留原路径，视为冷归档资料，日常不再维护与加载：

- **历史阶段路线图 / 待办**：`development-plan.md`、`optimization-plan-v023.md`、`todo-v029-oss-and-audit.md`、`todo-v032-roadmap-and-optimizations.md`、`todo-v034-product-review.md`、`todo-v035-clash-rules-hardening.md`、`todo-v036-multi-account-history-and-fixes.md`、`todo-v038-smart-update-scheduler.md`
- **历史缺陷审计 / 踩坑录**：`dev-issues-log.md`、`audit-full-bug-list-20261126.md`、`docs/bugs/2026-11-26/*`、`ui-v3-qa-audit-checklist.md`
- **历史一次性开发交接 / Prompt**：`handoff-20261124.md`、`handoff-to-dev.md`、`handoff-ui-v3-upgrade.md`、`handoff-v030-account-audit.md`、`prompt-ui-v3-settings-modal.md`
- **已终止商业化历史文档**：`commercial-licensing.md`（产品已于 `v0.2.9` 转为 GPL-3.0 免费开源）
