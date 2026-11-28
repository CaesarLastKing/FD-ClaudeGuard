# FD Claude Guard 任务与问题持久化登记总表（已升级至文档体系 v3.0 · 轻量入口）

> **重要升级说明（2026-11-27）**：为解决历史已关闭项不断堆积占用上下文（原文件达 `38 KB`）以及需求与 Bug 混杂问题，本台账已按 **热/冷分层** 拆分为职责清晰、极简轻量的独立文档，总导航见 [docs/README.md](./README.md)：
>
> - **未完成需求表（热区）**：[docs/active/feature-backlog.md](./active/feature-backlog.md)（只放未完成/进行中的新功能、重构、调研与生态项）
> - **活跃 Bug 与待验收表（热区）**：[docs/active/bug-tracker.md](./active/bug-tracker.md)（只放未发布关闭的缺陷与待真机验收项）
> - **待拍板决策表（热区）**：[docs/active/decisions-open.md](./active/decisions-open.md)（卡住推进的 Q 池，拍板即清）
> - **需求方案与讨论细节库（防上下文压缩失忆）**：[docs/specs/README.md](./specs/README.md)（复杂需求讨论边聊边写 `SPEC-xxx.md`，压缩前必同步）
> - **已完成历史冷归档（冷区·日常免读）**：[docs/archive/completed-tasks-v021-v040.md](./archive/completed-tasks-v021-v040.md)（完整保留原 `T-001` ~ `T-060` 已发布关闭记录）

---

## 当前仅余 2 条原编号活跃映射（实时明细请直接查看 `docs/active/`）

| 原 ID | 类型 | 简述 | 当前状态 | 新体系对应位置 |
| :--- | :--- | :--- | :---: | :--- |
| `T-061` | 缺陷与验收 | `v0.4.1` UI/CDP 全页修复 + 2 轮跨界深挖 12 项修复 + 9 维静态契约门禁 | `待打包确认` | [docs/active/bug-tracker.md](./active/bug-tracker.md)（`BUG-41-01 ~ 08`） |
| `T-062` | 专项优化 | 4 层热熔断机制专项优化（含 `guard://killswitch` 联动与体验打磨） | `待排期` | [docs/active/feature-backlog.md](./active/feature-backlog.md)（`F-04`） |
