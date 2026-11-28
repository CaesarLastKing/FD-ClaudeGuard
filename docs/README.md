# FD Claude Guard 文档体系导航总览（v3.0 · 热冷分层防失忆）

> **核心原则**：**热区极简（AI 每次开工只读 < 5 KB）、冷区隔离（已完成历史绝不混入活跃表）、方案落盘（讨论需求边聊边写 `specs/` 防上下文压缩失忆）**。

---

## 一、全仓到底有哪些“表”与文档？（6 类职责划分）

| 层级 | 目录 / 文件 | 职责定位 | 含已完成项？ | AI 日常读取规则 |
| :--- | :--- | :--- | :---: | :--- |
| **1. 活跃跟踪表（热区）** | [`docs/active/feature-backlog.md`](./active/feature-backlog.md) | **需求表**：只记录未完成的新功能、重构优化、专项调研与生态规划 | ❌ 否 | **必读**（开工/排期/同步进度） |
| | [`docs/active/bug-tracker.md`](./active/bug-tracker.md) | **Bug 表**：只记录未发布关闭的缺陷与待验收/待打包确认项 | ❌ 否 | **必读**（修 Bug/验收/发版前） |
| | [`docs/active/decisions-open.md`](./active/decisions-open.md) | **待拍板决策表**：只记录卡住开发的开放选择题（Q 池） | ❌ 否 | **按需必读**（拍板后即移出） |
| **2. 需求方案细节库（防失忆区）** | [`docs/specs/`](./specs/README.md) | **需求方案与讨论细节库**：每讨论一个复杂需求建一份 `SPEC-xxx.md`，实时记录需求点、边界、否决方案与讨论增量，**彻底防上下文压缩失忆** | 仅进行中方案（上线后迁 `archive/`） | **讨论/开发该专题时必读必写** |
| **3. 长期活规范（真源区）** | [`engineering-workflow.md`](./engineering-workflow.md) · [`ui-design-system.md`](./ui-design-system.md) · [`protocol-constants.md`](./protocol-constants.md) · [`standards/`](./standards/) | 研发/测试/验收规范、UI v3.0 视觉规范、协议常量、SOP | 长期有效 | 修改对应领域前按需读取 |
| **4. 架构与产品背景** | [`architecture-and-design.md`](./architecture-and-design.md) · [`anti-ban-playbook.md`](./anti-ban-playbook.md) · [`reversible-safety-and-qa-plan.md`](./reversible-safety-and-qa-plan.md) | 架构原理、防封策略、可逆安全与质检总方案 | 长期有效 | 按需查阅 |
| **5. 调研与视觉原型** | [`research/`](./research/README.md) · [`mockups/`](./mockups/) | 专题技术调研报告（如多账户隔离、403 消歧）与 1:1 交互原型 | 参考资料 | 做对应设计/研发时查阅 |
| **6. 已完成冷归档（冷区）** | [`docs/archive/`](./archive/README.md) · [`CHANGELOG.md`](../CHANGELOG.md) | 全部已发布关闭的需求、Bug、历史版本台账、过期交接文档 | ✅ 是 | **日常禁止主动读取**（防占上下文），仅回溯查历史时翻阅 |

---

## 二、流转纪律（保持文档永不臃肿的 4 条铁律）

1. **热表只减不增历史**：`docs/active/` 下任何条目一旦随版本发布关闭，**立刻从热表删除**，仅在 `CHANGELOG.md` 与 `docs/archive/` 追加一行归档索引。
2. **需求与 Bug 严格分表**：新能力/重构/体验升级/调研进 `feature-backlog.md`；实机故障/逻辑错误/跨界契约缺陷进 `bug-tracker.md`；需要用户二选一拍板的统一汇入 `decisions-open.md`。
3. **讨论需求先建 Spec**：凡涉及多轮讨论或 3 个以上细节的需求，先复制 [`docs/specs/_TEMPLATE-spec.md`](./specs/_TEMPLATE-spec.md) 创建 `SPEC-xxx-<主题>.md`，**每轮讨论结束或执行 `/compact` 前必须把新敲定的细节与否决项落盘**。
4. **旧入口兼容保留**：原 `docs/task-ledger.md` 与 `docs/todo-master-roadmap.md` 已瘦身为轻量导航指针（历史 60 条记录已完整迁入 [`docs/archive/completed-tasks-v021-v040.md`](./archive/completed-tasks-v021-v040.md)），释放 36 KB+ 上下文。
