# 活跃需求与功能待办表（Feature Backlog · 仅保留未完成）

> **更新日期**：2026-11-28  
> **规则**：本表**只记录未完成/进行中的新功能、产品重构、体验优化、技术调研与生态规划**（Bug 请走 [bug-tracker.md](./bug-tracker.md)）。凡已发布关闭的需求，立即移出并归档至 [docs/archive/](../archive/README.md)。  
> **配套**：复杂需求进入讨论时，必须在 [docs/specs/](../specs/README.md) 建立独立 `SPEC-xxx.md` 实时沉淀细节防压缩失忆。

| 编号 | 分类 | 优先级 | 状态 | 需求事项 | 核心范围与目标 | 方案文档 / 待决项 |
| :--- | :--- | :---: | :---: | :--- | :--- | :--- |
| `F-01` | **控制台** | **P1** | `代码已完·待实机验收` | **「本地封号污染残留审查」身份验证实锤拦截与闭环** | 仅实锤（封号/禁区/Persona/Portal）判 `Fail` 拦截（引导清记录+换节点，清完未换旧节点降级 `Warn` 提醒换点）；模糊 `len=164` 不拦截保持 `Ok` 仅说明提示；右侧极简中性展示+主蓝按钮 | 已实现定稿口径（待全量测试与实机验收） |
| `F-02` | **控制台** | **P1** | `代码已完·待实机验收` | **「单号卫生锁」三态确认与去组织号/去主号** | 控制台全量移除组织号与「主号」改称「当前号」：0 号 `Ok` / 1 号 `Warn`（需确认或清理后变 `Ok` 满足 12/12 解锁启动）/ ≥2 号 `Fail` 仅清理；右上角「一键处理全部」区分自动/人工杜绝空转 | 已实现定稿口径（待全量测试与实机验收） |
| `F-03` | **控制台** | **P1** | `待确认` | **控制台检查项优先级与展示位置调整** | 调整「必须通过（12 项）」与「建议优化（7 项）」的排序策略（未通过置顶 / 已通过折叠 / 分组重排） | 阻塞于 [Q1](./decisions-open.md) · 方案见 [02](../plans/backlog-optimization/02-phase2-p1-killswitch-and-console.md) |
| `F-04` | **熔断体系** | **P1** | `待排期` | **4 层热熔断机制专项优化（含 `guard://killswitch` 联动）** | 梳理触发精准度、防误杀边界、专用「紧急熔断中」状态卡/详情引导、与 Windows 原生通知去重防打扰、一键恢复解除闭环（原 `T-062`），以及**控制台「运行中防护警示横幅」区分真未通过（`Fail`）与风险提示（`Warn`）触发边界收敛**（杜绝单号运行时误弹清退横幅） | 方案见 [02](../plans/backlog-optimization/02-phase2-p1-killswitch-and-console.md) |
| `F-05` | **账户审计与宝典** | **P1** | `代码已完·待实机验收` | **拆分「新号、支付与 KYC 后高敏观察窗」** | 已拆分为 **1. 高敏感观察窗（新号 / KYC / 套餐跳变）** 与 **2. 支付方式与账单风控** 2 个独立卡片，并补齐单测断言 | 第一批已落盘（待收敛验收） |
| `F-06` | **账户审计与宝典** | **P1** | `待确认` | **按分类完善账户审计体检项（支付/指纹/使用方式等）** | 围绕支付方式、设备指纹、使用方式等建立清晰分类体系，新增用户自判与环境审计项并重分类 | 阻塞于 [Q2](./decisions-open.md) · 方案见 [03](../plans/backlog-optimization/03-phase3-audit-system-and-playbook.md) |
| `F-07` | **账户审计与宝典** | **P2** | `代码已完·待实机验收` | **重排「工具可介入防御与修复」5 项先后顺序** | 已按 Q3 定稿顺序重排：`归属地与出口 → Clash 断连防护 → 多号混登残留 → API 端点防反代 → 本机遥测降噪` | 第一批已落盘（`Q3` 已关闭） |
| `F-08` | **账户审计与宝典** | **P2** | `暂缓归档` | **100 分制评分权重体系重构（v2）** | 修复 `LocalOnly` 虚高染绿 `85 分`、严重限制标/KYC 过期扣分过轻且无硬封顶问题 | 已有草案：[design-scoring-model-v2.md](../design-scoring-model-v2.md) |
| `F-09` | **账户审计与宝典** | **P2** | `待排期` | **「防封宝典」按分类体系重构注意事项** | 同步账户审计新分类维度，按分类归档重写防封宝典抽屉注意事项，便于对照查阅 | 与 `F-06` 联动 · 方案见 [03](../plans/backlog-optimization/03-phase3-audit-system-and-playbook.md) |
| `F-10` | **界面精修** | **P2** | `代码已完·待实机验收` | **侧边栏左下角状态卡与「系统设置」间距微调** | `Claude 进程` 与 `Clash Verge` 两卡间距调大至 `16px`；`Clash Verge` 卡片到底部分割线/「系统设置」间距收紧（`marginTop:-10, paddingTop:7`） | 第一批已落盘（待双主题实看） |
| `F-11` | **多账户与额度** | **P2** | `部分完成` | **无/有 `sk` 刷新体验边界收口** | 在 `v0.4.0/0.4.1` 历史档案持久化基础上，复核无 `sk` 切换新号、实时出口联动及有 `sk` 手动重验粒度细节 | 阻塞于 [Q4](./decisions-open.md) · 方案见 [03](../plans/backlog-optimization/03-phase3-audit-system-and-playbook.md) |
| `F-12` | **多账户与额度** | **P2** | `待调研` | **Claude 5h/7d 额度显示方案（GitHub 开源选型）** | 深度对比离线 `ccusage`、`/api/oauth/usage` 与已内置 `sessionKey`，权衡准确度 vs 明文 OAuth 隐私红线与 429 限流 | RFC 思路见 [04](../plans/backlog-optimization/04-phase4-exploratory-and-ecosystem-rfcs.md) |
| `F-15` | **安全与生态** | **P2** | `待确认` | **AI 检验工具自身安全性（开源安全审计）** | 对源码、联网、脱敏、提权边界、Clash 可逆性与构建产物做系统安全审计 | 阻塞于 [Q7](./decisions-open.md) · RFC 见 [04](../plans/backlog-optimization/04-phase4-exploratory-and-ecosystem-rfcs.md) |
| `F-17` | **安全与生态** | **P3** | `待确认` | **开源版本广告位设计与落地** | 在不破坏 UI v3.0 极简审美前提下规划轻量广告位/赞助位 | 阻塞于 [Q9](./decisions-open.md) · RFC 见 [04](../plans/backlog-optimization/04-phase4-exploratory-and-ecosystem-rfcs.md) |
| `F-18` | **安全与生态** | **P3** | `待确认` | **「AI 工具箱」首批真实功能规划与接入** | 为已预留的 `AiToolsPage.tsx` 确定首批高价值模块（如 MCP 管理、提示词/会话归档、快捷诊断等） | RFC 见 [04](../plans/backlog-optimization/04-phase4-exploratory-and-ecosystem-rfcs.md) |
| `F-19` | **发版与签名** | **P3** | `远期规划` | **Windows Authenticode 代码签名证书接入** | 消除 Windows SmartScreen 安装拦截蓝窗（原 `B-003` / `O-14`） | RFC 见 [04](../plans/backlog-optimization/04-phase4-exploratory-and-ecosystem-rfcs.md) |
