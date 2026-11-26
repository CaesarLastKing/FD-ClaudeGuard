# 2026-11-26 全仓 Bug 与逻辑错误审计总台账

> **归档目录**：`docs/bugs/2026-11-26/`  
> **总计**：46 项实锤问题（P0 15 项 / P1 23 项 / P2 8 项）+ 2 项已确认增量 UI 改动  
> **执行原则**：按功能模块逐卷修复 → 每项补精准回归单测 → 原地更新状态与验证摘要 → 全模块完成后跑真机实测与 Gate 0~5 发布门禁。

## 模块分卷索引

| 序号 | 模块文件 | 涵盖范围 | P0 | P1 | P2 | 当前进度 |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: |
| 01 | [01-basic-features-and-ui.md](./01-basic-features-and-ui.md) | 不可用基础功能、开机真自启、托盘退出确认、更新器 NSIS 冲突、已确认 2 处 UI 改动 | 4 | 0 | 1 | `已完成` |
| 02 | [02-guard-lifecycle-and-nsis.md](./02-guard-lifecycle-and-nsis.md) | NSIS 卸载权限、Kill-Hold 事务锁、安全启动熔断门禁、MSIX 中文路径、提权转义、防误杀、回滚与单实例 | 5 | 7 | 2 | `已完成` |
| 03 | [03-proxy-preflight-and-nodes.md](./03-proxy-preflight-and-nodes.md) | 禁区节点正则、`node_dns` Fake-IP 真修复、无合规节点拦截、Mihomo/AGY/GeoIP/端口与策略优先级 | 3 | 8 | 2 | `已完成` |
| 04 | [04-account-audit-and-maintenance.md](./04-account-audit-and-maintenance.md) | 6 态拓扑同源、原子还原防损坏、封号特征对齐、云端探针冷却与脱敏防泄密 | 2 | 3 | 1 | `已完成` |
| 05 | [05-frontend-state-and-hud.md](./05-frontend-state-and-hud.md) | 深度核验锁死、审计加载白屏、HUD 跳转劫持、实时流量角标、熔断主按钮与 store 竞态 | 1 | 5 | 2 | `已完成` |
