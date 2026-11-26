# 04 · 账户审计、看门狗日志与数据维护（2026-11-26）

> **模块范围**：`account_audit/*.rs`、`watchdog/mod.rs`、`maintenance/mod.rs`

| 编号 | 级别 | 标题 | 代码位置 | 根因与后果 | 状态 | 修复与验证摘要 |
| :---: | :---: | :--- | :--- | :--- | :---: | :--- |
| `BUG-P0-13` | **P0** | “单一真源 6 态拓扑”口径分裂：账户审计传 `&[]` 丢弃 Portal 受限号 | `account_audit/mod.rs:961` | 本地日志命中 `portal.anthropic.com/verify` 时控制台报红灯高危连坐，账户审计却报绿灯无污染 | `已完成` | 传入 `local.desktop.portal_org_prefixes` 与控制台 100% 同源，补回归单测通过 |
| `BUG-P0-14` | **P0** | “原子还原”实为原地合并覆写：残留 WAL/LDB 致数据库损坏、未防目标软链穿越、失败半残且漏 staging 目录 | `maintenance/mod.rs:1780-2000` | 还原不清理备份后新增脏文件导致 SQLite/LevelDB 损坏或旧污染日志残留；未检目标软链；异常退出残留 `.restore-staging-*` | `已完成` | 新增 `TempDirGuard` 清理 staging；写回前调 `purge_restorable_stale_files` 清除非保护区脏 WAL/LDB/日志（保护 VM/MCP）；`ensure_not_symlink_target` 拦目标软链穿越；补单测通过 |
| `BUG-P1-16` | **P1** | 封号残留规则三方分裂（`local_scan` 漏检多项特征）+ 切号后归属地/续费日/额度张冠李戴老号 | `local_scan.rs:1632`<br>`account_audit/mod.rs:668,1254,1669` | 漏检 `account_suspended`/`organization_disabled`/`ban_evasion`/`sessionkey names a different account`；`load_bound_workspace_geo` 未按 org 分桶；桌面 Free 号误借 CLI 旧号续费与额度 | `已完成` | 封号/跨号规则三方对齐；`load_bound_workspace_geo` 按活跃 org 分桶查询；Free 或跨端不同号绝不借用 CLI 续费日与额度 |
| `BUG-P1-17` | **P1** | `cloud_probe` 中 `chat_available` 故障假绿 + 失败也锁 60s 冷却 + 响应头拆分边界；`restore_official_endpoint` 吞错 & 隐私补齐丢非字符串原值 | `cloud_probe.rs:231,527,1041,1271`<br>`account_audit/mod.rs:1857,2013` | 超时/HTML 页误判 `chat_available=true`；代理失败后切节点重试被锁 60s；删注册表吞错未广播；布尔/数字原值撤回误删 | `已完成` | `chat_available` 仅 `r.ok` 为真；代理/CF 失败撤销 60s 冷却；稳健拆分响应头；端点清理校验错误并广播 `WM_SETTINGCHANGE`；保留非字符串原值 |
| `BUG-P1-18` | **P1** | `watchdog` orgId 大小写误判混登 + 折叠已读吞新告警 + 尾读首行残片置顶；清理未检 0 进程 & 脱敏漏驼峰凭据/代理账密 | `watchdog/mod.rs:869,1180,1410`<br>`local_scan.rs:196`<br>`maintenance/mod.rs:110,1455` | 大小写 UUID 触发假混登；主 ID 已读吞子告警；首行残片永久置顶；未归 0 进程删锁文件；诊断包明文漏 `accessToken`/`ANTHROPIC_API_KEY`/代理密码 | `已完成` | `orgId` 统一转小写；折叠已读改按 `all_collapsed_acked`；尾读丢首行残片且改用 `take().read_to_end`；清理前强检 0 进程且仅删已归档文件；补全驼峰凭据与代理 URL 账密脱敏（补单测通过） |
| `BUG-P2-05` | **P2** | 备份 ZIP 失败残留 `.zip.tmp`；诊断包同分钟导出静默覆盖且非原子写 | `maintenance/mod.rs:1282,2265` | 备份失败留垃圾 `.tmp`；同分钟连点导出覆盖前包且中断留损坏半成品 | `已完成` | 引入 `TempFileGuard` 清理失败 `.tmp`；诊断包精确到秒并先写 `.tmp` 原子重命名；122/122 Rust 单测 0 警告通过 |
