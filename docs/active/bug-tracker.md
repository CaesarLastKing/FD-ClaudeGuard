# 活跃 Bug 与待验收缺陷追踪表（Bug Tracker · 仅保留未发布关闭）

> **更新日期**：2026-11-27  
> **当前已发版基线**：`v0.4.0`（Commit `96817f7`）｜**工作区待发版本**：`v0.4.1`  
> **规则**：本表**只记录尚未发布关闭的 Bug 与代码已完待验收项**（新需求请走 [feature-backlog.md](./feature-backlog.md)）。一旦随正式包发布并通过真机验收，立即移出本表并归档至 [docs/archive/](../archive/README.md)。  
> **关联排查明细**：[v0.4.1 Bug 排查与验收方案](../v041-bugfix-and-audit-plan.md) · [v0.4.0 全页面实机审查报告](../v040-full-ui-audit-report.md) · [v0.4.1 跨界深度排查报告](../v041-deep-system-audit.md)

---

## 一、`v0.4.1` 代码已修完，待真机 Gate 0~5 终验与打包确认

> 说明：以下 `v0.4.1` 批次代码已在当前工作区落盘（`check:contracts` 9 维、`tsc --noEmit`、`cargo check` 与 8 份定向 Vitest 通过），**尚未执行全量单测、真机安装包闭环验收（Gate 0~5）与正式打包发布**（对应原 `T-061`）。

| 编号 | 严重度 | 状态 | 缺陷简述 | 修复落点与待验收核心证据 |
| :--- | :---: | :---: | :--- | :--- |
| `BUG-41-01` | **P0** | `代码已完·待真机验收` | **冷启动前 15 分钟防裸奔失明 + 更新失败无退避** | `lib.rs` 首检完成置位 `initial_preflight_done = true`；`updater/mod.rs` 新增 10m 失败退避与回退锁版本号；待真机冷启动 5 秒内实测拦截 |
| `BUG-41-02` | **P0** | `代码已完·待真机验收` | **开机自启安装未注册、开关割裂 & 无法识别 Clash 计划任务自启** | `hooks.nsh` 全新安装注册 `FDClaudeGuard_AutoStart` + `lib.rs` 启动期幂等对齐 + `startup_audit/mod.rs` 计划任务 XML 扫描识别 `Clash Verge (Admin)` + 一次性配置迁移 `config_schema_version = 1`；待正反向安装/开关实机闭环 |
| `BUG-41-03` | **P0** | `代码已完·待真机验收` | **控制台 KV 行挤压重叠、中英混排与 4 处安全值误标红** | 修复 `.c-kv-row` 压扁叠字、19 项左中文/右简约、修正 `0 冲突`/`已阻断 (OK)` 误标红与 IPv6 冒号拆行、清理全部废弃 v2 页面引导文案；待双主题 19 项逐条验收 |
| `BUG-41-04` | **P0** | `代码已完·待真机验收` | **云端诊断上报字段名不匹配 & Worker `?kind=events` SQL 缺列崩溃** | `diag-worker/src/index.js` 兼容 `installIdHash`/`appVersion` 双命名并修正 `telemetry_events` 真实列名；需真机主动上传新工单并用 D1 查询核验 `app_version` 非 `unknown` |
| `BUG-41-05` | **P0** | `代码已完·待真机验收` | **二轮深挖 3 项安全/持久化隐患（禁无代理裸连 `sk` + 唯一临时文件原子写）** | `cloud_probe.rs` 禁止非回环地址无代理发 `sk`；关键 JSON 全面改用带 `pid/seq` 唯一临时文件原子替换；`check:contracts` 升至 9 维防错 |
| `BUG-41-06` | **P1** | `代码已完·待真机验收` | **历史账号 `sk` 快照丢失 + 美国节点误标 `US(TPE)` + 未读红标打架** | `account_audit/mod.rs` 跨号确认前即持久化 `orgSnapshots`/`accountHistory` 并自动融合；禁止无 `exit_colo` 时回退拼旧 `edge_colo`；修正未读数与脉冲卡文案冲突 |
| `BUG-41-07` | **P1** | `代码已完·待真机验收` | **实时流量空进程名兜底硬写 `"Claude"` 与「0 残留」自相矛盾** | `killswitch/mod.rs` 改用 Windows 原生端口反查真实进程（识别 `chrome.exe (网页端)`），严禁空进程名假冒 `"Claude"`；待 Chrome 开 `claude.ai` 实机验收 |
| `BUG-41-08` | **P1** | `代码已完·待真机验收` | **一轮 9 项跨界契约与 UI 细节修复** | 修 `--bad-border` 未定义、调高设置弹窗首屏露出主动上传、统一 `GPL-3.0 开源`、归档废弃 `MaintenancePage`/`SettingsPage` 并迁移 8 份测试、补 `guard://killswitch` 监听兜底 |

---

## 二、本批同步收口的低优缺陷（已随第一批落盘，待同批次实机验收关闭）

| 编号 | 严重度 | 状态 | 缺陷简述 | 修复落点与核验口径 |
| :--- | :---: | :---: | :--- | :--- |
| `BUG-42-01` | **P2** | `代码已完·待实机验收` | **桌面悬浮窗（HUD）深色主题同步** | `HudCard.tsx` 已同步 `data-theme`；本次补充 `guardStore.ts` 主题持久化至 `localStorage` 与 `hud.tsx` 渲染前首帧预置，消除冷启动闪白 |
| `BUG-42-02` | **P2** | `代码已完·待实机验收` | **「清理恢复」基线读取慢无缓存 + `CN台湾` 左徽标误显 `HK`** | `rollback/mod.rs` 新增 15s 内存 TTL 缓存与全写点失效联动（手动刷新穿透）；`NodesTrafficPage.tsx` 已用 `formatCleanNodeName` 剥离退化国旗 Emoji 并明确区分「实测落地 HK（挂名 TW · 禁区隔离）」；`mihomo/mod.rs` 合并台湾/台北地区提取重复分支 |
| `BUG-42-03` | **P2** | `代码已完·待实机验收` | **Mihomo 命名管道瞬时重试 `os error 231` 告警噪音** | 源码核实 `mihomo/mod.rs:1759` 已实现 `ERROR_PIPE_BUSY (231)` 8 次静默退避重试（仅全败记 1 条 WARN），待实机日志核销关闭 |
