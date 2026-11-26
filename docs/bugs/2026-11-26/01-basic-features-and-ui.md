# 01 · 基础功能失效、自动更新与已确认 UI 改动（2026-11-26）

> **模块范围**：`MaintenancePage.tsx`、`SettingsPage.tsx`、`AccountAuditPage.tsx`、`App.tsx`、`SupportModal.tsx`、`updater/mod.rs`、`lib.rs`（自启/退出）、`telemetry/mod.rs`

| 编号 | 级别 | 标题 | 代码位置 | 根因与后果 | 状态 | 修复与验证摘要 |
| :---: | :---: | :--- | :--- | :--- | :---: | :--- |
| `BUG-P0-01` | **P0** | 「一键匿名上报排障」100% 必报错 & 2 个遥测开关空转 | `MaintenancePage.tsx`、`SettingsPage.tsx`、`telemetry/mod.rs` | 开源默认无 `FD_TELEMETRY_API_URL` 后端，点击上报必弹红框报错，2 个绿标遥测开关完全空转 | `已完成` | 已移除必报错的「一键匿名上报排障」按钮/弹窗与 2 个空转遥测开关，保留「导出脱敏 AI 诊断包」；已更新 Vitest 断言 |
| `BUG-P0-02` | **P0** | 托盘退出防呆弹窗在仅防火墙激活（0 进程）时文案误报 | `lib.rs:2883`、`App.tsx:90-125` | 核实 `App.tsx` 已监听 `listenConfirmExit`，但 `bgProcs === 0`（仅熔断防火墙激活）时误报“检测到 0 个进程存活” | `已完成` | 区分进程存活与仅防火墙激活两套准确确认文案及退出动作 |
| `BUG-P0-03` | **P0** | 「开机自启」与「开机仅显悬浮窗」在管理员提权下开机根本起不来 | `startup_audit/mod.rs`、`lib.rs:572,2549`、`nsis/hooks.nsh` | `HKCU\Run` 无法自启带 `requireAdministrator` 的程序，且失败静默吞错弹绿 Toast | `已完成` | 改用高权限计划任务 `FDClaudeGuard_AutoStart`（`schtasks /SC ONLOGON /RL HIGHEST`），失败立即报错不吞错，卸载钩子同步清理，并接入 `StartupApproved` 禁用位检查 |
| `BUG-P0-09` | **P0** | 自动更新 NSIS 覆盖安装后 400ms 又调 `handle.restart()` 抢文件锁 + 60s 下载总超时 | `updater/mod.rs` | NSIS 覆盖升级期间重拉旧进程冲突，且 60s 整包超时在慢网必中断，无并发重入锁 | `已完成` | 增加 `UPDATE_INSTALL_IN_FLIGHT` 防重入锁、下载超时放宽至 300s、Windows NSIS 不再调用 `handle.restart()` |
| `UI-V34-01` | **已确认** | 账户审计左栏极简多档案标记 + Free 隐藏多余「订阅时长 ⇄」 | `AccountAuditPage.tsx`、`account-audit.css` | 按已确认精简效果图 v2 仅改左栏（`当前档案 (N)` + `双号` + 2 行紧凑旧号次卡）与 Free 胶囊，右侧结构不动 | `已完成` | 已按效果图 v2 精确落地，右侧整体设计零改动 |
| `UI-V34-02` | **已确认** | 守卫配置更新模块状态文案与单一检测按钮解耦 + 实时下载百分比 | `SettingsPage.tsx`、`guardStore.ts`、`App.tsx`、`ipc.ts` | 按已确认效果图移除页头右上角重复「检查更新」按钮，状态改纯只读徽章，对接 `guard://update-progress` 实时百分比 | `已完成` | 单入口更新卡片落地，状态徽章与操作按钮彻底分离，支持下载百分比与失败直达 Releases |
| `BUG-P2-08` | **P2** | `SupportModal` 残留旧商业文案「官方售后 QQ」& 2 个死注册命令 | `SupportModal.tsx:161`、`lib.rs` | 顶部已为「免费开源」，下方卡片仍写「官方售后 QQ」；`save_hud_position`/`get_killswitch_state` 未被调用 | `已完成` | 统一改为「开发者交流 QQ」，已清理 2 个未用 Tauri 命令 |
