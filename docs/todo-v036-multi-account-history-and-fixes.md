# v0.3.6 / v0.3.7 改动记录与逐项验收台账（已 100% 闭环收口）

> **最终状态**：**Gate 0 ~ Gate 5 全部 6 道硬门禁 100% 实证通过**（含线上 GitHub Actions 签名发版 + 本机 `v0.3.5 → v0.3.7` 线上通道实机热更新终验）  
> **终验时间**：2026-11-27 02:52  
> **线上正式发布**：[GitHub Release v0.3.7](https://github.com/CaesarLastKing/FD-ClaudeGuard/releases/tag/v0.3.7)（Commit `c82c89c`）  
> **关联文档**：[docs/design-scoring-model-v2.md](./design-scoring-model-v2.md)（评分重构暂缓专题）、[docs/todo-v038-smart-update-scheduler.md](./todo-v038-smart-update-scheduler.md)（下一阶段智能更新自检方案）

---

## 一、逐项改动明细与 4 维验收矩阵（全项实证结案）

| 编号 | 功能 / Bug 项 | 改动文件 | 代码实现 | 单测 / 故障注入 | 浏览器双主题 1:1 | 真机桌面端实测 | 最终状态 |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **T2-1** | 第 1 项「高敏观察窗」未读到时间时标 `待核观察`（不再假绿 `已过观察`） | `src/pages/AccountAuditPage.tsx` | ✅ | ✅ | ✅ `final_step_12.png` | ✅ 已装 `v0.3.7` 实机运行 | **已验收通过** |
| **T2-2** | 云端 `personaKycStatus=expired/pending/required/failed` 联动更新子格与总状态 `实名已过期/待实名核验` | `src/pages/AccountAuditPage.tsx` | ✅ | ✅ | ✅ `step_20_shot_1.png` | ✅ 已装 `v0.3.7` 实机运行 | **已验收通过** |
| **T2-3** | `Free` 无订阅账号支付复审窗标 `Free 无订阅（不适用支付复审）` | `src/pages/AccountAuditPage.tsx` | ✅ | ✅ | ✅ 双主题复拍 | ✅ 已装 `v0.3.7` 实机运行 | **已验收通过** |
| **T3-1** | 多账号历史持久化（`account-audit-cache.json` v2）、清登录态不丢历史、修覆盖旧号与 `verifyCount` 串号 | `src-tauri/src/account_audit/mod.rs`、`src-tauri/src/lib.rs` | ✅ | ✅ 4 项（含 A2~A4 故障注入） | N/A | ✅ 真实缓存已升级 `version: 2`，含 `0ffb0302` 与 `a4722ea6` | **已验收通过** |
| **T3-2** | 左栏「历史归档 (N)」点击切换只读回溯、顶部只读横幅、禁用本机修复按钮、二次确认单条删除 | `src/pages/AccountAuditPage.tsx`、`src/styles/account-audit.css`、`src/lib/ipc.ts`、`src/types/guard.ts` | ✅ | ✅ | ✅ 终版复拍零重复 `96分` | ✅ `v0.3.7` 实机落盘双号 | **已验收通过** |
| **B1** | 左栏「实时异常日志流」未读角标与正文自相矛盾（2 未读不再写“日志平稳”） | `src/pages/AccountAuditPage.tsx` | ✅ | ✅ | ✅ | ✅ `v0.3.7` 实机运行 | **已验收通过** |
| **B2** | `cargo test` 单元测试污染宿主机真实 `guard-runtime-YYYYMMDD.jsonl` | `src-tauri/src/logger/mod.rs` | ✅ | ✅ 138 项全绿 | N/A | ✅ 跑完单测后真实日志 0 字节新增 | **已验收通过** |
| **B3** | 启动 1.5s 内重复触发 2 次自动更新检查 | `src-tauri/src/updater/mod.rs` | ✅ | ✅ `v037_b3_update_check_cache_ttl_dedup` | N/A | ✅ `02:52:32` 启动日志仅 1 条检查记录 | **已验收通过** |
| **B4** | NSIS 安装前自动静默卸载旧版 `currentUser` (`%LOCALAPPDATA%\FD Claude Guard`) 残留 | `src-tauri/nsis/hooks.nsh` | ✅ `SetShellVarContext current/all` + LogicLib | N/A | N/A | ✅ **实机铁证**：旧 `0.3.1` 目录与 HKCU 卸载项已 100% 清除，`Program Files` 已升级 `0.3.7` | **已验收通过** |
| **B5** | 左栏底部免责声明微裁切 + 多历史档案流式滚动 | `src/styles/account-audit.css` | ✅ | N/A | ✅ 终版双主题 3 行完整无裁切 | ✅ `v0.3.7` 实机运行 | **已验收通过** |
| **D3** | 100 分制评分权重体系重构（v2） | — | ⏸️ 已归档暂缓 | — | — | — | **已归档暂缓** |

---

## 二、真机线上热更新终验实证记录（2026-11-27 02:52）

- [x] **线上发版与更新通道验签**：`CI Checks #45972057459` 与 `Release Windows Installer #45972063280` 全部成功；`latest.json` 返回 `0.3.7`，Ed25519 Key ID `524DD4CBF003E3FD` 匹配，`FD.Claude.Guard_0.3.7_x64-setup.exe`（4,680,243 B）200 可达。
- [x] **B4-2 · 实机安装卸载旧版验证**：
  - `C:\Program Files\FD Claude Guard\fd-claude-guard.exe` → `FileVersion=0.3.7`（运行中 PID `63296`）；
  - `<USER_HOME>\AppData\Local\FD Claude Guard` → **已不存在（DIR_ABSENT）**；
  - `HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\FD Claude Guard` → **`False`**。
- [x] **D1 · 启动日志核查（`guard-runtime-20261127.jsonl`）**：
  - `02:50:12` 检出 `v0.3.7` → `02:52:11` 开始下载 → `02:52:14` Ed25519 验签通过 → `02:52:25` `v0.3.7` 正式启动；
  - `RECENT_ERROR_COUNT = 0`，19 项真实探针 `must=12/12 | opt=7/7` 全绿；
  - `02:52:32` 自动更新检查仅记录 **1 次**（验证 B3 生效）。
- [x] **D2 · 真实账户审计缓存验证**：`%LOCALAPPDATA%\FDClaudeGuard\account-audit-cache.json` 已无损升级 `version: 2`，`accountHistory` 含 `0ffb0302`，`knownAccounts` 含 `0ffb0302, a4722ea6`。

---

## 三、6 道硬门禁最终状态

- [x] **Gate 0**：写操作与可逆性评审通过
- [x] **Gate 1**：前端 16 文件 / 74 用例全绿 + Rust 138 用例 0 警告 + Clippy 0 警告
- [x] **Gate 2**：真机线上更新通道升级 `v0.3.5 → v0.3.7`、旧 `0.3.1` 彻底清除、0 ERROR、缓存 `v2` 全部实证通过
- [x] **Gate 3**：损坏 JSON / 30 条上限淘汰 / 无效 org / 更新去重故障注入全通过
- [x] **Gate 4**：终版 `1440×900` 深/浅双主题 1:1 复拍审图通过（0 报错）
- [x] **Gate 5**：线上签名 Release 与本地产物安全清单全项通过
