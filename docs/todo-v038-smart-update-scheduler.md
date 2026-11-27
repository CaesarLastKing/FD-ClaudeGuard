# 智能更新自检、顶栏去双悬浮与日志精简改动台账（已落盘待随整体 UI 改版统一发版）

> **更新时间**：2026-11-27 03:38  
> **当前状态**：本批次后端与前端核心改动已全部落地，Rust 139 项单测 + Clippy 0 警告全绿，本批次关联 6 组前端回归单测全绿；检测到工作区已有另一并行 UI 改版会话正在推进 `SettingsModal` / `AiToolsPage` / `SupportModal`，已做好 `openSettingsModal("update")` 无缝兼容对接，待整体 UI 改版合入后统一执行最终双主题 1:1 审图与发版打包。

---

## 一、改动明细与验收状态矩阵

| 编号 | 事项 | 改动文件 | 代码实现 | 单测 / 故障注入 | 说明 |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **U1** | 持久化更新状态 `%LOCALAPPDATA%\FDClaudeGuard\update-state.json` + 4 小时节流 + 损坏 JSON / 升级自动失效 / 时钟回拨保护 | `src-tauri/src/updater/mod.rs` | ✅ | ✅ `v038_persisted_update_state_throttles_4h_handles_upgrade_clock_rollback_and_corrupt_json` | 仅在线上检查成功时刷新 `lastCheckedAtMs`，断网/超时失败绝不触发 4h 误冷却 |
| **U2** | 智能更新 5 类触发时机：启动 0s 零网络秒读本地缓存 + 启动 3 分钟首检 + 每 4 小时后台周期 + 休眠唤醒/复网延迟 60s 补检（均受 4h 节流）+ 手动点击强制穿透 | `src-tauri/src/updater/mod.rs`、`src-tauri/src/lib.rs`、`src/App.tsx`、`src/pages/SettingsPage.tsx`、`src/lib/ipc.ts`、`src/stores/guardStore.ts` | ✅ | ✅ Rust 139 项（含线程隔离审计 `get_cached_app_update` 异步 `spawn_blocking`）+ 前端 `v038_smart_update_and_chrome.test.tsx` | 彻底消灭启动 3.5s 抢跑被迫走直连 `via_proxy=false` 以及每次打开配置页重复刷接口问题 |
| **U3** | 彻底取消后台静默更新检查的右下角 Toast 弹窗 | `src/stores/guardStore.ts` | ✅ | ✅ `v038_smart_update_and_chrome.test.tsx`（断言 `toasts.length === 0`） | 仅手动点「检查更新」时做正常操作反馈；静默发现新版只在顶栏与设置更新区亮标 |
| **U4** | 顶栏更新微标改版为极简 **`✨ 新版本发布！！`**（移除 `NEW` 色块与冗长版本号，无原生 `title` 防双气泡，点击无缝对接 `openSettingsModal("update")`） | `src/components/WindowChrome.tsx` | ✅ | ✅ `v029_fixes.test.tsx`、`v038_smart_update_and_chrome.test.tsx` | 鼠标悬停 0ms 浮现自定义气泡展示新版本号与提示 |
| **U5** | 修复 `Fuck Dario！！！` 悬浮双效果（移除原生 `title` 悬浮，仅保留自定义气泡弹窗） | `src/components/WindowChrome.tsx` | ✅ | ✅ `v029_fixes.test.tsx`、`v038_smart_update_and_chrome.test.tsx`（断言无 `title` 属性） | 彻底消除原生白灰框与自定义深色弹窗重叠 |
| **U6** | 精简配置修改日志（`format_config_patch_compact`） | `src-tauri/src/lib.rs` | ✅ | ✅ Rust 编译与单测 0 警告 | 仅输出实际变更字段（如 `theme=light`），告别 19 个 `None` 字段刷屏 |

---

## 二、测试与门禁记录

- **Rust 后端**：`cargo test --lib` **139 passed / 0 failed**（含 `tauri_commands_thread_isolation_audit` 线程隔离门禁通过）；`cargo clippy --lib` **0 警告 0 错误**。
- **前端回归（本批次相关）**：`npx tsc --noEmit` 0 错；`v038_smart_update_and_chrome.test.tsx`、`v027`、`v029`、`v032`、`v035`、`v036` 全部通过。
- **并发工作区提醒**：当前工作区另有并行 UI 改版正在调整 `SupportModal.tsx`（改 X/Twitter 联系方式）与 `Sidebar` / `SettingsModal`（`m3_m4.test.tsx`、`v17_v18_v19.test.tsx` 等旧测试需随整体 UI 改版一并更新），本轮未干涉其文件，待 UI 改版收口后再统一跑全量浏览器双主题 1:1 审图、真机验收与发版。
