# v0.3.6 / v0.3.7 改动记录与逐项验收台账

> **维护原则（硬纪律）**：
> 1. 每一项功能与 Bug 必须明确列出**改动文件、改动明细、验收步骤与 4 维独立状态**（`代码实现` / `单测与故障注入` / `浏览器双主题 1:1` / `真机桌面端实测`）；
> 2. **未实测项严禁提前打 `[x]`**，真机未实际运行验证前一律标注 `待真机终验`；
> 3. 每次完成对应验证后，原地更新对应行状态并附上实测日志/截图/命令证据。
>
> **关联文档**：
> - 评分体系暂缓备忘：[docs/design-scoring-model-v2.md](./design-scoring-model-v2.md)（已按用户指示归档暂缓，本批次不改 `score.rs`）
> - 前序 Clash 加固台账：[docs/todo-v035-clash-rules-hardening.md](./todo-v035-clash-rules-hardening.md)
> - UI 设计规范真源：[docs/ui-design-system.md](./ui-design-system.md)
> - 总路线图：[docs/todo-master-roadmap.md](./todo-master-roadmap.md)

---

## 一、总览与当前真实进度（2026-11-27 02:04 实时更新）

- **已完成门禁**：**Gate 0 / Gate 1 / Gate 3 / Gate 4（终版复拍）/ Gate 5（`v0.3.7`）全部实证通过**。
- **唯一待闭环门禁**：**Gate 2（B4-2 / D1 / D2 真机桌面端安装与启动终验）**——因当前会话终端非管理员权限，需用户双击安装 `v0.3.7` 并打开一次「账户审计」页后，由代理直查本机目录、运行日志与 `account-audit-cache.json` 完成最终勾销。
- **正式待实装产物**：
  - 安装包：[FD Claude Guard_0.3.7_x64-setup.exe](../src-tauri/target/release/bundle/nsis/FD%20Claude%20Guard_0.3.7_x64-setup.exe)（`4,683,140` 字节 / `4.47 MiB`）
  - SHA-256：`DE5B9A1E2777267A6045A497146C367C6B6ED0F30072D47F06AF5FFABAC28852`
  - 校验：`FileVersion=0.3.7`、`requireAdministrator=True`、`EXE_SECRET_LEAK=False`、历史 `0.3.6` 包完好保留。
- **Git 提交状态**：`v0.3.5` ~ `v0.3.7` 尚未做 `git commit`，待真机终验通过后按用户确认的范围切干净提交。

---

## 二、逐项改动明细与 4 维验收矩阵

| 编号 | 功能 / Bug 项 | 改动文件 | 代码实现 | 单测 / 故障注入 | 浏览器双主题 1:1 | 真机桌面端实测 | 当前总状态 |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **T2-1** | 第 1 项「高敏观察窗」未读到时间时标 `待核观察`（不再假绿 `已过观察`） | `src/pages/AccountAuditPage.tsx` | ✅ 已完成 | ✅ `v036_history_and_window_fixes.test.tsx` | ✅ 已截 `final_step_12.png` 核验 | ⏳ 待装 `v0.3.7` 终验 | **待真机终验** |
| **T2-2** | 云端 `personaKycStatus=expired/pending/required/failed` 联动更新子格与总状态 `实名已过期/待实名核验` | `src/pages/AccountAuditPage.tsx` | ✅ 已完成 | ✅ `v036_history_and_window_fixes.test.tsx` | ✅ 已截终版 `step_20_shot_1.png` 核验 | ⏳ 待装 `v0.3.7` 终验 | **待真机终验** |
| **T2-3** | `Free` 无订阅账号支付复审窗标 `Free 无订阅（不适用支付复审）` | `src/pages/AccountAuditPage.tsx` | ✅ 已完成 | ✅ `v036_history_and_window_fixes.test.tsx` | ✅ 已截终版双主题核验 | ⏳ 待装 `v0.3.7` 终验 | **待真机终验** |
| **T3-1** | 多账号历史持久化（`account-audit-cache.json` v2）、清登录态不丢历史、修复覆盖旧号与 `verifyCount` 跨号累加 | `src-tauri/src/account_audit/mod.rs`、`src-tauri/src/lib.rs` | ✅ 已完成 | ✅ 4 项单测全绿（含 A2 损坏 JSON / A3 30 条上限淘汰 / A4 空/缺 org 安全） | N/A | ⚠️ 真实缓存副本闭环已过；⏳ 待装 `v0.3.7` 真机写入终验 | **待真机终验** |
| **T3-2** | 前端左栏「历史归档 (N)」点击切换只读回溯、顶部只读横幅、禁用本机修复按钮、带二次确认单条删除 | `src/pages/AccountAuditPage.tsx`、`src/styles/account-audit.css`、`src/lib/ipc.ts`、`src/types/guard.ts` | ✅ 已完成 | ✅ `v036_history_and_window_fixes.test.tsx` | ✅ **终版双主题复拍通过**（`step_20_shot_1.png` / `step_22_shot_1.png`，无重复 `96分`，0 报错） | ⏳ 待装 `v0.3.7` 实机切换 `a4722ea6`/`0ffb0302` 终验 | **待真机终验** |
| **B1** | 左栏「实时异常日志流」未读角标与正文自相矛盾（2 未读不再写“日志平稳”） | `src/pages/AccountAuditPage.tsx` | ✅ 已完成 | ✅ `v036_history_and_window_fixes.test.tsx` | ✅ 单元+界面链路通过 | ⏳ 待装 `v0.3.7` 实机核验 | **待真机终验** |
| **B2** | `cargo test` 单元测试污染宿主机真实 `guard-runtime-YYYYMMDD.jsonl` | `src-tauri/src/logger/mod.rs` | ✅ 已完成 | ✅ 138 项 Rust 单测全绿 | N/A | ✅ **已实证**：跑完单测后真实日志 0 字节新增 | **已验收通过** |
| **B3** | 启动 1.5s 内重复触发 2 次自动更新检查 | `src-tauri/src/updater/mod.rs` | ✅ 已完成 | ✅ `v037_b3_update_check_cache_ttl_dedup` 通过 | N/A | ⏳ 待装 `v0.3.7` 启动后查真实日志仅 1 条检查记录 | **待真机终验** |
| **B4** | NSIS 安装前自动静默卸载旧版 `currentUser` (`%LOCALAPPDATA%\FD Claude Guard`) 残留 | `src-tauri/nsis/hooks.nsh` | ✅ **已加固修复**（显式 `SetShellVarContext current/all` + `${If} ${FileExists}`，NSIS 0 警告编译通过） | N/A | N/A | ⏳ 待双击安装 `v0.3.7` 实证旧 `0.3.1` 目录与 HKCU 卸载项彻底清除 | **待真机实装终验** |
| **B5** | 左栏底部免责声明微裁切 + 多历史档案流式滚动 | `src/styles/account-audit.css` | ✅ 已完成 | N/A | ✅ 终版双主题 1:1 复拍确认 3 行完整无裁切 | ⏳ 待装 `v0.3.7` 终验 | **待真机终验** |
| **D3** | 100 分制评分权重体系重构（v2） | — | ⏸️ 已按用户要求暂缓 | — | — | — | **已归档暂缓** |

---

## 三、详细功能验收测试用例清单（逐项勾销实证）

### 用例组 A：缓存持久化与 Gate 3 破坏性故障注入（已全数通过）
- [x] **A1 · 正常多号闭环**：`v036_multi_account_history_persists_across_switch_clean_and_supports_delete` 通过（老号保留、清登录态不丢、新号 `verifyCount=1` 不串累加、单条删除仅删目标号）。
- [x] **A2 · 损坏 / 截断 JSON 冷启动**：`v037_gate3_corrupted_json_graceful_recovery` 通过（截断 JSON 读取/删除不崩溃，写入新报告自动恢复合法 JSON）。
- [x] **A3 · 超 30 条上限淘汰**：`v037_gate3_history_evicts_oldest_beyond_max_30` 通过（连续写 35 个 org，完整历史快照严格上限 30 条，淘汰最久未更新的 5 条、保留最新 30 条）。
- [x] **A4 · 空/不存在 org 查询与删除**：`v037_gate3_empty_and_missing_org_queries_and_deletes_are_safe` 通过（空串/空白/不存在 org 安全返回 `None`/`Ok(false)`，不破坏既有档案）。
- [x] **A5 · 更新检查单飞缓存去重（B3）**：`v037_b3_update_check_cache_ttl_dedup` 通过（1.5s/24s 窗口内复用缓存，>=25s 重新拉取）。

### 用例组 B：NSIS 安装前清理旧版（B4）
- [x] **B4-1 · 修复 `hooks.nsh`**：已显式切换 `SetShellVarContext current` → `${If} ${FileExists}` 静默卸载与清理 → 恢复 `SetShellVarContext all`，`v0.3.7` NSIS 0 警告编译通过。
- [ ] **B4-2 · 实机安装验证**：待用户双击安装 `FD Claude Guard_0.3.7_x64-setup.exe` 后实查 `C:\Users\xujun\AppData\Local\FD Claude Guard` 与 HKCU 旧卸载项已 100% 清除，`C:\Program Files\FD Claude Guard\fd-claude-guard.exe` 为 `0.3.7`。

### 用例组 C：浏览器双主题 1:1 终版复拍（Gate 4，已通过）
- [x] **C1 · 暗色 + 浅色终版复拍**：强制重载后 `1440×900` 复拍 `step_20_shot_1.png`（暗色）与 `step_22_shot_1.png`（浅色），1:1 肉眼审图确认 `jaso***11@gmail.com` 显示 `归属 US · a4722ea6` + 单个 `96分`（零重复）、免责声明 3 行无裁切、`star***at@outlook.com` 展开第 1 项显示 `实名已过期` 与 `Free 无订阅`，`console.error = 0`、`pageerror = 0`。

### 用例组 D：真机桌面端启动终验（Gate 2，待用户安装后核销）
- [ ] **D1 · 启动日志核查**：用户安装并启动 `v0.3.7` 后，核查最新 `guard-runtime-*.jsonl`：① 版本号为 `v0.3.7`；② `ERROR = 0`；③ 自动更新检查日志仅 1 次（实证 B3）。
- [ ] **D2 · 真实账户审计页实测**：用户打开一次「账户审计」页后，核查本机 `%LOCALAPPDATA%\FDClaudeGuard\account-audit-cache.json` 已无损升级 `version: 2`，同时保存现号 `0ffb0302` 与老号 `a4722ea6` 可供左栏切换与删除。

---

## 四、6 道硬门禁总状态（实时更新）

- [x] **Gate 0**：写操作与可逆性评审通过
- [x] **Gate 1**：前端 `tsc` 0 错 + `vitest` **16 文件 / 74 用例全绿** + `vite build` 0 错；Rust `cargo test --lib` **0 警告 / 138 passed / 0 failed**
- [ ] **Gate 2**：真机桌面端实装启动与双向闭环终验（**待完成 B4-2 / D1 / D2 后打勾**）
- [x] **Gate 3**：破坏性故障注入矩阵（损坏 JSON / 30 条上限淘汰 / 无效 org / 更新去重）全部补齐并通过
- [x] **Gate 4**：最终代码 `1440×900` 深/浅双主题 1:1 复拍审图通过（0 报错）
- [x] **Gate 5**：`v0.3.7` Release 0 警告编译打包与安全核验通过（`FileVersion=0.3.7`、`requireAdministrator=True`、`EXE_SECRET_LEAK=False`、旧 `0.3.6` 完好保留）
