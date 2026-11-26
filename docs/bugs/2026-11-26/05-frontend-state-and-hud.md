# 05 · 前端状态机、HUD 悬浮窗与交互边界（2026-11-26）

> **模块范围**：`src/App.tsx`、`src/stores/guardStore.ts`、`src/pages/*.tsx`、`src/components/*.tsx`

| 编号 | 级别 | 标题 | 代码位置 | 根因与后果 | 状态 | 修复与验证摘要 |
| :---: | :---: | :--- | :--- | :--- | :---: | :--- |
| `BUG-P0-15` | **P0** | 前端 2 处永久卡死：① 深度核验竞态永久锁死「安全启动 Claude」；② 账户审计扫描失败永久无限转圈白屏 | `guardStore.ts`<br>`AccountAuditPage.tsx` | 1) 迟到的 `invoke` 返回值把 `deepAudit.running` 覆写回 `true` 永久锁死主按钮；2) 本地审计异常静默吞错且 `!report` 永久加载白屏 | `已完成` | 引入 `deepAuditEventSeq` 终态防迟到 `invoke` 覆写；新增 `accountAuditError` 并在 `!report` 时展示错误重试卡片与日志入口（`v034_bugfixes.test.tsx` 通过） |
| `BUG-P1-19` | **P1** | HUD 点击「节点不可用 · 前往换节点」及动态告警行被强行劫持跳回控制台；点日志漏切子页 | `HudCard.tsx`<br>`App.tsx`<br>`guardStore.ts` | 非 console 目标仍传 `focusItemId="__first_fail__"` 触发强切回控制台；`logOnlyFocus` 漏传 `subTab="logs"` | `已完成` | 仅当 `targetTab === "console"` 时透传 `focusItemId`，日志提醒直达 `audit` + `subTab: "logs"` |
| `BUG-P1-20` | **P1** | 实时流量「全部标为已处理」只写前端内存，侧边栏与 HUD 报警红/黄灯永不消退且重启复活 | `NodesTrafficPage.tsx`<br>`guardStore.ts`<br>`src-tauri/src/lib.rs` | 弹绿 Toast 宣称清零角标，但既不调后端也不改 `snapshot`，侧边栏与 HUD 纹丝不动 | `已完成` | 新增后端命令 `ack_flow_anomalies` 与 `AppState.acked_flow_ids`，实时排除已确认连接并广播刷新 `GuardSnapshot`（`v034_bugfixes.test.tsx` 通过） |
| `BUG-P1-21` | **P1** | 控制台主 CTA 优先级倒置：熔断态伴随 ≥2 项体检失败时，「解除熔断保护」被遮盖 | `ConsolePage.tsx` | 自动熔断必连带多项失败，主操作位被「一键处理全部」覆盖，用户无法在主按钮直接解熔断 | `已完成` | 将 `snapshot.killSwitchActive` 提至 `mustFail >= 2` 之前，熔断期间主按钮稳定优先展示「解除熔断保护」（`v034_bugfixes.test.tsx` 通过） |
| `BUG-P1-22` | **P1** | `guardStore` 多处异步请求缺代际序号与防重入锁，慢响应覆盖新状态（快速拨开关弹回） | `guardStore.ts` | 刚修好/核验变绿被在途旧响应刷回红灯；快速连拨开机自启与相邻开关时后拨开关自动弹回 | `已完成` | 为 `accountAudit` / `config` / `preflight` / `nodes` 补齐递增代际序号与 `fixing` 防重入锁，慢响应不再覆写新状态（`v034_bugfixes.test.tsx` 通过） |
| `BUG-P1-23` | **P1** | 环境维护手动触发熔断缺 `catch` 吞错；节点页刷新失败仍弹绿假成功；非审计页清理后侧边栏角标滞留 | `MaintenancePage.tsx`<br>`NodesTrafficPage.tsx`<br>`CleanConfirmModal.tsx` | 触发熔断失败无反馈；离线刷新同时弹红失败+绿成功；其他页清理后账户审计红标滞留 | `已完成` | 熔断调用补 `catch` 报错；`refreshNodes` 返回布尔值消除红绿双 Toast；清理完成后统一静默刷新账户审计清角标 |
| `BUG-P2-06` | **P2** | 侧边栏 `interceptFlash` cleanup 陷阱样式卡死；控制台倒计时休眠漂移；账户审计按钮硬编码 `45s` 且 `useMemo` 漏依赖 | `Sidebar.tsx`<br>`ConsolePage.tsx`<br>`AccountAuditPage.tsx` | 1.5s 内解盯防闪烁常驻；休眠后倒计时严重滞后；改 30s/60s 后审计页仍显 45s | `已完成` | 侧边栏改用 `flashTimerRef`；倒计时改按 `nextFullAuditEpochMs - Date.now()` 实时计算；审计页动态读取 `config.killHoldSeconds` 并补全依赖 |
| `BUG-P2-07` | **P2** | 撤回中心失败空白 + 一键撤回弹窗并排两个「取消」按钮；HUD 贴边高度去重跳过 & 顶栏按钮漏 `catch`；日志已读假成功 | `NetworkRescueRollbackPanel.tsx`<br>`HudCard.tsx`<br>`LogAnalysisPage.tsx`<br>`guardStore.ts` | 读取失败空白误显 0 项、弹窗双「取消」；贴边展开偶发裁剪；日志已读失败不回滚 | `已完成` | 撤回中心补 `loadError` 错误卡片与重试并改左按钮为「暂不撤回」；HUD 贴边清缓存尺寸、顶栏按钮补异常回滚；日志已读改为校验返回 `true` 后才弹绿并失败回滚（`v034_bugfixes.test.tsx` 通过） |
