# 已归档的 UI v2.0 旧页面组件

- **归档日期**：2026-11-27
- **归档原因**：UI v3.0 升级后，系统配置与环境维护入口已统一重构收敛至居中双栏模态弹窗 `src/components/SettingsModal.tsx`（含「常规开关」「安全策略」「清理恢复」「版本更新」四个标签页，以及复用的 `src/components/NetworkRescueRollbackPanel.tsx`），原全屏旧页面在生产代码中已无任何路由挂载与引用。
- **归档文件清单**：
  - `MaintenancePage.tsx`（原 `src/pages/MaintenancePage.tsx`，原「环境维护」页）
  - `SettingsPage.tsx`（原 `src/pages/SettingsPage.tsx`，原「守卫配置」页）
- **现役保留说明**：
  - 原 `src/pages/LogAnalysisPage.tsx` 仍作为「完整取证日志台」嵌入在 `src/pages/AccountAuditPage.tsx` 中实际使用，**不在归档范围内，继续保留于 `src/pages/`**。
- **测试迁移说明**：
  - 原先直接渲染旧页面的 8 个测试文件已全部无损迁移至现役 `SettingsModal` 与 `NetworkRescueRollbackPanel`，原逻辑覆盖不丢失。
  - 本归档目录位于 `tsconfig.json` `include: ["src"]` 之外，仅作历史对照留存，禁止在 `src/` 下重新 `import`。
