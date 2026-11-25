# FD Claude Guard 待办清单与演进路线图（v0.2.9 稳定修复 + 开源广告位转型 + 文档 01 落地）

> **维护说明**：本文档作为当前阶段与下一阶段的唯一待办跟踪清单，开发、测试与验收过程中原地更新状态。  
> **远端仓库**：`https://github.com/CaesarLastKing/FD-ClaudeGuard.git`（主分支 `main`）  
> **关联调研总览**：[docs/research/README.md](./research/README.md) · [文档 01：本地配置识别与 403 精准消歧](./research/01-local-config-audit-and-403-disambiguation.md)

---

## 阶段一：修复当前 3 项真机问题并推送首个公开仓库版本（当前立即执行）

| 编号 | 优先级 | 任务项 | 根因与改写边界 | 状态 | 验证摘要 |
| :--- | :---: | :--- | :--- | :---: | :--- |
| `T-053` | P0 | **修复 Clash Mihomo `ipv6: false` 未持久化导致重启/开 TUN 服务后 `node_group` 反复变红** | **改**：`preflight/mod.rs` 同步持久化写 `config.yaml` / `clash-verge.yaml` 顶层 `ipv6: false`（不碰缩进的 `dns.ipv6`），`rollback/mod.rs` 补齐 `original_config_ipv6` First-Write-Wins 基线捕获与精准撤回还原，并补充规则模式隔离提示文案；**不动**：不强杀 Clash、不干扰其他应用分流 | `已完成` | 单测 `t053_*` + 真机双向撤回/重注入闭环通过；实测 `config.yaml` 顶层 `ipv6: false` 落盘且 `system-baseline.json` 记录 `originalConfigIpv6: true` |
| `T-054` | P1 | **修复守卫配置页「Clash Verge Rev 未开启开机自启」徽章误显「已开启（有风险）」** | **改**：`SettingsPage.tsx` 按 `entry.enabled` + `entry.riskLevel` 组合渲染（`enabled && warn` → `已开启（有风险）`，`!enabled && warn` → `未开启（建议开启）`）；**不动**：后端只读扫描边界 | `已完成` | `tsc --noEmit` + Vitest 41/41（含 `v029_fixes.test.tsx`）通过 |
| `T-055` | P0 | **修复日志分析页全部已读后左侧角标永久卡 `1` 消不掉** | **改**：`watchdog/mod.rs` 逐行扫描时维护上一行有效时间戳 `last_seen_ts`，无行首时间戳的多行堆栈子行继承前文时间戳（无前文时用固定占位），严禁用 `Local::now()` 参与 `stable_log_event_id` 哈希；**不动**：原始 Claude 日志只读不篡改 | `已完成` | 单测 `t055_*` + 真机 `live_v027_real_machine_log_audit` 实测 `main.log:3243` 已自动折叠入 `3069~3419 (共 10 次)`，ID 恒定不再漂移 |
| `T-056` | P0 | **全量质检、开源前敏感信息审计并推送 `main` 至远端仓库** | **做**：补齐 `T-053/054/055` 回归单测、全量 Rust + Vitest + TypeScript 0 警告验证、真机双向闭环实测、严格审计 `.gitignore` 与全仓零私密文件/密钥/真实订阅 URL 泄露，执行 `git init` / `remote add` / `push -u origin main` | `已完成` | Rust 70/70（0 警告）+ Vitest 41/41 + 7890 端口实机探针 11/11 全绿；历史文档与测试样本隐私全面脱敏后推送 `main` |

---

## 阶段二：基于开源最新版本启动定位转型与文档 01 规划（推送完成后展开讨论与实施）

> 遵循「先对齐方案与效果图，再编码落地」原则，阶段一推送完成后立即进入本阶段的需求拆解与设计确认。

| 编号 | 优先级 | 任务项 | 规划范围与关键约束 | 状态 | 备注 |
| :--- | :---: | :--- | :--- | :---: | :--- |
| `T-057` | P0 | **产品定位转型：免费开源 + 广告位（全面移除买断制与激活锁）** | 1. 全面剥离商业激活锁（`licensing` 付费墙、`FeatureLockedGate`、`LicenseModal`、侧边栏锁图标、未激活脱敏截断与 `require_licensed()` 门禁，全部核心功能免费开放）；<br>2. 清理/下线不再需要的买断制核销逻辑与商业特性开关；<br>3. 设计**非侵入、可配置的赞助/广告位体系**（明确展示位置、加载降级策略、零追踪隐私承诺、本地配置开关与开源协议 `LICENSE` 补齐） | `待规划` | 阶段一推送后优先讨论方案与视觉位 |
| `T-058` | P0 | **落地文档 01：单用户本地非侵入配置识别 + 403 精准消歧 + 综合风险评估** | 基于 [01-local-config-audit-and-403-disambiguation.md](./research/01-local-config-audit-and-403-disambiguation.md)：<br>1. 统一抽象 `ProfileContext`（严禁硬编码 `~/.claude` / `%LOCALAPPDATA%\Claude`，为后续多账户 100% 复用留好底座）；<br>2. 本地只读识别配置、账号状态、离线用量与关键元数据（零解密、零侵入）；<br>3. 403 精准消歧（区分无害/权限不足/KYC/风控/封禁）+ 14 项行为风控综合评估；<br>4. 结合现有 UI 规范做克制增量改造（先确认单图方案再落地） | `待规划` | 紧随 `T-057` 同步统筹规划 |
