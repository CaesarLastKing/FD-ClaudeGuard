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
| `T-057` | P0 | **产品定位转型：免费开源 + 广告位（全面移除买断制与激活锁）** | 1. 全面剥离商业激活锁（`licensing` 付费墙、`FeatureLockedGate`、`LicenseModal`、侧边栏锁图标、未激活脱敏截断与 `require_licensed()` 门禁，全部核心功能免费开放）；<br>2. 清理买断制依赖与卸载金库提示，固化 SemVer 三处版本号同步门禁与 `CHANGELOG.md`；<br>3. 广告位暂待定，待后续核心功能完善后再出单图效果图确认 | `去锁已完成（广告位待定）` | Rust 67/67（0 警告）+ `tsc` + Vitest 39/39 全过，版本号升至 `0.2.9` |
| `T-058` | P0 | **落地「账户审计」双层融合方案（本地非侵入只读 + 按需 `sessionKey` 深度核验 + 100 分纯函数评分 + 控制台同源联动 + 外部 `sk+代理` 只读脱敏 API 契约预留）** | 1. 左侧主导航顺序升级为 `控制台 → 账户审计 → 节点流量 → 环境维护 → 守卫配置`，原「日志分析」并入作为第 2 分段「实时异常日志流」；<br>2. 严格 1:1 对齐 `v12` 定稿原型（精简左侧档案卡、顶部纯本体 4 格绿点白字、上下两大段 7 项单开互斥、白皮书级去套娃「防封宝典」与折叠 100 分权重表、3 级温和语气与 0 设计术语）；<br>3. 后端落地 6 条 `ProfileContext` 契约、3 层零风控额度提精、`orgId` 防串号校验、控制台 `claude_acct`/`claude_tel`/`node_geo` 同源修复 + 新增 `claude_endpoint`、环境维护补齐可选 CLI 清理、预留 `POST /v1/audit/check-sk`（`sk+代理`）只读脱敏 API 契约 | `已完成` | M1~M3 全部实证通过：Rust 全量单测（含 403 消歧 / 100 分评分 / `ProfileContext` / 云端探针 / 外部 `check-sk`）0 警告；M2 真机双向闭环实测通过（2/4 → 4/4 → 100% 精准撤回）；前端 Vitest + 零设计术语扫描全绿；`1440×900` 深/浅双主题真实渲染审图 0 error / 0 瑕疵 |
| `T-059` | P1 | **客户端自动检查新版本与一键更新（方案 A：`tauri-plugin-updater` + GitHub Releases）** | 接入 Tauri v2 官方签名热更新 + GitHub Actions 自动打包发布 `latest.json`，配套 `CHANGELOG.md` 与 GitHub Releases 历史/最新版本自动汇总 | `已完成` | 已接入 `tauri-plugin-updater` + Ed25519 公钥（Key ID `524DD4CBF003E3FD`）+ 动态代理优先/直连回退更新检测 IPC + 守卫配置更新卡片 + `.github/workflows/release.yml` 自动签名发布流水线；Rust + 前端全量单测 0 警告通过，三处版本号同步至 `0.3.0` |
