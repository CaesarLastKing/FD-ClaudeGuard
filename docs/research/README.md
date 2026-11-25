# FDtools 账户风控与多账户架构调研总览索引

本目录按职责边界将本轮调研、真机实证、架构规划与原型成果拆分为 **4 大独立专题文档**，既支持先落地单账户优化，又确保后续演进多账户时零返工。

---

## 专题文档目录

| 编号 | 文档链接 | 核心主题 | 对应落地阶段 |
| :-: | :--- | :--- | :---: |
| **01** | [01-local-config-audit-and-403-disambiguation.md](./01-local-config-audit-and-403-disambiguation.md) | **本地非侵入配置识别、403 精准消歧与 14 项行为风控**<br>解决单用户当下最痛点：能从本机读出哪些数据、哪些 403 无害、如何综合判风险 | **Phase 1（立即可做）** |
| **02** | [02-single-and-multi-account-roadmap.md](./02-single-and-multi-account-roadmap.md) | **单账户与多账户产品演进、客群分层与 5 层风险隔离架构**<br>同一套代码渐进式披露、3 类客户体验分层、Mihomo 多端口编排、充值门禁与 UI 重构蓝图 | **Phase 1 → Phase 2** |
| **03** | [03-claude-web-session-probe-findings.md](./03-claude-web-session-probe-findings.md) | **Claude 网页端 `sessionKey` 探测原理与真机实证沉淀**<br>竞品逆向拆解、多组织选主、`kyc_status`、`geo` vs `cf-ray` 错配、`account_banned` 实锤样本 | **协议真源参考** |
| **04** | [04-github-ecosystem-and-agent-benchmark.md](./04-github-ecosystem-and-agent-benchmark.md) | **GitHub 开源监控/安全审计项目与 2026 Agent 多模型方案对标**<br>`ccusage` / `Usage-Monitor` / `claude-security-audit` / `T3 Code` / `Zed ACP` 与 `Magpie` 雷区 | **外部生态参考** |

---

## 配套实证代码与高保真效果图

- **本地只读实测脚本（零网络、零解密）**：[local-audit-probe.mjs](../../session-analyzer-mvp/scripts/local-audit-probe.mjs)
- **独立 7 维网页探测 MVP**：[session-analyzer-mvp](../../session-analyzer-mvp/README.md)
- **重构效果图（待定稿）**：
  - 合并版「账号与审计」：[account-audit-merged-preview.html](../mockups/account-audit-merged-preview.html)
  - 清爽重构版「环境维护」：[maintenance-refactored-preview.html](../mockups/maintenance-refactored-preview.html)

---

## 关键架构结论：文档 01 与文档 02 分期做是否有“无用功”？

**结论：零无用功，01 是 02 的底层发动机，02 对 01 是 100% 复用。**

- **防返工唯一纪律**：开发文档 01（单账户本地审计与 403 消歧）时，所有 Rust 扫描/判定函数**不要硬编码 `~/.claude` 或 `%LOCALAPPDATA%\Claude`**，统一接收一个轻量参数 `ProfileContext { profile_id, cli_config_dir, claude_json_path, desktop_data_dir, bound_proxy_port, expected_geo }`。
- **阶段 1（单号）**：传入 1 个默认的 `ProfileContext("default", ...)`，立即上线 403 智能降噪、离线用量与风险综合评估；
- **阶段 2（多号）**：只需外层加一套 `ProfileManager` + Mihomo 多端口编排，循环调用阶段 1 的同一套审计函数，**零重写、零浪费**。
