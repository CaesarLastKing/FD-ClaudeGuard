# 04 · GitHub 开源生态、长尾安全审计项目与 2026 AI Agent 多模型方案对标

> **用途**：沉淀所有外部开源生态调研成果，明确 **“哪些设计精华值得 `FDtools` 吸收”**、**“哪些多模型 Agent 组合最安全好用”**，以及 **“哪些高危雷区必须严防”**。

---

## 一、GitHub 成熟 Claude 监控与离线分析项目（推荐借鉴）

| 项目 | 技术栈 | 最值得 `FDtools` 借鉴的精华机制 |
| :--- | :--- | :--- |
| **[ryoppippi/ccusage](https://github.com/ryoppippi/ccusage)** | **Rust 核心** + TS | 纯离线扫描 `~/.claude/projects/**/*.jsonl`，零网络还原 5 小时滚动块消耗与 Subagent/Sidechain 并发倍数（与 `src-tauri` 100% 同构）。 |
| **[Maciek-roboblog/Claude-Code-Usage-Monitor](https://github.com/Maciek-roboblog/Claude-Code-Usage-Monitor)** | Python | ① **数据溯源标签**（`official` / `local_estimate` / `unknown`）；② Statusline 零额外探测捕获官方限流；③ 本地长期 Usage Warehouse 突破官方 30 天滚动清理限制。 |
| **[CodeZeno/Claude-Code-Usage-Monitor](https://github.com/CodeZeno/Claude-Code-Usage-Monitor)** | **Rust** | 低频被动轮询对齐（15 分钟）、读取本地 `~/.claude/.credentials.json` 非敏感状态、极简 5h/7d 双进度条呈现。 |
| **[LyndonWangWork/Claude-Code-Usage-Tracker](https://github.com/LyndonWangWork/Claude-Code-Usage-Tracker)** | **Tauri + React + Rust** | 与 `FDtools` 完全同构的桌面端 IPC 聚合与趋势可视化结构参考。 |
| **[cn0xroot/CC-Monitor](https://github.com/cn0xroot/CC-Monitor)** | Python + SQLite | 借鉴其**本地 SQLite 统一审计账本**思路与 `~/.claude.json` 画像读取（不照搬其命令拦截与 Linux eBPF）。 |

---

## 二、GitHub 小众 / 长尾「账户与配置安全审计」项目挖掘

| 项目 / 思路 | 核心安全洞察 | 对 `FDtools` 的补位价值 |
| :--- | :--- | :--- |
| **Manifest V3 浏览器伴侣扩展思路** | 在已登录 `claude.ai` 标签页内直接用 `fetch(..., { credentials: "include" })` 查状态，不抠 `sessionKey` | 彻底消除剪贴板泄密与 CF 弹盾，可作为未来免手动粘贴 key 的透明伴侣通道。 |
| **`tdccccc/claude-security-audit` & `claudit-sec`** | 扫描 `.claude/settings*.json` 权限白名单明文凭据泄漏（Secret Sprawl）、高危通配符与恶意 Hook/MCP 注入 | 低成本增强「Claude 本机卫生」配置审计项。 |
| **`ashishmerani/claude-code-security-harness`** | 防止本地安全配置 / Hook 被外部更新器静默篡改 | 借鉴**配置哈希完整性校验**，守护 `FDtools` 降噪配置与 Clash 覆写规则。 |
| **`danielhagever/agent-guardrails-kit`** | Fail-Closed（默认拒绝）的 `PreToolUse` 护栏与 JSON 审计日志 | 进阶本地护栏参考，与防裸奔/熔断设计同源。 |
| **[anthropics/axt-verify](https://github.com/anthropics/axt-verify) & Compliance API 生态** | 官方 Go 工具基于 C2SP `tlog` 密码学校验企业审计日志 | 面向未来 Team / Enterprise 团队版的正统合规审计通道。 |

---

## 三、GitHub 多账户切换项目流派对比

1. **❌ 凭据原地覆盖型（`realiti4/claude-swap`、`edglz/ccswitch`、`uwuclxdy/clauth`）**：
   - 原地替换 `~/.claude` 凭据甚至限流秒切接力——极易触发跨 `orgId` 404 竞态与同 IP 多号套利连坐，**绝不借鉴**。
2. **✅ 目录沙箱隔离型（`diranged/claude-profile`、`jakubkontra/claude-profile-manager`、`jmdarre-v/claude-multiprofile`、`jspanji/Swivel`）**：
   - 基于官方 `CLAUDE_CONFIG_DIR` 与 Electron `--user-data-dir` 实现文件隔离；但**普遍缺失网络端口绑定、Kill-Hold 进程清零、归属地校验与封号隔离锁**，这正是 `FDtools` 5 层隔离的独家护城河。

---

## 四、2026 主流 AI Coding Agent 排行与安全多模型方案评估

| 方案路线 | 代表工具 | 安全多模型接入原理 | 防封结论与推荐度 |
| :--- | :--- | :--- | :--- |
| **路线 1：官方 CLI / ACP 编排外壳（BYOS）** | **`T3 Code` (`pingdotgg/t3code`)**、**`Zed` (ACP)**、`Conductor` | 用户走官方命令登录本机原生 CLI，上层 GUI 通过标准 CLI 管道或开放 ACP 协议驱动多个原生 Agent（支持 Claude Code / Codex / Cursor / OpenCode / Antigravity / Grok 等），绝不劫持 OAuth。 | **🔥 最佳推荐**：`T3 Code` 开源免费（MIT）、带后台浏览器预览、Git Worktree 隔离、行内 Diff 与一键 PR，搭配 **`FDtools` 底层防封**是目前最稳又最好用的组合。 |
| **路线 2：商业厂商统一采购多模型** | **Cursor**、**Windsurf**、**GitHub Copilot** | 厂商企业级采购 API，用户付统一月费在 IDE 内切换多模型。 | **✅ 极安全、最省心**，但需单独付月费，无法直接复用现有 Claude 订阅。 |
| **路线 3：纯 BYOK 按量付费 API Key** | **OpenCode**、**Cline / Roo Code** | 填入官方 Console 按量 API Key（`sk-ant-api03-...`）。 | **✅ 100% 合规**，重度写代码成本较高。 |
| **❌ 雷区路线 4：伪造 OAuth / 劫持本地网关** | 早期部分 OpenCode OAuth 劫持插件、把消费级 OAuth 放进 **`yetone/magpie`** 做多号池转发 | 抠出 Pro/Max `claude_code_oauth_token` 改写 `ANTHROPIC_BASE_URL` 指向本地网关转发或做多号 Failover。 | **🚨 高危封号（主力号禁碰）**：Magpie 仅适合接官方按量 API Key 或第三方替代模型，切勿接消费级 Claude OAuth。 |
