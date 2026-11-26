# FD Claude 安全启动器（FD Claude Guard）

面向 Windows 11 环境的免费开源 **Claude Desktop / Claude Code CLI** 安全护航与防封启动器，基于 **Tauri v2（Rust + React 19 + TypeScript + Tailwind CSS v4 + Zustand）** 构建。

## 核心能力
- **启动前 12 项必须门禁 + 7 项建议项真实探针**：直连 Clash Verge Rev Mihomo Windows 命名管道（`\\.\pipe\verge-mihomo-*`），实测代理端口独占、`Claude-Fixed` 策略组与规则、出口 IP 归属与纯净度、IPv6 三层防泄漏、TUN 与 Fake-IP（`198.18.0.0/15`）、本地封号残留、跨端单号卫生锁、官方 API 端点防反代与 4/4 官方隐私降噪开关（`~/.claude/settings.json`），绝不伪造绿灯。
- **账户审计双层融合体系**：
  - 第一层本地非侵入只读扫描（`~/.claude.json`、编译期白名单 `.credentials.json`、`settings.json`、离线 `.jsonl` 节律与桌面端日志 7 类 HTTP 403 精准消歧）；
  - 第二层按需一次性云端只读核验（支持粘贴 `sessionKey` 或 `Copy as cURL` 自动正则提取，明文用完即焚零落盘，内置 60 秒冷却锁与 `orgId` 防串号拦截）；
  - 100 分制纯函数风险评分与白皮书级「防封宝典」，并集成「实时异常日志流」与 8 大安全守则联动。
- **节点质量、双 AI 评估与隔离区**：同步评估 Claude API / 网页 CF 盾与 Google Antigravity (AGY) 地区准入，识别落地州/城市与时区，隔离不可用与落地禁区节点并支持主备同区容灾切换。
- **4 层紧急防回传 & 三层安全网**：异常触发 Clash `DELETE /connections` 毫秒掐流 + Windows Defender 防火墙封锁 + 强杀进程树（跳过 `onQuitCleanup`）+ 清扫 `~/.claude/telemetry/`；配套 First-Write-Wins 基线快照、6 项精准单项/批量撤回（100% 保留用户后续订阅）与无门槛「一键网络急救」。
- **桌面悬浮动态卡片（独立窗口 `hud`）与签名自动更新**：独立轻量悬浮雷达窗支持拖拽记忆坐标与开机静默守护；接入 `tauri-plugin-updater` + Ed25519 公钥验签，支持优先经本机代理并自动回退直连检查与一键升级。

## 常用命令
```powershell
npm test                                                    # 运行前端 Vitest 单元测试
npm run build                                               # TypeScript 类型检查 + Vite 双入口构建
cargo test --manifest-path src-tauri/Cargo.toml --lib       # 运行 Rust 单元测试
cargo clippy --manifest-path src-tauri/Cargo.toml --lib     # 运行 Rust 静态代码检查
npm run tauri dev                                           # 启动双窗口开发模式
npm run tauri build                                         # 构建 Windows Release 安装包 (NSIS)
```

## 标准研发、测试与验收流程文档
所有功能迭代、缺陷修复与正式发版遵循 `docs/standards/` 下的工程流程：
- **全生命周期总纲 SOP**：[`docs/standards/engineering-lifecycle-sop.md`](./docs/standards/engineering-lifecycle-sop.md)
- **开发阶段标准化规范**：[`docs/standards/development-standard.md`](./docs/standards/development-standard.md)
- **测试阶段标准化规范**：[`docs/standards/testing-standard.md`](./docs/standards/testing-standard.md)
- **验收阶段标准化手册**：[`docs/standards/acceptance-checklist.md`](./docs/standards/acceptance-checklist.md)
- **UI 设计规范**：[`docs/ui-design-system.md`](./docs/ui-design-system.md)
- **当前待办与优化清单**：[`docs/todo-v032-roadmap-and-optimizations.md`](./docs/todo-v032-roadmap-and-optimizations.md)
- **历史任务台账与缺陷记录**：[`docs/task-ledger.md`](./docs/task-ledger.md) · [`docs/dev-issues-log.md`](./docs/dev-issues-log.md)

## 开源协议
本项目采用 [**GNU General Public License v3.0 (GPL-3.0)**](./LICENSE) 开源发布，与同生态桌面工具保持一致。本工具按现状（AS IS）提供，仅供本地环境合规检测与网络排障使用。
