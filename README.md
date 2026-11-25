# FD Claude 安全启动器（FD Claude Guard）

面向 Windows 11 环境的 **Claude Desktop / Claude Code CLI** 安全护航与防封启动器，基于 **Tauri v2（Rust + React 19 + TypeScript + Tailwind CSS v4 + HeroUI）** 构建。

## 核心能力
- **启动前两级三防线真实探针**：直连 Clash Verge Rev Mihomo Windows 命名管道（`\\.\pipe\verge-mihomo-*`），逐项实测代理端口独占、`Claude-Fixed` 策略组与规则、出口 IP 白名单、IPv6 三层防泄漏、TUN 与 Fake-IP（`198.18.0.0/15`）、本地封号残留、第三方反代审计与官方隐私降噪开关（`~/.claude/settings.json`），绝不伪造绿灯。
- **桌面悬浮动态卡片（独立窗口 `hud`）**：默认展开与固定置顶、支持拖拽记忆坐标，纯状态雷达与跳转入口，底部按钮统一跳回控制台处理；支持开机自启仅显悬浮窗不弹控制台。
- **4 层紧急防回传 & 防裸奔接管**：异常触发 Clash `DELETE /connections` 毫秒掐流 + Windows Defender 防火墙规则 `FDGuard_Block_Claude_Out` + 强杀进程树（跳过 `onQuitCleanup`）+ 清扫 `~/.claude/telemetry/`。
- **实时日志归因 & 8 大安全守则联动**：解析 `region_unavailable`、`account_banned`、跨 `orgId` 竞态与 `429` 限流，一键平滑滚动并高亮闪烁定位对应安全守则。
- **环境维护与脱敏 AI 排障包**：清理前自动 ZIP 备份至 `~/FDtools-Backups/` 支持一键还原；一键导出自动打码邮箱/Token/SessionKey/完整公网 IP/用户名路径的 AI 排障包。

## 常用命令
```powershell
npm test                                          # 运行前端 Vitest 单元测试
npm run build                                     # TypeScript 类型检查 + Vite 双入口构建
cargo test --manifest-path src-tauri/Cargo.toml --lib                        # 运行 Rust 商业版单元测试
cargo test --manifest-path src-tauri/Cargo.toml --lib --no-default-features  # 运行 Rust 开源版单元测试
npm run tauri dev                                 # 启动双窗口开发模式
npm run tauri build                               # 构建 Windows Release 安装包 (NSIS)
```

## 标准研发、测试与验收流程文档（必读）
所有功能迭代、缺陷修复与正式发版必须严格遵循 `docs/standards/` 下的标准化工程流程：
- **全生命周期总纲 SOP（G0–G6 门禁与一票否决红线）**：[`docs/standards/engineering-lifecycle-sop.md`](./docs/standards/engineering-lifecycle-sop.md)
- **开发阶段标准化规范（Rust / Win32 / React / 授权 / NSIS）**：[`docs/standards/development-standard.md`](./docs/standards/development-standard.md)
- **测试阶段标准化规范（L1–L5 五层测试金字塔与命令集）**：[`docs/standards/testing-standard.md`](./docs/standards/testing-standard.md)
- **验收阶段标准化手册与发版签收表（关卡 A–D）**：[`docs/standards/acceptance-checklist.md`](./docs/standards/acceptance-checklist.md)
- **UI 设计规范与 1:1 视觉验收门禁**：[`docs/ui-design-system.md`](./docs/ui-design-system.md)
- **开发问题与真机缺陷追踪台账（`ISS-001+`）**：[`docs/dev-issues-log.md`](./docs/dev-issues-log.md)
