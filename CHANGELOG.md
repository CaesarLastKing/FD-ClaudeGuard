# 更新日志（CHANGELOG）

本项目遵循 [语义化版本规范（SemVer）](https://semver.org/lang/zh-CN/)：
- **修订号（`PATCH`，如 `0.2.8 → 0.2.9`）**：问题修复、真机兼容性优化与小幅改进；
- **次版本号（`MINOR`，如 `0.2.9 → 0.3.0`）**：新增核心功能模块或架构演进；
- **主版本号（`MAJOR`，如 `1.0.0`）**：重大里程碑版本。

---

## [0.2.9] - 2026-11-25

### 变更
- **产品定位正式转型为免费开源**：全面移除商业激活锁、付费墙门禁、未激活遮罩、锁图标与加密脚本分支，全部 17 项真实防封检测、节点质量评估、日志分析、环境维护与守卫配置默认全量开放。
- 同步规范化三处版本号清单（`package.json` / `src-tauri/Cargo.toml` / `src-tauri/tauri.conf.json`）并固化自动化版本号一致性单测门禁。

### 修复
- **Clash Mihomo `ipv6: false` 持久化（`T-053`）**：修复关闭 Mihomo IPv6 仅热改内存未写盘 `config.yaml` 导致重启 Clash Verge 或切换服务模式后 `node_group` 反复变红的问题，补齐 `originalConfigIpv6` First-Write-Wins 基线捕获与精准撤回还原，并补充规则模式隔离说明。
- **开机启动项徽章文案语义（`T-054`）**：修复守卫配置页「Clash Verge Rev 未开启开机自启」错误显示「已开启（有风险）」的问题，精准区分「未开启（建议开启）」与「已开启（有风险）」。
- **日志分析未读角标永久卡 `1`（`T-055`）**：修复无行首时间戳的多行 Error 堆栈子行（如 `[message]: 'net::ERR_CONNECTION_CLOSED'`）回退使用 `Local::now()` 参与稳定事件 ID 哈希导致跨秒漂移、已读游标失效的问题。

---

## [0.2.8] - 2026-11-25

### 新增
- **三层安全网**：First-Write-Wins 系统基线快照、6 项精准单项/批量撤回引擎（100% 保留用户后续新增订阅）与无门槛「一键网络急救」。

### 修复
- 根治重装 Clash Verge v2.x 服务模式 5 项真机故障：排除 `clash-verge-service` 沙箱目录、中文网卡名 UTF-8/纯数字 `InterfaceIndex` 检出并重置 `127.0.0.1` 死 DNS、防脱组直连 `CN` 栽赃海外节点、废除 `taskkill /F` 强杀 Clash 改走 Mihomo API 热开 TUN。
