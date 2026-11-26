# 03 · Clash/Mihomo 代理、禁区过滤与体检引擎（2026-11-26）

> **模块范围**：`mihomo/mod.rs`、`preflight/mod.rs`、`clash-scripts/claude-verge-override.js`、`lib.rs`（深度核验编排）

| 编号 | 级别 | 标题 | 代码位置 | 根因与后果 | 状态 | 修复与验证摘要 |
| :---: | :---: | :--- | :--- | :--- | :---: | :--- |
| `BUG-P0-10` | **P0** | 禁区节点名过滤正则 `\bHK\b` 在数字/下划线前失效，`HK01`/`HK_01`/`CN01`/`RU02`/`🇭🇰` 与 `SY`/`CU` 漏网 | `mihomo/mod.rs`<br>`preflight/mod.rs`<br>`claude-verge-override.js` | `\w` 含数字/下划线致 `\b` 失效，真实高频禁区节点直接混入 `Claude-Fixed` 触发地区封号 | `已完成` | 三处 100% 同步升级为 `(?:^|[^a-z])(HK|MO|CN|RU|BY|KP|IR|SY|CU)(?:[^a-z]|$)` + 国旗 Emoji + Macao/Syria/Cuba，补单测全覆盖 |
| `BUG-P0-11` | **P0** | `node_dns`（Fake-IP）检测承诺一键写入，实际 `execute_fix_item("node_dns")` 是空壳仅唤起窗口 | `preflight/mod.rs`<br>`claude-verge-override.js` | 订阅配了 `redir-host` 或关 DNS 时永久红灯卡死门禁，修复按钮无实质动作 | `已完成` | 新增 `inject_fake_ip_dns_into_yaml_value` 与 `apply_fake_ip_dns_and_reload` 真正写入 `clash-verge.yaml` & `Script.js`、热重载并 `ipconfig /flushdns` 实测验收 |
| `BUG-P0-12` | **P0** | `inject_claude_fixed_into_yaml_value` 在无合规节点时兜底塞入全部禁区节点 | `preflight/mod.rs:5139` | 全禁区订阅不拦截报错，反而把禁区节点全部放进 `Claude-Fixed` 热重载生效 | `已完成` | 删除禁区兜底，全禁区订阅直接返回明确错误拒绝写入；补单测通过 |
| `BUG-P1-08` | **P1** | PowerShell 探测 Clash 目录缺 UTF-8（中文路径乱码）+ 多进程 `-d` 遇服务沙箱提前中止 | `mihomo/mod.rs:1397-1465` | 中文便携版/用户名乱码失败；首个进程为服务沙箱时漏检用户配置目录 | `已完成` | 显式设 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8` 并遍历全部 `-d` 候选路径 |
| `BUG-P1-09` | **P1** | AGY 探针网络错误误判限区/假绿 + GeoIP 探测失败锁死 24h 磁盘缓存 | `mihomo/mod.rs:241,978` | 瞬时超时误标 `AGY 限区` 或反判假绿 `AGY ✓`；GeoIP 限流导致 24h 永久显示探测失败 | `已完成` | AGY 探针严格区分 HTTP 403/451 与传输错误（归 `unknown / AGY 待测`）；GeoIP 失败或 `risk_level==unknown` 改用 5m 短 TTL |
| `BUG-P1-10` | **P1** | 深度节点核验非原子重入 + 未校验 direct/GLOBAL 脱组 + 取消/手动切节点后仍写盘污染 | `lib.rs:1387-1725`<br>`mihomo/mod.rs:192` | 并发或脱组核验致全量节点串线污染 24h 缓存；手动切节点后仍可能被反切覆盖且文案谎报恢复 | `已完成` | 新增原子抢锁 `try_acquire_deep_audit_lock` + RAII 释放守卫；前置拦截 direct/GLOBAL 脱组；切节点与落盘二次复核代际号并修正文案 |
| `BUG-P1-11` | **P1** | 单次超时致 `drop_rate_pct` 长期超 7.8% 红线，健康节点被拉黑需连赢 12 次才解封 | `mihomo/mod.rs:103,530,2197` | 新节点 1 次偶发抖动即长期禁切，极难自然恢复 | `已完成` | 引入最近 12 次滑动窗口 `recent_outcomes` 且高断连拉黑要求至少 4 次样本；补单测通过 |
| `BUG-P1-12` | **P1** | `inspect_windows_ipv6` 与 `inspect_wintun_adapter` 缺 UTF-8，中文网卡名乱码 | `preflight/mod.rs:2584,2824` | `"以太网"`/`"本地连接"` 在界面证据中显示乱码 | `已完成` | 两处 PowerShell 命令均显式设置 UTF-8 输出编码 |
| `BUG-P1-13` | **P1** | `sys_env` 离线端口 7890/7897 死循环 + 子串校验漏洞 + HKLM 吞错 + 漏检两端点键 | `preflight/mod.rs:288,1866-2340` | 7897 用户离线红灯修不动；`contains(":7897")` 放行远端/混合端口；HKLM 吞错；漏删 2 个官方端点键 | `已完成` | 离线调 `resolve_active_mixed_port`；新增严格 `is_local_proxy_matching_port`；覆盖全部 4 端点键；HKLM 无权提权或明确报错；补单测通过 |
| `BUG-P1-14` | **P1** | `opt_webrtc` 策略优先级颠倒（`HKCU` 压过 `HKLM`）造成假绿泄露真实 IP | `preflight/mod.rs:3655-3730` | `HKLM` 存 `default` 时写入 `HKCU` 探针报绿，但浏览器按 `HKLM` 继续漏真实 IP | `已完成` | 改为 `hklm_val.or(hkcu_val)` 真实优先级，优先通过 `run_ps_elevated_checked` 覆写 `HKLM` 冲突策略 |
| `BUG-P1-15` | **P1** | `node_group` 多故障短路 + `node_geo` 原地切回死节点 + `opt_exit_geo` 缺后端处理分支 | `preflight/mod.rs:4224-4390` | 多故障修完仍红；`node_geo` 不排除 `g.now` 可能切回自身死节点；`opt_exit_geo` 掉入 `_` 兜底 | `已完成` | `node_group` 解除多故障短路；`node_geo` 排除 `g.now` 并用 `pick_best_compliant_node`；补齐 `opt_exit_geo` 校准处理分支 |
| `BUG-P2-03` | **P2** | `read_clash_external_controller_and_secret` 未转 `0.0.0.0`/`[::]` 且未剥行内 `# 注释` | `mihomo/mod.rs:1568-1610` | 回退 HTTP 模式连接局域网监听地址必失败，带注释 secret 401 鉴权失败 | `已完成` | 改用 `serde_yaml` 解析并归一化 `0.0.0.0`/`[::]`/`*` → `127.0.0.1`；补单测通过 |
| `BUG-P2-04` | **P2** | `node_geo` 布尔短路、冲突端口误写 `verge.yaml`、文案写“11 项”、YAML 遇 BOM 写重复 `mode:` | `preflight/mod.rs`<br>`rollback/mod.rs` | `baseline_changed` 失效；冲突端口误清 WinINET；UTF-8 BOM 致后续 YAML 解析报错 | `已完成` | 修正 `landing_drifted`；端口冲突时不盲写 `verge.yaml`；文案改动态 `must_total`；YAML 读写统一剥 BOM 并原子落盘；119/119 Rust 单测通过 |
