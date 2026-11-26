# FD Claude Guard 全仓地毯式 Bug 与逻辑错误审计总清单

> **审计日期**：2026-11-26  
> **审计覆盖**：后端全部 Rust 模块（`src-tauri/src/**/*.rs`）、NSIS 安装/卸载钩子（`src-tauri/nsis/hooks.nsh`）、Clash 覆写脚本（`clash-scripts/claude-verge-override.js`）、前端全部 React/TS 源码（`src/**/*.{ts,tsx}`）。  
> **去重后实锤问题总数**：**46 项**（**P0 致命级 15 项** / **P1 严重级 23 项** / **P2 边界体验级 8 项**）。  
> **已排除**：本轮已完成修复并单测通过的项（Portal 假绿、URL `?org=`、`chat_restricted`、新号分桶、动态天数与 Free 无订阅、日志 10s 分桶折叠、`guard://update-progress` 后端事件）。

---

## 一、P0 致命级（15 项：基础功能不可用 / 永久断网或锁死 / 禁区漏放 / 数据损坏）

| 编号 | 所属域 | 问题标题 | 精确代码位置 | 真实触发场景与后果 | 建议修法 | 状态 |
| :---: | :---: | :--- | :--- | :--- | :--- | :---: |
| `BUG-P0-01` | 基础功能 | **「一键匿名上报排障」100% 必报错 & 2 个遥测开关彻底空转** | `src/pages/MaintenancePage.tsx:286-298`<br>`src/pages/SettingsPage.tsx:528-577`<br>`src-tauri/src/telemetry/mod.rs:68,341` | 开源版无 `FD_TELEMETRY_API_URL` 后端：点「一键匿名上报排障 → 确认」必弹红框报错；守卫配置 2 个默认绿标遥测开关完全空转无作用 | 开源版直接移除该必报错按钮/弹窗与 2 个空转开关，保留真正可用的「导出脱敏 AI 诊断包」+ GitHub Issues 入口 | `待修复` |
| `BUG-P0-02` | 基础功能 | **托盘「退出 FD Claude Guard」在 Claude 运行/熔断时退不出也没弹窗** | `src-tauri/src/lib.rs:2883-2895`<br>`src/lib/ipc.ts:1301`<br>`src/App.tsx`（缺失监听） | 后端发射 `guard://confirm-exit` 后 return 等确认，但全仓前端无人调用 `listenConfirmExit`；Claude 运行时点托盘退出只会把窗口拉到前台，无弹窗且退不掉 | 在 `App.tsx` 接入 `listenConfirmExit` 弹出三段式退出确认框（清退 Claude 并退出 / 仅退出守卫 / 取消） | `待修复` |
| `BUG-P0-03` | 基础功能 | **「开机自启」与「开机仅显悬浮窗」在管理员提权下开机根本起不来** | `src-tauri/src/lib.rs:582-592,4223-4226` | 本机实查 `HKCU\Run` 无启动项；且 `requireAdministrator` EXE 写进 `HKCU\Run` 会被 Windows UAC 开机静默拦截，同时失败吞错弹绿 Toast | 改用 Windows 高权限计划任务（`schtasks /Create /SC ONLOGON /RL HIGHEST /TN "FDClaudeGuard_AutoStart" ... --autostart`），失败诚实报错，卸载同步删任务 | `待修复` |
| `BUG-P0-04` | 安装/卸载 | **NSIS 卸载/升级默认非管理员（`currentUser`），硬杀高权限主进程与清防火墙全线拒绝访问** | `src-tauri/tauri.conf.json:38-44`<br>`src-tauri/build.rs:8-33`<br>`src-tauri/nsis/hooks.nsh:13-35` | 卸载器先弹窗宣称会清空防火墙规则，实际因无管理员权限 `taskkill`/`netsh`/`schtasks` 全部 `Access Denied` 被静默丢弃，**卸载后 Claude 永久断网**、覆盖升级文件占用失败 | `tauri.conf.json` 的 `bundle.windows.nsis` 显式配置 `"installMode": "perMachine"`；卸载钩子补 `/T`、短暂 `Sleep` 与失败校验，并同步清理自启任务 | `待修复` |
| `BUG-P0-05` | 守护核心 | **`Kill-Hold` 事务锁 3 处缺陷：清理/还原/切节点期 100% 漏防真空 + 并发熔断引用计数泄漏 + 休眠熔断漏锁** | `src-tauri/src/lib.rs:279,1840,1911,3029,3190-3219,3693-3713` | 1) 非熔断事务期 250ms 押运协程条件 `!tx_locked \|\| ks_active` 恒假跳过，500ms 防裸奔见 `in_kill_hold` 也跳过，双向甩锅 0 拦截；2) 并发/重复熔断令 `tx_lock_count >= 2` 解除后永不归零卡死；3) 休眠熔断未加锁 | 押运协程在 `cur_snap.active` 时统一拦截；熔断改用独立布尔锁避免裸计数泄漏；休眠熔断补齐加锁与防重入 | `待修复` |
| `BUG-P0-06` | 守护核心 | **`safe_launch_claude` 未校验熔断激活态与防火墙规则，直接拆毁熔断盯防锁并强起被封死的 Claude** | `src-tauri/src/lib.rs:1135-1200` | 代理恢复后 12 项变绿但防火墙熔断未解除时点「安全启动 Claude」，直接拆掉熔断盯防锁并强行拉起被 Defender 阻断的 Claude | 启动前强制校验 `!killswitch.active && !has_active_guard_firewall_rules()`，未解除时明确拦截引导先解熔断 | `待修复` |
| `BUG-P0-07` | 编码/熔断 | **`resolve_claude_exe_path()` 扫描 MSIX 版 Claude 未设 PowerShell UTF-8，中文路径必乱码失效** | `src-tauri/src/process/mod.rs:398-413`<br>（波及 `killswitch/mod.rs:236,299,524`） | 中文 Windows PowerShell 输出 GBK，`from_utf8_lossy` 变 `\u{FFFD}` 导致 `path.exists() == false`，**MSIX 版防火墙规则 100% 写入失败且无法安全启动** | PowerShell 首行加 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;`，遍历全部匹配包定位首个存在的 `Claude.exe` | `待修复` |
| `BUG-P0-08` | 提权安全 | **`run_ps_elevated_checked()` 取消 UAC 返回 `Ok` 假成功、双引号未转义破坏脚本、原生命令漏检 `$LASTEXITCODE`** | `src-tauri/src/rollback/mod.rs:279-325`<br>`src-tauri/src/killswitch/mod.rs:498-501` | 非管理员点「否」取消 UAC 时 `$p` 为 `$null` 退出码 `0` 误报成功；内层含双引号（如 `"{exe_path}"`）直接截断语法；`schtasks` 失败但末尾 `netsh` 成功时漏报 | 改用 PowerShell `-EncodedCommand`（UTF-16LE Base64）；外层显式 `$ErrorActionPreference='Stop'; if(-not $p){exit 1}`；原生 EXE 每条检查 `$LASTEXITCODE` | `待修复` |
| `BUG-P0-09` | 自动更新 | **自动更新 Windows NSIS 覆盖安装后 400ms 又调 `handle.restart()` 抢文件锁 + 60 秒整包下载超时** | `src-tauri/src/updater/mod.rs:156,165,250-316` | 慢网下载超 60s 必中断；下载完成后 NSIS 正在覆盖安装，400ms 后 `handle.restart()` 抢拉旧进程导致文件占用失败或双实例冲突；且无并发重入锁 | Windows NSIS 下载安装后不再调 `handle.restart()`；元数据 check 15s 与安装包下载 300s+ 超时分离；加 `AtomicBool` 防重入 | `待修复` |
| `BUG-P0-10` | 代理防封 | **禁区节点名过滤正则 `\bHK\b` 在数字/下划线前失效，`HK01`/`HK_01`/`CN01`/`RU02`/`🇭🇰` 绕过黑名单** | `src-tauri/src/mihomo/mod.rs:1143-1157`<br>`src-tauri/src/preflight/mod.rs:4703`<br>`clash-scripts/claude-verge-override.js:9-10` | `\w` 含数字与下划线，`\b` 在 `HK01`/`HK_01` 中不成立；且漏掉国旗 Emoji、`Macao`、`SY`/`CU`，真实高频机场禁区节点直接混入 `Claude-Fixed` 触发封号红线 | 改为 `(?i)(?:^\|[^a-z])(HK\|MO\|CN\|RU\|BY\|KP\|IR\|SY\|CU)(?:[^a-z]\|$)`，补齐 Emoji/完整国名，三处保持 100% 同源 | `待修复` |
| `BUG-P0-11` | 体检修复 | **`node_dns`（Fake-IP）检测承诺写入配置，实际 `execute_fix_item("node_dns")` 为空壳仅唤起窗口** | `src-tauri/src/preflight/mod.rs:2823-2829` vs `4428-4436` | 订阅配了 `redir-host` 或关了 DNS 时 `node_dns` 永久红灯卡死门禁，点「写入 Fake-IP 配置并实测验收」毫无实质动作 | 锁定基线后向 `clash-verge.yaml` 与 `Script.js` 注入 `dns: { enable: true, enhanced-mode: fake-ip, fake-ip-range: 198.18.0.1/16 }` 并热重载实测 | `待修复` |
| `BUG-P0-12` | 代理防封 | **`inject_claude_fixed_into_yaml_value` 在无合规节点时兜底塞入全部禁区节点** | `src-tauri/src/preflight/mod.rs:4992-4999` | 订阅全是香港/大陆/俄区节点时不报错拦截，反而把全部禁区节点塞进 `Claude-Fixed` 热重载生效 | 删除该回退分支，直接返回 `Err("当前订阅未找到非禁区合规节点，已拒绝构建 Claude-Fixed")` | `待修复` |
| `BUG-P0-13` | 账户审计 | **“单一真源 6 态拓扑”口径分裂：账户审计传 `&[]` 丢弃 Portal 受限号** | `src-tauri/src/account_audit/mod.rs:959` vs `preflight/mod.rs:2954-2959` | 本地日志命中 `portal.anthropic.com/verify` 时控制台单号锁报红灯高危连坐，账户审计页拓扑与维度 3 却报绿灯无污染 | `account_audit/mod.rs:959` 传入 `local.desktop.portal_org_prefixes`（并合并跨号命中），确保两页 100% 同源 | `待修复` |
| `BUG-P0-14` | 数据维护 | **“原子还原”实为原地合并覆写：残留 WAL/LDB 致数据库损坏、未防目标软链穿越、失败半残且漏 staging 目录** | `src-tauri/src/maintenance/mod.rs:1714-1916` | 还原不清理备份后新增的 `Cookies-wal`/新 `.ldb`/新污染日志，导致 SQLite/LevelDB 损坏或旧日志继续报警；`copy_dir_recursive` 未校验目标 `symlink_metadata`；异常退出永久残留 `.restore-staging-*` | 用 Drop Guard 清理 staging；还原前清理非保护区脏文件（不动 VM/程序本体）；写回前校验目标非软链/Junction；失败引导回滚 `pre-restore` | `待修复` |
| `BUG-P0-15` | 前端状态 | **前端 2 处永久卡死：① 深度核验竞态永久锁死「安全启动 Claude」；② 账户审计扫描失败永久无限转圈白屏** | `src/stores/guardStore.ts:339-394,476-494`<br>`src/pages/AccountAuditPage.tsx:1486-1495` | 1) 深度核验秒结束先发 `{running:false}` 事件，迟到的 `invoke` 返回值把 `deepAudit.running` 覆写回 `true`，控制台主按钮永久禁用；2) 本地审计异常静默吞错且 `!report` 永久显示加载转圈，连日志子页都进不去 | 1) 为深度核验引入 `runId + seq` 终态保护；2) 增加 `accountAuditError` 错误态与「重试审计」按钮，保留日志子页入口 | `待修复` |

---

## 二、P1 严重级（23 项：误杀 / 防线失效 / 交互劫持 / 不可逆副作用 / 并发竞态 / 凭据漏脱敏）

### A. 系统守护、回滚与配置安全（7 项）

| 编号 | 问题标题 | 精确代码位置 | 真实影响与简明修法 | 状态 |
| :---: | :--- | :--- | :--- | :---: |
| `BUG-P1-01` | **2s 状态哨兵把 `fetch_configs` 单次超时误判为关 TUN，直接误杀正常对话中的 Claude** | `src-tauri/src/lib.rs:3407-3428,3473-3500` | Clash 刷新订阅瞬时超时时 `tun_on` 兜底 `false`，无二次确认直接 4 层熔断杀进程。修法：采样失败间隔 400ms 重试确认后再判掉线 | `待修复` |
| `BUG-P1-02` | **撤回/网络急救清 `last_preflight_at` 致防裸奔失明；休眠熔断无视 `auto_kill_switch=false`** | `src-tauri/src/lib.rs:3184-3194,3679-3692,3742,4126,4144,4162` | 刚撤回规则（最危险时）防裸奔失效长达 15 分钟；关闭自动熔断的用户休眠唤醒仍被强杀；通知文案谎报已熔断。修法：独立 `initial_preflight_done` 标志，休眠与通知严格尊重 `auto_kill_switch` | `待修复` |
| `BUG-P1-03` | **撤回中心 3 缺陷：丢弃 `mode/tun/sysproxy` 基线；IPv6 误伤虚拟网卡永不恢复；防火墙撤回 60s 假显已安装** | `src-tauri/src/rollback/mod.rs:396,647-682,1022-1123,1421-1503`<br>`src-tauri/src/preflight/mod.rs:4262` | 一键撤回不恢复 Clash 模式/TUN；正向禁用 IPv6 波及 WSL/Hyper-V/VPN 虚拟网卡且撤回只还原物理网卡；删计划任务未清 `FW_HELPER_CACHE`。修法：补全 3 项还原、正向限定 `-Physical`、删任务即清缓存 | `待修复` |
| `BUG-P1-04` | **网络急救漏检 `http=127.0.0.1:7897;...` 死代理；`sys_env` 撤回/急救未刷新 WinINET 与 `WM_SETTINGCHANGE`** | `src-tauri/src/rollback/mod.rs:1293-1338,1649-1671` | 带协议前缀/多协议分号/`localhost` 的死代理急救漏清导致持续断网；撤回环境变量需注销重启才生效。修法：完善解析器 + 广播 `WM_SETTINGCHANGE` 与 `InternetSetOptionW` | `待修复` |
| `BUG-P1-05` | **`startup_audit` 未读 Windows `StartupApproved` 禁用位（按指引关 Claude 自启永不消警）且默认自启假绿** | `src-tauri/src/startup_audit/mod.rs:7-25,110-152`<br>`src-tauri/src/config/mod.rs:90` | Windows 设置关闭自启只写 `StartupApproved` 禁用位不删原键，导致 `opt_boot` 永不转绿；漏扫公共启动目录；首次安装未注册自启却显已开启。修法：读取 `StartupApproved` 并实查系统自启状态 | `待修复` |
| `BUG-P1-06` | **单实例唤醒在开机仅显 HUD 模式下双击图标毫无反应；退出静默吞防火墙清理失败** | `src-tauri/src/lib.rs:868-922,3846-3878,4236-4241` | 懒创建主窗口时 `FindWindowW` 找不到窗口直接静默退出；非管理员退出清规则失败无提示导致断网。修法：通过 IPC/隐藏窗口消息唤起主窗口；退出清防火墙失败拦截报错 | `待修复` |
| `BUG-P1-07` | **`config.json` 与 `system-baseline.json` 并发落盘固定 `.tmp` 竞态 + 损坏静默重置丢绑定与基线** | `src-tauri/src/config/mod.rs:213-234`<br>`src-tauri/src/rollback/mod.rs:219-249` | 多处释放锁后并发抢写同一 `.json.tmp` 致覆盖丢失；`update_baseline` 无互斥锁；坏 JSON 静默清空不备份。修法：加写盘 `Mutex`、唯一临时文件名、坏文件备份为 `.corrupt-{ts}` | `待修复` |

### B. Clash/Mihomo、体检、账户审计与维护（11 项）

| 编号 | 问题标题 | 精确代码位置 | 真实影响与简明修法 | 状态 |
| :---: | :--- | :--- | :--- | :---: |
| `BUG-P1-08` | **PowerShell 探测 Clash 配置目录缺 UTF-8（中文路径乱码）+ 多进程 `-d` 遇服务沙箱提前中止** | `src-tauri/src/mihomo/mod.rs:1354-1429` | 中文用户名/中文便携路径必失败；多 Mihomo 进程首个为服务沙箱时漏检用户目录。修法：加 UTF-8 编码，收集全部 `-d` 候选逐个校验 | `待修复` |
| `BUG-P1-09` | **AGY 探针网络错误误判限区/假绿 + GeoIP 探测失败被 24h 磁盘缓存锁死** | `src-tauri/src/mihomo/mod.rs:935-957,1053-1111` | `cloudcode` 超时把健康节点误标 `AGY 限区`、`api` 超时反判 `AGY ✓`；GeoIP 瞬断锁死 24h 显示探测失败。修法：网络错误统一 `unknown/AGY 待测`，Geo 失败改 5m 短 TTL 且不覆盖旧有效 Geo | `待修复` |
| `BUG-P1-10` | **深度节点核验非原子重入 + 未校验 direct/GLOBAL 脱组 + 取消/手动切节点后仍写盘污染** | `src-tauri/src/lib.rs:1269-1290,1347-1378,1500-1605` | 并发或脱组核验导致全量节点 IP/风控串线污染 24h 缓存；手动切节点 2.4s 超时后仍可能被反切覆盖且文案谎报已恢复。修法：`compare_exchange` 原子锁 + 路由前置校验 + 落盘/切节点前二次校验代际号 | `待修复` |
| `BUG-P1-11` | **单次抖动超时令 `drop_rate_pct` 长期超 7.8% 红线，健康节点被拉黑需连赢 12 次才解封** | `src-tauri/src/mihomo/mod.rs:507-530,2115-2126,2308` | 新节点偶发 1 次超时永久掉到 100%→50% 标红禁切。修法：最小样本数 ≥4 或改近期 10 次滑动窗口 | `待修复` |
| `BUG-P1-12` | **`inspect_windows_ipv6` 与 `inspect_wintun_adapter` 缺 PowerShell UTF-8，中文网卡名乱码** | `src-tauri/src/preflight/mod.rs:2505-2518,2745-2754` | `"以太网"`/`"本地连接"` 在体检摘要与证据中变乱码。修法：命令首行显式加 `[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;` | `待修复` |
| `BUG-P1-13` | **`sys_env` 离线端口 7890/7897 死循环 + 子串校验漏洞 + HKLM 吞错 + 漏检两端点键** | `src-tauri/src/preflight/mod.rs:289,1874,1995-2079,2138-2153` | 7897 用户 Clash 离线时红灯且修复不清理；`contains(":7897")` 放行远端代理或混合端口；HKLM 删除吞错；漏删 `CLAUDE_API_BASE_URL`/`ANTHROPIC_API_URL`。修法：离线调 `resolve_active_mixed_port`、严格解析本机 host+全段端口、复用 `API_ENDPOINT_ENV_KEYS` | `待修复` |
| `BUG-P1-14` | **`opt_webrtc` 策略优先级颠倒（`HKCU` 压过 `HKLM`）造成假绿泄露真实 IP** | `src-tauri/src/preflight/mod.rs:3568-3580,3616-3634` | Chrome/Edge 中机器级 `HKLM` 优先于 `HKCU`，若 `HKLM` 存有 `default` 会覆盖 `HKCU` 修复但探针仍报绿。修法：检测改为 `hklm.or(hkcu)`，存在冲突时强制更新 `HKLM` | `待修复` |
| `BUG-P1-15` | **`node_group` 多故障短路 + `node_geo` 原地切回死节点 + `opt_exit_geo` 后端无处理分支** | `src-tauri/src/preflight/mod.rs:4152-4198,4229-4256,4437-4440` | `node_group` 修完 direct/GLOBAL 后跳过组与规则校验；`node_geo` 未排除当前故障节点 `g.now` 可能原地切回死节点；`opt_exit_geo` 掉入 `_` 兜底。修法：补全连续校验、排除 `g.now` 并优先选优、补齐 `opt_exit_geo` 分支 | `待修复` |
| `BUG-P1-16` | **封号残留规则三方分裂（`local_scan` 漏检多项实锤特征）+ 切号后归属地/续费日/额度张冠李戴老号** | `src-tauri/src/account_audit/local_scan.rs:1626,1649`<br>`src-tauri/src/account_audit/mod.rs:669,1251,1651` | `local_scan` 漏检 `account_suspended`/`organization_disabled`/`ban_evasion`/`sessionkey names a different account`；`load_bound_workspace_geo` 未按 org 分桶、桌面 Free 号误借 CLI 旧号续费日与额度。修法：抽取共享匹配函数、按活跃 org 隔离 | `待修复` |
| `BUG-P1-17` | **`cloud_probe` 中 `chat_available` 故障假绿 + 失败也锁 60s 冷却 + 响应头拆分边界；`restore_official_endpoint` 吞错 & 隐私补齐丢非字符串原值** | `src-tauri/src/account_audit/cloud_probe.rs:518-541,1030,1112`<br>`src-tauri/src/account_audit/mod.rs:1822,1977-2014` | 超时/HTML 页误判 `chat_available=true`；代理失败后切节点重试被锁 60s；删注册表吞错未广播；JSON 布尔/数字原值撤回时误删。修法：严格校验 `r.ok`、失败撤冷却、校验注册表删除并保留原 Value | `待修复` |
| `BUG-P1-18` | **`watchdog` orgId 大小写误判混登 + 折叠已读吞新告警 + 尾读首行残片置顶；备份清理未校验 0 进程 & 脱敏漏驼峰凭据/代理账密** | `src-tauri/src/watchdog/mod.rs:870,1172,1413`<br>`src-tauri/src/maintenance/mod.rs:100-219,650,1403-1476` | 大小写 UUID 触发假混登红灯；折叠组主 ID 已读吞掉新子告警；日志截断首行变 `"时间未知"` 置顶；进程未归 0 跳过备份却删文件；诊断包明文泄露 `accessToken`/`ANTHROPIC_API_KEY`/`http://user:pass@`。修法：统一小写、改 `all_collapsed_acked`、跳过截断首行、强杀后校验 0 进程、补全脱敏正则 | `待修复` |

### C. 前端状态机与核心交互（5 项）

| 编号 | 问题标题 | 精确代码位置 | 真实影响与简明修法 | 状态 |
| :---: | :--- | :--- | :--- | :---: |
| `BUG-P1-19` | **悬浮窗（HUD）点「节点不可用 · 前往换节点」及动态告警行被强行劫持跳回控制台；点日志漏切子页** | `src/components/HudCard.tsx:501-515,869,889`<br>`src/App.tsx:71-87`<br>`src/stores/guardStore.ts:508-517` | 非 console 目标仍传 `focusItemId="__first_fail__"`，触发 `focusFirstUnhealthyCheck()` 强切回控制台；`logOnlyFocus` 漏传 `subTab="logs"`。修法：仅 `tab==="console"` 传 `focusFirstFail`，日志态传 `subTab="logs"` | `待修复` |
| `BUG-P1-20` | **实时流量「全部标为已处理」只写前端内存，侧边栏与 HUD 红/黄灯永不消退且重启复活** | `src/pages/NodesTrafficPage.tsx:133-149`<br>`src/stores/guardStore.ts:579-583`<br>`src/components/Sidebar.tsx:41-42` | 弹绿 Toast 宣称已清零角标，实际不调后端也不改 `snapshot`，侧边栏和 HUD 报警纹丝不动。修法：补后端 `ack_flow_anomalies` 持久化并重推 `snapshot` | `待修复` |
| `BUG-P1-21` | **控制台主 CTA 优先级倒置：熔断态伴随 ≥2 项体检失败时，「解除熔断保护」按钮被遮盖** | `src/pages/ConsolePage.tsx:507-545` | 自动熔断必然连带 ≥2 项体检失败，主按钮被「一键处理全部」覆盖，用户找不到解除熔断入口。修法：将 `snapshot.killSwitchActive` 提升至 `mustFail >= 2` 之前 | `待修复` |
| `BUG-P1-22` | **`guardStore` 多处异步请求缺代际序号与防重入锁，慢响应覆盖新状态（快速拨开关弹回）** | `src/stores/guardStore.ts:182-300,396-498,641-654` | 刚修好/核验变绿被在途旧响应刷回红灯；快速连拨「开机自启」与相邻开关时后改开关自动弹回。修法：全量写状态异步入口统一加 `ReqSeq` 序号校验与 `fixing` 防重入守卫 | `待修复` |
| `BUG-P1-23` | **环境维护手动触发熔断缺 `catch` 吞错；节点页刷新失败仍弹绿假成功；非审计页清理后侧边栏审计角标滞留** | `src/pages/MaintenancePage.tsx:219-231`<br>`src/pages/NodesTrafficPage.tsx:358-371`<br>`src/components/CleanConfirmModal.tsx:121-155` | 手动触发熔断失败无任何提示；离线刷新节点同时弹红失败与绿成功；控制台/维护页清理完混号后账户审计红标仍留着。修法：补 `catch`、`refreshNodes` 返回 `boolean`、清理完统一 `refreshAccountAudit(true)` | `待修复` |

---

## 三、P2 边界体验与工程卫生（8 项）

| 编号 | 所属域 | 问题摘要 | 精确代码位置 | 简明修法 | 状态 |
| :---: | :---: | :--- | :--- | :--- | :---: |
| `BUG-P2-01` | 窗口/HUD | 悬浮窗位置恢复缺多屏可见性校验（拔副屏永久不可见、左副屏负坐标被拽回）+ 拖拽防抖尾包丢失 | `src-tauri/src/lib.rs:745-780,2847-2853,4310-4355` | 复用 `available_monitors()` 校验可见性；防抖 `store(false)` 后复核序号防丢尾包 | `待修复` |
| `BUG-P2-02` | 后端锁卫生 | 持同步 `RwLock` 写锁内嵌套锁/同步写盘；异步命令直调同步 `netsh`；`confirm_primary_org_binding` 缺 `preflight_gate` 锁 | `src-tauri/src/lib.rs:571,1845,2055,2303,2760` | 持锁只改内存/克隆，释放后写盘与 emit；同步 `netsh` 移入 `spawn_blocking`；换绑加单飞锁 | `待修复` |
| `BUG-P2-03` | Mihomo | `read_clash_external_controller_and_secret` 未将 `0.0.0.0`/`[::]` 规范化为 `127.0.0.1`，且未剥离 YAML 行尾 `# 注释` | `src-tauri/src/mihomo/mod.rs:1514-1545` | 改用 `serde_yaml` 解析并将 `0.0.0.0`/`[::]` 转 `127.0.0.1` | `待修复` |
| `BUG-P2-04` | 体检引擎 | `node_geo` 漂移布尔短路（`baseline_changed` 失效）；冲突端口误覆写 `verge.yaml`；文案仍写“11 项”；YAML 遇 UTF-8 BOM 写重复 `mode:` 键 | `src-tauri/src/preflight/mod.rs:1177,4506,4648,5387-5412` | 修正条件表达式、仅 `tun_failed` 写 TUN、改“12 项”、剥离 BOM 并原子写 YAML | `待修复` |
| `BUG-P2-05` | 数据维护 | 备份 ZIP 失败残留 `.zip.tmp` 垃圾文件；诊断包时间戳只到分钟同分钟连点静默覆盖且非原子写 | `src-tauri/src/maintenance/mod.rs:1288-1350,2113-2116` | Drop Guard 清失败 `.tmp`；诊断包精确到秒 (`%H%M%S`) + 原子写 | `待修复` |
| `BUG-P2-06` | 前端组件 | 侧边栏 `interceptFlash` 在 1.5s 内解除盯防时 `useEffect` cleanup 陷阱致闪烁样式永久残留；控制台倒计时休眠漂移；账户审计按钮硬编码 `45s` 且 `useMemo` 漏依赖 | `src/components/Sidebar.tsx:48-58`<br>`src/pages/ConsolePage.tsx:48-62`<br>`src/pages/AccountAuditPage.tsx:814,921` | `useRef` 管 timer；倒计时按 `nextFullAuditEpochMs - Date.now()` 同步；动态读 `config.killHoldSeconds` | `待修复` |
| `BUG-P2-07` | 前端交互 | 撤回中心读取失败静默空白误显 0 项 + 一键撤回弹窗并排出现**两个「取消」按钮**；HUD 贴边展开高度去重跳过；日志标已读失败不回滚且与成功 Toast 冲突 | `src/components/NetworkRescueRollbackPanel.tsx:39,128`<br>`src/components/HudCard.tsx:164-203,270-296`<br>`src/stores/guardStore.ts:535-577` | 撤回中心加错误重试态、主按钮改「暂不撤回」；HUD 收起清尺寸缓存并补 `catch` 回滚；日志已读改异步成功后再 Toast | `待修复` |
| `BUG-P2-08` | 开源清理 | `SupportModal.tsx:161` 顶部已改「免费开源」下方仍残留「官方售后 QQ」；`lib.rs` 残留 2 个未调用命令 `save_hud_position`/`get_killswitch_state` | `src/components/SupportModal.tsx:161`<br>`src-tauri/src/lib.rs` | 统一文案为「交流与反馈 QQ」；移除死注册命令 | `待修复` |

---

## 四、建议分批推进策略（先亮短板再推荐）

- **全量一次性大改的短板（先亮风险）**：46 项横跨 NSIS 权限、防火墙/计划任务、Clash 覆写、备份还原、账户审计与前端状态机，如果混在同一个大版本一次性全改，真机测试回归面过大，且 NSIS 从 `currentUser` 切 `perMachine` 会改变安装目录（`%LOCALAPPDATA%` → `Program Files`），**需要专门实测老版本 `v0.3.3` 自动更新覆盖升级到新版的兼容性**（防止新旧并存两份卸载项）。
- **推荐分 2 个清晰版本稳扎稳打落地**：
  1. **`v0.3.4`（基础功能清零 + 核心安全止血 + 已确认 UI 落地）**：
     - 落地全部 **15 项 P0**（含你刚确认的 2 处 UI 改动 + 去掉必报错匿名上报/假遥测开关 + 补托盘退出确认 + 真计划任务自启 + 修复 Kill-Hold 真空/安全启动熔断漏检/MSIX 中文路径/禁区正则 `HK01`/Fake-IP 真写入/原子还原/前端两处永久卡死，其中 `BUG-P0-04` 的 NSIS 提权策略需特别验证覆盖升级兼容性）；
     - 顺手带走高发 P1：`BUG-P1-19`（HUD 跳转劫持）、`BUG-P1-20`（流量已处理角标）、`BUG-P1-21`（熔断主按钮被遮盖）、`BUG-P1-18`（脱敏防泄密 + 大小写混登）、`BUG-P1-01`（防误杀 Claude）。
  2. **`v0.3.5`（全面稳健性收口）**：
     - 集中消化其余 **P1 竞态/回滚/探测细节（18 项）+ P2 边界体验（8 项）**，每项配齐精准回归单测与真机双向闭环验证。
