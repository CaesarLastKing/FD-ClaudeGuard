# 更新日志（CHANGELOG）

本项目遵循 [语义化版本规范（SemVer）](https://semver.org/lang/zh-CN/)：
- **修订号（`PATCH`，如 `0.2.8 → 0.2.9`）**：问题修复、真机兼容性优化与小幅改进；
- **次版本号（`MINOR`，如 `0.2.9 → 0.3.0`）**：新增核心功能模块或架构演进；
- **主版本号（`MAJOR`，如 `1.0.0`）**：重大里程碑版本。

---

## [0.3.7] - 2026-11-27

### 严格验收加固与补丁
- **加固 NSIS 安装前旧版自动卸载钩子（`hooks.nsh`）**：显式切换 `SetShellVarContext current` 定位历史 `currentUser` 残留目录（`%LOCALAPPDATA%\FD Claude Guard`）与 HKCU 卸载项，并用 `${If} ${FileExists}` 替代相对跳转，清理完毕后严格恢复 `SetShellVarContext all`。
- **补齐 Gate 3 破坏性故障注入与去重单测**：覆盖 `account-audit-cache.json` 截断损坏冷启动自愈、超 30 条历史上限淘汰、空/不存在 org 查询与删除安全、以及自动更新检查 25s 单飞 TTL 去重；Rust 单测增至 138 项全绿（0 警告）。
- **精修历史档案卡片排版并完成终版双主题 1:1 复拍**：左栏历史归档卡片第二行改为 `归属 XX · orgPrefix8` 与右侧独立状态/分数短签，消除重复分数展示。

---

## [0.3.6] - 2026-11-26

### 新增与体验升级
- **账户审计多历史账号档案永久保留、点击切换与手动删除**：
  - `account-audit-cache.json` 升级至 `v2`，按 `orgPrefix8` 独立持久化每个审计过账号的脱敏评分、云端 4 项本体状态、额度、属地与 7 项评估快照（严禁落盘任何明文 `sk` / Cookie；执行清理登录态/换号仅清本机登录目录与内存，绝不丢弃历史记录）；
  - 账户审计左栏新增「历史归档 (N)」分区，支持在「当前本机激活账号」与任意历史归档账号间一键切换回溯查看当时评分与账户状态（右侧顶部叠加只读快照提示条并保护本机修复按钮防误操作），并支持单条二次确认删除；
  - 向下兼容 `v1` 历史缓存，自动找回旧版缓存中的老号归档记录。

### 核心修复与质量收口
- **修复第 1 项「新号、支付与 KYC 后高敏观察窗」假绿与 KYC 状态未联动 Bug**：
  - 未读到注册/订阅/KYC 时间时不再误标「已过观察」，改为诚实提示「待核观察」；
  - 当云端核验查出 `personaKycStatus` 为 `expired` / `pending` / `required` / `failed` 时，右上角联动标示「实名已过期 / 待实名核验」，下方「过 KYC 后复核窗」子格立即更新为具体实名状态与高敏提醒，彻底消除「当前无实名复核观察记录」误导；
  - `Free` 无订阅账号的「支付/升级复审窗」明确标注「Free 无订阅（不适用支付复审）」。
- **修复多账号缓存覆写与核验次数串号 Bug**：
  - 覆盖默认主档案前自动抢救原有旧号快照至历史归档，且各账号 `verifyCount` 按 `orgPrefix8` 独立计数，消除新号首验显示老号累计次数的问题。
- **修复左栏「实时异常日志流」未读角标与正文自相矛盾**：
  - 存在未读或非降噪异常事件（如 OAuth 403 / 令牌交换失败）时如实呈现待核异常摘要，不再显示「近 24 小时日志平稳」。
- **NSIS 安装前自动静默卸载旧版 `currentUser` 残留**：
  - 保持 `perMachine`（带 UAC 盾）安装模式，新增 `NSIS_HOOK_PREINSTALL` 在安装前自动结束旧实例并清理 `%LOCALAPPDATA%\FD Claude Guard` 残留与 HKCU 旧卸载项，杜绝新旧双份共存。
- **其他实机体验与工程优化**：
  - 修复 `cargo test` 单元测试向真实 `%LOCALAPPDATA%\FDClaudeGuard\logs\guard-runtime-*.jsonl` 写入测试噪音的问题；
  - 为自动更新检查增加 25 秒进程级单飞缓存去重，消除启动 1.5s 内双窗重复检查与双写日志；
  - 修复账户审计左栏底部免责声明微裁切问题，优化多档案流式滚动体验。

---

## [0.3.5] - 2026-11-26

### 新增与体验升级
- **实时连接域名用途精准区分与纯自动「未收录新域」雷达**：
  - 「节点流量 → 实时连接监控」逐条标注每个域名的业务用途胶囊与大白话说明（`核心 API`、`主站与会话`、`开发者控制台`、`功能开关`、`资源 / 沙箱`、`KYC 身份核验`、`CF 人机盾`、`Stripe 支付`、`遥测 · 行为监控 / 崩溃上报 / 埋点配置 / 链路追踪` 等），并修正已被 `REJECT` 拦截的遥测连接状态为中性「已拦截」；
  - 零用户配置自动雷达：当 `Claude.exe` 等进程访问不在已知清单的陌生外部域名时，进程规则自动兜底走 `Claude-Fixed`，列表自动标出琥珀黄「未收录新域」胶囊并按需出现「未收录新域 (N)」筛选按钮。
- **守卫配置新增 Cloudflare 人机盾 & Stripe 支付同源同步开关**：
  - 默认开启「同步锁定 Cloudflare 人机盾与 Stripe 支付至 Claude-Fixed」，切换后经 `sync_clash_rule_policy` 自动热同步分流规则与 `Script.js` 并实时刷新控制台与账户审计；关闭开关后若发生跨组双 IP 串线，于建议项 `opt_exit_geo` 与账户审计槽位 12 温和提醒，不阻断启动。

### 核心修复与安全加固（C1~C7 + E1~E7）
- **彻底修复 `🇨🇳台湾` 合规节点误杀 Bug（兼容 Go RE2）**：移除三处禁区正则中的裸 `🇨🇳`（补充 `回国|回國`），并在 Rust/JS 过滤中显式保护台湾合规节点不被剔除。
- **补齐 Anthropic / Claude 规则单真源与 DNS 深度加固**：
  - 补齐 14 条第 3 层遥测拦截（根治 `browser-intake-datadoghq.com` 连字符后缀逃逸，新增 `datadoghq.eu`、`statsigcdn.com`、`featureassets.org`、`prodregistryv2.org`、`segment.io`、`api.segment.com`、`honeycomb.io`，刻意不拦截 `statsig.anthropic.com` 功能开关）；
  - 补齐 `anthropic.org`、`clau.de`、`servd-anthropic-website.b-cdn.net`、`withpersona.com` 及官方桥接进程 `chrome-native-host.exe` 至 `Claude-Fixed`（严守不锁 `accounts.google.com` 与 `node.exe` 边界）；
  - 新增 `dns.ipv6: false`、无 `fallback` 时海外加密 DoH + `fallback-filter(geoip: CN)` 与基础 `fake-ip-filter`（保护局域网与 `time.windows.com` NTP）。
- **升级运行态首命中体检引擎与持久化 `Script.js` 漂移检测（根治假绿灯）**：
  - 自上而下首命中校验核心域截胡、14 条遥测逃逸、递归解包策略组链的跨组双 IP 冲突、`find-process-mode: off`、`dns.ipv6: true` 与磁盘 `Script.js` 版本漂移，并同步联动账户审计槽位 12。
- **`Script.js` 标记块无损增量合并、回滚去痕与实时监控闭环**：
  - 升级 `Script.js` 时原地更新 `FD-CLAUDE-GUARD` 标记块，100% 保留用户自定义的 `AGY_TELEMETRY_RULES` / Google 扩展段；
  - 修复 `rollback` 撤回 Clash 规则时漏删本工具注入的 14 条 `REJECT` 遥测规则问题，实现正向升级与反向撤回 100% 双向还原；
  - 修复实时流量监控漏抓 `withpersona.com` / `clau.de` / `anthropic.org`、命中机场规则的非 `MATCH` 脱组漏报，以及启动器自身进程（`fd-claude-guard.exe`）NTP 校时探测自报风险/新域误报（E8）。

---

## [0.3.4] - 2026-11-26

### 新增与体验升级
- **账户审计多档案检测与动态天数实时演进**：
  - 账户审计左栏升级为极简多档案卡片列表，自动识别本机新登录/多端账号并在检测到多份档案时展示紧凑警示胶囊；新账号登录不再被旧账号云端缓存覆盖，主账号自动切换；
  - 注册天数、订阅天数、本机天数及过 KYC 小时数按当前时间戳实时动态递增，无需等待重验 `sessionKey` 才刷新；
  - 订阅卡片同步兼容 `Free` 胶囊展示，跨端不同号或 Free 账号绝不借用 CLI 续费日与额度。
- **守卫配置单入口自动更新卡片与真实进度**：
  - 合并双份更新入口为「客户端版本与自动更新」卡片内清晰的状态徽章（只读）+ 单一操作按钮（「检查更新 / 立即更新」），消除页面同时出现两个转圈按钮的困惑；
  - 新增 `guard://update-progress` 实时下载进度推送与 300s 网络超时、原子防重入锁，修复 NSIS 安装器启动时与 `handle.restart()` 冲突导致升级卡死的问题。
- **移除未配置后端必报错的匿名上报入口**：
  - 移除「一键匿名上报排障诊断」与无效后台遥测开关，排障统一收口至 100% 本地可控的「导出脱敏 AI 诊断包」。

### 核心修复与安全加固（46 项全仓缺陷闭环）
- **真高权限开机自启、NSIS 安装权限与守护生命周期**：
  - 开机自启改用带 `/RL HIGHEST` 的 Windows 计划任务 `FDClaudeGuard_AutoStart`，彻底修复 `requireAdministrator` 应用被系统静默拦掉无法开机自启的问题；
  - `tauri.conf.json` 切换 `installMode: "perMachine"` 并升级 `nsis/hooks.nsh` 卸载钩子（递归结束进程、移除自启任务）；
  - 修复 Kill-Hold 250ms 押运漏拦、安全启动熔断/防火墙强门禁、状态哨兵 `/configs` 瞬抖误熔断、休眠唤醒尊重 `auto_kill_switch`、单实例仅 HUD 态唤醒、退出清防火墙失败硬阻断，以及 PowerShell UTF-16LE `-EncodedCommand` 提权防取消假成功与环境变量/WinINET 实时广播生效。
- **代理引擎、禁区过滤与深度核验防误杀**：
  - 三处禁区正则（`claude-verge-override.js` / `mihomo` / `preflight`）100% 同步覆盖 `HK01`/`HK_01`/国旗 Emoji/`Macao`/`Syria`/`Cuba`；
  - `node_dns` 升级为真正注入 Fake-IP DNS 配置并热重载验收；全禁区订阅直接拦截拒写不再降级写入禁区节点；
  - 深度核验引入原子单飞锁、前置防脱组与二次代际校验；补齐 GeoIP 失败 5m 短 TTL、12 次滑动丢包窗口、`opt_webrtc` HKLM 优先、`serde_yaml` 解析 `external-controller` 及多处 Windows 中文路径/网卡 UTF-8 编码。
- **账户审计同源、原子备份还原与前端状态机稳定性**：
  - 账户审计与控制台 6 态拓扑 100% 同源；原子还原新增清理非保护区脏 WAL/LDB 并拦截目标软链穿越、保留 VM/MCP 保护区；云端探针仅 `r.ok` 判可用且网络/CF 失败撤销 60s 冷却；脱敏引擎补齐驼峰凭据与代理 URL 账密；
  - 修复深度核验迟到响应锁死主按钮、账户审计失败无限白屏、HUD 跳节点/日志被劫持回控制台、实时流量「全部标为已处理」同步后端清角标、熔断态主按钮优先级倒置、多处 `guardStore` 异步竞态与撤回中心失败提示/弹窗文案冲突。

---

## [0.3.3] - 2026-11-26

### 修复与优化
- **彻底消灭 Portal 风控门户假绿误判（多路探测 + 本地实锤融合）**：
  - `cloud_probe` 在 `portal_resp` 不可达/404/未返回明确 `"hold_notice": null` 时不再假绿为 `clear`，改为诚实返回 `unknown`（前端展示灰色「接口未返回」并提示结合本地日志与实发对话核实）；
  - 扩充云端响应全路径检测，同步扫描 `chat_conversations`/`organizations`/`account`/`kyc` 响应体与错误文案中的 `portal.anthropic.com/verify`、`can't receive replies`、`verification_required`、`account_restricted`，增补 `active_flags` 扩展词（`verif`/`portal`/`compliance`/`lock`/`review`）、`api_disabled_reason`、`billable_usage_paused_until` 与 `kyc_status` 待核验/失败态监控；
  - `account_audit` 新增按精确 `orgId` 融合本地 `claude.ai-web.log` Portal 实锤：命中当前主号的本地 Portal 验证记录且云端非明确 `clear` 时自动提升为 `local_hold`（触发挂起 · 本地日志实锤）并触发致命熔断（总分 `≤ 15`），跨号绝不误伤。
- **修复 Portal URL 归因张冠李戴与半封对话受限漏熔断**：
  - `watchdog` 与 `local_scan` 的 `RE_ORG` 正则新增匹配 URL 查询参数 `[?&]org=`，修复 `portal.anthropic.com/verify?org=B` 错归前文 `last_seen_org`（账号 A）的问题；
  - `score.rs` 新增 `chat_restricted`（`!chat_available && !is_banned`）致命熔断判定，同步覆盖桌面端审计与外部 `build_check_sk_response` 契约。
- **修复脱敏日志二次打码截断已脱敏邮箱**：
  - `maintenance::sanitize_sensitive_text` 保留已含 `***` 的可读脱敏邮箱（如 `demo***88@example.com`）不二次截断域名，同时继续严格打码明文邮箱。

---

## [0.3.2] - 2026-11-26

### 安全加固与高危缺陷修复
- **云端 `sessionKey` 零命令行明文暴露（`BUG-09`）**：将 `account_audit::cloud_probe` 调用 Windows 原生 `curl.exe` 的 `Cookie: sessionKey=...` 与代理配置改为 `--config -` 经 stdin 管道传入，严格转义并剥离控制字符防注入，彻底消除进程命令行明文可见风险。
- **备份 ZIP 还原全量防 Zip Slip（`BUG-10`）**：新增 `is_safe_zip_entry_name` 严格约束相对路径组件，阻断 Windows 盘符绝对路径（`C:\...`）、反斜杠、UNC 前缀与 `..` 路径穿越。
- **官方外链白名单精确校验 & Tauri 安全收紧（`BUG-04` / `OPT-02`）**：收紧 `open_external_url` 防前缀拼接/`@` 绕过；在 `tauri.conf.json` 启用精确 WebView CSP，并移除前端未使用的通用 `shell:allow-open` 权限。
- **修复离线检查更新死循环与更新下载直连回退（`BUG-01` / `BUG-02`）**：修复守卫配置页离线/网络失败时静默检查更新陷入无限重试循环的问题；补齐 `download_and_install_app_update` 经代理拉取元数据或下载失败自动回退直连逻辑。

### 逻辑缺陷修复与运行态优化
- **修复夏令时（DST）期间同城时区误报差 1h（`BUG-03`）**：`probe_system_timezone_consistency` 优先比对 Windows 注册表 `TimeZoneKeyName` 与推荐 Windows 时区键名，免疫悉尼/美西/英国夏令时 ±1h 偏移误报。
- **运行态交互与状态诚实化（`BUG-05` / `BUG-06` / `BUG-07` / `FIX-01` / `FIX-02`）**：
  - 节点流量页悬浮解释靠近窗口顶部时自动向下翻转防裁剪；未连接 Mihomo（0 节点）诚实显示「暂无评估节点」与未连接流量提示；
  - 环境维护分项清理确认弹窗补齐 `Esc` 键关闭支持（执行清理中禁用防误中断）；
  - 桌面悬浮窗（HUD）在 Clash 未连接时诚实展示「等待连接 Clash · 尚未锁定」与预警态，不再亮绿灯误报「稳定锁定」；
  - 正式 Release 构建隐藏日志分析调试按钮「+ 模拟高并发 429 异常」，「防封宝典」抽屉补齐 `role="dialog"` 语义；
  - 控制台接入 `guard://naked-launch-intercepted` 拦截即时危险 Toast 提醒，并补齐运行中 B 级非断链必须项横幅警示、5 重防护严防漏链、未装 CLI 自动豁免遥测与后端全量 `ack_all_log_events` 归零。
- **主窗口几何尺寸记忆与工程减负（`O-04` / `O-06` / `OPT-01`）**：
  - 持久化记住主窗口手动调整后的宽高与坐标（恢复前自动校验落在当前可用显示器工作区内防多屏拔插丢失）；
  - 移除空挂重依赖 `@heroui/react` 与 `framer-motion`（共削减 237 个冗余 npm 包）；
  - 通过构建期 `__APP_VERSION__` 统一前端版本号单一真源，补齐 `.gitattributes` 与 PR 自动 CI 门禁，并清零全部 Vitest React `act(...)` 测试警告噪音。

---

## [0.3.1] - 2026-11-26

### 新增
- **顶栏新版本提醒与官网直达入口**：
  - 后台静默检测到 GitHub Releases 新版本后，顶栏展示 `NEW · 新版发布啦` 胶囊直达升级；
  - 「守卫配置 → 客户端版本与自动更新」卡片右侧新增「立即更新 / 已是最新版本」状态按钮与「GitHub 官网」直达按钮（经白名单异步命令打开系统浏览器）；
  - 品牌副标题增加悬停气泡 `Claude is awesome, but fuck Dario!`。
- **节点流量隔离区与精确账目拆解**：
  - 顶部统计卡严格按 `订阅总数 = 名称禁区 + 评估可用 + 落地禁区 + 其他不可用` 拆账对齐；
  - 新增独立可折叠「隔离区：不可用与落地禁区节点」列表，彻底与可用节点视觉隔离。
- **节点落地州/城市与精准时区识别**：
  - 三源 GeoIP 探针同步解析落地州/城市与 IANA 时区，并给出对应 Windows 时区微调建议；判定口径明确为「同国时区即显示通过，具体州仅供精细对齐参考」。

### 修复与优化
- **高危号误判修复与全端脱敏账号展示**：
  - 修复 `watchdog` 将桌面端 Free 号背景 OAuth 403 (`len=156/164`) 误判为高危受限号的问题，与 7 类 403 消歧引擎 100% 同源；
  - 控制台单号卫生锁、冲突确认弹窗、账户审计与清理弹窗全面展示脱敏账号与来源端，不再仅显示 8 位组织号前缀。
- **清理弹窗默认全清（桌面端 + CLI）且可自主保留**：
  - 默认同时勾选桌面端与 CLI 登录态，并在对应项醒目展示各自脱敏账号，取消勾选即可明确保留指定端登录态。
- **解耦主力档案对 CLI 的强绑定 & 本地缓存诚实化**：
  - 全面兼容桌面客户端/网页端主力用户，云端 `sessionKey` 核验不再被旧 CLI 组织死锁，跨端时弹出双账号脱敏对比确认；
  - 补齐 7d 过期额度缓存校正、未核验套餐标注「本地缓存」，并将未核验态 Portal 风控门户统一为「待 sk 实证」。
- **定时任务按真实行为分级 & `sessionKey` 引导升级**：
  - 拆分近期活跃定时任务（`0~5` 绿灯，`≥ 6` 轻度黄灯 `-5` 分）与超过 72h 未变动的历史留存脚本（0 扣分不标红），仅真实跨夜机刷（`≥ 16h` 高轮次）/ 高频 429 (`≥ 3`) / 高并发判红，并附只读「打开目录查看」；
  - `sessionKey` 复制教程升级为 `F12 → Application（应用）→ Storage（存储）→ Cookies → https://claude.ai → sessionKey` + 自适应深浅主题 SVG 引导图，粘贴无效链接时即时红字纠错。

---

## [0.3.0] - 2026-11-26

### 新增
- **账户审计双层融合体系（`T-058`）**：
  - 左侧主导航升级为「控制台 → 账户审计 → 节点流量 → 环境维护 → 守卫配置」，原「日志分析」合并为账户审计第 2 分段「实时异常日志流」并支持一键切入完整取证日志台。
  - **第一层本地非侵入只读扫描**：按 `ProfileContext` 路径参数化只读解析 `~/.claude.json`、`~/.claude/.credentials.json`（编译期白名单结构体，绝不反序列化令牌）、`~/.claude/settings.json`（4 项官方隐私降噪与官方端点防反代）、`~/.claude/projects/**/*.jsonl` 增量行为节律监测及传统/MSIX 桌面端日志尾读扫描，支持 7 类 HTTP 403 精准消歧（自动降噪无害背景 OAuth 403）。
  - **第二层按需一次性云端只读核验**：支持粘贴 `sessionKey` 或整段 `Copy as cURL` 自动正则提取，复用本机 Clash 动态代理经 Windows 原生 `curl.exe` 只读查询 `/api/organizations`，智能识别 `chat` 主组织、`orgId` 防串号拦截、永久绑定工作区注册属地并长期对照出口地区，明文 `sk` 用完即焚零落盘，内置 60 秒 SHA-256 内存冷却锁。
  - **100 分纯函数风险评分与防封宝典**：8 项权重严格求和 100 分（未核/超 7 天诚实封顶 85 分，致命熔断封顶 15 分，Persona 实名过 72h 抗封加分），桌面端与预留外部 `POST /v1/audit/check-sk` 极简只读脱敏 API 契约共用同一评分内核；配套右侧滑出「防封宝典」与可折叠 100 分权重明细表。
- **客户端自动检查与一键签名更新（`T-059`）**：
  - 接入 `tauri-plugin-updater` 与 Ed25519 公钥验签（Key ID `524DD4CBF003E3FD`），优先复用本机 Clash 动态代理检查 GitHub Releases `latest.json`，代理不可用时自动回退直连。
  - 在「守卫配置」新增版本与自动更新卡片（支持手动检查与一键下载验签升级），并在 `.github/workflows/release.yml` 落地 tag 触发的 Windows NSIS 签名打包发布流水线。

### 改进与修复
- **控制台与账户审计同源联动**：
  - `claude_acct` 同源检出 CLI 与桌面端跨端混登组织差异；
  - `claude_tel` 升级为严格 4/4 官方隐私降噪项校验（补齐 `DISABLE_TELEMETRY` / `DISABLE_BUG_COMMAND`）并支持 First-Write-Wins 基线快照与 `claude_settings` 单项精准撤回；
  - 新增第 12 项必须检测项 `claude_endpoint`（官方 API 端点防反代校验与一键备份还原），`node_geo` 接入工作区归属地跨洲错配联动预警；
  - 环境维护分项清理弹窗新增第 6 项可选「CLI 凭据与历史备份清理」（默认不勾选，清理前强制 ZIP 原子备份并支持完整还原）。
- **节点稳定性与核心功能维度加固**：
  - Anthropic API 节点探测新增单次网络抖动 / 冷握手超时 450ms 自动重试，避免健康节点被瞬时毛刺误杀为离线；
  - 修复「已自动屏蔽禁区节点」统计漏算订阅中被覆写剔除节点及跨维度重复计数问题，提供去重后的真实统计；
  - 修复熔断生效期间误报防火墙残留告警、解除熔断后快照健康态与事务级防复活锁联动复位，以及多处 UI 细节修复。

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
