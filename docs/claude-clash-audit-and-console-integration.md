# Anthropic / Claude 分流隐患专项审计与 FDtools 控制台融入方案

> **文档用途**：汇总本机 Clash Verge 实测审计发现的 Anthropic / Claude 分流与风控隐患、客观利弊权衡后的处理方案、融入 `FDtools` 控制台的完整工程落地思路，以及可直接复用的研发交接提示词。  
> **实施原则**：不在本机 `Script.js` 中手工硬改 Claude 规则，统一通过 `FDtools` 项目以「检测 → 控制台提示 → 一键可逆修复 → 双向闭环验证」的方式规范落地。

---

## 一、Anthropic / Claude 专项排查发现（实锤隐患清单）

基于本机生效配置 `clash-verge.yaml`（26,511 条规则）、`profiles.yaml` 与当前 `FDtools` 仓库源码（[claude-verge-override.js](../clash-scripts/claude-verge-override.js)、[preflight/mod.rs](../src-tauri/src/preflight/mod.rs)、[mihomo/mod.rs](../src-tauri/src/mihomo/mod.rs)）的交叉核查，共确认 **6 处运行态隐患 + 1 处项目源码潜在误杀 Bug**：

| 编号 | 风险等级 | 隐患名称 | 实测根因与证据 | 真实危害 |
| :-: | :-: | :--- | :--- | :--- |
| **C1** | **P0** | **Cloudflare 人机盾跨节点双 IP 串线** | `profiles.yaml` 中 `Claude-Fixed` 选 `🇺🇸美国1`，而机场主组 `天悦云` 选 `🇺🇸美国2`；生效规则 `R1295` 为 `DOMAIN-SUFFIX,challenges.cloudflare.com,天悦云` | 浏览器打开 `claude.ai`（美国1）弹 Turnstile 盾时，验证请求走美国2；CF Token 严格绑定出口 IP，导致无限弹盾、403 或账号风控加分 |
| **C2** | **P0** | **Datadog 遥测后缀匹配逃逸 + 新代遥测漏网** | 现有规则写的是 `DOMAIN-SUFFIX,datadoghq.com,REJECT`，但 `R1305` 的 `browser-intake-datadoghq.com` 前缀是连字符 `-` 而非点号 `.`，根本不匹配 `datadoghq.com`；此外 `datadoghq.eu`、`statsigcdn.com`、`featureassets.org`、`prodregistryv2.org`、`segment.io`、`honeycomb.io` 未拦截 | 控制台看似绿灯，实际浏览器与客户端持续向第三方遥测域上报指纹与异常事件，突破第 3 层防回传 |
| **C3** | **P0** | **KYC 核验 / 支付 / 官方关联域未锁死 `Claude-Fixed`** | 当前仅锁了 4 个主域（`anthropic.com` / `claude.ai` / `claude.com` / `claudeusercontent.com`）；以下域全落入主代理组甚至走不同节点：`withpersona.com`（`portal.anthropic.com/verify` KYC 核验）、`stripe.com` / `stripe.network`（订阅支付反欺诈）、`clau.de`、`anthropic.org`、`servd-anthropic-website.b-cdn.net` | 触发 KYC 核验或 Pro/Max 付费时，主体页面走 `Claude-Fixed` 而核验/支付接口走另一节点 IP，极易触发身份核验拒单或支付反欺诈风控 |
| **C4** | **P1** | **Claude 桥接子进程遗漏** | `PROCESS-NAME` 规则仅有 `Claude.exe`、`claude.exe`、`FD Claude Guard.exe`、`fd-claude-guard.exe`，缺少 Claude Desktop 官方 Chrome 桥接宿主进程 `chrome-native-host.exe` | 桥接进程在非域名直连或特殊上报场景下可能绕过进程级兜底 |
| **C5** | **P1** | **旧版 `Script.js` 禁区正则漏网 + 缺失 DNS 加固** | 生产环境存量旧版 `Script.js` 使用 `\bHK\b`（匹配不到无分隔符的 `HK01`），缺少 `SY`/`CU` 与国旗 Emoji，且没有 `config.dns` Fake-IP 加固与 `fallback-filter` 补全 | 换用英文紧凑命名机场（如 `HK01`）时禁区节点可能混入 `Claude-Fixed`；DNS 未加固时未命中域名的探测易走国内 DoH |
| **C6** | **P1** | **控制台规则体检口径过窄（老环境假绿灯）** | [mihomo/mod.rs](../src-tauri/src/mihomo/mod.rs#L2621-L2652) 的 `verify_claude_rules()` 只检查 `anthropic.com` 和 `claude.ai` 是否指向 `Claude-Fixed`，`verify_exit_probe_rules()` 只查 `ip-api.com` 等 3 个监测域，**完全不检查遥测拦截完整性、不检查 CF 盾/KYC 是否跨组串线、不检查 `Script.js` 版本漂移** | 用户即使运行着存在 C1~C5 漏洞的旧脚本，控制台仍显示全绿，无法感知隐患并引导一键升级 |
| **C7** | **P1（源码 Bug）** | **项目源码禁区正则误杀 `🇨🇳台湾` 合规节点** | 仓库内 [claude-verge-override.js](../clash-scripts/claude-verge-override.js#L9-L10) 与 [preflight/mod.rs](../src-tauri/src/preflight/mod.rs#L4850) 直接将 `🇨🇳` 加入禁区正则；但国内机场普遍把合规的台湾节点命名为 `🇨🇳台湾1|流媒体AI` | 用户点击一键修复写入新版模板后，原本可用的台湾节点会被误杀剔除（且 Mihomo `exclude-filter` 使用 Go RE2 引擎，**不支持** `(?!)` 负向前瞻，修复时必须注意正则引擎兼容性） |

---

## 二、建议处理方案与客观利弊分析（先亮短板再推荐）

为避免“一刀切导致误伤其他软件”，建议按 **三档策略** 分层治理：

### 第一档：默认强制纳入（纯收益、极低副作用）
1. **补齐逃逸遥测拦截（`REJECT`）**：
   - 新增：`browser-intake-datadoghq.com`、`datadoghq.eu`、`statsigcdn.com`、`featureassets.org`、`prodregistryv2.org`、`segment.io`、`api.segment.com`、`honeycomb.io`。
   - **短板/注意点**：若用户自己开发 Web 项目并在本地调试自家 Sentry/Datadog/Segment/Honeycomb 面板，全局 `REJECT` 会导致对应控制台打不开或上报失败。因此必须在控制台明确标示“第 3 层遥测拦截”来源，并支持通过一键撤回恢复或后续提供开关。
2. **补齐 Anthropic 官方关联域 & KYC 核验域至 `Claude-Fixed`**：
   - 新增：`anthropic.org`、`clau.de`、`servd-anthropic-website.b-cdn.net`、`withpersona.com`。
   - **短板/注意点**：`withpersona.com` 是第三方 KYC 服务商，若用户访问其他海外金融/交易所的 Persona 核验也会走 `Claude-Fixed`；但因 `Claude-Fixed` 本身是高纯净合规单节点，走它反而比机场随机节点更安全。
3. **补齐 Claude 官方桥接子进程**：
   - 新增：`PROCESS-NAME,chrome-native-host.exe,Claude-Fixed`。
   - **短板/注意点**：极少数其他软件也可能把 Native Messaging 宿主命名为 `chrome-native-host.exe`；若担心误伤，可仅在检测日志发现 Claude 启用了 Chrome 桥接时或按路径校验，不过走合规海外节点风险极低。
4. **修复 `🇨🇳台湾` 误杀 Bug（兼顾 Go RE2 兼容性）**：
   - **推荐做法**：从 `BLOCKED_EXCLUDE_FILTER`（给 Mihomo Go RE2 使用）与 `BLOCKED_REGION_RE` 中移除裸 `🇨🇳`（靠 `中国|中國|国内|China|(?:^|[^a-z])CN(?:[^a-z]|$)` 已可精准拦截所有大陆节点，同时保留 `🇭🇰`/`🇲🇴`/`🇷🇺`/`🇧🇾`/`🇰🇵`/`🇮🇷`/`🇸🇾`/`🇨🇺` 等无歧义国旗）；在 Rust `is_blocked_node_name()` 与 JS `safeNodes` 过滤逻辑中可额外做显式白名单兜底：若节点名含 `台湾|臺灣|Taiwan`（且不含香港/澳门/中国移动直连中转等字样），绝不误判为禁区。
   - **短板/注意点**：如果某个冷门机场节点只写了 `🇨🇳01`（既不写“中国”也不写“CN”），移除裸 `🇨🇳` 后将无法单靠名字拦住——需要靠 `FDtools` 已有的**真实落地 GeoIP 深度核验（实测 `country_code == CN`）**兜底拦截，形成“命名初筛 + 实测落地终裁”的双保险。

### 第二档：默认建议纳入，但必须向用户明示边界（或做可选开关）
1. **`challenges.cloudflare.com` 锁死 `Claude-Fixed`**
   - **收益**：彻底消除 `claude.ai` 与 Turnstile 人机盾跨节点双 IP 串线，显著降低无限弹盾与风控分。
   - **真实短板（必须先亮明）**：这是**全局域名规则**，开启后所有走浏览器过 Cloudflare 盾的其他网站（如 ChatGPT、Perplexity、各类海外论坛）的验证请求也会走 `Claude-Fixed` 节点。如果用户的机场主组（如 `天悦云`）选了日本节点，而 `Claude-Fixed` 选了美国节点，反过来会导致 **ChatGPT 网页端与 CF 盾出现跨国 IP 错位**！
   - **最优解法**：
     - **桌面端/CLI 场景**：`PROCESS-NAME,Claude.exe,Claude-Fixed` 已经天然隔离了 `Claude.exe` 内的 CF 盾，不会影响浏览器里的 ChatGPT；
     - **浏览器网页端场景**：在控制台「守卫配置」或「分流规则」提供清晰策略（推荐两种方式二选一）：
       - **方案 A（默认推荐 · 面向主力 Claude 网页用户）**：锁定 `challenges.cloudflare.com` 到 `Claude-Fixed`，并在控制台提示“若同时在浏览器使用 ChatGPT 等 CF 站点，建议将主代理组与 `Claude-Fixed` 选在同一节点”；
       - **方案 B（零干扰隔离 · 进阶开关）**：把「锁定 CF 盾与 Stripe 支付至 `Claude-Fixed`」做成守卫配置里的独立开关（默认开启或由风险检测按需一键开启），彻底把选择权交给用户。
2. **`stripe.com` / `stripe.network` 锁死 `Claude-Fixed`**
   - **收益**：确保 Pro/Max 绑卡、续费与 `claude.ai` 同出口 IP，降低支付反欺诈拒付。
   - **真实短板**：其他海外 SaaS 走 Stripe 付款也会共用 `Claude-Fixed` 节点（通常无害，反而是合规纯净节点，但如用户要给某个绑定其他地区账单的海外服务付款，可能需要临时留意）。

### 第三档：明确“刻意不拦截 / 不强锁”的边界（避免越修越坏）
1. **不拦截 `statsig.anthropic.com`**：它承载 Claude Web/Desktop 的功能开关（模型列表、Artifacts、Cowork 等），强行 `REJECT` 会造成前端功能缺失或报错。
2. **不强锁 `accounts.google.com` 到 `Claude-Fixed`**：它同时服务于 Chrome、Google Antigravity 等其他工具，强锁会破坏“不干扰 AGY / 其他应用”的产品隔离原则；改为在控制台风险雷达或防封守则中提醒“Google OAuth 登录 `claude.ai` 时尽量让主代理与 `Claude-Fixed` 同区”。
3. **不对 `node.exe` 做进程锁死**：npm 版 Claude Code CLI 运行在 `node.exe` 中，锁死 `node.exe` 会劫持本机全部 Node 开发服务；保持通过 `anthropic.com` / `claude.ai` / `claude.com` 域名规则精准接管即可。

---

## 三、如何融入现有 `FDtools` 控制台项目的完整工程思路

不另起炉灶、不破坏现有 UI 信息密度，严格沿着 `FDtools` 现有「**单真源规则 → Mihomo 运行态审计 → 控制台门禁展示 → 可逆一键热修 + 持久化 → 回归测试**」架构做增量融入：

### 1. 规则与正则真源统一（Rust + JS 模板零漂移）
- **改动位置**：
  - [clash-scripts/claude-verge-override.js](../clash-scripts/claude-verge-override.js)
  - [src-tauri/src/preflight/mod.rs](../src-tauri/src/preflight/mod.rs)（`FD_CLAUDE_FIXED_RULES` 与 `CLAUDE_BLOCKED_EXCLUDE_FILTER`）
  - [src-tauri/src/mihomo/mod.rs](../src-tauri/src/mihomo/mod.rs)（`is_blocked_node_name` 同步放行 `🇨🇳台湾` 并保留大陆/香港/澳门/俄/白俄/朝/伊/叙/古巴拦截）
- **关键工程约束**：
  - 增加一条编译期/单测一致性断言（类似现有的 `preflight` 源码比对测试），强制断言 `FD_CLAUDE_FIXED_RULES` 与 `clash-scripts/claude-verge-override.js` 的 `CLAUDE_RULES` **逐条 100% 一致**，防止以后两边改漏。
  - 若商业版构建涉及加密资产（如 `licensing::get_override_script()`），务必同步走构建资产刷新流程并验证零明文泄露门禁。

### 2. 升级运行态规则体检引擎（根治“老环境假绿灯”）
- **改动位置**：[src-tauri/src/mihomo/mod.rs](../src-tauri/src/mihomo/mod.rs#L2620-L2653) & [src-tauri/src/preflight/mod.rs](../src-tauri/src/preflight/mod.rs#L736-L820)
- **新增结构化审计函数 `audit_claude_rules(rules, proxies)`**，返回清晰的细粒度结构体 `ClaudeRuleAuditReport`：
  1. `core_domains_ok`：`anthropic.com`、`claude.ai`、`claude.com`、`claudeusercontent.com`、`clau.de`、`anthropic.org` 是否全部在首个命中即指向 `Claude-Fixed`（**注意：不能只查“规则表里有没有”，还要按自上而下顺序检查是否被前面某条 `DIRECT` 规则截胡！**）；
  2. `exit_probe_ok`：`ip-api.com`、`ipapi.is`、`ipinfo.io` 是否指向 `Claude-Fixed`；
  3. `telemetry_escape_items: Vec<String>`：逐项检查 `browser-intake-datadoghq.com`、`datadoghq.com`、`sentry.io`、`statsigapi.net`、`statsig.com`、`intercom.io`、`segment.io` 等是否首个命中即为 `REJECT`（精准抓出“前面没拦住、落到机场规则 `R1305` 放行了”的逃逸！）；
  4. `cross_group_conflicts: Vec<CrossGroupConflict>`（**高价值新能力**）：针对 `challenges.cloudflare.com`、`withpersona.com`、`stripe.com`，模拟匹配当前 Mihomo `/rules` 首个命中的策略组，再对比该策略组当前选中节点 `now` 与 `Claude-Fixed.now` 是否为同一节点——一旦不同，立刻报出具体冲突（例如：`challenges.cloudflare.com 走「天悦云 → 美国2」，与 Claude-Fixed「美国1」跨节点双 IP`）！
  5. `bridge_process_ok`：`chrome-native-host.exe`、`Claude.exe`、`claude.exe` 是否已覆盖。
- **门禁分级（克制不误拦）**：
  - **必须通过（阻断启动门禁，标红）**：核心域名缺失/被截胡、出口探针未同源、`DIRECT` 裸奔、禁区节点、`ipv6: true`。
  - **高危预警（标黄提醒、支持一键升级，但不暴力卡死正常办公）**：Datadog 等遥测逃逸、`challenges.cloudflare.com` / `withpersona.com` 跨组双 IP 串线、`Script.js` 版本落后于当前内置模板。

### 3. 升级 `Script.js` 写入机制：从“整文件覆写”进化为“标记块无损注入”（强烈推荐）
- **痛点发现**：刚才排查你本机就遇到一个真实冲突——你在自己的 `Script.js` 里加了 `AGY_TELEMETRY_RULES` 和 Google 分流优化，而目前 `FDtools` 的 `write_clash_override_script()` 是**整文件覆写** `Script.js`（虽会备份 `.bak`，但会把用户自己在 `Script.js` 里维护的其他规则冲掉！）。
- **推荐设计（标记块增量合并）**：
  - 对全新或由 `FDtools` 生成的 `Script.js`，写入带明确版本头（`// FD-CLAUDE-GUARD-SCHEMA: v2`）的完整脚本；
  - 若检测到用户 `Script.js` 包含自定义内容（如 `AGY_TELEMETRY_RULES` 或自定义函数），或包含标记块 `// === FD-CLAUDE-GUARD:RULES:BEGIN === ... END`，升级时**优先仅原地更新 FD 规则块与 `BLOCKED_REGION_RE`**，保留用户自己的非 Claude 扩展逻辑（若无法安全 AST/标记匹配，才回退到“先备份原文件再覆写”并在 Toast/日志中明示备份路径）。
- **客观短板**：标记块解析比整文件覆写复杂，如果用户手动删改了注释标记边界，可能回退到备份+覆写分支，因此必须为“空白文件 / 旧版 FD 脚本 / 带自定义扩展的脚本 / 损坏标记” 4 种形态补全 Rust 回归单测。

### 4. 前端控制台 UI 呈现（严守 `docs/ui-design-system.md`）
- **零新增页面、零视觉污染**：
  - 在现有的 [ConsolePage.tsx](../src/pages/ConsolePage.tsx)「分流规则与防泄露（`node_rules`）」体检项中，保持**静默正常、高亮异常**原则：
    - 全绿时：一行紧凑文案（如 `手动固定单节点已锁定 🇺🇸美国1 · 规则/遥测/CF盾同源已校验`）；
    - 检出 C1~C5 任意缺口时：自动标黄/标红，在证据区列出命中的具体缺口（如 `检测到 browser-intake-datadoghq.com 遥测逃逸、challenges.cloudflare.com 跨组双 IP（美国2 ≠ 美国1）`），并复用现有唯一修复按钮「一键升级分流规则」，点击后通过现有 IPC 通道完成热重载 + 持久化 + 复检闭环。
  - 在 [AccountAuditPage.tsx](../src/pages/AccountAuditPage.tsx) 槽位 12（`环境防裸奔与三端同 IP`）中，同步接入 `cross_group_conflicts` 与 `telemetry_escape_items` 信号，与 `docs/claude-desktop-audit-and-risk-slots.md` L27 的规划 100% 闭环。
  - 在 [SettingsPage.tsx](../src/pages/SettingsPage.tsx)（守卫配置）按需提供一个清晰的二级开关：「将 Cloudflare 盾与 Stripe 支付同步锁至 `Claude-Fixed`（减少网页弹盾与付费风控；若混用其他 CF 站点建议主代理同节点）」。

### 5. 回归测试与 6 道发布门禁（Gate 0 ~ Gate 5）
- **新增精准 Rust 回归单测**：
  1. `browser-intake-datadoghq.com` 在旧规则下被 `audit_claude_rules` 检出逃逸、注入新规则后通过；
  2. `challenges.cloudflare.com` 命中 `天悦云(美国2)` 而 `Claude-Fixed` 为 `美国1` 时检出 `cross_group_conflicts`，改为同节点或注入 `Claude-Fixed` 规则后通过；
  3. `is_blocked_node_name("🇨🇳台湾1|流媒体AI") == false` 且 `is_blocked_node_name("HK01") == true`、`is_blocked_node_name("🇨🇳中国直连") == true`；
  4. 校验 `CLAUDE_BLOCKED_EXCLUDE_FILTER` 能被 Rust `regex::Regex`（兼容 Go RE2，无 lookaround）正常编译且放行 `🇨🇳台湾1|流媒体AI`、拦截 `🇭🇰香港1|流媒体AI` / `HK01` / `🇺🇸中国移动`；
  5. 验证 `write_clash_override_script()` 与 `rollback` 的正向升级 → 反向撤回 100% 干净还原双向闭环。

---

## 四、可直接复用的研发交接提示词（Prompt）

将下面这段提示词直接复制到新会话中，即可让 AI 按工程规范在 `FDtools` 项目中完成设计评审与研发落地：

```markdown
请在 `FDtools` 项目中实施「Anthropic / Claude 分流规则深度加固与控制台体检闭环升级」。

先完整阅读以下背景文档与核心源码，再按规范先给出改动方案与影响面确认，经我认可后再编码：
1. 审计与方案设计文档：`docs/claude-clash-audit-and-console-integration.md`
2. 项目规范与相关源码：
   - `clash-scripts/claude-verge-override.js`
   - `src-tauri/src/mihomo/mod.rs`（`verify_claude_rules`、`verify_exit_probe_rules`、`is_blocked_node_name`）
   - `src-tauri/src/preflight/mod.rs`（`FD_CLAUDE_FIXED_RULES`、`CLAUDE_BLOCKED_EXCLUDE_FILTER`、`node_rules` 检查、热注入与 `write_clash_override_script`）
   - `src-tauri/src/rollback/mod.rs`
   - `src/pages/ConsolePage.tsx`、`src/pages/SettingsPage.tsx`、`src/pages/AccountAuditPage.tsx`
   - `docs/ui-design-system.md`

本次核心改造目标（全部通过项目自身检测与一键修复闭环实现，严禁绕过项目直接手工改本机 Clash 配置）：
1. **修复禁区正则误杀台湾节点 Bug**：修复 `clash-scripts/claude-verge-override.js`、`preflight/mod.rs` 和 `mihomo/mod.rs` 中裸 `🇨🇳` 误杀 `🇨🇳台湾1|流媒体AI` 的问题，同时确保 `exclude-filter` 100% 兼容 Go RE2（不使用负向前瞻 `(?!)`）且覆盖 `HK01` 等无单词边界命名。
2. **加固 Anthropic / Claude 规则真源**：
   - 补齐逃逸遥测拦截：`browser-intake-datadoghq.com`、`datadoghq.eu`、`statsigcdn.com`、`featureassets.org`、`prodregistryv2.org`、`segment.io`、`api.segment.com`、`honeycomb.io`（明确不拦截 `statsig.anthropic.com`）；
   - 补齐官方关联与 KYC 核验域至 `Claude-Fixed`：`anthropic.org`、`clau.de`、`servd-anthropic-website.b-cdn.net`、`withpersona.com`；
   - 补齐进程：`chrome-native-host.exe`；
   - 将 `challenges.cloudflare.com` 与 `stripe.com` / `stripe.network` 锁至 `Claude-Fixed`（在守卫配置中提供清晰的开关与跨站点说明，默认行为先与我确认）。
3. **升级运行态规则体检引擎（消除旧脚本假绿灯）**：
   - 在 `mihomo/mod.rs` 中扩展规则审计，按自上而下首命中逻辑校验：核心域未被 `DIRECT` 截胡、遥测无逃逸、`challenges.cloudflare.com` / `withpersona.com` 无跨组双 IP 串线、桥接进程已覆盖；
   - 在控制台 `node_rules` 检查项与账号审计槽位 12 精准透出缺失项与跨组冲突详情，并复用现有一键修复能力完成热注入 + 持久化升级。
4. **保护用户自定义 `Script.js` 扩展段**：评估并设计标记块增量更新机制，尽量避免一键升级 `Script.js` 时覆盖用户自己维护的非 Claude 扩展规则（如 AGY 遥测拦截、Google 代理规则），并保证与现有 First-Write-Wins `rollback` 100% 兼容。
5. **严格遵守验证铁律**：
   - 严禁对 `clash-verge.exe` 执行 `taskkill /F`；
   - 补齐上述每个 Bug 与边界场景的 Rust/前端回归单测；
   - 完成「初始旧规则态 → 控制台检出异常 → 一键修复并验证生效 → 撤回并验证 100% 还原」双向闭环验证；
   - 暂不打包发布，若后续需要打包先核对已有产出版本号。
```
