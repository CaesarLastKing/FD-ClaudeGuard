# 系统修改风险深度分析、可撤回安全网设计及硬核验收流程方案

> **状态**：✅ 已审批落地并通过 Gate 0 ~ Gate 5 全流程验收（已随 `v0.2.8` 商业版发布）  
> **验收留证摘要**：Gate 1（Rust 68/68 0 警告 + `tsc` 0 错 + Vitest 40/40 + `CLEAN: ZERO_CLASH_TASKKILL`）；Gate 2/3（Clash 服务模式精准撤回即时生效且 100% 保留现有订阅 `R0sXAdglK3oa` → 正向重注入 1 次热重载变绿 + `system-baseline.json` 落盘 + 中文网卡 `以太网 (#6)` 零乱码检出）；Gate 4（深/浅双主题 1440×900 真实点击急救 4 步回执与单项撤回确认弹窗，`console.error = 0`）；Gate 5（`FD Claude Guard_0.2.8_x64-setup.exe` 3.74 MB，`HAS_REQUIRE_ADMIN=True`，`LEAK_OVERRIDE_JS_PLAIN=False`）。  
> **适用范围**：`FD Claude Guard` 商业版（Windows / Tauri v2 + Rust + React）  
> **核心目标**：绝不让安全工具变成「解决不了问题、还制造不可逆断网/系统破坏」的工具；确保绝大部分宿主与 Clash 改写**可精准撤回**，确保小白用户在任何异常态都有**无门槛一键救网**出口，并用**可重复、不浮于表面的 6 道硬门禁**管控每一次发布。

---

## 一、本机断网现场实证（测试复现记录）

2026-11-25 在本机真实网络环境下采集到的铁证如下：

| 探针项 | 实测结果 | 说明 |
| :--- | :--- | :--- |
| 物理网卡 `以太网`（`ifIndex=6`）IPv4 DNS | `{127.0.0.1}` | **异常写死**（非 DHCP 自动获取） |
| 虚拟网卡 `Meta`（`ifIndex=38`）IPv4 DNS | `{198.18.0.2}` | 开启 TUN 时接管系统 DNS |
| 故障复现：向 `127.0.0.1` 解析 `www.baidu.com` | **失败**：`An existing connection was forcibly closed by the remote host` | 模拟关闭 TUN 后物理网卡直连行为，**100% 复现国内外全断网** |
| 对照实测：向路由器网关 `192.168.31.1` 解析 `www.baidu.com` | **成功**（毫秒级返回解析记录） | 恢复 DHCP 后国内直连立即恢复 |
| 对照实测：向路由器网关 `192.168.31.1` 解析订阅域名 `sub.example.com` | **成功**（返回 `203.0.113.10`） | 恢复 DHCP 后 Clash 无需开 TUN 即可正常导入订阅 |
| 物理网卡 `Tcpip6\Parameters\DisabledComponents` | 当前值为 `8` | 证明用户机器原值未必为空，**不可盲写或盲删，必须快照原值** |
| 非交互终端提权实测 | `Set-DnsClientServerAddress` 报 `PermissionDenied`；非交互式会话 `Start-Process -Verb RunAs` 报 `The request is not supported` | 发现真实权限边界：**管理员态应直接调用原生命令，非管理员态需明确提示权限不足而非静默吞错** |

**断网根因闭环结论**：
1. 直接把物理网卡 DNS 留在 `127.0.0.1` 的是 Clash Verge（在开启 TUN/DNS 接管后被强杀、异常退出或卸载时未能还原系统 DNS）；
2. 但我们旧代码存在严重间接诱因——`restart_clash_verge_process()` 虽然注释写着“平滑重启”，**实际调用的是 `taskkill /F /IM clash-verge.exe` 强制硬杀**（`TerminateProcess`），会直接跳过 Clash 的退出清理钩子，极易把用户网卡 DNS 永久卡死在 `127.0.0.1`！

---

## 二、全仓写操作深度风险审计（哪些修改会出问题？）

经全仓逐行扫描 `src-tauri/src/`，本工具共有 **10 类会对宿主 Windows 或第三方软件产生持久化写入的操作**。按破坏半径从高到低拆解如下：

### P0 级（可能导致全网断网、内网失联或代理彻底瘫痪）

#### 1. 强杀重启 Clash Verge（`taskkill /F /IM clash-verge.exe`）
- **代码位置**：`src-tauri/src/preflight/mod.rs:5183-5207`（被 `node_tun` 修复、`fix_all` 调用）
- **会出什么问题**：
  - `/F` 强制终止跳过 Clash 优雅退出流程，极易残留 `127.0.0.1` 物理网卡 DNS 或悬空的 `WinINET ProxyEnable=1`，导致用户关闭 TUN 或卸载 Clash 后国内外全部断网、重装 Clash 导不了订阅；
  - 强杀后若用户用的是便携版或非默认安装路径，还存在拉起失败导致断网的风险。
- **治理方案（治本：直接废除危险写操作）**：
  - **彻底禁止在任何修复路径对 `clash-verge.exe` 使用 `taskkill /F`**；
  - 开启/同步 TUN 改用 Mihomo 热配置接口 `PATCH /configs {"tun":{"enable":true}}` + 写 `verge.yaml` 持久化，**热生效不杀进程**；
  - 检测 `clash_verge_service` 未安装时**严禁外部硬调无参安装器、严禁先改配置再杀 Clash**，只提示引导用户通过 Clash Verge 官方「设置 → 服务模式」安装。

#### 2. 禁用物理网卡 IPv6 + 修改 `Tcpip6\Parameters\DisabledComponents`
- **代码位置**：`src-tauri/src/preflight/mod.rs:3796`
- **会出什么问题**：
  - 校园网（教育网纯 IPv6）、运营商 IPv6 专线、家庭 NAS / 局域网 IPv6 服务、部分企业 VPN 依赖 IPv6，禁用后会导致对应网络或内网设备无法访问；
  - 原代码同时改了两处（`ms_tcpip6` 网卡绑定 + 注册表 `DisabledComponents=32`），但完全没有恢复入口；且不同机器原值不同（实测本机原值就是 `8`）。
- **可撤回方案**：
  - 首次修改前快照：记录每张物理网卡的 `InterfaceIndex`、`Name`、原始 `ms_tcpip6` 开关状态，以及 `DisabledComponents` 原始 `Option<u32>`；
  - 撤回时按快照逐张恢复 `Enable-NetAdapterBinding`（注意 PowerShell 需用管道 `(Get-NetAdapter -InterfaceIndex <id>) | Enable-NetAdapterBinding -ComponentID ms_tcpip6`）并还原 `DisabledComponents` 原值（原不存在则 `Remove-ItemProperty`）。

#### 3. Windows Defender 防火墙 4 层熔断规则 & 免 UAC 计划任务
- **代码位置**：`src-tauri/src/killswitch/mod.rs:237, 486`
- **会出什么问题**：
  - 熔断触发写入 `FDClaudeGuard_KillSwitch_*` 出站拦截规则后，若用户直接关闭或卸载了本工具，规则会**永久残留**，导致 Claude 永远无法联网，重装 Claude 也无解；
  - 计划任务 `FDClaudeGuard_FirewallHelper` 会在系统里遗留无主后台任务。
- **可撤回方案**：
  - 纳入「一键网络急救」与「一键撤回全部改动」必清项；
  - 「全部撤回 / 卸载前清理」同时移除 `FDClaudeGuard_FirewallHelper` 计划任务；
  - 后续在 NSIS 安装包卸载脚本（`uninstall` hook）中也增加清理 `FDClaudeGuard_KillSwitch_*` 与计划任务的兜底命令。

---

### P1 级（可能导致代理规则污染、浏览器异常或其它开发工具断连）

#### 4. 修改 Clash Verge 配置文件（`Script.js`、`profiles.yaml`、`clash-verge.yaml`、`verge.yaml`、订阅扩展脚本）
- **代码位置**：`src-tauri/src/preflight/mod.rs:4257-5017`
- **会出什么问题**：
  - 用户原本自定义的全局 `Script.js` 分流脚本可能被覆盖；
  - `profiles.yaml` 中新增了 `uid: Script` 且修改了 `selected[0]=Claude-Fixed`，用户停用本工具后，Clash 里永远残留删不干净的策略组和规则；
  - 现有的 `.fd-bak` 若每次注入都覆盖，会冲掉首次干净备份；若撤回时粗暴用旧 `profiles.yaml` 整文件覆盖，**会把用户之后新导入的机场订阅全部抹掉**！
- **可撤回方案（精准去痕，严禁粗暴整文件覆盖 `profiles.yaml`）**：
  - **首次改动前锁定基线（First-Write-Wins）**：仅在基线尚无记录时保存 `Script.js` 原状态（存在与否 + 原内容）、`profiles.yaml` 原本是否已注册 `uid: Script`、`verge.yaml` 原本的 `enable_tun_mode`/`enable_system_proxy`、原 `mode`；
  - **精准撤回动作（「清除 Clash 策略组与规则痕迹」）**：
    1. 若原本无 `Script.js` → 删除我们写入的 `profiles/Script.js`，并从 `profiles.yaml` 中**仅移除**我们注册的 `uid: Script` 项（**完整保留用户现有和后来新增的全部订阅**）；
    2. 若原本有自定义 `Script.js` → 恢复为基线保存的原内容；
    3. 从 `profiles.yaml` 各订阅 `selected` 列表中精准删除 `Claude-Fixed` 选中项；
    4. 从 `clash-verge.yaml` 中精准剥离 `Claude-Fixed` 策略组与本工具注入的 Claude 规则块（不动当前最新节点列表），并通过 Mihomo `PUT /configs` 热重载，让策略组 1 秒内干净消失；
    5. 可选还原 `verge.yaml` 原始代理/TUN 开关设置。

#### 5. 写入 Chrome / Edge 浏览器 `WebRtcIPHandling` 组策略注册表
- **代码位置**：`src-tauri/src/preflight/mod.rs:3325`
- **会出什么问题**：
  - Chrome/Edge 菜单顶部会立刻出现「**由你的组织管理**」，小白极易恐慌以为中了流氓软件或木马；
  - 禁用非代理 UDP 会导致腾讯会议网页版、飞书、Discord 语音频道等 WebRTC 应用卡顿或无法建立点对点连接。
- **可撤回方案**：
  - 基线记录 Chrome / Edge 对应注册表 `WebRtcIPHandling` 原始值（`Option<String>`）；
  - 撤回时按基线恢复或删除 `WebRtcIPHandling` 键值（若其下无其它策略项则清理空键），浏览器重启后立刻消除「由你的组织管理」。

#### 6. 修改系统代理（WinINET）、用户/系统环境变量、`~/.claude/settings.json`
- **代码位置**：`src-tauri/src/preflight/mod.rs:1915-2010`
- **会出什么问题**：
  - 用户可能原本为 `git` / `npm` / `pip` 或其它 AI 代理工具配过公司代理、第三方 API 中转地址或自定义端口；清理或改写后会影响用户原有开发工具链；
  - 若 `WinINET ProxyEnable=1` 指向了关闭后的旧端口，会导致系统浏览器和所有走 WinINET 的应用断网。
- **可撤回方案**：
  - 首次改写前把被修改/删除的每个环境变量、`WinINET ProxyEnable/ProxyServer`、`~/.claude/settings.json` 原 `env` 片段存入基线；
  - 单项撤回支持还原原值；同时「网络急救」提供独立的“关闭悬空系统代理”兜底。

---

### P2 级（影响系统日常体验，但通常不致断网）

#### 7. 关闭 Windows 系统定位权限 & 禁用 `lfsvc` 地理定位服务
- **代码位置**：`src-tauri/src/preflight/mod.rs:2259-2275`
- **会出什么问题**：天气、地图、自动时区、夜间模式日落切换、部分依赖 Windows 定位的企业软件无法获取位置。
- **可撤回方案**：
  - 基线快照 3 处 `ConsentStore\location` 注册表原值（`HKLM` / `HKCU` / `NonPackaged`）与 `lfsvc` 原启动类型（通常为 `3=Manual`）；
  - 撤回时逐一恢复注册表原值并将 `lfsvc` 恢复为原启动类型（默认 `Manual`）。

---

### 边界明确：哪些操作**不需要**新增撤回（避免过度设计或反向破坏）

| 操作项 | 归类与处理策略 | 原因 |
| :--- | :--- | :--- |
| **8. Claude 本地数据目录清理** | **已有完整方案，直接复用** | 已具备原子事务 ZIP 快照备份与一键还原，只需在「撤回中心」展示入口即可 |
| **9. 物理网卡 `127.0.0.1` 死 DNS 恢复 DHCP** | **属于「网络急救」纠错项，不做“撤回成 127.0.0.1”** | 把网卡改回 `127.0.0.1` 只会让用户重新断网；只需在日志记录修复前旧值用于排障 |
| **10. Windows 时间同步 (`w32tm /resync`)** | **无副作用幂等校准，无需撤回** | 对齐标准网络时间不会破坏任何系统配置 |

---

## 三、「三层安全网」产品落地方案（彻底照顾小白用户）

### 第一层：首次改动前自动基线快照（First-Write-Wins）
- 存储路径：`~/.fd-claude-guard/system-baseline.json`（JSON 格式，人类可读，纳入脱敏诊断包）；
- **铁律**：
  1. 每一项系统/Clash 改写执行前，先检查该项在基线中是否已有 `original` 记录；**已有则绝不覆盖**，确保多次点击修复后仍保留“最初使用本工具前”的干净状态；
  2. 记录 `touchedByGuard: bool` 与 `lastModifiedAt`——**只撤回我们真的动过的项**，绝不盲改用户自己配好的其它设置；
  3. 每次写入基线采用「写临时文件 → 原子重命名」防掉电损坏。

### 第二层：两级撤回能力（放在「环境维护」核心区，清晰透明）
1. **「系统改动与撤回中心」逐项撤回**：
   - 以清晰列表展示 6 大可逆改动项：**Clash 策略组与覆写脚本 / 物理网卡 IPv6 / Windows 系统定位 / 浏览器 WebRTC 策略 / 系统代理与环境变量 / 防火墙熔断与计划任务**；
   - 每行只展示 3 个对小白有用的信息：① 本工具是否改动过（未改动 / 已改动）；② 当前状态 vs 改动前状态；③ **「撤回此项」** 按钮（未改动项禁用或隐藏，避免误操作）；
2. **「一键撤回全部系统改动（还原到使用前）」**：
   - 按安全逆序执行：**清除防火墙与计划任务 → 剥离 Clash `Claude-Fixed` 与脚本并热重载 → 还原代理/环境变量 → 恢复 IPv6 → 恢复系统定位与 `lfsvc` → 恢复 WebRTC 策略**；
   - 每步独立 `Result` 容错，执行完给出逐项回执（哪些已还原、哪些本来未改动、哪项失败及原因），绝不黑盒报错。

### 第三层：无门槛「一键网络急救（关代理也能上网）」—— **不锁付费墙！**
- **定位**：专门解救「关 TUN / 卸载 Clash 后国内国外全打不开、Clash 导不了订阅」的终极救命按钮；
- **入口**：同时放在「环境维护」顶部显眼处、未激活拦截页（`FeatureLockedGate` 底部辅助入口），以及控制台检测到死 DNS / 防火墙残留时的告警操作区——**无论激活与否、无论 Clash 是否运行，都能一键执行**；
- **执行 4 步硬核救网 + 现场实测验收**：
  1. 扫描所有非虚拟物理网卡（排除 `Meta/Mihomo/Wintun/Clash/TAP`），将残留 `127.0.0.1` 的 IPv4 DNS 按纯数字 `InterfaceIndex` 恢复为 DHCP 自动获取；
  2. 检测 `WinINET ProxyEnable==1` 且指向不可达本地端口时自动关闭 `ProxyEnable=0`；
  3. 清空全部 `FDClaudeGuard_KillSwitch_*` 防火墙阻断规则；
  4. 执行 `ipconfig /flushdns`，并**当场用直连（绕过代理）探测国内连通性（如 `223.5.5.5` / `www.baidu.com` DNS 解析 + HTTP HEAD）**，给小白看到明确结果：「物理网卡 DNS 已恢复自动获取，国内直连已通，现在无需开 TUN 也可正常上网和导入订阅」。

---

## 四、一套真正硬核、不浮于表面的开发测试与发布验收流程（6 道硬门禁）

彻底告别“跑个只读探针 + 老环境全绿就打包”的假验收。此后凡涉及功能发布，**必须按以下 Gate 0 ~ Gate 5 逐道打勾留证，任一门禁未过一票否决，严禁构建安装包**：

### Gate 0：写操作设计评审门禁（写代码之前）
- [ ] 列出本次改动涉及的**全部写操作**（文件、注册表、网卡、服务、进程、第三方配置）；
- [ ] 确认**零新增不可撤回的系统级改动**（每新增 1 个写操作必须同步定义其基线字段与撤回函数）；
- [ ] 确认**零强杀第三方客户端进程**（禁止 `taskkill /F` 杀 Clash 等会修改系统网络的工具）；
- [ ] 复杂改动或涉及宿主网络/交互取舍的方案，先向用户明示并获确认后再施工。

### Gate 1：静态质量 + 回归单测门禁（0 警告、0 跳过）
- [ ] `cargo test --manifest-path src-tauri/Cargo.toml`：全量通过且 **0 compiler warnings**；
- [ ] `npx tsc --noEmit`：**0 TypeScript errors**；
- [ ] `npm test`：Vitest 全量通过；
- [ ] **Bug-to-Test 铁律**：本轮修复的每一个真机 Bug，必须新增至少 1 个精准复现该故障条件的自动化单测（例如：服务模式沙箱目录排除测试、中文网卡名 UTF-8 解析测试、脱组直连禁止污染节点缓存测试、基线 First-Write-Wins 不被二次覆盖测试、Clash 精准去痕不删用户新订阅测试）。

### Gate 2：双向闭环真机实测门禁（正向修 + 反向撤，禁止“只测读不测修”）
针对本轮触及的每一类系统/Clash 写操作，在真实 Windows 机器上**逐一执行三连实测并留存命令输出日志**：
1. **记录初始态**（读取真实注册表/网卡/服务/Clash 配置文件）；
2. **执行正向操作 → 复测生效**（确认目标项真实变绿、配置真实落盘生效）；
3. **执行撤回操作 → 复测干净还原**（确认目标项 100% 回到步骤 1 的初始态，无残留键、无残留策略组、无残留防火墙规则、无断网）。

| 验收项 | 正向操作验证 | 反向撤回验证 |
| :--- | :--- | :--- |
| Clash 策略组与脚本 | `Claude-Fixed` 注入并热重载立即生效 | 撤回后 `Claude-Fixed` 消失、`Script.js` 恢复原状、**用户现有订阅 100% 完整保留** |
| 物理网卡 IPv6 | 禁用后 `ms_tcpip6=False` 且 IPv6 不可达 | 撤回后每张网卡 `ms_tcpip6` 与 `DisabledComponents` 精准还原原值 |
| Windows 系统定位 | 3 处注册表=`Deny` 且 `lfsvc=Disabled` | 撤回后注册表与 `lfsvc` 恢复原启动类型 |
| 浏览器 WebRTC 策略 | `WebRtcIPHandling` 写入生效 | 撤回后注册表键清除 |
| 系统代理与环境变量 | 冲突端口校准、体检变绿 | 撤回后还原修改前快照值 |
| 防火墙熔断与计划任务 | 规则创建生效 | 撤回后 `netsh` 查 0 规则、计划任务移除 |

### Gate 3：新客户冷启动 / 破坏性故障注入矩阵（消灭老环境幸存者偏差）
**必须脱离“本来就全绿的老环境”，主动制造以下 5 种真实糟糕现场逐项实测**：

| 编号 | 破坏性故障注入场景 | 必须通过的实测结果 |
| :--- | :--- | :--- |
| **F-01** | **重装 Clash 服务模式现场**：Clash Verge v2.x 服务模式（沙箱 `-d C:\ProgramData\clash-verge-service\...`）+ 非默认端口 `7897` + 无 `Claude-Fixed` | 一键注入命中 `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev`，1 次热重载变绿，零手动步骤 |
| **F-02** | **TUN 服务缺失 / 停用现场**：`clash_verge_service` 未安装或已停止 | 未安装时**零盲装、零强杀 Clash、零报错雪崩**，准确引导官方安装；已停止时安全启动服务 |
| **F-03** | **关 TUN 断网自救现场**：物理网卡 DNS 注入 `127.0.0.1` + 关闭 Clash TUN → 先验证 `www.baidu.com` 与订阅域名解析失败 → 点击「一键网络急救」 | 自动恢复物理网卡 DHCP，**不开 TUN 状态下** `www.baidu.com` 与订阅域名解析和直连 100% 恢复正常 |
| **F-04** | **脱组直连防栽赃现场**：移除 `Claude-Fixed` 且切到 `GLOBAL=DIRECT` 跑体检 | 界面明确提示“未建组走直连”，**绝不把 `CN` 写入任何海外节点缓存**，重启后无节点被误判拉黑 |
| **F-05** | **中文环境 & 权限边界现场**：中文网卡名（`以太网`/`WLAN`）+ 管理员/非管理员双视角 | 全程 UTF-8 零乱码；管理员态直调原生命令成功；非管理员态明确提示需管理员权限，不静默假成功 |

### Gate 4：UI 交互与双主题真机验收门禁（非静态看图）
- [ ] 浅色 & 深色双主题下检查控制台、节点流量、环境维护（含「撤回中心」与「一键网络急救」）、设置页，确认无截断、无横向溢出、无文字重叠；
- [ ] 交互验证：未激活态下确认付费功能锁定但 **「一键网络急救」依然可点可用**；弹窗 `Escape`/遮罩可关闭；撤回二次确认与执行回执清晰可见；
- [ ] 控制台零未捕获 console error / unhandled rejection。

### Gate 5：商业版发布产物安全校验与安装包实机冒烟
- [ ] `.local-private\build-secrets.json` 参与正式构建；
- [ ] 核对 Release 主程序与 NSIS 安装包版本号、体积、SHA-256；
- [ ] 二进制安全审计：`requireAdministrator` 清单存在（`HAS_REQUIRE_ADMIN=True`）、零明文覆写脚本泄露（`LEAK_OVERRIDE_PLAIN=False`）；
- [ ] 安装包在本机真实安装启动一次，走通「启动体检 → 核心修复/急救 → 撤回 → 查看日志无异常循环与报错」后方可交付用户。

---

## 五、落地施工排期（待你审批后立即执行）

若你认可本方案，我将按以下 4 步推进并逐项更新台账：
1. **第一步（核心安全加固）**：彻底移除 `taskkill /F` 强杀 Clash 逻辑，落实 `system-baseline.json`（First-Write-Wins 基线快照）；
2. **第二步（后端能力实现）**：实现 6 项系统/Clash 精准单项撤回、一键全撤、以及 4 步「一键网络急救（含直连实测）」IPC 命令与回归单测；
3. **第三步（前端 UI 落地）**：在「环境维护」落地「一键网络急救」与「系统改动与撤回中心」（并在未激活态开放「一键网络急救」入口）；
4. **第四步（严格过 Gate 1 ~ Gate 5 验收）**：真机跑通正向+反向双向闭环与 5 项故障注入矩阵，全部留证通过后再打包发布 `v0.2.8`（同时把本套 6 道验收门禁正式同步进工程规范 `AGENTS.md`）。
