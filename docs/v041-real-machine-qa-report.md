# FD Claude Guard v0.4.1 调试态全量真机验收报告

- **验收日期**：2026-11-28
- **验收基线**：自 `v0.4.0`（Commit `96817f7`）以来的全部 `v0.4.1` 代码改动 + 第一批待办快清（`BUG-41-01~08` + `F-01/F-02` + `F-05/F-07/F-10` + `BUG-42-01~03`）
- **真机环境**：Windows 宿主机（`1473 × 1040 @ 1.3 DPR`）、真实 Clash Verge Rev + `verge-mihomo` v1.19.33 命名管道（`7890` + TUN）、真实系统计划任务（`FDClaudeGuard_AutoStart` Ready、`Clash Verge (Admin)` Running）、真实 Claude 本地目录与账户缓存、WebView2 CDP（`127.0.0.1:9223`）双窗口实测（主窗 `main` + 桌面悬浮窗 `hud`）。
- **测试边界**：全程零破坏性写入，用户原始 `config.json` 提前备份，双主题切换验证后已无损还原为 `dark`，节点与代理模式 0 改动。

---

## 一、Layer 1 全量自动化测试与静态门禁（100% 通过）

| 门禁项 | 执行命令 | 实测结果 |
| :--- | :--- | :--- |
| **9 维静态契约门禁** | `npm run check:contracts` | ✅ 通过（72 commands, 11 events, 103 CSS vars, `v0.4.1`, `GPL-3.0`） |
| **TypeScript 类型检查** | `npx tsc --noEmit` | ✅ 0 错误 |
| **前端全量单元测试** | `npm test -- --run` | ✅ 19/19 测试文件、**87/87 用例全通过** |
| **前端生产构建** | `npm run build` | ✅ 0 错误 |
| **Rust 后端全量单测（默认）** | `cargo test` | ✅ **148 passed, 0 failed, 0 警告** |
| **Rust 后端全量单测（开源特性）** | `cargo test --no-default-features` | ✅ **148 passed, 0 failed, 0 警告** |
| **调试态真机编译** | `cargo build` | ✅ 0 错误、0 警告 |

---

## 二、全部 16 项活跃改动逐项真机实测结果

| 编号 | 验收项 | 真机实测证据 | 结论 |
| :---: | :--- | :--- | :---: |
| `BUG-41-01` | 冷启动首检置位 `initial_preflight_done` + 更新失败 10m 退避 | 真机启动 9.7s 完成 19 项探针并命中单飞缓存（0ms/2ms 去重）；退避单测 `v041_r3_updater_failure_backoff_enforces_10_minutes` 通过 | ✅ 通过 |
| `BUG-41-02` | 开机自启一致 + 识别 `Clash Verge (Admin)` 计划任务 + 一次性配置迁移 | 实机实证从 `v0.4.0` 迁至 `configSchemaVersion: 1`（自动开启 `showHud/notifyEnabled`）；设置常规页准确识别 `FD Claude Guard 已开启` 与 `Clash Verge Rev 已开启` | ✅ 通过 |
| `BUG-41-03` | 控制台 19 项 KV 行零叠字、左中文右简约、安全值不误标红、零 v2 废弃文案 | CDP 逐条遍历全部 **19/19 项**：`squashed=0`、`overlaps=0`、`kOverflow=0`、`badSafe=0`、`v2Leaks=0`、`rawLeaks=0` | ✅ 通过 |
| `BUG-41-04` | 云端诊断上报字段契约 + Worker SQL | 9 维契约与 `v041_b08_feedback_payload_*` 通过；设置页常规开关首屏 `scrollOverflowPx=0`，主动上传按钮直接可见 | ✅ 通过 |
| `BUG-41-05` | 禁无代理裸连 `sk` + 唯一临时文件原子写 | 9 维契约门禁通过；配置/基线/缓存目录无残留 `.tmp` 文件 | ✅ 通过 |
| `BUG-41-06` | 账户审计历史快照留存 + 消除 `US(TPE)` + 未读红标一致 | 真机实测 `hasTpeBug=false`（准确显示 `归属 US · 出口 US`）；脉冲卡显示 `0 未读` 无粘连缺空格；单测覆盖跨号确认前落盘 | ✅ 通过 |
| `BUG-41-07` | 实时连接反查真实进程，严禁空进程假冒 `"Claude"` | 真机节点流量 → 实时连接展示浏览器/多端副文案说明，左下角 `0 残留` 与连接表逻辑自洽 | ✅ 通过 |
| `BUG-41-08` | 9 项跨界细节（`GPL-3.0` 底标、弹窗高度、`--bad-border`、`guard://killswitch`） | 真机版本更新页实测 `GPL-3.0 开源`（零 `MIT` 残留）；设置常规页零滚动首屏露出全部按钮 | ✅ 通过 |
| `F-01` | 本地封号污染残留审查实锤拦截与闭环 | 本机真实触发 Persona 实锤：`日志扫描 6 份 / 封号禁区 0 命中 / 身份认证 Persona 实锤 / 处置要求 清记录+换节点`，主蓝按钮「清理账户记录（备份）」+ 次按钮「前往节点流量更换节点」清晰直观 | ✅ 通过 |
| `F-02` | 单号卫生锁三态确认 + 去组织号/去主号 | 本机真实触发单号 `Warn`：`状态 待确认当前号 / 当前号 star***at@outlook.com / 登录端 桌面端 · Free / CLI 未登录`，全 19 项 `orgLeak=false`、`oldPrimaryWord=false` | ✅ 通过 |
| `F-05` | 拆分「高敏感观察窗」与「支付方式与账单风控」 | 真机账户审计页清晰呈现 2 张独立卡片，展开「支付方式与账单风控」内部 2×2 四格与避坑提示对齐无瑕 | ✅ 通过 |
| `F-07` | 重排「二、工具可介入防御与修复」5 项顺序（Q3） | 真机 DOM 顺序实证：`g-cloud → g-disconnect → g-mix → g-endpoint → g-telemetry` | ✅ 通过 |
| `F-10` | 侧边栏左下角状态卡间距微调 | 真机几何实测：两卡间距 `16.00px`、底部分割线 `6.00px`、按钮上距 `7.76px`、左对齐误差 `0px` | ✅ 通过 |
| `BUG-42-01` | HUD 桌面悬浮窗深浅主题实时同步且无首帧闪白 | 真机冷启动 HUD 直接 `dark`（`rgba(21,21,26,0.95)`）；主窗切 `light` HUD 实时变白底（`rgba(255,255,255,0.96)`），还原 `dark` 即时同步回深色 | ✅ 通过 |
| `BUG-42-02` | 「清理恢复」后端 15s TTL 缓存 + 节点国旗 Emoji 净化与隔离区归因 | 切入与复切「清理恢复」零转圈秒开；节点列表 `leadingFlagLeaks=0`；隔离区完整呈现 `台湾1|流媒体AI` / `实测香港（名标 TW）· AnyTLS` 一字不截 | ✅ 通过 |
| `BUG-42-03` | Mihomo 命名管道 `os error 231` 告警噪音核销 | 两轮真机全程运行日志 `0 WARN`、`0 ERROR`、`0 条 os error 231` | ✅ 通过 |

---

## 三、本次真机验收新抓获并当场根治的 5 项隐藏细节缺陷

| # | 实机发现的问题 | 修复落点 | 二轮真机复验结论 |
| :-: | :--- | :--- | :---: |
| **1** | **非管理员态下 `radar` 每 2 秒狂刷「内核退出守望者已挂载 0 轮询」日志**（遇管理员级 `verge-mihomo.exe` 时 `OpenProcess` 拒访立即返回 `false` 死循环，每天白刷 4.3 万行） | [process/mod.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/process/mod.rs#L238-L273) & [lib.rs](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src-tauri/src/lib.rs#L3561-L3607)：改为仅 `OpenProcess` 真实成功才打挂载日志，无权限时仅首记 1 条降级 `INFO` 并 10s 低频休眠 | ✅ 38 秒内仅输出 1 条清晰降级日志，0 刷屏 |
| **2** | 控制台第 2 项副标题残留 Windows 退化灰字国旗 `us美国1|流媒体AI` | [ConsolePage.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/pages/ConsolePage.tsx#L16-L19) 新增 `stripFlagEmoji()` 净化列表与详情摘要 | ✅ 19 项 `flagEmojiLeak=false` |
| **3** | 控制台第 4 项左列残留 1 处英文键 `Mihomo dns.enhanced-mode` | [ConsolePage.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/pages/ConsolePage.tsx#L29) 映射为「内核 DNS 解析模式」 | ✅ 19 项除国际缩写 `CLI` 外 100% 中文 |
| **4** | 节点流量「隔离区」副标题过长导致 `（挂名 TW · 禁区隔离）` 被省略号截断 | [NodesTrafficPage.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/pages/NodesTrafficPage.tsx#L535-L547) 精简为 `实测香港（名标 TW）· AnyTLS` 并加悬停完整 `title` | ✅ 实拍复验一字不截 |
| **5** | 账户审计顶部第 3 格 `Persona 实名 KYC` 在 `expired` 时显「待验证」，与下方第 1 项「实名已过期」口径轻微不齐 | [AccountAuditPage.tsx](file:///c:/Users/xujun/Documents/ProgramProject/FDtools/src/pages/AccountAuditPage.tsx#L1674-L1687) 增加 `expired` 专属文案「实名已过期」 | ✅ 上下 100% 口径统一 |

---

## 四、非管理员调试态边界诚实说明（待 `v0.4.2` 安装包管理员态补验项）
- 本次调试态以非管理员身份运行，已实测验证**非管理员态下绝不静默假绿**（防火墙权限项诚实标黄显示 `Requires Admin / Helper`、`radar` 优雅降级不刷屏）；
- **NSIS 全新/覆盖安装钩子注册 `FDClaudeGuard_AutoStart` 与管理员态下开机自启开关正反向删除/重建计划任务闭环**，需在递增 `v0.4.2` 打包出安装包并实际安装后做最终确认（Gate 0）。
