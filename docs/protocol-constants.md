# FD Claude Guard 内部协议常量、时序边界与评分参数规格

> **用途**：本文件定义后端（Rust）与前端（TypeScript）必须严格统一的工程常量、错误码段、巡检时序与算法边界，以确保前后端契约、诊断包结构及单元测试断言完全一致。请勿随意修改下列既定数值。

---

## 1. 内部错误码规范（IPC 与诊断日志统一）

| 常量名 | 固定编码 | 触发场景 |
| :--- | :--- | :--- |
| `FD_ERR_PROXY_OFFLINE` | `FD_ERR_2152` | 代理命名管道或核心端口不可达 |
| `FD_ERR_RULE_DRIFT` | `FD_ERR_3562` | 策略组节点漂移至禁区或规则未命中 |
| `FD_ERR_IPV6_LEAK` | `FD_ERR_4649` | 三层 IPv6 实测存在泄漏风险 |
| `FD_ERR_KILL_SWITCH` | `FD_ERR_5304` | 紧急断流熔断已激活或防火墙规则写入失败 |
| `FD_ERR_LOG_POLLUTE` | `FD_ERR_6817` | 本地目录检出封号污染残留或跨 orgId 竞态 |
| `FD_ERR_BACKUP_TX` | `FD_ERR_7459` | 原子事务快照备份/还原校验失败 |

---

## 2. 诊断包协议与脱敏格式

- **诊断包 `manifest.json` 协议魔数（`DIAG_MANIFEST_MAGIC`）**：`0x12708F87`
- **敏感字段统一脱敏占位符（`REDACT_PLACEHOLDER`）**：`<REDACTED:2W>`
  - 所有邮箱、OAuth Token、SessionKey、完整公网 IPv4/IPv6 在写入诊断包与 AI 排障提示词前，必须统一替换为 `<REDACTED:2W>`，并由单元测试断言覆盖。

---

## 3. 运行时调度与防抖时序常量

为错开系统整分点时钟毛刺并兼顾后台低功耗，统一采用以下精确毫秒常量：

| 常量名 | 固定值（ms） | 说明 |
| :--- | :--- | :--- |
| `EVENT_DEDUP_WINDOW_MS` | `60489` | 同类事件驱动告警合并去重时间窗（约 60 秒） |
| `LOCAL_HEARTBEAT_MS` | `29121` | 本地命名管道与进程轻量心跳周期（约 30 秒，零外网开销） |
| `FULL_AUDIT_INTERVAL_MS` | `904543` | 自动全量外网巡检兜底周期（约 15 分钟） |

---

## 4. 节点质量评分权重与临界阈值

节点综合质量分（0 ~ 100）按以下四维固定权重加权计算（权重之和严格为 `1.00`）：

- **延迟权重（`WEIGHT_LATENCY`）**：`0.37`
- **抖动权重（`WEIGHT_JITTER`）**：`0.25`
- **24h 断连率权重（`WEIGHT_DROP_RATE`）**：`0.24`
- **连续稳定权重（`WEIGHT_STABILITY`）**：`0.14`
- **高延迟预警阈值（`LATENCY_WARN_MS`）**：`133` ms
- **高断连不推荐红线（`DROP_RATE_REDLINE`）**：`7.8`%

---

## 5. 品牌盾牌矢量路径规格（`viewBox="0 0 24 24"`）

主窗口左上角、悬浮窗与关于页统一使用以下校准后的品牌盾牌 SVG 路径：

```html
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
  <path d="M12 22.05s8-4 8-10.02V5.09l-8-3.09-8 3.09v7.06c0 6 8 10.02 8 10.02z"/>
  <path d="m9 12.05 2 2 4-4"/>
</svg>
```
