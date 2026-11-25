# FD Claude 账户分析平台（本地只读 MVP）

纯本机运行、零第三方外传、零明文 `sessionKey` 落盘的 Claude 账户状态探测与风控归因分析平台原型，已按 `FDtools`（FD Claude 安全启动器）的 UI 设计规范构建，便于后续直接嵌入主项目。

## 启动方式

```powershell
node session-analyzer-mvp/server.mjs
```

启动后在浏览器访问：`http://127.0.0.1:4789`

运行核心模块自动化测试：

```powershell
node --test session-analyzer-mvp/tests/core.test.mjs
```

## 隐私与安全红线

1. **仅监听本机回环**：服务端仅绑定 `127.0.0.1:4789`，不向局域网或公网暴露。
2. **严格纯只读**：所有探测仅发送 HTTP `GET` 请求，不包含任何吊销会话或修改账号的写接口。
3. **零明文落盘**：快照保存在已被 `.gitignore` 忽略的 `.local-private/session-analyzer/db.json`，仅写入 SHA-256 指纹与脱敏邮箱，永不写入明文 `sessionKey`。
4. **强脱敏诊断包**：详情页支持一键复制强脱敏 JSON，自动清除 key、邮箱、姓名、手机号、URL Token 与真实 UUID，可用于安全排查新字段。
