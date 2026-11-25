# FD Claude 安全启动器 · 一次性密钥核销服务部署指南（Cloudflare Workers + D1）

## 1. 创建 D1 数据库并建表
```bash
npx wrangler d1 create fd_claude_guard_licenses
# 将返回的 database_id 填入 license-server/wrangler.toml
npx wrangler d1 execute fd_claude_guard_licenses --remote --file=./license-server/schema.sql
```

## 2. 使用本地脚本生成密钥对与首批激活码
```bash
node .local-private/generate-keys.mjs --count 100 --batch B202611
```
脚本会在 `.local-private/`（已在 `.gitignore` 中忽略，严禁提交）生成：
- `build-secrets.json`：构建商业版安装包时 `src-tauri/build.rs` 自动读取其中公钥与 `payload_key_hex` 并执行 AES-256-GCM 资产加密；
- `worker-secrets.txt`：服务端 3 个机密；
- `batch-<id>-keys.txt`：发卡明文密钥；
- `batch-<id>-d1.sql`：脱敏 hash SQL（数据库绝不存明文密钥）。

## 3. 写入 Workers Secrets、导入卡密并发布
```bash
cd license-server
npx wrangler secret put SERVER_SALT
npx wrangler secret put ED25519_PRIVATE_PKCS8
npx wrangler secret put PAYLOAD_KEY_HEX
npx wrangler d1 execute fd_claude_guard_licenses --remote --file=../.local-private/batch-B202611-d1.sql
npx wrangler deploy
```
部署完成后，设置环境变量 `FD_LICENSE_API_URL=https://你的worker域名/api/v1/activate` 重新 `npm run tauri build` 即可。
