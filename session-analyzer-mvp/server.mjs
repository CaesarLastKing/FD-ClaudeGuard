/**
 * FD Claude 账户分析平台 MVP — 纯本机后端服务
 * 安全铁律：
 * 1. 仅监听 127.0.0.1（不向局域网或公网暴露）；
 * 2. 仅执行只读探测（绝不提供任何吊销/修改账号写接口）；
 * 3. 本地持久化位于已被 .gitignore 忽略的 .local-private/session-analyzer/db.json，且零明文落盘 sessionKey。
 */

import http from "node:http";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractSessionKeys, buildShareableDiagnosticBundle } from "./core/sanitizer.mjs";
import { probeSessionKey } from "./core/probe.mjs";
import { createLocalStore } from "./core/storage.mjs";
import { DEMO_ACCOUNTS } from "./core/demo-data.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WORKSPACE_ROOT = path.resolve(__dirname, "..");
const PUBLIC_DIR = path.join(__dirname, "public");
const DB_PATH = path.join(WORKSPACE_ROOT, ".local-private", "session-analyzer", "db.json");

const HOST = "127.0.0.1";
const PORT = Number(process.env.PORT || 4789);
const MAX_BATCH = 50;

const store = createLocalStore(DB_PATH);

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
};

/**
 * 快速探测本机常见代理端口（仅检查 127.0.0.1 TCP 监听状态）
 */
async function detectLocalProxies() {
  const candidates = [
    { port: 7890, label: "Clash / Mihomo (7890)" },
    { port: 7897, label: "Clash Verge (7897)" },
    { port: 7891, label: "Clash SOCKS/Mixed (7891)" },
    { port: 10809, label: "v2rayN HTTP (10809)" },
    { port: 10808, label: "v2rayN SOCKS (10808)" },
  ];

  const checks = candidates.map(
    (item) =>
      new Promise((resolve) => {
        const socket = new net.Socket();
        let settled = false;
        const finish = (open) => {
          if (settled) return;
          settled = true;
          socket.destroy();
          resolve(open ? { url: `http://127.0.0.1:${item.port}`, label: item.label, port: item.port } : null);
        };
        socket.setTimeout(250);
        socket.once("connect", () => finish(true));
        socket.once("timeout", () => finish(false));
        socket.once("error", () => finish(false));
        socket.connect(item.port, "127.0.0.1");
      })
  );

  const results = await Promise.all(checks);
  return results.filter(Boolean);
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(body);
}

async function readJsonBody(req, maxBytes = 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) {
      throw new Error("PAYLOAD_TOO_LARGE");
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  return JSON.parse(raw);
}

function serveStatic(req, res, pathname) {
  const rel = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const safePath = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!safePath.startsWith(PUBLIC_DIR) || !fs.existsSync(safePath) || fs.statSync(safePath).isDirectory()) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not Found");
    return;
  }
  const ext = path.extname(safePath).toLowerCase();
  res.writeHead(200, {
    "Content-Type": MIME_TYPES[ext] || "application/octet-stream",
    "Cache-Control": "no-store",
  });
  fs.createReadStream(safePath).pipe(res);
}

export function createAppServer() {
  return http.createServer(async (req, res) => {
    const urlObj = new URL(req.url || "/", `http://${HOST}:${PORT}`);
    const pathname = urlObj.pathname;
    const method = req.method || "GET";

    try {
      // 1. 健康检查与本机配置
      if (method === "GET" && pathname === "/api/config") {
        const proxies = await detectLocalProxies();
        return sendJson(res, 200, {
          ok: true,
          bindHost: HOST,
          port: PORT,
          mode: "read-only-local",
          maxBatch: MAX_BATCH,
          storagePath: ".local-private/session-analyzer/db.json",
          detectedProxies: proxies,
        });
      }

      // 2. 纯文本提取预览（不落盘、不发网络请求）
      if (method === "POST" && pathname === "/api/parse-preview") {
        const body = await readJsonBody(req);
        const parsed = extractSessionKeys(body.text || "", { dedupe: body.dedupe !== false });
        return sendJson(res, 200, {
          ok: true,
          count: parsed.items.length,
          duplicateCount: parsed.duplicateCount,
          unrecognizedLines: parsed.unrecognizedLines,
          preview: parsed.items.map((i) => ({
            index: i.index,
            keyMask: i.keyMask,
            keyFingerprint: i.keyFingerprint,
          })),
        });
      }

      // 3. 流式只读探测（NDJSON）
      if (method === "POST" && pathname === "/api/probe-stream") {
        const body = await readJsonBody(req);
        const rawText = typeof body.text === "string" ? body.text : "";
        const parsed = rawText
          ? extractSessionKeys(rawText, { dedupe: body.dedupe !== false }).items
          : Array.isArray(body.items)
            ? body.items
                .map((x, idx) => ({ index: idx, sessionKey: String(x?.sessionKey || "").trim() }))
                .filter((x) => x.sessionKey.startsWith("sk-ant-sid"))
            : [];

        if (parsed.length === 0) {
          return sendJson(res, 400, { ok: false, error: "未识别到有效的 sk-ant-sid... sessionKey" });
        }
        if (parsed.length > MAX_BATCH) {
          return sendJson(res, 413, { ok: false, error: `为防止高频请求触发风控，单次最多探测 ${MAX_BATCH} 条` });
        }

        const transport = body.transport === "fetch" ? "fetch" : "curl";
        const proxyUrl = String(body.proxyUrl || "").trim();
        const baseUrl = String(body.baseUrl || "https://claude.ai").trim() || "https://claude.ai";
        const includeOptionalProbes = body.includeOptionalProbes !== false;
        const saveSnapshot = body.saveSnapshot !== false;
        const maskEmailInResult = body.maskEmailInResult !== false;
        const delayBetweenMs = Math.min(Math.max(Number(body.delayBetweenMs ?? 600), 0), 5000);

        res.writeHead(200, {
          "Content-Type": "application/x-ndjson; charset=utf-8",
          "Cache-Control": "no-store",
          Connection: "keep-alive",
        });

        let aborted = false;
        req.on("close", () => {
          aborted = true;
        });

        const writeEvent = (obj) => {
          if (!aborted && !res.writableEnded) {
            res.write(`${JSON.stringify(obj)}\n`);
          }
        };

        const summary = { total: parsed.length, alive: 0, restricted: 0, invalid: 0, error: 0 };

        for (let i = 0; i < parsed.length; i++) {
          if (aborted) break;
          const item = parsed[i];
          const result = await probeSessionKey(item.sessionKey, {
            baseUrl,
            proxyUrl,
            transport,
            includeOptionalProbes,
            maskEmailInResult,
          });

          let diffs = [];
          if (saveSnapshot) {
            const saved = store.recordSnapshot(result);
            diffs = saved.diffs;
          }

          if (result.status === "alive") summary.alive += 1;
          else if (result.status === "alive-but-restricted") summary.restricted += 1;
          else if (result.status === "invalid") summary.invalid += 1;
          else summary.error += 1;

          writeEvent({
            type: "result",
            data: { ...result, index: i, diffs },
          });
          writeEvent({
            type: "progress",
            tested: i + 1,
            total: parsed.length,
          });

          // 顺序低频间隔，降低多条探测瞬时并发风控风险
          if (i < parsed.length - 1 && delayBetweenMs > 0 && !aborted) {
            await new Promise((r) => setTimeout(r, delayBetweenMs));
          }
        }

        writeEvent({ type: "done", summary });
        res.end();
        return;
      }

      // 4. 查询已保存账号与时间线
      if (method === "GET" && pathname === "/api/accounts") {
        const useDemo = urlObj.searchParams.get("demo") === "1";
        return sendJson(res, 200, {
          ok: true,
          demo: useDemo,
          accounts: useDemo ? DEMO_ACCOUNTS : store.listAccounts(),
        });
      }

      // 5. 更新账号环境归因标签
      if (method === "PUT" && pathname.startsWith("/api/accounts/") && pathname.endsWith("/tags")) {
        const fp = decodeURIComponent(pathname.slice("/api/accounts/".length, -"/tags".length));
        const body = await readJsonBody(req);
        const updated = store.updateAccountTags(fp, body);
        if (!updated) {
          return sendJson(res, 404, { ok: false, error: "未找到该账号指纹记录" });
        }
        return sendJson(res, 200, { ok: true, account: updated });
      }

      // 6. 删除单条或清空本地快照
      if (method === "DELETE" && pathname === "/api/accounts") {
        store.clearAll();
        return sendJson(res, 200, { ok: true });
      }
      if (method === "DELETE" && pathname.startsWith("/api/accounts/")) {
        const fp = decodeURIComponent(pathname.slice("/api/accounts/".length));
        const deleted = store.deleteAccount(fp);
        return sendJson(res, deleted ? 200 : 404, { ok: deleted });
      }

      // 7. 封号与风控归因分析看板
      if (method === "GET" && pathname === "/api/analytics") {
        const useDemo = urlObj.searchParams.get("demo") === "1";
        const analytics = useDemo ? store.buildAnalytics(DEMO_ACCOUNTS) : store.buildAnalytics();
        return sendJson(res, 200, { ok: true, demo: useDemo, analytics });
      }

      // 8. 生成强脱敏可分享诊断包
      if (method === "POST" && pathname === "/api/export-sanitized") {
        const body = await readJsonBody(req);
        const bundle = buildShareableDiagnosticBundle(body.result || {});
        return sendJson(res, 200, { ok: true, bundle });
      }

      // 静态前端资源
      if (method === "GET") {
        return serveStatic(req, res, pathname);
      }

      return sendJson(res, 405, { ok: false, error: "Method Not Allowed" });
    } catch (err) {
      if (err?.message === "PAYLOAD_TOO_LARGE") {
        return sendJson(res, 413, { ok: false, error: "请求体过大" });
      }
      return sendJson(res, 500, { ok: false, error: err?.message || "内部错误" });
    }
  });
}

// 仅直接运行时启动监听（便于单元测试 import）
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const server = createAppServer();
  server.listen(PORT, HOST, () => {
    console.log(`[FD Claude Account Analyzer MVP] 纯本机只读服务已启动: http://${HOST}:${PORT}`);
    console.log(`[Privacy] 仅监听 127.0.0.1，脱敏快照存储于: ${DB_PATH}`);
  });
}
