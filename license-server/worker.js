/**
 * FD Claude 安全启动器 · 一次性密钥在线核销 & 低频高价值匿名诊断服务（Cloudflare Workers + D1）
 *
 * 必须配置的 Worker Secrets（通过 `wrangler secret put` 注入，严禁明文写入代码仓库）：
 * - SERVER_SALT           : 服务端随机盐值（与离线生码脚本保持一致）
 * - ED25519_PRIVATE_PKCS8 : Base64 编码的 PKCS#8 Ed25519 私钥 DER
 * - PAYLOAD_KEY_HEX       : 64 位十六进制（32 字节）AES-256-GCM 资产解密密钥
 * - ADMIN_TOKEN           : 开发者查询 /api/v1/admin/telemetry 的 Bearer 口令
 */

const PUBLIC_CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const ADMIN_CORS_HEADERS = {
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

const ALLOWED_LEVELS = new Set(["fail", "error", "warn"]);

function jsonResp(data, status = 200, isAdmin = false) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...(isAdmin ? ADMIN_CORS_HEADERS : PUBLIC_CORS_HEADERS),
    },
  });
}

function utf8ByteLen(text) {
  return new TextEncoder().encode(text).byteLength;
}

async function readJsonBodyWithLimit(request, maxBytes) {
  const cl = Number(request.headers.get("Content-Length") || "0");
  if (Number.isFinite(cl) && cl > maxBytes) {
    return { errorResp: jsonResp({ error: "PAYLOAD_TOO_LARGE", message: `请求体超过 ${maxBytes} 字节上限` }, 413) };
  }
  const rawText = await request.text();
  if (utf8ByteLen(rawText) > maxBytes) {
    return { errorResp: jsonResp({ error: "PAYLOAD_TOO_LARGE", message: `请求体超过 ${maxBytes} 字节上限` }, 413) };
  }
  let body;
  try {
    body = JSON.parse(rawText);
  } catch {
    return { errorResp: jsonResp({ error: "BAD_REQUEST", message: "请求体非合法 JSON" }, 400) };
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { errorResp: jsonResp({ error: "BAD_REQUEST", message: "请求体必须为 JSON 对象" }, 400) };
  }
  return { rawText, body };
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function timingSafeEqualStr(a, b) {
  const enc = new TextEncoder();
  const ba = enc.encode(a);
  const bb = enc.encode(b);
  if (ba.byteLength !== bb.byteLength) return false;
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(ba, bb);
  }
  let diff = 0;
  for (let i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
  return diff === 0;
}

/**
 * 轻量 D1 固定窗口频控：按 (route + clientIpHash + windowBucket) 限流，防止 D1 配额打爆与激活码穷举
 */
async function checkRateLimit(request, env, routeKey, maxHits, windowMinutes) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const nowMs = Date.now();
  const winId = Math.floor(nowMs / (windowMinutes * 60 * 1000));
  const ipHash = (await sha256Hex(`${routeKey}:${ip}`)).slice(0, 16);
  const bucketKey = `${routeKey}:${ipHash}:${winId}`;
  const expiresAt = new Date(nowMs + windowMinutes * 60 * 1000 + 60000).toISOString();

  try {
    const row = await env.DB.prepare(
      `INSERT INTO rate_limits (bucket_key, hits, expires_at)
       VALUES (?1, 1, ?2)
       ON CONFLICT(bucket_key) DO UPDATE SET hits = hits + 1
       RETURNING hits`
    )
      .bind(bucketKey, expiresAt)
      .first();
    if (row && Number(row.hits) > maxHits) {
      return false;
    }
  } catch {
    // 若旧环境尚未执行最新 schema.sql 建 rate_limits 表，降级放行不阻塞主业务
  }
  return true;
}

function base64ToBytes(b64) {
  const bin = atob(b64.trim());
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

async function signOfflineCert(payloadObj, privatePkcs8B64) {
  const key = await crypto.subtle.importKey(
    "pkcs8",
    base64ToBytes(privatePkcs8B64),
    { name: "Ed25519" },
    false,
    ["sign"]
  );
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payloadObj));
  const sigBuf = await crypto.subtle.sign("Ed25519", key, payloadBytes);
  const sigBytes = new Uint8Array(sigBuf);
  return `${bytesToBase64(payloadBytes)}.${bytesToBase64(sigBytes)}`;
}

function generateTicketId() {
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  // P1 扩容至 32-bit（8 位 Hex，42 亿组合）根除主键碰撞
  const randBytes = new Uint8Array(4);
  crypto.getRandomValues(randBytes);
  const hex = [...randBytes].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return `FD-${y}${m}${d}-${hex}`;
}

function safeCompactEnvJson(envObj) {
  if (!envObj || typeof envObj !== "object" || Array.isArray(envObj)) return "{}";
  const out = {};
  const keys = Object.keys(envObj).slice(0, 12);
  for (const k of keys) {
    const v = envObj[k];
    if (typeof v === "string") out[k.slice(0, 32)] = v.slice(0, 64);
    else if (typeof v === "number" || typeof v === "boolean") out[k.slice(0, 32)] = v;
  }
  const serialized = JSON.stringify(out);
  return utf8ByteLen(serialized) <= 1024 ? serialized : "{}";
}

async function handleTelemetryBatch(request, env) {
  if (!(await checkRateLimit(request, env, "telemetry", 20, 60 * 24))) {
    return jsonResp({ error: "RATE_LIMITED", message: "单日遥测上报次数已达上限" }, 429);
  }
  const parsed = await readJsonBodyWithLimit(request, 48 * 1024);
  if (parsed.errorResp) return parsed.errorResp;
  const { body } = parsed;

  const installIdHash = String(body.install_id_hash || "").trim().slice(0, 64);
  const appVersion = String(body.app_version || "0.2.6").trim().slice(0, 24);
  const events = Array.isArray(body.events) ? body.events.slice(0, 20) : [];
  if (installIdHash.length < 8 || events.length === 0) {
    return jsonResp({ error: "INVALID_TELEMETRY", message: "缺少 install_id_hash 或事件为空" }, 400);
  }

  const stmts = [];
  for (const ev of events) {
    if (!ev || typeof ev !== "object" || Array.isArray(ev)) continue;
    const category = ev.category === "claude_error" ? "claude_error" : "tool_diag";
    const eventType = String(ev.event_type || "unknown").slice(0, 64);
    const rawLevel = String(ev.level || "warn").toLowerCase();
    const level = ALLOWED_LEVELS.has(rawLevel) ? rawLevel : "warn";
    const tag = String(ev.tag || "").slice(0, 48);
    const signature = String(ev.signature || "").slice(0, 240);
    const repeatCount = Math.max(1, Math.min(999, Math.floor(Number(ev.repeat_count) || 1)));
    const preBanFactors = JSON.stringify(
      Array.isArray(ev.pre_ban_factors)
        ? ev.pre_ban_factors.slice(0, 12).map((s) => String(s).slice(0, 48))
        : []
    );
    const envJson = safeCompactEnvJson(ev.env);
    const clientEventId = String(ev.client_event_id || "").trim().slice(0, 96);
    if (!clientEventId) continue;

    stmts.push(
      env.DB.prepare(
        `INSERT OR IGNORE INTO telemetry_events
         (install_id_hash, app_version, category, event_type, level, tag, signature, repeat_count, pre_ban_factors, env_json, client_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
      ).bind(
        installIdHash,
        appVersion,
        category,
        eventType,
        level,
        tag,
        signature,
        repeatCount,
        preBanFactors,
        envJson,
        clientEventId
      )
    );
  }

  if (stmts.length === 0) {
    return jsonResp({ error: "NO_VALID_EVENTS", message: "批次中无合法事件（缺少 client_event_id）" }, 400);
  }

  // P0-8：改用 env.DB.batch 单次事务往返提交，彻底消除 30 次串行延迟
  const results = await env.DB.batch(stmts);
  let inserted = 0;
  for (const r of results) {
    inserted += Number(r?.meta?.changes || 0);
  }
  return jsonResp({ ok: true, submitted: stmts.length, accepted: inserted });
}

async function handleFeedbackReport(request, env) {
  if (!(await checkRateLimit(request, env, "feedback", 10, 60 * 24))) {
    return jsonResp({ error: "RATE_LIMITED", message: "今日匿名排障上报已达上限，请改用本地导出脱敏诊断包" }, 429);
  }
  const parsed = await readJsonBodyWithLimit(request, 96 * 1024);
  if (parsed.errorResp) return parsed.errorResp;
  const { rawText, body } = parsed;

  const installIdHash = String(body.installIdHash || body.install_id_hash || "anonymous").trim().slice(0, 64);
  const appVersion = String(body.appVersion || body.app_version || "0.2.6").trim().slice(0, 24);
  const createdAt = new Date().toISOString();

  for (let attempt = 0; attempt < 3; attempt++) {
    const ticketId = generateTicketId();
    try {
      await env.DB.prepare(
        `INSERT INTO feedback_reports (ticket_id, created_at, install_id_hash, app_version, summary_json)
         VALUES (?1, ?2, ?3, ?4, ?5)`
      )
        .bind(ticketId, createdAt, installIdHash, appVersion, rawText)
        .run();
      return jsonResp({ ok: true, ticket_id: ticketId, created_at: createdAt });
    } catch (err) {
      if (attempt === 2) throw err;
    }
  }
  return jsonResp({ error: "TICKET_CONFLICT", message: "生成单号重试失败，请稍后重试" }, 500);
}

async function handleAdminTelemetry(request, env) {
  const adminToken = String(env.ADMIN_TOKEN || "").trim();
  const auth = String(request.headers.get("Authorization") || "").trim();
  const expected = `Bearer ${adminToken}`;
  if (!adminToken || !timingSafeEqualStr(auth, expected)) {
    return jsonResp({ error: "UNAUTHORIZED", message: "未授权访问管理统计接口" }, 403, true);
  }
  const byCategoryTag = await env.DB.prepare(
    `SELECT category, tag, level, COUNT(*) AS event_count, SUM(repeat_count) AS total_hits
     FROM telemetry_events
     WHERE received_at >= datetime('now', '-7 days')
     GROUP BY category, tag, level
     ORDER BY event_count DESC
     LIMIT 50`
  ).all();
  const recentEvents = await env.DB.prepare(
    `SELECT received_at, app_version, category, event_type, level, tag, signature, pre_ban_factors, env_json
     FROM telemetry_events
     ORDER BY id DESC
     LIMIT 50`
  ).all();
  const recentTickets = await env.DB.prepare(
    `SELECT ticket_id, created_at, app_version, install_id_hash
     FROM feedback_reports
     ORDER BY created_at DESC
     LIMIT 20`
  ).all();

  return jsonResp(
    {
      ok: true,
      windowDays: 7,
      byCategoryTag: byCategoryTag.results || [],
      recentEvents: recentEvents.results || [],
      recentTickets: recentTickets.results || [],
    },
    200,
    true
  );
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const isAdminPath = url.pathname.startsWith("/api/v1/admin/");
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: isAdminPath ? ADMIN_CORS_HEADERS : PUBLIC_CORS_HEADERS,
        });
      }

      if (url.pathname === "/api/v1/health" && request.method === "GET") {
        return jsonResp({ ok: true, service: "fd-claude-guard-license" });
      }
      if (url.pathname === "/api/v1/telemetry/batch" && request.method === "POST") {
        return await handleTelemetryBatch(request, env);
      }
      if (url.pathname === "/api/v1/feedback/report" && request.method === "POST") {
        return await handleFeedbackReport(request, env);
      }
      if (url.pathname === "/api/v1/admin/telemetry" && request.method === "GET") {
        return await handleAdminTelemetry(request, env);
      }

      if (url.pathname !== "/api/v1/activate" || request.method !== "POST") {
        return jsonResp({ error: "NOT_FOUND", message: "接口不存在" }, 404);
      }

      if (!(await checkRateLimit(request, env, "activate", 15, 60))) {
        return jsonResp({ error: "RATE_LIMITED", message: "激活尝试过于频繁，请 1 小时后再试" }, 429);
      }

      const parsed = await readJsonBodyWithLimit(request, 8 * 1024);
      if (parsed.errorResp) return parsed.errorResp;
      const { body } = parsed;

      const rawKey = String(body.license_key || "").trim().toUpperCase();
      const machineFpHash = String(body.machine_fp_hash || "").trim().toLowerCase().slice(0, 128);
      const installInstanceId = String(body.install_instance_id || "").trim().slice(0, 128);
      const appVersion = String(body.app_version || "0.2.6").trim().slice(0, 24);

      if (!/^FDG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(rawKey)) {
        return jsonResp({ error: "INVALID_FORMAT", message: "激活密钥格式错误（应为 FDG-XXXX-XXXX-XXXX）" }, 400);
      }
      if (machineFpHash.length < 16 || installInstanceId.length < 16) {
        return jsonResp({ error: "INVALID_BINDING", message: "缺少客户端设备与安装实例绑定参数" }, 400);
      }

      const serverSalt = String(env.SERVER_SALT || "").trim();
      const privatePkcs8 = String(env.ED25519_PRIVATE_PKCS8 || "").trim();
      const payloadKeyHex = String(env.PAYLOAD_KEY_HEX || "").trim();

      if (!serverSalt || !privatePkcs8 || !payloadKeyHex) {
        return jsonResp({ error: "SERVER_MISCONFIG", message: "授权服务密钥未配置" }, 500);
      }

      const keyHash = await sha256Hex(`${rawKey}:${serverSalt}`);
      const installIdHash = await sha256Hex(installInstanceId);

      const row = await env.DB.prepare(
        `UPDATE licenses
         SET status = 'used',
             activated_at = datetime('now'),
             machine_fp_hash = ?2,
             install_id_hash = ?3
         WHERE key_hash = ?1 AND status = 'unused'
         RETURNING batch_id, activated_at`
      )
        .bind(keyHash, machineFpHash, installIdHash)
        .first();

      if (!row) {
        return jsonResp(
          {
            error: "KEY_USED_OR_INVALID",
            message: "激活密钥不存在、已核销作废或已撤销（一次性密钥不可复用）",
          },
          409
        );
      }

      const certPayload = {
        v: 1,
        key_hash: keyHash,
        batch_id: row.batch_id,
        machine_fp_hash: machineFpHash,
        install_id_hash: installIdHash,
        issued_at: row.activated_at,
        app_version: appVersion,
      };

      const certB64 = await signOfflineCert(certPayload, privatePkcs8);

      return jsonResp({
        ok: true,
        batch_id: row.batch_id,
        activated_at: row.activated_at,
        cert_b64: certB64,
        payload_key_hex: payloadKeyHex,
      });
    } catch (err) {
      return jsonResp({ error: "INTERNAL_ERROR", message: `服务内部异常: ${String(err?.message || err)}` }, 500);
    }
  },

  async scheduled(_event, env, ctx) {
    ctx.waitUntil(
      env.DB.batch([
        env.DB.prepare(`DELETE FROM telemetry_events WHERE received_at < datetime('now', '-30 days')`),
        env.DB.prepare(`DELETE FROM feedback_reports WHERE created_at < datetime('now', '-30 days')`),
        env.DB.prepare(`DELETE FROM rate_limits WHERE expires_at < datetime('now')`),
      ])
    );
  },
};
