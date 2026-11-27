/**
 * FD Claude Guard 脱敏诊断日志与排障工单接收服务（Cloudflare Worker + D1）
 *
 * 100% 对齐客户端 src-tauri/src/telemetry/mod.rs 契约：
 * - POST /api/v1/feedback/report  主动一键上报脱敏诊断，返回唯一工单号 FD-YYYYMMDD-XXXXXXXX
 * - POST /api/v1/telemetry/batch  后台低频 L2 高价值故障事件（熔断/防裸奔/致命报错）
 * - GET  /api/v1/admin/ticket     作者凭 Bearer ADMIN_QUERY_KEY 按工单号或最近列表查单
 * - GET  /health                  健康探针
 */

const MAX_FEEDBACK_BYTES = 512 * 1024; // 单次主动排障上报上限 512 KB
const MAX_BATCH_BYTES = 128 * 1024; // 单次 L2 批量事件上限 128 KB
const MAX_EVENTS_PER_BATCH = 15;
const RETENTION_DAYS = 14;

function jsonResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

function generateTicketId(now) {
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(now.getUTCDate()).padStart(2, "0");
  const buf = new Uint8Array(4);
  crypto.getRandomValues(buf);
  const hex = Array.from(buf, (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
  return `FD-${yyyy}${mm}${dd}-${hex}`;
}

/** 服务端兜底二次脱敏（防止旧版或异常客户端漏脱敏敏感串，同时兼容 JSON 双反斜杠与普通单反斜杠路径） */
function scrubSensitiveText(raw) {
  return String(raw || "")
    .replace(/sk-ant-[a-zA-Z0-9_-]{8,}/g, "<REDACTED:SK>")
    .replace(/eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, "<REDACTED:JWT>")
    .replace(/[A-Za-z]:\\\\Users\\\\[^\\\s"']+/gi, "<USER_HOME>")
    .replace(/[A-Za-z]:\\Users\\[^\\\s"']+/gi, "<USER_HOME>")
    .replace(/[A-Za-z]:\/Users\/[^/\s"']+/gi, "<USER_HOME>");
}

/** 单 IP 分钟级简易限流（D1 计数，防止恶意刷爆免费库） */
async function checkRateLimit(db, key, maxHits, windowSecs) {
  const now = Math.floor(Date.now() / 1000);
  const row = await db
    .prepare("SELECT hits, expires_at_unix FROM rate_limits WHERE bucket_key = ?")
    .bind(key)
    .first();

  if (!row || row.expires_at_unix <= now) {
    await db
      .prepare(
        "INSERT OR REPLACE INTO rate_limits (bucket_key, hits, expires_at_unix) VALUES (?, 1, ?)"
      )
      .bind(key, now + windowSecs)
      .run();
    return true;
  }

  if (row.hits >= maxHits) {
    return false;
  }

  await db
    .prepare("UPDATE rate_limits SET hits = hits + 1 WHERE bucket_key = ?")
    .bind(key)
    .run();
  return true;
}

async function readJsonWithLimit(request, maxBytes) {
  const raw = await request.text();
  const bytes = new TextEncoder().encode(raw).length;
  if (bytes === 0 || bytes > maxBytes) {
    return { error: `载荷大小超出限制 (${bytes} B / 上限 ${maxBytes} B)`, status: 413 };
  }
  try {
    const cleaned = scrubSensitiveText(raw);
    return { parsed: JSON.parse(cleaned), rawClean: cleaned, bytes };
  } catch {
    return { error: "无效的 JSON 请求体", status: 400 };
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const country = request.headers.get("CF-IPCountry") || "";

    if (request.method === "GET" && path === "/health") {
      return jsonResp({ ok: true, service: "fd-claude-guard-diag", storage: "d1" });
    }

    // 1. 主动一键上报脱敏排障单号
    if (request.method === "POST" && path === "/api/v1/feedback/report") {
      const allowed = await checkRateLimit(env.DB, `fb:${ip}`, 10, 3600);
      if (!allowed) {
        return jsonResp({ ok: false, message: "上报过于频繁，请稍后再试" }, 429);
      }

      const body = await readJsonWithLimit(request, MAX_FEEDBACK_BYTES);
      if (body.error) {
        return jsonResp({ ok: false, message: body.error }, body.status);
      }

      const now = new Date();
      const nowUnix = Math.floor(now.getTime() / 1000);
      const createdAtIso = now.toISOString();
      const ticketId = generateTicketId(now);
      const installHash = String(body.parsed?.install_id_hash || "anonymous").slice(0, 32);
      const appVersion = String(body.parsed?.app_version || "unknown").slice(0, 32);

      await env.DB.prepare(
        `INSERT INTO feedback_reports
         (ticket_id, install_id_hash, app_version, payload_json, bytes_size, client_country, created_at_unix, created_at_iso)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          ticketId,
          installHash,
          appVersion,
          body.rawClean,
          body.bytes,
          country.slice(0, 8),
          nowUnix,
          createdAtIso
        )
        .run();

      return jsonResp({
        ok: true,
        ticket_id: ticketId,
        created_at: createdAtIso,
        uploaded_bytes: body.bytes,
      });
    }

    // 2. 后台 L2 低频高价值脱敏故障事件批量上报
    if (request.method === "POST" && path === "/api/v1/telemetry/batch") {
      const allowed = await checkRateLimit(env.DB, `tel:${ip}`, 20, 3600);
      if (!allowed) {
        return jsonResp({ ok: false, message: "rate limited" }, 429);
      }

      const body = await readJsonWithLimit(request, MAX_BATCH_BYTES);
      if (body.error) {
        return jsonResp({ ok: false, message: body.error }, body.status);
      }

      const events = Array.isArray(body.parsed?.events) ? body.parsed.events : [];
      if (events.length === 0 || events.length > MAX_EVENTS_PER_BATCH) {
        return jsonResp({ ok: false, message: "事件数组为空或超过单批上限" }, 400);
      }

      const installHash = String(body.parsed?.install_id_hash || "anonymous").slice(0, 32);
      const appVersion = String(body.parsed?.app_version || "unknown").slice(0, 32);
      const nowUnix = Math.floor(Date.now() / 1000);

      const stmts = events.map((ev) =>
        env.DB.prepare(
          `INSERT INTO telemetry_events
           (client_event_id, install_id_hash, app_version, category, event_type, level, tag, signature, event_json, created_at_unix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          String(ev?.client_event_id || "").slice(0, 96),
          installHash,
          appVersion,
          String(ev?.category || "unknown").slice(0, 32),
          String(ev?.event_type || "unknown").slice(0, 64),
          String(ev?.level || "info").slice(0, 16),
          String(ev?.tag || "").slice(0, 64),
          String(ev?.signature || "").slice(0, 240),
          JSON.stringify(ev),
          nowUnix
        )
      );

      await env.DB.batch(stmts);
      return jsonResp({ ok: true, accepted: events.length });
    }

    // 3. 作者私有查单接口（必须配置 wrangler secret ADMIN_QUERY_KEY）
    if (request.method === "GET" && path === "/api/v1/admin/ticket") {
      const adminKey = env.ADMIN_QUERY_KEY;
      const auth = request.headers.get("Authorization") || "";
      if (!adminKey || auth !== `Bearer ${adminKey}`) {
        return jsonResp({ ok: false, message: "Unauthorized" }, 401);
      }

      const ticketId = (url.searchParams.get("id") || "").trim();
      if (ticketId) {
        const row = await env.DB.prepare(
          "SELECT ticket_id, install_id_hash, app_version, bytes_size, client_country, created_at_iso, payload_json FROM feedback_reports WHERE ticket_id = ?"
        )
          .bind(ticketId)
          .first();
        if (!row) {
          return jsonResp({ ok: false, message: "未找到该排障单号" }, 404);
        }
        return jsonResp({
          ok: true,
          report: { ...row, payload: JSON.parse(row.payload_json), payload_json: undefined },
        });
      }

      const list = await env.DB.prepare(
        "SELECT ticket_id, install_id_hash, app_version, bytes_size, client_country, created_at_iso FROM feedback_reports ORDER BY created_at_unix DESC LIMIT 30"
      ).all();
      return jsonResp({ ok: true, items: list.results || [] });
    }

    return jsonResp({ ok: false, message: "Not Found" }, 404);
  },

  /** 定时清理超过 14 天的旧记录与过期限流桶 */
  async scheduled(_event, env) {
    const cutoff = Math.floor(Date.now() / 1000) - RETENTION_DAYS * 86400;
    const now = Math.floor(Date.now() / 1000);
    await env.DB.batch([
      env.DB.prepare("DELETE FROM feedback_reports WHERE created_at_unix < ?").bind(cutoff),
      env.DB.prepare("DELETE FROM telemetry_events WHERE created_at_unix < ?").bind(cutoff),
      env.DB.prepare("DELETE FROM rate_limits WHERE expires_at_unix < ?").bind(now),
    ]);
  },
};
