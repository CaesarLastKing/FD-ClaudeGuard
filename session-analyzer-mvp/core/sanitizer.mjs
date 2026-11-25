/**
 * 脱敏与隐私保护工具模块
 * 核心安全红线：
 * 1. 永远不向磁盘或日志写入明文 sessionKey；
 * 2. 提供邮箱、手机号、姓名、Token、UUID 等字段的递归脱敏能力；
 * 3. 支持生成可安全分享排查结构的脱敏诊断包。
 */

import crypto from "node:crypto";

const SESSION_KEY_REGEX = /sk-ant-sid(?:(?!----)[0-9A-Za-z._-])+/g;
const SENSITIVE_KEY_PATTERN =
  /(session|cookie|token|secret|password|auth|csrf|inquiry_url|verification_url|phone|email|full_name|display_name|ip_address|billing_address|card|stripe|customer_id)/i;

/**
 * 计算 sessionKey 的稳定不可逆指纹（仅用于本机多轮快照归档关联）
 * @param {string} sessionKey
 * @returns {string}
 */
export function fingerprintKey(sessionKey) {
  return crypto.createHash("sha256").update(String(sessionKey).trim()).digest("hex").slice(0, 16);
}

/**
 * 掩码显示 sessionKey（保留前缀与极短尾码便于识别）
 * @param {string} sessionKey
 * @returns {string}
 */
export function maskSessionKey(sessionKey) {
  const s = String(sessionKey || "").trim();
  if (!s) return "—";
  if (s.length <= 20) return `${s.slice(0, 8)}…`;
  return `${s.slice(0, 14)}…${s.slice(-4)}`;
}

/**
 * 邮箱脱敏（如 alice.chen@gmail.com -> al***@gmail.com）
 * @param {string | null | undefined} email
 * @returns {string | null}
 */
export function maskEmail(email) {
  if (!email || typeof email !== "string") return null;
  const trimmed = email.trim();
  const atIdx = trimmed.indexOf("@");
  if (atIdx <= 0) return "***";
  const local = trimmed.slice(0, atIdx);
  const domain = trimmed.slice(atIdx + 1);
  const visible = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2);
  return `${visible}***@${domain}`;
}

/**
 * 从任意文本中提取并去重 sk-ant-sid... 会话凭据
 * @param {string} rawText
 * @param {{ dedupe?: boolean }} [options]
 * @returns {{ items: Array<{ index: number, sessionKey: string, keyMask: string, keyFingerprint: string }>, duplicateCount: number, unrecognizedLines: number }}
 */
export function extractSessionKeys(rawText, options = {}) {
  const dedupe = options.dedupe !== false;
  const lines = String(rawText || "").split(/\r?\n/);
  const seen = new Set();
  const items = [];
  let duplicateCount = 0;
  let unrecognizedLines = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const matches = trimmed.match(SESSION_KEY_REGEX);
    if (!matches || matches.length === 0) {
      unrecognizedLines += 1;
      continue;
    }
    for (const key of matches) {
      if (dedupe && seen.has(key)) {
        duplicateCount += 1;
        continue;
      }
      seen.add(key);
      items.push({
        index: items.length,
        sessionKey: key,
        keyMask: maskSessionKey(key),
        keyFingerprint: fingerprintKey(key),
      });
    }
  }

  return { items, duplicateCount, unrecognizedLines };
}

/**
 * 脱敏字符串中可能出现的 sessionKey 或邮箱
 * @param {string} text
 * @returns {string}
 */
export function sanitizeString(text) {
  if (typeof text !== "string") return text;
  let out = text.replace(SESSION_KEY_REGEX, (m) => maskSessionKey(m));
  out = out.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, (m) => maskEmail(m) || "***");
  return out;
}

/**
 * 递归脱敏任意 JSON 对象（保留字段名、类型、布尔值、枚举与数值特征，剥离个人敏感隐私）
 * @param {unknown} value
 * @param {{ strict?: boolean, depth?: number }} [options]
 * @returns {unknown}
 */
export function sanitizePayload(value, options = {}) {
  const strict = Boolean(options.strict);
  const depth = options.depth ?? 0;
  if (depth > 12) return "[TRUNCATED_DEPTH]";
  if (value === null || value === undefined) return value;

  if (typeof value === "string") {
    if (value.length > 1500) {
      return `${sanitizeString(value.slice(0, 300))}…[len=${value.length}]`;
    }
    return sanitizeString(value);
  }

  if (typeof value !== "object") return value;

  if (Array.isArray(value)) {
    return value.slice(0, 60).map((item) => sanitizePayload(item, { strict, depth: depth + 1 }));
  }

  const result = {};
  for (const [k, v] of Object.entries(value)) {
    if (v === null || v === undefined) {
      result[k] = v;
      continue;
    }

    if (typeof v === "string") {
      if (/email/i.test(k)) {
        result[k] = strict ? "<REDACTED_EMAIL>" : maskEmail(v);
        continue;
      }
      if (/phone/i.test(k)) {
        result[k] = v ? `<PHONE_VERIFIED:${v.slice(0, 3)}***>` : null;
        continue;
      }
      if (/(full_name|display_name|first_name|last_name)/i.test(k)) {
        result[k] = v ? "<REDACTED_NAME>" : null;
        continue;
      }
      if (strict && /uuid|^id$|_id$/i.test(k) && v.length >= 16) {
        result[k] = `<UUID:${crypto.createHash("sha256").update(v).digest("hex").slice(0, 8)}>`;
        continue;
      }
      if (SENSITIVE_KEY_PATTERN.test(k)) {
        result[k] = v.startsWith("http")
          ? `<REDACTED_URL:${(() => {
              try {
                return new URL(v).origin;
              } catch {
                return "url";
              }
            })()}>`
          : `<REDACTED:${k}:${v.length}chars>`;
        continue;
      }
      result[k] = sanitizeString(v);
      continue;
    }

    result[k] = sanitizePayload(v, { strict, depth: depth + 1 });
  }
  return result;
}

/**
 * 生成可安全分享的脱敏诊断包（完全不含明文 sessionKey、真实邮箱、姓名、UUID 与 URL Token）
 * @param {object} probeResult
 * @returns {object}
 */
export function buildShareableDiagnosticBundle(probeResult) {
  return sanitizePayload(
    {
      exportedAt: new Date().toISOString(),
      schemaVersion: "1.0-sanitized",
      notice: "本诊断包已自动剥离 sessionKey、真实邮箱、姓名、手机号与可追踪 UUID，仅保留结构特征用于风控与字段分析。",
      summary: {
        status: probeResult.status,
        riskLevel: probeResult.riskLevel,
        planLabel: probeResult.planLabel,
        planTier: probeResult.planTier,
        accountAgeDays: probeResult.accountAgeDays,
        billingType: probeResult.billingType,
        merchantOfRecord: probeResult.merchantOfRecord,
        capabilities: probeResult.capabilities,
        restrictionReasons: probeResult.restrictionReasons,
        kyc: probeResult.kyc,
        portalKyc: probeResult.portalKyc,
        usage: probeResult.usage,
      },
      endpointMatrix: probeResult.endpoints,
      sanitizedRaw: probeResult.rawPayloads,
    },
    { strict: true }
  );
}
