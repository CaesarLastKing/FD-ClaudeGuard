/**
 * 只读多端点探测引擎
 * 核心红线：
 * 1. 严格仅发送 HTTP GET 只读请求，绝不触发登出、吊销、修改配置或写入操作；
 * 2. 遇到 Cloudflare 人机挑战立即如实上报，绝不尝试绕过或破解 CAPTCHA；
 * 3. 支持 Windows 原生 curl.exe (Schannel) 与 Node 原生 fetch 双传输模式，兼容本地代理与自定义网关。
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evaluateAccountDiagnosis, selectPrimaryOrganization } from "./classifier.mjs";
import { fingerprintKey, maskEmail, maskSessionKey, sanitizePayload } from "./sanitizer.mjs";

const execFileAsync = promisify(execFile);

const DEFAULT_BASE_URL = "https://claude.ai";
const DEFAULT_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36";

/**
 * 判断响应是否为 Cloudflare 拦截/人机验证挑战
 * @param {number} statusCode
 * @param {Record<string, string>} headers
 * @param {string} bodyText
 * @returns {boolean}
 */
export function detectCloudflareChallenge(statusCode, headers, bodyText) {
  const cfMitigated = (headers["cf-mitigated"] || "").toLowerCase();
  const server = (headers["server"] || "").toLowerCase();
  const contentType = (headers["content-type"] || "").toLowerCase();
  const snippet = String(bodyText || "").slice(0, 1200).toLowerCase();

  if (cfMitigated.includes("challenge")) return true;
  if (
    (statusCode === 403 || statusCode === 503) &&
    server.includes("cloudflare") &&
    contentType.includes("text/html") &&
    (snippet.includes("just a moment") ||
      snippet.includes("cf-browser-verification") ||
      snippet.includes("challenge-platform") ||
      snippet.includes("turnstile"))
  ) {
    return true;
  }
  return false;
}

/**
 * 解析 HTTP 响应头文本为小写键字典
 * @param {string} rawHeaders
 * @returns {Record<string, string>}
 */
function parseHeaderBlock(rawHeaders) {
  const blocks = String(rawHeaders || "")
    .trim()
    .split(/\r?\n\r?\n/);
  const lastBlock = blocks[blocks.length - 1] || "";
  const map = {};
  for (const line of lastBlock.split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      const key = line.slice(0, idx).trim().toLowerCase();
      const val = line.slice(idx + 1).trim();
      map[key] = val;
    }
  }
  return map;
}

/**
 * 使用 Windows 原生 curl.exe (Schannel) 发起纯 GET 只读请求
 * @param {string} url
 * @param {string} sessionKey
 * @param {{ proxyUrl?: string, timeoutMs?: number }} options
 */
async function getWithCurl(url, sessionKey, options) {
  const start = Date.now();
  const timeoutSec = Math.max(3, Math.ceil((options.timeoutMs || 15000) / 1000));
  const marker = "__FD_HTTP_META__";
  const args = [
    "--silent",
    "--show-error",
    "--location",
    "--max-redirs",
    "3",
    "--max-time",
    String(timeoutSec),
    "--compressed",
    "--include",
    "--request",
    "GET",
    "-H",
    `Cookie: sessionKey=${sessionKey}`,
    "-H",
    "anthropic-client-platform: web_claude_ai",
    "-H",
    `User-Agent: ${DEFAULT_USER_AGENT}`,
    "-H",
    "Accept: application/json, text/plain, */*",
    "-H",
    "Accept-Language: en-US,en;q=0.9",
    "-H",
    "Referer: https://claude.ai/",
    "-H",
    "Origin: https://claude.ai",
    "-w",
    `\n${marker}%{http_code}`,
  ];

  if (options.proxyUrl) {
    args.push("--proxy", options.proxyUrl);
  }
  args.push(url);

  try {
    const { stdout } = await execFileAsync("curl.exe", args, {
      maxBuffer: 4 * 1024 * 1024,
      windowsHide: true,
    });
    const latencyMs = Date.now() - start;
    const markerIdx = stdout.lastIndexOf(marker);
    const statusCode = markerIdx >= 0 ? Number(stdout.slice(markerIdx + marker.length).trim()) || 0 : 0;
    const rawResp = markerIdx >= 0 ? stdout.slice(0, markerIdx) : stdout;

    // 分离最后一个 HTTP 响应头与正文
    const sepMatch = rawResp.match(/\r?\n\r?\n/);
    let headerPart = "";
    let bodyText = rawResp;
    if (sepMatch) {
      // 处理经代理 CONNECT 后可能出现的多段响应头
      const parts = rawResp.split(/\r?\n\r?\n/);
      let bodyStartIndex = 1;
      for (let i = 0; i < parts.length - 1; i++) {
        if (/^HTTP\/\d/i.test(parts[i].trim())) {
          bodyStartIndex = i + 1;
        } else {
          break;
        }
      }
      headerPart = parts.slice(0, bodyStartIndex).join("\r\n\r\n");
      bodyText = parts.slice(bodyStartIndex).join("\r\n\r\n").trim();
    }

    const headers = parseHeaderBlock(headerPart);
    const cfBlocked = detectCloudflareChallenge(statusCode, headers, bodyText);
    let data = null;
    try {
      data = JSON.parse(bodyText);
    } catch {
      data = null;
    }
    const isHtmlFallback =
      !cfBlocked &&
      data === null &&
      ((headers["content-type"] || "").toLowerCase().includes("text/html") ||
        /^<!doctype html|^<html/i.test(bodyText.trim()));

    return {
      ok: statusCode >= 200 && statusCode < 300 && !cfBlocked && !isHtmlFallback,
      statusCode,
      latencyMs,
      cfBlocked,
      networkError: false,
      reasonCode: cfBlocked
        ? "cloudflare_challenge"
        : isHtmlFallback
          ? "non_json_html"
          : statusCode >= 200 && statusCode < 300
            ? null
            : `http_${statusCode}`,
      errorMessage: cfBlocked ? "Cloudflare 挑战拦截" : isHtmlFallback ? "返回 HTML 非 JSON" : null,
      headers: {
        server: headers["server"] || null,
        cfRay: headers["cf-ray"] || null,
        cfMitigated: headers["cf-mitigated"] || null,
        contentType: headers["content-type"] || null,
      },
      data,
      bodyPreview: data ? null : bodyText.slice(0, 240),
    };
  } catch (err) {
    const latencyMs = Date.now() - start;
    const msg = String(err?.stderr || err?.message || "curl 执行失败");
    const isTimeout = /timed out|operation timed out|code 28/i.test(msg);
    return {
      ok: false,
      statusCode: 0,
      latencyMs,
      cfBlocked: false,
      networkError: true,
      reasonCode: isTimeout ? "timeout" : "network_error",
      errorMessage: isTimeout ? "请求超时" : msg.slice(0, 180),
      headers: {},
      data: null,
      bodyPreview: null,
    };
  }
}

/**
 * 使用 Node 原生 fetch 发起纯 GET 只读请求（直连或已配置环境代理）
 * @param {string} url
 * @param {string} sessionKey
 * @param {{ timeoutMs?: number }} options
 */
async function getWithFetch(url, sessionKey, options) {
  const start = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs || 15000);
  try {
    const resp = await fetch(url, {
      method: "GET",
      headers: {
        Cookie: `sessionKey=${sessionKey}`,
        "anthropic-client-platform": "web_claude_ai",
        "User-Agent": DEFAULT_USER_AGENT,
        Accept: "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        Referer: "https://claude.ai/",
      },
      signal: controller.signal,
    });
    const bodyText = await resp.text();
    const latencyMs = Date.now() - start;
    const headers = {};
    resp.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    const cfBlocked = detectCloudflareChallenge(resp.status, headers, bodyText);
    let data = null;
    try {
      data = JSON.parse(bodyText);
    } catch {
      data = null;
    }
    const isHtmlFallback =
      !cfBlocked &&
      data === null &&
      ((headers["content-type"] || "").toLowerCase().includes("text/html") ||
        /^<!doctype html|^<html/i.test(bodyText.trim()));
    return {
      ok: resp.ok && !cfBlocked && !isHtmlFallback,
      statusCode: resp.status,
      latencyMs,
      cfBlocked,
      networkError: false,
      reasonCode: cfBlocked
        ? "cloudflare_challenge"
        : isHtmlFallback
          ? "non_json_html"
          : resp.ok
            ? null
            : `http_${resp.status}`,
      errorMessage: cfBlocked ? "Cloudflare 挑战拦截" : isHtmlFallback ? "返回 HTML 非 JSON" : null,
      headers: {
        server: headers["server"] || null,
        cfRay: headers["cf-ray"] || null,
        cfMitigated: headers["cf-mitigated"] || null,
        contentType: headers["content-type"] || null,
      },
      data,
      bodyPreview: data ? null : bodyText.slice(0, 240),
    };
  } catch (err) {
    const latencyMs = Date.now() - start;
    const isTimeout = err?.name === "AbortError";
    return {
      ok: false,
      statusCode: 0,
      latencyMs,
      cfBlocked: false,
      networkError: true,
      reasonCode: isTimeout ? "timeout" : "network_error",
      errorMessage: isTimeout ? "请求超时" : String(err?.message || "网络异常").slice(0, 180),
      headers: {},
      data: null,
      bodyPreview: null,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 统一只读 GET 执行入口
 */
async function performReadOnlyGet(url, sessionKey, options) {
  if (options.transport === "fetch") {
    return getWithFetch(url, sessionKey, options);
  }
  return getWithCurl(url, sessionKey, options);
}

/**
 * 根据 Cloudflare cf-ray 末尾的 3 字母机场代码推断大致地区（仅覆盖常见边缘机房，辅助对比工作区归属区）
 * @param {string | null | undefined} cfRay
 */
export function parseCfEdgeColo(cfRay) {
  if (!cfRay || typeof cfRay !== "string") return null;
  const parts = cfRay.trim().split("-");
  const colo = parts.length > 1 ? parts[parts.length - 1].toUpperCase() : null;
  if (!colo || !/^[A-Z]{3}$/.test(colo)) return null;
  const coloCountryMap = {
    SJC: "us", LAX: "us", SEA: "us", SFO: "us", ORD: "us", DFW: "us", IAD: "us", EWR: "us", JFK: "us", MIA: "us", ATL: "us", DEN: "us", PHX: "us",
    NRT: "jp", KIX: "jp", HND: "jp",
    SIN: "sg",
    HKG: "hk",
    TPE: "tw",
    ICN: "kr",
    SYD: "au", MEL: "au", BNE: "au", PER: "au",
    LHR: "gb", MAN: "gb",
    FRA: "de", AMS: "nl", CDG: "fr",
    YYZ: "ca", YVR: "ca",
  };
  return { colo, country: coloCountryMap[colo] || null };
}

/**
 * 基于账号画像与本次实测网络特征，生成可执行的防封建议列表
 */
export function buildAntiBanAdvice(diagnosis, edgeInfo) {
  const advice = [];
  const geo = diagnosis.workspaceGeo ? String(diagnosis.workspaceGeo).toLowerCase() : null;
  const edgeCountry = edgeInfo?.country || null;

  if (geo && edgeCountry && geo !== edgeCountry) {
    advice.push({
      level: "warn",
      title: `出口地区与账号归属区不一致（归属 ${geo.toUpperCase()} vs 当前边缘 ${edgeInfo.colo}/${edgeCountry.toUpperCase()}）`,
      detail: `当前请求落在 ${edgeInfo.colo} 边缘节点，建议在 Clash 中锁定与 ${geo.toUpperCase()} 一致的固定干净节点，避免跨洲/跨区登录增加风控权重。`,
    });
  } else if (geo && edgeInfo?.colo) {
    advice.push({
      level: "ok",
      title: `出口区域匹配（归属 ${geo.toUpperCase()} · 边缘 ${edgeInfo.colo}）`,
      detail: "继续保持当前固定单节点，不要开启自动测速切节点或负载均衡。",
    });
  }

  if (diagnosis.kyc?.status === "verified") {
    const completedAgeDays = diagnosis.kyc.completedAt
      ? Math.floor((Date.now() - Date.parse(diagnosis.kyc.completedAt)) / 86400000)
      : null;
    advice.push({
      level: "ok",
      title: `已完成 Persona 身份核验 (verified)${completedAgeDays !== null && completedAgeDays <= 7 ? ` · 刚通过 ${completedAgeDays} 天` : ""}`,
      detail:
        completedAgeDays !== null && completedAgeDays <= 7
          ? "刚通过 KYC 的 1 周内建议保持极稳定的单 IP 与正常人工使用节奏，避免立刻高频并发或切设备。"
          : "实名核验已通过，账号基础信任度高于未验证新号。",
    });
  } else if (diagnosis.kyc?.clear === false) {
    advice.push({
      level: "danger",
      title: `KYC 处于受限状态（${diagnosis.kyc.label}）`,
      detail: "请先完成官方身份核验流程，未通过前不要尝试强行高频调用或频繁切换代理。",
    });
  }

  if (diagnosis.planLabel === "Free") {
    advice.push({
      level: "neutral",
      title: "当前为 Free 免费方案（后续升级付费注意事项）",
      detail:
        "如需升级 Pro/Max，优先使用信任度更高的正规渠道（如 Apple/Google 内购或地区匹配实体卡），避开高拒付虚拟卡段；升级前后不要更换出口 IP。",
    });
  }

  if (!diagnosis.phoneVerified) {
    advice.push({
      level: "neutral",
      title: "未绑定验证手机号",
      detail: "如遇二次验证或升级触发风控，可准备干净的对应地区正规手机号（避免接码平台公共号段）。",
    });
  }

  const legalMissing = diagnosis.accountMeta?.neverAcceptedLegalDocs || [];
  if (legalMissing.length > 0) {
    advice.push({
      level: "neutral",
      title: `存在未签署条款标记（${legalMissing.join(", ")}）`,
      detail: "通常出现在从 Console 延展到 Claude.ai 的账号，按正常网页端引导确认即可，属常规状态。",
    });
  }

  return advice;
}

/**
 * 对单个 sessionKey 执行完整的 7 维只读探测
 * @param {string} sessionKey
 * @param {{ baseUrl?: string, proxyUrl?: string, transport?: "curl" | "fetch", timeoutMs?: number, includeOptionalProbes?: boolean, maskEmailInResult?: boolean }} [options]
 */
export async function probeSessionKey(sessionKey, options = {}) {
  const startedAt = Date.now();
  const baseUrl = String(options.baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const transport = options.transport === "fetch" ? "fetch" : "curl";
  const proxyUrl = String(options.proxyUrl || "").trim();
  const timeoutMs = Number(options.timeoutMs) || 15000;
  const includeOptional = options.includeOptionalProbes !== false;
  const reqOpts = { transport, proxyUrl, timeoutMs };

  const keyFingerprint = fingerprintKey(sessionKey);
  const keyMask = maskSessionKey(sessionKey);

  // 1. 主探测：组织列表（最核心的套餐/能力/风控元数据来源）
  const orgsProbe = await performReadOnlyGet(`${baseUrl}/api/organizations`, sessionKey, reqOpts);

  // 如果组织探测直接 401/403 或被 Cloudflare 拦截或网络断连，无需再发后续请求，避免无谓触发风控
  let accountProbe = { skipped: true, statusCode: null, latencyMs: 0, ok: false, data: null };
  let kycProbe = { skipped: true, statusCode: null, latencyMs: 0, ok: false, data: null };
  let subscriptionProbe = { skipped: true, statusCode: null, latencyMs: 0, ok: false, data: null };
  let usageProbe = { skipped: true, statusCode: null, latencyMs: 0, ok: false, data: null };
  let chatProbe = { skipped: true, statusCode: null, latencyMs: 0, ok: false, data: null };
  let portalProbe = { skipped: true, statusCode: null, latencyMs: 0, ok: false, data: null };

  if (orgsProbe.ok && Array.isArray(orgsProbe.data)) {
    // 2. 账号基础画像（邮箱、创建时间、手机号校验状态、附属组织）
    accountProbe = await performReadOnlyGet(`${baseUrl}/api/account`, sessionKey, reqOpts);

    // 使用智能主组织选择（优先含 chat 能力的 Claude.ai 主组织，避免错选纯 Console API 组织导致 403）
    const primaryOrg = selectPrimaryOrganization(orgsProbe.data);
    const primaryOrgUuid = primaryOrg?.uuid || null;

    if (includeOptional && primaryOrgUuid) {
      // 低并发顺序探测，避免瞬时并发过高引起风控敏感
      kycProbe = await performReadOnlyGet(
        `${baseUrl}/api/organizations/${encodeURIComponent(primaryOrgUuid)}/kyc_status`,
        sessionKey,
        reqOpts
      );
      subscriptionProbe = await performReadOnlyGet(
        `${baseUrl}/api/organizations/${encodeURIComponent(primaryOrgUuid)}/subscription_details`,
        sessionKey,
        reqOpts
      );
      usageProbe = await performReadOnlyGet(
        `${baseUrl}/api/organizations/${encodeURIComponent(primaryOrgUuid)}/usage`,
        sessionKey,
        reqOpts
      );
      chatProbe = await performReadOnlyGet(
        `${baseUrl}/api/organizations/${encodeURIComponent(primaryOrgUuid)}/chat_conversations?limit=1`,
        sessionKey,
        reqOpts
      );
      portalProbe = await performReadOnlyGet(
        `${baseUrl}/edge-api/organizations/${encodeURIComponent(primaryOrgUuid)}/billing_portal`,
        sessionKey,
        reqOpts
      );
    }
  } else if (!orgsProbe.cfBlocked && !orgsProbe.networkError && orgsProbe.statusCode !== 401 && orgsProbe.statusCode !== 403) {
    // 若 /api/organizations 返回非 403 异常，补探一次 /api/account 确认状态
    accountProbe = await performReadOnlyGet(`${baseUrl}/api/account`, sessionKey, reqOpts);
  }

  const primaryProbe = orgsProbe.ok ? orgsProbe : accountProbe.ok ? accountProbe : orgsProbe;

  const diagnosis = evaluateAccountDiagnosis({
    accountData: accountProbe.data,
    orgsData: orgsProbe.data,
    subscriptionData: subscriptionProbe.data,
    usageData: usageProbe.data,
    chatProbe,
    kycData: kycProbe.ok ? kycProbe.data : null,
    portalProbe,
    primaryProbe,
  });

  const totalLatencyMs = Date.now() - startedAt;
  const cfEdge = parseCfEdgeColo(primaryProbe.headers?.cfRay);
  const antiBanAdvice = primaryProbe.ok ? buildAntiBanAdvice(diagnosis, cfEdge) : [];

  const isFreeNoSub = diagnosis.billingType === "none" || diagnosis.planLabel === "Free";

  const endpointSummary = (name, path, probe, extra = {}) => ({
    name,
    path,
    skipped: Boolean(probe.skipped),
    ok: Boolean(probe.ok),
    expectedForPlan: Boolean(extra.expectedForPlan),
    note: extra.note || null,
    statusCode: probe.statusCode ?? null,
    latencyMs: probe.latencyMs ?? 0,
    cfBlocked: Boolean(probe.cfBlocked),
    reasonCode: probe.reasonCode ?? null,
    cfRay: probe.headers?.cfRay ?? null,
    server: probe.headers?.server ?? null,
  });

  // 全部原始负载均经脱敏后再返回前端和落盘，确保零明文敏感信息泄漏
  const rawPayloads = {
    organizations: sanitizePayload(orgsProbe.data),
    account: sanitizePayload(accountProbe.data),
    kycStatus: sanitizePayload(kycProbe.data || kycProbe.bodyPreview),
    subscription: sanitizePayload(subscriptionProbe.data),
    usage: sanitizePayload(usageProbe.data),
    chatCheck: chatProbe.ok
      ? { accessible: true, sampleCount: Array.isArray(chatProbe.data) ? chatProbe.data.length : 0 }
      : sanitizePayload(chatProbe.data || chatProbe.bodyPreview),
    portal: sanitizePayload(portalProbe.data || portalProbe.bodyPreview),
  };

  return {
    checkedAt: new Date().toISOString(),
    keyFingerprint,
    keyMask,
    transport,
    usedProxy: Boolean(proxyUrl),
    status: diagnosis.status,
    riskLevel: diagnosis.riskLevel,
    statusCode: primaryProbe.statusCode ?? 0,
    latencyMs: totalLatencyMs,
    reasonCode: diagnosis.reasonCode,
    reasonText: diagnosis.reasonText,
    restrictionReasons: diagnosis.restrictionReasons,
    email: options.maskEmailInResult ? maskEmail(diagnosis.email) : diagnosis.email,
    emailMasked: maskEmail(diagnosis.email),
    createdAt: diagnosis.createdAt ?? null,
    orgCreatedAt: diagnosis.orgCreatedAt ?? null,
    accountCreatedAt: diagnosis.accountCreatedAt ?? null,
    accountAgeDays: diagnosis.accountAgeDays ?? null,
    orgAgeDays: diagnosis.orgAgeDays ?? null,
    accountTotalAgeDays: diagnosis.accountTotalAgeDays ?? null,
    planLabel: diagnosis.planLabel,
    planRank: diagnosis.planRank,
    planTier: diagnosis.planTier ?? null,
    analyticsPlan: diagnosis.analyticsPlan ?? null,
    workspaceGeo: diagnosis.workspaceGeo ?? null,
    freeCreditsStatus: diagnosis.freeCreditsStatus ?? null,
    modelSummary: diagnosis.modelSummary ?? null,
    cfEdge,
    antiBanAdvice,
    capabilities: diagnosis.capabilities ?? [],
    billingType: diagnosis.billingType ?? null,
    merchantOfRecord: diagnosis.merchantOfRecord ?? null,
    phoneVerified: Boolean(diagnosis.phoneVerified),
    accountMeta: diagnosis.accountMeta ?? null,
    orgCount: diagnosis.orgCount ?? 0,
    org: diagnosis.org ?? null,
    allOrgs: diagnosis.allOrgs ?? [],
    kyc: diagnosis.kyc ?? null,
    portalKyc: diagnosis.portalKyc ?? null,
    usage: diagnosis.usage ?? null,
    endpoints: [
      endpointSummary("组织与套餐", "/api/organizations", orgsProbe),
      endpointSummary("账号画像", "/api/account", accountProbe),
      endpointSummary("订阅 KYC 状态", "/api/organizations/:id/kyc_status", kycProbe),
      endpointSummary("订阅与计费", "/api/organizations/:id/subscription_details", subscriptionProbe, {
        expectedForPlan: isFreeNoSub && subscriptionProbe.statusCode === 403,
        note: isFreeNoSub && subscriptionProbe.statusCode === 403 ? "Free 无订阅" : null,
      }),
      endpointSummary("用量窗口", "/api/organizations/:id/usage", usageProbe),
      endpointSummary("对话域可读性", "/api/organizations/:id/chat_conversations?limit=1", chatProbe),
      endpointSummary("Portal 挂起检查", "/edge-api/organizations/:id/billing_portal", portalProbe),
    ],
    rawPayloads,
  };
}
