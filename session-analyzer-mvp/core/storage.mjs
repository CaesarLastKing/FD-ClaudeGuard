/**
 * 本地脱敏快照存储与归因分析引擎
 * 存储路径默认位于已被 .gitignore 忽略的 .local-private/session-analyzer/db.json
 * 安全保证：绝不写入任何明文 sessionKey，默认仅存不可逆指纹、脱敏邮箱与状态时间线。
 */

import fs from "node:fs";
import path from "node:path";
import { maskEmail } from "./sanitizer.mjs";

const DIFF_TRACKED_FIELDS = [
  { key: "status", label: "账号状态" },
  { key: "planLabel", label: "套餐等级" },
  { key: "planTier", label: "限流分级" },
  { key: "billingType", label: "计费类型" },
  { key: "merchantOfRecord", label: "收款商户" },
  { key: "reasonText", label: "受限/状态说明" },
];

/**
 * 计算两次快照间的关键风控字段变化
 * @param {object | null} prev
 * @param {object} next
 * @returns {Array<{ field: string, label: string, before: unknown, after: unknown }>}
 */
export function computeSnapshotDiff(prev, next) {
  if (!prev) return [];
  const diffs = [];
  for (const item of DIFF_TRACKED_FIELDS) {
    const before = prev[item.key] ?? null;
    const after = next[item.key] ?? null;
    if (JSON.stringify(before) !== JSON.stringify(after)) {
      diffs.push({ field: item.key, label: item.label, before, after });
    }
  }
  const prevKyc = prev.kyc?.status ?? null;
  const nextKyc = next.kyc?.status ?? null;
  if (prevKyc !== nextKyc) {
    diffs.push({ field: "kyc.status", label: "订阅 KYC 状态", before: prevKyc, after: nextKyc });
  }
  const prevPortal = prev.portalKyc?.state ?? null;
  const nextPortal = next.portalKyc?.state ?? null;
  if (prevPortal !== nextPortal) {
    diffs.push({ field: "portalKyc.state", label: "Portal KYC 状态", before: prevPortal, after: nextPortal });
  }
  const prevFlags = JSON.stringify(prev.org?.activeFlags ?? []);
  const nextFlags = JSON.stringify(next.org?.activeFlags ?? []);
  if (prevFlags !== nextFlags) {
    diffs.push({
      field: "org.activeFlags",
      label: "组织风控标记",
      before: prev.org?.activeFlags ?? [],
      after: next.org?.activeFlags ?? [],
    });
  }
  return diffs;
}

/**
 * 创建本地 JSON 快照存储实例
 * @param {string} dbFilePath
 */
export function createLocalStore(dbFilePath) {
  function ensureDb() {
    const dir = path.dirname(dbFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    if (!fs.existsSync(dbFilePath)) {
      const initial = { version: 1, accounts: {} };
      fs.writeFileSync(dbFilePath, JSON.stringify(initial, null, 2), "utf8");
      return initial;
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(dbFilePath, "utf8"));
      if (!parsed || typeof parsed !== "object" || !parsed.accounts) {
        return { version: 1, accounts: {} };
      }
      return parsed;
    } catch {
      return { version: 1, accounts: {} };
    }
  }

  function saveDb(db) {
    const dir = path.dirname(dbFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(dbFilePath, JSON.stringify(db, null, 2), "utf8");
  }

  /**
   * 写入一次脱敏后的检测快照（永不落盘明文 sessionKey）
   * @param {object} probeResult
   */
  function recordSnapshot(probeResult) {
    const db = ensureDb();
    const fp = probeResult.keyFingerprint;
    const existing = db.accounts[fp] || {
      keyFingerprint: fp,
      keyMask: probeResult.keyMask,
      emailMasked: probeResult.emailMasked || maskEmail(probeResult.email),
      firstSeenAt: probeResult.checkedAt,
      lastSeenAt: probeResult.checkedAt,
      tags: {
        region: "",
        paymentChannel: "",
        proxyType: "",
        clientType: "",
        notes: "",
      },
      latest: null,
      history: [],
    };

    const sanitizedLatest = {
      checkedAt: probeResult.checkedAt,
      status: probeResult.status,
      riskLevel: probeResult.riskLevel,
      statusCode: probeResult.statusCode,
      latencyMs: probeResult.latencyMs,
      reasonCode: probeResult.reasonCode,
      reasonText: probeResult.reasonText,
      restrictionReasons: probeResult.restrictionReasons,
      emailMasked: probeResult.emailMasked || maskEmail(probeResult.email),
      createdAt: probeResult.createdAt,
      accountAgeDays: probeResult.accountAgeDays,
      planLabel: probeResult.planLabel,
      planTier: probeResult.planTier,
      capabilities: probeResult.capabilities,
      billingType: probeResult.billingType,
      merchantOfRecord: probeResult.merchantOfRecord,
      orgCount: probeResult.orgCount,
      org: probeResult.org,
      kyc: probeResult.kyc,
      portalKyc: probeResult.portalKyc,
      usage: probeResult.usage,
      endpoints: probeResult.endpoints,
    };

    const diffs = computeSnapshotDiff(existing.latest, sanitizedLatest);
    existing.keyMask = probeResult.keyMask;
    if (sanitizedLatest.emailMasked) {
      existing.emailMasked = sanitizedLatest.emailMasked;
    }
    existing.lastSeenAt = probeResult.checkedAt;
    existing.latest = sanitizedLatest;
    existing.history.unshift({
      checkedAt: probeResult.checkedAt,
      status: sanitizedLatest.status,
      riskLevel: sanitizedLatest.riskLevel,
      statusCode: sanitizedLatest.statusCode,
      planLabel: sanitizedLatest.planLabel,
      reasonText: sanitizedLatest.reasonText,
      kycStatus: sanitizedLatest.kyc?.status ?? null,
      portalState: sanitizedLatest.portalKyc?.state ?? null,
      fiveHourPct: sanitizedLatest.usage?.fiveHourPct ?? null,
      diffs,
    });
    // 单账号保留最近 100 条时间线快照
    if (existing.history.length > 100) {
      existing.history = existing.history.slice(0, 100);
    }

    db.accounts[fp] = existing;
    saveDb(db);
    return { account: existing, diffs };
  }

  function updateAccountTags(keyFingerprint, tags) {
    const db = ensureDb();
    const account = db.accounts[keyFingerprint];
    if (!account) return null;
    account.tags = {
      region: String(tags?.region || "").trim().slice(0, 40),
      paymentChannel: String(tags?.paymentChannel || "").trim().slice(0, 40),
      proxyType: String(tags?.proxyType || "").trim().slice(0, 40),
      clientType: String(tags?.clientType || "").trim().slice(0, 40),
      notes: String(tags?.notes || "").trim().slice(0, 300),
    };
    saveDb(db);
    return account;
  }

  function deleteAccount(keyFingerprint) {
    const db = ensureDb();
    if (!db.accounts[keyFingerprint]) return false;
    delete db.accounts[keyFingerprint];
    saveDb(db);
    return true;
  }

  function clearAll() {
    saveDb({ version: 1, accounts: {} });
  }

  function listAccounts() {
    const db = ensureDb();
    return Object.values(db.accounts).sort((a, b) => Date.parse(b.lastSeenAt) - Date.parse(a.lastSeenAt));
  }

  /**
   * 计算封号与风控归因统计摘要
   */
  function buildAnalytics(customAccounts = null) {
    const accounts = customAccounts || listAccounts();
    const totals = {
      total: accounts.length,
      alive: 0,
      restricted: 0,
      invalid: 0,
      error: 0,
    };
    const reasonCounts = {};

    const buckets = {
      byMerchant: {},
      byAge: {},
      byPlan: {},
      byProxyType: {},
      byClientType: {},
    };

    const addBucket = (map, label, status) => {
      const k = label || "未标注 / 未知";
      if (!map[k]) {
        map[k] = { label: k, total: 0, alive: 0, restricted: 0, invalid: 0, error: 0 };
      }
      map[k].total += 1;
      if (status === "alive") map[k].alive += 1;
      else if (status === "alive-but-restricted") map[k].restricted += 1;
      else if (status === "invalid") map[k].invalid += 1;
      else map[k].error += 1;
    };

    for (const acc of accounts) {
      const latest = acc.latest || {};
      const st = latest.status || "error";
      if (st === "alive") totals.alive += 1;
      else if (st === "alive-but-restricted") totals.restricted += 1;
      else if (st === "invalid") totals.invalid += 1;
      else totals.error += 1;

      for (const r of latest.restrictionReasons || []) {
        reasonCounts[r] = (reasonCounts[r] || 0) + 1;
      }

      const age = latest.accountAgeDays;
      const ageBucket =
        age === null || age === undefined
          ? "未知年龄"
          : age < 7
            ? "0–6 天（极新号）"
            : age < 30
              ? "7–29 天（新号）"
              : age < 90
                ? "30–89 天（成长期）"
                : "90+ 天（老号）";

      addBucket(buckets.byMerchant, latest.merchantOfRecord || latest.billingType, st);
      addBucket(buckets.byAge, ageBucket, st);
      addBucket(buckets.byPlan, latest.planLabel, st);
      addBucket(buckets.byProxyType, acc.tags?.proxyType, st);
      addBucket(buckets.byClientType, acc.tags?.clientType, st);
    }

    const sortBucket = (obj) =>
      Object.values(obj)
        .map((item) => ({
          ...item,
          riskRate: item.total > 0 ? Math.round(((item.restricted + item.invalid) / item.total) * 100) : 0,
        }))
        .sort((a, b) => b.total - a.total);

    return {
      totals,
      topReasons: Object.entries(reasonCounts)
        .map(([reason, count]) => ({ reason, count }))
        .sort((a, b) => b.count - a.count),
      byMerchant: sortBucket(buckets.byMerchant),
      byAge: sortBucket(buckets.byAge),
      byPlan: sortBucket(buckets.byPlan),
      byProxyType: sortBucket(buckets.byProxyType),
      byClientType: sortBucket(buckets.byClientType),
    };
  }

  return {
    dbFilePath,
    recordSnapshot,
    updateAccountTags,
    deleteAccount,
    clearAll,
    listAccounts,
    buildAnalytics,
  };
}
