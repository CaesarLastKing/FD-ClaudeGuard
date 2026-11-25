import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  extractSessionKeys,
  maskEmail,
  maskSessionKey,
  sanitizePayload,
  buildShareableDiagnosticBundle,
} from "../core/sanitizer.mjs";
import { classifyPlan, evaluateAccountDiagnosis, selectPrimaryOrganization } from "../core/classifier.mjs";
import { detectCloudflareChallenge, parseCfEdgeColo, buildAntiBanAdvice } from "../core/probe.mjs";
import { createLocalStore, computeSnapshotDiff } from "../core/storage.mjs";

test("sanitizer: 准确提取去重 sessionKey 并彻底脱敏导出包", () => {
  const fakeKey = "sk-ant-sid01-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH123456";
  const raw = [
    `alice@example.com----pass123----${fakeKey}----extra`,
    `重复行 ${fakeKey}`,
    "无关注释行",
  ].join("\n");

  const parsed = extractSessionKeys(raw);
  assert.equal(parsed.items.length, 1);
  assert.equal(parsed.duplicateCount, 1);
  assert.equal(parsed.unrecognizedLines, 1);
  assert.equal(parsed.items[0].sessionKey, fakeKey);
  assert.equal(maskSessionKey(fakeKey), "sk-ant-sid01-A…3456");
  assert.equal(maskEmail("alice@example.com"), "al***@example.com");

  const payload = {
    email_address: "alice@example.com",
    full_name: "Alice Chen",
    verified_phone_number: "+14155550199",
    uuid: "12345678-1234-1234-1234-1234567890ab",
    vendor_inquiry_url: "https://withpersona.com/verify?inquiry-id=inq_secret_token",
    note: `leaked ${fakeKey}`,
  };

  const bundle = buildShareableDiagnosticBundle({
    status: "alive-but-restricted",
    riskLevel: "high",
    planLabel: "Max 20x",
    rawPayloads: { account: sanitizePayload(payload) },
    endpoints: [],
  });
  const serialized = JSON.stringify(bundle);
  assert.ok(!serialized.includes(fakeKey), "强脱敏包绝不能包含明文 sessionKey");
  assert.ok(!serialized.includes("alice@example.com"), "强脱敏包绝不能包含明文邮箱");
  assert.ok(!serialized.includes("Alice Chen"), "强脱敏包绝不能包含明文姓名");
  assert.ok(!serialized.includes("12345678-1234-1234-1234-1234567890ab"), "强脱敏包绝不能包含明文 UUID");
  assert.ok(!serialized.includes("inq_secret_token"), "强脱敏包绝不能包含验证 URL Token");
});

test("classifier: 覆盖全套餐分级与多维风控状态判定", () => {
  assert.equal(classifyPlan({ ravenType: "enterprise", capabilities: ["chat"] }).label, "Enterprise");
  assert.equal(classifyPlan({ capabilities: ["raven", "chat"] }).label, "Team");
  assert.equal(classifyPlan({ capabilities: ["claude_max"], planTier: "default_claude_max_20x" }).label, "Max 20x");
  assert.equal(classifyPlan({ capabilities: ["claude_max"], planTier: "default_claude_max_5x" }).label, "Max 5x");
  assert.equal(classifyPlan({ capabilities: ["claude_pro"] }).label, "Pro");
  assert.equal(classifyPlan({ planTier: "default_claude_ai" }).label, "Free");

  // 场景 1: Cloudflare 挑战不能误判为 invalid (403)
  const cfDiag = evaluateAccountDiagnosis({
    primaryProbe: { ok: false, statusCode: 403, cfBlocked: true, networkError: false },
  });
  assert.equal(cfDiag.status, "error");
  assert.equal(cfDiag.reasonCode, "cloudflare_challenge");

  // 场景 2: 上游明确 403 -> 区分 account_banned（实锤封号）与普通 session 失效
  const bannedDiag = evaluateAccountDiagnosis({
    primaryProbe: {
      ok: false,
      statusCode: 403,
      cfBlocked: false,
      networkError: false,
      data: {
        error: {
          type: "permission_error",
          message: "account_banned",
          details: { error_code: "account_banned", appeals_redirect_enabled: true },
        },
      },
    },
  });
  assert.equal(bannedDiag.status, "invalid");
  assert.equal(bannedDiag.reasonCode, "account_banned");
  assert.ok(bannedDiag.reasonText.includes("官方封禁"));

  const expiredDiag = evaluateAccountDiagnosis({
    primaryProbe: {
      ok: false,
      statusCode: 403,
      cfBlocked: false,
      networkError: false,
      data: { error: { type: "authentication_error", message: "Invalid authorization" } },
    },
  });
  assert.equal(expiredDiag.status, "invalid");
  assert.equal(expiredDiag.reasonCode, "upstream_403");
  assert.ok(expiredDiag.reasonText.includes("Invalid authorization"));

  // 场景 3: 能登录但 Portal 出现 hold_notice + 订阅 KYC pending -> alive-but-restricted
  const restrictedDiag = evaluateAccountDiagnosis({
    primaryProbe: { ok: true, statusCode: 200, cfBlocked: false, networkError: false },
    accountData: { email_address: "user@example.com", created_at: "2026-11-20T00:00:00Z" },
    orgsData: [
      {
        uuid: "org-1",
        name: "My Org",
        capabilities: ["chat", "claude_max"],
        rate_limit_tier: "default_claude_max_20x",
        billing_type: "stripe_subscription",
        merchant_of_record: "stripe",
        api_disabled_reason: null,
        billable_usage_paused_until: "2026-12-01T00:00:00Z",
      },
    ],
    subscriptionData: { kyc: { status: "pending", vendor_inquiry_id: "inq_123" } },
    usageData: { five_hour: { utilization: 91 }, seven_day: { utilization: 65 } },
    chatProbe: { ok: false, skipped: false, statusCode: 403, data: { error: { type: "permission_error" } } },
    portalProbe: { ok: true, statusCode: 200, data: { hold_notice: { reason: "kyc_required" }, admin_required: false } },
    nowMs: Date.parse("2026-11-25T00:00:00Z"),
  });

  assert.equal(restrictedDiag.status, "alive-but-restricted");
  assert.equal(restrictedDiag.planLabel, "Max 20x");
  assert.equal(restrictedDiag.accountAgeDays, 5);
  assert.equal(restrictedDiag.portalKyc.state, "required");
  assert.equal(restrictedDiag.kyc.clear, false);
  assert.ok(restrictedDiag.restrictionReasons.length >= 4);

  // 场景 4: 多组织（API 组织在前 + Chat 组织在后）必须选中 Chat 组织，且 kyc verified 放行，双年龄准确
  const dualOrgs = [
    {
      uuid: "api-org",
      capabilities: ["api", "api_individual"],
      rate_limit_tier: "auto_api_evaluation",
      api_disabled_reason: "out_of_credits",
      created_at: "2026-09-01T00:00:00Z",
    },
    {
      uuid: "chat-org",
      capabilities: ["chat"],
      rate_limit_tier: "default_claude_ai",
      billing_type: "none",
      merchant_of_record: "anthropic",
      created_at: "2026-10-17T00:00:00Z",
    },
  ];
  assert.equal(selectPrimaryOrganization(dualOrgs)?.uuid, "chat-org");
  const dualDiag = evaluateAccountDiagnosis({
    primaryProbe: { ok: true, statusCode: 200, cfBlocked: false, networkError: false },
    accountData: { email_address: "user@example.com", created_at: "2026-09-01T00:00:00Z", is_verified: true, age_is_verified: true },
    orgsData: dualOrgs,
    kycData: { status: "verified", vendor_inquiry_id: "inq_abc" },
    portalProbe: { ok: false, skipped: false, statusCode: 200, reasonCode: "non_json_html" },
    nowMs: Date.parse("2026-11-24T12:00:00Z"),
  });
  assert.equal(dualDiag.status, "alive");
  assert.equal(dualDiag.kyc.clear, true);
  assert.equal(dualDiag.orgAgeDays, 38);
  assert.equal(dualDiag.accountTotalAgeDays, 84);
});

test("probe: 准确区分 Cloudflare 挑战与正常 API 403 JSON", () => {
  assert.equal(
    detectCloudflareChallenge(403, { "cf-mitigated": "challenge", server: "cloudflare" }, "<html>Just a moment</html>"),
    true
  );
  assert.equal(
    detectCloudflareChallenge(
      403,
      { server: "cloudflare", "content-type": "application/json" },
      '{"type":"error","error":{"type":"permission_error"}}'
    ),
    false
  );

  const edge = parseCfEdgeColo("a5fbd07e0a6af36a-SYD");
  assert.deepEqual(edge, { colo: "SYD", country: "au" });
  const advice = buildAntiBanAdvice(
    { workspaceGeo: "us", planLabel: "Free", phoneVerified: false, kyc: { status: "verified", clear: true } },
    edge
  );
  assert.ok(advice.some((a) => a.level === "warn" && a.title.includes("不一致")));
});

test("storage: 落盘零明文 key、正确计算状态变更 Diff 与归因统计", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fd-analyzer-test-"));
  const dbPath = path.join(tmpDir, "db.json");
  const store = createLocalStore(dbPath);

  const secretKey = "sk-ant-sid01-NEVER_WRITE_THIS_TO_DISK_999999";
  store.recordSnapshot({
    checkedAt: "2026-11-24T00:00:00Z",
    keyFingerprint: "fp_test_001",
    keyMask: maskSessionKey(secretKey),
    status: "alive",
    riskLevel: "low",
    statusCode: 200,
    latencyMs: 300,
    reasonText: "存活",
    restrictionReasons: [],
    email: "alice@example.com",
    emailMasked: "al***@example.com",
    accountAgeDays: 10,
    planLabel: "Pro",
    merchantOfRecord: "stripe",
    kyc: { status: "not_required" },
    portalKyc: { state: "not_flagged" },
  });

  const second = store.recordSnapshot({
    checkedAt: "2026-11-25T00:00:00Z",
    keyFingerprint: "fp_test_001",
    keyMask: maskSessionKey(secretKey),
    status: "alive-but-restricted",
    riskLevel: "high",
    statusCode: 200,
    latencyMs: 420,
    reasonText: "Portal KYC / hold_notice 触发限制",
    restrictionReasons: ["Portal KYC / hold_notice 触发限制"],
    email: "alice@example.com",
    emailMasked: "al***@example.com",
    accountAgeDays: 11,
    planLabel: "Pro",
    merchantOfRecord: "stripe",
    kyc: { status: "pending" },
    portalKyc: { state: "required" },
  });

  const rawFile = fs.readFileSync(dbPath, "utf8");
  assert.ok(!rawFile.includes(secretKey), "本地数据库文件严禁包含明文 sessionKey");
  assert.ok(!rawFile.includes("alice@example.com"), "本地数据库文件严禁包含未脱敏邮箱");
  assert.ok(second.diffs.some((d) => d.field === "status" && d.before === "alive" && d.after === "alive-but-restricted"));
  assert.ok(second.diffs.some((d) => d.field === "portalKyc.state" && d.after === "required"));

  store.updateAccountTags("fp_test_001", { proxyType: "共享机房", clientType: "Web" });
  const analytics = store.buildAnalytics();
  assert.equal(analytics.totals.total, 1);
  assert.equal(analytics.totals.restricted, 1);
  assert.equal(analytics.byProxyType[0].riskRate, 100);

  // 直接校验 computeSnapshotDiff 独立调用
  const directDiff = computeSnapshotDiff({ status: "alive" }, { status: "invalid" });
  assert.equal(directDiff.length, 1);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
