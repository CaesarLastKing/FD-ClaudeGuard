/**
 * Claude 账号状态分类、套餐识别、双路 KYC 与风控评估引擎
 * 参考并扩展了 Claude 网页端内部元数据结构：
 * - 套餐分级：Enterprise / Team / Max 20x / Max 5x / Max / Pro / Free
 * - 受限识别：组织 API 禁用、计费暂停、活跃风控标记、订阅 KYC、Portal hold_notice、对话域拒绝
 */

const KYC_CLEAR_SET = new Set(["not_required", "approved", "completed", "verified"]);
const KYC_BLOCKED_SET = new Set([
  "created",
  "pending",
  "needs_review",
  "marked_for_review",
  "expired",
  "denied",
  "declined",
  "failed",
  "required",
]);

/**
 * 根据组织元数据推导套餐等级与排序权重
 * @param {{ ravenType?: string | null, capabilities?: string[], planTier?: string | null }} info
 * @returns {{ label: string, rank: number }}
 */
export function classifyPlan(info = {}) {
  const ravenType = String(info.ravenType || "").toLowerCase();
  const caps = new Set((info.capabilities || []).map((c) => String(c).toLowerCase()));
  const tier = String(info.planTier || "").toLowerCase();

  if (ravenType === "enterprise" || caps.has("claude_enterprise")) {
    return { label: "Enterprise", rank: 70 };
  }
  if (ravenType === "team" || caps.has("raven") || caps.has("claude_team")) {
    return { label: "Team", rank: 60 };
  }
  if (caps.has("claude_max") || tier.includes("claude_max")) {
    if (tier.includes("20x") || tier.includes("x20")) {
      return { label: "Max 20x", rank: 50 };
    }
    if (tier.includes("5x") || tier.includes("x5")) {
      return { label: "Max 5x", rank: 40 };
    }
    return { label: "Max", rank: 35 };
  }
  if (caps.has("claude_pro")) {
    return { label: "Pro", rank: 20 };
  }
  if (tier === "default_claude_ai" || tier === "free" || caps.has("chat")) {
    return { label: "Free", rank: 10 };
  }
  if (info.planTier) {
    return { label: String(info.planTier), rank: 5 };
  }
  return { label: "未知", rank: 0 };
}

/**
 * 评估订阅 KYC 状态
 * @param {string | null | undefined} status
 * @returns {{ normalized: string | null, clear: boolean | null, label: string }}
 */
export function evaluateSubscriptionKyc(status) {
  if (!status) {
    return { normalized: null, clear: null, label: "未知" };
  }
  const normalized = String(status).trim().toLowerCase();
  if (KYC_CLEAR_SET.has(normalized)) {
    const labelMap = {
      not_required: "无需验证",
      approved: "已通过",
      completed: "已完成",
      verified: "已通过 (verified)",
    };
    return { normalized, clear: true, label: labelMap[normalized] || normalized };
  }
  if (KYC_BLOCKED_SET.has(normalized)) {
    const labelMap = {
      created: "待完成(已创建)",
      pending: "审核/验证中",
      needs_review: "待人工复核",
      marked_for_review: "已标记复核",
      expired: "验证已过期",
      denied: "验证被拒",
      declined: "验证被拒",
      failed: "验证失败",
      required: "需要验证",
    };
    return { normalized, clear: false, label: labelMap[normalized] || normalized };
  }
  return { normalized, clear: null, label: normalized };
}

/**
 * 从多个可能的组织列表中选取当前主组织
 * 优先选择具备最高套餐能力或包含 chat 能力的组织
 * @param {Array<object>} orgs
 * @returns {object | null}
 */
export function selectPrimaryOrganization(orgs) {
  if (!Array.isArray(orgs) || orgs.length === 0) return null;
  const scored = orgs.map((org, idx) => {
    const caps = Array.isArray(org.capabilities) ? org.capabilities.map((c) => String(c).toLowerCase()) : [];
    const hasChat = caps.includes("chat");
    const isApiOnly = !hasChat && (caps.includes("api") || caps.includes("api_individual"));
    const plan = classifyPlan({
      ravenType: org.raven_type ?? org.ravenType,
      capabilities: caps,
      planTier: org.rate_limit_tier ?? org.planTier,
    });
    // Claude.ai 聊天组织权重远高于纯 Console API 组织
    const chatBonus = hasChat ? 1000 : isApiOnly ? -500 : 0;
    return { org, score: chatBonus + plan.rank * 10 - idx * 0.01 };
  });
  scored.sort((a, b) => b.score - a.score);
  return scored[0].org;
}

/**
 * 计算账号注册天数
 * @param {string | null | undefined} createdAt
 * @param {number} [nowMs]
 * @returns {number | null}
 */
export function computeAccountAgeDays(createdAt, nowMs = Date.now()) {
  if (!createdAt) return null;
  const ts = Date.parse(createdAt);
  if (Number.isNaN(ts)) return null;
  const diffDays = Math.floor((nowMs - ts) / (1000 * 60 * 60 * 24));
  return diffDays >= 0 ? diffDays : 0;
}

/**
 * 从多端点探测结果综合归类账户状态、受限原因与风险等级
 * @param {object} input
 * @returns {object}
 */
export function evaluateAccountDiagnosis(input) {
  const {
    accountData,
    orgsData,
    subscriptionData,
    usageData,
    chatProbe,
    kycData,
    portalProbe,
    primaryProbe,
    nowMs = Date.now(),
  } = input;

  // 1. 先检查主入口是否直接失效或网络拦截
  if (primaryProbe.cfBlocked) {
    return {
      status: "error",
      riskLevel: "unknown",
      reasonCode: "cloudflare_challenge",
      reasonText: `请求被 Cloudflare 拦截（HTTP ${primaryProbe.statusCode}），非账号失效，建议检查本机代理或切换网络`,
      restrictionReasons: [],
      planLabel: "—",
      planRank: 0,
    };
  }

  if (primaryProbe.networkError) {
    return {
      status: "error",
      riskLevel: "unknown",
      reasonCode: primaryProbe.reasonCode || "network_error",
      reasonText: primaryProbe.errorMessage || "网络连接失败或超时",
      restrictionReasons: [],
      planLabel: "—",
      planRank: 0,
    };
  }

  if (primaryProbe.statusCode === 401 || primaryProbe.statusCode === 403) {
    const errObj = primaryProbe.data?.error || {};
    const errCode = errObj?.details?.error_code || errObj?.message || null;
    const errType = errObj?.type || null;
    const appealsEnabled = Boolean(errObj?.details?.appeals_redirect_enabled);
    const isBanned = String(errCode || "").toLowerCase() === "account_banned";

    if (isBanned) {
      return {
        status: "invalid",
        riskLevel: "dead",
        reasonCode: "account_banned",
        reasonText: `账号已被官方封禁 (account_banned)${appealsEnabled ? " · 允许提交官方申诉" : ""}`,
        restrictionReasons: [
          "官方实锤封号 (account_banned)",
          ...(appealsEnabled ? ["支持申诉通道 (appeals_redirect_enabled=true)"] : []),
        ],
        planLabel: "—",
        planRank: 0,
      };
    }

    const detailLabel = errCode || errType || `HTTP ${primaryProbe.statusCode}`;
    return {
      status: "invalid",
      riskLevel: "dead",
      reasonCode: `upstream_${primaryProbe.statusCode}`,
      reasonText: `会话凭据无效或已过期（${detailLabel}），未必代表账号被封`,
      restrictionReasons: [`会话被上游拒绝 (${detailLabel})`],
      planLabel: "—",
      planRank: 0,
    };
  }

  if (!primaryProbe.ok) {
    return {
      status: "error",
      riskLevel: "unknown",
      reasonCode: primaryProbe.statusCode >= 500 ? "upstream_5xx" : "bad_response",
      reasonText: `上游返回异常状态码 HTTP ${primaryProbe.statusCode}`,
      restrictionReasons: [],
      planLabel: "—",
      planRank: 0,
    };
  }

  // 2. 提取主组织与全部组织列表
  const orgList = Array.isArray(orgsData)
    ? orgsData
    : Array.isArray(accountData?.memberships)
      ? accountData.memberships.map((m) => m.organization).filter(Boolean)
      : [];

  const primaryOrg = selectPrimaryOrganization(orgList);
  const capabilities = Array.isArray(primaryOrg?.capabilities) ? primaryOrg.capabilities : [];
  const planTier = primaryOrg?.rate_limit_tier ?? subscriptionData?.rate_limit_tier ?? null;
  const ravenType = primaryOrg?.raven_type ?? null;
  const plan = classifyPlan({ ravenType, capabilities, planTier });

  const email = accountData?.email_address ?? accountData?.email ?? primaryOrg?.email ?? null;
  const orgCreatedAt = primaryOrg?.created_at ?? null;
  const accountCreatedAt = accountData?.created_at ?? null;
  const createdAt = orgCreatedAt ?? accountCreatedAt ?? null;
  const orgAgeDays = computeAccountAgeDays(orgCreatedAt, nowMs);
  const accountTotalAgeDays = computeAccountAgeDays(accountCreatedAt, nowMs);
  const accountAgeDays = orgAgeDays ?? accountTotalAgeDays;

  const billingType =
    primaryOrg?.billing_type ??
    subscriptionData?.billing_type ??
    subscriptionData?.subscription_type ??
    null;
  const merchantOfRecord =
    primaryOrg?.merchant_of_record ??
    subscriptionData?.merchant_of_record ??
    subscriptionData?.payment_provider ??
    null;

  // 从 account.memberships 中补充同 UUID 组织的扩展字段（如 default_workspace_geo、rate_limit_upsell、模型配置）
  const matchedMembershipOrg = Array.isArray(accountData?.memberships)
    ? accountData.memberships.find((m) => m?.organization?.uuid === primaryOrg?.uuid)?.organization || null
    : null;
  const workspaceGeo = matchedMembershipOrg?.default_workspace_geo ?? primaryOrg?.default_workspace_geo ?? null;
  const analyticsPlan = primaryOrg?.analytics_subscription_plan ?? matchedMembershipOrg?.analytics_subscription_plan ?? null;
  const freeCreditsStatus = primaryOrg?.free_credits_status ?? matchedMembershipOrg?.free_credits_status ?? null;
  const bootstrapModels = Array.isArray(matchedMembershipOrg?.claude_ai_bootstrap_models_config)
    ? matchedMembershipOrg.claude_ai_bootstrap_models_config
    : Array.isArray(primaryOrg?.claude_ai_bootstrap_models_config)
      ? primaryOrg.claude_ai_bootstrap_models_config
      : [];
  const activeModels = bootstrapModels.filter((m) => !m?.inactive);
  const maxContextHardLimit = bootstrapModels.reduce(
    (max, m) => (typeof m?.hard_limit === "number" && m.hard_limit > max ? m.hard_limit : max),
    0
  );

  // 3. 收集组织级、KYC、Portal 与对话域的全部限制信号
  const restrictionReasons = [];

  const apiDisabledReason = primaryOrg?.api_disabled_reason ?? null;
  const apiDisabledUntil = primaryOrg?.api_disabled_until ?? null;
  const billableUsagePausedUntil = primaryOrg?.billable_usage_paused_until ?? null;
  const accessBlock = primaryOrg?.access_block ?? matchedMembershipOrg?.access_block ?? null;
  const billingIssue = primaryOrg?.billing_issue ?? matchedMembershipOrg?.billing_issue ?? null;
  const subscriptionPause = primaryOrg?.subscription_pause ?? matchedMembershipOrg?.subscription_pause ?? null;
  const monitoringNotice = primaryOrg?.monitoring_notice ?? matchedMembershipOrg?.monitoring_notice ?? null;
  const activeFlags = Array.isArray(primaryOrg?.active_flags) ? primaryOrg.active_flags : [];

  if (apiDisabledReason) {
    restrictionReasons.push(`API 已禁用 (${apiDisabledReason})`);
  }
  if (apiDisabledUntil) {
    restrictionReasons.push(`API 禁用至 ${apiDisabledUntil}`);
  }
  if (billableUsagePausedUntil) {
    restrictionReasons.push(`计费/用量暂停至 ${billableUsagePausedUntil}`);
  }
  if (accessBlock) {
    restrictionReasons.push(`组织访问封锁 (access_block)`);
  }
  if (billingIssue) {
    restrictionReasons.push(`组织账单异常 (billing_issue)`);
  }
  if (subscriptionPause) {
    restrictionReasons.push(`订阅已暂停 (subscription_pause)`);
  }
  if (monitoringNotice) {
    restrictionReasons.push(`风控监控提醒 (monitoring_notice)`);
  }
  for (const flag of activeFlags) {
    const flagStr = typeof flag === "string" ? flag : flag?.type || flag?.name || JSON.stringify(flag);
    if (/(ban|restrict|suspend|abuse|fraud|kyc|hold|disable|warn)/i.test(flagStr)) {
      restrictionReasons.push(`组织标记: ${flagStr}`);
    }
  }

  // 4. 订阅 KYC 评估（从独立 kyc 接口、subscription 或 account 中提取）
  const rawKyc =
    kycData ||
    subscriptionData?.kyc ||
    subscriptionData?.identity_verification ||
    accountData?.kyc ||
    primaryOrg?.kyc ||
    null;

  const kycEval = evaluateSubscriptionKyc(rawKyc?.status);
  const kycInfo = rawKyc
    ? {
        status: kycEval.normalized,
        label: kycEval.label,
        clear: kycEval.clear,
        checkKind: rawKyc.check_kind ?? null,
        createdAt: rawKyc.created_at ?? rawKyc.createdAt ?? null,
        completedAt: rawKyc.completed_at ?? rawKyc.completedAt ?? null,
        shouldPoll: Boolean(rawKyc.should_poll),
        hasInquiryLink: Boolean(rawKyc.vendor_inquiry_url || rawKyc.vendor_inquiry_id),
      }
    : {
        status: null,
        label: "未检测到字段(未知)",
        clear: null,
        checkKind: null,
        createdAt: null,
        completedAt: null,
        shouldPoll: false,
        hasInquiryLink: false,
      };

  if (kycEval.clear === false) {
    restrictionReasons.push(`订阅 KYC 未通过 (${kycEval.label})`);
  }

  // 5. Portal KYC / hold_notice 评估（严格遵循状态诚实原则）
  let portalKyc = {
    state: "unknown",
    label: "未探测/接口不可达",
    statusCode: portalProbe?.statusCode ?? null,
    reason: portalProbe?.reasonCode ?? null,
    adminRequired: null,
    hasHoldNotice: null,
  };

  if (portalProbe && portalProbe.ok && portalProbe.data && typeof portalProbe.data === "object") {
    if ("hold_notice" in portalProbe.data) {
      if (portalProbe.data.hold_notice === null) {
        portalKyc = {
          state: "not_flagged",
          label: "未见限制 (hold_notice=null)",
          statusCode: portalProbe.statusCode,
          reason: null,
          adminRequired: Boolean(portalProbe.data.admin_required),
          hasHoldNotice: false,
        };
      } else {
        portalKyc = {
          state: "required",
          label: "触发 Portal 挂起/KYC",
          statusCode: portalProbe.statusCode,
          reason: portalProbe.data.hold_notice?.reason || "hold_notice_present",
          adminRequired: Boolean(portalProbe.data.admin_required),
          hasHoldNotice: true,
        };
        restrictionReasons.push("Portal KYC / hold_notice 触发限制");
      }
    } else {
      portalKyc = {
        state: "unknown",
        label: "响应不含 hold_notice 字段",
        statusCode: portalProbe.statusCode,
        reason: "missing_hold_notice",
        adminRequired: null,
        hasHoldNotice: null,
      };
    }
  } else if (portalProbe && !portalProbe.skipped) {
    portalKyc.label = portalProbe.cfBlocked
      ? "Portal 探测被 CF 拦截"
      : portalProbe.reasonCode === "non_json_html"
        ? "未命中 Portal JSON（需兼容网关路径）"
        : `Portal 不可用 (HTTP ${portalProbe.statusCode || 0})`;
  }

  // 6. 对话域可读性探测（验证是否出现“能拉组织但对话接口拒绝”的隐性受限）
  if (chatProbe && !chatProbe.skipped && !chatProbe.cfBlocked && (chatProbe.statusCode === 403 || chatProbe.statusCode === 400)) {
    const errMsg = chatProbe.data?.error?.message || chatProbe.data?.error?.type || `HTTP ${chatProbe.statusCode}`;
    restrictionReasons.push(`对话域接口受限 (${errMsg})`);
  }

  // 7. 用量窗口提取（如 5h / 7d 利用率）
  let usageSummary = null;
  if (usageData && typeof usageData === "object") {
    usageSummary = {
      fiveHourPct: usageData.five_hour?.utilization ?? null,
      fiveHourResetAt: usageData.five_hour?.resets_at ?? null,
      sevenDayPct: usageData.seven_day?.utilization ?? null,
      sevenDayResetAt: usageData.seven_day?.resets_at ?? null,
      sevenDayOpusPct: usageData.seven_day_opus?.utilization ?? null,
      sevenDaySonnetPct: usageData.seven_day_sonnet?.utilization ?? null,
    };
  }

  // 8. 最终状态与风险评级
  const isRestricted = restrictionReasons.length > 0;
  const status = isRestricted ? "alive-but-restricted" : "alive";
  let riskLevel = "low";
  if (isRestricted) {
    riskLevel = "high";
  } else if (
    (accountAgeDays !== null && accountAgeDays < 7) ||
    (usageSummary?.fiveHourPct !== null && usageSummary?.fiveHourPct >= 85) ||
    (usageSummary?.sevenDayPct !== null && usageSummary?.sevenDayPct >= 85)
  ) {
    riskLevel = "medium";
  }

  return {
    status,
    riskLevel,
    reasonCode: isRestricted ? "restricted" : null,
    reasonText: isRestricted ? restrictionReasons.join("；") : "存活，当前未检测到明确限制",
    restrictionReasons,
    email,
    createdAt,
    orgCreatedAt,
    accountCreatedAt,
    accountAgeDays,
    orgAgeDays,
    accountTotalAgeDays,
    planLabel: plan.label,
    planRank: plan.rank,
    planTier,
    analyticsPlan,
    workspaceGeo,
    freeCreditsStatus,
    modelSummary:
      bootstrapModels.length > 0
        ? {
            totalCount: bootstrapModels.length,
            activeCount: activeModels.length,
            maxHardLimit: maxContextHardLimit || null,
            topModels: activeModels.slice(0, 4).map((m) => m.name || m.model),
          }
        : null,
    capabilities,
    billingType,
    merchantOfRecord,
    orgCount: orgList.length,
    org: primaryOrg
      ? {
          uuid: primaryOrg.uuid ?? null,
          name: primaryOrg.name ?? null,
          ravenType,
          apiDisabledReason,
          apiDisabledUntil,
          billableUsagePausedUntil,
          accessBlock,
          billingIssue,
          subscriptionPause,
          monitoringNotice,
          activeFlags,
        }
      : null,
    allOrgs: orgList.map((o) => ({
      uuid: o.uuid ?? null,
      name: o.name ?? null,
      planLabel: classifyPlan({
        ravenType: o.raven_type,
        capabilities: o.capabilities,
        planTier: o.rate_limit_tier,
      }).label,
      capabilities: Array.isArray(o.capabilities) ? o.capabilities : [],
      billingType: o.billing_type ?? null,
      apiDisabledReason: o.api_disabled_reason ?? null,
      createdAt: o.created_at ?? null,
    })),
    kyc: kycInfo,
    portalKyc,
    usage: usageSummary,
    phoneVerified: Boolean(accountData?.verified_phone_number || accountData?.verified_phone_number_last4),
    accountMeta: accountData
      ? {
          isVerified: Boolean(accountData.is_verified),
          ageIsVerified: Boolean(accountData.age_is_verified),
          onboardingComplete: Boolean(accountData.onboarding_complete),
          completedVerificationAt: accountData.completed_verification_at ?? null,
          neverAcceptedLegalDocs: Array.isArray(accountData.never_accepted_legal_document_types)
            ? accountData.never_accepted_legal_document_types
            : [],
          groveLocked: Boolean(accountData.grove_locked_by_claude_science),
          chalkVerification: accountData.settings?.internal_has_initiated_chalk_verification ?? null,
        }
      : null,
  };
}
