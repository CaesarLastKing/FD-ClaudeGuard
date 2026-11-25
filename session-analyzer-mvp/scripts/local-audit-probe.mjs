#!/usr/bin/env node
/**
 * FD Claude 本地纯非侵入账户管控审计脚本（零网络、零解密、零注入、强脱敏）
 *
 * 用法：
 *   node session-analyzer-mvp/scripts/local-audit-probe.mjs          # 终端可读报告
 *   node session-analyzer-mvp/scripts/local-audit-probe.mjs --json   # 结构化脱敏 JSON 输出
 *
 * 安全红线：
 * 1. 仅只读扫描本地明文 JSON / 日志 / 元数据，不发任何网络请求；
 * 2. 绝不输出 accessToken / refreshToken / sessionKey / 明文邮箱 / 聊天正文 / 完整 UUID；
 * 3. 绝不解密 Chromium DPAPI Cookies，绝不注入或修改任何进程与文件。
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const HOME = process.env.USERPROFILE || os.homedir();
const APPDATA = process.env.APPDATA || path.join(HOME, "AppData", "Roaming");
const LOCALAPPDATA = process.env.LOCALAPPDATA || path.join(HOME, "AppData", "Local");
const OUTPUT_JSON = process.argv.includes("--json");

function maskEmail(email) {
  if (!email || typeof email !== "string") return null;
  const idx = email.indexOf("@");
  if (idx <= 0) return "***";
  const local = email.slice(0, idx);
  return `${local.slice(0, Math.min(2, local.length))}***@${email.slice(idx + 1)}`;
}

function shortId(val) {
  if (!val || typeof val !== "string") return null;
  const s = val.trim();
  if (s.length <= 10) return s;
  return `${s.slice(0, 8)}…${s.slice(-4)}`;
}

function daysSince(iso) {
  if (!iso) return null;
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return null;
  return Math.max(0, Math.floor((Date.now() - ts) / 86400000));
}

function safeReadJson(filePath) {
  try {
    if (!fs.existsSync(filePath)) return { exists: false, data: null, error: null };
    const raw = fs.readFileSync(filePath, "utf8");
    return { exists: true, data: JSON.parse(raw), error: null, sizeBytes: Buffer.byteLength(raw, "utf8") };
  } catch (err) {
    return { exists: fs.existsSync(filePath), data: null, error: err?.message || "JSON 解析失败" };
  }
}

function dirStats(dirPath) {
  if (!fs.existsSync(dirPath)) return { exists: false, fileCount: 0, totalBytes: 0, entries: [] };
  let fileCount = 0;
  let totalBytes = 0;
  const entries = [];
  try {
    for (const ent of fs.readdirSync(dirPath, { withFileTypes: true })) {
      const full = path.join(dirPath, ent.name);
      if (ent.isFile()) {
        const st = fs.statSync(full);
        fileCount += 1;
        totalBytes += st.size;
        entries.push({ name: ent.name, sizeBytes: st.size, mtime: st.mtime.toISOString() });
      } else if (ent.isDirectory()) {
        entries.push({ name: `${ent.name}/`, isDir: true });
      }
    }
  } catch {
    // 忽略无权限子项
  }
  return { exists: true, fileCount, totalBytes, entries };
}

/* ==================== 1. 扫描 ~/.claude.json（账号管控与缓存中心） ==================== */
function auditClaudeJson() {
  const filePath = path.join(HOME, ".claude.json");
  const { exists, data, error, sizeBytes } = safeReadJson(filePath);
  if (!exists || !data) {
    return { path: filePath, exists, error };
  }

  const oa = data.oauthAccount || {};
  const subAgeDays = daysSince(oa.subscriptionCreatedAt);
  const accAgeDays = daysSince(oa.accountCreatedAt);

  // 只抽取 modelAccessCache 的键摘要，不暴露大段冗余内容
  const modelAccessSummary =
    data.modelAccessCache && typeof data.modelAccessCache === "object"
      ? Object.keys(data.modelAccessCache).slice(0, 12)
      : [];

  // 精简并脱敏提取 cachedUsageUtilization（绝不透出内部完整 accountUuid）
  const rawCu = data.cachedUsageUtilization;
  let usageCacheSummary = null;
  if (rawCu && typeof rawCu === "object") {
    const u = rawCu.utilization || {};
    const breakdownRows = Array.isArray(u.seven_day_breakdown?.rows)
      ? u.seven_day_breakdown.rows.map((r) => `${r.display_name || r.key}:${r.percent}%`)
      : [];
    usageCacheSummary = {
      fetchedAt: rawCu.fetchedAtMs ? new Date(rawCu.fetchedAtMs).toISOString() : null,
      fiveHourPct: u.five_hour?.utilization ?? null,
      fiveHourLockedReason: u.five_hour?.locked_reason ?? null,
      sevenDayPct: u.seven_day?.utilization ?? null,
      sevenDayLockedReason: u.seven_day?.locked_reason ?? null,
      extraUsageDisabledReason: u.extra_usage?.disabled_reason ?? null,
      spendLimitReached: Boolean(u.extra_usage?.spend_limit_reached),
      canPurchaseCredits: u.spend?.can_purchase_credits ?? null,
      breakdown7d: breakdownRows,
    };
  }

  return {
    path: filePath,
    exists: true,
    sizeKB: Math.round((sizeBytes || 0) / 1024),
    account: {
      emailMasked: maskEmail(oa.emailAddress),
      accountUuidShort: shortId(oa.accountUuid),
      orgUuidShort: shortId(oa.organizationUuid),
      orgUuidPrefix8: oa.organizationUuid ? String(oa.organizationUuid).slice(0, 8).toLowerCase() : null,
      orgName: oa.organizationName ? oa.organizationName.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, (m) => maskEmail(m)) : null,
      orgType: oa.organizationType ?? null,
      orgRole: oa.organizationRole ?? null,
      workspaceRole: oa.workspaceRole ?? null,
      billingType: oa.billingType ?? null,
      seatTier: oa.seatTier ?? null,
      orgRateLimitTier: oa.organizationRateLimitTier ?? null,
      userRateLimitTier: oa.userRateLimitTier ?? null,
      hasExtraUsageEnabled: oa.hasExtraUsageEnabled ?? null,
      accountCreatedAt: oa.accountCreatedAt ?? null,
      accountAgeDays: accAgeDays,
      subscriptionCreatedAt: oa.subscriptionCreatedAt ?? null,
      subscriptionAgeDays: subAgeDays,
      in24hHighRiskSubWindow: subAgeDays !== null && subAgeDays <= 1,
      profileFetchedAt: oa.profileFetchedAt ?? null,
      claudeCodeFirstTokenDate: data.claudeCodeFirstTokenDate ?? null,
      trialEndsAt: oa.claudeCodeTrialEndsAt ?? null,
    },
    riskAndGovernanceCache: {
      cachedExtraUsageDisabledReason: data.cachedExtraUsageDisabledReason ?? null,
      cachedUsageSummary: usageCacheSummary,
      groveConfigCache: data.groveConfigCache ?? null,
      passesEligibilityCache: data.passesEligibilityCache ?? null,
      orgModelDefaultCache: data.orgModelDefaultCache ?? null,
      modelAccessKeys: modelAccessSummary,
      cachedFeatureFlagsCount: data.cachedFeatureFlags ? Object.keys(data.cachedFeatureFlags).length : 0,
      cachedGrowthBookFeaturesCount: data.cachedGrowthBookFeatures ? Object.keys(data.cachedGrowthBookFeatures).length : 0,
      claudeAiMcpEverConnected: Boolean(data.claudeAiMcpEverConnected),
      autoUpdates: data.autoUpdates ?? null,
      installMethod: data.installMethod ?? null,
      numStartups: data.numStartups ?? null,
      firstStartTime: data.firstStartTime ?? null,
      machineIdShort: shortId(data.machineID),
      userIdShort: shortId(data.userID),
      trackedProjectCount: data.projects ? Object.keys(data.projects).length : 0,
    },
  };
}

/* ==================== 2. 扫描 ~/.claude/.credentials.json（严格只读非敏感元数据） ==================== */
function auditCredentialsMeta() {
  const filePath = path.join(HOME, ".claude", ".credentials.json");
  const { exists, data, error } = safeReadJson(filePath);
  if (!exists || !data) {
    return { path: filePath, exists, error };
  }

  const oauth = data.claudeAiOauth || {};
  const expiresAtMs = typeof oauth.expiresAt === "number" ? oauth.expiresAt : Date.parse(oauth.expiresAt || "");
  const hasValidExpiry = !Number.isNaN(expiresAtMs) && expiresAtMs > 0;
  const remainingMinutes = hasValidExpiry ? Math.round((expiresAtMs - Date.now()) / 60000) : null;

  // 严禁读取或输出 accessToken / refreshToken，仅记录其是否存在
  const mcpServers = data.mcpOAuth && typeof data.mcpOAuth === "object"
    ? Object.keys(data.mcpOAuth).map((k) => k.split("|")[0])
    : [];

  return {
    path: filePath,
    exists: true,
    hasAccessToken: Boolean(oauth.accessToken),
    hasRefreshToken: Boolean(oauth.refreshToken),
    subscriptionType: oauth.subscriptionType ?? null,
    rateLimitTier: oauth.rateLimitTier ?? null,
    scopes: Array.isArray(oauth.scopes) ? oauth.scopes : [],
    expiresAt: hasValidExpiry ? new Date(expiresAtMs).toISOString() : null,
    isExpired: remainingMinutes !== null ? remainingMinutes <= 0 : null,
    remainingMinutes,
    mcpOAuthProviders: mcpServers,
  };
}

/* ==================== 3. 扫描 ~/.claude/settings.json（降噪/代理劫持/白名单泄密/Hook） ==================== */
function auditSettingsAndHygiene() {
  const filePath = path.join(HOME, ".claude", "settings.json");
  const { exists, data, error } = safeReadJson(filePath);
  const telemetryStats = dirStats(path.join(HOME, ".claude", "telemetry"));
  const scheduledTasksStats = dirStats(path.join(HOME, ".claude", "scheduled-tasks"));
  const backupsDir = path.join(HOME, ".claude", "backups");

  // 扫描备份目录中是否残留多个不同 orgUuid（防旧封号残留）
  const backupOrgPrefixes = new Set();
  const backupStats = dirStats(backupsDir);
  if (backupStats.exists) {
    for (const f of backupStats.entries.filter((e) => !e.isDir && e.name.includes(".claude.json.backup"))) {
      const parsed = safeReadJson(path.join(backupsDir, f.name));
      const orgId = parsed.data?.oauthAccount?.organizationUuid;
      if (orgId) backupOrgPrefixes.add(String(orgId).slice(0, 8).toLowerCase());
    }
  }

  if (!exists || !data) {
    return {
      path: filePath,
      exists,
      error,
      telemetryDir: { fileCount: telemetryStats.fileCount, totalBytes: telemetryStats.totalBytes },
      scheduledTasksCount: scheduledTasksStats.fileCount,
      backupOrgPrefixes: [...backupOrgPrefixes],
    };
  }

  const env = data.env && typeof data.env === "object" ? data.env : {};
  const baseUrl = env.ANTHROPIC_BASE_URL || env.ANTHROPIC_API_URL || null;
  const isOfficialBaseUrl = !baseUrl || /^https:\/\/api\.anthropic\.com/i.test(String(baseUrl).trim());

  const privacyEnvFlags = {
    DISABLE_TELEMETRY: env.DISABLE_TELEMETRY ?? null,
    DISABLE_ERROR_REPORTING: env.DISABLE_ERROR_REPORTING ?? null,
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC ?? null,
    DISABLE_BUG_COMMAND: env.DISABLE_BUG_COMMAND ?? null,
  };

  // 检测权限白名单明文凭据泄漏（Secret Sprawl）
  const allowList = Array.isArray(data.permissions?.allow) ? data.permissions.allow : [];
  const secretPattern = /(sk-ant-|bearer\s+[a-z0-9._-]{10,}|ghp_[a-z0-9]{10,}|password=|token=|secret=|api[_-]?key=)/i;
  const dangerousRulePattern = /(bash\(rm\s+-rf|bash\(curl\s+.*\|\s*sh|bash\(docker\s+run)/i;
  const leakedAllowCount = allowList.filter((r) => secretPattern.test(String(r))).length;
  const dangerousAllowRules = allowList.filter((r) => dangerousRulePattern.test(String(r))).slice(0, 5);

  const hookEvents = data.hooks && typeof data.hooks === "object" ? Object.keys(data.hooks) : [];

  return {
    path: filePath,
    exists: true,
    anthropicBaseUrl: baseUrl ? (isOfficialBaseUrl ? baseUrl : `<NON_OFFICIAL_URL:${(() => { try { return new URL(baseUrl).host; } catch { return "custom"; } })()}>`) : "默认官方",
    baseUrlRisk: !isOfficialBaseUrl,
    privacyEnvFlags,
    allowRuleCount: allowList.length,
    secretSprawlHits: leakedAllowCount,
    dangerousAllowRules,
    hookEvents,
    telemetryDir: { fileCount: telemetryStats.fileCount, totalBytes: telemetryStats.totalBytes },
    scheduledTasksCount: scheduledTasksStats.fileCount,
    backupCount: backupStats.fileCount,
    backupOrgPrefixes: [...backupOrgPrefixes],
  };
}

/* ==================== 4. 扫描 Claude Desktop（传统 + MSIX 目录、日志与 MCP 配置） ==================== */
function auditDesktopClient() {
  const candidateRoots = [
    { kind: "LocalAppData", dir: path.join(LOCALAPPDATA, "Claude") },
    { kind: "RoamingAppData", dir: path.join(APPDATA, "Claude") },
  ];

  // 自动发现微软商店 MSIX 沙箱目录
  const pkgsDir = path.join(LOCALAPPDATA, "Packages");
  if (fs.existsSync(pkgsDir)) {
    try {
      for (const ent of fs.readdirSync(pkgsDir, { withFileTypes: true })) {
        if (ent.isDirectory() && ent.name.startsWith("Claude_")) {
          candidateRoots.push({
            kind: `MSIX-Roaming(${ent.name})`,
            dir: path.join(pkgsDir, ent.name, "LocalCache", "Roaming", "Claude"),
          });
          candidateRoots.push({
            kind: `MSIX-Local(${ent.name})`,
            dir: path.join(pkgsDir, ent.name, "LocalCache", "Local", "Claude"),
          });
        }
      }
    } catch {
      // 忽略目录权限问题
    }
  }

  const foundDirs = [];
  const logFiles = [];
  const mcpConfigs = [];

  for (const item of candidateRoots) {
    if (!fs.existsSync(item.dir)) continue;
    foundDirs.push({ kind: item.kind, path: item.dir });

    // 检查 MCP 配置文件
    const mcpCfgPath = path.join(item.dir, "claude_desktop_config.json");
    if (fs.existsSync(mcpCfgPath)) {
      const parsed = safeReadJson(mcpCfgPath);
      const servers = parsed.data?.mcpServers && typeof parsed.data.mcpServers === "object"
        ? Object.keys(parsed.data.mcpServers)
        : [];
      mcpConfigs.push({ path: mcpCfgPath, serverCount: servers.length, serverNames: servers });
    }

    // 发现日志文件
    const logsDir = path.join(item.dir, "logs");
    if (fs.existsSync(logsDir)) {
      try {
        for (const f of fs.readdirSync(logsDir)) {
          if (f.endsWith(".log")) {
            const full = path.join(logsDir, f);
            const st = fs.statSync(full);
            logFiles.push({ name: f, path: full, sizeKB: Math.round((st.size / 1024) * 10) / 10, mtime: st.mtime.toISOString() });
          }
        }
      } catch {
        // 忽略
      }
    }
  }

  // 解析全部桌面日志中的账户管控与风控信号（只读统计，不吐原始敏感行）
  const orgIdPrefixes = new Set();
  const signals = {
    accountBannedHits: 0,
    portalVerifyHits: 0,
    crossOrg404Hits: 0,
    oauth403Hits: 0,
    cookie403Hits: 0,
    cfShield403Hits: 0,
    rateLimit429Hits: 0,
    planChangedHits: 0,
    highSideSessionHits: 0,
    maxSideSessionsSeen: 0,
    mcpErrorHits: 0,
  };

  const reOrg = /(?:orgId|organization_uuid|organizationId)["'=:\s]+([a-f0-9-]{8,36})/gi;
  const re429 = /(?:http[/\s]+|status[_\s:=]+["']?)429\b/i;
  const reSide = /sidesessions?\s*[:=]\s*(\d+)/i;

  for (const lf of logFiles) {
    try {
      // 最多读取单文件尾部 2MB 保持毫秒级速度
      const st = fs.statSync(lf.path);
      const readLen = Math.min(st.size, 2 * 1024 * 1024);
      const fd = fs.openSync(lf.path, "r");
      const buf = Buffer.alloc(readLen);
      fs.readSync(fd, buf, 0, readLen, Math.max(0, st.size - readLen));
      fs.closeSync(fd);
      const text = buf.toString("utf8");

      for (const m of text.matchAll(reOrg)) {
        orgIdPrefixes.add(m[1].slice(0, 8).toLowerCase());
      }

      const isMcpLog = lf.name.toLowerCase().includes("mcp");
      for (const line of text.split(/\r?\n/)) {
        const lower = line.toLowerCase();
        if (!lower) continue;
        if (lower.includes("account_banned")) signals.accountBannedHits += 1;
        if (lower.includes("portal.anthropic.com/verify") || lower.includes("withpersona.com")) signals.portalVerifyHits += 1;
        if (lower.includes("orgid") && lower.includes("404")) signals.crossOrg404Hits += 1;
        if ((lower.includes("authorize returned 403") || lower.includes("oauth failed")) && lower.includes("permission_error")) {
          signals.oauth403Hits += 1;
        }
        if (lower.includes("403") && lower.includes("credential: cookie") && lower.includes("withheld")) {
          signals.cookie403Hits += 1;
        }
        if (lower.includes("navigation to https://claude.ai/ failed with status code 403")) {
          signals.cfShield403Hits += 1;
        }
        if (re429.test(lower)) signals.rateLimit429Hits += 1;
        if (lower.includes("plan_changed")) signals.planChangedHits += 1;
        const sm = lower.match(reSide);
        if (sm) {
          const n = Number(sm[1]);
          if (n > signals.maxSideSessionsSeen) signals.maxSideSessionsSeen = n;
          if (n >= 3) signals.highSideSessionHits += 1;
        }
        if (isMcpLog && (lower.includes("[error]") || lower.includes("error:"))) {
          signals.mcpErrorHits += 1;
        }
      }
    } catch {
      // 忽略单文件读取失败
    }
  }

  return {
    discoveredDirectories: foundDirs,
    mcpConfigs,
    logFiles,
    discoveredOrgIdPrefixes: [...orgIdPrefixes],
    signals,
  };
}

/* ==================== 5. 离线扫描 ~/.claude/projects/*.jsonl（近 5h/24h/7d 行为强度，不读正文） ==================== */
function auditOfflineUsageBehavior() {
  const projectsDir = path.join(HOME, ".claude", "projects");
  if (!fs.existsSync(projectsDir)) {
    return { exists: false, path: projectsDir };
  }

  const now = Date.now();
  const cutoff7d = now - 7 * 86400000;
  const cutoff24h = now - 24 * 3600000;
  const cutoff5h = now - 5 * 3600000;

  let filesScanned = 0;
  const stats = {
    last5h: { assistantTurns: 0, sidechainTurns: 0, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0 },
    last24h: { assistantTurns: 0, sidechainTurns: 0, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0 },
    last7d: { assistantTurns: 0, sidechainTurns: 0, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0 },
    modelsUsed7d: {},
  };

  function walk(dir, depth = 0) {
    if (depth > 3) return;
    let ents = [];
    try {
      ents = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of ents) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        walk(full, depth + 1);
      } else if (ent.isFile() && ent.name.endsWith(".jsonl")) {
        try {
          const st = fs.statSync(full);
          if (st.mtimeMs < cutoff7d) continue;
          filesScanned += 1;
          const raw = fs.readFileSync(full, "utf8");
          for (const line of raw.split(/\r?\n/)) {
            if (!line || !line.includes('"usage"')) continue;
            let obj;
            try {
              obj = JSON.parse(line);
            } catch {
              continue;
            }
            const ts = Date.parse(obj.timestamp || "") || st.mtimeMs;
            if (ts < cutoff7d) continue;
            const usage = obj.message?.usage || obj.usage;
            if (!usage) continue;

            const isSide = Boolean(obj.isSidechain);
            const model = obj.message?.model || obj.model || "unknown";
            const inTok = Number(usage.input_tokens || 0);
            const outTok = Number(usage.output_tokens || 0);
            const cacheRead = Number(usage.cache_read_input_tokens || 0);

            stats.modelsUsed7d[model] = (stats.modelsUsed7d[model] || 0) + 1;

            const apply = (bucket) => {
              bucket.assistantTurns += 1;
              if (isSide) bucket.sidechainTurns += 1;
              bucket.inputTokens += inTok;
              bucket.outputTokens += outTok;
              bucket.cacheReadTokens += cacheRead;
            };
            apply(stats.last7d);
            if (ts >= cutoff24h) apply(stats.last24h);
            if (ts >= cutoff5h) apply(stats.last5h);
          }
        } catch {
          // 忽略坏行/占用文件
        }
      }
    }
  }

  walk(projectsDir);
  return { exists: true, path: projectsDir, recentFilesScanned7d: filesScanned, ...stats };
}

/* ==================== 6. 汇总跨端一致性与风险结论 ==================== */
function buildReport() {
  const claudeJson = auditClaudeJson();
  const credentials = auditCredentialsMeta();
  const hygiene = auditSettingsAndHygiene();
  const desktop = auditDesktopClient();
  const behavior = auditOfflineUsageBehavior();

  const cliOrgPrefix = claudeJson.account?.orgUuidPrefix8 || null;
  const desktopOrgs = desktop.discoveredOrgIdPrefixes || [];
  const crossClientMismatch =
    Boolean(cliOrgPrefix) && desktopOrgs.length > 0 && !desktopOrgs.includes(cliOrgPrefix);

  const findings = [];
  if (desktop.signals.accountBannedHits > 0) {
    findings.push({ level: "HIGH", item: "桌面日志检出 account_banned 封号残留", detail: `命中 ${desktop.signals.accountBannedHits} 次，切新号前须备份并纯净清理` });
  }
  if (desktop.signals.portalVerifyHits > 0) {
    findings.push({ level: "HIGH", item: "桌面日志检出验证门户 / Persona 核验痕迹", detail: `命中 ${desktop.signals.portalVerifyHits} 次` });
  }
  if (crossClientMismatch) {
    findings.push({ level: "WARN", item: "CLI 与 Desktop 检测到不同 orgId（可能跨号混登）", detail: `CLI=${cliOrgPrefix} vs Desktop=[${desktopOrgs.join(", ")}]` });
  }
  if (desktopOrgs.length > 1) {
    findings.push({ level: "WARN", item: "Desktop 日志出现多个不同 orgId", detail: `共 ${desktopOrgs.length} 个组织前缀：[${desktopOrgs.join(", ")}]` });
  }
  if (hygiene.backupOrgPrefixes && hygiene.backupOrgPrefixes.length > 1) {
    findings.push({ level: "INFO", item: "历史 .claude/backups 中存在多组织备份记录", detail: `共 ${hygiene.backupOrgPrefixes.length} 个不同 orgId 前缀` });
  }
  if (hygiene.baseUrlRisk) {
    findings.push({ level: "HIGH", item: "检测到非官方 ANTHROPIC_BASE_URL", detail: `${hygiene.anthropicBaseUrl}（消费订阅严禁走第三方反代）` });
  }
  if (hygiene.secretSprawlHits > 0) {
    findings.push({ level: "WARN", item: "settings.json 权限白名单疑似固化明文凭据", detail: `命中 ${hygiene.secretSprawlHits} 条` });
  }
  if (claudeJson.riskAndGovernanceCache?.cachedExtraUsageDisabledReason) {
    findings.push({ level: "WARN", item: "存在额外用量禁用缓存原因", detail: String(claudeJson.riskAndGovernanceCache.cachedExtraUsageDisabledReason) });
  }
  if (claudeJson.account?.in24hHighRiskSubWindow) {
    findings.push({ level: "WARN", item: "处于订阅开通 24h 高敏观察窗", detail: "建议保持固定单节点、温和低并发" });
  }
  if (hygiene.telemetryDir?.totalBytes > 0) {
    findings.push({ level: "INFO", item: "本地遥测目录存在待传缓存", detail: `${hygiene.telemetryDir.fileCount} 个文件，${hygiene.telemetryDir.totalBytes} 字节` });
  }
  if (hygiene.scheduledTasksCount > 0) {
    findings.push({ level: "INFO", item: "检测到 Claude scheduled-tasks 任务文件", detail: `${hygiene.scheduledTasksCount} 个，请确认非无人值守高频循环脚本` });
  }
  if (findings.length === 0) {
    findings.push({ level: "OK", item: "本地非侵入审计未检出高危风险信号", detail: "跨端组织一致、无封号残留、无第三方反代劫持" });
  }

  return {
    auditedAt: new Date().toISOString(),
    mode: "non-invasive-read-only-sanitized",
    findings,
    crossClientOrgCheck: {
      cliOrgPrefix,
      desktopOrgPrefixes: desktopOrgs,
      consistent: !crossClientMismatch,
    },
    claudeJson,
    credentialsMeta: credentials,
    settingsAndHygiene: hygiene,
    desktopClient: desktop,
    offlineUsageBehavior: behavior,
  };
}

const report = buildReport();

if (OUTPUT_JSON) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log("======================================================================");
  console.log("  FD Claude 本地纯非侵入账户管控审计报告（零网络 / 零解密 / 已脱敏）");
  console.log("======================================================================");
  console.log(`审计时间: ${report.auditedAt}\n`);

  console.log("【一、风险体检结论】");
  for (const f of report.findings) {
    console.log(`  [${f.level}] ${f.item} — ${f.detail}`);
  }

  console.log("\n【二、~/.claude.json 账号与组织管控元数据（无需联网）】");
  const a = report.claudeJson.account || {};
  const g = report.claudeJson.riskAndGovernanceCache || {};
  console.log(`  邮箱(脱敏): ${a.emailMasked || "—"} | 主组织: ${a.orgName || "—"} (${a.orgUuidShort || "—"})`);
  console.log(`  组织类型/角色: ${a.orgType || "—"} / ${a.orgRole || "—"} | 计费: ${a.billingType || "—"} | 席位: ${a.seatTier || "—"}`);
  console.log(`  限流分级(组织/用户): ${a.orgRateLimitTier || "—"} / ${a.userRateLimitTier || "—"} | 额外用量: ${a.hasExtraUsageEnabled}`);
  console.log(`  账号年龄: ${a.accountAgeDays ?? "—"} 天 (${a.accountCreatedAt || "—"}) | 订阅时长: ${a.subscriptionAgeDays ?? "—"} 天`);
  console.log(`  本地设备/用户指纹: machineID=${g.machineIdShort || "—"} | userID=${g.userIdShort || "—"}`);
  const u = g.cachedUsageSummary;
  console.log(`  额外用量禁用原因: ${g.cachedExtraUsageDisabledReason ?? "无"}`);
  console.log(
    `  官方缓存用量快照: ${u ? `5h=${u.fiveHourPct ?? "—"}%(lock:${u.fiveHourLockedReason || "无"}) | 7d=${u.sevenDayPct ?? "—"}%(lock:${u.sevenDayLockedReason || "无"}) | 渠道=[${(u.breakdown7d || []).join(", ")}] | 采样=${u.fetchedAt || "—"}` : "无"}`
  );
  console.log(`  缓存特性标志: featureFlags=${g.cachedFeatureFlagsCount} / growthBook=${g.cachedGrowthBookFeaturesCount} | 曾连 MCP=${g.claudeAiMcpEverConnected}`);

  console.log("\n【三、~/.claude/.credentials.json 凭据状态（绝不输出 Token 明文）】");
  const c = report.credentialsMeta;
  console.log(`  存在: ${c.exists} | 订阅类型: ${c.subscriptionType || "—"} | RateLimitTier: ${c.rateLimitTier || "—"}`);
  console.log(`  Token 过期时间: ${c.expiresAt || "—"} (${c.isExpired === null ? "未知" : c.isExpired ? "已过期" : `剩余 ${c.remainingMinutes} 分钟`})`);
  console.log(`  Scopes: ${(c.scopes || []).join(", ") || "—"}`);
  console.log(`  MCP OAuth 授权项 (${(c.mcpOAuthProviders || []).length}): ${(c.mcpOAuthProviders || []).join(", ") || "无"}`);

  console.log("\n【四、本机卫生、配置与跨端一致性】");
  const h = report.settingsAndHygiene;
  console.log(`  ANTHROPIC_BASE_URL: ${h.anthropicBaseUrl} | 权限白名单数: ${h.allowRuleCount ?? 0} (疑似明文泄密: ${h.secretSprawlHits ?? 0})`);
  console.log(`  隐私降噪环境变量: ${JSON.stringify(h.privacyEnvFlags || {})}`);
  console.log(`  Hooks 监听事件: ${(h.hookEvents || []).join(", ") || "无"} | 遥测缓存: ${h.telemetryDir?.fileCount ?? 0} 文件 (${h.telemetryDir?.totalBytes ?? 0} B)`);
  console.log(`  定时任务文件数: ${h.scheduledTasksCount ?? 0} | 历史备份数: ${h.backupCount ?? 0} (含 orgId: ${(h.backupOrgPrefixes || []).join(", ") || "无"})`);
  console.log(`  跨端 orgId 比对: CLI=${report.crossClientOrgCheck.cliOrgPrefix || "—"} vs Desktop=[${report.crossClientOrgCheck.desktopOrgPrefixes.join(", ") || "无"}] => ${report.crossClientOrgCheck.consistent ? "一致" : "不一致！"}`);

  console.log("\n【五、Claude Desktop 客户端日志与风控信号】");
  const d = report.desktopClient;
  console.log(`  发现目录: ${d.discoveredDirectories.map((x) => `${x.kind}`).join(" | ") || "无"}`);
  console.log(`  日志文件 (${d.logFiles.length}): ${d.logFiles.map((f) => `${f.name}(${f.sizeKB}KB)`).join(", ") || "无"}`);
  console.log(`  风控信号: banned=${d.signals.accountBannedHits}, portal/kyc=${d.signals.portalVerifyHits}, crossOrg404=${d.signals.crossOrg404Hits}, oauth403=${d.signals.oauth403Hits}, cookie403=${d.signals.cookie403Hits}, cf403=${d.signals.cfShield403Hits}, 429=${d.signals.rateLimit429Hits}, planChanged=${d.signals.planChangedHits}, maxSideSessions=${d.signals.maxSideSessionsSeen}`);

  console.log("\n【六、离线 .jsonl 行为强度（近 5h / 24h / 7d · 零网络）】");
  const b = report.offlineUsageBehavior;
  if (b.exists) {
    console.log(`  近 7 天活跃会话文件: ${b.recentFilesScanned7d} 个`);
    console.log(`  近 5 小时: ${b.last5h.assistantTurns} 轮 (子代理 ${b.last5h.sidechainTurns}) | in=${b.last5h.inputTokens}, out=${b.last5h.outputTokens}, cacheRead=${b.last5h.cacheReadTokens}`);
    console.log(`  近 24 小时: ${b.last24h.assistantTurns} 轮 (子代理 ${b.last24h.sidechainTurns}) | in=${b.last24h.inputTokens}, out=${b.last24h.outputTokens}, cacheRead=${b.last24h.cacheReadTokens}`);
    console.log(`  近 7 天: ${b.last7d.assistantTurns} 轮 (子代理 ${b.last7d.sidechainTurns}) | 模型: ${JSON.stringify(b.modelsUsed7d)}`);
  } else {
    console.log("  未发现 ~/.claude/projects 目录");
  }
  console.log("\n提示：加 --json 参数可输出完整脱敏 JSON 结构。");
}
