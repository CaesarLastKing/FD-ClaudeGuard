import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CleanConfirmModal } from "@/components/CleanConfirmModal";
import { HudCard } from "@/components/HudCard";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { AccountAuditPage } from "@/pages/AccountAuditPage";
import { ConsolePage } from "@/pages/ConsolePage";
import { NodesTrafficPage } from "@/pages/NodesTrafficPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { useGuardStore } from "@/stores/guardStore";
import type { AccountAuditReport } from "@/types/guard";

function buildMockAuditReport(overrides: Partial<AccountAuditReport> = {}): AccountAuditReport {
  return {
    profileId: "default",
    auditedAtMs: Date.now(),
    emailMasked: "桌面端账号 (本地不含邮箱 · org a4722ea6)",
    orgIdPrefix8: "a4722ea6",
    plan: "Free",
    merchantChannel: "Free",
    subscriptionRenewLabel: "预计续费 未知",
    subscriptionRenewIsEstimated: true,
    workspaceGeo: null,
    exitCountry: "AU",
    exitColo: "SYD",
    exitIpPurity: "常规机房",
    geoConsistency: "pending",
    cloudVerified: false,
    cloudStale: false,
    verifyCount: 0,
    quota: {
      fiveHourPct: null,
      sevenDayPct: null,
      stampShort: "暂无",
      stampTooltip: "暂无缓存",
      softLocked: false,
      source: "unknown",
    },
    scoreResult: {
      score: 85,
      maxScore: 100,
      level: "safe",
      levelLabel: "低风险",
      colorToken: "green",
      confidence: "local_only",
      confidenceLabel: "本地估",
      disclaimer: "非官方黑盒分",
      deductions: [],
    },
    local: {
      profileId: "default",
      scannedAtMs: Date.now(),
      claudeJson: { exists: false },
      credentials: { exists: false, scopes: [], mcpOauthProviders: [] },
      hygiene: {
        cliInstalled: false,
        settingsExists: false,
        privacyEnvFlags: {},
        privacyEnabledCount: 0,
        privacyMissingKeys: [
          "DISABLE_TELEMETRY",
          "DISABLE_ERROR_REPORTING",
          "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
          "DISABLE_BUG_COMMAND",
        ],
        systemEnvEndpointConflicts: [],
        telemetryFileCount: 0,
        telemetryTotalBytes: 0,
        scheduledTasksCount: 0,
        activeScheduledTasksCount: 0,
        historicalScheduledTasksCount: 0,
        backupFileCount: 0,
        backupAccounts: [],
      },
      behavior: {
        projectsDirExists: false,
        filesScanned7d: 0,
        desktopSessionsFiles7d: 0,
        last5h: { assistantTurns: 0, sidechainTurns: 0, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0 },
        last24h: { assistantTurns: 0, sidechainTurns: 0, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0 },
        last7d: { assistantTurns: 0, sidechainTurns: 0, inputTokens: 0, outputTokens: 0, cacheReadTokens: 0 },
        subagentRatio24hPct: 0,
        activeHours24h: 0,
        overnightBotRhythmSuspected: false,
      },
      desktop: {
        discoveredDirs: ["Claude-Data"],
        scannedLogFiles: 2,
        orgIdPrefixes: ["a4722ea6"],
        accountBannedHits: 0,
        portalVerifyHits: 0,
        crossOrg404Hits: 0,
        oauth403Hits: 0,
        cookie403Hits: 0,
        cfShield403Hits: 0,
        rateLimit429Hits: 0,
        planChangedHits: 0,
        fiveHourSoftLockHits: 0,
        maxSideSessionsSeen: 0,
        highSideSessionHits: 0,
        mcpErrorHits: 0,
        mcpErrorStorm: false,
        disconnectHits: 0,
        recentSamples: [],
      },
      crossClientOrgMismatch: false,
      allObservedOrgPrefixes: ["a4722ea6"],
    },
    runtimeClashPort: 7890,
    runtimeProxyOk: true,
    runtimeBgProcs: 8,
    runtimeKillHoldActive: false,
    runtimeKillHoldSecs: 0,
    runtimeDisconnectGuardOk: true,
    runtimeDisconnectGaps: [],
    denoisedOauth403Count: 0,
    logFlowItems: [
      {
        id: "audit-sample-oauth_403-main.log",
        cat: "403",
        denoised: false,
        chipLabel: "403 消歧",
        chipTone: "warn",
        title: "OAuth 403 权限被拒",
        desc: "保守提醒",
        timeLabel: "17:41:31 · main.log:715",
        rawSanitized: "authorize returned 403",
        count: 3,
      },
    ],
    pendingIssueCount: 0,
    hasDangerIssue: false,
    ...overrides,
  };
}

describe("v0.3.2 节点悬浮解释、运行中 B 级警示、严防漏链与全部标为已读回归", () => {
  beforeEach(() => {
    useGuardStore.setState({
      initialized: true,
      preflight: FALLBACK_PREFLIGHT,
      snapshot: FALLBACK_SNAPSHOT,
      auditSubTab: "audit",
      nodesSubTab: "quality",
      accountAudit: null,
      accountAuditLoading: false,
      checking: false,
      fixing: false,
      exitingClaude: false,
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("控制台在 Claude 运行中且存在非断链必须项未通过时展示 B 级警示横幅，支持一键清退并盯防", () => {
    const safeExitSpy = vi.fn().mockResolvedValue(undefined);
    useGuardStore.setState({
      safeExitClaude: safeExitSpy,
      snapshot: {
        ...FALLBACK_SNAPSHOT,
        bgClaudeProcs: 8,
        killSwitchActive: false,
        mustPassed: 11,
        mustTotal: 12,
      },
      preflight: {
        ...FALLBACK_PREFLIGHT,
        items: FALLBACK_PREFLIGHT.items.map((it) =>
          it.id === "sys_ipv6" ? { ...it, status: "fail" } : { ...it, status: "ok" }
        ),
      },
    });

    render(<ConsolePage />);
    expect(screen.getByTestId("console-running-must-fail-banner")).toHaveTextContent("8 个进程存活");
    fireEvent.click(screen.getByTestId("btn-banner-safe-exit-claude"));
    expect(safeExitSpy).toHaveBeenCalledTimes(1);
  });

  it("账户审计：5 重防护全绿时 8 进程运行显示「运行护航中」不报漏链；未装 CLI 自动豁免遥测；点击全部标为已读调用 ackAllLogEvents", async () => {
    const report = buildMockAuditReport();
    vi.spyOn(ipc, "auditAccountLocal").mockResolvedValue(report);
    const ackAllSpy = vi.spyOn(ipc, "ackAllLogEvents").mockResolvedValue({
      ...FALLBACK_SNAPSHOT,
      unreadLogAnomalies: 0,
      unreadLogCritical: 0,
      unreadLogWarnings: 0,
    });
    useGuardStore.setState({
      accountAudit: report,
      snapshot: {
        ...FALLBACK_SNAPSHOT,
        bgClaudeProcs: 8,
        unreadLogAnomalies: 2,
        unreadLogWarnings: 2,
      },
    });

    render(<AccountAuditPage />);
    const disRow = await screen.findByTestId("audit-group-g-disconnect");
    expect(disRow).toHaveTextContent("运行护航中");
    expect(disRow).not.toHaveTextContent("存在漏链");

    const telRow = screen.getByTestId("audit-group-g-telemetry");
    expect(telRow).toHaveTextContent("未装 CLI · 豁免");

    // 切到实时异常日志流并点击「全部标为已读」→ 必须直调后端 ackAllLogEvents 清零角标
    fireEvent.click(screen.getByRole("button", { name: /实时异常日志流/ }));
    fireEvent.click(await screen.findByRole("button", { name: "全部标为已读" }));
    await waitFor(() => {
      expect(ackAllSpy).toHaveBeenCalledTimes(1);
    });
    expect(useGuardStore.getState().snapshot.unreadLogAnomalies).toBe(0);
  });

  it("节点流量隔离区展示「落地禁区 / Claude 超时」悬浮解释窗与单行重测按钮", async () => {
    const startAuditSpy = vi.fn().mockResolvedValue(undefined);
    useGuardStore.setState({
      startDeepNodeAudit: startAuditSpy,
      nodeReport: {
        connected: true,
        endpoint: "Named Pipe",
        groupName: "Claude-Fixed",
        currentNode: "🇯🇵日本1",
        totalRawNodes: 2,
        filteredBlockedCount: 1,
        nodes: [
          {
            name: "🇯🇵日本1",
            regionCode: "JP",
            regionLabel: "日本 · Vless",
            nodeType: "Vless",
            delayMs: 78,
            jitterMs: 3,
            dropRatePct: 0,
            blocked: false,
            isCurrent: true,
            score: 94,
            recommendation: "推荐主节点",
            asnPurity: "ISP 住宅",
            asnShort: "ISP 住宅",
            anthropicProbe: "Claude ✓",
            cfBlocked: false,
            claudeStatus: "ok",
            claudeLabel: "Claude ✓",
            geminiStatus: "limited",
            geminiLabel: "AGY 限区",
            dualAiOk: false,
            driftCount24h: 0,
            riskLevel: "isp",
            riskDetail: "无代理标记",
            webCfChallenge: false,
          },
          {
            name: "🇸🇬新加坡1",
            regionCode: "SG",
            regionLabel: "新加坡 · Vless",
            nodeType: "Vless",
            delayMs: 92,
            jitterMs: 6,
            dropRatePct: 0,
            blocked: true,
            isCurrent: false,
            score: 35,
            recommendation: "Anthropic 超时",
            asnPurity: "ISP 住宅",
            asnShort: "ISP 住宅",
            anthropicProbe: "Claude 超时",
            cfBlocked: false,
            claudeStatus: "offline",
            claudeLabel: "Claude 超时",
            claudeProbeDetail: "实测失败：TLS handshake timeout",
            geminiStatus: "ok",
            geminiLabel: "AGY ✓",
            dualAiOk: false,
            driftCount24h: 0,
            riskLevel: "isp",
            riskDetail: "无代理标记",
            webCfChallenge: false,
          },
        ],
      },
    });

    render(<NodesTrafficPage />);
    // 可用区 AGY 限区标记风险但不禁用
    const agyLimitChip = screen.getByText("AGY 限区");
    fireEvent.mouseEnter(agyLimitChip);
    expect(screen.getByTestId("node-hover-tooltip")).toHaveTextContent("标记风险 · 不禁用");
    fireEvent.mouseLeave(agyLimitChip);

    // 切换至「隔离区」胶囊查看悬浮解释 + 按类型批量重测（重测超时类 / 重测隔离区）
    fireEvent.click(screen.getByTestId("tab-nodes-quarantine"));
    const timeoutChip = screen.getByText("Claude 超时");
    fireEvent.mouseEnter(timeoutChip);
    expect(screen.getByTestId("node-hover-tooltip")).toHaveTextContent("TLS handshake timeout");
    fireEvent.mouseLeave(timeoutChip);

    fireEvent.click(screen.getByTestId("btn-retest-timeout"));
    expect(startAuditSpy).toHaveBeenCalledWith(true, undefined, ["🇸🇬新加坡1"]);
  });

  it("守卫配置离线/检查更新失败时绝不陷入无限重试死循环（最多自动静默检查 1 次）", async () => {
    const checkSpy = vi
      .spyOn(ipc, "checkAppUpdate")
      .mockRejectedValue(new Error("network offline"));
    useGuardStore.setState({
      updateInfo: null,
      updateChecking: false,
      updateInstalling: false,
      updateError: null,
    });

    render(<SettingsPage />);
    await waitFor(() => {
      expect(checkSpy).toHaveBeenCalledTimes(1);
    });
    // 等待多个事件循环确认不会因 updateChecking 回到 false 而再次触发
    await new Promise((r) => setTimeout(r, 80));
    expect(checkSpy).toHaveBeenCalledTimes(1);
  });

  it("清理确认弹窗支持按 Esc 键正常关闭，且未连接 Mihomo 时节点页不误报「全部可用」", async () => {
    vi.spyOn(ipc, "previewClaudeCleanupPlan").mockResolvedValue({
      detectedInstallModes: ["经典安装版"],
      activeClaudeProcs: 0,
      categories: [],
      protected: {
        fileCount: 0,
        totalBytes: 0,
        sizeLabel: "0 B",
        reasons: [],
      },
      scannedMs: 12,
    });
    useGuardStore.setState({
      cleanModal: { open: true, sourceLabel: "来自环境维护" },
      nodeReport: {
        connected: false,
        endpoint: "",
        groupName: "Claude-Fixed",
        currentNode: "未连接",
        totalRawNodes: 0,
        filteredBlockedCount: 0,
        nodes: [],
      },
    });

    render(
      <>
        <CleanConfirmModal />
        <NodesTrafficPage />
      </>
    );

    expect(await screen.findByText(/暂无评估节点/)).toBeInTheDocument();
    expect(screen.queryByText(/全部可用/)).not.toBeInTheDocument();

    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => {
      expect(useGuardStore.getState().cleanModal).toBeNull();
    });
  });

  it("桌面悬浮窗在 Clash 未连接时不误显「稳定锁定」，流量卡切为预警态", () => {
    render(
      <HudCard
        initialConfig={{ ...DEFAULT_CONFIG }}
        initialSnapshot={{
          ...FALLBACK_SNAPSHOT,
          clashOnline: false,
          killSwitchActive: false,
          nodeDown: false,
        }}
      />
    );
    expect(screen.getByText("等待连接 Clash · 尚未锁定")).toBeInTheDocument();
    expect(screen.queryByText(/稳定锁定/)).not.toBeInTheDocument();
    expect(screen.getByTestId("hud-tile-flow").className).toContain("is-warn");
  });

  it("账户审计 Portal 卡片诚实区分 unknown（接口未返回，无绿点）与 local_hold（触发挂起 · 本地实锤）", async () => {
    const baseCloud = {
      verifiedAtMs: Date.now(),
      checkedAtIso: "2026-11-26T02:00:00Z",
      emailMasked: "demo***88@example.com",
      orgIdPrefix8: "bce33885",
      plan: "Pro",
      merchantChannel: "Stripe 直付",
      workspaceGeo: "US",
      edgeCountry: "US",
      edgeColo: "SJC",
      accountAgeDays: 30,
      subscriptionAgeDays: 20,
      subscriptionEndsAt: "2026-12-20",
      chatAvailable: true,
      isBanned: false,
      appealsRedirectEnabled: false,
      hasMonitoringNotice: false,
      activeFlagTypes: [],
      warningSummaryZh: null,
      personaKycStatus: null,
      personaKycCompletedAt: null,
      personaKycAgeHours: null,
      portalHold: false,
      portalState: "unknown",
      fiveHourPct: 12,
      fiveHourResetsAt: null,
      sevenDayPct: 24,
      sevenDayResetsAt: null,
      warnings: [],
    };

    const reportUnknown = buildMockAuditReport({
      cloudVerified: true,
      cloudSnapshot: baseCloud,
    });
    vi.spyOn(ipc, "auditAccountLocal").mockResolvedValue(reportUnknown);
    useGuardStore.setState({ accountAudit: reportUnknown });

    render(<AccountAuditPage />);
    expect(screen.getByText("接口未返回")).toBeInTheDocument();
    expect(screen.queryByText("无挂起 (clear)")).not.toBeInTheDocument();

    cleanup();

    const reportLocalHold = buildMockAuditReport({
      cloudVerified: true,
      cloudSnapshot: {
        ...baseCloud,
        portalHold: true,
        portalState: "local_hold",
      },
      scoreResult: {
        score: 12,
        maxScore: 100,
        level: "critical",
        levelLabel: "极危",
        colorToken: "red",
        confidence: "full_combined",
        confidenceLabel: "本地+云端",
        disclaimer: "非官方黑盒分",
        deductions: [],
      },
    });
    vi.spyOn(ipc, "auditAccountLocal").mockResolvedValue(reportLocalHold);
    useGuardStore.setState({ accountAudit: reportLocalHold });
    render(<AccountAuditPage />);

    expect(screen.getByText("触发挂起")).toBeInTheDocument();
    expect(screen.getByText(/本地日志实锤/)).toBeInTheDocument();
  });
});
