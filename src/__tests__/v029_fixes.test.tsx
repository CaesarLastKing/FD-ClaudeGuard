import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CleanConfirmModal } from "@/components/CleanConfirmModal";
import { NetworkRescueRollbackPanel } from "@/components/NetworkRescueRollbackPanel";
import { Sidebar } from "@/components/Sidebar";
import { WindowChrome } from "@/components/WindowChrome";
import { buildMockAccountAuditReport, DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { AccountAuditPage } from "@/pages/AccountAuditPage";
import { ConsolePage } from "@/pages/ConsolePage";
import { NodesTrafficPage } from "@/pages/NodesTrafficPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { useGuardStore } from "@/stores/guardStore";

describe("v0.2.9 真机回归：开机启动项徽章语义校验（T-054）", () => {
  beforeEach(() => {
    useGuardStore.setState({
      startupAudit: {
        claudeAutostartRisk: true,
        entries: [
          {
            app: "FD Claude Guard",
            enabled: true,
            riskLevel: "ok",
            detail: "已开启开机自启",
          },
          {
            app: "Clash Verge Rev",
            enabled: false,
            riskLevel: "warn",
            detail: "未检测到 Clash Verge 开机自启，开机后请先启动代理再打开 Claude",
          },
          {
            app: "Claude Desktop",
            enabled: true,
            riskLevel: "warn",
            detail: "检测到 Claude 已设开机自启，存在抢跑裸奔风险",
          },
        ],
      },
    });
  });

  it("Clash Verge 未开启自启且风险为 warn 时应显示「未开启（建议开启）」，Claude 已开启且 warn 时显示「已开启（有风险）」", async () => {
    render(<SettingsPage />);

    expect(screen.getByTestId("startup-chip-FD Claude Guard").textContent).toBe("已开启自启");
    expect(screen.getByTestId("startup-chip-Clash Verge Rev").textContent).toBe("未开启（建议开启）");
    expect(screen.getByTestId("startup-chip-Claude Desktop").textContent).toBe("已开启（有风险）");
    await waitFor(() => {
      expect(useGuardStore.getState().updateChecking).toBe(false);
    });
  });
});

describe("v0.2.9 真机回归：熔断与盯防联动、无锁文案清理与出口状态同源刷新", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useGuardStore.setState({
      config: { ...DEFAULT_CONFIG },
      snapshot: { ...FALLBACK_SNAPSHOT },
      preflight: { ...FALLBACK_PREFLIGHT },
      riskModal: null,
      toasts: [],
      initialized: true,
      activeTab: "console",
    });
  });

  it("熔断激活期间侧边栏显示联动锁定，点击按钮拉起统一解除熔断弹窗而非单独释放盯防", () => {
    const releaseHoldSpy = vi.spyOn(ipc, "releaseKillHold");
    useGuardStore.setState({
      snapshot: {
        ...FALLBACK_SNAPSHOT,
        killSwitchActive: true,
        killHoldActive: true,
        killHoldTxLocked: true,
        killHoldRemainingSecs: 0,
      },
    });

    render(<Sidebar />);
    expect(screen.getByTestId("sidebar-proc-status")).toHaveTextContent("熔断联动锁定");
    const btn = screen.getByTestId("btn-release-kill-hold");
    expect(btn).toHaveTextContent("解除熔断并解锁");

    fireEvent.click(btn);
    expect(releaseHoldSpy).not.toHaveBeenCalled();
    expect(useGuardStore.getState().riskModal?.open).toBe(true);
    expect(useGuardStore.getState().riskModal?.badge).toBe("解除熔断与盯防");
  });

  it("控制台熔断态顶栏去重双胶囊，右侧主 CTA 直接提供「解除熔断保护」避免溢出裁切", () => {
    useGuardStore.setState({
      snapshot: {
        ...FALLBACK_SNAPSHOT,
        mustPassed: 11,
        mustTotal: 11,
        killSwitchActive: true,
      },
      preflight: {
        ...FALLBACK_PREFLIGHT,
        items: FALLBACK_PREFLIGHT.items.map((x) =>
          x.part === "must" ? { ...x, status: "ok" } : x
        ),
      },
    });

    render(<ConsolePage />);
    expect(screen.queryByTestId("console-killswitch-status")).not.toBeInTheDocument();
    expect(screen.getByTestId("console-guard-status-pill")).toHaveTextContent("已自动熔断");
    expect(screen.getByTestId("btn-console-release-killswitch")).toHaveTextContent("解除熔断保护");
  });

  it("无锁版网络急救卡片移除「免激活永久可用」，且熔断生效中不将保护规则误报为残留故障", async () => {
    useGuardStore.setState({
      snapshot: {
        ...FALLBACK_SNAPSHOT,
        killSwitchActive: true,
      },
    });
    vi.spyOn(ipc, "inspectRollbackStatus").mockResolvedValue({
      baselineExists: true,
      baselinePath: "~/.fd-claude-guard/system-baseline.json",
      isElevated: true,
      loopbackDnsAdapters: [],
      activeFirewallRules: true,
      touchedCount: 1,
      items: [],
    });

    render(<NetworkRescueRollbackPanel />);
    await waitFor(() => {
      expect(screen.getByText(/熔断防护生效中/)).toBeInTheDocument();
    });
    expect(screen.queryByText("免激活永久可用")).not.toBeInTheDocument();
    expect(screen.queryByText("检测到残留防火墙规则")).not.toBeInTheDocument();
  });

  it("收到后端 guard://preflight-updated 出口状态变更后自动同步刷新节点评估表", async () => {
    const nodesSpy = vi.spyOn(ipc, "getNodesAndQuality").mockResolvedValue({
      connected: true,
      endpoint: "pipe",
      groupName: "Claude-Fixed",
      currentNode: "🇺🇸美国2|流媒体AI",
      totalRawNodes: 1,
      filteredBlockedCount: 0,
      nodes: [],
    });

    const nextReport = {
      ...FALLBACK_PREFLIGHT,
      items: FALLBACK_PREFLIGHT.items.map((it) =>
        it.id === "node_geo" ? { ...it, status: "fail" as const, summary: "当前节点无法连通 Anthropic API" } : it
      ),
    };
    useGuardStore.getState().setPreflightFromEvent(nextReport);

    await waitFor(() => {
      expect(nodesSpy).toHaveBeenCalledTimes(1);
    });
    expect(useGuardStore.getState().preflight.items.find((x) => x.id === "node_geo")?.status).toBe("fail");
  });

  it("节点流量页顶部统计扣除落地禁区不可用节点，且落地禁区评分副文案显示「禁区不可用」而非「拉黑不可用」", () => {
    useGuardStore.setState({
      nodesSubTab: "quality",
      nodeReport: {
        connected: true,
        endpoint: "pipe",
        groupName: "Claude-Fixed",
        currentNode: "🇺🇸美国2|流媒体AI",
        totalRawNodes: 2,
        subscriptionTotalNodes: 5,
        nameBlockedCount: 3,
        filteredBlockedCount: 4,
        nodes: [
          {
            name: "🇺🇸美国2|流媒体AI",
            regionCode: "US",
            regionLabel: "美国 · Vless",
            nodeType: "Vless",
            delayMs: 142,
            jitterMs: 5,
            dropRatePct: 0,
            blocked: false,
            isCurrent: true,
            score: 98,
            recommendation: "推荐主节点",
            asnShort: "ISP 住宅",
            riskLevel: "isp",
            riskDetail: "无代理标记",
            driftCount24h: 0,
            claudeStatus: "ok",
            claudeLabel: "Claude ✓",
            geminiStatus: "ok",
            geminiLabel: "AGY ✓",
            cfBlocked: false,
            webCfChallenge: false,
          },
          {
            name: "🇨🇳台湾1|流媒体AI",
            regionCode: "HK",
            regionLabel: "香港 · AnyTLS",
            nodeType: "AnyTLS",
            delayMs: 117,
            jitterMs: 7,
            dropRatePct: 0,
            blocked: true,
            isCurrent: false,
            score: 35,
            recommendation: "禁区不可用",
            asnShort: "落地禁区",
            riskLevel: "isp",
            riskDetail: "无代理标记",
            driftCount24h: 0,
            claudeStatus: "blocked",
            claudeLabel: "落地禁区",
            geminiStatus: "ok",
            geminiLabel: "AGY ✓",
            cfBlocked: true,
            webCfChallenge: false,
          },
        ],
      },
    });

    render(<NodesTrafficPage />);
    expect(screen.getByTestId("nodes-usable-count")).toHaveTextContent("1个");
    expect(screen.getByTestId("nodes-blocked-count")).toHaveTextContent("4个");
    expect(screen.getByTestId("nodes-usable-breakdown")).toHaveTextContent("订阅共 5 · 评估 2（1 个不可用）");
    expect(screen.getByTestId("nodes-blocked-breakdown")).toHaveTextContent("名称禁区 3 · 落地禁区 1");
    expect(screen.getByTestId("nodes-quarantine-section")).toBeInTheDocument();
    expect(screen.getByTestId("nodes-quarantine-table")).toHaveTextContent("禁区不可用");
    expect(screen.getByTestId("nodes-eval-table")).not.toHaveTextContent("🇨🇳台湾1|流媒体AI");
    expect(screen.queryByText("拉黑不可用")).not.toBeInTheDocument();
  });

  it("清理确认弹窗默认同时勾选桌面端与 CLI 登录态，并展示各端脱敏账号（取消勾选即可保留）", async () => {
    useGuardStore.setState({
      cleanModal: { open: true, sourceLabel: "来自控制台 · 单号卫生锁" },
    });

    render(<CleanConfirmModal />);

    await waitFor(() => {
      expect(screen.getByTestId("clean-check-cli_auth_and_backups")).toBeInTheDocument();
    });
    const authBox = screen.getByTestId("clean-check-auth") as HTMLInputElement;
    const cliBox = screen.getByTestId("clean-check-cli_auth_and_backups") as HTMLInputElement;
    expect(authBox.checked).toBe(true);
    expect(cliBox.checked).toBe(true);

    expect(screen.getByTestId("clean-account-auth")).toHaveTextContent("a4722ea6");
    expect(screen.getByTestId("clean-account-cli_auth_and_backups")).toHaveTextContent("stev***88@gmail.com");

    // 取消勾选 CLI 登录态后，明确展示「将保留」
    fireEvent.click(cliBox);
    expect(cliBox.checked).toBe(false);
    expect(screen.getByTestId("clean-account-cli_auth_and_backups")).toHaveTextContent("将保留");
  });

  it("账户审计页升级 Application→Cookies 教程与 SVG 图、无效粘贴红字提示及定时任务 ≥6 轻度分级", () => {
    const mockReport = buildMockAccountAuditReport("default");
    mockReport.local.hygiene.activeScheduledTasksCount = 0;
    mockReport.local.hygiene.historicalScheduledTasksCount = 10;
    mockReport.local.hygiene.scheduledTasksCount = 0;
    mockReport.local.hygiene.scheduledTasksDir = "C:\\Users\\demo\\.claude\\scheduled-tasks";

    useGuardStore.setState({
      accountAudit: mockReport,
      accountAuditLoading: false,
      auditSubTab: "audit",
    });

    render(<AccountAuditPage />);

    // 1. 0 活跃 + 10 历史脚本：节律正常（绝不标红「存在机刷」）
    const autoGroup = screen.getByTestId("audit-group-g-auto");
    expect(autoGroup).toHaveTextContent("节律正常");
    expect(autoGroup).not.toHaveTextContent("存在机刷");

    // 2. 展开云端核验面板：粘贴静态 JS URL 显示明确红字纠错，展开教程显示 Application→Cookies + SVG
    fireEvent.click(screen.getByTestId("audit-group-g-cloud").querySelector(".audit-row")!);
    const input = screen.getByTestId("audit-sk-input");
    fireEvent.change(input, {
      target: { value: "https://assets-proxy.anthropic.com/claude-ai/v2/assets/v1/c601666a3.js" },
    });
    expect(screen.getByTestId("audit-sk-feedback")).toHaveTextContent("未识别到有效 sessionKey");
    expect((screen.getByTestId("btn-verify-cloud-sk") as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(screen.getByTestId("btn-toggle-sk-how"));
    const howPanel = screen.getByTestId("audit-sk-how-panel");
    expect(howPanel).toHaveTextContent("Application（应用）");
    expect(howPanel).toHaveTextContent("Cookies");
    expect(howPanel.querySelector("svg")).toBeTruthy();

    // 3. 未核验 sk 时 Portal 第 4 格与前 3 格统一显示「待 sk 实证」
    expect(screen.getByTestId("portal-unverified-value")).toHaveTextContent("待 sk 实证");
  });

  it("顶栏显示新版本发布徽章，守卫配置页展示「立即更新 / 已是最新版本」与「GitHub 官网」按钮", () => {
    useGuardStore.setState({
      updateInfo: {
        currentVersion: "0.3.0",
        available: true,
        latestVersion: "0.3.1",
        publishedAt: "2026-11-26",
        notes: "修复多项体验细节",
        viaProxy: true,
        message: "发现新版本 v0.3.1",
      },
      updateChecking: false,
      updateInstalling: false,
    });

    const { unmount } = render(<WindowChrome />);
    expect(screen.getByTestId("topbar-new-version-badge")).toHaveTextContent("新版 v0.3.1 发布啦");
    const subtitleEl = screen.getByTestId("brand-subtitle");
    fireEvent.mouseEnter(subtitleEl);
    expect(screen.getByTestId("brand-subtitle-tooltip")).toHaveTextContent(
      "Claude is awesome, but fuck Dario!"
    );
    fireEvent.mouseLeave(subtitleEl);
    expect(screen.queryByTestId("brand-subtitle-tooltip")).not.toBeInTheDocument();
    unmount();

    const { unmount: unmountSettings } = render(<SettingsPage />);
    expect(screen.getByTestId("btn-install-app-update")).toHaveTextContent("立即更新 v0.3.1");
    expect(screen.getByTestId("btn-open-github-official")).toHaveTextContent("GitHub 官网");
    unmountSettings();

    // 无新版本时：配置页标题行显示只读「已是最新版本」徽章，右侧为单一「检查更新」操作按钮（消灭双按钮并发转圈）
    useGuardStore.setState({
      updateInfo: {
        currentVersion: "0.3.1",
        available: false,
        latestVersion: "0.3.1",
        publishedAt: null,
        notes: null,
        viaProxy: false,
        message: "当前已是最新版本 v0.3.1",
      },
    });
    render(<SettingsPage />);
    expect(screen.getByTestId("updater-status-badge")).toHaveTextContent("已是最新版本");
    expect(screen.getByTestId("btn-check-app-update")).toHaveTextContent("检查更新");
    expect(screen.getByTestId("btn-open-github-official")).toHaveTextContent("GitHub 官网");
  });

  it("桌面端清空但 CLI 残留失效凭据/跨号缓存时：绝不报「纯净无混」，且清理 CLI 按钮保持可点击", () => {
    const staleReport = buildMockAccountAuditReport("default");
    staleReport.primarySource = "cli_stale";
    staleReport.local.desktop.orgIdPrefixes = [];
    staleReport.local.crossClientOrgMismatch = false;
    staleReport.topology = {
      hygieneState: "single_surface_stale_or_polluted",
      headline:
        "桌面端已清空，但 CLI 仍残留失效/跨号旧数据（star***t4@gmail.com）：~/.claude.json 内部双账号交叉污染；CLI 登录凭据已失效",
      detail: "若该 CLI 旧号已封禁，切勿直接登新号，请先一键清理 CLI 残留。",
      desktopStatus: "empty",
      desktopAccounts: [],
      cliStatus: "stale_or_polluted",
      cliAccount: "star***t4@gmail.com (Pro · CLI · 7aacf131)",
      cliStaleReasons: ["CLI 登录凭据 (.credentials.json) 已失效/过期"],
      sessionDirOrphans: ["078cfdb1"],
      hasCliCleanupTarget: true,
    };

    useGuardStore.setState({
      accountAudit: staleReport,
      accountAuditLoading: false,
      auditSubTab: "audit",
    });

    render(<AccountAuditPage />);
    const mixGroup = screen.getByTestId("audit-group-g-mix");
    expect(mixGroup).toHaveTextContent("CLI 残留预警");
    expect(mixGroup).not.toHaveTextContent("纯净无混");

    fireEvent.click(mixGroup.querySelector(".audit-row")!);
    const cleanBtn = screen.getByRole("button", { name: "立即清理 CLI 残留与备份" }) as HTMLButtonElement;
    expect(cleanBtn.disabled).toBe(false);
  });
});
