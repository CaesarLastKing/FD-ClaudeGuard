import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NetworkRescueRollbackPanel } from "@/components/NetworkRescueRollbackPanel";
import { Sidebar } from "@/components/Sidebar";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
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

  it("Clash Verge 未开启自启且风险为 warn 时应显示「未开启（建议开启）」，Claude 已开启且 warn 时显示「已开启（有风险）」", () => {
    render(<SettingsPage />);

    expect(screen.getByTestId("startup-chip-FD Claude Guard").textContent).toBe("已开启自启");
    expect(screen.getByTestId("startup-chip-Clash Verge Rev").textContent).toBe("未开启（建议开启）");
    expect(screen.getByTestId("startup-chip-Claude Desktop").textContent).toBe("已开启（有风险）");
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
    expect(screen.getByText("共评估 2 个（1 个不可用）")).toBeInTheDocument();
    expect(screen.getByText("禁区不可用")).toBeInTheDocument();
    expect(screen.queryByText("拉黑不可用")).not.toBeInTheDocument();
  });
});
