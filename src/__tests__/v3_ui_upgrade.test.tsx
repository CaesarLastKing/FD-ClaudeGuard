import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { ConsolePage } from "@/pages/ConsolePage";
import { NodesTrafficPage } from "@/pages/NodesTrafficPage";
import { useGuardStore } from "@/stores/guardStore";
import type { ClaudeConn } from "@/types/guard";

describe("UI v3.0 商业级视觉升级终审覆盖点回归", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useGuardStore.setState({
      config: { ...DEFAULT_CONFIG },
      snapshot: { ...FALLBACK_SNAPSHOT },
      preflight: { ...FALLBACK_PREFLIGHT },
      nodesSubTab: "quality",
      selectedCheckId: "node_proxy",
      ackedFlowIds: [],
      toasts: [],
      initialized: true,
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("控制台终审覆盖点：移除页头安全守则按钮、通过 X/Y 后安全启动配色规则、详情区边框排障按钮", () => {
    // 1. 未打满态（10/12）：数字标 --bad-fg 柔丹红
    useGuardStore.setState({
      preflight: {
        ...FALLBACK_PREFLIGHT,
        items: FALLBACK_PREFLIGHT.items.map((it) =>
          it.id === "node_tun" || it.id === "sys_env"
            ? { ...it, status: "fail" as const }
            : { ...it, status: "ok" as const }
        ),
      },
      selectedCheckId: "node_tun",
    });

    const { rerender } = render(<ConsolePage />);
    expect(screen.queryByRole("button", { name: /安全守则/ })).not.toBeInTheDocument();
    expect(screen.getByTestId("console-guard-status-pill")).toBeInTheDocument();

    const mustSummary = screen.getByTestId("console-must-summary");
    expect(mustSummary.textContent).toBe("通过 10/12 后安全启动");
    const numSpanFail = mustSummary.querySelector("span");
    expect(numSpanFail?.style.color).toContain("var(--bad-fg)");

    // 排障包按钮使用统一标准边框按钮（非裸文字链接）
    const diagBtn = screen.getByTestId("btn-export-ai-diag");
    expect(diagBtn.className).toContain("guard-btn-flat");
    expect(diagBtn.className).not.toContain("guard-text-link");

    // 2. 全打满态（12/12）：数字静默无彩色
    act(() => {
      useGuardStore.setState({
        preflight: {
          ...FALLBACK_PREFLIGHT,
          items: FALLBACK_PREFLIGHT.items.map((it) => ({ ...it, status: "ok" as const })),
        },
      });
    });
    rerender(<ConsolePage />);
    const mustSummaryOk = screen.getByTestId("console-must-summary");
    expect(mustSummaryOk.textContent).toBe("通过 12/12 后安全启动");
    const numSpanOk = mustSummaryOk.querySelector("span");
    expect(numSpanOk?.style.color).toBe("");
  });

  it("实时流量终审覆盖点：省略 :443 与常规 Claude-Fixed、异常显脱组链路、基于 startedAtMs 计算实时持续时长", async () => {
    const now = Date.now();
    const conns: ClaudeConn[] = [
      {
        id: "c-ok",
        anomaly: false,
        process: "claude.exe",
        host: "api.anthropic.com:443",
        rule: "DomainSuffix(anthropic.com)",
        chain: "Claude-Fixed → us美国1|流媒体AI",
        action: "正常放行",
        time: "12:00:00",
        startedAtMs: now - 95_000,
        bytesLabel: "1.42 MB",
        purposeLabel: "核心 API",
        purposeDetail: "模型推理与对话流",
        isUnlistedDomain: false,
      },
      {
        id: "c-anom",
        anomaly: true,
        process: "claude.exe",
        host: "claude.ai:8443",
        rule: "Match",
        chain: "DIRECT",
        action: "风险连接",
        time: "12:01:00",
        startedAtMs: now - 15_000,
        bytesLabel: "4.8 KB",
        purposeLabel: "主站与会话",
        purposeDetail: "网页登录与会话",
        isUnlistedDomain: false,
      },
      {
        id: "c-rej",
        anomaly: false,
        process: "claude.exe",
        host: "o1158394.ingest.sentry.io:443",
        rule: "DomainSuffix(sentry.io)",
        chain: "REJECT-DROP",
        action: "已拦截（防回传）",
        time: "12:01:20",
        startedAtMs: now - 10_000,
        bytesLabel: "0 B",
        purposeLabel: "遥测 · 崩溃上报",
        purposeDetail: "Sentry 错误上报",
        isUnlistedDomain: false,
      },
    ];

    vi.spyOn(ipc, "getLiveConnections").mockResolvedValue(conns);
    useGuardStore.setState({
      nodesSubTab: "traffic",
      nodeReport: {
        connected: true,
        endpoint: "Named Pipe",
        groupName: "Claude-Fixed",
        currentNode: "us美国1|流媒体AI",
        totalRawNodes: 2,
        filteredBlockedCount: 0,
        nodes: [],
      },
    });

    render(<NodesTrafficPage />);
    const table = await screen.findByTestId("live-conns-table");

    await waitFor(() => {
      // :443 已省略，非 443 端口保留
      expect(table.textContent).toContain("api.anthropic.com");
      expect(table.textContent).not.toContain("api.anthropic.com:443");
      expect(table.textContent).toContain("claude.ai:8443");
      // 常规行省略 Claude-Fixed 前缀只显落地节点；异常行显脱出 Claude-Fixed
      expect(table.textContent).toContain("us美国1|流媒体AI");
      expect(table.textContent).not.toContain("Claude-Fixed → us美国1|流媒体AI");
      expect(table.textContent).toContain("脱出 Claude-Fixed");
      // 规则去重，不重复把域名贴在规则列
      expect(table.textContent).toContain("域名规则");
      expect(table.textContent).toContain("防回传拦截");
      // 实时持续时长（95s -> 1m 35s 左右）与阻断态「已阻断」
      expect(table.textContent).toMatch(/1m 3[5-9]s/);
      expect(table.textContent).toContain("已阻断");
    });
  });
});
