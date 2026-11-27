import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { useGuardStore } from "@/stores/guardStore";

beforeEach(() => {
  useGuardStore.setState({
    config: { ...DEFAULT_CONFIG },
    snapshot: { ...FALLBACK_SNAPSHOT, triggeredPlaybookIds: [] },
    preflight: FALLBACK_PREFLIGHT,
    activeTab: "console",
    selectedCheckId: "node_proxy",
    playbookOpen: false,
    playbookFocusId: null,
    playbookFocusSeq: 0,
    toasts: [],
    riskModal: null,
    initialized: false,
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  cleanup();
});

describe("FD Claude Guard M2 真实探针与一键修复闭环", () => {
  it("点击一键处理全部问题后自动聚焦首个需手动配合项并刷新状态", async () => {
    const spy = vi.spyOn(ipc, "oneClickFixAll").mockResolvedValue({
      fixedIds: ["claude_tel"],
      skippedManualId: "node_group",
      summary: "已完成 1 项自动处理；已自动聚焦至「策略组与全家桶规则锁死」",
      report: {
        ...FALLBACK_PREFLIGHT,
        items: FALLBACK_PREFLIGHT.items.map((it) =>
          it.id === "claude_tel" ? { ...it, status: "ok", fixLabel: null } : it
        ),
      },
      snapshot: { ...FALLBACK_SNAPSHOT, mustPassed: 1, mustTotal: 9 },
    });

    render(<App />);
    const btn = await screen.findByRole("button", { name: /一键处理全部/ });
    fireEvent.click(btn);

    await waitFor(() => {
      expect(spy).toHaveBeenCalledTimes(1);
      expect(useGuardStore.getState().selectedCheckId).toBe("node_group");
    });
  });

  it("节点流量页展示过滤禁区后的可用节点并区分同区热备与跨洲切换弹窗", async () => {
    vi.spyOn(ipc, "getNodesAndQuality").mockResolvedValue({
      connected: true,
      endpoint: "\\\\.\\pipe\\verge-mihomo-test",
      groupName: "Claude-Fixed",
      currentNode: "US-LA-Static-01",
      totalRawNodes: 6,
      filteredBlockedCount: 3,
      nodes: [
        {
          name: "US-LA-Static-01",
          regionCode: "US",
          nodeType: "Shadowsocks",
          delayMs: 42,
          jitterMs: 3,
          dropRatePct: 0,
          blocked: false,
          isCurrent: true,
          score: 96,
          recommendation: "推荐锁定",
        },
        {
          name: "US-LA-Static-02",
          regionCode: "US",
          nodeType: "Shadowsocks",
          delayMs: 48,
          jitterMs: 4,
          dropRatePct: 0,
          blocked: false,
          isCurrent: false,
          score: 96,
          recommendation: "推荐锁定",
        },
        {
          name: "JP-Tokyo-02",
          regionCode: "JP",
          nodeType: "Trojan",
          delayMs: 92,
          jitterMs: 9,
          dropRatePct: 1.0,
          blocked: false,
          isCurrent: false,
          score: 84,
          recommendation: "跨洲备选",
        },
      ],
    });

    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /节点流量/ }));

    expect(await screen.findByText("US-LA-Static-02")).toBeInTheDocument();
    expect(screen.getByTestId("nodes-usable-count")).toHaveTextContent("3");

    // 同区切换（US -> US）
    const switchBtns = screen.getAllByRole("button", { name: "切换锁定" });
    fireEvent.click(switchBtns[0]);
    expect(await screen.findByRole("dialog", { name: "节点切换风险评估" })).toBeInTheDocument();
    expect(screen.getAllByText("同区热备").length).toBeGreaterThanOrEqual(1);

    // 关闭弹窗后测试跨洲切换（US -> JP）
    fireEvent.click(screen.getByRole("button", { name: "关闭弹窗" }));
    fireEvent.click(switchBtns[1]);
    expect(await screen.findByRole("dialog", { name: "节点切换风险评估" })).toBeInTheDocument();
    expect(screen.getByText("跨洲切换")).toBeInTheDocument();
  });
});
