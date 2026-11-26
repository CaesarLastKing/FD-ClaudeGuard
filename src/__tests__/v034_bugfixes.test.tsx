import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NetworkRescueRollbackPanel } from "@/components/NetworkRescueRollbackPanel";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { AccountAuditPage } from "@/pages/AccountAuditPage";
import { ConsolePage } from "@/pages/ConsolePage";
import { NodesTrafficPage } from "@/pages/NodesTrafficPage";
import { useGuardStore } from "@/stores/guardStore";
import type { ClaudeConn, DeepAuditProgress } from "@/types/guard";

describe("v0.3.4 模块 05 回归：前端状态机、竞态防覆写与交互边界", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useGuardStore.setState({
      config: { ...DEFAULT_CONFIG },
      snapshot: { ...FALLBACK_SNAPSHOT },
      preflight: { ...FALLBACK_PREFLIGHT },
      accountAudit: null,
      accountAuditLoading: false,
      accountAuditError: null,
      deepAudit: {
        running: false,
        phase: "idle",
        currentIndex: 0,
        total: 0,
        currentNode: "",
        originalNode: "",
        currentNodeVerified: false,
        message: "",
      },
      riskModal: null,
      toasts: [],
      initialized: true,
      activeTab: "console",
      ackedFlowIds: [],
      ackedLogIds: [],
    });
  });

  it("BUG-P0-15: 深度核验事件先推送终态后，迟到的 invoke 返回值不得把 running 覆写回 true", async () => {
    let resolveInvoke!: (val: DeepAuditProgress) => void;
    vi.spyOn(ipc, "startDeepNodeAudit").mockImplementation(
      () =>
        new Promise<DeepAuditProgress>((resolve) => {
          resolveInvoke = resolve;
        })
    );
    vi.spyOn(ipc, "getNodesAndQuality").mockResolvedValue({
      connected: true,
      endpoint: "http://127.0.0.1:9097",
      groupName: "Claude-Fixed",
      currentNode: "US-01",
      totalRawNodes: 1,
      filteredBlockedCount: 0,
      nodes: [],
    });

    const startPromise = useGuardStore.getState().startDeepNodeAudit(false);
    // 模拟后端事件提前推送已完成终态
    useGuardStore.getState().setDeepAuditFromEvent({
      running: false,
      phase: "done",
      currentIndex: 3,
      total: 3,
      currentNode: "US-01",
      originalNode: "US-01",
      currentNodeVerified: true,
      message: "核验完成",
    });

    // 迟到的 invoke 仍返回 running: true
    resolveInvoke({
      running: true,
      phase: "running",
      currentIndex: 0,
      total: 3,
      currentNode: "US-01",
      originalNode: "US-01",
      currentNodeVerified: false,
      message: "开始核验",
    });
    await startPromise;

    expect(useGuardStore.getState().deepAudit.running).toBe(false);
    expect(useGuardStore.getState().deepAudit.phase).toBe("done");
  });

  it("BUG-P0-15: 账户审计本地扫描失败时展示错误重试卡片而非无限加载白屏", async () => {
    const spy = vi
      .spyOn(ipc, "auditAccountLocal")
      .mockRejectedValueOnce(new Error("本地日志目录不可读"));

    render(<AccountAuditPage />);

    const card = await screen.findByTestId("audit-load-error-card");
    expect(card).toHaveTextContent("本地账户审计加载失败");
    expect(card).toHaveTextContent("本地日志目录不可读");
    expect(screen.getByTestId("btn-retry-account-audit")).toBeInTheDocument();
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("BUG-P1-20: 节点流量页「全部标为已处理」同步调用后端 ackFlowAnomalies 并更新状态", async () => {
    const fakeConns: ClaudeConn[] = [
      {
        id: "conn-leak-1",
        anomaly: true,
        acked: false,
        process: "claude.exe",
        host: "api.anthropic.com",
        rule: "MATCH",
        chain: "DIRECT",
        action: "直连泄漏",
        time: "10:00:00",
        bytesLabel: "300 B",
      },
    ];
    vi.spyOn(ipc, "getNodesAndQuality").mockResolvedValue({
      connected: true,
      endpoint: "http://127.0.0.1:9097",
      groupName: "Claude-Fixed",
      currentNode: "US-01",
      totalRawNodes: 1,
      filteredBlockedCount: 0,
      nodes: [],
    });
    vi.spyOn(ipc, "getLiveConnections").mockResolvedValue(fakeConns);
    const ackSpy = vi.spyOn(ipc, "ackFlowAnomalies").mockResolvedValue({
      ...FALLBACK_SNAPSHOT,
      liveFlowAnomalies: 0,
      activeFlowAnomalies: 0,
    });

    useGuardStore.setState({ nodesSubTab: "traffic" });
    render(<NodesTrafficPage />);
    const btn = await screen.findByRole("button", { name: "全部标为已处理" });
    fireEvent.click(btn);

    await waitFor(() => {
      expect(ackSpy).toHaveBeenCalledWith(["conn-leak-1"]);
    });
    expect(useGuardStore.getState().ackedFlowIds).toContain("conn-leak-1");
  });

  it("BUG-P1-21: 熔断激活且存在多项必检失败时，控制台主 CTA 优先展示「解除熔断保护」", () => {
    useGuardStore.setState({
      snapshot: {
        ...FALLBACK_SNAPSHOT,
        killSwitchActive: true,
      },
      preflight: {
        ...FALLBACK_PREFLIGHT,
        items: FALLBACK_PREFLIGHT.items.map((item) =>
          item.part === "must" ? { ...item, status: "fail" as const } : item
        ),
      },
    });

    render(<ConsolePage />);
    const btn = screen.getByTestId("btn-console-release-killswitch");
    expect(btn).toBeInTheDocument();
    expect(btn).toHaveTextContent("解除熔断保护");
  });

  it("BUG-P1-22: 连续更新 config 时后发的请求结果不被慢响应旧请求覆盖", async () => {
    let resolveFirst!: (val: typeof DEFAULT_CONFIG) => void;
    let resolveSecond!: (val: typeof DEFAULT_CONFIG) => void;
    const spy = vi
      .spyOn(ipc, "updateConfig")
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveFirst = resolve;
          })
      )
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            resolveSecond = resolve;
          })
      );

    const p1 = useGuardStore.getState().updateConfig({ bootStart: false });
    const p2 = useGuardStore.getState().updateConfig({ showHud: false });

    resolveSecond({ ...DEFAULT_CONFIG, bootStart: false, showHud: false });
    await p2;
    resolveFirst({ ...DEFAULT_CONFIG, bootStart: false, showHud: true });
    await p1;

    expect(spy).toHaveBeenCalledTimes(2);
    expect(useGuardStore.getState().config.showHud).toBe(false);
  });

  it("BUG-P2-07: 撤回中心读取基线失败时显示错误提示与重试按钮，不伪装成 0 项改动", async () => {
    vi.spyOn(ipc, "inspectRollbackStatus").mockRejectedValueOnce(new Error("读取快照权限不足"));

    render(<NetworkRescueRollbackPanel />);
    const errBox = await screen.findByTestId("rollback-load-error");
    expect(errBox).toHaveTextContent("读取撤回基线失败");
    expect(screen.getByTestId("btn-retry-rollback-overview")).toBeInTheDocument();
  });
});
