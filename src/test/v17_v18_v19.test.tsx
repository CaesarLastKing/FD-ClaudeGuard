import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import App from "@/App";
import { HudCard } from "@/components/HudCard";
import { Sidebar } from "@/components/Sidebar";
import { ConsolePage } from "@/pages/ConsolePage";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT } from "@/lib/ipc";
import { NodesTrafficPage } from "@/pages/NodesTrafficPage";
import { useGuardStore } from "@/stores/guardStore";

describe("免费开源无锁门禁与核心交互回归（T-057 + 增量 17/18/19）", () => {
  beforeEach(() => {
    useGuardStore.setState({
      activeTab: "console",
      nodesSubTab: "quality",
      selectedCheckId: "node_group",
      supportModalOpen: false,
      preflight: FALLBACK_PREFLIGHT,
      snapshot: { ...FALLBACK_SNAPSHOT },
      config: { ...DEFAULT_CONFIG },
    });
  });

  it("T-057：免费开源版全量 17 项检测与 5 大导航零锁开放，无激活弹窗/遮罩/锁图标", async () => {
    render(<App />);

    // 控制台标题区无未激活胶囊，右侧直接展示明文步骤与排障包导出
    expect(screen.queryByTestId("console-license-chip")).not.toBeInTheDocument();
    expect(screen.queryByTestId("guide-mosaic-locked")).not.toBeInTheDocument();
    expect(screen.queryByTestId("evidence-mosaic-locked")).not.toBeInTheDocument();
    expect(screen.getByTestId("guide-plaintext")).toBeInTheDocument();
    expect(screen.getByTestId("btn-export-ai-diag")).toBeInTheDocument();

    // 所有核心检测项标题完整明文展示，侧边栏零锁图标
    expect(screen.getAllByText("策略组与全家桶规则锁死").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Windows 系统定位服务关闭")).toBeInTheDocument();
    expect(screen.getByText("本地封号污染残留审查")).toBeInTheDocument();
    expect(screen.getByText("单号卫生锁（防混号与跨 orgId）")).toBeInTheDocument();
    expect(screen.queryByTestId("nav-lock-nodes")).not.toBeInTheDocument();
    expect(screen.queryByTestId("nav-lock-logs")).not.toBeInTheDocument();
    expect(screen.queryByTestId("nav-lock-maintain")).not.toBeInTheDocument();
    expect(screen.queryByTestId("nav-lock-config")).not.toBeInTheDocument();

    // 4 个副页面全部直接可进，无付费墙门禁
    fireEvent.click(screen.getByRole("button", { name: /账户审计/ }));
    expect(screen.queryByTestId("locked-gate-audit")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /节点流量/ }));
    expect(screen.queryByTestId("locked-gate-nodes")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /环境维护/ }));
    expect(screen.queryByTestId("locked-gate-maintain")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /守卫配置/ }));
    expect(screen.queryByTestId("locked-gate-config")).not.toBeInTheDocument();
    await waitFor(() => {
      expect(useGuardStore.getState().initialized).toBe(true);
      expect(useGuardStore.getState().updateChecking).toBe(false);
    });
  });

  it("主窗口顶栏耳机支持按钮弹出开源交流支持弹窗（不含商业激活跳转按钮）", async () => {
    render(<App />);
    await waitFor(() => {
      expect(useGuardStore.getState().initialized).toBe(true);
    });

    const supportBtn = screen.getByTestId("topbar-btn-support");
    fireEvent.click(supportBtn);
    const supportModal = await screen.findByTestId("support-modal");
    expect(supportModal).toBeInTheDocument();
    expect(screen.getByTestId("support-qq-number")).toHaveTextContent("2568515327");
    expect(screen.queryByTestId("btn-support-to-activate")).not.toBeInTheDocument();
  });

  it("增量 17：侧边栏与悬浮窗同步展示 Kill-Hold 盯防蓝态与解除按钮", async () => {
    useGuardStore.setState({
      snapshot: {
        ...FALLBACK_SNAPSHOT,
        killHoldActive: true,
        killHoldRemainingSecs: 45,
        killHoldBlockedCount: 2,
        killHoldTxLocked: false,
      },
    });

    const { unmount } = render(<App />);
    expect(screen.getByTestId("sidebar-proc-status")).toHaveTextContent("盯防 45s");
    expect(screen.getByTestId("btn-release-kill-hold")).toBeInTheDocument();
    await waitFor(() => {
      expect(useGuardStore.getState().initialized).toBe(true);
    });
    unmount();

    render(
      <HudCard
        initialConfig={DEFAULT_CONFIG}
        initialSnapshot={{
          ...FALLBACK_SNAPSHOT,
          killHoldActive: true,
          killHoldRemainingSecs: 45,
          killHoldBlockedCount: 1,
        }}
      />
    );
    const procTile = screen.getByTestId("hud-tile-proc");
    expect(procTile.className).toContain("is-hold");
    expect(procTile).toHaveTextContent("盯防 45s");
  });

  it("增量 18/v5：节点页展示 6 列分列评估表（含延迟/断连/稳定性）、悬停解释与右侧当前锁定", async () => {
    useGuardStore.setState({
      activeTab: "nodes",
      nodesSubTab: "quality",
      nodeReport: {
        connected: true,
        endpoint: "Named Pipe",
        groupName: "Claude-Fixed",
        currentNode: "US-LA-Static-01",
        totalRawNodes: 5,
        filteredBlockedCount: 2,
        currentExitSummary: "US · 104.28.xx.xx · ISP 住宅 · 24h 0 漂移",
        nodes: [
          {
            name: "US-LA-Static-01",
            regionCode: "US",
            regionLabel: "美国洛杉矶 · 主节点",
            nodeType: "Vless",
            delayMs: 42,
            jitterMs: 3,
            dropRatePct: 0,
            blocked: false,
            isCurrent: true,
            score: 96,
            recommendation: "推荐主节点",
            asnShort: "ISP 住宅",
            riskLevel: "isp",
            riskDetail: "无代理标记",
            driftCount24h: 0,
            claudeStatus: "ok",
            claudeLabel: "Claude ✓",
            geminiStatus: "ok",
            geminiLabel: "Gemini ✓",
            dualAiOk: true,
            cfBlocked: false,
            webCfChallenge: false,
          },
          {
            name: "TW-Taipei-04",
            regionCode: "TW",
            regionLabel: "中国台湾 · 备选",
            nodeType: "Vless",
            delayMs: 72,
            jitterMs: 11,
            dropRatePct: 0.3,
            blocked: false,
            isCurrent: false,
            score: 78,
            recommendation: "仅 Claude 备选",
            asnShort: "常规机房",
            riskLevel: "hosting",
            riskDetail: "0 滥用记录",
            driftCount24h: 0,
            claudeStatus: "ok",
            claudeLabel: "Claude ✓",
            geminiStatus: "cn_redirect",
            geminiLabel: "Gemini 限区",
            dualAiOk: false,
            cfBlocked: false,
            webCfChallenge: false,
          },
          {
            name: "US-Bad-09",
            regionCode: "US",
            regionLabel: "美国 · 脏节点",
            nodeType: "Vmess",
            delayMs: 162,
            jitterMs: 30,
            dropRatePct: 8.5,
            blocked: false,
            isCurrent: false,
            score: 38,
            recommendation: "拉黑不可用",
            asnShort: "高危滥用",
            riskLevel: "abuser",
            riskDetail: "命中滥用黑名单",
            driftCount24h: 2,
            claudeStatus: "cf_403",
            claudeLabel: "Claude 拉黑",
            geminiStatus: "restricted",
            geminiLabel: "Gemini 限区",
            dualAiOk: false,
            cfBlocked: true,
            webCfChallenge: false,
          },
        ],
      },
    });

    render(<NodesTrafficPage />);

    const connStatus = screen.getByTestId("mihomo-conn-status");
    expect(connStatus.textContent).toContain("管道已连接 (Claude-Fixed)");
    expect(connStatus.textContent).not.toContain("已直连");

    const table = screen.getByTestId("nodes-eval-table");
    const headers = Array.from(table.querySelectorAll("thead th")).map((th) => th.textContent);
    expect(headers).toEqual([
      "节点 / 地区",
      "平台支持",
      "节点类型",
      "延迟 / 断连 / 稳定性",
      "质量评分",
      "操作",
    ]);
    expect(table.textContent).toContain("Claude ✓");
    expect(table.textContent).toContain("AGY ✓");
    expect(table.textContent).toContain("AGY 限区");
    expect(table.textContent).toContain("当前锁定");

    // 不可用/拉黑节点已独立展示在隔离区表格，与可用区视觉隔离
    const quarantineTable = screen.getByTestId("nodes-quarantine-table");
    expect(quarantineTable.textContent).toContain("Claude 拉黑");

    fireEvent.mouseEnter(screen.getByText("Claude 拉黑"));
    expect(screen.getByTestId("node-hover-tooltip")).toHaveTextContent("Cloudflare 403");
    fireEvent.mouseLeave(screen.getByText("Claude 拉黑"));
    expect(screen.queryByTestId("node-hover-tooltip")).not.toBeInTheDocument();

    const limitChips = screen.getAllByText("AGY 限区");
    fireEvent.mouseEnter(limitChips[0]);
    expect(screen.getByTestId("node-hover-tooltip")).toHaveTextContent("Antigravity");
  });

  it("盯防卡片默认及解除盯防后不残留白边，且节点不可用/漂移风险时侧边栏角标三方联动", () => {
    const baseState = useGuardStore.getState();
    useGuardStore.setState({
      snapshot: {
        ...baseState.snapshot,
        killHoldActive: false,
        nodeDown: false,
        activeFlowAnomalies: 0,
      },
      preflight: {
        ...baseState.preflight,
        items: baseState.preflight.items.map((item) =>
          item.id === "node_geo" ? { ...item, status: "ok" } : item
        ),
      },
    });

    const { rerender } = render(<Sidebar />);
    const procCard = screen.getByTestId("sidebar-proc-card");
    expect(procCard.style.border).toContain("var(--border)");
    expect(screen.queryByTestId("nav-badge-nodes")).not.toBeInTheDocument();

    act(() => {
      useGuardStore.setState({
        snapshot: { ...useGuardStore.getState().snapshot, killHoldActive: true, killHoldRemainingSecs: 45 },
      });
    });
    rerender(<Sidebar />);
    expect(procCard.style.border).toContain("rgba(0, 111, 238, 0.45)");

    act(() => {
      useGuardStore.setState({
        snapshot: { ...useGuardStore.getState().snapshot, killHoldActive: false, killHoldRemainingSecs: 0 },
      });
    });
    rerender(<Sidebar />);
    expect(procCard.style.border).toContain("var(--border)");

    act(() => {
      useGuardStore.setState({
        preflight: {
          ...useGuardStore.getState().preflight,
          items: useGuardStore.getState().preflight.items.map((item) =>
            item.id === "node_geo" ? { ...item, status: "warn" } : item
          ),
        },
      });
    });
    rerender(<Sidebar />);
    const warnBadge = screen.getByTestId("nav-badge-nodes");
    expect(warnBadge.textContent).toBe("1");
    expect(warnBadge.style.color).toContain("var(--warning)");

    act(() => {
      useGuardStore.setState({
        snapshot: { ...useGuardStore.getState().snapshot, nodeDown: true, activeFlowAnomalies: 1 },
        preflight: {
          ...useGuardStore.getState().preflight,
          items: useGuardStore.getState().preflight.items.map((item) =>
            item.id === "node_geo" ? { ...item, status: "fail" } : item
          ),
        },
      });
    });
    rerender(<Sidebar />);
    const failBadge = screen.getByTestId("nav-badge-nodes");
    expect(failBadge.textContent).toBe("1");
    expect(failBadge.style.color).toContain("var(--danger-bright)");
  });

  it("出口节点漂移风险(Warn 且命中 DRIFT DETECTED)才显示重置漂移基准按钮，非漂移跨洲错配与真不可用(Fail)仅引导换节点", () => {
    const baseState = useGuardStore.getState();
    useGuardStore.setState({
      selectedCheckId: "opt_exit_geo",
      preflight: {
        ...baseState.preflight,
        items: baseState.preflight.items.map((item) =>
          item.id === "opt_exit_geo"
            ? {
                ...item,
                status: "warn",
                summary: "AU · 常规机房 · 24h 落地 IP 漂移 1 次预警",
                evidence: "24h Landing IP Drift: DRIFT DETECTED (count=1)",
                fixLabel: "前往「节点流量」更换稳定节点 →",
              }
            : { ...item, status: "ok" }
        ),
      },
    });

    const { rerender } = render(<ConsolePage />);
    const resetBtn = screen.getByTestId("btn-reset-drift-baseline");
    expect(resetBtn.className).toContain("guard-btn-primary");
    expect(resetBtn.textContent).toContain("确认当前 IP 已稳定（重置漂移基准）");
    expect(screen.getByTestId("btn-goto-nodes-fallback")).toHaveTextContent(
      "前往「节点流量」更换稳定节点 →"
    );

    // 跨洲错配但 0 漂移（Stable）：绝不误显示「确认当前 IP 已稳定（重置漂移基准）」
    act(() => {
      useGuardStore.setState({
        preflight: {
          ...useGuardStore.getState().preflight,
          items: useGuardStore.getState().preflight.items.map((item) =>
            item.id === "opt_exit_geo"
              ? {
                  ...item,
                  status: "warn",
                  summary: "账号绑定属地 US 与当前出口 AU 跨洲错配",
                  evidence: "24h Landing IP Drift: Stable (count=0)\nBound Account Geo vs Exit: US vs AU",
                  fixLabel: "前往「节点流量」核对并切换稳定节点",
                }
              : item
          ),
        },
      });
    });
    rerender(<ConsolePage />);
    expect(screen.queryByTestId("btn-reset-drift-baseline")).not.toBeInTheDocument();
    expect(screen.getByText("前往「节点流量」核对并切换稳定节点")).toBeInTheDocument();

    act(() => {
      useGuardStore.setState({
        selectedCheckId: "node_geo",
        preflight: {
          ...useGuardStore.getState().preflight,
          items: useGuardStore.getState().preflight.items.map((item) =>
            item.id === "node_geo"
              ? {
                  ...item,
                  status: "fail",
                  summary: "当前出口被 Cloudflare 403 拉黑",
                  fixLabel: "节点不可用，前往「节点流量」手动更换节点 →",
                }
              : item
          ),
        },
      });
    });
    rerender(<ConsolePage />);
    expect(screen.queryByTestId("btn-reset-drift-baseline")).not.toBeInTheDocument();
    expect(screen.getByText("节点不可用，前往「节点流量」手动更换节点 →")).toBeInTheDocument();
  });
});
