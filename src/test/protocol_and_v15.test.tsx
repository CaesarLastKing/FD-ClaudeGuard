import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import App from "@/App";
import { HudCard } from "@/components/HudCard";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT } from "@/lib/ipc";
import {
  APP_BRAND_SUBTITLE,
  BRAND_SHIELD_SVG,
  DIAG_MANIFEST_MAGIC,
  DIAG_MANIFEST_MAGIC_HEX,
  DROP_RATE_REDLINE,
  EVENT_DEDUP_WINDOW_MS,
  FD_ERRORS,
  FULL_AUDIT_INTERVAL_MS,
  LATENCY_WARN_MS,
  LOCAL_HEARTBEAT_MS,
  NODE_SCORE_WEIGHTS,
  REDACT_PLACEHOLDER,
  extractRegionCode,
  isSameRegionSwitch,
} from "@/lib/protocol";
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
  cleanup();
});

describe("docs/protocol-constants.md 100% 协议常量与 v1.5 增量回归断言", () => {
  it("严格锁定全部错误码、魔数、占位符、毫秒时序、权重与品牌盾牌 SVG 路径", () => {
    expect(FD_ERRORS.PROXY_OFFLINE).toBe("FD_ERR_2152");
    expect(FD_ERRORS.RULE_DRIFT).toBe("FD_ERR_3562");
    expect(FD_ERRORS.IPV6_LEAK).toBe("FD_ERR_4649");
    expect(FD_ERRORS.KILL_SWITCH).toBe("FD_ERR_5304");
    expect(FD_ERRORS.LOG_POLLUTE).toBe("FD_ERR_6817");
    expect(FD_ERRORS.BACKUP_TX).toBe("FD_ERR_7459");

    expect(DIAG_MANIFEST_MAGIC).toBe(0x12708f87);
    expect(DIAG_MANIFEST_MAGIC_HEX).toBe("0x12708F87");
    expect(REDACT_PLACEHOLDER).toBe("<REDACTED:2W>");

    expect(EVENT_DEDUP_WINDOW_MS).toBe(60489);
    expect(LOCAL_HEARTBEAT_MS).toBe(29121);
    expect(FULL_AUDIT_INTERVAL_MS).toBe(904543);

    expect(NODE_SCORE_WEIGHTS.LATENCY).toBe(0.37);
    expect(NODE_SCORE_WEIGHTS.JITTER).toBe(0.25);
    expect(NODE_SCORE_WEIGHTS.DROP_RATE).toBe(0.24);
    expect(NODE_SCORE_WEIGHTS.STABILITY).toBe(0.14);
    expect(
      Number(
        (
          NODE_SCORE_WEIGHTS.LATENCY +
          NODE_SCORE_WEIGHTS.JITTER +
          NODE_SCORE_WEIGHTS.DROP_RATE +
          NODE_SCORE_WEIGHTS.STABILITY
        ).toFixed(2)
      )
    ).toBe(1.0);
    expect(LATENCY_WARN_MS).toBe(133);
    expect(DROP_RATE_REDLINE).toBe(7.8);

    expect(BRAND_SHIELD_SVG.viewBox).toBe("0 0 24 24");
    expect(BRAND_SHIELD_SVG.strokeWidth).toBe(1.8);
    expect(BRAND_SHIELD_SVG.outlinePath).toBe(
      "M12 22.05s8-4 8-10.02V5.09l-8-3.09-8 3.09v7.06c0 6 8 10.02 8 10.02z"
    );
    expect(BRAND_SHIELD_SVG.checkPath).toBe("m9 12.05 2 2 4-4");
    expect(APP_BRAND_SUBTITLE).toBe("Fuck Dario！！！");
  });

  it("跨洲与同区判定严格以地区码比对，绝不将 JP -> US 误判为同区热备", () => {
    expect(extractRegionCode("JP-Tokyo-02")).toBe("JP");
    expect(extractRegionCode("US-LA-Static-01")).toBe("US");
    expect(extractRegionCode("🇦🇺澳大利亚|原生")).toBe("AU");

    expect(isSameRegionSwitch("JP-Tokyo-02", "US-LA-Static-01")).toBe(false);
    expect(isSameRegionSwitch("US-LA-Static-01", "US-SJ-Static-02")).toBe(true);
  });

  it("主窗口固定显示 Fuck Dario！！！副标题，顶栏双纯图标开关可双向同步守卫配置", async () => {
    render(<App />);
    await waitFor(() => {
      expect(useGuardStore.getState().initialized).toBe(true);
    });
    expect(screen.getByText("Fuck Dario！！！")).toBeInTheDocument();

    const hudBtn = screen.getByTestId("topbar-toggle-hud");
    const notifyBtn = screen.getByTestId("topbar-toggle-notify");
    expect(hudBtn).toHaveAttribute("aria-pressed", "true");
    expect(notifyBtn).toHaveAttribute("aria-pressed", "true");

    fireEvent.click(hudBtn);
    await waitFor(() => {
      expect(hudBtn).toHaveAttribute("aria-pressed", "false");
    });
    fireEvent.click(notifyBtn);
    await waitFor(() => {
      expect(notifyBtn).toHaveAttribute("aria-pressed", "false");
    });

    fireEvent.click(screen.getByTestId("sidebar-settings-trigger"));
    expect(await screen.findByRole("switch", { name: /显示桌面悬浮状态窗/ })).toHaveAttribute(
      "aria-checked",
      "false"
    );
    expect(screen.getByRole("switch", { name: /桌面预警消息提醒/ })).toHaveAttribute(
      "aria-checked",
      "false"
    );
  });

  it("HUD v2.2 支持靠右贴边自动隐藏与耳标移入展开", async () => {
    render(
      <HudCard
        initialConfig={{ ...DEFAULT_CONFIG, hudPinned: true, hudFolded: false, hudEdgeDocked: false }}
        initialSnapshot={{
          ...FALLBACK_SNAPSHOT,
          currentNode: "US-LA-Static-01",
          regionCode: "US",
          latencyLabel: "42 ms",
          mustPassed: 9,
          mustTotal: 9,
          clashOnline: true,
        }}
      />
    );

    expect(screen.getByTestId("hud-region-badge")).toHaveTextContent("US");
    const edgeBtn = screen.getByTestId("hud-btn-edge");
    fireEvent.click(edgeBtn);
    await waitFor(() => {
      expect(screen.getByTestId("hud-shell").className).toContain("docked");
    });

    fireEvent.mouseEnter(screen.getByTestId("edge-tab"));
    await waitFor(() => {
      expect(screen.getByTestId("hud-shell").className).toContain("docked-open");
    });
  });

  it("v0.3.2 三大纯粹操作边界（12 必须 + 7 建议含出口合规建议项）、运行态 CTA 切换与账户审计日志取证闭环", async () => {
    const allOkItems = FALLBACK_PREFLIGHT.items.map((it) => ({
      ...it,
      status: "ok" as const,
      fixLabel: null,
    }));
    const mustCount = allOkItems.filter((x) => x.part === "must").length;
    const optItems = allOkItems.filter((x) => x.part === "opt");
    expect(mustCount).toBe(12);
    expect(optItems.length).toBe(7);
    const tzIdx = optItems.findIndex((x) => x.id === "opt_tz");
    const exitGeoIdx = optItems.findIndex((x) => x.id === "opt_exit_geo");
    expect(tzIdx).toBeGreaterThanOrEqual(0);
    expect(exitGeoIdx).toBe(tzIdx + 1);

    render(<App />);
    await waitFor(() => {
      expect(useGuardStore.getState().initialized).toBe(true);
    });

    // 全部通过且有 14 个后台进程时：右上角显示「安全退出 Claude」而非「安全启动 Claude」
    act(() => {
      useGuardStore.setState({
        preflight: { ...FALLBACK_PREFLIGHT, items: allOkItems },
        snapshot: {
          ...FALLBACK_SNAPSHOT,
          mustPassed: 12,
          mustTotal: 12,
          bgClaudeProcs: 14,
        },
      });
    });
    expect(await screen.findByTestId("btn-safe-exit-claude")).toHaveTextContent(
      "安全退出 Claude（14 进程运行中）"
    );
    expect(screen.queryByTestId("btn-safe-launch-claude")).not.toBeInTheDocument();

    // 切到账户审计 → 实时异常日志流 → 打开完整取证日志台：模拟事件带「模拟演示」徽章，点击「遥测 / 设备记录」可展开遥测详情面板
    fireEvent.click(screen.getByRole("button", { name: /账户审计/ }));
    fireEvent.click(await screen.findByRole("button", { name: /实时异常日志流/ }));
    fireEvent.click(await screen.findByRole("button", { name: /打开完整取证日志台/ }));
    fireEvent.click(await screen.findByRole("button", { name: /\+ 模拟高并发 429 异常/ }));
    expect((await screen.findAllByText("模拟演示")).length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByTestId("log-stat-telemetry"));
    expect(await screen.findByTestId("telemetry-inspector-panel")).toBeInTheDocument();
  });
});
