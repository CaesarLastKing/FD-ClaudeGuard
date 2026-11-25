import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { HudCard } from "@/components/HudCard";
import { Sidebar } from "@/components/Sidebar";
import { DEFAULT_CONFIG, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { LogAnalysisPage } from "@/pages/LogAnalysisPage";
import { MaintenancePage } from "@/pages/MaintenancePage";
import { SettingsPage } from "@/pages/SettingsPage";
import { useGuardStore } from "@/stores/guardStore";
import type { GuardSnapshot } from "@/types/guard";

function makeSnapshot(patch: Partial<GuardSnapshot>): GuardSnapshot {
  return {
    ...FALLBACK_SNAPSHOT,
    healthLevel: "ok",
    statusLabel: "守护正常",
    currentNode: "AU澳大利亚|原生",
    regionCode: "AU",
    exitIpMasked: "172.105.xx.xx",
    latencyMs: 218,
    latencyLabel: "218 ms",
    mustPassed: 11,
    mustTotal: 11,
    clashOnline: true,
    clashPort: 7897,
    unreadLogAnomalies: 0,
    unreadLogCritical: 0,
    unreadLogWarnings: 0,
    ...patch,
  };
}

describe("v0.2.7 日志风险/异常分开统计、OAuth v2 拆分折叠与匿名诊断上报回归", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useGuardStore.setState({
      config: { ...DEFAULT_CONFIG },
      snapshot: makeSnapshot({}),
      ackedLogIds: [],
    });
  });

  it("悬浮窗按「风险 X / 异常 Y」分开统计：仅风险黄卡、混合红卡、全部已读绿卡归零", () => {
    const first = render(
      <HudCard
        initialConfig={{ ...DEFAULT_CONFIG }}
        initialSnapshot={makeSnapshot({
          unreadLogAnomalies: 1,
          unreadLogCritical: 0,
          unreadLogWarnings: 1,
        })}
      />
    );
    const logTile = screen.getByTestId("hud-tile-log");
    expect(logTile).toHaveClass("is-warn");
    expect(logTile).toHaveTextContent("风险 1");
    expect(screen.getByText(/前往日志分析查看（风险 1）/)).toBeInTheDocument();
    first.unmount();

    const second = render(
      <HudCard
        initialConfig={{ ...DEFAULT_CONFIG }}
        initialSnapshot={makeSnapshot({
          unreadLogAnomalies: 3,
          unreadLogCritical: 2,
          unreadLogWarnings: 1,
        })}
      />
    );
    expect(screen.getByTestId("hud-tile-log")).toHaveClass("is-fail");
    expect(screen.getByTestId("hud-tile-log")).toHaveTextContent("风险 1 · 异常 2");
    expect(screen.getByText(/前往日志分析查看（风险 1 · 异常 2）/)).toBeInTheDocument();
    second.unmount();

    render(
      <HudCard
        initialConfig={{ ...DEFAULT_CONFIG }}
        initialSnapshot={makeSnapshot({
          unreadLogAnomalies: 0,
          unreadLogCritical: 0,
          unreadLogWarnings: 0,
        })}
      />
    );
    expect(screen.getByTestId("hud-tile-log")).toHaveClass("is-ok");
    expect(screen.getByTestId("hud-tile-log")).toHaveTextContent("正常");
    expect(screen.getByText(/前往控制台安全启动 Claude/)).toBeInTheDocument();
  });

  it("侧边栏日志角标仅风险呈黄、有异常呈红、全部已读隐藏", () => {
    useGuardStore.setState({
      snapshot: makeSnapshot({
        unreadLogAnomalies: 1,
        unreadLogCritical: 0,
        unreadLogWarnings: 1,
      }),
    });
    const { rerender } = render(<Sidebar />);
    const badgeWarn = screen.getByTestId("nav-badge-logs");
    expect(badgeWarn).toHaveTextContent("1");
    expect(badgeWarn.getAttribute("title")).toBe("风险 1 · 异常 0");

    useGuardStore.setState({
      snapshot: makeSnapshot({
        unreadLogAnomalies: 0,
        unreadLogCritical: 0,
        unreadLogWarnings: 0,
      }),
    });
    rerender(<Sidebar />);
    expect(screen.queryByTestId("nav-badge-logs")).not.toBeInTheDocument();
  });

  it("日志分析页 OAuth v2 鉴权折叠 ×5 不显示污染清理红按钮，全部标为已读同步调用 ackLogEvents 并归零", async () => {
    vi.spyOn(ipc, "getLogAnalysis").mockResolvedValue({
      events: [
        {
          id: "log-main.log-72",
          ruleId: "pb_pay",
          anomaly: true,
          simulated: false,
          acked: false,
          level: "warn",
          tag: "OAuth v2 鉴权",
          time: "2026-11-25 04:47:45",
          file: "main.log:72 ~ 336 (共 5 次)",
          line: 72,
          repeatCount: 5,
          collapsedIds: ["log-main.log-72", "log-main.log-73"],
          title: "OAuth v2 令牌交换失败（auth_error，风险提醒 · 非 403）",
          cause: "风险原因：非 HTTP 403",
          context: "2026-11-25 04:47:42 [info] [oauth-v2] fresh exchange failed (auth_error)",
        },
        {
          id: "log-main.log-418",
          ruleId: "pb_exit",
          anomaly: true,
          simulated: false,
          acked: false,
          level: "fail",
          tag: "退出回传 403",
          time: "2026-11-25 04:51:12",
          file: "main.log:418",
          line: 418,
          repeatCount: 1,
          title: "断连瞬间退出清理触发带 Cookie 403 回传（高危）",
          cause: "触发归因：代理断连后退出回传",
          context: "returned 403 (credential: cookie, withheld, 182 chars)",
          attributionClue: "72h 前置线索：断连退出/带 Cookie 403 共 1 次",
        },
      ],
      stats: {
        totalAnomalies: 2,
        criticalCount: 1,
        warningCount: 1,
        regionOrRateCount: 2,
        disconnectCount: 0,
        telemetryOrDeviceCount: 0,
        watchingFiles: ["main.log"],
      },
    });
    const ackSpy = vi.spyOn(ipc, "ackLogEvents").mockResolvedValue(
      makeSnapshot({ unreadLogAnomalies: 0, unreadLogCritical: 0, unreadLogWarnings: 0 })
    );

    render(<LogAnalysisPage />);

    const v2Title = await screen.findByText(/OAuth v2 令牌交换失败/);
    expect(screen.getByText("×5")).toBeInTheDocument();
    expect(screen.getByTestId("log-stat-unread")).toHaveTextContent("风险 1");
    expect(screen.getByTestId("log-stat-unread")).toHaveTextContent("异常 1");

    // 展开 OAuth v2 鉴权：绝不出现红色清理污染目录按钮
    fireEvent.click(v2Title);
    expect(screen.queryByTestId("btn-log-backup-clean")).not.toBeInTheDocument();

    // 展开高危退出回传 403：保留红按钮并显示 1 行 72h 前置线索
    fireEvent.click(screen.getByText(/断连瞬间退出清理触发带 Cookie 403/));
    expect(screen.getByTestId("btn-log-backup-clean")).toBeInTheDocument();
    expect(screen.getByTestId("log-attribution-clue")).toHaveTextContent("72h 前置线索");

    // 全部标为已读 -> 调用后端持久化 ackLogEvents 归零悬浮窗
    fireEvent.click(screen.getByRole("button", { name: "全部标为已读" }));
    await waitFor(() => {
      expect(ackSpy).toHaveBeenCalledTimes(1);
    });
    expect(useGuardStore.getState().snapshot.unreadLogAnomalies).toBe(0);
    expect(useGuardStore.getState().snapshot.unreadLogWarnings).toBe(0);
    expect(useGuardStore.getState().snapshot.unreadLogCritical).toBe(0);
  });

  it("环境维护页一键匿名上报排障弹窗生成单号，守卫配置页可预览脱敏数据结构", async () => {
    vi.spyOn(ipc, "listBackups").mockResolvedValue([]);
    vi.spyOn(ipc, "inspectClaudeDataRoots").mockResolvedValue({
      classicDetected: true,
      msixPackages: [],
      telemetryExists: false,
    });
    const submitSpy = vi.spyOn(ipc, "submitAnonymousFeedbackReport").mockResolvedValue({
      ticketId: "FD-20261125-7A3F",
      createdAt: "2026-11-25T08:00:00Z",
      uploadedBytes: 512,
      endpointUsed: "https://worker.test/api/v1/feedback/report",
      message: "已匿名上报",
    });

    const { unmount } = render(<MaintenancePage />);
    fireEvent.click(screen.getByTestId("btn-anonymous-report"));
    expect(screen.getByTestId("anonymous-report-modal")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("btn-confirm-anonymous-report"));

    await waitFor(() => {
      expect(submitSpy).toHaveBeenCalledTimes(1);
      expect(screen.getByTestId("anonymous-report-ticket")).toHaveTextContent("FD-20261125-7A3F");
    });
    unmount();

    const previewSpy = vi
      .spyOn(ipc, "previewAnonymousFeedbackPayload")
      .mockResolvedValue('{"schemaVersion": 2, "preBanAttribution72h": {}}');
    render(<SettingsPage />);
    fireEvent.click(screen.getByTestId("btn-preview-telemetry-sample"));
    await waitFor(() => {
      expect(previewSpy).toHaveBeenCalledTimes(1);
      expect(screen.getByTestId("telemetry-sample-modal")).toHaveTextContent("preBanAttribution72h");
    });
  });
});
