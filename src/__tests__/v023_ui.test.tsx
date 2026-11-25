import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HudCard } from "@/components/HudCard";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { LogAnalysisPage } from "@/pages/LogAnalysisPage";
import { MaintenancePage } from "@/pages/MaintenancePage";
import { useGuardStore } from "@/stores/guardStore";
import type { LogAnalysisReport } from "@/types/guard";

/**
 * v0.2.3 UI 回归测试：
 * 1. T-025 悬浮窗中列精准跳转分流（节点漂移 / 节点异常 / 实时流量拦截 / 纯净正常）
 * 2. 日志分析页（时区跳变提示 / 噪音分类折叠面板 / 统计卡筛选验证受限与退出回传 403）
 * 3. 环境维护页（经典目录与微软商店 MSIX 双目录识别摘要）
 */
describe("v0.2.3 UI 核心回归门禁", () => {
  beforeEach(() => {
    useGuardStore.setState({
      activeTab: "console",
      nodesSubTab: "quality",
      selectedCheckId: "node_proxy",
      ackedLogIds: [],
      toasts: [],
      riskModal: null,
      playbookOpen: false,
      playbookFocusId: null,
      supportModalOpen: false,
      preflight: FALLBACK_PREFLIGHT,
      snapshot: { ...FALLBACK_SNAPSHOT },
      config: { ...DEFAULT_CONFIG },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    cleanup();
  });

  describe("T-025 悬浮窗中列精准跳转分流", () => {
    it("节点漂移预警时中列显示「节点漂移」，点击跳转到 nodes / quality", () => {
      const onGoConsole = vi.fn();
      render(
        <HudCard
          initialConfig={{ ...DEFAULT_CONFIG }}
          initialSnapshot={{
            ...FALLBACK_SNAPSHOT,
            killSwitchActive: false,
            nodeDown: false,
            nodeDriftWarn: true,
            activeFlowAnomalies: 1,
            liveFlowAnomalies: 0,
          }}
          onGoConsole={onGoConsole}
        />
      );

      const flowTile = screen.getByTestId("hud-tile-flow");
      expect(flowTile).toHaveTextContent("节点漂移");

      fireEvent.click(flowTile);
      expect(onGoConsole).toHaveBeenCalledTimes(1);
      expect(onGoConsole).toHaveBeenCalledWith(false, "nodes", "quality");
    });

    it("节点不可用时中列显示「节点异常」，点击跳转到 nodes / quality", () => {
      const onGoConsole = vi.fn();
      render(
        <HudCard
          initialConfig={{ ...DEFAULT_CONFIG }}
          initialSnapshot={{
            ...FALLBACK_SNAPSHOT,
            killSwitchActive: false,
            nodeDown: true,
            nodeDriftWarn: false,
            activeFlowAnomalies: 1,
            liveFlowAnomalies: 0,
          }}
          onGoConsole={onGoConsole}
        />
      );

      const flowTile = screen.getByTestId("hud-tile-flow");
      expect(flowTile).toHaveTextContent("节点异常");

      fireEvent.click(flowTile);
      expect(onGoConsole).toHaveBeenCalledTimes(1);
      expect(onGoConsole).toHaveBeenCalledWith(false, "nodes", "quality");
    });

    it("实时流量连接拦截时中列显示「2 拦截」，点击跳转到 nodes / traffic", () => {
      const onGoConsole = vi.fn();
      render(
        <HudCard
          initialConfig={{ ...DEFAULT_CONFIG }}
          initialSnapshot={{
            ...FALLBACK_SNAPSHOT,
            killSwitchActive: false,
            nodeDown: false,
            nodeDriftWarn: false,
            activeFlowAnomalies: 2,
            liveFlowAnomalies: 2,
          }}
          onGoConsole={onGoConsole}
        />
      );

      const flowTile = screen.getByTestId("hud-tile-flow");
      expect(flowTile).toHaveTextContent("2 拦截");

      fireEvent.click(flowTile);
      expect(onGoConsole).toHaveBeenCalledTimes(1);
      expect(onGoConsole).toHaveBeenCalledWith(false, "nodes", "traffic");
    });

    it("纯净正常态（全为 0）时中列显示「纯净」，点击跳转到 nodes / traffic", () => {
      const onGoConsole = vi.fn();
      render(
        <HudCard
          initialConfig={{ ...DEFAULT_CONFIG }}
          initialSnapshot={{
            ...FALLBACK_SNAPSHOT,
            killSwitchActive: false,
            nodeDown: false,
            nodeDriftWarn: false,
            activeFlowAnomalies: 0,
            liveFlowAnomalies: 0,
          }}
          onGoConsole={onGoConsole}
        />
      );

      const flowTile = screen.getByTestId("hud-tile-flow");
      expect(flowTile).toHaveTextContent("纯净");

      fireEvent.click(flowTile);
      expect(onGoConsole).toHaveBeenCalledTimes(1);
      expect(onGoConsole).toHaveBeenCalledWith(false, "nodes", "traffic");
    });
  });

  describe("日志分析页：时区跳变、噪音分类面板与统计卡筛选", () => {
    const mockReport: LogAnalysisReport = {
      events: [
        {
          id: "log-main-10",
          ruleId: "pb_pay",
          anomaly: true,
          simulated: false,
          level: "fail",
          tag: "验证受限",
          time: "2026-11-24 10:15:00",
          file: "main.log:10",
          line: 10,
          title: "触发官方验证门户限制（portal.anthropic.com/verify · 高危待核验）",
          cause: "触发归因：属于高危风控升级（待核验），并非确认永久封号。",
          context: "2026-11-24 10:15:00 [warn] Redirected to https://portal.anthropic.com/verify",
        },
        {
          id: "log-main-28",
          ruleId: "pb_exit",
          anomaly: true,
          simulated: false,
          level: "fail",
          tag: "退出回传 403",
          time: "2026-11-24 10:16:08",
          file: "main.log:28",
          line: 28,
          title: "断连瞬间退出清理触发带 Cookie 403 回传（高危）",
          cause: "触发归因：代理断连后 15 秒内执行退出清理将 Cookie 打到 Anthropic 触发 403。",
          context: "2026-11-24 10:16:08 [error] onQuitCleanup credential: cookie returned 403 (withheld 182 chars)",
        },
        {
          id: "log-main-35",
          ruleId: "pb_node",
          anomaly: true,
          simulated: false,
          level: "warn",
          tag: "网络断连",
          time: "2026-11-24 10:16:02",
          file: "main.log:35",
          line: 35,
          title: "代理链路异常断连或 WebSocket 中断（ERR_CONNECTION_RESET / 1006）",
          cause: "触发归因：节点高抖动或本地代理端口波动。",
          context: "2026-11-24 10:16:02 [warn] ERR_CONNECTION_RESET socket closed: 1006",
        },
      ],
      stats: {
        totalAnomalies: 3,
        regionOrRateCount: 2,
        disconnectCount: 1,
        telemetryOrDeviceCount: 0,
        watchingFiles: ["C:\\Users\\test\\AppData\\Roaming\\Claude\\logs\\main.log"],
        ignoredNoiseCount: 5,
        ignoredNoiseBreakdown: [
          { label: "系统合盖休眠挂起 (ERR_NETWORK_IO_SUSPENDED)", count: 3 },
          { label: "第三方引导页 503 (custom3p-setup)", count: 2 },
        ],
        timezoneJumpWarning:
          "检测到历史系统时区剧烈跳变：UTC-7 ↔ UTC+8（跨 15 小时），建议保持固定系统时区并选用近时区节点",
      },
    };

    it("展示时区跳变提示、支持点击展开噪音分类明细，并可通过第 2 张统计卡同时筛出「验证受限」与「退出回传 403」", async () => {
      const logSpy = vi.spyOn(ipc, "getLogAnalysis").mockResolvedValue(mockReport);

      render(<LogAnalysisPage />);

      await waitFor(() => expect(logSpy).toHaveBeenCalledTimes(1));

      // 1. 断言渲染时区跳变提示
      const tzWarn = await screen.findByTestId("log-tz-jump-warn");
      expect(tzWarn).toBeInTheDocument();
      expect(tzWarn).toHaveTextContent("UTC-7 ↔ UTC+8");
      expect(tzWarn).toHaveTextContent("15 小时");

      // 2. 默认不渲染噪音详情面板，点击切换按钮后展开并展示噪音分类明细
      expect(screen.queryByTestId("noise-inspector-panel")).not.toBeInTheDocument();
      const toggleNoiseBtn = screen.getByTestId("btn-toggle-noise-panel");
      fireEvent.click(toggleNoiseBtn);

      const noisePanel = await screen.findByTestId("noise-inspector-panel");
      expect(noisePanel).toBeInTheDocument();
      expect(noisePanel).toHaveTextContent("系统合盖休眠挂起 (ERR_NETWORK_IO_SUSPENDED)");
      expect(noisePanel).toHaveTextContent("3");
      expect(noisePanel).toHaveTextContent("第三方引导页 503 (custom3p-setup)");
      expect(noisePanel).toHaveTextContent("2");

      // 3. 点击第 2 张统计卡，断言「验证受限」与「退出回传 403」均被正确筛出，且无关断连条目被过滤
      fireEvent.click(screen.getByTestId("log-stat-region-rate"));
      await waitFor(() => {
        expect(screen.getByText("验证受限")).toBeInTheDocument();
        expect(screen.getByText("退出回传 403")).toBeInTheDocument();
        expect(
          screen.getByText("触发官方验证门户限制（portal.anthropic.com/verify · 高危待核验）")
        ).toBeInTheDocument();
        expect(
          screen.getByText("断连瞬间退出清理触发带 Cookie 403 回传（高危）")
        ).toBeInTheDocument();
        expect(screen.queryByText("网络断连")).not.toBeInTheDocument();
      });
    });
  });

  describe("环境维护页：Claude 双数据根目录识别摘要", () => {
    it("正确展示经典目录与微软商店 MSIX 实例识别结果", async () => {
      vi.spyOn(ipc, "listBackups").mockResolvedValue([]);
      const rootsSpy = vi.spyOn(ipc, "inspectClaudeDataRoots").mockResolvedValue({
        classicDetected: true,
        msixPackages: ["Claude_abc123"],
        telemetryExists: true,
      });

      render(<MaintenancePage />);

      await waitFor(() => expect(rootsSpy).toHaveBeenCalledTimes(1));

      const rootsSummary = await screen.findByTestId("maintenance-roots-summary");
      expect(rootsSummary).toBeInTheDocument();
      expect(rootsSummary).toHaveTextContent("经典目录（已识别）");
      expect(rootsSummary).toHaveTextContent("微软商店 MSIX（已识别 1 个实例）");
    });
  });
});
