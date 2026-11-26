import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CleanConfirmModal } from "@/components/CleanConfirmModal";
import { RiskModal } from "@/components/RiskModal";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { ConsolePage } from "@/pages/ConsolePage";
import { LogAnalysisPage } from "@/pages/LogAnalysisPage";
import { useGuardStore } from "@/stores/guardStore";
import type { BackupInfo, LogAnalysisReport, PreflightReport } from "@/types/guard";

/**
 * 构造指定必须项通过数量的预检报告，与 snapshot.mustPassed / mustTotal 保持严格同步
 */
function buildPreflightWithMustPassed(passedCount: number): PreflightReport {
  let mustIndex = 0;
  return {
    ...FALLBACK_PREFLIGHT,
    items: FALLBACK_PREFLIGHT.items.map((item) => {
      if (item.part !== "must") {
        return { ...item };
      }
      const nextStatus = mustIndex < passedCount ? "ok" : "fail";
      mustIndex += 1;
      return { ...item, status: nextStatus };
    }),
  };
}

/**
 * v0.2.4 UI 回归测试：
 * 1. T-026 控制台顶栏去重「官方服务异常」与本机守护状态胶囊（守护正常 / N 项待办 / 节点不可用 / 已自动熔断）
 * 2. T-026 日志分析页 Claude 官方状态中文化展示
 * 3. T-029 日志分析页「退出登录并清理（备份）本地污染目录」确认弹窗与真执行闭环
 */
describe("v0.2.4 UI 核心回归门禁", () => {
  beforeEach(() => {
    useGuardStore.setState({
      activeTab: "console",
      nodesSubTab: "quality",
      selectedCheckId: "node_proxy",
      ackedLogIds: [],
      toasts: [],
      riskModal: null,
      cleanModal: null,
      playbookOpen: false,
      playbookFocusId: null,
      supportModalOpen: false,
      preflight: buildPreflightWithMustPassed(12),
      snapshot: {
        ...FALLBACK_SNAPSHOT,
        mustPassed: 12,
        mustTotal: 12,
        nodeDown: false,
        killSwitchActive: false,
      },
      config: { ...DEFAULT_CONFIG },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    cleanup();
  });

  describe("T-026 控制台顶栏状态胶囊与去重", () => {
    it("官方服务降级且本机 12/12 全绿时，不渲染「官方服务异常」，状态胶囊显示「守护正常」", () => {
      useGuardStore.setState({
        preflight: buildPreflightWithMustPassed(12),
        snapshot: {
          ...FALLBACK_SNAPSHOT,
          anthropicStatusIndicator: "minor",
          anthropicStatusDesc: "Partially Degraded Service",
          mustPassed: 12,
          mustTotal: 12,
          nodeDown: false,
          killSwitchActive: false,
        },
      });

      render(<ConsolePage />);

      expect(screen.queryByText(/官方服务异常/)).not.toBeInTheDocument();
      const statusPill = screen.getByTestId("console-guard-status-pill");
      expect(statusPill).toBeInTheDocument();
      expect(statusPill).toHaveTextContent("守护正常");
    });

    it("存在 2 项必须项未通过（10/12）时，状态胶囊显示「2 项待办」", () => {
      useGuardStore.setState({
        preflight: buildPreflightWithMustPassed(10),
        snapshot: {
          ...FALLBACK_SNAPSHOT,
          mustPassed: 10,
          mustTotal: 12,
          nodeDown: false,
          killSwitchActive: false,
        },
      });

      render(<ConsolePage />);

      const statusPill = screen.getByTestId("console-guard-status-pill");
      expect(statusPill).toHaveTextContent("2 项待办");
    });

    it("节点不可用（nodeDown = true）时，状态胶囊显示「节点不可用」", () => {
      useGuardStore.setState({
        preflight: buildPreflightWithMustPassed(12),
        snapshot: {
          ...FALLBACK_SNAPSHOT,
          mustPassed: 12,
          mustTotal: 12,
          nodeDown: true,
          killSwitchActive: false,
        },
      });

      render(<ConsolePage />);

      const statusPill = screen.getByTestId("console-guard-status-pill");
      expect(statusPill).toHaveTextContent("节点不可用");
    });

    it("自动熔断激活（killSwitchActive = true）时，状态胶囊显示「已自动熔断」", () => {
      useGuardStore.setState({
        preflight: buildPreflightWithMustPassed(12),
        snapshot: {
          ...FALLBACK_SNAPSHOT,
          mustPassed: 12,
          mustTotal: 12,
          nodeDown: false,
          killSwitchActive: true,
        },
      });

      render(<ConsolePage />);

      const statusPill = screen.getByTestId("console-guard-status-pill");
      expect(statusPill).toHaveTextContent("已自动熔断");
    });
  });

  describe("T-026 日志分析页官方状态中文化", () => {
    it("anthropicStatusIndicator 为 minor 且英文为 Partially Degraded Service 时显示「Claude 官方：部分服务降级」", async () => {
      useGuardStore.setState({
        snapshot: {
          ...FALLBACK_SNAPSHOT,
          anthropicStatusIndicator: "minor",
          anthropicStatusDesc: "Partially Degraded Service",
        },
      });

      const emptyReport: LogAnalysisReport = {
        events: [],
        stats: {
          totalAnomalies: 0,
          regionOrRateCount: 0,
          disconnectCount: 0,
          telemetryOrDeviceCount: 0,
          watchingFiles: [],
        },
      };
      const logSpy = vi.spyOn(ipc, "getLogAnalysis").mockResolvedValue(emptyReport);

      render(<LogAnalysisPage />);

      await waitFor(() => expect(logSpy).toHaveBeenCalledTimes(1));

      const officialStatus = screen.getByTestId("log-claude-official-status");
      expect(officialStatus).toBeInTheDocument();
      expect(officialStatus).toHaveTextContent("Claude 官方：部分服务降级");
    });
  });

  describe("T-029 日志分析页「退出登录并清理（备份）本地污染目录」真执行闭环", () => {
    it("展开身份验证/权限异常并点击备份清理按钮后弹出确认窗，确认后真实调用 ipc.backupAndCleanClaude 1 次", async () => {
      const mockReport: LogAnalysisReport = {
        events: [
          {
            id: "log-auth-403-1",
            ruleId: "pb_pay",
            anomaly: true,
            simulated: false,
            level: "fail",
            tag: "身份验证/权限",
            time: "2026-11-24 11:20:00",
            file: "main.log:42",
            line: 42,
            title: "检测到 OAuth 403 身份验证或权限拒绝异常",
            cause: "触发归因：本地登录态疑似受限或触发组织权限风控，需备份并清理本地污染目录。",
            context: "2026-11-24 11:20:00 [error] HTTP 403 permission_error: oauth credential rejected",
          },
        ],
        stats: {
          totalAnomalies: 1,
          regionOrRateCount: 1,
          disconnectCount: 0,
          telemetryOrDeviceCount: 0,
          watchingFiles: ["C:\\Users\\test\\AppData\\Roaming\\Claude\\logs\\main.log"],
        },
      };

      const mockBackupInfo: BackupInfo = {
        fileName: "claude-backup-clean-20261124-112500-000.zip",
        fullPath: "C:\\Users\\test\\FDtools-Backups\\claude-backup-clean-20261124-112500-000.zip",
        kind: "clean",
        createdAt: "2026-11-24 11:25:00",
        sizeBytes: 4096,
        sizeLabel: "4.0 KB",
      };

      const logSpy = vi.spyOn(ipc, "getLogAnalysis").mockResolvedValue(mockReport);
      const backupCleanSpy = vi
        .spyOn(ipc, "backupAndCleanClaude")
        .mockResolvedValue(mockBackupInfo);

      render(
        <>
          <LogAnalysisPage />
          <CleanConfirmModal />
        </>
      );

      await waitFor(() => expect(logSpy).toHaveBeenCalledTimes(1));

      // 1. 点击展开「身份验证/权限」异常条目
      const entryTitle = await screen.findByText("检测到 OAuth 403 身份验证或权限拒绝异常");
      fireEvent.click(entryTitle);

      // 2. 点击展开区域中的「退出登录并清理（备份）本地污染目录」按钮
      const backupCleanBtn = await screen.findByTestId("btn-log-backup-clean");
      expect(backupCleanBtn).toBeInTheDocument();
      fireEvent.click(backupCleanBtn);

      // 3. 断言打开透明分项确认弹窗（CleanConfirmModal），默认保护 MCP 配置不勾选
      const cleanModal = await screen.findByTestId("clean-confirm-modal");
      expect(cleanModal).toBeInTheDocument();
      const mcpCheck = (await screen.findByTestId("clean-check-mcp_sessions")) as HTMLInputElement;
      expect(mcpCheck.checked).toBe(false);
      expect(await screen.findByTestId("clean-protected-row")).toBeInTheDocument();

      // 4. 点击弹窗中的真实执行确认按钮
      fireEvent.click(await screen.findByTestId("btn-clean-modal-confirm"));

      // 5. 断言 ipc.backupAndCleanClaude 被真实调用 1 次且包含默认 5 项（桌面端+CLI全清，不含 mcp_sessions）
      await waitFor(() => expect(backupCleanSpy).toHaveBeenCalledTimes(1));
      expect(backupCleanSpy).toHaveBeenCalledWith([
        "auth",
        "cli_auth_and_backups",
        "logs",
        "telemetry",
        "cache",
      ]);
    });
  });

  describe("T-032 / T-045 控制台单号卫生锁多账号弹窗解析与透明分项清理闭环", () => {
    it("正确解析 Observed Unique orgIds (2) 并切入分项透明清理弹窗", async () => {
      const items = buildPreflightWithMustPassed(11).items.map((it) =>
        it.id === "claude_acct"
          ? {
              ...it,
              status: "fail" as const,
              summary: "最高危连坐预警：本机混登 2 个账号且包含已受限/待验证号（bce33885）",
              evidence:
                "Scanned Claude Log Files: 2\nObserved Unique orgIds (2): bce33885, ce65bc28\nCross-orgId Race Hits: 0",
              fixLabel: "引导处理单号冲突（二选一确认）",
            }
          : it
      );
      const mockBackupInfo: BackupInfo = {
        fileName: "claude-backup-clean-20261124-152200-000.zip",
        fullPath: "C:\\Users\\test\\FDtools-Backups\\claude-backup-clean-20261124-152200-000.zip",
        kind: "clean",
        createdAt: "2026-11-24 15:22:00",
        sizeBytes: 4096,
        sizeLabel: "4.0 KB",
      };
      const backupCleanSpy = vi
        .spyOn(ipc, "backupAndCleanClaude")
        .mockResolvedValue(mockBackupInfo);

      useGuardStore.setState({
        preflight: { checkedAt: "2026-11-24 15:22:00", stage: "v1.6", items },
        snapshot: {
          ...useGuardStore.getState().snapshot,
          mustPassed: 10,
          mustTotal: 11,
        },
      });

      render(
        <>
          <ConsolePage />
          <RiskModal />
          <CleanConfirmModal />
        </>
      );

      fireEvent.click(screen.getByText("单号卫生锁（防混号与跨 orgId）"));
      fireEvent.click(screen.getByRole("button", { name: "引导处理单号冲突（二选一确认）" }));

      const modal = await screen.findByTestId("risk-modal");
      expect(modal).toHaveTextContent("多账号混登 / 跨 orgId 冲突处理确认");
      expect(modal).toHaveTextContent("ce65bc28...");

      fireEvent.click(
        screen.getByRole("button", { name: "分项清理并备份" })
      );
      expect(await screen.findByTestId("clean-confirm-modal")).toBeInTheDocument();
      fireEvent.click(await screen.findByTestId("btn-clean-modal-confirm"));
      await waitFor(() => expect(backupCleanSpy).toHaveBeenCalledTimes(1));
    });

    it("T-046 本地封号污染残留审查（claude_ban）直接呼出透明分项清理弹窗，不静默盲删", async () => {
      const items = buildPreflightWithMustPassed(11).items.map((it) =>
        it.id === "claude_ban"
          ? {
              ...it,
              status: "fail" as const,
              summary: "检测到本地存在确认封号或地区封锁残留记录",
              fixLabel: "预览并分项清理（备份）本地目录",
            }
          : it
      );
      const backupCleanSpy = vi.spyOn(ipc, "backupAndCleanClaude").mockResolvedValue({
        fileName: "claude-backup-clean-20261125-052200-000.zip",
        fullPath: "C:\\Users\\test\\FDtools-Backups\\claude-backup-clean-20261125-052200-000.zip",
        kind: "clean",
        createdAt: "2026-11-25 05:22:00",
        sizeBytes: 4096,
        sizeLabel: "4.0 KB",
      });

      useGuardStore.setState({
        preflight: { checkedAt: "2026-11-25 05:22:00", stage: "v1.6", items },
        snapshot: { ...useGuardStore.getState().snapshot, mustPassed: 10, mustTotal: 11 },
      });

      render(
        <>
          <ConsolePage />
          <CleanConfirmModal />
        </>
      );

      fireEvent.click(screen.getByText("本地封号污染残留审查"));
      fireEvent.click(screen.getByRole("button", { name: "预览并分项清理（备份）本地目录" }));

      expect(await screen.findByTestId("clean-confirm-modal")).toBeInTheDocument();
      // 未点确认前绝不自动删除
      expect(backupCleanSpy).not.toHaveBeenCalled();
      fireEvent.click(await screen.findByTestId("btn-clean-modal-confirm"));
      await waitFor(() => expect(backupCleanSpy).toHaveBeenCalledTimes(1));
    });
  });
});
