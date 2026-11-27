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

describe("FD Claude Guard M3/M4 紧急防回传、备份还原与脱敏诊断包", () => {
  it("环境维护页可强杀进程、备份清理、一键还原并导出脱敏 AI 诊断包", async () => {
    const killSpy = vi.spyOn(ipc, "killClaudeProcesses").mockResolvedValue({
      beforeCount: 2,
      afterCount: 0,
      telemetryClearedBytes: 512,
      message: "已强杀 2 个 Claude 进程并清扫 512 B 遥测缓存。",
    });
    const backupSpy = vi.spyOn(ipc, "backupAndCleanClaude").mockResolvedValue({
      fileName: "claude-backup-clean-20261123-220000-001.zip",
      fullPath: "C:\\Users\\<USER>\\FDtools-Backups\\claude-backup-clean-20261123-220000-001.zip",
      kind: "clean",
      createdAt: "2026-11-23 22:00",
      sizeBytes: 2048,
      sizeLabel: "2.0 KB",
    });
    vi.spyOn(ipc, "listBackups").mockResolvedValue([
      {
        fileName: "claude-backup-clean-20261123-220000-001.zip",
        fullPath: "C:\\Users\\<USER>\\FDtools-Backups\\claude-backup-clean-20261123-220000-001.zip",
        kind: "clean",
        createdAt: "2026-11-23 22:00",
        sizeBytes: 2048,
        sizeLabel: "2.0 KB",
      },
    ]);
    const restoreSpy = vi.spyOn(ipc, "restoreBackup").mockResolvedValue("已成功还原 3 个文件。");
    const deleteSpy = vi
      .spyOn(ipc, "deleteBackup")
      .mockResolvedValue("已删除备份快照 claude-backup-clean-20261123-220000-001.zip");
    const fwRescueSpy = vi
      .spyOn(ipc, "cleanupAllGuardFirewallRules")
      .mockResolvedValue("已清空全部 FDClaudeGuard_KillSwitch_* 规则");
    const diagSpy = vi.spyOn(ipc, "exportAiDiagnosticBundle").mockResolvedValue({
      zipPath: "C:\\Users\\<USER>\\Desktop\\FDClaudeGuard-diag.zip",
      promptMarkdown: "# FD Claude Guard 脱敏排障上下文",
      manifestMagic: 0x12708f87,
    });

    render(<App />);
    fireEvent.click(screen.getByTestId("sidebar-settings-trigger"));
    fireEvent.click(await screen.findByTestId("settings-tab-recovery"));

    fireEvent.click(await screen.findByRole("button", { name: "应急清理" }));
    await waitFor(() => expect(killSpy).toHaveBeenCalledWith(true));

    fireEvent.click(screen.getByRole("button", { name: "仅清防火墙" }));
    await waitFor(() => expect(fwRescueSpy).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("button", { name: "退出并清理" }));
    expect(await screen.findByTestId("clean-confirm-modal")).toBeInTheDocument();
    fireEvent.click(await screen.findByTestId("btn-clean-modal-confirm"));
    await waitFor(() => expect(backupSpy).toHaveBeenCalledTimes(1));

    fireEvent.click(await screen.findByRole("button", { name: "一键还原" }));
    await waitFor(() => expect(restoreSpy).toHaveBeenCalledWith("claude-backup-clean-20261123-220000-001.zip"));

    fireEvent.click(screen.getByRole("button", { name: /删除备份 claude-backup-clean/ }));
    await waitFor(() => expect(deleteSpy).toHaveBeenCalledWith("claude-backup-clean-20261123-220000-001.zip"));

    fireEvent.click(screen.getByTestId("settings-tab-general"));
    fireEvent.click(await screen.findByTestId("btn-settings-export-diag"));
    await waitFor(() => expect(diagSpy).toHaveBeenCalledTimes(1));
  });
});
