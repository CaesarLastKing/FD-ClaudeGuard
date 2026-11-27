import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import {
  OFFICIAL_AUTHOR_X_HANDLE,
  OFFICIAL_AUTHOR_X_URL,
  OFFICIAL_CLASH_VERGE_RELEASES_URL,
  OFFICIAL_CLASH_VERGE_REPO_URL,
  OFFICIAL_GITHUB_REPO_URL,
} from "@/lib/protocol";
import { useGuardStore } from "@/stores/guardStore";

describe("UI v3.1 系统设置弹窗、联系作者 (X)、AI 工具箱与 5 项实机调优回归", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useGuardStore.setState({
      activeTab: "console",
      nodesSubTab: "quality",
      auditSubTab: "audit",
      settingsModalOpen: false,
      settingsModalTab: "general",
      supportModalOpen: false,
      networkRescueAlert: false,
      preflight: FALLBACK_PREFLIGHT,
      snapshot: { ...FALLBACK_SNAPSHOT },
      config: { ...DEFAULT_CONFIG },
      toasts: [],
      riskModal: null,
      cleanModal: null,
      playbookOpen: false,
      initialized: true,
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("支持 Ctrl+, 开关系统设置弹窗，并按 Esc 严格分层关闭最顶层弹窗", async () => {
    render(<App />);
    expect(screen.queryByTestId("settings-modal")).not.toBeInTheDocument();

    // Ctrl+, 打开系统设置弹窗
    fireEvent.keyDown(window, { key: ",", ctrlKey: true });
    expect(await screen.findByTestId("settings-modal")).toBeInTheDocument();

    // 在设置弹窗之上打开联系作者 (X) 弹窗
    fireEvent.click(screen.getByTestId("topbar-btn-support"));
    expect(await screen.findByTestId("support-modal")).toBeInTheDocument();

    // 第一次 Esc 仅关闭上层 SupportModal，不误关底层 SettingsModal
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => {
      expect(screen.queryByTestId("support-modal")).not.toBeInTheDocument();
    });
    expect(screen.getByTestId("settings-modal")).toBeInTheDocument();

    // 第二次 Esc 关闭 SettingsModal
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => {
      expect(screen.queryByTestId("settings-modal")).not.toBeInTheDocument();
    });
  });

  it("系统设置 4 子页完整交互与脱敏诊断日志自动/主动上报闭环", async () => {
    const openUrlSpy = vi.spyOn(ipc, "openExternalUrl").mockResolvedValue(undefined);
    const openLogsSpy = vi.spyOn(ipc, "openGuardLogsDir").mockResolvedValue("C:\\Users\\demo\\logs");
    const uploadSpy = vi.spyOn(ipc, "submitAnonymousFeedbackReport").mockResolvedValue({
      ticketId: "FD-20261127-ABCD1234",
      createdAt: "2026-11-27T14:00:00Z",
      uploadedBytes: 2048,
      endpointUsed: "https://diag.rookiebird.org/api/v1/feedback/report",
      message: "已上报",
    });

    render(<App />);
    fireEvent.click(screen.getByTestId("sidebar-settings-trigger"));
    expect(await screen.findByTestId("settings-modal")).toBeInTheDocument();

    // 1. 常规开关：脱敏诊断日志自动上传开关可用、主动上传可获取排障单号
    const autoUploadRow = screen.getByTestId("row-auto-upload-diag");
    expect(autoUploadRow).toBeInTheDocument();
    const autoUploadSwitch = screen.getByRole("switch", { name: "允许自动上传脱敏诊断日志" });
    expect(autoUploadSwitch).not.toBeDisabled();
    fireEvent.click(autoUploadSwitch);
    await waitFor(() => {
      expect(autoUploadSwitch).toHaveAttribute("aria-checked", "false");
    });

    const manualUploadBtn = screen.getByTestId("btn-settings-manual-upload");
    expect(manualUploadBtn).not.toBeDisabled();
    fireEvent.click(manualUploadBtn);
    await waitFor(() => expect(uploadSpy).toHaveBeenCalledTimes(1));

    // 真实日志目录按钮可用
    fireEvent.click(screen.getByTestId("btn-settings-open-log-dir"));
    await waitFor(() => expect(openLogsSpy).toHaveBeenCalledTimes(1));

    // 2. 安全策略：含 4 步闭环、独立紧急熔断按钮、灰蓝锁定常驻开关与 Kill-Hold 分段
    fireEvent.click(screen.getByTestId("settings-tab-policy"));
    expect(await screen.findByText("核心特色 · 4 层纵深防护与 2 秒热熔断闭环")).toBeInTheDocument();
    expect(screen.getByTestId("btn-settings-killswitch")).toHaveTextContent("手动触发熔断");
    const lockedSwitches = document.querySelectorAll(".s-switch.is-locked");
    expect(lockedSwitches.length).toBe(6);

    // 3. 清理恢复：4 锚点快捷跳转与网络急救按钮（恒定蓝色主 CTA）
    fireEvent.click(screen.getByTestId("settings-tab-recovery"));
    const rescueBtn = await screen.findByTestId("btn-settings-network-rescue");
    expect(rescueBtn).toHaveTextContent("一键网络急救");
    expect(rescueBtn).toHaveClass("guard-btn-primary");

    // 4. 版本更新：自上而下顺序为 联系作者 → Clash Verge 安装与官网 → 客户端版本更新
    fireEvent.click(screen.getByTestId("settings-tab-update"));
    const xBtn = await screen.findByTestId("btn-settings-open-x");
    const clashCard = screen.getByTestId("settings-clash-verge-card");
    const updaterCard = screen.getByTestId("settings-updater-card");
    expect(
      xBtn.compareDocumentPosition(clashCard) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
    expect(
      clashCard.compareDocumentPosition(updaterCard) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();

    expect(xBtn).toHaveTextContent("前往 X 主页 ↗");
    fireEvent.click(xBtn);
    await waitFor(() => expect(openUrlSpy).toHaveBeenCalledWith(OFFICIAL_AUTHOR_X_URL));

    fireEvent.click(screen.getByTestId("btn-settings-install-clash"));
    await waitFor(() =>
      expect(openUrlSpy).toHaveBeenCalledWith(OFFICIAL_CLASH_VERGE_RELEASES_URL)
    );

    fireEvent.click(screen.getByTestId("btn-settings-clash-github"));
    await waitFor(() =>
      expect(openUrlSpy).toHaveBeenCalledWith(OFFICIAL_CLASH_VERGE_REPO_URL)
    );
  });

  it("联系作者弹窗展示官方 X 账号与 GitHub 仓库，并支持打开外部链接", async () => {
    const openUrlSpy = vi.spyOn(ipc, "openExternalUrl").mockResolvedValue(undefined);
    render(<App />);

    fireEvent.click(screen.getByTestId("topbar-btn-support"));
    expect(await screen.findByTestId("support-modal")).toBeInTheDocument();
    expect(screen.getByTestId("support-x-handle")).toHaveTextContent(OFFICIAL_AUTHOR_X_HANDLE);

    fireEvent.click(screen.getByTestId("btn-open-x-profile"));
    await waitFor(() => expect(openUrlSpy).toHaveBeenCalledWith(OFFICIAL_AUTHOR_X_URL));

    fireEvent.click(screen.getByTestId("btn-open-github-from-contact"));
    await waitFor(() => expect(openUrlSpy).toHaveBeenCalledWith(OFFICIAL_GITHUB_REPO_URL));
  });

  it("检测到网络急救告警时，侧边栏系统设置显示「需急救」红点且点击直达「清理恢复」", async () => {
    render(<App />);
    act(() => {
      useGuardStore.setState({ networkRescueAlert: true });
    });

    const trigger = screen.getByTestId("sidebar-settings-trigger");
    expect(trigger).toHaveTextContent("需急救");

    fireEvent.click(trigger);
    expect(await screen.findByTestId("settings-modal")).toBeInTheDocument();
    expect(useGuardStore.getState().settingsModalTab).toBe("recovery");
    expect(screen.getByTestId("settings-recovery-alert-dot")).toBeInTheDocument();
  });

  it("AI 工具箱预留页干净无假按钮，且账户审计与节点流量分段命名按终审精简生效", async () => {
    render(<App />);

    // AI 工具箱
    fireEvent.click(screen.getByRole("button", { name: /AI 工具箱/ }));
    const aiPage = await screen.findByTestId("ai-tools-page");
    expect(aiPage).toHaveTextContent("AI 工具箱");
    expect(aiPage).toHaveTextContent("即将上线");

    // 账户审计分段命名为「安全审计」与「实时日志」
    fireEvent.click(screen.getByRole("button", { name: /账户审计/ }));
    expect(await screen.findByTestId("tab-account-audit")).toHaveTextContent("安全审计");
    expect(screen.getByTestId("tab-account-logs")).toHaveTextContent("实时日志");

    // 节点流量分段命名为「节点质量」与「实时连接」
    fireEvent.click(screen.getByRole("button", { name: /节点流量/ }));
    expect(await screen.findByRole("tab", { name: "节点质量" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "实时连接" })).toBeInTheDocument();
  });
});
