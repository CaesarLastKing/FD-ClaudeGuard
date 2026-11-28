import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import { SettingsModal } from "@/components/SettingsModal";
import { Sidebar } from "@/components/Sidebar";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { AccountAuditPage } from "@/pages/AccountAuditPage";
import { useGuardStore } from "@/stores/guardStore";

const FORBIDDEN_DESIGN_TERMS = [
  "手风琴",
  "T-058",
  "T-059",
  "同源",
  "只读对照区",
  "第 2 格",
  "按需亮灯",
  "哪项有隐患",
  "+ 多账户",
  "设计说明",
];

describe("v0.3.0 账户审计（v12 1:1 交互、单开互斥、云端核验与零设计术语红线）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useGuardStore.setState({
      activeTab: "audit",
      auditSubTab: "audit",
      accountAudit: null,
      accountAuditLoading: false,
      preflight: FALLBACK_PREFLIGHT,
      snapshot: { ...FALLBACK_SNAPSHOT },
      config: { ...DEFAULT_CONFIG },
      toasts: [],
      riskModal: null,
      cleanModal: null,
      initialized: true,
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("主导航顺序严格为 控制台 → 账户审计 → 节点流量 → AI 工具箱，并在左下角提供系统设置入口", () => {
    render(<Sidebar />);
    const navButtons = Array.from(
      document.querySelectorAll('nav[aria-label="主导航"] button')
    ).map((btn) => btn.textContent ?? "");

    expect(navButtons.length).toBe(4);
    expect(navButtons[0]).toContain("控制台");
    expect(navButtons[1]).toContain("账户审计");
    expect(navButtons[2]).toContain("节点流量");
    expect(navButtons[3]).toContain("AI 工具箱");
    expect(screen.getByTestId("sidebar-settings-trigger")).toHaveTextContent("系统设置");
  });

  it("渲染双层档案卡、顶部 4 格、订阅天数原地切换与上下两段 7 项严格单开互斥", async () => {
    render(<AccountAuditPage />);

    // 脱敏邮箱与 7 项标题就绪
    expect((await screen.findAllByText(/stev\*\*\*88@gmail\.com/)).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("一、需用户自行注意与克制")).toBeInTheDocument();
    expect(screen.getByText("二、工具可介入防御与修复")).toBeInTheDocument();
    expect(screen.getByText("对话可用状态")).toBeInTheDocument();
    expect(screen.getByText("官方警告与静默标")).toBeInTheDocument();
    expect(screen.getByText("Persona 实名 KYC")).toBeInTheDocument();
    expect(screen.getByText("Portal 风控门户")).toBeInTheDocument();

    // 点击订阅周期原地切换预计到期/续费日（按月计费周期展示 Pro 订阅 · 第 X 天）
    const subBtn = screen.getByTestId("btn-sub-toggle");
    expect(subBtn.textContent).toContain("Pro 订阅 · 第 3 天");
    fireEvent.click(subBtn);
    expect(subBtn.textContent).toContain("预计续费");
    fireEvent.click(subBtn);
    expect(subBtn.textContent).toContain("Pro 订阅 · 第 3 天");

    // 默认全部折叠，单开互斥展开：点第一项展开 1 项，再点另一项前一项自动收起，再点同一项收起
    expect(document.querySelectorAll(".audit-group.is-open").length).toBe(0);

    fireEvent.click(screen.getByText("自动化机刷与人机节律监测"));
    const afterFirstClick = document.querySelectorAll(".audit-group.is-open");
    expect(afterFirstClick.length).toBe(1);
    expect(afterFirstClick[0].textContent).toContain("自动化机刷与人机节律监测");

    fireEvent.click(screen.getByText("官方 API 端点防反代检测"));
    const afterSecondClick = document.querySelectorAll(".audit-group.is-open");
    expect(afterSecondClick.length).toBe(1);
    expect(afterSecondClick[0].textContent).toContain("官方 API 端点防反代检测");

    fireEvent.click(screen.getByText("官方 API 端点防反代检测"));
    expect(document.querySelectorAll(".audit-group.is-open").length).toBe(0);
  });

  it("支持直接粘贴 Copy as cURL 自动提取 sessionKey 触发云端只读核验并刷新状态", async () => {
    const verifySpy = vi.spyOn(ipc, "verifyAccountCloudWithSk");
    render(<AccountAuditPage />);

    const topVerifyBtn = await screen.findByTestId("btn-top-cloud-verify");
    fireEvent.click(topVerifyBtn);

    const input = await screen.findByTestId("audit-sk-input");
    fireEvent.change(input, {
      target: {
        value:
          "curl 'https://claude.ai/api/organizations' -H 'cookie: sessionKey=sk-ant-sid01-demo-token-1234567890abcdef; cf_clearance=abc'",
      },
    });
    fireEvent.click(screen.getByTestId("btn-verify-cloud-sk"));

    await waitFor(() => {
      expect(verifySpy).toHaveBeenCalledTimes(1);
    });
    expect(verifySpy.mock.calls[0][0]).toContain("sk-ant-sid01-demo-token");
    await waitFor(() => {
      expect(screen.getAllByText(/归属地/).length).toBeGreaterThanOrEqual(1);
    });
  });

  it("打开「防封宝典」抽屉与折叠 100 分权重表，且全页与抽屉零设计术语泄漏", async () => {
    const { container } = render(<AccountAuditPage />);
    await screen.findByText("一、需用户自行注意与克制");

    // 扫描账户审计主视图全文
    const mainText = container.textContent ?? "";
    for (const term of FORBIDDEN_DESIGN_TERMS) {
      expect(mainText).not.toContain(term);
    }

    // 打开「防封宝典」抽屉并展开 100 分权重说明
    fireEvent.click(screen.getByTestId("btn-open-anti-ban-guide"));
    const drawer = await screen.findByTestId("anti-ban-guide-drawer");
    expect(drawer).toHaveTextContent("防封宝典");

    const weightBtn = screen.getByTestId("btn-toggle-weight-table");
    fireEvent.click(weightBtn);
    const weightBox = await screen.findByTestId("weight-table-box");
    expect(weightBox).toHaveTextContent("24");
    expect(weightBox).toHaveTextContent("16");

    const fullTextWithDrawer = container.textContent ?? "";
    for (const term of FORBIDDEN_DESIGN_TERMS) {
      expect(fullTextWithDrawer).not.toContain(term);
    }
  });

  it("支持切至第 2 分段「实时异常日志流」并勾选显示已降噪的 OAuth 403", async () => {
    render(<App />);
    fireEvent.click(screen.getByRole("button", { name: /账户审计/ }));

    fireEvent.click(await screen.findByTestId("tab-account-logs"));
    expect(await screen.findByTestId("audit-logs-view")).toBeInTheDocument();

    const checkbox = screen.getByRole("checkbox", { name: /显示已降噪的 OAuth 403/ });
    expect(checkbox).not.toBeChecked();
    fireEvent.click(checkbox);
    expect(checkbox).toBeChecked();
    expect(screen.getAllByText(/已自动降噪/).length).toBeGreaterThanOrEqual(1);
  });

  it("系统设置支持检查更新并在发现新版本时展示更新摘要与一键安装按钮", async () => {
    const checkSpy = vi.spyOn(ipc, "checkAppUpdate").mockResolvedValue({
      currentVersion: "0.3.0",
      available: true,
      latestVersion: "0.3.1",
      publishedAt: "2026-12-01T00:00:00Z",
      notes: "- 修复节点抖动重测提示",
      viaProxy: true,
      message: "发现新版本 v0.3.1（已启用 Ed25519 签名校验）。",
    });
    const installSpy = vi
      .spyOn(ipc, "installAppUpdate")
      .mockResolvedValue("已下载并校验 v0.3.1 更新包，正在安装并重启...");

    useGuardStore.setState({
      settingsModalOpen: true,
      settingsModalTab: "update",
      updateInfo: {
        currentVersion: "0.3.0",
        available: false,
        latestVersion: "0.3.0",
        viaProxy: false,
        message: "当前已是最新版本",
      },
    });
    render(<SettingsModal />);
    fireEvent.click(screen.getByTestId("btn-settings-check-update"));

    await waitFor(() => {
      expect(checkSpy).toHaveBeenCalledTimes(1);
      expect(screen.getByTestId("settings-updater-card")).toHaveTextContent("发现新版本 v0.3.1");
      expect(screen.getByTestId("settings-updater-card")).toHaveTextContent("修复节点抖动重测提示");
    });

    fireEvent.click(screen.getByRole("button", { name: /立即更新 v0\.3\.1/ }));
    await waitFor(() => {
      expect(installSpy).toHaveBeenCalledTimes(1);
    });
  });
});
