import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SettingsModal } from "@/components/SettingsModal";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, FALLBACK_STARTUP_AUDIT, ipc } from "@/lib/ipc";
import { NodesTrafficPage } from "@/pages/NodesTrafficPage";
import { useGuardStore } from "@/stores/guardStore";
import type { ClaudeConn } from "@/types/guard";

describe("v0.3.5 Clash 分流深度加固与守卫配置开关回归", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useGuardStore.setState({
      config: { ...DEFAULT_CONFIG, lockCfAndStripeToClaude: true },
      snapshot: { ...FALLBACK_SNAPSHOT },
      preflight: { ...FALLBACK_PREFLIGHT },
      startupAudit: { ...FALLBACK_STARTUP_AUDIT },
      updateInfo: {
        currentVersion: "0.3.5",
        available: false,
        viaProxy: false,
        message: "已是最新版本",
      },
      toasts: [],
      initialized: true,
    });
  });

  it("守卫配置展示「同步锁定 Cloudflare 人机盾与 Stripe 支付至 Claude-Fixed」且切换后触发热同步", async () => {
    const updateSpy = vi
      .spyOn(ipc, "updateConfig")
      .mockResolvedValue({ ...DEFAULT_CONFIG, lockCfAndStripeToClaude: false });
    const syncSpy = vi
      .spyOn(ipc, "syncClashRulePolicy")
      .mockResolvedValue("已无损更新 Script.js 并热重载规则，CF 盾与 Stripe 同步锁定已取消。");
    const preflightSpy = vi
      .spyOn(ipc, "runPreflightChecks")
      .mockResolvedValue({ ...FALLBACK_PREFLIGHT });
    vi.spyOn(ipc, "auditStartupItems").mockResolvedValue({ ...FALLBACK_STARTUP_AUDIT });
    vi.spyOn(ipc, "getNodesAndQuality").mockResolvedValue({
      connected: true,
      endpoint: "pipe",
      groupName: "Claude-Fixed",
      currentNode: "🇺🇸美国1",
      totalRawNodes: 1,
      filteredBlockedCount: 0,
      nodes: [],
    });
    vi.spyOn(ipc, "getSnapshot").mockResolvedValue({ ...FALLBACK_SNAPSHOT });
    vi.spyOn(ipc, "auditAccountLocal").mockResolvedValue(null as never);

    useGuardStore.setState({
      settingsModalOpen: true,
      settingsModalTab: "policy",
    });
    render(<SettingsModal />);

    const toggle = screen.getByRole("switch", {
      name: "同步锁定人机盾与 Stripe 支付至 Claude-Fixed",
    });
    expect(toggle).toHaveAttribute("aria-checked", "true");

    fireEvent.click(toggle);

    await waitFor(() => {
      expect(updateSpy).toHaveBeenCalledWith({ lockCfAndStripeToClaude: false });
      expect(syncSpy).toHaveBeenCalledTimes(1);
      expect(preflightSpy).toHaveBeenCalledWith(true);
    });

    expect(useGuardStore.getState().config.lockCfAndStripeToClaude).toBe(false);
    expect(
      useGuardStore
        .getState()
        .toasts.some((t) => t.body.includes("CF 盾与 Stripe 同步锁定已取消"))
    ).toBe(true);
  });

  it("节点流量实时连接准确区分域名用途、已拦截遥测与未收录新域自动雷达筛选", async () => {
    const mockConns: ClaudeConn[] = [
      {
        id: "conn-api",
        anomaly: false,
        process: "Claude.exe",
        host: "api.anthropic.com:443",
        rule: "DomainSuffix",
        chain: "Claude-Fixed → 🇺🇸美国1",
        action: "正常放行",
        time: "18:20:01",
        bytesLabel: "12.4 KB",
        domainCategory: "core_api",
        purposeLabel: "核心 API",
        purposeDetail: "Anthropic 官方模型推理、桌面端与 Claude Code 核心接口",
        isUnlistedDomain: false,
      },
      {
        id: "conn-tel",
        anomaly: false,
        process: "Claude.exe",
        host: "browser-intake-datadoghq.com:443",
        rule: "DomainSuffix",
        chain: "REJECT",
        action: "已拦截（防回传）",
        time: "18:20:02",
        bytesLabel: "0 B",
        domainCategory: "telemetry",
        purposeLabel: "遥测 · 行为监控",
        purposeDetail: "Datadog 客户端/网页指纹与性能事件上报（建议 REJECT 拦截）",
        isUnlistedDomain: false,
      },
      {
        id: "conn-new",
        anomaly: false,
        process: "Claude.exe",
        host: "edge-new.anthropic-labs.dev:443",
        rule: "Process",
        chain: "Claude-Fixed → 🇺🇸美国1",
        action: "进程兜底放行（未收录新域）",
        time: "18:20:03",
        bytesLabel: "1.2 KB",
        domainCategory: "unknown_new",
        purposeLabel: "未收录新域",
        purposeDetail: "Claude 进程访问的新外部域名，已由进程规则自动兜底走 Claude-Fixed（建议后续版本收录）",
        isUnlistedDomain: true,
      },
    ];
    useGuardStore.setState({
      nodesSubTab: "traffic",
      nodeReport: {
        connected: true,
        endpoint: "pipe",
        groupName: "Claude-Fixed",
        currentNode: "🇺🇸美国1",
        totalRawNodes: 1,
        filteredBlockedCount: 0,
        nodes: [],
      },
    });
    vi.spyOn(ipc, "getLiveConnections").mockResolvedValue(mockConns);

    render(<NodesTrafficPage />);

    expect(await screen.findByTestId("conn-purpose-conn-api")).toHaveTextContent("核心 API");
    expect(screen.getByTestId("conn-purpose-conn-tel")).toHaveTextContent("遥测 · 行为监控");
    expect(screen.getByTestId("conn-purpose-conn-new")).toHaveTextContent("未收录新域");
    expect(screen.getByText("已拦截")).toBeInTheDocument();

    // 自动出现「未收录新域 1」筛选按钮，点击后仅显示未收录新域
    const unlistedBtn = screen.getByTestId("btn-filter-unlisted-domains");
    expect(unlistedBtn).toHaveTextContent(/未收录新域\s*1/);
    fireEvent.click(unlistedBtn);

    expect(screen.getByTestId("conn-purpose-conn-new")).toBeInTheDocument();
    expect(screen.queryByTestId("conn-purpose-conn-api")).not.toBeInTheDocument();
  });
});
