import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { HudCard } from "@/components/HudCard";
import { CleanConfirmModal } from "@/components/CleanConfirmModal";
import { SettingsModal } from "@/components/SettingsModal";
import {
  buildMockAccountAuditReport,
  DEFAULT_CONFIG,
  FALLBACK_PREFLIGHT,
  FALLBACK_SNAPSHOT,
  ipc,
} from "@/lib/ipc";
import { formatCleanNodeName } from "@/lib/protocol";
import { AccountAuditPage } from "@/pages/AccountAuditPage";
import { ConsolePage, formatEvidenceKeyZh, parseEvidenceKv } from "@/pages/ConsolePage";
import { NodesTrafficPage } from "@/pages/NodesTrafficPage";
import { useGuardStore } from "@/stores/guardStore";

describe("v0.4.1 前端全面修复回归单测", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    document.documentElement.setAttribute("data-theme", "dark");
    useGuardStore.setState({
      config: { ...DEFAULT_CONFIG },
      snapshot: { ...FALLBACK_SNAPSHOT },
      preflight: { ...FALLBACK_PREFLIGHT },
      settingsModalOpen: false,
      settingsModalTab: "general",
      accountAudit: null,
      accountAuditLoading: false,
      accountAuditError: null,
      ackedLogIds: [],
      ackedFlowIds: [],
      toasts: [],
      initialized: true,
    });
  });

  it("B-05: parseEvidenceKv 正确解析 IPv6/len=164/管道哈希/安全值不误标红并去重主号候选", () => {
    expect(formatEvidenceKeyZh("Desktop Accounts")).toBe("桌面端账号");

    const ipv6Rows = parseEvidenceKv(
      "4. 外网 IPv6 连通探针 (2606:4700::1111): Blocked / Unreachable (OK)\nEndpoint: \\\\.\\pipe\\verge-mihomo-production-66b64146261caec4e13cfb7f76e58232ba78a886800d00e4b1b6a57caf845b19\nGroup: Claude-Fixed (手动固定单节点=true) → US美国1|流媒体AI"
    );
    expect(ipv6Rows).not.toBeNull();
    expect(ipv6Rows![0].k).toBe("外网 IPv6 连通");
    expect(ipv6Rows![0].v).toBe("已阻断 / 不可达（安全）");
    expect(ipv6Rows![0].tone).toBe("ok");
    expect(ipv6Rows![1].v).toBe("Mihomo 命名管道（在线）");
    expect(ipv6Rows![2].v).toBe("Claude-Fixed（手动固定） → US美国1|流媒体AI");

    const safeConflictRows = parseEvidenceKv(
      [
        "System ENV (HKCU/HKLM) API Endpoints: 0 冲突 · 原生直连",
        "CLI Proxy ENV & WinINET ProxyServer: 0 冲突 / 无直连豁免",
        "Cross-Group: 0 项跨组双 IP 冲突",
        "Elevated Helper Task: 管理员直写就绪（无需额外任务）",
        "KYC / Permission-Pending (len=164) Notice: 存在身份验证/权限暂限记录（非封号，不阻断启动，详见「账户审计 → 实时日志」）",
      ].join("\n")
    );
    expect(safeConflictRows).not.toBeNull();
    expect(safeConflictRows!.slice(0, 4).every((r) => r.tone !== "bad")).toBe(true);
    expect(safeConflictRows![4].k).toBe("实名与权限提示");
    expect(safeConflictRows![4].tone).toBe("warn");

    const acctRows = parseEvidenceKv(
      [
        "Topology Hygiene State: SingleSurfaceClean",
        "CLI (~/.claude.json): 未登录 [status=empty]",
        "Bound Primary Account: star***at@outlook.com (Free · 桌面端 · 0ffb0302)",
        "Primary Candidate Label: star***at@outlook.com (Free · 桌面端 · 0ffb0302)",
      ].join("\n")
    );
    expect(acctRows).not.toBeNull();
    expect(acctRows![0].v).toBe("单端纯净（安全）");
    expect(acctRows![1].v).toBe("未登录");
    expect(acctRows!.filter((r) => r.k === "主号候选标识")).toHaveLength(0);
  });

  it("B-02/03/04/14: 设置弹窗常规开关动态徽标、启动建议命中 Clash Verge Rev、自动重扫自启与 GPL-3.0 底标", async () => {
    const auditSpy = vi.spyOn(ipc, "auditStartupItems").mockResolvedValue({
      claudeAutostartRisk: false,
      entries: [
        {
          app: "FD Claude Guard",
          enabled: true,
          riskLevel: "ok",
          detail: "已开启高权限后台守护自启",
        },
        {
          app: "Clash Verge Rev",
          enabled: false,
          riskLevel: "warn",
          detail: "未检测到计划任务或自启项",
        },
      ],
    });

    useGuardStore.setState({
      config: { ...DEFAULT_CONFIG, showHud: false, notifyEnabled: true, bootStart: false },
      settingsModalOpen: true,
      settingsModalTab: "general",
    });

    await act(async () => {
      render(<SettingsModal />);
    });

    await waitFor(() => {
      expect(auditSpy).toHaveBeenCalledTimes(1);
    });

    expect(screen.getAllByText("建议开启").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/建议开启 · 未检测到计划任务或自启项/)).toBeInTheDocument();
    expect(screen.getByText("已开启高权限后台守护自启")).toBeInTheDocument();

    fireEvent.click(screen.getByTestId("settings-tab-update"));
    expect(screen.getByText("GPL-3.0 开源")).toBeInTheDocument();
    expect(screen.queryByText("MIT 开源")).not.toBeInTheDocument();
  });

  it("B-10: 账户审计脉冲卡在 0 未读时不与历史非降噪记录打架", () => {
    const mockAudit = buildMockAccountAuditReport();
    mockAudit.local.desktop.cookie403Hits = 0;
    mockAudit.local.desktop.cfShield403Hits = 0;
    mockAudit.logFlowItems = [
      {
        id: "ev-1",
        cat: "403",
        denoised: false,
        chipLabel: "403 预警",
        chipTone: "warn",
        title: "历史 OAuth 403",
        desc: "已读历史",
        timeLabel: "12:00",
        rawSanitized: "main.log:10",
        count: 1,
      },
      {
        id: "ev-2",
        cat: "403",
        denoised: false,
        chipLabel: "403 预警",
        chipTone: "warn",
        title: "历史 OAuth 403",
        desc: "已读历史",
        timeLabel: "12:05",
        rawSanitized: "main.log:20",
        count: 1,
      },
    ];

    useGuardStore.setState({
      accountAudit: mockAudit,
      snapshot: { ...FALLBACK_SNAPSHOT, unreadLogAnomalies: 0 },
    });

    render(<AccountAuditPage />);
    const card = screen.getByTestId("audit-pulse-card");
    expect(card).toHaveTextContent("0 未读");
    expect(card).toHaveTextContent("未读已清零");
    expect(card).not.toHaveTextContent("待核异常事件");
  });

  it("B-15: 清理前导国旗 Emoji 并在节点隔离区准确标注名标与实测地区差异", () => {
    expect(formatCleanNodeName("🇺🇸美国1|流媒体AI")).toBe("美国1|流媒体AI");
    expect(formatCleanNodeName("🇨🇳台湾1|流媒体AI")).toBe("台湾1|流媒体AI");

    useGuardStore.setState({
      nodeReport: {
        connected: true,
        endpoint: "pipe",
        groupName: "Claude-Fixed",
        currentNode: "🇺🇸美国1|流媒体AI",
        totalRawNodes: 2,
        filteredBlockedCount: 1,
        nodes: [
          {
            name: "🇺🇸美国1|流媒体AI",
            regionCode: "US",
            regionLabel: "美国 · 原生",
            nodeType: "ISP 住宅",
            delayMs: 140,
            jitterMs: 8,
            dropRatePct: 0,
            score: 94,
            cfBlocked: false,
            blocked: false,
            isCurrent: true,
            recommendation: "主力推荐",
          },
          {
            name: "🇨🇳台湾1|流媒体AI",
            regionCode: "HK",
            regionLabel: "香港 · AnyTLS",
            nodeType: "AnyTLS",
            delayMs: 170,
            jitterMs: 10,
            dropRatePct: 0,
            score: 35,
            cfBlocked: false,
            blocked: true,
            isCurrent: false,
            recommendation: "落地禁区",
          },
        ],
      },
    });

    render(<NodesTrafficPage />);
    expect(screen.getAllByText("美国1|流媒体AI").length).toBeGreaterThanOrEqual(1);

    fireEvent.click(screen.getByTestId("tab-nodes-quarantine"));
    expect(screen.getByText("台湾1|流媒体AI")).toBeInTheDocument();
    expect(screen.getByText("实测香港（名标 TW）· AnyTLS")).toBeInTheDocument();
  });

  it("B-12: HUD 悬浮窗监听 config-changed 与窗口 focus 同步主题", async () => {
    let configListener: ((cfg: typeof DEFAULT_CONFIG) => void) | undefined;
    vi.spyOn(ipc, "listenConfigChanged").mockImplementation(async (cb) => {
      configListener = cb;
      return () => {};
    });
    const getConfigSpy = vi
      .spyOn(ipc, "getConfig")
      .mockResolvedValue({ ...DEFAULT_CONFIG, theme: "light" });
    vi.spyOn(ipc, "getSnapshot").mockResolvedValue({ ...FALLBACK_SNAPSHOT });

    render(<HudCard />);

    await waitFor(() => {
      expect(getConfigSpy).toHaveBeenCalled();
    });
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");

    act(() => {
      configListener?.({ ...DEFAULT_CONFIG, theme: "dark" });
    });
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("M1-03/M1-04: 控制台身份认证遗留双行动（清理+换节点）与单号卫生锁 Warn 确认/清理闭环", async () => {
    const confirmAcctSpy = vi.spyOn(ipc, "confirmCurrentAccount").mockResolvedValue({
      ...FALLBACK_PREFLIGHT,
      items: FALLBACK_PREFLIGHT.items.map((it) =>
        it.id === "claude_acct"
          ? {
              ...it,
              status: "ok",
              summary: "已确认继续使用当前号（star***at@outlook.com（Free · 桌面端）），单号环境纯净",
              fixLabel: null,
            }
          : it
      ),
    });
    const ackBanSpy = vi.spyOn(ipc, "acknowledgeBanWarnSession").mockResolvedValue({
      ...FALLBACK_PREFLIGHT,
      items: FALLBACK_PREFLIGHT.items.map((it) =>
        it.id === "claude_ban"
          ? {
              ...it,
              status: "ok",
              summary: "已扫描 4 份本地日志，0 封号与身份认证残留",
              fixLabel: null,
            }
          : it
      ),
    });

    const customItems = FALLBACK_PREFLIGHT.items.map((it) => {
      if (it.id === "claude_ban") {
        return {
          ...it,
          status: "fail" as const,
          summary: "检测到身份认证（Persona / Portal）遗留记录：portal_verification",
          evidence: "已扫描日志文件: 4 份（桌面端与商店版目录）\n封号与验证实锤: portal_verification",
          fixLabel: "清理账户记录（备份）",
        };
      }
      if (it.id === "claude_acct") {
        return {
          ...it,
          status: "warn" as const,
          title: "单号卫生锁（防多号混登）",
          summary: "检测到当前登录账号：star***at@outlook.com（Free · 桌面端），请确认即将登录的是否为当前号",
          evidence: "当前状态: 待确认当前号\n桌面端当前号: star***at@outlook.com（Free · 桌面端）\n检测到账号数: 1",
          fixLabel: "确认继续使用当前号",
        };
      }
      return { ...it, status: "ok" as const, fixLabel: null };
    });

    useGuardStore.setState({
      activeTab: "console",
      selectedCheckId: "claude_ban",
      preflight: { ...FALLBACK_PREFLIGHT, items: customItems },
    });

    render(
      <>
        <ConsolePage />
        <CleanConfirmModal />
      </>
    );

    // 1) 仅有 claude_ban(Fail) + claude_acct(Warn) 两项人工项时，右上角不应渲染空转「一键处理全部」
    expect(screen.queryByTestId("btn-batch-fix-all")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /请先处理 1 项未通过/ })).toBeDisabled();

    // 2) claude_ban Fail 态主按钮为蓝色（guard-btn-primary）+ 前往节点流量换节点
    const cleanBanBtn = screen.getByTestId("btn-ban-clean-records");
    expect(cleanBanBtn).toHaveClass("guard-btn-primary");
    expect(screen.getByTestId("btn-ban-switch-node")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("btn-ban-switch-node"));
    expect(useGuardStore.getState().activeTab).toBe("nodes");
    expect(useGuardStore.getState().nodesSubTab).toBe("quality");

    // 3) claude_ban 清理后未换旧节点 Warn 态可核实放行；此时若仅有 claude_acct Warn，右上角文案写「请先确认 2 项风险」且禁点
    act(() => {
      useGuardStore.setState({
        activeTab: "console",
        selectedCheckId: "claude_ban",
        preflight: {
          ...FALLBACK_PREFLIGHT,
          items: customItems.map((it) =>
            it.id === "claude_ban"
              ? {
                  ...it,
                  status: "warn",
                  summary: "记录已清理，请前往「节点流量」更换节点",
                }
              : it
          ),
        },
      });
    });
    expect(screen.getByRole("button", { name: /请先确认 2 项风险/ })).toBeDisabled();
    fireEvent.click(screen.getByTestId("btn-ban-ack-warn"));
    await waitFor(() => expect(ackBanSpy).toHaveBeenCalledTimes(1));

    // 4) claude_acct 单号 Warn 态：右上角显示「请先确认 1 项风险」，右侧主蓝按钮确认 + 清理
    act(() => {
      useGuardStore.setState({
        selectedCheckId: "claude_acct",
        preflight: {
          ...FALLBACK_PREFLIGHT,
          items: customItems.map((it) =>
            it.id === "claude_ban" ? { ...it, status: "ok", fixLabel: null } : it
          ),
        },
      });
    });
    expect(screen.getByRole("button", { name: /请先确认 1 项风险/ })).toBeDisabled();
    expect(screen.getByTestId("btn-acct-confirm-current")).toHaveClass("guard-btn-primary");
    expect(screen.getByTestId("btn-acct-clean-state")).toHaveTextContent("不是当前号，清理登录状态");
    fireEvent.click(screen.getByTestId("btn-acct-confirm-current"));
    await waitFor(() => expect(confirmAcctSpy).toHaveBeenCalledTimes(1));
  });
});
