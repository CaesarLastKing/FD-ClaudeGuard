import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import { HudCard } from "@/components/HudCard";
import { LicenseModal } from "@/components/LicenseModal";
import { Sidebar } from "@/components/Sidebar";
import { ConsolePage } from "@/pages/ConsolePage";
import { DEFAULT_CONFIG, FALLBACK_PREFLIGHT, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { NodesTrafficPage } from "@/pages/NodesTrafficPage";
import { useGuardStore } from "@/stores/guardStore";

describe("增量 17 / 18 / 19 回归与核心体验门禁", () => {
  beforeEach(() => {
    useGuardStore.setState({
      activeTab: "console",
      nodesSubTab: "quality",
      selectedCheckId: "node_group",
      licenseModalOpen: false,
      supportModalOpen: false,
      preflight: FALLBACK_PREFLIGHT,
      snapshot: { ...FALLBACK_SNAPSHOT },
      config: { ...DEFAULT_CONFIG },
      licenseStatus: {
        commercialFeatureEnabled: true,
        licensed: false,
        activatedAt: null,
        batchId: null,
        installIdShort: "test0001",
        machineFpShort: "fp0001",
        apiEndpoint: "https://example.invalid/api/v1/activate",
      },
    });
  });

  it("增量 19：未激活态右侧仅显纯净毛玻璃马赛克、隐藏导出链、聚焦白色解锁按钮；激活弹窗底部绝不出现 QQ 售后", async () => {
    render(<App />);

    // 标题旁状态胶囊显示「未激活 · 点击激活」
    expect(screen.getByTestId("console-license-chip")).toHaveTextContent("未激活 · 点击激活");

    // 纯净毛玻璃马赛克：存在锁定层、绝无居中文字胶囊、DOM 中不泄漏明文指南
    const mosaic = screen.getByTestId("guide-mosaic-locked");
    expect(mosaic).toBeInTheDocument();
    expect(mosaic.textContent).not.toContain("Script.js");

    // 未激活态隐藏底部导出排障包链接
    expect(screen.queryByTestId("btn-export-ai-diag")).not.toBeInTheDocument();

    // 高对比白色解锁主按钮存在，点击弹出激活弹窗
    const unlockBtn = screen.getByTestId("btn-unlock-license-cta");
    expect(unlockBtn).toHaveTextContent("输入激活密钥 · 解锁步骤并一键处理");
    fireEvent.click(unlockBtn);

    const modal = await screen.findByTestId("license-modal");
    expect(modal).toBeInTheDocument();

    // 红线断言：激活弹窗底部（乃至整个弹窗）绝不显示 QQ 售后或 2568515327
    const footer = screen.getByTestId("license-modal-footer");
    expect(footer.textContent).not.toContain("QQ");
    expect(footer.textContent).not.toContain("2568515327");
    expect(footer.textContent).not.toContain("售后");
    expect(modal.textContent).not.toContain("2568515327");
  });

  it("未激活态严格收紧边界：公开 3 项左右全公开，其余 11 项左右名称与状态均隐藏，4 个副页面全部激活后开启", async () => {
    const licSpy = vi.spyOn(ipc, "getLicenseStatus").mockResolvedValue({
      commercialFeatureEnabled: true,
      licensed: false,
      activatedAt: null,
      batchId: null,
      installIdShort: "test0001",
      machineFpShort: "fp0001",
      apiEndpoint: "https://example.invalid/api/v1/activate",
    });

    try {
      render(<App />);

      // 隐藏项（如 node_group / sys_location / claude_ban / claude_acct）右侧状态显示「已隐藏」、左侧标题脱敏绝不泄漏原始检测名
      expect(screen.getByTestId("check-locked-chip-node_group")).toHaveTextContent("已隐藏");
      expect(screen.getByTestId("check-locked-chip-sys_location")).toHaveTextContent("已隐藏");
      expect(screen.getByTestId("check-locked-chip-claude_ban")).toHaveTextContent("已隐藏");
      expect(screen.getByTestId("check-locked-chip-claude_acct")).toHaveTextContent("已隐藏");
      expect(screen.getByTestId("check-locked-title-node_group")).toHaveTextContent("核心防封深度检测项 #");
      expect(screen.getByTestId("check-locked-title-sys_location")).toHaveTextContent("核心防封深度检测项 #");
      expect(screen.getByTestId("evidence-mosaic-locked")).toBeInTheDocument();

      // 关键断言：DOM 中绝不能出现隐藏项（含新增 3 项建议优化）的真实检测名称！
      expect(screen.queryByText("策略组与全家桶规则锁死")).not.toBeInTheDocument();
      expect(screen.queryByText("Windows 系统定位服务关闭")).not.toBeInTheDocument();
      expect(screen.queryByText("本地封号污染残留审查")).not.toBeInTheDocument();
      expect(screen.queryByText("单号卫生锁（防混号与跨 orgId）")).not.toBeInTheDocument();
      expect(screen.queryByText("浏览器 WebRTC 防泄露策略")).not.toBeInTheDocument();
      expect(screen.queryByText("系统时区与出口地区一致性")).not.toBeInTheDocument();
      expect(screen.queryByText("浏览器独立代理插件冲突审计")).not.toBeInTheDocument();

      // 3 项免费公开体验项：左侧标题与右侧状态均完整公开，无锁定芯片
      expect(screen.getByText("代理引擎在线与端口独占")).toBeInTheDocument();
      expect(screen.getByText("虚拟网卡接管（Clash TUN）")).toBeInTheDocument();
      expect(screen.getByText("Windows 网卡 IPv6 禁用")).toBeInTheDocument();
      expect(screen.queryByTestId("check-locked-chip-node_proxy")).not.toBeInTheDocument();
      expect(screen.queryByTestId("check-locked-chip-node_tun")).not.toBeInTheDocument();
      expect(screen.queryByTestId("check-locked-chip-sys_ipv6")).not.toBeInTheDocument();

      // 4 个副页面在未激活态均展示统一锁定门禁页
      fireEvent.click(screen.getByRole("button", { name: /节点流量/ }));
      expect(await screen.findByTestId("locked-gate-nodes")).toBeInTheDocument();

      fireEvent.click(screen.getByRole("button", { name: /日志分析/ }));
      expect(await screen.findByTestId("locked-gate-logs")).toBeInTheDocument();

      fireEvent.click(screen.getByRole("button", { name: /环境维护/ }));
      expect(await screen.findByTestId("locked-gate-maintain")).toBeInTheDocument();

      fireEvent.click(screen.getByRole("button", { name: /守卫配置/ }));
      expect(await screen.findByTestId("locked-gate-config")).toBeInTheDocument();
    } finally {
      licSpy.mockRestore();
    }
  });

  it("增量 19：主窗口顶栏纯图标售后按钮弹出官方售后 QQ 2568515327，已激活态严格保留 ISS-009 排障导出", async () => {
    useGuardStore.setState({
      licenseStatus: {
        commercialFeatureEnabled: true,
        licensed: true,
        activatedAt: "2026-11-24T00:00:00Z",
        batchId: "B202611",
      },
    });

    render(<App />);

    // 已激活态：展示明文步骤且保留 ISS-009 导出链接
    expect(screen.getByTestId("guide-plaintext")).toBeInTheDocument();
    expect(screen.getByTestId("btn-export-ai-diag")).toBeInTheDocument();

    // 点击顶栏耳机售后按钮 -> 展示官方售后 QQ 2568515327
    const supportBtn = screen.getByTestId("topbar-btn-support");
    fireEvent.click(supportBtn);
    const supportModal = await screen.findByTestId("support-modal");
    expect(supportModal).toBeInTheDocument();
    expect(screen.getByTestId("support-qq-number")).toHaveTextContent("2568515327");
  });

  it("增量 17：侧边栏与悬浮窗同步展示 Kill-Hold 盯防蓝态与解除按钮，且保留 ISS-021 安全退出 Claude", () => {
    useGuardStore.setState({
      licenseStatus: {
        commercialFeatureEnabled: true,
        licensed: true,
      },
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

  it("增量 18/v5：已激活态节点页展示 6 列分列评估表（含延迟/断连/稳定性）、悬停解释与右侧当前锁定", async () => {
    useGuardStore.setState({
      licenseStatus: {
        commercialFeatureEnabled: true,
        licensed: true,
        activatedAt: "2026-11-24T00:00:00Z",
        batchId: "B202611",
      },
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
    expect(table.textContent).toContain("Claude 拉黑");
    expect(table.textContent).toContain("当前锁定");

    // 悬停在「Claude 拉黑」与「AGY 限区」时即时浮出大白话解释
    fireEvent.mouseEnter(screen.getByText("Claude 拉黑"));
    expect(screen.getByTestId("node-hover-tooltip")).toHaveTextContent("Cloudflare 403");
    fireEvent.mouseLeave(screen.getByText("Claude 拉黑"));
    expect(screen.queryByTestId("node-hover-tooltip")).not.toBeInTheDocument();

    const limitChips = screen.getAllByText("AGY 限区");
    fireEvent.mouseEnter(limitChips[0]);
    expect(screen.getByTestId("node-hover-tooltip")).toHaveTextContent("Antigravity");
  });

  it("核销失败后错误提示持久保留，不会被 submitting 状态变化意外清空", async () => {
    const origActivate = useGuardStore.getState().activateLicense;
    const mockFail = vi.fn().mockRejectedValue(new Error("连接核销服务失败：模拟网络异常"));
    useGuardStore.setState({
      licenseModalOpen: true,
      activateLicense: mockFail,
    });

    try {
      render(<LicenseModal />);
      const input = screen.getByTestId("license-key-input");
      fireEvent.change(input, { target: { value: "FDG-TEST-DEMO-0001" } });
      fireEvent.click(screen.getByTestId("btn-submit-license"));

      const errBox = await screen.findByTestId("license-error-msg");
      expect(errBox.textContent).toContain("连接核销服务失败：模拟网络异常");
      expect(mockFail).toHaveBeenCalledWith("FDG-TEST-DEMO-0001");
      // 确认按钮已恢复非提交态，但错误提示依然牢固显示
      expect(screen.getByTestId("btn-submit-license")).not.toBeDisabled();
      expect(screen.getByTestId("license-error-msg")).toBeInTheDocument();
    } finally {
      useGuardStore.setState({ activateLicense: origActivate });
    }
  });

  it("盯防卡片默认及解除盯防后不残留白边，且节点不可用/漂移风险时侧边栏角标三方联动", () => {
    const baseState = useGuardStore.getState();
    useGuardStore.setState({
      licenseStatus: { commercialFeatureEnabled: true, licensed: true },
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

    // 模拟开启盯防后再解除盯防：绝不可因为清空 borderColor 回落为 currentColor 白边
    useGuardStore.setState({
      snapshot: { ...useGuardStore.getState().snapshot, killHoldActive: true, killHoldRemainingSecs: 45 },
    });
    rerender(<Sidebar />);
    expect(procCard.style.border).toContain("rgba(0, 111, 238, 0.45)");

    useGuardStore.setState({
      snapshot: { ...useGuardStore.getState().snapshot, killHoldActive: false, killHoldRemainingSecs: 0 },
    });
    rerender(<Sidebar />);
    expect(procCard.style.border).toContain("var(--border)");

    // 模拟节点漂移预警（Warn）→ 侧边栏节点流量亮黄色角标 1
    useGuardStore.setState({
      preflight: {
        ...useGuardStore.getState().preflight,
        items: useGuardStore.getState().preflight.items.map((item) =>
          item.id === "node_geo" ? { ...item, status: "warn" } : item
        ),
      },
    });
    rerender(<Sidebar />);
    const warnBadge = screen.getByTestId("nav-badge-nodes");
    expect(warnBadge.textContent).toBe("1");
    expect(warnBadge.style.color).toContain("var(--warning)");

    // 模拟节点不可用（Fail / nodeDown）→ 侧边栏节点流量亮红色角标 1
    useGuardStore.setState({
      snapshot: { ...useGuardStore.getState().snapshot, nodeDown: true, activeFlowAnomalies: 1 },
      preflight: {
        ...useGuardStore.getState().preflight,
        items: useGuardStore.getState().preflight.items.map((item) =>
          item.id === "node_geo" ? { ...item, status: "fail" } : item
        ),
      },
    });
    rerender(<Sidebar />);
    const failBadge = screen.getByTestId("nav-badge-nodes");
    expect(failBadge.textContent).toBe("1");
    expect(failBadge.style.color).toContain("var(--danger-bright)");
  });

  it("出口节点漂移风险(Warn)将重置漂移基准作为默认蓝色主按钮，真不可用(Fail)仅引导换节点", () => {
    const baseState = useGuardStore.getState();
    useGuardStore.setState({
      licenseStatus: { commercialFeatureEnabled: true, licensed: true },
      selectedCheckId: "node_geo",
      preflight: {
        ...baseState.preflight,
        items: baseState.preflight.items.map((item) =>
          item.id === "node_geo"
            ? {
                ...item,
                status: "warn",
                summary: "AU · 常规机房 · 24h 落地 IP 漂移 1 次预警",
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

    // 切换为真不可用 Fail：严禁出现重置漂移按钮
    useGuardStore.setState({
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
    rerender(<ConsolePage />);
    expect(screen.queryByTestId("btn-reset-drift-baseline")).not.toBeInTheDocument();
    expect(screen.getByText("节点不可用，前往「节点流量」手动更换节点 →")).toBeInTheDocument();
  });
});
