import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ipc, buildMockAccountAuditReport } from "@/lib/ipc";
import { AccountAuditPage } from "@/pages/AccountAuditPage";
import { useGuardStore } from "@/stores/guardStore";
import type { AccountAuditReport } from "@/types/guard";

describe("v0.3.6 账户审计多历史切换删除、观察窗/KYC联动与未读日志摘要回归", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useGuardStore.setState({
      accountAudit: null,
      accountAuditLoading: false,
      accountAuditError: null,
      auditSubTab: "audit",
      riskModal: null,
      snapshot: {
        ...useGuardStore.getState().snapshot,
        unreadLogAnomalies: 0,
        unreadLogCritical: 0,
        unreadLogWarnings: 0,
      },
    });
  });

  it("未读到注册/订阅/KYC 时间时显示「待核观察」，绝不假绿「已过观察」；且 2 未读不写日志平稳", async () => {
    const base = buildMockAccountAuditReport("default");
    const unverifiedNew: AccountAuditReport = {
      ...base,
      emailMasked: "桌面端账号 (本地不含邮箱 · org 0ffb0302)",
      orgIdPrefix8: "0ffb0302",
      plan: "未知",
      accountAgeDays: null,
      subscriptionAgeDays: null,
      cloudVerified: false,
      cloudSnapshot: null,
      local: {
        ...base.local,
        desktop: {
          ...base.local.desktop,
          cookie403Hits: 0,
          cfShield403Hits: 0,
        },
      },
      logFlowItems: [],
      denoisedOauth403Count: 0,
    };

    useGuardStore.setState({
      accountAudit: unverifiedNew,
      snapshot: {
        ...useGuardStore.getState().snapshot,
        unreadLogAnomalies: 2,
        unreadLogWarnings: 2,
      },
    });

    render(<AccountAuditPage />);

    const winRow = screen.getByTestId("audit-group-g-window");
    expect(winRow.textContent).toContain("待核观察");
    expect(winRow.textContent).not.toContain("已过观察");

    const pulseCard = screen.getByTestId("audit-pulse-card");
    expect(pulseCard.textContent).toContain("2 未读");
    expect(pulseCard.textContent).toContain("捕获 2 条待核异常事件");
    expect(pulseCard.textContent).not.toContain("近 24 小时日志平稳");
  });

  it("云端查出 personaKycStatus=expired 且 Free 套餐时，第 1 项立即联动更新实名已过期与 Free 无订阅", async () => {
    const base = buildMockAccountAuditReport("default");
    const kycExpiredReport: AccountAuditReport = {
      ...base,
      emailMasked: "star***at@outlook.com",
      orgIdPrefix8: "0ffb0302",
      plan: "Free",
      merchantChannel: "Free 无订阅",
      accountAgeDays: 86,
      subscriptionAgeDays: null,
      cloudVerified: true,
      cloudSnapshot: {
        verifiedAtMs: Date.now(),
        checkedAtIso: new Date().toISOString(),
        emailMasked: "star***at@outlook.com",
        orgIdPrefix8: "0ffb0302",
        plan: "Free",
        merchantChannel: "Free 无订阅",
        workspaceGeo: "US",
        edgeCountry: "US",
        edgeColo: "SJC",
        accountAgeDays: 86,
        subscriptionAgeDays: null,
        subscriptionEndsAt: null,
        chatAvailable: true,
        isBanned: false,
        appealsRedirectEnabled: false,
        hasMonitoringNotice: true,
        activeFlagTypes: ["access_block", "api_disabled:kyc_pending"],
        warningSummaryZh: "访问封锁 · API 受限(kyc_pending)",
        personaKycStatus: "expired",
        personaKycCompletedAt: null,
        personaKycAgeHours: null,
        portalHold: false,
        portalState: "unknown",
        fiveHourPct: null,
        fiveHourResetsAt: null,
        sevenDayPct: null,
        sevenDayResetsAt: null,
        warnings: [],
      },
    };

    useGuardStore.setState({ accountAudit: kycExpiredReport });
    render(<AccountAuditPage />);

    const winGroup = screen.getByTestId("audit-group-g-window");
    expect(winGroup.textContent).toContain("实名已过期");
    expect(winGroup.textContent).not.toContain("已过观察");

    // 展开第 1 项（高敏感观察窗），验证 KYC 过期子格文案联动更新
    const toggleBtn = winGroup.querySelector(".audit-row") as HTMLElement;
    fireEvent.click(toggleBtn);
    expect(winGroup.textContent).toContain("实名验证已过期（待重新完成 KYC · 未通过前属高敏态）");
    expect(winGroup.textContent).not.toContain("当前无实名复核观察记录");

    // F-05：展开独立拆分后的「支付方式与账单风控」，验证 Free 无订阅联动更新
    const payGroup = screen.getByTestId("audit-group-g-payment");
    expect(payGroup.textContent).toContain("支付方式与账单风控");
    expect(payGroup.textContent).toContain("免检正常");
    fireEvent.click(payGroup.querySelector(".audit-row") as HTMLElement);
    expect(payGroup.textContent).toContain("Free 无订阅（不适用支付复审）");

    // F-07（Q3）：验证「二、工具可介入防御与修复」5 项按新优先级顺序排列
    const allGroupIds = Array.from(document.querySelectorAll("[data-testid^='audit-group-']")).map(
      (el) => el.getAttribute("data-testid")
    );
    expect(allGroupIds).toEqual([
      "audit-group-g-window",
      "audit-group-g-payment",
      "audit-group-g-auto",
      "audit-group-g-cloud",
      "audit-group-g-disconnect",
      "audit-group-g-mix",
      "audit-group-g-endpoint",
      "audit-group-g-telemetry",
    ]);
  });

  it("支持多历史账号点击切换查看历史评分与状态，以及用户手动确认删除", async () => {
    const base = buildMockAccountAuditReport("default");
    const histOld: AccountAuditReport = {
      ...base,
      profileId: "history:a4722ea6",
      emailMasked: "jaso***11@gmail.com",
      orgIdPrefix8: "a4722ea6",
      plan: "Free",
      accountAgeDays: 85,
      subscriptionAgeDays: null,
      workspaceGeo: "US",
      cloudVerified: true,
      verifyCount: 2,
      scoreResult: {
        ...base.scoreResult,
        score: 96,
        level: "safe",
        levelLabel: "低危稳健",
        colorToken: "green",
      },
      archivedAccounts: [],
    };

    const getHistSpy = vi
      .spyOn(ipc, "getAccountAuditHistoryReport")
      .mockResolvedValue(histOld);
    const delHistSpy = vi
      .spyOn(ipc, "deleteAccountAuditHistory")
      .mockResolvedValue([]);

    useGuardStore.setState({
      accountAudit: {
        ...base,
        emailMasked: "star***at@outlook.com",
        orgIdPrefix8: "0ffb0302",
        archivedAccounts: [
          {
            orgPrefix8: "a4722ea6",
            emailMasked: "jaso***11@gmail.com",
            plan: "Free",
            workspaceGeo: "US",
            exitCountry: "US",
            score: 96,
            scoreLevel: "safe",
            scoreLevelLabel: "低危稳健",
            scoreColorToken: "green",
            cloudVerified: true,
            verifyCount: 2,
            hasDangerIssue: false,
            pendingIssueCount: 0,
            personaKycStatus: "verified",
            hasMonitoringNotice: false,
            isBanned: false,
            portalHold: false,
            fiveHourPct: 12,
            sevenDayPct: 28,
            auditedAtMs: Date.now() - 3600_000,
            hasFullReport: true,
          },
        ],
      },
    });

    render(<AccountAuditPage />);

    // 左栏显示历史归档卡片，点击后右侧切换为老号历史评分快照
    const histCard = screen.getByTestId("audit-history-card-a4722ea6");
    expect(histCard.textContent).toContain("jaso***11@gmail.com");
    fireEvent.click(histCard);

    await waitFor(() => {
      expect(getHistSpy).toHaveBeenCalledWith("a4722ea6");
      expect(screen.getByTestId("audit-history-banner")).toBeTruthy();
    });
    expect(screen.getByTestId("audit-detail-view").textContent).toContain("jaso***11@gmail.com");
    expect(screen.getByTestId("btn-score-pill").textContent).toContain("96 分");

    // 点击删除按钮应唤起确认弹窗，确认后移除历史记录并切回本机当前账号
    fireEvent.click(screen.getByTestId("btn-delete-history-a4722ea6"));
    const modal = useGuardStore.getState().riskModal;
    expect(modal).not.toBeNull();
    expect(modal?.title).toContain("jaso***11@gmail.com");

    await act(async () => {
      await modal?.onPrimary();
    });

    expect(delHistSpy).toHaveBeenCalledWith("a4722ea6");
    await waitFor(() => {
      expect(screen.queryByTestId("audit-history-card-a4722ea6")).toBeNull();
      expect(screen.queryByTestId("audit-history-banner")).toBeNull();
    });
  });
});
