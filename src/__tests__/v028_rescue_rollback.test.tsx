import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_CONFIG, FALLBACK_SNAPSHOT, ipc } from "@/lib/ipc";
import { MaintenancePage } from "@/pages/MaintenancePage";
import { useGuardStore } from "@/stores/guardStore";
import type { NetworkRescueReport, RollbackOverview } from "@/types/guard";

function makeOverview(touched = 2, loopback = ["以太网 (#6)"]): RollbackOverview {
  return {
    baselineExists: true,
    baselinePath: "~/.fd-claude-guard/system-baseline.json",
    isElevated: true,
    loopbackDnsAdapters: loopback,
    activeFirewallRules: false,
    touchedCount: touched,
    items: [
      {
        id: "clash_rules",
        title: "Clash 策略组与覆写脚本（Claude-Fixed）",
        category: "Clash 配置",
        touchedByGuard: touched >= 1,
        canRollback: touched >= 1,
        originalSummary: "原无 Claude-Fixed 策略组与全局 Script.js",
        currentSummary: touched >= 1 ? "存在 Claude-Fixed" : "无残留",
        riskNote: "精准去痕，100% 保留后续新增订阅。",
      },
      {
        id: "sys_ipv6",
        title: "物理网卡 IPv6 绑定与系统优先策略",
        category: "Windows 网络",
        touchedByGuard: touched >= 2,
        canRollback: touched >= 2,
        originalSummary: "DisabledComponents 原值=8",
        currentSummary: touched >= 2 ? "已禁用" : "原状",
        riskNote: "可随时恢复精确原值。",
      },
    ],
  };
}

describe("v0.2.8 无门槛网络急救与 6 项精准撤回中心回归", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useGuardStore.setState({
      config: { ...DEFAULT_CONFIG },
      snapshot: { ...FALLBACK_SNAPSHOT },
      riskModal: null,
      toasts: [],
    });
  });

  it("免费开源态下环境维护页直接开放「一键网络急救」与「撤回中心」，点击急救可检出并恢复死 DNS", async () => {
    vi.spyOn(ipc, "listBackups").mockResolvedValue([]);
    vi.spyOn(ipc, "inspectClaudeDataRoots").mockResolvedValue({
      classicDetected: true,
      msixPackages: [],
      telemetryExists: false,
    });
    const inspectSpy = vi
      .spyOn(ipc, "inspectRollbackStatus")
      .mockResolvedValueOnce(makeOverview(2, ["以太网 (#6)"]))
      .mockResolvedValueOnce(makeOverview(2, []));

    const rescuePayload: NetworkRescueReport = {
      ok: true,
      isElevated: true,
      directConnectivityOk: true,
      steps: [
        { step: "恢复物理网卡 DNS", ok: true, detail: "已将 以太网(#6) 恢复为 DHCP" },
        { step: "刷新 DNS 并实测国内直连", ok: true, detail: "国内直连畅通" },
      ],
      summary: "网络急救完成！国内直连实测畅通。",
    };
    const rescueSpy = vi
      .spyOn(ipc, "runNetworkEmergencyRescue")
      .mockResolvedValue(rescuePayload);
    vi.spyOn(useGuardStore.getState(), "refreshPreflight").mockResolvedValue();

    render(<MaintenancePage />);

    // 开源无锁态不存在付费墙门禁
    expect(screen.queryByTestId("locked-gate-maintain")).toBeNull();
    // 同时网络急救与撤回中心必须可见
    expect(screen.getByTestId("network-rescue-rollback-panel")).toBeTruthy();

    await waitFor(() => {
      expect(screen.getByText(/检测到死 DNS：以太网/)).toBeTruthy();
    });

    fireEvent.click(screen.getByTestId("btn-network-emergency-rescue"));

    await waitFor(() => {
      expect(rescueSpy).toHaveBeenCalledTimes(1);
      expect(screen.getByTestId("network-rescue-result")).toBeTruthy();
      expect(screen.getByText(/国内直连实测畅通/)).toBeTruthy();
    });
    expect(inspectSpy).toHaveBeenCalledTimes(2);
  });

  it("点击单项撤回打开二次确认弹窗，确认后精准调用 rollbackSingleItem 并更新状态", async () => {
    vi.spyOn(ipc, "listBackups").mockResolvedValue([]);
    vi.spyOn(ipc, "inspectClaudeDataRoots").mockResolvedValue({
      classicDetected: true,
      msixPackages: [],
      telemetryExists: false,
    });
    vi.spyOn(ipc, "inspectRollbackStatus").mockResolvedValue(makeOverview(2, []));
    const rollbackSpy = vi.spyOn(ipc, "rollbackSingleItem").mockResolvedValue({
      itemId: "clash_rules",
      ok: true,
      message: "已精准移除 Claude-Fixed 策略组与脚本并热重载。",
      overview: makeOverview(1, []),
    });
    vi.spyOn(useGuardStore.getState(), "refreshPreflight").mockResolvedValue();

    render(<MaintenancePage />);

    const btn = await screen.findByTestId("btn-rollback-clash_rules");
    fireEvent.click(btn);

    const modal = useGuardStore.getState().riskModal;
    expect(modal).not.toBeNull();
    expect(modal?.title).toContain("Clash 策略组与覆写脚本");

    await act(async () => {
      await modal?.onDanger?.();
    });

    await waitFor(() => {
      expect(rollbackSpy).toHaveBeenCalledWith("clash_rules");
      expect(screen.getByText("已记录改动 1 项")).toBeTruthy();
    });
  });
});
