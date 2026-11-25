import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { SettingsPage } from "@/pages/SettingsPage";
import { useGuardStore } from "@/stores/guardStore";

describe("v0.2.9 真机回归：开机启动项徽章语义校验（T-054）", () => {
  beforeEach(() => {
    useGuardStore.setState({
      startupAudit: {
        claudeAutostartRisk: true,
        entries: [
          {
            app: "FD Claude Guard",
            enabled: true,
            riskLevel: "ok",
            detail: "已开启开机自启",
          },
          {
            app: "Clash Verge Rev",
            enabled: false,
            riskLevel: "warn",
            detail: "未检测到 Clash Verge 开机自启，开机后请先启动代理再打开 Claude",
          },
          {
            app: "Claude Desktop",
            enabled: true,
            riskLevel: "warn",
            detail: "检测到 Claude 已设开机自启，存在抢跑裸奔风险",
          },
        ],
      },
    });
  });

  it("Clash Verge 未开启自启且风险为 warn 时应显示「未开启（建议开启）」，Claude 已开启且 warn 时显示「已开启（有风险）」", () => {
    render(<SettingsPage />);

    expect(screen.getByTestId("startup-chip-FD Claude Guard").textContent).toBe("已开启自启");
    expect(screen.getByTestId("startup-chip-Clash Verge Rev").textContent).toBe("未开启（建议开启）");
    expect(screen.getByTestId("startup-chip-Claude Desktop").textContent).toBe("已开启（有风险）");
  });
});
