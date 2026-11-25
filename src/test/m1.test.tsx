import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "@/App";
import { HudCard } from "@/components/HudCard";
import { DEFAULT_CONFIG, FALLBACK_SNAPSHOT } from "@/lib/ipc";
import { useGuardStore } from "@/stores/guardStore";

beforeEach(() => {
  useGuardStore.setState({
    config: { ...DEFAULT_CONFIG },
    snapshot: { ...FALLBACK_SNAPSHOT, triggeredPlaybookIds: [] },
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
  cleanup();
});

describe("FD Claude Guard M1 核心功能与设计红线验收", () => {
  it("渲染 5 大导航且必须项默认诚实锁定启动（绝不伪造绿灯）", async () => {
    render(<App />);

    for (const label of ["控制台", "节点流量", "日志分析", "环境维护", "守卫配置"]) {
      expect(screen.getByRole("button", { name: new RegExp(label) })).toBeInTheDocument();
    }

    await waitFor(() => {
      expect(screen.getByText(/一键处理全部 \(11\)/)).toBeInTheDocument();
    });
    expect(screen.queryByRole("button", { name: /安全启动 Claude/ })).not.toBeInTheDocument();
    // 回归 ISS-009：未通过且无自动修复按钮时绝不显示绿色通过文案，且必须保留 AI 排障包导出按钮
    expect(screen.queryByText(/该项已通过真实探针验收/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /导出脱敏问题包给 AI 分析/ })).toBeInTheDocument();
  });

  it("守卫配置支持全 Toggle 开关，关闭开机自启联动关闭开机仅显悬浮窗，开启 24h 保护同步点亮安全守则", async () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: /守卫配置/ }));
    expect(await screen.findByText(/所有自动防护策略默认开启/)).toBeInTheDocument();

    const bootSwitch = screen.getByRole("switch", { name: /开机自动启动/ });
    const hudOnlySwitch = screen.getByRole("switch", { name: /开机时仅显示桌面悬浮窗/ });
    const calm24hSwitch = screen.getByRole("switch", { name: /24h 冷静保护模式/ });

    expect(bootSwitch).toHaveAttribute("aria-checked", "true");
    expect(hudOnlySwitch).toHaveAttribute("aria-checked", "true");
    expect(calm24hSwitch).toHaveAttribute("aria-checked", "false");

    // 关闭开机自启 → 自动联动关闭并禁用开机仅显悬浮窗
    fireEvent.click(bootSwitch);
    await waitFor(() => {
      expect(bootSwitch).toHaveAttribute("aria-checked", "false");
      expect(hudOnlySwitch).toHaveAttribute("aria-checked", "false");
      expect(hudOnlySwitch).toBeDisabled();
    });

    // 开启 24h 冷静保护 → 同步命中安全守则 #1
    fireEvent.click(calm24hSwitch);
    await waitFor(() => {
      expect(calm24hSwitch).toHaveAttribute("aria-checked", "true");
      expect(useGuardStore.getState().snapshot.triggeredPlaybookIds).toContain("pb_24h");
    });
  });

  it("日志分析模拟高并发 429 异常后跳转安全守则抽屉，展开 8 大守则并触发高亮闪烁定位", async () => {
    render(<App />);

    fireEvent.click(screen.getByRole("button", { name: /日志分析/ }));
    fireEvent.click(screen.getByRole("button", { name: /\+ 模拟高并发 429 异常/ }));
    fireEvent.click(await screen.findByRole("button", { name: /查看联动安全守则/ }));

    expect(await screen.findByRole("dialog", { name: /Claude 账号安全守则/ })).toBeInTheDocument();
    expect(screen.getByText(/3\. 禁止无人值守全自动循环脚本与异常高并发刷量/)).toBeInTheDocument();

    await waitFor(
      () => {
        const card = document.getElementById("pb-card-pb_rate");
        expect(card).toHaveClass("flash-focus");
      },
      { timeout: 1000 }
    );
  });

  it("桌面悬浮状态卡 v2.2 默认展开与固定置顶，图钉纯图标无蓝底，折叠保留三维微卡片", async () => {
    const onGoConsole = vi.fn();
    render(
      <HudCard
        initialConfig={{ ...DEFAULT_CONFIG, hudPinned: true, hudFolded: false }}
        initialSnapshot={FALLBACK_SNAPSHOT}
        onGoConsole={onGoConsole}
      />
    );

    const pinBtn = screen.getByTestId("hud-btn-pin");
    expect(pinBtn).toHaveAttribute("aria-pressed", "true");
    expect(pinBtn.className).toContain("is-active");
    // 三维监测微卡片存在（日志 / 流量 / 进程）
    expect(screen.getByTestId("hud-tile-log")).toBeInTheDocument();
    expect(screen.getByTestId("hud-tile-flow")).toBeInTheDocument();
    expect(screen.getByTestId("hud-tile-proc")).toBeInTheDocument();

    // 默认展开，可见 hud-body 与底部跳回控制台按钮
    expect(screen.getByTestId("hud-body")).toBeInTheDocument();
    const gotoBtn = screen.getByTestId("hud-cta");
    fireEvent.click(gotoBtn);
    expect(onGoConsole).toHaveBeenCalledWith(true, "console", null);

    // 点击收折图标后折叠动态体，但三维微卡片常驻
    fireEvent.click(screen.getByTestId("hud-btn-fold"));
    await waitFor(() => {
      expect(screen.queryByTestId("hud-body")).not.toBeInTheDocument();
      expect(screen.getByTestId("hud-metrics")).toBeInTheDocument();
    });
  });
});
