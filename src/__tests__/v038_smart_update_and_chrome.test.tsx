import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { WindowChrome } from "@/components/WindowChrome";
import { ipc } from "@/lib/ipc";
import { SettingsPage } from "@/pages/SettingsPage";
import { useGuardStore } from "@/stores/guardStore";

describe("v0.3.8 顶栏极简更新微标、消除副标题双悬浮与取消静默更新 Toast 回归", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useGuardStore.setState({
      toasts: [],
      updateInfo: null,
      updateChecking: false,
      updateInstalling: false,
      updateError: null,
      activeTab: "console",
    });
  });

  it("Fuck Dario 副标题去掉原生 title 防双悬浮，仅保留自定义气泡弹窗；大/重要更新亮顶栏微标且常规小修补静默降噪", () => {
    // 1. 常规小修订版（0.3.7 -> 0.3.8 无重要标记）：顶栏静默不打扰
    useGuardStore.setState({
      updateInfo: {
        currentVersion: "0.3.7",
        available: true,
        latestVersion: "0.3.8",
        publishedAt: "2026-11-27",
        notes: "常规细节修补",
        viaProxy: true,
        message: "发现新版本 v0.3.8",
      },
    });
    const { unmount: unmountMinor } = render(<WindowChrome />);
    expect(screen.queryByTestId("topbar-new-version-badge")).not.toBeInTheDocument();
    unmountMinor();

    // 2. 次/主版本升级（0.3.7 -> 0.4.0）：顶栏点亮 ✨ 新版本发布！！
    useGuardStore.setState({
      updateInfo: {
        currentVersion: "0.3.7",
        available: true,
        latestVersion: "0.4.0",
        publishedAt: "2026-11-27",
        notes: "智能更新调度与 UI v3.0 升级",
        viaProxy: true,
        message: "发现新版本 v0.4.0",
      },
    });

    render(<WindowChrome />);

    const sub = screen.getByTestId("brand-subtitle");
    expect(sub).not.toHaveAttribute("title");
    fireEvent.mouseEnter(sub);
    expect(screen.getByTestId("brand-subtitle-tooltip")).toHaveTextContent(
      "Claude is awesome, but fuck Dario!"
    );
    fireEvent.mouseLeave(sub);
    expect(screen.queryByTestId("brand-subtitle-tooltip")).not.toBeInTheDocument();

    const badge = screen.getByTestId("topbar-new-version-badge");
    expect(badge).toHaveTextContent("✨ 新版本发布！！");
    expect(badge).not.toHaveAttribute("title");
    fireEvent.mouseEnter(badge);
    expect(screen.getByTestId("topbar-new-version-tooltip")).toHaveTextContent("v0.4.0");
    fireEvent.click(badge);
    expect(useGuardStore.getState().settingsModalOpen).toBe(true);
    expect(useGuardStore.getState().settingsModalTab).toBe("update");
  });

  it("静默检查发现新版本绝不再弹出 Toast，仅更新全局状态；进入守卫配置仅零网络读缓存不自动刷接口", async () => {
    const cachedSpy = vi.spyOn(ipc, "getCachedAppUpdate").mockResolvedValue(null);
    const checkSpy = vi.spyOn(ipc, "checkAppUpdate").mockResolvedValue({
      currentVersion: "0.3.7",
      available: true,
      latestVersion: "0.3.8",
      publishedAt: "2026-11-27",
      notes: "智能更新调度",
      viaProxy: true,
      message: "发现新版本 v0.3.8",
    });

    // 1. 静默检查发现新版 -> force=false 且 0 个 Toast 弹窗
    await act(async () => {
      await useGuardStore.getState().checkForAppUpdate(true);
    });
    expect(checkSpy).toHaveBeenCalledWith(false);
    expect(useGuardStore.getState().updateInfo?.available).toBe(true);
    expect(useGuardStore.getState().toasts.length).toBe(0);

    // 2. 重置状态打开 SettingsPage -> 仅调用 getCachedAppUpdate，不重复触发网络 checkAppUpdate
    checkSpy.mockClear();
    useGuardStore.setState({ updateInfo: null });
    render(<SettingsPage />);
    expect(cachedSpy).toHaveBeenCalledTimes(1);
    expect(checkSpy).not.toHaveBeenCalled();

    // 3. 手动点击检查更新 -> force=true 强制穿透刷新
    await act(async () => {
      await useGuardStore.getState().checkForAppUpdate(false);
    });
    expect(checkSpy).toHaveBeenCalledWith(true);
  });
});
