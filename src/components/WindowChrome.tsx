import { useState } from "react";
import { Bell, BellOff, Headphones, Minus, Moon, Square, Sun, X } from "lucide-react";
import { ipc } from "@/lib/ipc";
import { APP_BRAND_SUBTITLE } from "@/lib/protocol";
import { useGuardStore } from "@/stores/guardStore";

const BRAND_SUBTITLE_TOOLTIP = "Claude is awesome, but fuck Dario!";

/**
 * 大/小版本顶栏提醒分级降噪（M5-03）：
 * 仅主/次版本号递增（如 0.3.x -> 0.4.0）或更新日志含重要/安全/紧急标记时才在顶栏点亮微标；
 * 常规小修订版（如 0.3.7 -> 0.3.8）静默留在「系统设置 → 版本更新」供用户按需自查，零打扰。
 */
function shouldHighlightTopbarUpdate(
  currentVersion: string,
  latestVersion: string,
  notes?: string | null
): boolean {
  const parse = (v: string) =>
    v
      .replace(/^v/i, "")
      .split(".")
      .map((n) => parseInt(n, 10) || 0);
  const cur = parse(currentVersion);
  const lat = parse(latestVersion);
  if ((lat[0] ?? 0) > (cur[0] ?? 0)) return true;
  if ((lat[0] ?? 0) === (cur[0] ?? 0) && (lat[1] ?? 0) > (cur[1] ?? 0)) return true;
  if (notes && /(\[重要\]|\[安全\]|\[紧急\]|\[major\]|critical|security)/i.test(notes)) {
    return true;
  }
  return false;
}

export function WindowChrome() {
  const [subtitleHover, setSubtitleHover] = useState(false);
  const [updateHover, setUpdateHover] = useState(false);
  const theme = useGuardStore((s) => s.config.theme);
  const showHud = useGuardStore((s) => s.config.showHud);
  const notifyEnabled = useGuardStore((s) => s.config.notifyEnabled);
  const updateConfig = useGuardStore((s) => s.updateConfig);
  const setSupportModalOpen = useGuardStore((s) => s.setSupportModalOpen);
  const updateInfo = useGuardStore((s) => s.updateInfo);
  const openSettingsModal = useGuardStore((s) => s.openSettingsModal);

  const handleToggleHud = () => {
    void updateConfig({ showHud: !showHud }, "桌面悬浮状态窗");
  };

  const handleToggleNotify = () => {
    void updateConfig({ notifyEnabled: !notifyEnabled }, "桌面预警消息提醒");
  };

  const handleToggleTheme = () => {
    void updateConfig({ theme: theme === "dark" ? "light" : "dark" });
  };

  const handleDragStart = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    if ((e.target as HTMLElement).closest("button")) return;
    void ipc.startDraggingCurrentWindow();
  };

  return (
    <header
      data-testid="window-chrome"
      onMouseDown={handleDragStart}
      onDoubleClick={(e) => {
        if ((e.target as HTMLElement).closest("button")) return;
        void ipc.toggleMaximizeCurrentWindow();
      }}
      style={{
        height: 38,
        flexShrink: 0,
        background: "var(--bg-chrome)",
        borderBottom: "1px solid var(--divider)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        paddingLeft: 16,
      }}
    >
      {/* 品牌区：17px 应用图标 + 12.5px 主标题 + 11px 固定副标题 Fuck Dario！！！ */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          minWidth: 0,
        }}
      >
        <img
          src="/app-icon.png"
          alt="FD Claude Guard"
          data-testid="brand-app-icon"
          width={17}
          height={17}
          style={{ width: 17, height: 17, borderRadius: 4, flexShrink: 0, display: "block" }}
        />
        <span
          style={{
            fontSize: 12.5,
            fontWeight: 400,
            letterSpacing: "-0.005em",
            color: "var(--text-1)",
            whiteSpace: "nowrap",
          }}
        >
          FD Claude 安全启动器
        </span>
        <span
          data-testid="brand-subtitle"
          onMouseEnter={() => setSubtitleHover(true)}
          onMouseLeave={() => setSubtitleHover(false)}
          style={{
            position: "relative",
            color: "var(--text-3)",
            fontWeight: 400,
            fontSize: 11,
            cursor: "help",
            padding: "2px 4px",
            borderRadius: 4,
            whiteSpace: "nowrap",
          }}
        >
          {APP_BRAND_SUBTITLE}
          {subtitleHover && (
            <span
              role="tooltip"
              data-testid="brand-subtitle-tooltip"
              style={{
                position: "absolute",
                top: "calc(100% + 6px)",
                left: 0,
                whiteSpace: "nowrap",
                padding: "5px 10px",
                borderRadius: 7,
                background: "var(--tooltip-bg)",
                border: "1px solid rgba(255, 255, 255, 0.08)",
                color: "var(--tooltip-fg)",
                fontSize: 11,
                fontWeight: 400,
                boxShadow: "0 10px 26px rgba(0, 0, 0, 0.32)",
                pointerEvents: "none",
                zIndex: 300,
              }}
            >
              {BRAND_SUBTITLE_TOOLTIP}
            </span>
          )}
        </span>
        {updateInfo?.available &&
          updateInfo.latestVersion &&
          shouldHighlightTopbarUpdate(
            updateInfo.currentVersion,
            updateInfo.latestVersion,
            updateInfo.notes
          ) && (
          <button
            type="button"
            data-testid="topbar-new-version-badge"
            onClick={() => openSettingsModal("update")}
            onMouseEnter={() => setUpdateHover(true)}
            onMouseLeave={() => setUpdateHover(false)}
            style={{
              position: "relative",
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              height: 22,
              padding: "0 9px",
              marginLeft: 2,
              borderRadius: 999,
              border: "1px solid var(--primary-border)",
              background: "var(--primary-soft)",
              color: "var(--primary)",
              fontSize: 11,
              fontWeight: 500,
              cursor: "pointer",
              lineHeight: 1,
              whiteSpace: "nowrap",
            }}
          >
            <span>✨ 新版本发布！！</span>
            {updateHover && (
              <span
                role="tooltip"
                data-testid="topbar-new-version-tooltip"
                style={{
                  position: "absolute",
                  top: "calc(100% + 7px)",
                  left: 0,
                  whiteSpace: "nowrap",
                  padding: "6px 10px",
                  borderRadius: 7,
                  background: "var(--tooltip-bg)",
                  border: "1px solid var(--divider-strong)",
                  color: "var(--tooltip-fg)",
                  fontSize: 11,
                  fontWeight: 400,
                  boxShadow: "0 10px 26px rgba(0, 0, 0, 0.32)",
                  pointerEvents: "none",
                  zIndex: 300,
                }}
              >
                发现新版本 v{updateInfo.latestVersion} · 点击前往「版本更新」一键更新
              </span>
            )}
          </button>
        )}
      </div>

      {/* 右侧：28×25 纯图标快捷开关组 + 1×13px 细竖线 + 38px 系统窗控三键 */}
      <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
        <div
          data-testid="topbar-quick-toggles"
          style={{ display: "flex", alignItems: "center", gap: 6, paddingRight: 10 }}
        >
          {/* 0. 联系作者入口（保留原版耳机客服符号，点击打开全新 X / Twitter 联系作者弹窗） */}
          <button
            type="button"
            data-testid="topbar-btn-support"
            aria-label="联系作者 · X (Twitter)"
            title="联系作者 · X (Twitter)"
            onClick={() => setSupportModalOpen(true)}
            className="chrome-btn"
            style={quickIcoBtnStyle(true)}
          >
            <Headphones size={14} strokeWidth={1.45} />
          </button>

          {/* 1. 桌面悬浮窗开关 */}
          <button
            type="button"
            data-testid="topbar-toggle-hud"
            aria-label={showHud ? "隐藏桌面悬浮窗" : "显示桌面悬浮窗"}
            aria-pressed={showHud}
            title={showHud ? "桌面悬浮窗已开启（点击隐藏）" : "桌面悬浮窗已隐藏（点击开启）"}
            onClick={handleToggleHud}
            className="chrome-btn"
            style={quickIcoBtnStyle(showHud)}
          >
            <svg
              viewBox="0 0 24 24"
              width={14}
              height={14}
              fill="none"
              stroke="currentColor"
              strokeWidth={1.45}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <rect x="3" y="4.5" width="18" height="15" rx="2.8" />
              {showHud ? (
                <rect x="11.5" y="7.8" width="6.5" height="5" rx="1.2" fill="currentColor" stroke="none" />
              ) : (
                <rect x="12" y="8" width="6" height="4.5" rx="1" />
              )}
            </svg>
          </button>

          {/* 2. 消息提醒开关 */}
          <button
            type="button"
            data-testid="topbar-toggle-notify"
            aria-label={notifyEnabled ? "静音普通预警通知" : "开启桌面预警消息提醒"}
            aria-pressed={notifyEnabled}
            title={
              notifyEnabled
                ? "桌面预警消息提醒已开启（点击静音普通预警）"
                : "普通预警通知已静音（熔断与防裸奔危急警报仍保持强提醒）"
            }
            onClick={handleToggleNotify}
            className="chrome-btn"
            style={quickIcoBtnStyle(notifyEnabled)}
          >
            {notifyEnabled ? (
              <Bell size={14} strokeWidth={1.45} />
            ) : (
              <BellOff size={14} strokeWidth={1.45} />
            )}
          </button>

          {/* 3. 深浅主题切换 */}
          <button
            type="button"
            data-testid="topbar-toggle-theme"
            aria-label="切换深浅主题"
            title={theme === "dark" ? "切换至浅色模式" : "切换至深色模式"}
            onClick={handleToggleTheme}
            className="chrome-btn"
            style={quickIcoBtnStyle(false)}
          >
            {theme === "dark" ? (
              <Sun size={13.5} strokeWidth={1.45} />
            ) : (
              <Moon size={13.5} strokeWidth={1.45} />
            )}
          </button>
        </div>

        {/* 1px × 13px 细竖分割线 */}
        <span
          aria-hidden="true"
          style={{
            width: 1,
            height: 13,
            background: "var(--divider-strong)",
            marginRight: 4,
          }}
        />

        {/* Windows 原生风格右上角三键（38px 满高） */}
        <button
          type="button"
          title="最小化"
          aria-label="最小化"
          onClick={() => void ipc.minimizeCurrentWindow()}
          className="chrome-btn"
          style={winBtnStyle}
        >
          <Minus size={12.5} strokeWidth={1.5} />
        </button>
        <button
          type="button"
          title="最大化 / 还原"
          aria-label="最大化"
          onClick={() => void ipc.toggleMaximizeCurrentWindow()}
          className="chrome-btn"
          style={winBtnStyle}
        >
          <Square size={10.5} strokeWidth={1.55} />
        </button>
        <button
          type="button"
          title="隐藏到托盘（后台继续守卫）"
          aria-label="隐藏到托盘"
          onClick={() => void ipc.hideMainWindow()}
          className="chrome-btn chrome-close"
          style={winBtnStyle}
        >
          <X size={12.5} strokeWidth={1.5} />
        </button>
      </div>
    </header>
  );
}

function quickIcoBtnStyle(isOn: boolean): React.CSSProperties {
  return {
    position: "relative",
    width: 28,
    height: 25,
    borderRadius: 6,
    color: isOn ? "var(--text-1)" : "var(--text-3)",
    opacity: isOn ? 0.94 : 0.78,
  };
}

const winBtnStyle: React.CSSProperties = {
  width: 38,
  height: "100%",
};
