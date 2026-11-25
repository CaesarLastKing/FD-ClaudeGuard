import { Bell, BellOff, Headphones, Minus, Moon, Square, Sun, X } from "lucide-react";
import { ipc } from "@/lib/ipc";
import { APP_BRAND_SUBTITLE } from "@/lib/protocol";
import { useGuardStore } from "@/stores/guardStore";

export function WindowChrome() {
  const theme = useGuardStore((s) => s.config.theme);
  const showHud = useGuardStore((s) => s.config.showHud);
  const notifyEnabled = useGuardStore((s) => s.config.notifyEnabled);
  const updateConfig = useGuardStore((s) => s.updateConfig);
  const setSupportModalOpen = useGuardStore((s) => s.setSupportModalOpen);

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
        background: "var(--bg-sidebar)",
        borderBottom: "1px solid var(--border)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        paddingLeft: 16,
      }}
    >
      {/* 品牌区：校准版品牌盾牌 SVG + 主标题 + 固定副标题 Fuck Dario！！！ */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          fontSize: 13,
          fontWeight: 600,
          color: "var(--text-1)",
        }}
      >
        <img
          src="/app-icon.png"
          alt="FD Claude Guard"
          data-testid="brand-app-icon"
          width={18}
          height={18}
          style={{ width: 18, height: 18, borderRadius: 4, flexShrink: 0, display: "block" }}
        />
        <span>FD Claude 安全启动器</span>
        <span
          data-testid="brand-subtitle"
          style={{ color: "var(--text-3)", fontWeight: 400, fontSize: 11.5 }}
        >
          {APP_BRAND_SUBTITLE}
        </span>
      </div>

      {/* 右侧：纯图标快捷开关组 (32x28, gap:6, stroke-width:1.7) + 1x14px 对称竖线 + Windows 三键 */}
      <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
        <div
          data-testid="topbar-quick-toggles"
          style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 10px 0 4px" }}
        >
          {/* 0. 同风格纯图标开源支持入口（耳机图标，弹窗展示交流 QQ） */}
          <button
            type="button"
            data-testid="topbar-btn-support"
            aria-label="开源交流与技术支持"
            title="开源交流与技术支持（QQ: 2568515327）"
            onClick={() => setSupportModalOpen(true)}
            className="win-ico-btn is-on"
            style={quickIcoBtnStyle(true)}
          >
            <Headphones size={15} strokeWidth={1.7} />
          </button>

          {/* 1. 桌面悬浮窗开关：干净双层浮窗（开启态内窗实心高亮，隐藏态空心描边，不加压线圆点） */}
          <button
            type="button"
            data-testid="topbar-toggle-hud"
            aria-label={showHud ? "隐藏桌面悬浮窗" : "显示桌面悬浮窗"}
            aria-pressed={showHud}
            title={showHud ? "桌面悬浮窗已开启（点击隐藏）" : "桌面悬浮窗已隐藏（点击开启）"}
            onClick={handleToggleHud}
            className={`win-ico-btn ${showHud ? "is-on" : ""}`}
            style={quickIcoBtnStyle(showHud)}
          >
            <svg
              viewBox="0 0 24 24"
              width={15}
              height={15}
              fill="none"
              stroke="currentColor"
              strokeWidth={1.7}
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <rect x="3" y="4" width="18" height="16" rx="3" />
              {showHud ? (
                <rect x="11" y="7.5" width="7" height="5.5" rx="1.4" fill="currentColor" stroke="none" />
              ) : (
                <rect x="11.5" y="8" width="6" height="4.5" rx="1" />
              )}
            </svg>
          </button>

          {/* 2. 消息提醒开关：标准 Lucide Bell / BellOff */}
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
            className={`win-ico-btn ${notifyEnabled ? "is-on" : ""}`}
            style={quickIcoBtnStyle(notifyEnabled)}
          >
            {notifyEnabled ? <Bell size={15} strokeWidth={1.7} /> : <BellOff size={15} strokeWidth={1.7} />}
          </button>

          {/* 主题切换（轻量纯图标） */}
          <button
            type="button"
            aria-label="切换深浅主题"
            title={theme === "dark" ? "切换至浅色模式" : "切换至深色模式"}
            onClick={handleToggleTheme}
            className="win-ico-btn"
            style={quickIcoBtnStyle(false)}
          >
            {theme === "dark" ? <Sun size={14.5} strokeWidth={1.7} /> : <Moon size={14.5} strokeWidth={1.7} />}
          </button>
        </div>

        {/* 1px × 14px 对称细竖线 */}
        <span
          aria-hidden="true"
          style={{
            width: 1,
            height: 14,
            background: "var(--border-strong)",
            margin: "0 6px 0 0",
            opacity: 0.65,
          }}
        />

        {/* Windows 11 原生风格右上角三键 */}
        <button
          type="button"
          title="最小化"
          aria-label="最小化"
          onClick={() => void ipc.minimizeCurrentWindow()}
          className="wc-icon-btn"
          style={winBtnStyle}
        >
          <Minus size={14} strokeWidth={1.85} />
        </button>
        <button
          type="button"
          title="最大化 / 还原"
          aria-label="最大化"
          onClick={() => void ipc.toggleMaximizeCurrentWindow()}
          className="wc-icon-btn"
          style={winBtnStyle}
        >
          <Square size={11.5} strokeWidth={1.9} />
        </button>
        <button
          type="button"
          title="隐藏到托盘（后台继续守卫）"
          aria-label="隐藏到托盘"
          onClick={() => void ipc.hideMainWindow()}
          className="wc-close-btn"
          style={winBtnStyle}
        >
          <X size={14} strokeWidth={1.85} />
        </button>
      </div>
      <style>{`
        .win-ico-btn:hover { background: var(--bg-subtle) !important; color: var(--text-1) !important; opacity: 1 !important; }
        .wc-icon-btn:hover { background: var(--bg-subtle) !important; color: var(--text-1) !important; }
        .wc-close-btn:hover { background: #dc2626 !important; color: #ffffff !important; }
      `}</style>
    </header>
  );
}

function quickIcoBtnStyle(isOn: boolean): React.CSSProperties {
  return {
    position: "relative",
    width: 32,
    height: 28,
    borderRadius: 7,
    border: "none",
    background: "transparent",
    color: isOn ? "var(--text-1)" : "var(--text-3)",
    opacity: isOn ? 0.92 : 0.65,
    cursor: "pointer",
    display: "grid",
    placeItems: "center",
    transition: "background-color 0.14s, color 0.14s, opacity 0.14s",
  };
}

const winBtnStyle: React.CSSProperties = {
  width: 44,
  height: "100%",
  border: "none",
  background: "transparent",
  color: "var(--text-2)",
  cursor: "pointer",
  display: "grid",
  placeItems: "center",
  transition: "background-color 0.12s, color 0.12s",
};
