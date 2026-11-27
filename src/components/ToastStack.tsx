import { X } from "lucide-react";
import { useGuardStore } from "@/stores/guardStore";

/**
 * 全局轻提示队列（v3.0 双主题轻投影 + 柔和语义边框 + 进场微动效）
 */
export function ToastStack() {
  const toasts = useGuardStore((s) => s.toasts);
  const dismiss = useGuardStore((s) => s.dismissToast);

  if (toasts.length === 0) return null;

  return (
    <div
      style={{
        position: "fixed",
        right: 18,
        bottom: 18,
        zIndex: 160,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        pointerEvents: "none",
      }}
    >
      {toasts.map((t) => (
        <div
          key={t.id}
          className="toast-item-enter"
          onClick={() => dismiss(t.id)}
          style={{
            width: 356,
            pointerEvents: "auto",
            cursor: "pointer",
            background: "var(--bg-card)",
            border: `1px solid ${t.type === "danger" ? "var(--bad-border)" : "var(--border-card)"}`,
            borderRadius: "var(--r-card)",
            padding: "11px 13px",
            boxShadow: "var(--shadow-toast)",
            display: "flex",
            alignItems: "flex-start",
            gap: 10,
          }}
        >
          <span
            className={`guard-dot ${t.type === "danger" ? "danger" : t.type === "ok" ? "" : "warn"}`}
            style={{ marginTop: 5 }}
          />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
              <div style={{ fontSize: 12.5, fontWeight: 500, color: "var(--text-strong)", lineHeight: 1.35 }}>
                {t.title}
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
                {t.badge && (
                  <span
                    className={`guard-chip ${t.type === "danger" ? "guard-chip-fail" : "guard-chip-warn"}`}
                    style={{ height: 18, fontSize: 10, padding: "0 6px" }}
                  >
                    {t.badge}
                  </span>
                )}
                <X size={13} strokeWidth={1.5} style={{ color: "var(--text-4)" }} />
              </div>
            </div>
            <div style={{ fontSize: 11.5, color: "var(--text-2)", marginTop: 3, lineHeight: 1.5 }}>
              {t.body}
            </div>
            {t.action && (
              <div style={{ marginTop: 8 }}>
                <button
                  type="button"
                  className={`guard-btn ${
                    t.action.tone === "danger" ? "guard-btn-danger-soft" : "guard-btn-flat"
                  } guard-btn-xs`}
                  onClick={(e) => {
                    e.stopPropagation();
                    t.action?.onClick();
                    dismiss(t.id);
                  }}
                >
                  {t.action.label}
                </button>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
