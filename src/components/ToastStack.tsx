import { useGuardStore } from "@/stores/guardStore";

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
          onClick={() => dismiss(t.id)}
          style={{
            width: 356,
            pointerEvents: "auto",
            cursor: "pointer",
            background: "var(--bg-card)",
            border: `1px solid ${t.type === "danger" ? "var(--danger)" : "var(--border-strong)"}`,
            borderRadius: "var(--r-card)",
            padding: "12px 14px",
            boxShadow: "0 14px 36px rgba(0, 0, 0, 0.45)",
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
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 6 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-1)" }}>{t.title}</div>
              {t.badge && (
                <span
                  className={`guard-chip ${t.type === "danger" ? "guard-chip-fail" : "guard-chip-warn"}`}
                  style={{ fontSize: 10, padding: "1px 6px" }}
                >
                  {t.badge}
                </span>
              )}
            </div>
            <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 2, lineHeight: 1.48 }}>
              {t.body}
            </div>
            {t.action && (
              <div style={{ marginTop: 7 }}>
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
