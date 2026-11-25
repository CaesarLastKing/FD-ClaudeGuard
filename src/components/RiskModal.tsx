import { useEffect, useState } from "react";
import { AlertTriangle, ArrowRight, CheckCircle2, Loader2, ShieldAlert, X } from "lucide-react";
import { useGuardStore } from "@/stores/guardStore";

/**
 * 现代三段式对话框（496px 宽，1:1 对齐增量 8 终版规范）
 * Header（36x36 语义圆角图标 + 中性高对比主标题 + 风险胶囊 + 副文 + 右上角 X）
 * Body（可选路由对比条 + 1px 细分割线紧凑键值卡）
 * Footer（独立浅底栏 + 右对齐单行主次按钮组）
 */
export function RiskModal() {
  const modal = useGuardStore((s) => s.riskModal);
  const close = useGuardStore((s) => s.closeRiskModal);
  const pushToast = useGuardStore((s) => s.pushToast);
  const [busyAction, setBusyAction] = useState<"primary" | "secondary" | "danger" | null>(null);

  useEffect(() => {
    if (!modal?.open) {
      setBusyAction(null);
      return;
    }
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busyAction) {
        close();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [modal?.open, busyAction, close]);

  if (!modal || !modal.open) return null;

  const runAction = async (
    kind: "primary" | "secondary" | "danger",
    fn?: () => void | Promise<void>
  ) => {
    if (!fn || busyAction) return;
    setBusyAction(kind);
    try {
      await fn();
      close();
    } catch (err) {
      pushToast("操作执行失败", String(err), "danger");
    } finally {
      setBusyAction(null);
    }
  };

  const tone = modal.tone ?? "warn";
  const icoBg =
    tone === "danger"
      ? "var(--danger-soft)"
      : tone === "ok"
      ? "var(--success-soft)"
      : "var(--warning-soft)";
  const icoColor =
    tone === "danger"
      ? "var(--danger-bright)"
      : tone === "ok"
      ? "var(--success)"
      : "var(--warning)";
  const badgeClass =
    tone === "danger"
      ? "guard-chip-fail"
      : tone === "ok"
      ? "guard-chip-ok"
      : "guard-chip-warn";

  const buttonCount =
    1 + (modal.primaryLabel ? 1 : 0) + (modal.secondaryLabel ? 1 : 0) + (modal.dangerLabel ? 1 : 0);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={modal.title}
      data-testid="risk-modal"
      onClick={(e) => {
        if (e.target === e.currentTarget && !busyAction) close();
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0, 0, 0, 0.62)",
        backdropFilter: "blur(5px)",
        zIndex: 150,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
      }}
    >
      <div
        style={{
          width: buttonCount >= 3 ? 560 : 496,
          maxWidth: "96vw",
          background: "var(--bg-card)",
          border: "1px solid var(--border-strong)",
          borderRadius: 14,
          boxShadow: "0 28px 72px rgba(0, 0, 0, 0.68), 0 0 0 1px rgba(255, 255, 255, 0.03) inset",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "18px 20px 14px",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 12,
          }}
        >
          <div style={{ display: "flex", alignItems: "flex-start", gap: 12, minWidth: 0 }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
                background: icoBg,
                color: icoColor,
              }}
            >
              {tone === "danger" ? (
                <ShieldAlert size={18} strokeWidth={1.85} />
              ) : tone === "ok" ? (
                <CheckCircle2 size={18} strokeWidth={1.85} />
              ) : (
                <AlertTriangle size={18} strokeWidth={1.85} />
              )}
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <h3
                  style={{
                    fontSize: 15.5,
                    fontWeight: 600,
                    color: "var(--text-1)",
                    letterSpacing: "-0.01em",
                    margin: 0,
                  }}
                >
                  {modal.title}
                </h3>
                {modal.badge && <span className={`guard-chip ${badgeClass}`}>{modal.badge}</span>}
              </div>
              {modal.subtitle && (
                <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 3, lineHeight: 1.45 }}>
                  {modal.subtitle}
                </div>
              )}
            </div>
          </div>
          <button
            type="button"
            aria-label="关闭弹窗"
            disabled={busyAction !== null}
            onClick={close}
            style={{
              width: 28,
              height: 28,
              borderRadius: 7,
              border: "none",
              background: "transparent",
              color: "var(--text-3)",
              cursor: "pointer",
              display: "grid",
              placeItems: "center",
              flexShrink: 0,
            }}
          >
            <X size={15} strokeWidth={1.85} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: "0 20px 18px", display: "flex", flexDirection: "column", gap: 12 }}>
          {modal.routeCompare && (
            <div
              data-testid="modal-route-strip"
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 10,
                padding: "11px 14px",
                borderRadius: 10,
                background: "var(--bg-subtle)",
                border: "1px solid var(--border)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 9, minWidth: 0 }}>
                <div
                  className="font-mono-code"
                  style={{
                    width: 28,
                    height: 28,
                    borderRadius: 7,
                    background: modal.routeCompare.fromDanger ? "var(--danger-soft)" : "var(--bg-card)",
                    border: `1px solid ${
                      modal.routeCompare.fromDanger ? "rgba(239, 68, 68, 0.4)" : "var(--border-strong)"
                    }`,
                    color: modal.routeCompare.fromDanger ? "var(--danger-bright)" : "var(--text-1)",
                    display: "grid",
                    placeItems: "center",
                    fontSize: 11,
                    fontWeight: 700,
                    flexShrink: 0,
                  }}
                >
                  {modal.routeCompare.fromCode}
                </div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-1)", whiteSpace: "nowrap" }}>
                    {modal.routeCompare.fromName}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-3)", marginTop: 1 }}>
                    {modal.routeCompare.fromRole}
                  </div>
                </div>
              </div>

              <ArrowRight size={15} style={{ color: "var(--text-3)", flexShrink: 0 }} />

              <div style={{ display: "flex", alignItems: "center", gap: 9, minWidth: 0 }}>
                <div
                  className="font-mono-code"
                  style={{
                    width: 28,
                    height: 28,
                    borderRadius: 7,
                    background: "var(--bg-card)",
                    border: "1px solid var(--border-strong)",
                    color: "var(--text-1)",
                    display: "grid",
                    placeItems: "center",
                    fontSize: 11,
                    fontWeight: 700,
                    flexShrink: 0,
                  }}
                >
                  {modal.routeCompare.toCode}
                </div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-1)", whiteSpace: "nowrap" }}>
                    {modal.routeCompare.toName}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-3)", marginTop: 1 }}>
                    {modal.routeCompare.toRole}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 1px 细分割线紧凑键值卡（左标签 74px） */}
          <div
            style={{
              borderRadius: 10,
              border: "1px solid var(--border)",
              background: "rgba(128, 128, 140, 0.03)",
              overflow: "hidden",
            }}
          >
            {modal.rows.map((r, idx) => (
              <div
                key={r.label}
                style={{
                  display: "grid",
                  gridTemplateColumns: "74px 1fr",
                  gap: 12,
                  padding: "10px 14px",
                  fontSize: 12.5,
                  borderBottom: idx === modal.rows.length - 1 ? "none" : "1px solid var(--border)",
                  alignItems: "baseline",
                }}
              >
                <div style={{ color: "var(--text-3)", fontSize: 12 }}>{r.label}</div>
                <div
                  style={{
                    color:
                      r.tone === "danger"
                        ? "var(--danger-bright)"
                        : r.tone === "ok"
                        ? "var(--success)"
                        : "var(--text-1)",
                    fontWeight: r.tone === "danger" ? 600 : 400,
                    lineHeight: 1.5,
                  }}
                >
                  {r.value}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer：独立浅底栏（当按钮 >= 3 时不放左下角易折行提示语，保持单行舒展右对齐） */}
        <div
          style={{
            padding: "12px 20px",
            borderTop: "1px solid var(--border)",
            background: "rgba(128, 128, 140, 0.03)",
            display: "flex",
            alignItems: "center",
            justifyContent: buttonCount >= 3 || !modal.footTip ? "flex-end" : "space-between",
            gap: 12,
          }}
        >
          {buttonCount < 3 && modal.footTip && (
            <span style={{ fontSize: 11.5, color: "var(--text-3)" }}>{modal.footTip}</span>
          )}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "flex-end",
              flexWrap: "wrap",
              gap: 8,
              minWidth: 0,
            }}
          >
            <button
              type="button"
              className="guard-btn guard-btn-flat guard-btn-sm"
              disabled={busyAction !== null}
              onClick={close}
            >
              取消
            </button>
            {modal.secondaryLabel && modal.onSecondary && (
              <button
                type="button"
                className="guard-btn guard-btn-flat guard-btn-sm"
                disabled={busyAction !== null}
                onClick={() => void runAction("secondary", modal.onSecondary)}
              >
                {busyAction === "secondary" && <Loader2 size={13} strokeWidth={2} className="guard-spin" />}
                <span>{modal.secondaryLabel}</span>
              </button>
            )}
            {modal.dangerLabel && modal.onDanger && (
              <button
                type="button"
                className="guard-btn guard-btn-danger-soft guard-btn-sm"
                disabled={busyAction !== null}
                onClick={() => void runAction("danger", modal.onDanger)}
              >
                {busyAction === "danger" && <Loader2 size={13} strokeWidth={2} className="guard-spin" />}
                <span>{modal.dangerLabel}</span>
              </button>
            )}
            <button
              type="button"
              className="guard-btn guard-btn-primary guard-btn-sm"
              disabled={busyAction !== null}
              onClick={() => void runAction("primary", modal.onPrimary)}
            >
              {busyAction === "primary" && <Loader2 size={13} strokeWidth={2} className="guard-spin" />}
              <span>{modal.primaryLabel}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
