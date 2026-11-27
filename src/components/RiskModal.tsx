import { useEffect, useState } from "react";
import { AlertTriangle, ArrowRight, CheckCircle2, Loader2, ShieldAlert, X } from "lucide-react";
import { useGuardStore } from "@/stores/guardStore";

/**
 * 现代三段式确认对话框（v3.0 双主题轻遮罩/轻投影 + 长节点名截断防溢出 + 统一纤细字阶）
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
      ? "var(--bad-bg)"
      : tone === "ok"
      ? "var(--ok-bg)"
      : "var(--warning-soft)";
  const icoBorder =
    tone === "danger"
      ? "var(--bad-border)"
      : tone === "ok"
      ? "var(--ok-border)"
      : "var(--warning-border)";
  const icoColor =
    tone === "danger"
      ? "var(--bad-fg)"
      : tone === "ok"
      ? "var(--ok-fg)"
      : "var(--warning-fg)";
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
        background: "var(--modal-backdrop)",
        backdropFilter: "blur(4px)",
        zIndex: 150,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
      }}
    >
      <div
        style={{
          width: buttonCount >= 3 ? 560 : 512,
          maxWidth: "96vw",
          background: "var(--bg-card)",
          border: "1px solid var(--border-card)",
          borderRadius: 13,
          boxShadow: "var(--shadow-modal)",
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
                width: 34,
                height: 34,
                borderRadius: 9,
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
                background: icoBg,
                border: `1px solid ${icoBorder}`,
                color: icoColor,
              }}
            >
              {tone === "danger" ? (
                <ShieldAlert size={16} strokeWidth={1.5} />
              ) : tone === "ok" ? (
                <CheckCircle2 size={16} strokeWidth={1.5} />
              ) : (
                <AlertTriangle size={16} strokeWidth={1.5} />
              )}
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <h3
                  style={{
                    fontSize: 15,
                    fontWeight: 500,
                    color: "var(--text-strong)",
                    letterSpacing: "-0.01em",
                    margin: 0,
                  }}
                >
                  {modal.title}
                </h3>
                {modal.badge && <span className={`guard-chip ${badgeClass}`}>{modal.badge}</span>}
              </div>
              {modal.subtitle && (
                <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 3, lineHeight: 1.48 }}>
                  {modal.subtitle}
                </div>
              )}
            </div>
          </div>
          <button
            type="button"
            aria-label="关闭弹窗"
            disabled={busyAction !== null}
            className="modal-close-btn"
            onClick={close}
          >
            <X size={15} strokeWidth={1.5} />
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
                gap: 12,
                padding: "11px 14px",
                borderRadius: 10,
                background: "var(--bg-subtle)",
                border: "1px solid var(--divider)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 9, flex: 1, minWidth: 0 }}>
                <div
                  className={`region-box ${modal.routeCompare.fromDanger ? "is-bad" : ""}`}
                  style={{ width: 28, height: 28, fontSize: 10 }}
                >
                  {modal.routeCompare.fromCode}
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div
                    title={modal.routeCompare.fromName}
                    style={{
                      fontSize: 12.5,
                      fontWeight: 500,
                      color: "var(--text-strong)",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {modal.routeCompare.fromName}
                  </div>
                  <div
                    style={{
                      fontSize: 11,
                      color: "var(--text-3)",
                      marginTop: 1.5,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {modal.routeCompare.fromRole}
                  </div>
                </div>
              </div>

              <ArrowRight size={14} strokeWidth={1.5} style={{ color: "var(--text-3)", flexShrink: 0 }} />

              <div style={{ display: "flex", alignItems: "center", gap: 9, flex: 1, minWidth: 0 }}>
                <div className="region-box" style={{ width: 28, height: 28, fontSize: 10 }}>
                  {modal.routeCompare.toCode}
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div
                    title={modal.routeCompare.toName}
                    style={{
                      fontSize: 12.5,
                      fontWeight: 500,
                      color: "var(--text-strong)",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {modal.routeCompare.toName}
                  </div>
                  <div
                    style={{
                      fontSize: 11,
                      color: "var(--text-3)",
                      marginTop: 1.5,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {modal.routeCompare.toRole}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 1px 细分割线紧凑键值卡 */}
          <div
            style={{
              borderRadius: 10,
              border: "1px solid var(--divider)",
              background: "var(--bg-card-band)",
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
                  fontSize: 12,
                  borderBottom: idx === modal.rows.length - 1 ? "none" : "1px solid var(--divider)",
                  alignItems: "baseline",
                }}
              >
                <div style={{ color: "var(--text-3)", fontSize: 11.5 }}>{r.label}</div>
                <div
                  style={{
                    color:
                      r.tone === "danger"
                        ? "var(--bad-fg)"
                        : r.tone === "ok"
                        ? "var(--ok-fg)"
                        : "var(--text-1)",
                    fontWeight: r.tone === "danger" ? 500 : 400,
                    lineHeight: 1.55,
                  }}
                >
                  {r.value}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer：独立浅底栏 */}
        <div
          style={{
            padding: "12px 20px",
            borderTop: "1px solid var(--divider)",
            background: "var(--bg-card-band)",
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
                {busyAction === "secondary" && <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />}
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
                {busyAction === "danger" && <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />}
                <span>{modal.dangerLabel}</span>
              </button>
            )}
            <button
              type="button"
              className="guard-btn guard-btn-primary guard-btn-sm"
              disabled={busyAction !== null}
              onClick={() => void runAction("primary", modal.onPrimary)}
            >
              {busyAction === "primary" && <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />}
              <span>{modal.primaryLabel}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
