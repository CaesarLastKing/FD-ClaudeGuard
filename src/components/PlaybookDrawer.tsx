import { useEffect, useState } from "react";
import { PLAYBOOK_RULES } from "@/data/playbooks";
import { useGuardStore } from "@/stores/guardStore";

export function PlaybookDrawer() {
  const open = useGuardStore((s) => s.playbookOpen);
  const setOpen = useGuardStore((s) => s.setPlaybookOpen);
  const focusId = useGuardStore((s) => s.playbookFocusId);
  const focusSeq = useGuardStore((s) => s.playbookFocusSeq);
  const triggeredIds = useGuardStore((s) => s.snapshot.triggeredPlaybookIds);
  const [flashingId, setFlashingId] = useState<string | null>(null);

  const triggeredSet = new Set(triggeredIds);
  const sortedRules = [...PLAYBOOK_RULES].sort(
    (a, b) => Number(triggeredSet.has(b.id)) - Number(triggeredSet.has(a.id))
  );

  useEffect(() => {
    if (!open || !focusId) return;
    let rafId: number | null = null;
    const timer = window.setTimeout(() => {
      const el = document.getElementById(`pb-card-${focusId}`);
      if (el && typeof el.scrollIntoView === "function") {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
      }
      setFlashingId(null);
      rafId = window.requestAnimationFrame(() => setFlashingId(focusId));
    }, 80);
    const clearTimer = window.setTimeout(() => setFlashingId(null), 2600);
    return () => {
      window.clearTimeout(timer);
      window.clearTimeout(clearTimer);
      if (rafId !== null) {
        window.cancelAnimationFrame(rafId);
      }
    };
  }, [open, focusId, focusSeq]);

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-label="Claude 账号安全守则"
      data-testid="playbook-drawer"
      onClick={(e) => {
        if (e.target === e.currentTarget) setOpen(false);
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0, 0, 0, 0.52)",
        backdropFilter: "blur(3px)",
        zIndex: 140,
        display: "flex",
        justifyContent: "flex-end",
      }}
    >
      <div
        style={{
          width: 500,
          maxWidth: "94vw",
          height: "100%",
          background: "var(--bg-canvas)",
          borderLeft: "1px solid var(--border-strong)",
          padding: "20px 22px",
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          gap: 12,
          boxShadow: "-16px 0 48px rgba(0, 0, 0, 0.5)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <h2 style={{ fontSize: 18, fontWeight: 600, margin: 0 }}>
              Claude 账号安全守则（实时联动）
            </h2>
            <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 2 }}>
              结合本机实时日志与环境状态自动预警，已命中条目置顶高亮
            </div>
          </div>
          <button
            type="button"
            className="guard-btn guard-btn-flat guard-btn-xs"
            onClick={() => setOpen(false)}
          >
            关闭
          </button>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {sortedRules.map((rule) => {
            const hit = triggeredSet.has(rule.id);
            const isFlashing = flashingId === rule.id;
            const cardCls = [
              "pb-card",
              hit ? (rule.level === "fail" ? "triggered" : "triggered-warn") : "",
              isFlashing ? "flash-focus" : "",
            ]
              .filter(Boolean)
              .join(" ");
            const tagCls = hit
              ? rule.level === "fail"
                ? "guard-chip-fail"
                : "guard-chip-warn"
              : "guard-chip-neutral";

            return (
              <div key={rule.id} id={`pb-card-${rule.id}`} className={cardCls}>
                <h3
                  style={{
                    fontSize: 13.5,
                    fontWeight: 600,
                    margin: "0 0 5px 0",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 8,
                  }}
                >
                  <span>
                    {rule.code}. {rule.title}
                  </span>
                  <span className={`guard-chip ${tagCls}`}>
                    {hit ? "当前已触发" : rule.tag}
                  </span>
                </h3>
                {hit && (
                  <div
                    style={{
                      fontSize: 11.5,
                      color: rule.level === "fail" ? "var(--danger-bright)" : "var(--warning)",
                      marginBottom: 5,
                      fontWeight: 500,
                    }}
                  >
                    • {rule.hitText}
                  </div>
                )}
                <p style={{ fontSize: 12, color: "var(--text-2)", lineHeight: 1.62, margin: 0 }}>
                  {rule.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
