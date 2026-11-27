import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { ThinScrollArea } from "@/components/ThinScrollArea";
import { PLAYBOOK_RULES } from "@/data/playbooks";
import { useGuardStore } from "@/stores/guardStore";

/**
 * Claude 账号安全守则联动抽屉（v3.0 扁平白皮书文档流 + 固定顶栏防裁切 + ThinScrollArea）
 */
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
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, setOpen]);

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
      aria-modal="true"
      aria-label="Claude 账号安全守则"
      data-testid="playbook-drawer"
      onClick={(e) => {
        if (e.target === e.currentTarget) setOpen(false);
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "var(--drawer-backdrop)",
        backdropFilter: "blur(2px)",
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
          background: "var(--bg-sidebar)",
          borderLeft: "1px solid var(--divider-strong)",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          boxShadow: "var(--shadow-drawer)",
        }}
      >
        {/* 固定顶栏：滚动定位高亮条目时始终吸顶不被裁切 */}
        <div
          style={{
            padding: "14px 20px",
            borderBottom: "1px solid var(--divider)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            flexShrink: 0,
            background: "var(--bg-sidebar)",
          }}
        >
          <div style={{ minWidth: 0 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 7,
                fontSize: 14.5,
                fontWeight: 500,
                color: "var(--text-strong)",
                lineHeight: 1.3,
              }}
            >
              <ShieldCheck size={15} strokeWidth={1.55} style={{ color: "var(--primary)", flexShrink: 0 }} />
              <span>Claude 账号安全守则（实时联动）</span>
            </div>
            <div style={{ fontSize: 11.5, color: "var(--text-3)", marginTop: 3 }}>
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

        {/* 独立 ThinScrollArea 扁平文档流（零卡片套娃） */}
        <ThinScrollArea>
          <div
            style={{
              padding: "12px 20px 28px",
              display: "flex",
              flexDirection: "column",
              userSelect: "text",
            }}
          >
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
                      fontSize: 13,
                      fontWeight: 500,
                      color: "var(--text-strong)",
                      margin: "0 0 5px 0",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 10,
                      lineHeight: 1.4,
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
                        color: rule.level === "fail" ? "var(--bad-fg)" : "var(--warning-fg)",
                        marginBottom: 5,
                        fontWeight: 500,
                      }}
                    >
                      • {rule.hitText}
                    </div>
                  )}
                  <p style={{ fontSize: 12, color: "var(--text-2)", lineHeight: 1.65, margin: 0 }}>
                    {rule.desc}
                  </p>
                </div>
              );
            })}
          </div>
        </ThinScrollArea>
      </div>
    </div>
  );
}
