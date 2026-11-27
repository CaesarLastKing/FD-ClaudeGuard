import { useEffect, useRef, useState } from "react";
import { Check, Copy, Headphones, X } from "lucide-react";
import { useGuardStore } from "@/stores/guardStore";

export const OFFICIAL_SUPPORT_QQ = "2568515327";

/**
 * 开源交流与技术支持弹窗（v3.0 双主题轻遮罩/轻投影规范）
 */
export function SupportModal() {
  const open = useGuardStore((s) => s.supportModalOpen);
  const setOpen = useGuardStore((s) => s.setSupportModalOpen);
  const pushToast = useGuardStore((s) => s.pushToast);

  const [copied, setCopied] = useState(false);
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    if (!open) return;
    setCopied(false);
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, [open, setOpen]);

  if (!open) return null;

  const handleCopyQq = async () => {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("clipboard unavailable");
      }
      await navigator.clipboard.writeText(OFFICIAL_SUPPORT_QQ);
      setCopied(true);
      pushToast("已复制交流 QQ 号", `QQ：${OFFICIAL_SUPPORT_QQ}，添加时请备注“FD 启动器”。`, "ok");
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopied(false);
        copyTimerRef.current = null;
      }, 2400);
    } catch {
      pushToast("请手动复制 QQ 号", `开发者交流 QQ：${OFFICIAL_SUPPORT_QQ}`, "info");
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="开源交流与技术支持"
      data-testid="support-modal"
      onClick={(e) => {
        if (e.target === e.currentTarget) setOpen(false);
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "var(--modal-backdrop)",
        backdropFilter: "blur(4px)",
        zIndex: 160,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
      }}
    >
      <div
        style={{
          width: 496,
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
                background: "var(--primary-soft)",
                border: "1px solid var(--primary-border)",
                color: "var(--primary)",
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
              }}
            >
              <Headphones size={16} strokeWidth={1.5} />
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
                  开源交流与技术支持
                </h3>
                <span className="guard-chip guard-chip-ok">免费开源</span>
              </div>
              <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 3, lineHeight: 1.45 }}>
                环境排障协助、功能反馈与版本更新交流
              </div>
            </div>
          </div>

          <button
            type="button"
            aria-label="关闭弹窗"
            className="modal-close-btn"
            onClick={() => setOpen(false)}
          >
            <X size={15} strokeWidth={1.5} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: "0 20px 18px", display: "flex", flexDirection: "column", gap: 12 }}>
          <div className="qq-card">
            <div>
              <div style={{ fontSize: 11.5, color: "var(--text-3)" }}>开发者交流 QQ</div>
              <div className="qq-num tabular" data-testid="support-qq-number">
                {OFFICIAL_SUPPORT_QQ}
              </div>
            </div>
            <button
              type="button"
              data-testid="btn-copy-qq"
              className="guard-btn guard-btn-primary guard-btn-sm"
              onClick={() => void handleCopyQq()}
            >
              {copied ? <Check size={13.5} strokeWidth={1.8} /> : <Copy size={13.5} strokeWidth={1.5} />}
              <span>{copied ? "已复制 QQ 号" : "复制 QQ 号"}</span>
            </button>
          </div>

          <div
            style={{
              borderRadius: 9,
              border: "1px solid var(--divider)",
              background: "var(--bg-card-band)",
              padding: "10px 14px",
              fontSize: 12,
              color: "var(--text-2)",
              lineHeight: 1.62,
            }}
          >
            <div>• 添加好友时请备注「FD 启动器」，方便快速响应与协助。</div>
            <div>• 如遇复杂代理或封号环境问题，可导出脱敏诊断 ZIP 包发给开发者快速定位。</div>
          </div>
        </div>

        {/* Footer */}
        <div
          style={{
            padding: "12px 20px",
            borderTop: "1px solid var(--divider)",
            background: "var(--bg-card-band)",
            display: "flex",
            alignItems: "center",
            justifyContent: "flex-end",
            gap: 8,
          }}
        >
          <button
            type="button"
            className="guard-btn guard-btn-flat guard-btn-sm"
            onClick={() => setOpen(false)}
          >
            关闭
          </button>
        </div>
      </div>
    </div>
  );
}
