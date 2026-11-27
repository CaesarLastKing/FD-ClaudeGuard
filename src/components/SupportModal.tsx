import { useEffect, useRef, useState } from "react";
import { Check, Copy, ExternalLink, X } from "lucide-react";
import { ipc } from "@/lib/ipc";
import {
  OFFICIAL_AUTHOR_X_HANDLE,
  OFFICIAL_AUTHOR_X_URL,
  OFFICIAL_GITHUB_REPO_URL,
} from "@/lib/protocol";
import { useGuardStore } from "@/stores/guardStore";

export { OFFICIAL_AUTHOR_X_HANDLE, OFFICIAL_AUTHOR_X_URL };

/** X（Twitter）极简品牌矢量徽标 */
export function XBrandIcon({ size = 15 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
    </svg>
  );
}

/**
 * 全新 UI 3.0「联系作者（X / Twitter）」名片弹窗（444px 居中双主题，取代旧 QQ 弹窗）
 * 严格 1:1 对齐 docs/mockups/ui-v3-settings-modal-preview.html 中的 contact-modal
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
      if (e.key === "Escape") {
        e.stopImmediatePropagation();
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown, true);
    return () => {
      window.removeEventListener("keydown", onKeyDown, true);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, [open, setOpen]);

  if (!open) return null;

  const shortUrl = OFFICIAL_AUTHOR_X_URL.replace(/^https?:\/\//i, "");

  const handleCopyHandle = async () => {
    const fallbackCopy = (): boolean => {
      try {
        const ta = document.createElement("textarea");
        ta.value = OFFICIAL_AUTHOR_X_HANDLE;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(ta);
        return ok;
      } catch {
        return false;
      }
    };

    try {
      let ok = false;
      if (navigator.clipboard?.writeText) {
        ok = await navigator.clipboard
          .writeText(OFFICIAL_AUTHOR_X_HANDLE)
          .then(() => true)
          .catch(() => false);
      }
      if (!ok) {
        ok = fallbackCopy();
      }
      if (!ok) {
        throw new Error("clipboard unavailable");
      }
      setCopied(true);
      pushToast("已复制作者 X 账号", OFFICIAL_AUTHOR_X_HANDLE, "ok");
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopied(false);
        copyTimerRef.current = null;
      }, 2400);
    } catch {
      pushToast("请手动复制账号", `作者 X（Twitter）：${OFFICIAL_AUTHOR_X_HANDLE}`, "info");
    }
  };

  const handleOpenExternal = async (url: string, label: string) => {
    try {
      await ipc.openExternalUrl(url);
    } catch (err) {
      pushToast(`打开${label}失败`, String(err), "danger");
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="联系作者"
      data-testid="support-modal"
      onClick={(e) => {
        if (e.target === e.currentTarget) setOpen(false);
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "var(--modal-backdrop)",
        backdropFilter: "blur(4px)",
        zIndex: 170,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
        cursor: "pointer",
      }}
    >
      <div
        style={{
          width: 444,
          maxWidth: "100%",
          borderRadius: "var(--r-hud)",
          background: "var(--bg-card)",
          border: "1px solid var(--divider-strong)",
          boxShadow: "var(--shadow-modal)",
          overflow: "hidden",
          cursor: "default",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "16px 18px 14px",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 12,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0 }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                background: "var(--bg-subtle)",
                border: "1px solid var(--divider-strong)",
                color: "var(--text-strong)",
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
              }}
            >
              <XBrandIcon size={16} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <span style={{ fontSize: 14.5, fontWeight: 500, color: "var(--text-strong)" }}>
                  联系作者
                </span>
                <span className="guard-chip guard-chip-pass">免费开源</span>
              </div>
              <div style={{ fontSize: 11, color: "var(--text-3)", marginTop: 2 }}>
                问题反馈、功能建议与版本动态
              </div>
            </div>
          </div>

          <button
            type="button"
            aria-label="关闭联系作者"
            className="modal-close-btn"
            onClick={() => setOpen(false)}
          >
            <X size={14} strokeWidth={1.6} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: "0 18px 16px", display: "flex", flexDirection: "column", gap: 11 }}>
          <div className="x-profile-card">
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: 10.5, color: "var(--text-3)", marginBottom: 2 }}>
                X（Twitter）官方账号
              </div>
              <div
                data-testid="support-x-handle"
                role="button"
                tabIndex={0}
                title={`点击复制 ${OFFICIAL_AUTHOR_X_HANDLE}`}
                onClick={() => void handleCopyHandle()}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    void handleCopyHandle();
                  }
                }}
                style={{
                  fontSize: 14.5,
                  fontWeight: 500,
                  color: "var(--text-strong)",
                  letterSpacing: "-0.01em",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  cursor: "pointer",
                  userSelect: "text",
                }}
              >
                {OFFICIAL_AUTHOR_X_HANDLE}
              </div>
              <div
                style={{
                  fontSize: 11,
                  color: "var(--text-3)",
                  marginTop: 2,
                  userSelect: "text",
                }}
              >
                {shortUrl}
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
              <button
                type="button"
                data-testid="btn-copy-x-handle"
                className="guard-btn guard-btn-flat"
                onClick={() => void handleCopyHandle()}
              >
                {copied ? <Check size={12.5} strokeWidth={1.8} /> : <Copy size={12.5} strokeWidth={1.5} />}
                <span>{copied ? "已复制" : "复制账号"}</span>
              </button>
              <button
                type="button"
                data-testid="btn-open-x-profile"
                className="guard-btn guard-btn-primary"
                onClick={() => void handleOpenExternal(OFFICIAL_AUTHOR_X_URL, "作者 X 主页")}
              >
                <span>前往主页 ↗</span>
              </button>
            </div>
          </div>

          <div
            style={{
              borderRadius: 9,
              border: "1px solid var(--divider)",
              background: "var(--bg-card-band)",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                padding: "9px 13px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
                borderBottom: "1px solid var(--divider)",
                fontSize: 11.5,
              }}
            >
              <span style={{ color: "var(--text-3)", flexShrink: 0 }}>排障反馈</span>
              <span style={{ color: "var(--text-2)", textAlign: "right" }}>
                可在「常规开关」导出脱敏诊断包后附带说明反馈
              </span>
            </div>
            <div
              style={{
                padding: "9px 13px",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
                fontSize: 11.5,
              }}
            >
              <span style={{ color: "var(--text-3)", flexShrink: 0 }}>开源仓库</span>
              <button
                type="button"
                data-testid="btn-open-github-from-contact"
                className="guard-btn guard-btn-flat guard-btn-xs"
                onClick={() => void handleOpenExternal(OFFICIAL_GITHUB_REPO_URL, "GitHub 仓库")}
              >
                <ExternalLink size={11} strokeWidth={1.55} />
                <span>GitHub · FD-ClaudeGuard ↗</span>
              </button>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div
          style={{
            padding: "11px 18px",
            borderTop: "1px solid var(--divider)",
            background: "var(--bg-card-band)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
          }}
        >
          <span style={{ fontSize: 11, color: "var(--text-3)" }}>感谢使用与关注更新</span>
          <button
            type="button"
            className="guard-btn guard-btn-flat guard-btn-xs"
            onClick={() => setOpen(false)}
          >
            关闭
          </button>
        </div>
      </div>
    </div>
  );
}
