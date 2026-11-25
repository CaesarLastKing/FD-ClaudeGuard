import { useEffect, useState } from "react";
import { KeyRound, Loader2, X } from "lucide-react";
import { useGuardStore } from "@/stores/guardStore";

/**
 * 一次性激活密钥核销弹窗（增量 19）
 * 严格遵循用户界面红线：Footer 左侧留空，不显示任何 QQ 售后信息，仅右侧展示「暂不激活」与「立即核销并解锁」。
 */
export function LicenseModal() {
  const open = useGuardStore((s) => s.licenseModalOpen);
  const setOpen = useGuardStore((s) => s.setLicenseModalOpen);
  const activateLicense = useGuardStore((s) => s.activateLicense);

  const [keyInput, setKeyInput] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // 仅在弹窗重新打开时重置上次的错误提示；切勿把 submitting 放进重置错误提示的依赖中，否则核销失败后会瞬间清空错误
  useEffect(() => {
    if (open) {
      setErrorMsg(null);
    }
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !submitting) {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, submitting, setOpen]);

  if (!open) return null;

  const handleSubmit = async () => {
    const cleaned = keyInput.trim().toUpperCase();
    if (!/^FDG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(cleaned)) {
      setErrorMsg("请输入正确的 18 位激活密钥格式（例如 FDG-XXXX-XXXX-XXXX）");
      return;
    }
    setSubmitting(true);
    setErrorMsg(null);
    try {
      await activateLicense(cleaned);
      setKeyInput("");
      setOpen(false);
    } catch (err) {
      setErrorMsg(String(err).replace(/^Error:\s*/, ""));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="激活 FD Claude 安全启动器"
      data-testid="license-modal"
      onClick={(e) => {
        if (e.target === e.currentTarget && !submitting) setOpen(false);
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0, 0, 0, 0.62)",
        backdropFilter: "blur(5px)",
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
          border: "1px solid var(--border-strong)",
          borderRadius: 14,
          boxShadow: "0 28px 72px rgba(0, 0, 0, 0.68), 0 0 0 1px rgba(255, 255, 255, 0.03) inset",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
        }}
      >
        {/* 顶部 Header */}
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
                background: "var(--primary-soft)",
                color: "var(--primary)",
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
              }}
            >
              <KeyRound size={17} strokeWidth={1.9} />
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
                  激活 FD Claude 安全启动器
                </h3>
                <span className="guard-chip guard-chip-mode">一次性密钥</span>
              </div>
              <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 3, lineHeight: 1.45 }}>
                免费体检可无限运行；核销密钥后解锁清晰方案与自动修复
              </div>
            </div>
          </div>

          <button
            type="button"
            aria-label="关闭弹窗"
            disabled={submitting}
            onClick={() => setOpen(false)}
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
            <X size={15} strokeWidth={1.9} />
          </button>
        </div>

        {/* 主体 Body */}
        <div style={{ padding: "0 20px 18px", display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <label
              htmlFor="fd-license-key-input"
              style={{ fontSize: 12, color: "var(--text-2)", fontWeight: 500 }}
            >
              输入激活密钥（一码一次核销）
            </label>
            <input
              id="fd-license-key-input"
              data-testid="license-key-input"
              type="text"
              autoFocus
              disabled={submitting}
              value={keyInput}
              placeholder="FDG-XXXX-XXXX-XXXX"
              onChange={(e) => {
                setKeyInput(e.target.value.toUpperCase());
                if (errorMsg) setErrorMsg(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !submitting) {
                  void handleSubmit();
                }
              }}
              className={`lic-input ${errorMsg ? "is-err" : ""}`}
            />
            {errorMsg && (
              <div
                role="alert"
                data-testid="license-error-msg"
                style={{
                  fontSize: 12,
                  color: "var(--danger-bright)",
                  background: "var(--danger-soft)",
                  border: "1px solid rgba(239, 68, 68, 0.35)",
                  borderRadius: 8,
                  padding: "8px 10px",
                  lineHeight: 1.5,
                  wordBreak: "break-word",
                }}
              >
                {errorMsg}
              </div>
            )}
          </div>

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 7,
              padding: "11px 13px",
              borderRadius: 10,
              background: "var(--bg-subtle)",
              border: "1px solid var(--border)",
              fontSize: 12,
              color: "var(--text-2)",
              lineHeight: 1.5,
            }}
          >
            <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
              <span style={ruleDotStyle} />
              <span>
                <strong style={{ color: "var(--text-1)", fontWeight: 500 }}>一码一次核销作废</strong>
                ：密钥在线核销成功后立即永久失效，无法在另一台机器或第二次重复使用。
              </span>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
              <span style={ruleDotStyle} />
              <span>
                <strong style={{ color: "var(--text-1)", fontWeight: 500 }}>绑定当前安装实例</strong>
                ：只要不卸载本软件，本地加密凭证永久有效，后续完全离线运行无需联网。
              </span>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
              <span style={ruleDotStyle} />
              <span>
                <strong style={{ color: "var(--text-1)", fontWeight: 500 }}>卸载即同步销毁</strong>
                ：卸载软件时将清除本地加密凭证与安装实例，旧密钥作废不可再次激活。
              </span>
            </div>
          </div>
        </div>

        {/* 底部 Footer：左侧严禁显示 QQ 售后信息，仅右侧放置动作按钮 */}
        <div
          data-testid="license-modal-footer"
          style={{
            padding: "12px 20px",
            borderTop: "1px solid var(--border)",
            background: "rgba(128, 128, 140, 0.03)",
            display: "flex",
            alignItems: "center",
            justifyContent: "flex-end",
            gap: 8,
          }}
        >
          <button
            type="button"
            disabled={submitting}
            className="guard-btn guard-btn-flat guard-btn-sm"
            onClick={() => setOpen(false)}
          >
            暂不激活
          </button>
          <button
            type="button"
            data-testid="btn-submit-license"
            disabled={submitting}
            className="guard-btn guard-btn-primary guard-btn-sm"
            onClick={() => void handleSubmit()}
          >
            {submitting && <Loader2 size={13} strokeWidth={2} className="guard-spin" />}
            <span>{submitting ? "正在核销..." : "立即核销并解锁"}</span>
          </button>
        </div>
      </div>
    </div>
  );
}

const ruleDotStyle: React.CSSProperties = {
  width: 5,
  height: 5,
  borderRadius: "50%",
  background: "var(--primary)",
  marginTop: 7,
  flexShrink: 0,
};
