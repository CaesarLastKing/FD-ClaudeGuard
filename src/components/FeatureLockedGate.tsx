import { KeyRound, Lock } from "lucide-react";
import { useGuardStore } from "@/stores/guardStore";

interface FeatureLockedGateProps {
  pageTitle: string;
  pageSubtitle: string;
  badgeText?: string;
  description: string;
  highlights: string[];
  testId: string;
}

/**
 * 未激活态副页面统一锁定门禁卡片
 * 确保除控制台 3 项基础体验探针外，节点评估、日志审计、环境维护与守卫策略全部在输入激活密钥后开启。
 */
export function FeatureLockedGate({
  pageTitle,
  pageSubtitle,
  badgeText = "输入激活密钥后开启",
  description,
  highlights,
  testId,
}: FeatureLockedGateProps) {
  const setLicenseModalOpen = useGuardStore((s) => s.setLicenseModalOpen);

  return (
    <section
      data-testid={testId}
      style={{ display: "flex", flex: 1, minHeight: 0, flexDirection: "column" }}
    >
      <div
        style={{
          padding: "16px 22px 14px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 14,
          flexShrink: 0,
        }}
      >
        <div>
          <h1
            style={{
              fontSize: 20,
              fontWeight: 600,
              letterSpacing: "-0.02em",
              margin: 0,
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <span>{pageTitle}</span>
            <span className="guard-chip guard-chip-mode">
              <Lock size={11} strokeWidth={2} />
              <span>{badgeText}</span>
            </span>
          </h1>
          <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4 }}>{pageSubtitle}</div>
        </div>
        <button
          type="button"
          className="guard-btn guard-btn-primary guard-btn-sm"
          onClick={() => setLicenseModalOpen(true)}
        >
          <KeyRound size={14} strokeWidth={1.9} />
          <span>立即激活解锁</span>
        </button>
      </div>

      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 28,
          overflowY: "auto",
        }}
      >
        <div
          className="guard-card"
          style={{
            width: 520,
            maxWidth: "100%",
            padding: "28px 26px",
            display: "flex",
            flexDirection: "column",
            gap: 18,
          }}
        >
          <div style={{ display: "flex", alignItems: "flex-start", gap: 14 }}>
            <div
              style={{
                width: 44,
                height: 44,
                borderRadius: 12,
                background: "var(--primary-soft)",
                color: "var(--primary)",
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
              }}
            >
              <Lock size={20} strokeWidth={1.9} />
            </div>
            <div>
              <h2
                style={{
                  fontSize: 16.5,
                  fontWeight: 600,
                  margin: 0,
                  color: "var(--text-1)",
                  lineHeight: 1.35,
                }}
              >
                {pageTitle}需激活后开启实测与操作
              </h2>
              <p
                style={{
                  fontSize: 12.5,
                  color: "var(--text-2)",
                  margin: "6px 0 0",
                  lineHeight: 1.6,
                }}
              >
                {description}
              </p>
            </div>
          </div>

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 9,
              padding: "13px 15px",
              borderRadius: 10,
              background: "var(--bg-subtle)",
              border: "1px solid var(--border)",
              fontSize: 12.5,
              color: "var(--text-2)",
              lineHeight: 1.55,
            }}
          >
            {highlights.map((line) => (
              <div key={line} style={{ display: "flex", alignItems: "flex-start", gap: 9 }}>
                <span
                  style={{
                    width: 5,
                    height: 5,
                    borderRadius: "50%",
                    background: "var(--primary)",
                    marginTop: 7,
                    flexShrink: 0,
                  }}
                />
                <span>{line}</span>
              </div>
            ))}
          </div>

          <button
            type="button"
            data-testid={`${testId}-unlock-btn`}
            className="guard-btn guard-btn-secondary"
            style={{ width: "100%", padding: "11px 16px" }}
            onClick={() => setLicenseModalOpen(true)}
          >
            <KeyRound size={15} strokeWidth={2} />
            <span>输入一次性激活密钥 · 立即解锁全部功能</span>
          </button>
        </div>
      </div>
    </section>
  );
}
