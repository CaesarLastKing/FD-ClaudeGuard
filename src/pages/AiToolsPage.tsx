import { Sparkles } from "lucide-react";

/**
 * 「AI 工具箱」预留页面（严格遵循 UI v3.0 视觉规范，克制留白、双主题一致、无假功能按钮）
 */
export function AiToolsPage() {
  return (
    <section
      data-testid="ai-tools-page"
      style={{
        display: "flex",
        flex: 1,
        minHeight: 0,
        flexDirection: "column",
        background: "var(--bg-canvas)",
      }}
    >
      {/* 58px 标准单行页头 */}
      <div className="page-hd">
        <div className="page-hd-left">
          <h1 className="page-title">AI 工具箱</h1>
          <span className="page-sub">常用 AI 工作流辅助模块预留入口 · 持续演进中</span>
        </div>
      </div>

      {/* 居中克制预留区 */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: 24,
        }}
      >
        <div
          className="guard-card"
          style={{
            width: "min(520px, 100%)",
            padding: "28px 26px",
            display: "flex",
            flexDirection: "column",
            alignItems: "flex-start",
            gap: 14,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 11 }}>
            <div
              className="guard-icon-box"
              style={{
                width: 36,
                height: 36,
                borderRadius: 9,
                background: "var(--primary-soft)",
                borderColor: "var(--primary-border)",
                color: "var(--primary)",
              }}
            >
              <Sparkles size={16} strokeWidth={1.5} />
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 15, fontWeight: 500, color: "var(--text-strong)" }}>
                  AI 工具箱模块规划中
                </span>
                <span className="guard-chip guard-chip-neutral">即将上线</span>
              </div>
              <div style={{ fontSize: 11.5, color: "var(--text-3)", marginTop: 2.5 }}>
                所有核心防封守护、安全策略与清理恢复能力均已整合至左下角「系统设置」
              </div>
            </div>
          </div>

          <div
            style={{
              width: "100%",
              padding: "12px 14px",
              borderRadius: 8,
              background: "var(--bg-card-band)",
              border: "1px solid var(--divider)",
              fontSize: 12,
              color: "var(--text-2)",
              lineHeight: 1.65,
            }}
          >
            本页面将用于后续集成面向 Claude 与 AI 日常开发的轻量辅助能力（例如 MCP 配置管理、提示词与会话归档、跨端快捷诊断工具等）。功能完备前保持克制留白，不放置占位假按钮。
          </div>
        </div>
      </div>
    </section>
  );
}
