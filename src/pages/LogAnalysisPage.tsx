import { useCallback, useEffect, useRef, useState } from "react";
import { Database, Loader2, RefreshCw, Trash2 } from "lucide-react";
import { ipc } from "@/lib/ipc";
import { useGuardStore } from "@/stores/guardStore";
import type { LogAnalysisReport, TelemetryInspection } from "@/types/guard";

type LogCategoryFilter = "anomaly" | "all" | "region_rate" | "disconnect" | "telemetry";

/** 将 Anthropic 官方状态页英文描述映射为简洁中文标签 */
function formatAnthropicStatusZh(indicator: string, desc: string): string {
  const trimmedDesc = (desc ?? "").trim();
  if (trimmedDesc && /[\u4e00-\u9fff]/.test(trimmedDesc)) {
    return trimmedDesc;
  }
  switch (trimmedDesc.toLowerCase()) {
    case "all systems operational":
      return "全部服务正常";
    case "partially degraded service":
      return "部分服务降级";
    case "minor service outage":
      return "轻微服务波动";
    case "partial system outage":
      return "部分服务中断";
    case "major service outage":
      return "重大服务故障";
    case "service under maintenance":
      return "系统维护中";
    default:
      break;
  }
  switch ((indicator ?? "").trim().toLowerCase()) {
    case "none":
      return "全部服务正常";
    case "minor":
      return "部分服务降级";
    case "major":
      return "部分服务中断";
    case "critical":
      return "重大服务故障";
    default:
      return "状态探测中";
  }
}

export function LogAnalysisPage({ embedded = false }: { embedded?: boolean } = {}) {
  const [filter, setFilter] = useState<LogCategoryFilter>("anomaly");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [simBusy, setSimBusy] = useState(false);
  const [telemetryOpen, setTelemetryOpen] = useState(false);
  const [noiseOpen, setNoiseOpen] = useState(false);
  const [telemetryLoading, setTelemetryLoading] = useState(false);
  const [telemetryInfo, setTelemetryInfo] = useState<TelemetryInspection | null>(null);
  const [report, setReport] = useState<LogAnalysisReport>({
    events: [],
    stats: {
      totalAnomalies: 0,
      regionOrRateCount: 0,
      disconnectCount: 0,
      telemetryOrDeviceCount: 0,
      watchingFiles: [],
    },
  });

  const snapshot = useGuardStore((s) => s.snapshot);
  const ackedLogIds = useGuardStore((s) => s.ackedLogIds);
  const ackLogIds = useGuardStore((s) => s.ackLogIds);
  const ackAllLogIds = useGuardStore((s) => s.ackAllLogIds);
  const openCleanModal = useGuardStore((s) => s.openCleanModal);
  const openPlaybookFocus = useGuardStore((s) => s.openPlaybookFocus);
  const pushToast = useGuardStore((s) => s.pushToast);

  const mountedRef = useRef(true);
  const loadSeqRef = useRef(0);
  const prevUnreadRef = useRef<number | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const loadLogs = useCallback(async () => {
    const seq = ++loadSeqRef.current;
    setLoading(true);
    try {
      const res = await ipc.getLogAnalysis();
      if (!mountedRef.current || seq !== loadSeqRef.current) return;
      setReport(res);
    } catch (err) {
      if (mountedRef.current) {
        pushToast("扫描日志失败", String(err), "danger");
      }
    } finally {
      if (mountedRef.current && seq === loadSeqRef.current) {
        setLoading(false);
      }
    }
  }, [pushToast]);

  const loadTelemetryPreview = useCallback(async () => {
    setTelemetryLoading(true);
    try {
      const info = await ipc.inspectTelemetryData();
      if (!mountedRef.current) return;
      setTelemetryInfo(info);
    } catch (err) {
      if (mountedRef.current) {
        pushToast("读取遥测目录失败", String(err), "danger");
      }
    } finally {
      if (mountedRef.current) {
        setTelemetryLoading(false);
      }
    }
  }, [pushToast]);

  // 仅在首次挂载时扫描一次；后续仅当未读数严格增大（出现新日志触发）时才自动重扫，标为已读/归零不再重复扫盘
  useEffect(() => {
    if (prevUnreadRef.current === null) {
      prevUnreadRef.current = snapshot.unreadLogAnomalies;
      void loadLogs();
      return;
    }
    if (snapshot.unreadLogAnomalies > prevUnreadRef.current) {
      prevUnreadRef.current = snapshot.unreadLogAnomalies;
      void loadLogs();
      return;
    }
    prevUnreadRef.current = snapshot.unreadLogAnomalies;
  }, [snapshot.unreadLogAnomalies, loadLogs]);

  const handleSimulate = async () => {
    if (simBusy) return;
    setSimBusy(true);
    try {
      const ev = await ipc.simulateLogAnomaly();
      if (!mountedRef.current) return;
      setReport((prev) => ({
        events: [ev, ...prev.events],
        stats: {
          ...prev.stats,
          totalAnomalies: prev.stats.totalAnomalies + 1,
          regionOrRateCount: prev.stats.regionOrRateCount + 1,
        },
      }));
      setFilter("anomaly");
      setExpandedId(ev.id);
      pushToast(
        "模拟演示：高并发 429 联动预警",
        "已注入带「模拟演示」标记的测试事件并点亮安全守则，随时可点右上角「清空模拟」移除。",
        "danger",
        { badge: "模拟演示" }
      );
    } catch (err) {
      pushToast("注入模拟事件失败", String(err), "danger");
    } finally {
      if (mountedRef.current) setSimBusy(false);
    }
  };

  const handleClearSimulated = async () => {
    if (simBusy) return;
    setSimBusy(true);
    try {
      const removed = await ipc.clearSimulatedLogs();
      await loadLogs();
      pushToast("已清空模拟演示记录", `共移除 ${removed} 条模拟记录，当前仅保留本机真实扫描日志。`, "ok");
    } catch (err) {
      pushToast("清空模拟记录失败", String(err), "danger");
    } finally {
      if (mountedRef.current) setSimBusy(false);
    }
  };

  const handleToggleTelemetryViewer = () => {
    const next = !telemetryOpen;
    setTelemetryOpen(next);
    if (next) {
      void loadTelemetryPreview();
    }
  };

  const handleStatCardClick = (target: LogCategoryFilter, count: number) => {
    if (target === "telemetry") {
      setFilter((prev) => (prev === "telemetry" ? "all" : "telemetry"));
      setTelemetryOpen(true);
      void loadTelemetryPreview();
      return;
    }
    if (count === 0 && filter !== target) {
      return;
    }
    setFilter((prev) => (prev === target ? "all" : target));
  };

  const isEventAcked = (e: LogAnalysisReport["events"][number]) => {
    if (e.acked) return true;
    if (ackedLogIds.includes(e.id)) return true;
    if (e.collapsedIds && e.collapsedIds.length > 0) {
      return e.collapsedIds.every((cid) => ackedLogIds.includes(cid));
    }
    return false;
  };

  const unreadAnomalies = report.events.filter((e) => e.anomaly && !isEventAcked(e));
  const unreadCritCount = unreadAnomalies.filter((e) => e.level === "fail").length;
  const unreadWarnCount = unreadAnomalies.filter((e) => e.level === "warn").length;
  const regionRateCritCount = report.events.filter(
    (e) =>
      e.anomaly &&
      !isEventAcked(e) &&
      e.level === "fail" &&
      [
        "地区封锁",
        "高并发 429",
        "账号封禁",
        "账号连坐",
        "验证受限",
        "带凭证 403",
        "退出回传 403",
        "身份验证/权限",
        "OAuth v2 鉴权",
      ].includes(e.tag)
  ).length;
  const unreadBadgeText =
    unreadCritCount > 0 && unreadWarnCount > 0
      ? `风险 ${unreadWarnCount} · 异常 ${unreadCritCount}`
      : unreadCritCount > 0
      ? `异常 ${unreadCritCount}`
      : unreadWarnCount > 0
      ? `风险 ${unreadWarnCount}`
      : "0";
  const simulatedCount = report.events.filter((e) => e.simulated).length;

  const shown = (() => {
    switch (filter) {
      case "anomaly":
        return unreadAnomalies;
      case "region_rate":
        return report.events.filter((e) =>
          [
            "地区封锁",
            "高并发 429",
            "账号封禁",
            "账号连坐",
            "验证受限",
            "带凭证 403",
            "退出回传 403",
            "身份验证/权限",
            "OAuth v2 鉴权",
          ].includes(e.tag)
        );
      case "disconnect":
        return report.events.filter((e) => e.tag === "网络断连");
      case "telemetry":
        return report.events.filter((e) => ["遥测", "设备采集"].includes(e.tag));
      default:
        return report.events;
    }
  })();

  const filterTitleMap: Record<LogCategoryFilter, string> = {
    anomaly:
      unreadAnomalies.length === 0
        ? "24h 未读事件与触发归因（全部已读，仅在有新触发时重新提醒）"
        : unreadCritCount > 0
        ? `24h 未读事件与触发归因（风险 ${unreadWarnCount} · 异常 ${unreadCritCount}）`
        : `24h 未读风险提醒（风险 ${unreadWarnCount} · 异常 0）`,
    all: "全部监听行为与历史取证记录",
    region_rate: "已筛选：地区封锁 / 429 限流 / 鉴权与封号记录",
    disconnect: "已筛选：代理链路网络断连记录",
    telemetry: "已筛选：遥测 EventLogging 与设备采集记录",
  };

  const statusOk =
    snapshot.anthropicStatusIndicator === "none" || snapshot.anthropicStatusIndicator === "unknown";

  return (
    <section
      style={{
        display: "flex",
        flex: 1,
        minHeight: 0,
        flexDirection: "column",
        gap: embedded ? 12 : 0,
      }}
    >
      <div
        style={{
          padding: embedded ? "10px 14px" : "14px 22px",
          borderBottom: embedded ? undefined : "1px solid var(--divider)",
          border: embedded ? "1px solid var(--border-card)" : undefined,
          borderRadius: embedded ? "var(--r-card)" : undefined,
          background: embedded ? "var(--bg-card)" : "var(--bg-header)",
          boxShadow: embedded ? "var(--shadow-card)" : undefined,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          flexShrink: 0,
          flexWrap: "wrap",
        }}
      >
        <div style={{ minWidth: 0, display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {!embedded && (
            <h1 style={{ fontSize: 16.5, fontWeight: 500, letterSpacing: "-0.015em", margin: 0, color: "var(--text-strong)" }}>
              完整取证日志台
            </h1>
          )}
          <span
            data-testid="log-claude-official-status"
            className={`guard-chip ${statusOk ? "guard-chip-ok" : "guard-chip-warn"}`}
            title="Anthropic 官方状态页 API (status.anthropic.com/api/v2/summary.json)"
          >
            Claude 官方：{formatAnthropicStatusZh(snapshot.anthropicStatusIndicator, snapshot.anthropicStatusDesc)}
          </span>
          {!embedded && (
            <span style={{ fontSize: 11.5, color: "var(--text-3)" }}>
              24h 未读异常游标 · 原始日志绝不删改
            </span>
          )}
        </div>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "flex-end",
            gap: 8,
            flexWrap: "wrap",
            flexShrink: 0,
          }}
        >
          {simulatedCount > 0 && (
            <button
              type="button"
              className="guard-btn guard-btn-flat guard-btn-xs"
              onClick={() => void handleClearSimulated()}
            >
              <Trash2 size={12} strokeWidth={1.55} />
              <span>清空模拟 ({simulatedCount})</span>
            </button>
          )}
          {unreadAnomalies.length > 0 && (
            <button
              type="button"
              className="guard-btn guard-btn-flat guard-btn-xs"
              onClick={async () => {
                const allIds = unreadAnomalies.flatMap((e) =>
                  e.collapsedIds && e.collapsedIds.length > 0 ? [e.id, ...e.collapsedIds] : [e.id]
                );
                const ok = await ackAllLogIds(allIds);
                if (ok) {
                  pushToast(
                    "已将当前未读风险/异常全部标为已读",
                    "已推进持久化已读游标并同步悬浮窗归零，原始日志保留在「全部行为」中供随时取证。",
                    "ok"
                  );
                }
              }}
            >
              全部标为已读
            </button>
          )}
          <div className="in-seg" style={{ height: 27 }}>
            <button
              type="button"
              className={`in-seg-btn ${filter === "anomaly" ? "active" : ""}`}
              style={{ fontSize: 11.5, padding: "0 9px" }}
              onClick={() => setFilter("anomaly")}
            >
              仅看未读 ({unreadBadgeText})
            </button>
            <button
              type="button"
              className={`in-seg-btn ${filter === "all" ? "active" : ""}`}
              style={{ fontSize: 11.5, padding: "0 9px" }}
              onClick={() => setFilter("all")}
            >
              全部行为 ({report.events.length})
            </button>
          </div>
          <button
            type="button"
            disabled={loading}
            className="guard-btn guard-btn-flat guard-btn-xs"
            onClick={() => void loadLogs()}
          >
            {loading ? (
              <Loader2 size={12} strokeWidth={1.85} className="guard-spin" />
            ) : (
              <RefreshCw size={12} strokeWidth={1.5} />
            )}
            <span>{loading ? "扫描中..." : "扫描日志"}</span>
          </button>
          {(import.meta.env.DEV || import.meta.env.MODE === "test") && (
            <button
              type="button"
              className="guard-btn guard-btn-flat guard-btn-xs"
              onClick={() => void handleSimulate()}
            >
              + 模拟高并发 429 异常
            </button>
          )}
        </div>
      </div>

      <div
        style={{
          flex: 1,
          minHeight: 0,
          padding: embedded ? 0 : "16px 22px",
          overflowY: embedded ? "visible" : "auto",
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        {/* 时区跳变告警提示条（仅当检测到时区跳变时渲染） */}
        {report.stats.timezoneJumpWarning && (
          <div
            data-testid="log-tz-jump-warn"
            className="guard-card"
            style={{
              padding: "10px 14px",
              flexShrink: 0,
              display: "flex",
              alignItems: "center",
              gap: 10,
              fontSize: 12,
              color: "var(--text-2)",
              lineHeight: 1.5,
            }}
          >
            <span className="guard-chip guard-chip-warn" style={{ flexShrink: 0 }}>
              时区跳变
            </span>
            <span>{report.stats.timezoneJumpWarning}</span>
          </div>
        )}

        {/* v3.0 4 等分一体化统计筛选条（彻底消除窄容器文字折行挤压） */}
        <div className="guard-card metric-strip-equal tabular" style={{ flexShrink: 0 }}>
          <button
            type="button"
            data-testid="log-stat-unread"
            onClick={() => handleStatCardClick("anomaly", unreadAnomalies.length)}
            className="metric-cell"
            style={statCellBtnStyle(filter === "anomaly", unreadAnomalies.length > 0)}
          >
            <div style={statHeaderRow}>
              <span style={statTitleEllipsis}>24h 未读风险 / 异常</span>
              {filter === "anomaly" && (
                <span style={{ fontSize: 10, color: "var(--primary)", flexShrink: 0 }}>●</span>
              )}
            </div>
            <div
              style={{
                fontSize: 15,
                fontWeight: 500,
                letterSpacing: "-0.01em",
                marginTop: 5,
                lineHeight: 1.25,
                display: "flex",
                alignItems: "baseline",
                gap: 6,
                flexWrap: "wrap",
              }}
            >
              {unreadAnomalies.length === 0 ? (
                <span style={{ color: "var(--ok-fg)" }}>
                  0<span style={statUnitStyle}>已清零</span>
                </span>
              ) : (
                <>
                  {unreadWarnCount > 0 && (
                    <span style={{ color: "var(--warning-fg)" }}>风险 {unreadWarnCount}</span>
                  )}
                  {unreadCritCount > 0 && (
                    <span style={{ color: "var(--bad-fg)" }}>异常 {unreadCritCount}</span>
                  )}
                </>
              )}
            </div>
            <div style={statSubRow}>
              {unreadAnomalies.length === 0
                ? "全部已读归档"
                : unreadWarnCount > 0 && unreadCritCount === 0
                ? "异常 0 · 点击筛选"
                : "点击筛选未读项"}
            </div>
          </button>

          <button
            type="button"
            data-testid="log-stat-region-rate"
            onClick={() => handleStatCardClick("region_rate", report.stats.regionOrRateCount)}
            className="metric-cell"
            style={statCellBtnStyle(filter === "region_rate", report.stats.regionOrRateCount > 0)}
          >
            <div style={statHeaderRow}>
              <span style={statTitleEllipsis}>地区 / 429 / 鉴权</span>
              {filter === "region_rate" && (
                <span style={{ fontSize: 10, color: "var(--primary)", flexShrink: 0 }}>●</span>
              )}
            </div>
            <div
              style={{
                fontSize: 15,
                fontWeight: 500,
                letterSpacing: "-0.01em",
                marginTop: 5,
                lineHeight: 1.25,
                color:
                  report.stats.regionOrRateCount > 0
                    ? regionRateCritCount > 0
                      ? "var(--bad-fg)"
                      : "var(--warning-fg)"
                    : "var(--ok-fg)",
              }}
            >
              {report.stats.regionOrRateCount}
              <span style={statUnitStyle}>次</span>
            </div>
            <div style={statSubRow}>含封号 / 限流 / 权限</div>
          </button>

          <button
            type="button"
            data-testid="log-stat-disconnect"
            onClick={() => handleStatCardClick("disconnect", report.stats.disconnectCount)}
            className="metric-cell"
            style={statCellBtnStyle(filter === "disconnect", report.stats.disconnectCount > 0)}
          >
            <div style={statHeaderRow}>
              <span style={statTitleEllipsis}>网络断连累计</span>
              {filter === "disconnect" && (
                <span style={{ fontSize: 10, color: "var(--primary)", flexShrink: 0 }}>●</span>
              )}
            </div>
            <div
              style={{
                fontSize: 15,
                fontWeight: 500,
                letterSpacing: "-0.01em",
                marginTop: 5,
                lineHeight: 1.25,
                color: report.stats.disconnectCount > 0 ? "var(--warning-fg)" : "var(--ok-fg)",
              }}
            >
              {report.stats.disconnectCount}
              <span style={statUnitStyle}>次</span>
            </div>
            <div style={statSubRow}>代理长连接重置</div>
          </button>

          <button
            type="button"
            data-testid="log-stat-telemetry"
            onClick={() => handleStatCardClick("telemetry", report.stats.telemetryOrDeviceCount)}
            className="metric-cell"
            style={statCellBtnStyle(filter === "telemetry" || telemetryOpen, true)}
          >
            <div style={statHeaderRow}>
              <span style={statTitleEllipsis}>遥测 / 设备记录</span>
              {(filter === "telemetry" || telemetryOpen) && (
                <span style={{ fontSize: 10, color: "var(--primary)", flexShrink: 0 }}>●</span>
              )}
            </div>
            <div
              style={{
                fontSize: 15,
                fontWeight: 500,
                letterSpacing: "-0.01em",
                marginTop: 5,
                lineHeight: 1.25,
                color: "var(--text-strong)",
              }}
            >
              {report.stats.telemetryOrDeviceCount}
              <span style={statUnitStyle}>条</span>
            </div>
            <div style={{ ...statSubRow, color: "var(--primary)" }}>点击查看明细 ↗</div>
          </button>
        </div>

        {/* 本地遥测数据查看器（问题 9：点击「遥测 / 设备记录」即可查看遥测到底包含什么与脱敏文件内容） */}
        {telemetryOpen && (
          <div
            data-testid="telemetry-inspector-panel"
            className="guard-card"
            style={{ padding: 16, flexShrink: 0, display: "flex", flexDirection: "column", gap: 10 }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Database size={15} strokeWidth={1.8} />
                <span style={{ fontSize: 14, fontWeight: 600 }}>本地遥测数据与设备采集详情（脱敏只读）</span>
                {telemetryInfo && (
                  <span className="guard-chip guard-chip-neutral tabular">
                    {telemetryInfo.totalFiles} 个缓存文件 · {telemetryInfo.totalSizeLabel}
                  </span>
                )}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  type="button"
                  disabled={telemetryLoading}
                  className="guard-btn guard-btn-flat guard-btn-xs"
                  onClick={() => void loadTelemetryPreview()}
                >
                  {telemetryLoading ? "读取中..." : "刷新遥测目录"}
                </button>
                <button
                  type="button"
                  className="guard-btn guard-btn-flat guard-btn-xs"
                  onClick={handleToggleTelemetryViewer}
                >
                  收起
                </button>
              </div>
            </div>

            <div style={{ fontSize: 12, color: "var(--text-2)", lineHeight: 1.6 }}>
              {telemetryInfo?.explanation ??
                "正在读取本机 ~/.claude/telemetry/ 遥测缓存目录说明..."}
            </div>

            {telemetryInfo && (
              <div style={{ fontSize: 11.5, color: "var(--text-3)" }} className="font-mono-code">
                目录路径：{telemetryInfo.telemetryDir}
              </div>
            )}

            {telemetryLoading ? (
              <div style={{ fontSize: 12, color: "var(--text-2)", display: "flex", alignItems: "center", gap: 6 }}>
                <Loader2 size={13} className="guard-spin" />
                <span>正在读取本地遥测文件清单...</span>
              </div>
            ) : !telemetryInfo || telemetryInfo.files.length === 0 ? (
              <div
                style={{
                  padding: "10px 12px",
                  borderRadius: "var(--r-btn)",
                  background: "var(--bg-subtle)",
                  fontSize: 12,
                  color: "var(--success)",
                }}
              >
                当前 ~/.claude/telemetry/ 目录为空（0 B），无待上传的离线遥测缓存文件；下方列表展示的是日志中记录的历史遥测/设备采集行为。
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                {telemetryInfo.files.slice(0, 6).map((f) => (
                  <div
                    key={f.fileName}
                    style={{
                      border: "1px solid var(--border)",
                      borderRadius: "var(--r-btn)",
                      padding: "10px 12px",
                      background: "var(--bg-subtle)",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        fontSize: 12,
                        fontWeight: 500,
                        marginBottom: 6,
                      }}
                    >
                      <span className="font-mono-code">{f.fileName}</span>
                      <span className="tabular" style={{ color: "var(--text-3)" }}>
                        {f.sizeLabel} · {f.modifiedAt}
                      </span>
                    </div>
                    <pre
                      className="font-mono-code"
                      style={{
                        margin: 0,
                        fontSize: 11,
                        color: "var(--text-2)",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-all",
                        maxHeight: 120,
                        overflowY: "auto",
                      }}
                    >
                      {f.previewText}
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {noiseOpen && (report.stats.ignoredNoiseCount ?? 0) > 0 && (
          <div
            data-testid="noise-inspector-panel"
            className="guard-card"
            style={{ padding: 16, flexShrink: 0, display: "flex", flexDirection: "column", gap: 10 }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ fontSize: 14, fontWeight: 600 }}>已过滤无关噪音明细（只读）</span>
                <span className="guard-chip guard-chip-neutral tabular">
                  共 {report.stats.ignoredNoiseCount} 条
                </span>
              </div>
              <button
                type="button"
                className="guard-btn guard-btn-flat guard-btn-xs"
                onClick={() => setNoiseOpen(false)}
              >
                收起
              </button>
            </div>
            <div style={{ fontSize: 12, color: "var(--text-2)", lineHeight: 1.6 }}>
              以下为日志扫描器自动剔除的非风控类无关噪音记录，原始日志文件保持完整绝不删改。
            </div>
            {report.stats.ignoredNoiseBreakdown && report.stats.ignoredNoiseBreakdown.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {report.stats.ignoredNoiseBreakdown.map((item) => (
                  <div
                    key={item.label}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "8px 12px",
                      borderRadius: "var(--r-btn)",
                      border: "1px solid var(--border)",
                      background: "var(--bg-subtle)",
                      fontSize: 12,
                    }}
                  >
                    <span style={{ color: "var(--text-1)" }}>{item.label}</span>
                    <span className="guard-chip guard-chip-neutral tabular">{item.count} 条</span>
                  </div>
                ))}
              </div>
            ) : (
              <div
                style={{
                  padding: "10px 12px",
                  borderRadius: "var(--r-btn)",
                  background: "var(--bg-subtle)",
                  fontSize: 12,
                  color: "var(--text-2)",
                  lineHeight: 1.6,
                }}
              >
                默认过滤规则：自动排除非风控相关的常规界面渲染、心跳轮询、本地扩展加载与低级别调试输出，仅保留与风控、网络链路及账号安全相关的取证事件。
              </div>
            )}
          </div>
        )}

        <div className="guard-card" style={{ flexShrink: 0 }}>
          <div
            style={{
              padding: "10px 14px",
              background:
                filter === "anomaly" && unreadCritCount > 0
                  ? "var(--danger-soft)"
                  : filter === "anomaly" && unreadWarnCount > 0
                  ? "var(--warning-soft)"
                  : "var(--bg-subtle)",
              color:
                filter === "anomaly" && unreadCritCount > 0
                  ? "var(--danger-bright)"
                  : filter === "anomaly" && unreadWarnCount > 0
                  ? "var(--warning)"
                  : "var(--text-1)",
              fontSize: 12.5,
              fontWeight: 500,
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              borderBottom: "1px solid var(--divider)",
            }}
          >
            <span>{filterTitleMap[filter]}（点击条目展开原文上下文与安全守则联动）</span>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
              {(report.stats.ignoredNoiseCount ?? 0) > 0 && (
                <button
                  type="button"
                  data-testid="btn-toggle-noise-panel"
                  className="guard-btn guard-btn-flat guard-btn-xs tabular"
                  onClick={() => setNoiseOpen((prev) => !prev)}
                >
                  已过滤 {report.stats.ignoredNoiseCount} 条无关噪音 {noiseOpen ? "▴" : "▾"}
                </button>
              )}
              <span className="tabular" style={{ fontSize: 12, fontWeight: 500 }}>
                显示 {shown.length} 条记录
              </span>
            </div>
          </div>

          {shown.length === 0 ? (
            <div style={{ padding: 20, fontSize: 12.5, color: "var(--text-2)", lineHeight: 1.6 }}>
              当前筛选模式下暂无记录（监听文件数：{report.stats.watchingFiles.length}；可点击「全部行为」或上方其他统计卡切换查看）。
            </div>
          ) : (
            shown.map((ev) => {
              const isOpen = expandedId === ev.id;
              const isAcked = isEventAcked(ev);
              const isPollute =
                ev.tag !== "OAuth v2 鉴权" &&
                (ev.ruleId === "pb_pay" ||
                  ev.ruleId === "pb_exit" ||
                  ev.tag === "验证受限" ||
                  ev.tag === "退出回传 403" ||
                  ev.tag === "带凭证 403");
              return (
                <div
                  key={ev.id}
                  onClick={() => setExpandedId(isOpen ? null : ev.id)}
                  style={{
                    padding: "12px 14px",
                    borderBottom: "1px solid var(--border)",
                    cursor: "pointer",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      justifyContent: "space-between",
                      gap: 12,
                    }}
                  >
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                        <span
                          className={`guard-chip ${
                            isAcked
                              ? "guard-chip-neutral"
                              : ev.level === "fail"
                              ? "guard-chip-fail"
                              : ev.level === "warn"
                              ? "guard-chip-warn"
                              : "guard-chip-neutral"
                          }`}
                        >
                          {isAcked ? `${ev.tag} · 已读` : ev.tag}
                        </span>
                        {(ev.repeatCount ?? 1) > 1 && (
                          <span
                            className={`guard-chip font-mono-code tabular ${
                              ev.level === "fail" ? "guard-chip-fail" : "guard-chip-warn"
                            }`}
                          >
                            ×{ev.repeatCount}
                          </span>
                        )}
                        {ev.simulated && (
                          <span
                            className="guard-chip guard-chip-mode"
                            style={{ border: "1px dashed var(--primary)", color: "var(--primary)" }}
                          >
                            模拟演示
                          </span>
                        )}
                        <span style={{ fontSize: 13, fontWeight: 500 }}>{ev.title}</span>
                      </div>
                      <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 3 }}>
                        {ev.cause}
                      </div>
                    </div>
                    <div style={{ textAlign: "right", flexShrink: 0 }}>
                      <div className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
                        {ev.time}
                      </div>
                      <div
                        className="font-mono-code tabular"
                        style={{ fontSize: 11, color: "var(--text-2)", marginTop: 2 }}
                      >
                        {ev.file}
                      </div>
                    </div>
                  </div>

                  {isOpen && (
                    <div style={{ marginTop: 10 }}>
                      <div
                        className="font-mono-code tabular"
                        style={{
                          background: "var(--bg-subtle)",
                          border: "1px solid var(--border)",
                          borderRadius: "var(--r-btn)",
                          padding: "10px 12px",
                          fontSize: 11.5,
                          color: "var(--text-2)",
                          wordBreak: "break-all",
                          whiteSpace: "pre-wrap",
                        }}
                      >
                        {ev.context}
                      </div>
                      {ev.level === "fail" && ev.attributionClue && (
                        <div
                          data-testid="log-attribution-clue"
                          style={{ fontSize: 11.5, color: "var(--text-3)", marginTop: 6 }}
                        >
                          {ev.attributionClue}
                        </div>
                      )}
                      <div
                        style={{
                          marginTop: 8,
                          display: "flex",
                          gap: 8,
                          flexWrap: "wrap",
                          alignItems: "center",
                        }}
                      >
                        {ev.ruleId && (
                          <button
                            type="button"
                            className="guard-btn guard-btn-primary guard-btn-xs"
                            onClick={(e) => {
                              e.stopPropagation();
                              openPlaybookFocus(ev.ruleId!);
                            }}
                          >
                            查看联动安全守则
                          </button>
                        )}
                        {ev.anomaly && !isAcked && isPollute && (
                          <button
                            type="button"
                            data-testid="btn-log-backup-clean"
                            className="guard-btn guard-btn-danger-soft guard-btn-xs"
                            onClick={(e) => {
                              e.stopPropagation();
                              openCleanModal({
                                sourceLabel: `来自完整取证日志台 · ${ev.tag}`,
                                onCompleted: async () => {
                                  await loadLogs();
                                },
                              });
                            }}
                          >
                            <span>退出登录并清理（备份）本地污染目录</span>
                          </button>
                        )}
                        {ev.anomaly && !isAcked ? (
                          <button
                            type="button"
                            className="guard-btn guard-btn-flat guard-btn-xs"
                            onClick={async (e) => {
                              e.stopPropagation();
                              const idsToAck =
                                ev.collapsedIds && ev.collapsedIds.length > 0
                                  ? [ev.id, ...ev.collapsedIds]
                                  : [ev.id];
                              const ok = await ackLogIds(idsToAck);
                              if (ok) {
                                pushToast(
                                  "已标为已读（推进游标）",
                                  "已解除此条告警提醒并同步悬浮窗，原始日志文件保持完整未删改。",
                                  "ok"
                                );
                              }
                            }}
                          >
                            标为已读（推进游标）
                          </button>
                        ) : (
                          isAcked && (
                            <span className="guard-chip guard-chip-neutral">
                              已读归档（原日志未删）
                            </span>
                          )
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </section>
  );
}

const statHeaderRow: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 6,
  fontSize: 11,
  color: "var(--text-3)",
  width: "100%",
  minWidth: 0,
};

const statTitleEllipsis: React.CSSProperties = {
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
  minWidth: 0,
};

const statSubRow: React.CSSProperties = {
  marginTop: 3,
  fontSize: 10.5,
  color: "var(--text-3)",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

const statUnitStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 400,
  color: "var(--text-3)",
  marginLeft: 3,
};

function statCellBtnStyle(selected: boolean, interactive: boolean): React.CSSProperties {
  return {
    border: "none",
    background: selected ? "var(--sel-bar-bg)" : "transparent",
    boxShadow: selected ? "inset 0 -2px 0 var(--primary)" : "none",
    textAlign: "left",
    fontFamily: "var(--font-sans)",
    cursor: interactive ? "pointer" : "default",
    transition: "background-color 140ms var(--ease), box-shadow 140ms var(--ease)",
  };
}
