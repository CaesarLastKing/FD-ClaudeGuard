import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  LifeBuoy,
  Loader2,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Undo2,
} from "lucide-react";
import { ipc } from "@/lib/ipc";
import { useGuardStore } from "@/stores/guardStore";
import type { NetworkRescueReport, RollbackOverview } from "@/types/guard";

interface NetworkRescueRollbackPanelProps {
  /** 当未激活态展示在锁定卡片下方时采用紧凑模式 */
  compact?: boolean;
}

/**
 * 无门槛「一键网络急救」与「系统改动与撤回中心」
 *
 * 铁律：
 * - 任何状态（含未激活态 / 授权到期 / Clash 离线）均允许救网与撤回本工具改动；
 * - 严格遵守 Design Tokens，深浅双主题高对比、单行按钮不折行。
 */
export function NetworkRescueRollbackPanel({ compact = false }: NetworkRescueRollbackPanelProps) {
  const [overview, setOverview] = useState<RollbackOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [rescueReport, setRescueReport] = useState<NetworkRescueReport | null>(null);

  const snapshot = useGuardStore((s) => s.snapshot);
  const pushToast = useGuardStore((s) => s.pushToast);
  const openRiskModal = useGuardStore((s) => s.openRiskModal);
  const refreshPreflight = useGuardStore((s) => s.refreshPreflight);

  const loadOverview = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const data = await ipc.inspectRollbackStatus();
      setOverview(data);
    } catch (err) {
      setLoadError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadOverview();
  }, [loadOverview, snapshot.killSwitchActive]);

  const busy = busyKey !== null;
  const hasLoopbackDns = (overview?.loopbackDnsAdapters.length ?? 0) > 0;
  // 区分「正常熔断保护生效中的防火墙规则」与「非熔断态下的异常残留规则」，避免正常熔断时误报残留故障
  const hasResidualFirewall = Boolean(overview?.activeFirewallRules) && !snapshot.killSwitchActive;
  const hasNetworkAlert = hasLoopbackDns || hasResidualFirewall;

  const handleRunRescue = async () => {
    setBusyKey("rescue");
    try {
      const report = await ipc.runNetworkEmergencyRescue();
      setRescueReport(report);
      await loadOverview();
      pushToast(
        report.ok ? "网络急救完成" : "网络急救已执行（请查看明细）",
        report.summary,
        report.ok ? "ok" : "info"
      );
      void refreshPreflight(true);
    } catch (err) {
      pushToast("网络急救失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleRollbackOne = (itemId: string, title: string, riskNote: string) => {
    openRiskModal({
      tone: "warn",
      badge: "精准撤回",
      title: `撤回：${title}`,
      subtitle: "按首次修改前锁定的系统基线快照精准还原此项设置",
      rows: [
        { label: "还原对象", value: title },
        { label: "安全承诺", value: riskNote },
      ],
      primaryLabel: "暂不撤回",
      onPrimary: () => {},
      dangerLabel: "确认撤回此项",
      onDanger: async () => {
        setBusyKey(`one:${itemId}`);
        try {
          const rep = await ipc.rollbackSingleItem(itemId);
          setOverview(rep.overview);
          pushToast(
            rep.ok ? "单项撤回完成" : "单项撤回未完成",
            rep.message,
            rep.ok ? "ok" : "danger"
          );
          void refreshPreflight(true);
        } catch (err) {
          pushToast("撤回失败", String(err), "danger");
        } finally {
          setBusyKey(null);
        }
      },
    });
  };

  const handleRollbackAll = () => {
    const count = overview?.touchedCount ?? 0;
    if (count === 0) return;
    openRiskModal({
      tone: "warn",
      badge: "全量还原",
      title: `一键撤回全部 ${count} 项本工具改动`,
      subtitle: "将按安全逆序逐项还原系统与 Clash 配置，适合卸载前或排查冲突时使用",
      rows: [
        { label: "预计撤回项数", value: `${count} 项（仅撤回本工具改动过的项目）` },
        {
          label: "订阅与数据保护",
          value: "100% 保留你后续新导入的 Clash 订阅与现有项目代码，不覆盖用户数据。",
        },
      ],
      primaryLabel: "暂不撤回",
      onPrimary: () => {},
      dangerLabel: "确认全部撤回",
      onDanger: async () => {
        setBusyKey("all");
        try {
          const rep = await ipc.rollbackAllChanges();
          setOverview(rep.overview);
          pushToast(
            rep.allOk ? "已还原全部改动" : "部分项目撤回需关注",
            rep.summary,
            rep.allOk ? "ok" : "info"
          );
          void refreshPreflight(true);
        } catch (err) {
          pushToast("批量撤回失败", String(err), "danger");
        } finally {
          setBusyKey(null);
        }
      },
    });
  };

  return (
    <div
      data-testid="network-rescue-rollback-panel"
      style={{ display: "flex", flexDirection: "column", gap: compact ? 12 : 16 }}
    >
      {/* 第一块：无门槛「一键网络急救」（专治关 TUN 全网断 / 导不了订阅） */}
      <div
        className="guard-card"
        style={{
          padding: compact ? "14px 16px" : "16px 18px",
          borderColor: hasNetworkAlert ? "var(--danger)" : "var(--border)",
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 14,
            flexWrap: "wrap",
          }}
        >
          <div style={{ display: "flex", alignItems: "flex-start", gap: 12, flex: 1, minWidth: 260 }}>
            <div
              style={{
                width: 36,
                height: 36,
                borderRadius: 10,
                background: hasNetworkAlert ? "var(--danger-soft)" : "var(--primary-soft)",
                color: hasNetworkAlert ? "var(--danger-bright)" : "var(--primary)",
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
              }}
            >
              <LifeBuoy size={18} strokeWidth={1.85} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <span style={{ fontSize: 14.5, fontWeight: 600, color: "var(--text-1)" }}>
                  一键网络急救（关代理 / 关 TUN 也能正常上网）
                </span>
                {hasNetworkAlert && (
                  <span className="guard-chip guard-chip-fail">
                    <AlertTriangle size={11} strokeWidth={2} />
                    <span>
                      {hasLoopbackDns
                        ? `检测到死 DNS：${overview?.loopbackDnsAdapters.join("、")}`
                        : "检测到残留防火墙规则"}
                    </span>
                  </span>
                )}
                {!hasNetworkAlert && snapshot.killSwitchActive && overview?.activeFirewallRules && (
                  <span className="guard-chip guard-chip-warn">
                    熔断防护生效中（防火墙已封锁 Claude 出站）
                  </span>
                )}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4, lineHeight: 1.55 }}>
                若关闭 TUN 或卸载重装 Clash 后出现国内外全断网、无法导入订阅链接，点击右侧一键恢复物理网卡 DHCP DNS、清除失效系统代理与本工具防火墙阻断，并现场实测国内直连。
              </div>
            </div>
          </div>

          <button
            type="button"
            data-testid="btn-network-emergency-rescue"
            className={`guard-btn guard-btn-sm ${hasNetworkAlert ? "guard-btn-danger-soft" : "guard-btn-primary"}`}
            disabled={busy}
            onClick={() => void handleRunRescue()}
            style={{ whiteSpace: "nowrap", flexShrink: 0 }}
          >
            {busyKey === "rescue" ? (
              <Loader2 size={14} className="guard-spin" />
            ) : (
              <LifeBuoy size={14} strokeWidth={1.9} />
            )}
            <span>{busyKey === "rescue" ? "急救执行中..." : "一键执行网络急救"}</span>
          </button>
        </div>

        {rescueReport && (
          <div
            data-testid="network-rescue-result"
            style={{
              background: "var(--bg-subtle)",
              border: "1px solid var(--border)",
              borderRadius: 10,
              padding: "10px 12px",
              display: "flex",
              flexDirection: "column",
              gap: 6,
            }}
          >
            <div
              style={{
                fontSize: 12.5,
                fontWeight: 600,
                color: rescueReport.ok ? "var(--success)" : "var(--warning)",
                display: "flex",
                alignItems: "center",
                gap: 6,
              }}
            >
              {rescueReport.ok ? (
                <CheckCircle2 size={14} strokeWidth={2} />
              ) : (
                <AlertTriangle size={14} strokeWidth={2} />
              )}
              <span>{rescueReport.summary}</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {rescueReport.steps.map((s) => (
                <div
                  key={s.step}
                  style={{
                    fontSize: 12,
                    color: "var(--text-2)",
                    display: "flex",
                    alignItems: "baseline",
                    gap: 8,
                  }}
                >
                  <span
                    style={{
                      fontWeight: 600,
                      color: s.ok ? "var(--success)" : "var(--danger-bright)",
                      flexShrink: 0,
                    }}
                  >
                    {s.ok ? "✓" : "✗"} {s.step}：
                  </span>
                  <span>{s.detail}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* 第二块：系统改动与撤回中心（6 项精准单项撤回 + 一键全撤） */}
      <div
        className="guard-card"
        style={{
          padding: compact ? "14px 16px" : "16px 18px",
          display: "flex",
          flexDirection: "column",
          gap: 12,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div
              style={{
                width: 34,
                height: 34,
                borderRadius: 10,
                background: "var(--bg-subtle)",
                color: "var(--text-1)",
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
              }}
            >
              <RotateCcw size={16} strokeWidth={1.85} />
            </div>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <span style={{ fontSize: 14.5, fontWeight: 600, color: "var(--text-1)" }}>
                  系统改动与撤回中心
                </span>
                <span className="guard-chip guard-chip-mode tabular">
                  {loadError
                    ? "状态读取失败"
                    : `已记录改动 ${overview?.touchedCount ?? 0} 项`}
                </span>
              </div>
              <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 2 }}>
                每次修改系统或 Clash 前自动锁定首次原始基线；随时支持单项精准撤回或一键还原，100% 保留后续新增订阅。
              </div>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
            <button
              type="button"
              className="guard-btn guard-btn-flat guard-btn-sm"
              disabled={busy || loading}
              onClick={() => void loadOverview()}
              style={{ whiteSpace: "nowrap" }}
            >
              <RefreshCw size={13} className={loading ? "guard-spin" : ""} />
              <span>刷新</span>
            </button>
            <button
              type="button"
              data-testid="btn-rollback-all"
              className="guard-btn guard-btn-secondary guard-btn-sm"
              disabled={busy || (overview?.touchedCount ?? 0) === 0}
              onClick={handleRollbackAll}
              style={{ whiteSpace: "nowrap" }}
            >
              {busyKey === "all" ? (
                <Loader2 size={13} className="guard-spin" />
              ) : (
                <Undo2 size={13} strokeWidth={1.9} />
              )}
              <span>
                {busyKey === "all"
                  ? "正在全量撤回..."
                  : `一键撤回全部改动 (${overview?.touchedCount ?? 0})`}
              </span>
            </button>
          </div>
        </div>

        {loading && !overview ? (
          <div style={{ fontSize: 12, color: "var(--text-3)", padding: "8px 0" }}>
            正在读取系统基线快照...
          </div>
        ) : loadError && !overview ? (
          <div
            data-testid="rollback-load-error"
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              padding: "12px 14px",
              borderRadius: 10,
              background: "var(--danger-soft)",
              border: "1px solid var(--danger-border)",
              color: "var(--danger-bright)",
              fontSize: 12.5,
            }}
          >
            <span>读取撤回基线失败：{loadError}</span>
            <button
              type="button"
              data-testid="btn-retry-rollback-overview"
              className="guard-btn guard-btn-flat guard-btn-sm"
              onClick={() => void loadOverview()}
              style={{ whiteSpace: "nowrap" }}
            >
              重新读取
            </button>
          </div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {(overview?.items ?? []).map((item) => {
              const itemBusy = busyKey === `one:${item.id}`;
              return (
                <div
                  key={item.id}
                  data-testid={`rollback-row-${item.id}`}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 12,
                    padding: "10px 12px",
                    borderRadius: 10,
                    background: "var(--bg-subtle)",
                    border: "1px solid var(--border)",
                  }}
                >
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <span className="guard-chip guard-chip-mode">{item.category}</span>
                      <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text-1)" }}>
                        {item.title}
                      </span>
                      {item.touchedByGuard ? (
                        <span className="guard-chip guard-chip-warn">本工具已改动 · 可撤回</span>
                      ) : (
                        <span className="guard-chip guard-chip-ok">
                          <ShieldCheck size={11} strokeWidth={2} />
                          <span>未改动</span>
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4, lineHeight: 1.45 }}>
                      <span>当前：{item.currentSummary}</span>
                      <span style={{ margin: "0 6px", color: "var(--text-3)" }}>|</span>
                      <span>原态：{item.originalSummary}</span>
                    </div>
                    <div style={{ fontSize: 11.5, color: "var(--text-3)", marginTop: 2 }}>
                      {item.riskNote}
                    </div>
                  </div>

                  <button
                    type="button"
                    data-testid={`btn-rollback-${item.id}`}
                    className="guard-btn guard-btn-flat guard-btn-sm"
                    disabled={busy || !item.canRollback}
                    onClick={() => handleRollbackOne(item.id, item.title, item.riskNote)}
                    style={{ whiteSpace: "nowrap", flexShrink: 0 }}
                  >
                    {itemBusy ? (
                      <Loader2 size={13} className="guard-spin" />
                    ) : (
                      <RotateCcw size={13} strokeWidth={1.85} />
                    )}
                    <span>{itemBusy ? "撤回中..." : item.canRollback ? "撤回此项" : "无需撤回"}</span>
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
