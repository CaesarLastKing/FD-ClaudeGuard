import { useEffect, useRef, useState } from "react";
import { Globe, Home, Loader2, Settings, Shield, ShieldCheck, Sparkles } from "lucide-react";
import { ipc, isTauriRuntime } from "@/lib/ipc";
import { useGuardStore } from "@/stores/guardStore";
import type { NavTab } from "@/types/guard";

const NAV_ITEMS: Array<{
  id: NavTab;
  label: string;
  renderIcon: (active: boolean) => React.ReactNode;
}> = [
  {
    id: "console",
    label: "控制台",
    renderIcon: (active) => (
      <Home
        size={15}
        strokeWidth={active ? 1.55 : 1.4}
        style={{ color: active ? "var(--nav-active-fg, var(--text-strong))" : "var(--text-3)", flexShrink: 0 }}
      />
    ),
  },
  {
    id: "audit",
    label: "账户审计",
    renderIcon: (active) => (
      <ShieldCheck
        size={15}
        strokeWidth={active ? 1.55 : 1.4}
        style={{ color: active ? "var(--nav-active-fg, var(--text-strong))" : "var(--text-3)", flexShrink: 0 }}
      />
    ),
  },
  {
    id: "nodes",
    label: "节点流量",
    renderIcon: (active) => (
      <Globe
        size={15}
        strokeWidth={active ? 1.55 : 1.4}
        style={{ color: active ? "var(--nav-active-fg, var(--text-strong))" : "var(--text-3)", flexShrink: 0 }}
      />
    ),
  },
  {
    id: "aitools",
    label: "AI 工具箱",
    renderIcon: (active) => (
      <Sparkles
        size={15}
        strokeWidth={active ? 1.55 : 1.4}
        style={{ color: active ? "var(--nav-active-fg, var(--text-strong))" : "var(--text-3)", flexShrink: 0 }}
      />
    ),
  },
];

export function Sidebar() {
  const activeTab = useGuardStore((s) => s.activeTab);
  const setActiveTab = useGuardStore((s) => s.setActiveTab);
  const settingsModalOpen = useGuardStore((s) => s.settingsModalOpen);
  const openSettingsModal = useGuardStore((s) => s.openSettingsModal);
  const networkRescueAlert = useGuardStore((s) => s.networkRescueAlert);
  const setNetworkRescueAlert = useGuardStore((s) => s.setNetworkRescueAlert);
  const setRollbackOverview = useGuardStore((s) => s.setRollbackOverview);
  const preflight = useGuardStore((s) => s.preflight);
  const snapshot = useGuardStore((s) => s.snapshot);
  const accountAudit = useGuardStore((s) => s.accountAudit);
  const config = useGuardStore((s) => s.config);
  const setSnapshot = useGuardStore((s) => s.setSnapshot);
  const openRiskModal = useGuardStore((s) => s.openRiskModal);
  const refreshPreflight = useGuardStore((s) => s.refreshPreflight);
  const pushToast = useGuardStore((s) => s.pushToast);
  const [busyKill, setBusyKill] = useState(false);

  const holdActive = Boolean(snapshot.killHoldActive);
  const holdSecs = snapshot.killHoldRemainingSecs ?? 0;
  const holdBlocked = snapshot.killHoldBlockedCount ?? 0;
  const holdTx = Boolean(snapshot.killHoldTxLocked);
  const ksLinkedHold = Boolean(snapshot.killSwitchActive) && holdActive;
  const defaultHoldSecs = config.killHoldSeconds ?? 45;

  const mustAll = preflight.items.filter((x) => x.part === "must");
  const mustPending = mustAll.filter((x) => x.status !== "ok").length;
  const mustHardFail = mustAll.filter((x) => x.status === "fail").length;
  const mustFail = mustPending;

  // 节点流量侧边栏角标双重兜底
  const nodeGeoItem = preflight.items.find((x) => x.id === "node_geo");
  const hasNodeFail = Boolean(snapshot.nodeDown) || nodeGeoItem?.status === "fail";
  const hasNodeIssue =
    hasNodeFail || snapshot.activeFlowAnomalies > 0 || nodeGeoItem?.status === "warn";

  const sideDotClass = snapshot.clashOnline ? "guard-dot" : "guard-dot danger";

  // 真实 Tauri 客户端静默探测死 DNS / 异常防火墙残留，点亮左下角「需急救」红点（仅真实变化时写 store，零多余渲染）
  useEffect(() => {
    if (!isTauriRuntime()) return;
    let cancelled = false;
    void ipc
      .inspectRollbackStatus()
      .then((overview) => {
        if (cancelled) return;
        setRollbackOverview(overview);
        const hasLoopbackDns = (overview.loopbackDnsAdapters?.length ?? 0) > 0;
        const hasResidualFw = Boolean(overview.activeFirewallRules) && !snapshot.killSwitchActive;
        const nextAlert = hasLoopbackDns || hasResidualFw;
        if (nextAlert !== useGuardStore.getState().networkRescueAlert) {
          setNetworkRescueAlert(nextAlert);
        }
      })
      .catch((err) => {
        void ipc.logFrontendEvent("WARN", "Sidebar", `检测撤回基线状态失败: ${String(err)}`);
      });
    return () => {
      cancelled = true;
    };
  }, [snapshot.killSwitchActive, setNetworkRescueAlert, setRollbackOverview]);

  const [interceptFlash, setInterceptFlash] = useState(false);
  const prevBlockedRef = useRef(holdBlocked);
  const flashTimerRef = useRef<number | null>(null);
  useEffect(() => {
    if (holdBlocked > prevBlockedRef.current) {
      setInterceptFlash(true);
      if (flashTimerRef.current !== null) {
        window.clearTimeout(flashTimerRef.current);
      }
      flashTimerRef.current = window.setTimeout(() => {
        setInterceptFlash(false);
        flashTimerRef.current = null;
      }, 1500);
    }
    prevBlockedRef.current = holdBlocked;
  }, [holdBlocked]);
  useEffect(() => {
    return () => {
      if (flashTimerRef.current !== null) {
        window.clearTimeout(flashTimerRef.current);
      }
    };
  }, []);

  const appVersionLabel =
    typeof __APP_VERSION__ === "string" && __APP_VERSION__ ? `v${__APP_VERSION__}` : "v0.4.3";

  return (
    <aside
      style={{
        width: "clamp(220px, 16.5vw, 248px)",
        flexShrink: 0,
        background: "var(--bg-sidebar)",
        borderRight: "1px solid var(--divider)",
        padding: "12px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
      }}
    >
      <nav aria-label="主导航" style={{ display: "flex", flexDirection: "column", gap: 3 }}>
        {NAV_ITEMS.map((item) => {
          const isActive =
            activeTab === item.id || (item.id === "audit" && activeTab === "logs");
          return (
            <button
              key={item.id}
              type="button"
              className={`c-nav-item ${isActive ? "active" : ""}`}
              onClick={() => setActiveTab(item.id)}
            >
              <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
                {item.renderIcon(isActive)}
                <span>{item.label}</span>
              </span>

              {item.id === "console" && (
                <span
                  className="tabular"
                  style={{
                    ...navBadgeStyle,
                    background:
                      mustHardFail > 0
                        ? "var(--bad-bg)"
                        : mustPending > 0
                        ? "var(--warning-soft)"
                        : "var(--ok-bg)",
                    color:
                      mustHardFail > 0
                        ? "var(--bad-fg)"
                        : mustPending > 0
                        ? "var(--warning-fg)"
                        : "var(--ok-fg)",
                  }}
                >
                  {mustPending > 0 ? mustPending : "OK"}
                </span>
              )}

              {item.id === "nodes" && hasNodeIssue && (
                <span
                  data-testid="nav-badge-nodes"
                  className="tabular"
                  style={{
                    ...navBadgeStyle,
                    background: hasNodeFail ? "var(--bad-bg)" : "var(--warning-soft)",
                    color: hasNodeFail ? "var(--danger-bright)" : "var(--warning)",
                  }}
                >
                  {Math.max(1, snapshot.activeFlowAnomalies)}
                </span>
              )}

              {item.id === "audit" &&
                (() => {
                  const hasSplit =
                    snapshot.unreadLogCritical !== undefined ||
                    snapshot.unreadLogWarnings !== undefined;
                  const crit = hasSplit
                    ? snapshot.unreadLogCritical ?? 0
                    : snapshot.unreadLogAnomalies;
                  const warn = hasSplit ? snapshot.unreadLogWarnings ?? 0 : 0;
                  const logTotal = hasSplit ? crit + warn : snapshot.unreadLogAnomalies;
                  const auditPending = accountAudit?.pendingIssueCount ?? 0;
                  const auditDanger = Boolean(accountAudit?.hasDangerIssue);
                  const total = Math.max(auditPending, logTotal);
                  const isCrit = crit > 0 || auditDanger;
                  if (total <= 0) {
                    return (
                      <span
                        data-testid="nav-badge-audit"
                        className="tabular"
                        style={{
                          ...navBadgeStyle,
                          background: "var(--ok-bg)",
                          color: "var(--ok-fg)",
                        }}
                      >
                        OK
                      </span>
                    );
                  }
                  return (
                    <span
                      data-testid="nav-badge-audit"
                      title={`审计待处理 ${auditPending} · 日志风险 ${warn} · 异常 ${crit}`}
                      className="tabular"
                      style={{
                        ...navBadgeStyle,
                        background: isCrit ? "var(--bad-bg)" : "var(--warning-soft)",
                        color: isCrit ? "var(--bad-fg)" : "var(--warning-fg)",
                      }}
                    >
                      {crit > 0 ? crit : total}
                    </span>
                  );
                })()}
            </button>
          );
        })}
      </nav>

      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {/* Claude 进程雷达 & Kill-Hold 防复活持续盯防卡 */}
        <div
          data-testid="sidebar-proc-card"
          className={`guard-card ${interceptFlash ? "guard-intercept-flash" : ""}`.trim()}
          style={{
            padding: "10px 12px",
            display: "flex",
            flexDirection: "column",
            gap: 6,
            border: holdActive
              ? "1px solid var(--primary-border)"
              : "1px solid var(--border)",
            background: holdActive ? "var(--primary-soft)" : "var(--bg-card)",
          }}
        >
          <div style={statusRowStyle}>
            <span
              style={{
                display: "flex",
                alignItems: "center",
                gap: 7,
                fontSize: 12,
                color: "var(--text-1)",
              }}
            >
              <span
                className={`guard-dot ${
                  holdActive ? "hold" : snapshot.bgClaudeProcs > 0 ? "warn" : ""
                }`}
              />
              <span>Claude 进程</span>
            </span>
            <span
              className="tabular"
              data-testid="sidebar-proc-status"
              style={{
                fontSize: 11,
                fontWeight: holdActive ? 500 : 400,
                color: holdActive
                  ? "var(--primary)"
                  : snapshot.bgClaudeProcs > 0
                  ? "var(--warning-fg)"
                  : "var(--text-3)",
              }}
            >
              {holdActive
                ? ksLinkedHold
                  ? "熔断联动锁定"
                  : holdTx
                  ? "事务盯防中"
                  : `盯防 ${holdSecs}s`
                : snapshot.bgClaudeProcs > 0
                ? `${snapshot.bgClaudeProcs} 存活`
                : "0 残留"}
            </span>
          </div>

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 7,
            }}
          >
            <span
              title={
                holdActive
                  ? ksLinkedHold
                    ? holdBlocked > 0
                      ? `防火墙已封锁 · 已拦截 ${holdBlocked} 次复活`
                      : "随防火墙熔断联动 · 250ms 防复活"
                    : holdBlocked > 0
                    ? `已拦截 ${holdBlocked} 次 Claude 非安全启动`
                    : "250ms 防复活盯防中"
                  : snapshot.bgClaudeProcs > 0
                  ? "运行中 · 切代理前建议清退并盯防"
                  : "已彻底退出，可安全操作"
              }
              style={{
                fontSize: 11,
                color: "var(--text-3)",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
                minWidth: 0,
              }}
            >
              {holdActive
                ? holdBlocked > 0
                  ? `防复活生效中 · 已拦截 ${holdBlocked} 次`
                  : ksLinkedHold
                  ? "随防火墙熔断联动护航中"
                  : "250ms 防复活盯防中"
                : snapshot.bgClaudeProcs > 0
                ? "运行中 · 切代理前建议清退"
                : "已彻底退出，可安全操作"}
            </span>

            {holdActive ? (
              <button
                type="button"
                data-testid="btn-release-kill-hold"
                disabled={busyKill}
                className={ksLinkedHold ? "guard-btn guard-btn-danger-soft guard-btn-xs" : "guard-btn guard-btn-flat guard-btn-xs"}
                style={{ width: "100%", height: 28, justifyContent: "center" }}
                title={ksLinkedHold ? "解除防火墙熔断并释放防复活盯防锁" : "解除当前防复活盯防锁"}
                onClick={async () => {
                  if (ksLinkedHold) {
                    openRiskModal({
                      tone: "warn",
                      badge: "解除熔断与盯防",
                      title: "确认解除防火墙熔断并释放盯防锁？",
                      subtitle:
                        "当前防复活盯防与防火墙出站熔断联动生效，解除后将同步清理阻断规则并恢复通信",
                      rows: [
                        {
                          label: "当前保护",
                          value: "防火墙已封锁 Claude 出站 + 250ms 进程防复活联动锁定中",
                          tone: "danger",
                        },
                        {
                          label: "环境复核",
                          value:
                            mustFail > 0
                              ? `当前仍有 ${mustFail} 项必须体检未通过，建议确认网络恢复后再放行`
                              : `当前 ${mustAll.length} 项必须体检已全部通过，可安全解除熔断与盯防锁`,
                          tone: mustFail > 0 ? "danger" : "ok",
                        },
                      ],
                      primaryLabel: "确认解除熔断并解锁",
                      onPrimary: async () => {
                        setBusyKill(true);
                        try {
                          await ipc.forceReleaseKillswitch(true);
                          pushToast(
                            "已解除熔断与盯防锁",
                            "防火墙阻断规则与防复活锁已同步释放，正在重跑真实探针复核。",
                            "ok"
                          );
                          await refreshPreflight(true);
                        } catch (err) {
                          pushToast("解除熔断失败", String(err), "danger");
                        } finally {
                          setBusyKill(false);
                        }
                      },
                    });
                    return;
                  }
                  setBusyKill(true);
                  try {
                    const hs = await ipc.releaseKillHold();
                    const latest = useGuardStore.getState().snapshot;
                    setSnapshot({
                      ...latest,
                      killHoldActive: hs.active,
                      killHoldRemainingSecs: hs.remainingSecs,
                      killHoldBlockedCount: hs.blockedCount,
                      killHoldTxLocked: hs.txLocked,
                    });
                    pushToast(
                      "已解除防复活盯防锁",
                      "已停止 250ms 强杀盯防，现在可按需安全启动 Claude。",
                      "info"
                    );
                  } catch (err) {
                    pushToast("解除盯防锁失败", String(err), "danger");
                  } finally {
                    setBusyKill(false);
                  }
                }}
              >
                {busyKill && <Loader2 size={11.5} strokeWidth={1.9} className="guard-spin" />}
                <span>{ksLinkedHold ? "解除熔断与盯防锁" : "解除防复活盯防锁"}</span>
              </button>
            ) : snapshot.bgClaudeProcs > 0 ? (
              <button
                type="button"
                data-testid="btn-kill-and-hold"
                disabled={busyKill}
                className="guard-btn guard-btn-xs"
                style={{
                  width: "100%",
                  height: 28,
                  justifyContent: "center",
                  background: "var(--hold-btn-bg)",
                  border: "1px solid var(--hold-btn-border)",
                  color: "var(--hold-btn-fg)",
                  boxShadow: "none",
                }}
                title={`强杀全部 Claude 进程并开启 ${defaultHoldSecs}s 防复活盯防`}
                onClick={async () => {
                  setBusyKill(true);
                  try {
                    const rep = await ipc.killClaudeProcesses(true);
                    const latest = useGuardStore.getState().snapshot;
                    setSnapshot({
                      ...latest,
                      bgClaudeProcs: rep.afterCount,
                      killHoldActive: rep.killHoldActive ?? true,
                      killHoldRemainingSecs: rep.killHoldRemainingSecs ?? defaultHoldSecs,
                    });
                    pushToast("已强杀 Claude 并启动防复活盯防", rep.message, "ok");
                  } catch (err) {
                    pushToast("强杀 Claude 进程失败", String(err), "danger");
                  } finally {
                    setBusyKill(false);
                  }
                }}
              >
                {busyKill ? (
                  <Loader2 size={11.5} strokeWidth={1.9} className="guard-spin" />
                ) : (
                  <Shield size={11.5} strokeWidth={1.55} />
                )}
                <span>{busyKill ? "强杀中..." : `强杀防复活盯防 (${defaultHoldSecs}s)`}</span>
              </button>
            ) : (
              <button
                type="button"
                data-testid="btn-start-kill-hold"
                disabled={busyKill}
                className="guard-btn guard-btn-xs"
                style={{
                  width: "100%",
                  height: 28,
                  justifyContent: "center",
                  background: "var(--hold-btn-bg)",
                  border: "1px solid var(--hold-btn-border)",
                  color: "var(--hold-btn-fg)",
                  boxShadow: "none",
                }}
                title={`开启 ${defaultHoldSecs}s 防复活盯防锁，防止切代理期间 Claude 后台自启`}
                onClick={async () => {
                  setBusyKill(true);
                  try {
                    const hs = await ipc.startKillHold(defaultHoldSecs, "手动开启防复活持续盯防锁");
                    const latest = useGuardStore.getState().snapshot;
                    setSnapshot({
                      ...latest,
                      bgClaudeProcs: 0,
                      killHoldActive: hs.active,
                      killHoldRemainingSecs: hs.remainingSecs,
                      killHoldBlockedCount: hs.blockedCount,
                      killHoldTxLocked: hs.txLocked,
                    });
                    pushToast(
                      `已启用 ${hs.remainingSecs}s 防复活盯防锁`,
                      "每 250ms 监测 Claude 关联进程树，冒头即强杀并顺延 +15s。",
                      "ok"
                    );
                  } catch (err) {
                    pushToast("启用防复活盯防失败", String(err), "danger");
                  } finally {
                    setBusyKill(false);
                  }
                }}
              >
                {busyKill ? (
                  <Loader2 size={11.5} strokeWidth={1.9} className="guard-spin" />
                ) : (
                  <Shield size={11.5} strokeWidth={1.55} />
                )}
                <span>{`强杀防复活盯防 (${defaultHoldSecs}s)`}</span>
              </button>
            )}
          </div>
        </div>

        {/* Clash Verge 内核连接状态卡（右上显示应用在线/离线状态，右下显示端口号且不带冒号） */}
        <div
          className="guard-card"
          style={{
            padding: "10px 12px",
            display: "flex",
            flexDirection: "column",
            gap: 5,
          }}
        >
          <div style={statusRowStyle}>
            <span
              style={{
                display: "flex",
                alignItems: "center",
                gap: 7,
                fontSize: 12,
                color: "var(--text-1)",
              }}
            >
              <span className={sideDotClass} />
              <span>Clash Verge</span>
            </span>
            <span
              style={{
                fontSize: 11,
                color: snapshot.clashOnline ? "var(--ok-fg)" : "var(--bad-fg)",
                flexShrink: 0,
              }}
            >
              {snapshot.clashOnline ? "在线" : "离线"}
            </span>
          </div>
          <div style={statusRowStyle}>
            <span
              className="tabular"
              style={{
                fontSize: 11,
                color: "var(--text-3)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {snapshot.clashVersion}
            </span>
            <span
              className="tabular"
              title={`混合代理端口 ${snapshot.clashPort}`}
              style={{ fontSize: 11, color: "var(--text-3)", flexShrink: 0 }}
            >
              {snapshot.clashPort}
            </span>
          </div>
        </div>

        {/* 左下角「系统设置」触发项（拉开上方两卡间距 16px，收紧 Clash 卡到底部分割线与设置按钮间距） */}
        <div style={{ marginTop: -10, paddingTop: 7, borderTop: "1px solid var(--divider)" }}>
          <button
            type="button"
            data-testid="sidebar-settings-trigger"
            className={`c-nav-item ${settingsModalOpen ? "active" : ""}`}
            title="打开系统设置（Ctrl+,）"
            onClick={() => openSettingsModal(networkRescueAlert ? "recovery" : undefined)}
          >
            <span style={{ display: "flex", alignItems: "center", gap: 9 }}>
              <Settings
                size={15}
                strokeWidth={settingsModalOpen ? 1.55 : 1.4}
                style={{ color: settingsModalOpen ? "var(--text-strong)" : "var(--text-3)", flexShrink: 0 }}
              />
              <span>系统设置</span>
            </span>
            <span
              data-testid="sidebar-settings-meta"
              className="tabular"
              style={{
                fontSize: 10.5,
                color: networkRescueAlert ? "var(--bad-fg)" : "var(--text-3)",
                display: "inline-flex",
                alignItems: "center",
                gap: 5,
              }}
            >
              {networkRescueAlert ? (
                <>
                  <span
                    style={{
                      width: 5.5,
                      height: 5.5,
                      borderRadius: "50%",
                      background: "var(--bad-dot)",
                      display: "inline-block",
                    }}
                  />
                  <span>需急救</span>
                </>
              ) : (
                appVersionLabel
              )}
            </span>
          </button>
        </div>
      </div>
    </aside>
  );
}

const navBadgeStyle: React.CSSProperties = {
  fontSize: 10,
  fontWeight: 400,
  minWidth: 17,
  height: 17,
  padding: "0 5px",
  borderRadius: 4.5,
  display: "inline-flex",
  alignItems: "center",
  justifyContent: "center",
};

const statusRowStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 8,
  minHeight: 19,
};
