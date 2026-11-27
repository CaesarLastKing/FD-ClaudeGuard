import { useEffect, useRef, useState } from "react";
import { Globe, Home, Loader2, Shield, ShieldCheck, SlidersHorizontal, Wrench } from "lucide-react";
import { ipc } from "@/lib/ipc";
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
        style={{ color: active ? "var(--text-strong)" : "var(--text-3)", flexShrink: 0 }}
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
        style={{ color: active ? "var(--text-strong)" : "var(--text-3)", flexShrink: 0 }}
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
        style={{ color: active ? "var(--text-strong)" : "var(--text-3)", flexShrink: 0 }}
      />
    ),
  },
  {
    id: "maintain",
    label: "环境维护",
    renderIcon: (active) => (
      <Wrench
        size={15}
        strokeWidth={active ? 1.55 : 1.4}
        style={{ color: active ? "var(--text-strong)" : "var(--text-3)", flexShrink: 0 }}
      />
    ),
  },
  {
    id: "config",
    label: "守卫配置",
    renderIcon: (active) => (
      <SlidersHorizontal
        size={15}
        strokeWidth={active ? 1.55 : 1.4}
        style={{ color: active ? "var(--text-strong)" : "var(--text-3)", flexShrink: 0 }}
      />
    ),
  },
];

export function Sidebar() {
  const activeTab = useGuardStore((s) => s.activeTab);
  const setActiveTab = useGuardStore((s) => s.setActiveTab);
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
  const mustFail = mustAll.filter((x) => x.status !== "ok").length;

  // 节点流量侧边栏角标双重兜底：同步关联 snapshot 唯一真源（含 nodeDown / activeFlowAnomalies / 漂移）与控制台 node_geo（硬可达性）
  const nodeGeoItem = preflight.items.find((x) => x.id === "node_geo");
  const hasNodeFail = Boolean(snapshot.nodeDown) || nodeGeoItem?.status === "fail";
  const hasNodeIssue =
    hasNodeFail || snapshot.activeFlowAnomalies > 0 || nodeGeoItem?.status === "warn";

  // Clash Verge 指示灯仅纯粹反映代理内核连接本身：在线恒定绿灯，仅离线时红灯提示
  const sideDotClass = snapshot.clashOnline ? "guard-dot" : "guard-dot danger";

  // 每次拦截到 Claude 非安全启动（拦截次数递增），触发边框脉冲闪烁提醒
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

  return (
    <aside
      style={{
        width: 212,
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
                    background: mustFail > 0 ? "var(--bad-bg)" : "var(--ok-bg)",
                    color: mustFail > 0 ? "var(--bad-fg)" : "var(--ok-fg)",
                  }}
                >
                  {mustFail > 0 ? mustFail : "OK"}
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

      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {/* Claude 进程雷达 & Kill-Hold 防复活持续盯防卡
            红线（ISS-056）：绝不可混用 border 简写与 borderColor 细分属性 */}
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
              alignItems: "center",
              justifyContent: "space-between",
              gap: 6,
              minHeight: 22,
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
                  ? `已拦截 ${holdBlocked} 次`
                  : ksLinkedHold
                  ? "熔断护航中"
                  : "防复活中"
                : snapshot.bgClaudeProcs > 0
                ? "运行中"
                : "已彻底退出"}
            </span>

            {holdActive ? (
              <button
                type="button"
                data-testid="btn-release-kill-hold"
                disabled={busyKill}
                className={`sidebar-hold-pill ${ksLinkedHold ? "is-danger" : "is-active"}`}
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
                {busyKill && <Loader2 size={10.5} strokeWidth={1.9} className="guard-spin" />}
                <span>{ksLinkedHold ? "解除熔断" : "解除盯防"}</span>
              </button>
            ) : snapshot.bgClaudeProcs > 0 ? (
              <button
                type="button"
                data-testid="btn-kill-and-hold"
                disabled={busyKill}
                className="sidebar-hold-pill is-active"
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
                  <Loader2 size={10.5} strokeWidth={1.9} className="guard-spin" />
                ) : (
                  <Shield size={10.5} strokeWidth={1.55} />
                )}
                <span>{busyKill ? "强杀中..." : `清退盯防 ${defaultHoldSecs}s`}</span>
              </button>
            ) : (
              <button
                type="button"
                data-testid="btn-start-kill-hold"
                disabled={busyKill}
                className="sidebar-hold-pill"
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
                  <Loader2 size={10.5} strokeWidth={1.9} className="guard-spin" />
                ) : (
                  <Shield size={10.5} strokeWidth={1.5} />
                )}
                <span>{`盯防 ${defaultHoldSecs}s`}</span>
              </button>
            )}
          </div>
        </div>

        {/* Clash Verge 内核连接状态卡 */}
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
            <span className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
              :{snapshot.clashPort}
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
              style={{
                fontSize: 11,
                color: snapshot.clashOnline ? "var(--ok-fg)" : "var(--bad-fg)",
                flexShrink: 0,
              }}
            >
              {snapshot.clashOnline ? "在线" : "离线"}
            </span>
          </div>
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
