import { useEffect, useRef, useState } from "react";
import { Globe, Home, Loader2, ShieldCheck, SlidersHorizontal, Wrench } from "lucide-react";
import { ipc } from "@/lib/ipc";
import { useGuardStore } from "@/stores/guardStore";
import type { NavTab } from "@/types/guard";

const NAV_ITEMS: Array<{ id: NavTab; label: string; icon: React.ReactNode }> = [
  { id: "console", label: "控制台", icon: <Home size={16} strokeWidth={1.75} /> },
  { id: "audit", label: "账户审计", icon: <ShieldCheck size={16} strokeWidth={1.75} /> },
  { id: "nodes", label: "节点流量", icon: <Globe size={16} strokeWidth={1.75} /> },
  { id: "maintain", label: "环境维护", icon: <Wrench size={16} strokeWidth={1.75} /> },
  { id: "config", label: "守卫配置", icon: <SlidersHorizontal size={16} strokeWidth={1.75} /> },
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

  // 节点流量侧边栏角标双重兜底：同步关联 snapshot 唯一真源与控制台 node_geo 状态，确保三方 100% 联动不漏标
  const nodeGeoItem = preflight.items.find((x) => x.id === "node_geo");
  const hasNodeFail = Boolean(snapshot.nodeDown) || nodeGeoItem?.status === "fail";
  const hasNodeIssue =
    hasNodeFail || snapshot.activeFlowAnomalies > 0 || nodeGeoItem?.status === "warn";

  // Clash Verge 指示灯仅纯粹反映代理内核连接本身：在线恒定绿灯，仅离线时红灯提示
  const sideDotClass = snapshot.clashOnline ? "guard-dot" : "guard-dot danger";

  // 每次拦截到 Claude 非安全启动（拦截次数递增），触发边框脉冲闪烁提醒
  const [interceptFlash, setInterceptFlash] = useState(false);
  const prevBlockedRef = useRef(holdBlocked);
  useEffect(() => {
    if (holdBlocked > prevBlockedRef.current) {
      setInterceptFlash(true);
      const timer = window.setTimeout(() => setInterceptFlash(false), 1500);
      prevBlockedRef.current = holdBlocked;
      return () => window.clearTimeout(timer);
    }
    prevBlockedRef.current = holdBlocked;
  }, [holdBlocked]);

  return (
    <aside
      style={{
        width: 198,
        flexShrink: 0,
        background: "var(--bg-sidebar)",
        borderRight: "1px solid var(--border)",
        padding: "14px 10px 12px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
      }}
    >
      <nav aria-label="主导航" style={{ display: "flex", flexDirection: "column", gap: 3 }}>
        {NAV_ITEMS.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveTab(item.id)}
              style={{
                width: "100%",
                border: "none",
                background: isActive ? "var(--bg-subtle)" : "transparent",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "9px 12px",
                borderRadius: "var(--r-btn)",
                fontFamily: "var(--font-sans)",
                fontSize: 14,
                fontWeight: isActive ? 600 : 500,
                color: isActive ? "var(--text-1)" : "var(--text-2)",
                cursor: "pointer",
                transition: "background-color 0.14s, color 0.14s",
              }}
            >
              <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
                {item.icon}
                {item.label}
              </span>
              {item.id === "console" && (
                <span
                  className="tabular"
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    minWidth: 20,
                    textAlign: "center",
                    padding: "1px 6px",
                    borderRadius: "var(--r-chip)",
                    background: mustFail > 0 ? "var(--danger-soft)" : "var(--success-soft)",
                    color: mustFail > 0 ? "var(--danger-bright)" : "var(--success)",
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
                    fontSize: 11,
                    fontWeight: 600,
                    minWidth: 20,
                    textAlign: "center",
                    padding: "1px 6px",
                    borderRadius: "var(--r-chip)",
                    background: hasNodeFail ? "var(--danger-soft)" : "var(--warning-soft)",
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
                          fontSize: 11,
                          fontWeight: 600,
                          minWidth: 20,
                          textAlign: "center",
                          padding: "1px 6px",
                          borderRadius: "var(--r-chip)",
                          background: "var(--success-soft)",
                          color: "var(--success)",
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
                        fontSize: 11,
                        fontWeight: 600,
                        minWidth: 20,
                        textAlign: "center",
                        padding: "1px 6px",
                        borderRadius: "var(--r-chip)",
                        background: isCrit ? "var(--danger-soft)" : "var(--warning-soft)",
                        color: isCrit ? "var(--danger-bright)" : "var(--warning)",
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
        {/* Claude 进程雷达 & Kill-Hold 防复活持续盯防卡（增量 17）
            注意：绝不可混用 border 简写与 borderColor 细分属性，否则解除盯防后 React 清空 borderColor 会回落成 currentColor 纯白边！ */}
        <div
          data-testid="sidebar-proc-card"
          className={interceptFlash ? "guard-intercept-flash" : undefined}
          style={{
            ...miniBoxStyle,
            border: holdActive
              ? "1px solid rgba(0, 111, 238, 0.45)"
              : "1px solid var(--border)",
            background: holdActive
              ? "linear-gradient(180deg, rgba(0, 111, 238, 0.08), var(--bg-card))"
              : "var(--bg-card)",
          }}
        >
          <div style={miniHdStyle}>
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span
                className={`guard-dot ${
                  holdActive ? "hold" : snapshot.bgClaudeProcs > 0 ? "warn" : ""
                }`}
              />
              Claude 进程
            </span>
            <span
              className="tabular"
              data-testid="sidebar-proc-status"
              style={{
                fontSize: 11,
                fontWeight: holdActive ? 600 : 500,
                color: holdActive
                  ? "var(--primary)"
                  : snapshot.bgClaudeProcs > 0
                  ? "var(--warning)"
                  : "var(--success)",
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
          <div style={{ fontSize: 11, color: "var(--text-3)" }}>
            {holdActive
              ? ksLinkedHold
                ? holdBlocked > 0
                  ? `防火墙已封锁 · 已拦截 ${holdBlocked} 次复活`
                  : "随防火墙熔断联动 · 250ms 防复活"
                : holdBlocked > 0
                ? `已拦截 ${holdBlocked} 次 Claude 非安全启动`
                : "250ms 防复活盯防中"
              : snapshot.bgClaudeProcs > 0
              ? "存在后台进程，切代理前需清空并盯防"
              : "已彻底退出，可安全操作"}
          </div>
          {holdActive ? (
            <div style={{ display: "flex", gap: 6, marginTop: 7 }}>
              <button
                type="button"
                data-testid="btn-release-kill-hold"
                disabled={busyKill}
                className={`guard-btn ${ksLinkedHold ? "guard-btn-danger-soft" : "guard-btn-flat"} guard-btn-xs`}
                style={{ width: "100%", justifyContent: "center" }}
                onClick={async () => {
                  if (ksLinkedHold) {
                    openRiskModal({
                      tone: "warn",
                      badge: "解除熔断与盯防",
                      title: "确认解除防火墙熔断并释放盯防锁？",
                      subtitle: "当前防复活盯防与防火墙出站熔断联动生效，解除后将同步清理阻断规则并恢复通信",
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
                              : "当前 11 项必须体检已全部通过，可安全解除熔断与盯防锁",
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
                    pushToast("已解除防复活盯防锁", "已停止 250ms 强杀盯防，现在可按需安全启动 Claude。", "info");
                  } catch (err) {
                    pushToast("解除盯防锁失败", String(err), "danger");
                  } finally {
                    setBusyKill(false);
                  }
                }}
              >
                {busyKill && <Loader2 size={11} strokeWidth={2} className="guard-spin" />}
                <span>{ksLinkedHold ? "解除熔断并解锁" : "解除盯防"}</span>
              </button>
            </div>
          ) : snapshot.bgClaudeProcs > 0 ? (
            <button
              type="button"
              data-testid="btn-kill-and-hold"
              disabled={busyKill}
              className="guard-btn guard-btn-flat guard-btn-xs"
              style={{ width: "100%", marginTop: 7 }}
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
              {busyKill && <Loader2 size={11} strokeWidth={2} className="guard-spin" />}
              <span>{busyKill ? "正在强杀..." : `彻底退出并盯防 ${defaultHoldSecs}s`}</span>
            </button>
          ) : (
            <button
              type="button"
              data-testid="btn-start-kill-hold"
              disabled={busyKill}
              className="guard-btn guard-btn-flat guard-btn-xs"
              style={{ width: "100%", marginTop: 7, color: "var(--text-2)" }}
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
              {busyKill && <Loader2 size={11} strokeWidth={2} className="guard-spin" />}
              <span>{`强杀防复活盯防 (${defaultHoldSecs}s)`}</span>
            </button>
          )}
        </div>

        {/* Clash Verge 内核连接状态卡 */}
        <div style={miniBoxStyle}>
          <div style={miniHdStyle}>
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span className={sideDotClass} />
              Clash Verge
            </span>
          </div>
          <div className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
            {snapshot.clashVersion} · {snapshot.clashPort}
          </div>
        </div>
      </div>
    </aside>
  );
}

const miniBoxStyle: React.CSSProperties = {
  padding: "10px 12px",
  borderRadius: "var(--r-btn)",
  background: "var(--bg-card)",
  border: "1px solid var(--border)",
  fontSize: 12,
  lineHeight: 1.45,
};

const miniHdStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  fontWeight: 500,
  marginBottom: 2,
};
