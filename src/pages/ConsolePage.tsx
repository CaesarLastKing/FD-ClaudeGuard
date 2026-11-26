import { useEffect, useState } from "react";
import { BookOpen, ChevronRight, Loader2, Lock, Play, Power, RefreshCw } from "lucide-react";
import { CheckIcon } from "@/components/CheckIcon";
import { ipc } from "@/lib/ipc";
import { FULL_AUDIT_INTERVAL_MS } from "@/lib/protocol";
import { useGuardStore } from "@/stores/guardStore";
import type { PreflightItem } from "@/types/guard";

const MUST_CATEGORIES = [
  "1. 代理与节点（改 Clash 配置）",
  "2. Windows 系统环境（改系统）",
  "3. Claude 本机卫生（改 Claude）",
] as const;

export function ConsolePage() {
  const preflight = useGuardStore((s) => s.preflight);
  const snapshot = useGuardStore((s) => s.snapshot);
  const checking = useGuardStore((s) => s.checking);
  const fixing = useGuardStore((s) => s.fixing);
  const fixingItemId = useGuardStore((s) => s.fixingItemId);
  const launching = useGuardStore((s) => s.launching);
  const exitingClaude = useGuardStore((s) => s.exitingClaude);
  const selectedId = useGuardStore((s) => s.selectedCheckId);
  const setSelectedId = useGuardStore((s) => s.setSelectedCheckId);
  const setPlaybookOpen = useGuardStore((s) => s.setPlaybookOpen);
  const refreshPreflight = useGuardStore((s) => s.refreshPreflight);
  const fixPreflightItem = useGuardStore((s) => s.fixPreflightItem);
  const oneClickFixAll = useGuardStore((s) => s.oneClickFixAll);
  const safeLaunchClaude = useGuardStore((s) => s.safeLaunchClaude);
  const safeExitClaude = useGuardStore((s) => s.safeExitClaude);
  const openRiskModal = useGuardStore((s) => s.openRiskModal);
  const openCleanModal = useGuardStore((s) => s.openCleanModal);
  const pushToast = useGuardStore((s) => s.pushToast);

  const [exportingDiag, setExportingDiag] = useState(false);
  const [releasingKs, setReleasingKs] = useState(false);
  const [resettingDrift, setResettingDrift] = useState(false);
  const config = useGuardStore((s) => s.config);
  const deepAudit = useGuardStore((s) => s.deepAudit);
  const cancelDeepNodeAudit = useGuardStore((s) => s.cancelDeepNodeAudit);
  const setActiveTab = useGuardStore((s) => s.setActiveTab);
  const setNodesSubTab = useGuardStore((s) => s.setNodesSubTab);

  const [remainSec, setRemainSec] = useState<number>(() =>
    Math.max(1, Math.round(FULL_AUDIT_INTERVAL_MS / 1000))
  );

  useEffect(() => {
    const syncRemain = () => {
      const target = snapshot.nextFullAuditEpochMs;
      if (target > Date.now()) {
        setRemainSec(Math.max(1, Math.round((target - Date.now()) / 1000)));
      } else {
        setRemainSec(0);
      }
    };
    syncRemain();
    const timer = window.setInterval(() => {
      setRemainSec((s) => (s > 0 ? s - 1 : 0));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [snapshot.nextFullAuditEpochMs]);

  const mm = String(Math.floor(remainSec / 60)).padStart(2, "0");
  const ss = String(remainSec % 60).padStart(2, "0");
  const auditCountdownLabel = remainSec > 0 ? `全量巡检 ${mm}:${ss}` : "自动巡检中...";

  const items = preflight.items;
  const mustAll = items.filter((x) => x.part === "must");
  const mustOk = mustAll.filter((x) => x.status === "ok").length;
  const mustFail = mustAll.length - mustOk;
  const optAll = items.filter((x) => x.part === "opt");
  const optOk = optAll.filter((x) => x.status === "ok").length;

  const blocked = mustFail > 0 || snapshot.killSwitchActive || snapshot.nodeDown;
  const guardStatusPill = snapshot.killSwitchActive
    ? {
        dotClass: "guard-dot danger",
        dotStyle: undefined,
        label: "已自动熔断",
        color: "var(--danger-bright)",
        cursor: "pointer" as const,
        title: "防火墙已锁死 Claude 全部出站流量，点击前往环境维护页处理",
        onClick: () => setActiveTab("maintain"),
      }
    : snapshot.nodeDown
    ? {
        dotClass: "guard-dot danger",
        dotStyle: undefined,
        label: "节点不可用",
        color: "var(--danger-bright)",
        cursor: "pointer" as const,
        title: "当前锁定节点不可用，点击前往节点流量质量页手动更换",
        onClick: () => {
          setActiveTab("nodes");
          useGuardStore.getState().setNodesSubTab("quality");
        },
      }
    : mustFail > 0
    ? {
        dotClass: "guard-dot warn",
        dotStyle: undefined,
        label: `${mustFail} 项待办`,
        color: "var(--warning)",
        cursor: "pointer" as const,
        title: `当前有 ${mustFail} 项必须体检未通过，点击定位首个待办项`,
        onClick: () => {
          const firstFail = mustAll.find((x) => x.status !== "ok");
          if (firstFail) {
            setSelectedId(firstFail.id);
          }
        },
      }
    : {
        dotClass: "guard-dot",
        dotStyle: undefined,
        label: "守护正常",
        color: "var(--success)",
        cursor: "default" as const,
        title: `${mustAll.length} 项必须项均已实测通过，与悬浮窗守护状态一致`,
        onClick: undefined,
      };
  const selectedItem = items.find((x) => x.id === selectedId) ?? items[0];
  const isAcctHighRisk =
    selectedItem?.id === "claude_acct" &&
    selectedItem.status === "fail" &&
    (selectedItem.summary.includes("最高危连坐") || selectedItem.summary.includes("受限"));
  const hitCount = snapshot.triggeredPlaybookIds.length;

  const handleExportDiag = async (itemId: string) => {
    setExportingDiag(true);
    try {
      const res = await ipc.exportAiDiagnosticBundle(itemId);
      let copiedOk = false;
      if (navigator.clipboard?.writeText) {
        copiedOk = await navigator.clipboard
          .writeText(res.promptMarkdown)
          .then(() => true)
          .catch(() => false);
      }
      pushToast(
        copiedOk ? "已导出脱敏诊断包并复制 AI 排障提示词" : "已导出脱敏诊断包（剪贴板复制失败，请从包内查看）",
        `保存路径：${res.zipPath}（含最近 7 天脱敏 JSONL 运行日志与 ai-review-prompt.md 复盘模板）`,
        "ok",
        {
          durationMs: 6500,
          action: {
            label: "打开所在文件夹",
            onClick: () => void ipc.openFileFolder(res.zipPath),
          },
        }
      );
    } catch (err) {
      pushToast("导出诊断包失败", String(err), "danger");
    } finally {
      setExportingDiag(false);
    }
  };

  /**
   * 增量 16：单号卫生锁（claude_acct）严禁擅自乱删，统一引导二选一确认弹窗
   */
  const handleFixItemClick = (item: PreflightItem) => {
    if (item.id === "node_geo" || item.id === "opt_exit_geo") {
      setActiveTab("nodes");
      setNodesSubTab("quality");
      return;
    }
    if (item.id === "claude_ban") {
      openCleanModal({
        sourceLabel: "来自控制台 · 本地封号污染残留审查",
      });
      return;
    }

    if (item.id === "claude_acct") {
      if (item.status === "warn") {
        openCleanModal({
          sourceLabel: "来自控制台 · CLI 失效凭据与旧号残留清理",
        });
        return;
      }
      const orgMatch = item.evidence.match(/Observed(?: Unique)? orgIds(?:\s*\(\d+\))?:\s*([^\n]+)/);
      const observedOrgs = (orgMatch?.[1] ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s && s !== "None");
      const latestOrg = observedOrgs[observedOrgs.length - 1] ?? "";
      const primaryLabelMatch = item.evidence.match(/Primary Candidate Label:\s*([^\n]+)/);
      const primaryCandidateLabel = primaryLabelMatch?.[1]?.trim() || (latestOrg ? `${latestOrg}...` : "");
      const highRiskMix =
        item.summary.includes("最高危连坐") || item.summary.includes("受限");
      const isSingleNewOrg =
        observedOrgs.length === 1 &&
        !highRiskMix &&
        !item.summary.includes("混登") &&
        !item.summary.includes("竞态");

      openRiskModal({
        tone: highRiskMix ? "danger" : "warn",
        badge: highRiskMix
          ? "高危连坐 · 建议清理"
          : isSingleNewOrg
          ? "单号换新确认"
          : "单号卫生锁 · 二选一",
        title: isSingleNewOrg
          ? "检测到新登录账号，确认更换主号？"
          : "多账号混登 / 跨 orgId 冲突处理确认",
        subtitle: isSingleNewOrg
          ? "当前日志仅观测到 1 个新账号，与历史绑定主号不同；若确认已永久换号可直接换绑，否则可先分项清理"
          : "绝不擅自乱删你的账号目录；分项清理弹窗会展示各端脱敏账号，默认桌面端与 CLI 全清，也可取消勾选保留你想留的那一端",
        rows: [
          {
            label: "当前检测",
            value: item.summary,
            tone: "danger",
          },
          {
            label: "分项清理",
            value:
              "打开透明分项清单（默认勾选清理桌面端与 CLI 登录态/日志/缓存，展示各端脱敏账号供自主保留，默认保护 MCP 与 VM 镜像）",
            tone: "ok",
          },
          {
            label: "仅换绑主号",
            value: primaryCandidateLabel
              ? `不删目录，直接将本机绑定主号更新为 ${primaryCandidateLabel}（仅在确认本机无混号风险时使用）`
              : "不删目录，直接重置主号绑定基线（仅在确认本机环境干净时使用）",
          },
        ],
        primaryLabel: isSingleNewOrg ? "确认为当前新主号" : "分项清理并备份",
        onPrimary: async () => {
          if (isSingleNewOrg) {
            try {
              await ipc.confirmPrimaryOrgBinding(latestOrg);
              pushToast(
                "已更新单号卫生锁绑定主号",
                latestOrg ? `主号已绑定为 ${latestOrg}... 并完成复测。` : "已刷新主号绑定并完成复测。",
                "info"
              );
              await refreshPreflight(true);
            } catch (err) {
              pushToast("更新绑定主号失败", String(err), "danger");
            }
          } else {
            openCleanModal({
              sourceLabel: "来自控制台 · 单号卫生锁",
            });
          }
        },
        dangerLabel: isSingleNewOrg ? "分项清理并备份" : "仅换绑新主号",
        onDanger: async () => {
          if (isSingleNewOrg) {
            openCleanModal({
              sourceLabel: "来自控制台 · 单号卫生锁",
            });
          } else {
            try {
              await ipc.confirmPrimaryOrgBinding(latestOrg);
              pushToast(
                "已更新单号卫生锁绑定主号",
                latestOrg ? `主号已绑定为 ${latestOrg}... 并完成复测。` : "已刷新主号绑定并完成复测。",
                "info"
              );
              await refreshPreflight(true);
            } catch (err) {
              pushToast("更新绑定主号失败", String(err), "danger");
            }
          }
        },
      });
      return;
    }
    void fixPreflightItem(item.id);
  };

  const renderCheckRow = (it: PreflightItem) => {
    const boxCls =
      it.status === "fail"
        ? "guard-icon-box is-fail"
        : it.status === "warn"
        ? "guard-icon-box is-warn"
        : "guard-icon-box";
    const chip =
      it.status === "fail" ? (
        <span className="guard-chip guard-chip-fail">未通过</span>
      ) : it.status === "warn" ? (
        <span className="guard-chip guard-chip-warn">风险提示</span>
      ) : (
        <span className="guard-chip guard-chip-ok">已通过</span>
      );

    return (
      <div
        key={it.id}
        role="button"
        tabIndex={0}
        className={`guard-row ${selectedId === it.id ? "selected" : ""}`}
        onClick={() => setSelectedId(it.id)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setSelectedId(it.id);
          }
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
          <div className={boxCls}>
            <CheckIcon name={it.icon} />
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 14, fontWeight: 500, color: "var(--text-1)", lineHeight: 1.3 }}>
              {it.title}
            </div>
            <div
              style={{
                fontSize: 12,
                color: "var(--text-2)",
                marginTop: 2,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
                maxWidth: 320,
              }}
            >
              {it.summary}
            </div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          {chip}
          <ChevronRight size={13} style={{ color: "var(--text-3)" }} />
        </div>
      </div>
    );
  };

  const openReleaseKillswitchModal = () => {
    openRiskModal({
      tone: "warn",
      badge: "解除自动熔断",
      title: "确认解除防火墙熔断并释放盯防锁？",
      subtitle: "解除后将删除 FDClaudeGuard_KillSwitch 防火墙阻断规则并同步解除事务盯防，恢复 Claude 通信",
      rows: [
        {
          label: "当前保护",
          value: "防火墙已锁死 Claude 全部出站流量（进程防复活盯防联动锁定中）",
          tone: "danger",
        },
        {
          label: "放行建议",
          value:
            mustFail > 0
              ? `当前仍有 ${mustFail} 项必须体检未通过，建议解除熔断前先修复异常项`
              : `当前 ${mustAll.length} 项必须体检已全部通过，可安全解除熔断与恢复启动`,
          tone: mustFail > 0 ? "danger" : "ok",
        },
      ],
      primaryLabel: "确认解除熔断并复测",
      onPrimary: async () => {
        setReleasingKs(true);
        try {
          await ipc.forceReleaseKillswitch(true);
          pushToast(
            "已解除自动熔断与盯防锁",
            "防火墙阻断规则与事务盯防锁已同步释放，正在重跑真实探针复核。",
            "ok"
          );
          await refreshPreflight(true);
        } catch (err) {
          pushToast("解除熔断失败", String(err), "danger");
        } finally {
          setReleasingKs(false);
        }
      },
    });
  };

  return (
    <section style={{ display: "flex", flex: 1, minHeight: 0, flexDirection: "column" }}>
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
        <div style={{ minWidth: 0 }}>
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
            <span>控制台</span>
          </h1>
          <div
            className="tabular"
            style={{
              fontSize: 12,
              color: "var(--text-3)",
              marginTop: 4,
              display: "flex",
              alignItems: "center",
              gap: 8,
              flexWrap: "wrap",
            }}
          >
            <span>{`启动前实测体检 · 事件实时监听中 · ${auditCountdownLabel}`}</span>
            {config.calm24h && (
              <button
                type="button"
                className="guard-chip guard-chip-mode"
                style={{ cursor: "pointer" }}
                onClick={() => setActiveTab("config")}
                title="已开启 24h 冷静保护期，点击前往守卫配置调整"
              >
                24h 冷静期
              </button>
            )}
            {deepAudit.running && (
              <span
                data-testid="console-deep-audit-badge"
                className="guard-chip guard-chip-warn tabular"
                style={{ display: "inline-flex", alignItems: "center", gap: 5 }}
                title={deepAudit.message}
              >
                <Loader2 size={10} strokeWidth={2.2} className="guard-spin" />
                <span>
                  核验节点 {deepAudit.currentIndex}/{deepAudit.total || "?"}
                </span>
                <button
                  type="button"
                  onClick={() => void cancelDeepNodeAudit()}
                  style={{
                    border: "none",
                    background: "transparent",
                    color: "inherit",
                    fontSize: 10.5,
                    textDecoration: "underline",
                    cursor: "pointer",
                    padding: 0,
                    marginLeft: 2,
                  }}
                >
                  停止
                </button>
              </span>
            )}
          </div>
        </div>

        {/* 单一蓝色主 CTA 原则：按待办数智能分配唯一蓝主焦点 */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <button
            type="button"
            data-testid="console-guard-status-pill"
            className="guard-btn guard-btn-flat guard-btn-sm tabular"
            style={{ color: guardStatusPill.color, cursor: guardStatusPill.cursor }}
            title={guardStatusPill.title}
            onClick={guardStatusPill.onClick}
          >
            <span className={guardStatusPill.dotClass} style={guardStatusPill.dotStyle} />
            <span>{guardStatusPill.label}</span>
          </button>

          <button
            type="button"
            className="guard-btn guard-btn-flat guard-btn-sm"
            onClick={() => setPlaybookOpen(true)}
          >
            <BookOpen size={14} strokeWidth={1.85} />
            <span>安全守则</span>
            {hitCount > 0 && (
              <span
                className="guard-chip guard-chip-fail tabular"
                style={{ padding: "0 5px", fontSize: 10 }}
              >
                {hitCount} 命中
              </span>
            )}
          </button>

          <button
            type="button"
            className="guard-btn guard-btn-flat guard-btn-sm"
            disabled={checking || fixing || launching || exitingClaude}
            onClick={() => void refreshPreflight()}
          >
            {checking ? (
              <Loader2 size={13} strokeWidth={2} className="guard-spin" />
            ) : (
              <RefreshCw size={13} strokeWidth={1.85} />
            )}
            <span>{checking ? "实测中..." : "重新实测"}</span>
          </button>

          {mustFail >= 2 ? (
            <button
              type="button"
              data-testid="btn-batch-fix-all"
              className="guard-btn guard-btn-primary"
              disabled={checking || fixing}
              onClick={() => void oneClickFixAll()}
            >
              {fixing && <Loader2 size={14} strokeWidth={2} className="guard-spin" />}
              <span>{fixing ? "处理中..." : `一键处理全部 (${mustFail})`}</span>
            </button>
          ) : deepAudit.running ? (
            <button
              type="button"
              data-testid="btn-launch-wait-audit"
              className="guard-btn guard-btn-primary"
              disabled
              title="正在深度核验备选节点（期间会临时切换代理通道），核验完成并恢复原锁定节点后自动解锁启动"
            >
              <Loader2 size={14} strokeWidth={2} className="guard-spin" />
              <span>
                核验节点中 ({deepAudit.currentIndex}/{deepAudit.total || "?"}) · 暂禁启动
              </span>
            </button>
          ) : snapshot.killSwitchActive ? (
            <button
              type="button"
              data-testid="btn-console-release-killswitch"
              className="guard-btn guard-btn-danger-soft"
              disabled={releasingKs || checking || fixing}
              onClick={openReleaseKillswitchModal}
            >
              {releasingKs ? (
                <Loader2 size={14} strokeWidth={2} className="guard-spin" />
              ) : (
                <Lock size={14} strokeWidth={1.9} />
              )}
              <span>{releasingKs ? "正在解除熔断..." : "解除熔断保护"}</span>
            </button>
          ) : blocked ? (
            <button type="button" className="guard-btn guard-btn-primary" disabled>
              <Lock size={14} strokeWidth={1.9} />
              <span>
                {snapshot.nodeDown && mustFail === 0
                  ? "节点不可用 · 请更换"
                  : `请先处理右侧 ${Math.max(1, mustFail)} 项`}
              </span>
            </button>
          ) : snapshot.bgClaudeProcs > 0 ? (
            <button
              type="button"
              data-testid="btn-safe-exit-claude"
              className="guard-btn guard-btn-danger-soft"
              disabled={exitingClaude || checking || fixing}
              onClick={() => void safeExitClaude()}
            >
              {exitingClaude ? (
                <Loader2 size={14} strokeWidth={2} className="guard-spin" />
              ) : (
                <Power size={14} strokeWidth={1.9} />
              )}
              <span>
                {exitingClaude
                  ? "正在安全退出..."
                  : `安全退出 Claude（${snapshot.bgClaudeProcs} 进程运行中）`}
              </span>
            </button>
          ) : (
            <button
              type="button"
              data-testid="btn-safe-launch-claude"
              className="guard-btn guard-btn-primary"
              disabled={checking || fixing || launching}
              onClick={() => void safeLaunchClaude()}
            >
              {launching ? (
                <Loader2 size={14} strokeWidth={2} className="guard-spin" />
              ) : (
                <Play size={14} strokeWidth={1.9} />
              )}
              <span>{launching ? "正在安全启动..." : "安全启动 Claude"}</span>
            </button>
          )}
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0, display: "grid", gridTemplateColumns: "1.15fr 0.85fr" }}>
        <div
          style={{
            padding: "16px 20px",
            overflowY: "auto",
            borderRight: "1px solid var(--border)",
            display: "flex",
            flexDirection: "column",
            gap: 18,
          }}
        >
          {snapshot.bgClaudeProcs > 0 && mustFail > 0 && !snapshot.killSwitchActive && (
            <div
              data-testid="console-running-must-fail-banner"
              style={{
                padding: "11px 14px",
                borderRadius: "var(--r-card)",
                border: "1px solid rgba(245, 165, 36, 0.42)",
                background: "var(--warning-soft)",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 12,
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: "var(--warning)" }}>
                  运行中防护警示：Claude 当前有 {snapshot.bgClaudeProcs} 个进程存活，且 {mustFail} 项必须项未通过
                </div>
                <div style={{ fontSize: 11.5, color: "var(--text-2)", marginTop: 2, lineHeight: 1.5 }}>
                  为避免直接强杀打断正在进行的对话，非致命断链项不会静默清退；若需修复配置或避免风险扩大，建议先安全清退并开启盯防。
                </div>
              </div>
              <button
                type="button"
                data-testid="btn-banner-safe-exit-claude"
                className="guard-btn guard-btn-danger-soft guard-btn-sm"
                style={{ flexShrink: 0 }}
                disabled={exitingClaude || checking || fixing}
                onClick={() => void safeExitClaude()}
              >
                {exitingClaude ? (
                  <Loader2 size={13} strokeWidth={2} className="guard-spin" />
                ) : (
                  <Power size={13} strokeWidth={1.9} />
                )}
                <span>{exitingClaude ? "正在清退..." : "立即清退 Claude 并盯防"}</span>
              </button>
            </div>
          )}

          <div>
            <div style={partHdStyle}>
              <div style={{ ...partTitleStyle, whiteSpace: "nowrap", flexShrink: 0 }}>
                <span>一、必须通过</span>
              </div>
              <span
                className="tabular"
                style={{ fontSize: 12, color: "var(--text-3)", textAlign: "right" }}
              >
                全部通过{" "}
                <span
                  style={{
                    fontWeight: 600,
                    color: mustFail > 0 ? "var(--danger-bright)" : "var(--text-1)",
                  }}
                >
                  {mustOk}/{mustAll.length}
                </span>{" "}
                项后，
                <span style={{ color: "var(--success)", fontWeight: 500 }}>健康</span>
                启动 Claude
              </span>
            </div>

            {MUST_CATEGORIES.map((cat) => {
              const catItems = mustAll.filter((x) => x.cat === cat);
              return (
                <div key={cat} style={{ marginBottom: 12 }}>
                  <div
                    style={{
                      fontSize: 12,
                      fontWeight: 500,
                      color: "var(--text-3)",
                      marginBottom: 6,
                      paddingLeft: 2,
                    }}
                  >
                    {cat}
                  </div>
                  <div className="guard-card">{catItems.map(renderCheckRow)}</div>
                </div>
              );
            })}
          </div>

          <div>
            <div style={partHdStyle}>
              <div style={partTitleStyle}>
                <span>二、建议优化</span>
                <span className="guard-chip guard-chip-neutral tabular">
                  {`${optOk}/${optAll.length}`}
                </span>
              </div>
              <span style={{ fontSize: 12, color: "var(--text-3)" }}>
                含启动项、时区与浏览器隐私监测，不阻断启动
              </span>
            </div>
            <div className="guard-card">{optAll.map(renderCheckRow)}</div>
          </div>
        </div>

        <div
          style={{
            padding: "16px 20px",
            overflowY: "auto",
            display: "flex",
            flexDirection: "column",
            gap: 14,
          }}
        >
          {selectedItem && (
            <div
              className="guard-card"
              style={{ padding: 16, display: "flex", flexDirection: "column", gap: 14 }}
            >
              <div style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
                <div
                  className={
                    selectedItem.status === "fail"
                      ? "guard-icon-box is-fail"
                      : selectedItem.status === "warn"
                      ? "guard-icon-box is-warn"
                      : "guard-icon-box"
                  }
                  style={{ width: 36, height: 36 }}
                >
                  <CheckIcon name={selectedItem.icon} size={17} />
                </div>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                    <h2
                      data-testid="detail-item-title"
                      style={{ fontSize: 16, fontWeight: 600, lineHeight: 1.3, margin: 0 }}
                    >
                      {selectedItem.title}
                    </h2>
                    <span
                      className={`guard-chip ${
                        selectedItem.status === "fail"
                          ? "guard-chip-fail"
                          : selectedItem.status === "warn"
                          ? "guard-chip-warn"
                          : "guard-chip-ok"
                      }`}
                    >
                      {selectedItem.status === "fail"
                        ? "必须项 · 未通过"
                        : selectedItem.status === "warn"
                        ? selectedItem.part === "must"
                          ? "必须项 · 风险提示"
                          : "建议项 · 风险提示"
                        : "实测通过"}
                    </span>
                    <span className="guard-chip guard-chip-mode">{selectedItem.mode}</span>
                  </div>
                  <p
                    style={{
                      fontSize: 12,
                      color: "var(--text-2)",
                      margin: "4px 0 0",
                      lineHeight: 1.55,
                    }}
                  >
                    {selectedItem.summary}
                  </p>
                </div>
              </div>

              <div>
                <div style={detLblStyle}>真实探针实测数据</div>
                <div
                  className="font-mono-code tabular"
                  style={{
                    background: "var(--bg-subtle)",
                    border: "1px solid var(--border)",
                    borderRadius: "var(--r-btn)",
                    padding: "10px 12px",
                    fontSize: 11.5,
                    lineHeight: 1.6,
                    color: "var(--text-2)",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                  }}
                >
                  {selectedItem.evidence}
                </div>
              </div>

              <div>
                <div style={detLblStyle}>处理方式与验证说明</div>
                <div
                  data-testid="guide-plaintext"
                  className="guide-box"
                  style={isAcctHighRisk ? { borderLeftColor: "var(--danger)" } : undefined}
                >
                  {selectedItem.guide || "该项已通过真实探针验证。"}
                </div>
              </div>

              {selectedItem.status === "ok" ? (
                <div style={{ fontSize: 12, color: "var(--success)", fontWeight: 500 }}>
                  该项已通过真实探针验收，无需额外操作。
                </div>
              ) : (
                /* 只要 status !== "ok" 始终显示排障包导出 */
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {(selectedItem.id === "opt_exit_geo" || selectedItem.id === "node_geo") &&
                  selectedItem.status === "warn" &&
                  selectedItem.evidence.includes("DRIFT DETECTED") ? (
                    <>
                      {/* 漂移风险提示：当仅 1 项待办时为唯一蓝色主焦点，当 >= 2 项待办时让位于右上角「一键处理全部」保持一屏唯一蓝 CTA */}
                      <button
                        type="button"
                        data-testid="btn-reset-drift-baseline"
                        disabled={resettingDrift || checking || fixing}
                        className={`guard-btn ${mustFail >= 2 ? "guard-btn-secondary" : "guard-btn-primary"}`}
                        style={{ padding: 10 }}
                        onClick={async () => {
                          setResettingDrift(true);
                          try {
                            const msg = await ipc.resetNodeDriftBaseline();
                            pushToast("已重置落地 IP 漂移基准", msg, "ok");
                            await refreshPreflight(true);
                          } catch (err) {
                            pushToast("重置漂移基准失败", String(err), "danger");
                          } finally {
                            setResettingDrift(false);
                          }
                        }}
                      >
                        {resettingDrift && <Loader2 size={14} strokeWidth={2} className="guard-spin" />}
                        <span>
                          {resettingDrift
                            ? "重置并复测中..."
                            : "确认当前 IP 已稳定（重置漂移基准）"}
                        </span>
                      </button>
                      {/* 备用选项：前往节点流量手动更换稳定节点 */}
                      <button
                        type="button"
                        data-testid="btn-goto-nodes-fallback"
                        className="guard-btn guard-btn-flat guard-btn-sm"
                        disabled={fixing || checking || resettingDrift}
                        style={{ padding: 9 }}
                        onClick={() => setActiveTab("nodes")}
                      >
                        <span>前往「节点流量」更换稳定节点 →</span>
                      </button>
                    </>
                  ) : selectedItem.fixLabel ? (
                    <button
                      type="button"
                      className={`guard-btn ${
                        isAcctHighRisk
                          ? "guard-btn-danger-soft"
                          : selectedItem.part === "opt" || mustFail >= 2 || mustFail === 0
                          ? "guard-btn-secondary"
                          : "guard-btn-primary"
                      }`}
                      disabled={fixing || checking}
                      style={{ padding: 10 }}
                      onClick={() => handleFixItemClick(selectedItem)}
                    >
                      {fixing && fixingItemId === selectedItem.id && (
                        <Loader2 size={14} strokeWidth={2} className="guard-spin" />
                      )}
                      <span>
                        {fixing && fixingItemId === selectedItem.id
                          ? "正在执行并实测验收..."
                          : selectedItem.fixLabel}
                      </span>
                    </button>
                  ) : (
                    <div
                      style={{
                        fontSize: 12,
                        color:
                          selectedItem.status === "fail"
                            ? "var(--danger-bright)"
                            : "var(--warning)",
                        fontWeight: 500,
                      }}
                    >
                      请按上方说明处理后点击右上角「重新实测」完成验收。
                    </div>
                  )}
                  <button
                    type="button"
                    data-testid="btn-export-ai-diag"
                    disabled={exportingDiag}
                    className="guard-text-link"
                    onClick={() => void handleExportDiag(selectedItem.id)}
                  >
                    {exportingDiag
                      ? "正在打包脱敏诊断包与运行日志..."
                      : "无法自动解决？导出脱敏问题包给 AI 分析 ↗"}
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

const partHdStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  marginBottom: 10,
};

const partTitleStyle: React.CSSProperties = {
  fontSize: 14,
  fontWeight: 600,
  display: "flex",
  alignItems: "center",
  gap: 8,
};

const detLblStyle: React.CSSProperties = {
  fontSize: 12,
  fontWeight: 500,
  color: "var(--text-3)",
  marginBottom: 6,
};
