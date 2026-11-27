import { useEffect, useState } from "react";
import { Check, ChevronDown, ChevronRight, Copy, ExternalLink, Loader2, Lock, Play, Power, RefreshCw } from "lucide-react";
import { CheckIcon } from "@/components/CheckIcon";
import { ThinScrollArea } from "@/components/ThinScrollArea";
import { ipc } from "@/lib/ipc";
import { FULL_AUDIT_INTERVAL_MS } from "@/lib/protocol";
import { useGuardStore } from "@/stores/guardStore";
import type { PreflightItem } from "@/types/guard";

interface EvidenceKvRow {
  k: string;
  v: string;
  tone?: "bad" | "warn" | "ok";
}

/**
 * 安全可降级的实测证据键值解析器：
 * 仅当证据串拆出至少 2 条结构清晰的 Key: Value / Key=Value 时返回键值列表，
 * 避免对纯句段、长 URL 或报错堆栈误拆导致可读性下降。
 */
function parseEvidenceKv(evidence: string): EvidenceKvRow[] | null {
  if (!evidence) return null;
  const rawParts = evidence
    .split(/\r?\n|\s+\|\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (rawParts.length < 2) return null;

  const rows: EvidenceKvRow[] = [];
  for (const part of rawParts) {
    const match = part.match(/^([^:=：]{1,28}?)\s*[:=：]\s*(.+)$/);
    if (!match) return null;
    const k = match[1].trim();
    const v = match[2].trim();
    if (!k || !v || /^https?$/i.test(k) || k.includes("\\") || k.includes("/")) {
      return null;
    }
    let tone: EvidenceKvRow["tone"];
    if (/fail|error|blocked|leak|deny|offline|异常|失败|阻断|未通过|离线|冲突/i.test(v)) {
      tone = "bad";
    } else if (/warn|drift|待实测|待探测|待审计|待实查|警告/i.test(v)) {
      tone = "warn";
    } else if (/^(ok|pass|true|enabled|online|clean|0|已通过|正常|在线|无泄漏)$/i.test(v)) {
      tone = "ok";
    }
    rows.push({ k, v, tone });
  }
  return rows.length >= 2 ? rows : null;
}

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
  const [showRawEvidence, setShowRawEvidence] = useState(false);
  const [copiedEvidence, setCopiedEvidence] = useState(false);

  useEffect(() => {
    setShowRawEvidence(false);
    setCopiedEvidence(false);
  }, [selectedId]);
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
    // 直接按 wall-clock 目标时间戳重算剩余秒数，避免电脑休眠或后台节流导致倒计时漂移
    const timer = window.setInterval(syncRemain, 1000);
    return () => window.clearInterval(timer);
  }, [snapshot.nextFullAuditEpochMs]);

  const mm = String(Math.floor(remainSec / 60)).padStart(2, "0");
  const ss = String(remainSec % 60).padStart(2, "0");
  const auditCountdownLabel = remainSec > 0 ? `巡检 ${mm}:${ss}` : "自动巡检中...";

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
        label: "已自动熔断",
        color: "var(--bad-fg)",
        cursor: "pointer" as const,
        title: "防火墙已锁死 Claude 全部出站流量，点击前往环境维护页处理",
        onClick: () => setActiveTab("maintain"),
      }
    : snapshot.nodeDown
    ? {
        dotClass: "guard-dot danger",
        label: "节点不可用",
        color: "var(--bad-fg)",
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
        label: `${mustFail} 项待办`,
        color: "var(--warning-fg)",
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
        label: "守护正常",
        color: "var(--ok-fg)",
        cursor: "default" as const,
        title: `${mustAll.length} 项必须项均已实测通过，与悬浮窗守护状态一致`,
        onClick: undefined,
      };

  const selectedItem = items.find((x) => x.id === selectedId) ?? items[0];
  const isAcctHighRisk =
    selectedItem?.id === "claude_acct" &&
    selectedItem.status === "fail" &&
    (selectedItem.summary.includes("最高危连坐") || selectedItem.summary.includes("受限"));

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
        copiedOk
          ? "已导出脱敏诊断包并复制 AI 排障提示词"
          : "已导出脱敏诊断包（剪贴板复制失败，请从包内查看）",
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
   * 单号卫生锁（claude_acct）严禁擅自乱删，统一引导二选一确认弹窗
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
      const primaryCandidateLabel =
        primaryLabelMatch?.[1]?.trim() || (latestOrg ? `${latestOrg}...` : "");
      const highRiskMix = item.summary.includes("最高危连坐") || item.summary.includes("受限");
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
    const isSelected = selectedId === it.id;
    const isFail = it.status === "fail";
    const isWarn = it.status === "warn";
    const boxCls = isFail
      ? "guard-icon-box is-fail"
      : isWarn
      ? "guard-icon-box is-warn"
      : "guard-icon-box";
    const chip = isFail ? (
      <span className="guard-chip guard-chip-fail" style={{ minWidth: 54 }}>
        未通过
      </span>
    ) : isWarn ? (
      <span className="guard-chip guard-chip-warn" style={{ minWidth: 54 }}>
        风险提示
      </span>
    ) : (
      <span className="guard-chip guard-chip-pass" style={{ minWidth: 54 }}>
        已通过
      </span>
    );

    return (
      <div
        key={it.id}
        role="button"
        tabIndex={0}
        className={`guard-row ${isSelected ? "selected" : ""}`}
        onClick={() => setSelectedId(it.id)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setSelectedId(it.id);
          }
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0, flex: 1 }}>
          <div className={boxCls}>
            <CheckIcon name={it.icon} size={14.5} />
          </div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div
              style={{
                fontSize: 12.5,
                fontWeight: 400,
                color: isSelected ? "var(--text-strong)" : "var(--text-1)",
                lineHeight: 1.38,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {it.title}
            </div>
            <div
              className="tabular"
              style={{
                fontSize: 11.5,
                color: "var(--text-2)",
                marginTop: 2,
                lineHeight: 1.45,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {it.summary}
            </div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          {chip}
          <ChevronRight
            size={12.5}
            strokeWidth={1.5}
            style={{ color: isSelected ? "var(--text-2)" : "var(--text-4)", flexShrink: 0 }}
          />
        </div>
      </div>
    );
  };

  const openReleaseKillswitchModal = () => {
    openRiskModal({
      tone: "warn",
      badge: "解除自动熔断",
      title: "确认解除防火墙熔断并释放盯防锁？",
      subtitle:
        "解除后将删除 FDClaudeGuard_KillSwitch 防火墙阻断规则并同步解除事务盯防，恢复 Claude 通信",
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
    <section
      style={{
        display: "flex",
        flex: 1,
        minHeight: 0,
        flexDirection: "column",
        background: "var(--bg-canvas)",
      }}
    >
      {/* 58px 极简页头：移除「安全守则」按钮，保留原位守护状态灯 + 重新实测 + 唯一主 CTA */}
      <div className="page-hd">
        <div className="page-hd-left">
          <h1 className="page-title">控制台</h1>
          <span className="page-sub tabular">{`启动前体检 · 实时监听 · ${auditCountdownLabel}`}</span>
          {config.calm24h && (
            <button
              type="button"
              className="guard-chip guard-chip-mode"
              style={{ cursor: "pointer", height: 20 }}
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
              style={{ height: 20, gap: 5 }}
              title={deepAudit.message}
            >
              <Loader2 size={10} strokeWidth={2} className="guard-spin" />
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

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <button
            type="button"
            data-testid="console-guard-status-pill"
            className="guard-btn guard-btn-flat tabular"
            style={{ color: guardStatusPill.color, cursor: guardStatusPill.cursor }}
            title={guardStatusPill.title}
            onClick={guardStatusPill.onClick}
          >
            <span className={guardStatusPill.dotClass} />
            <span>{guardStatusPill.label}</span>
          </button>

          <span
            aria-hidden="true"
            style={{ width: 1, height: 16, background: "var(--divider-strong)", margin: "0 2px" }}
          />

          <button
            type="button"
            className="guard-btn guard-btn-flat"
            disabled={checking || fixing || launching || exitingClaude}
            onClick={() => void refreshPreflight()}
          >
            {checking ? (
              <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />
            ) : (
              <RefreshCw size={13} strokeWidth={1.45} style={{ color: "var(--text-2)" }} />
            )}
            <span>{checking ? "实测中..." : "重新实测"}</span>
          </button>

          {/* 熔断态最高优先级直出「解除熔断保护」 */}
          {snapshot.killSwitchActive ? (
            <button
              type="button"
              data-testid="btn-console-release-killswitch"
              className="guard-btn guard-btn-danger-soft"
              disabled={releasingKs || checking || fixing}
              onClick={openReleaseKillswitchModal}
            >
              {releasingKs ? (
                <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />
              ) : (
                <Lock size={13} strokeWidth={1.55} />
              )}
              <span>{releasingKs ? "正在解除熔断..." : "解除熔断保护"}</span>
            </button>
          ) : mustFail >= 2 ? (
            <button
              type="button"
              data-testid="btn-batch-fix-all"
              className="guard-btn guard-btn-primary"
              disabled={checking || fixing}
              onClick={() => void oneClickFixAll()}
            >
              {fixing && <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />}
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
              <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />
              <span>
                核验节点中 ({deepAudit.currentIndex}/{deepAudit.total || "?"}) · 暂禁启动
              </span>
            </button>
          ) : blocked ? (
            <button type="button" className="guard-btn guard-btn-primary" disabled>
              <Lock size={12.5} strokeWidth={1.55} />
              <span>
                {snapshot.nodeDown && mustFail === 0
                  ? "节点不可用 · 请更换"
                  : `请先处理 ${Math.max(1, mustFail)} 项未通过`}
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
                <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />
              ) : (
                <Power size={13} strokeWidth={1.55} />
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
                <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />
              ) : (
                <Play size={11.5} strokeWidth={1.8} fill="currentColor" />
              )}
              <span>{launching ? "正在安全启动..." : "安全启动 Claude"}</span>
            </button>
          )}
        </div>
      </div>

      {/* 黄金双栏 + 各自独立 3×46px ThinScrollArea */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "grid",
          gridTemplateColumns: "minmax(0, 1fr) clamp(310px, 31.5%, 368px)",
        }}
      >
        <ThinScrollArea style={{ borderRight: "1px solid var(--divider)" }}>
          <div
            style={{
              padding: "16px 24px 22px",
              display: "flex",
              flexDirection: "column",
              gap: 20,
            }}
          >
            {snapshot.bgClaudeProcs > 0 && mustFail > 0 && !snapshot.killSwitchActive && (
              <div
                data-testid="console-running-must-fail-banner"
                style={{
                  padding: "11px 14px",
                  borderRadius: "var(--r-card)",
                  border: "1px solid var(--warning-border)",
                  background: "var(--warning-soft)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 12,
                }}
              >
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 500, color: "var(--warning-fg)" }}>
                    运行中防护警示：Claude 当前有 {snapshot.bgClaudeProcs} 个进程存活，且 {mustFail} 项必须项未通过
                  </div>
                  <div
                    style={{
                      fontSize: 11.5,
                      color: "var(--text-2)",
                      marginTop: 2.5,
                      lineHeight: 1.5,
                    }}
                  >
                    为避免直接强杀打断正在进行的对话，非致命断链项不会静默清退；若需修复配置或避免风险扩大，建议先安全清退并开启盯防。
                  </div>
                </div>
                <button
                  type="button"
                  data-testid="btn-banner-safe-exit-claude"
                  className="guard-btn guard-btn-danger-soft guard-btn-xs"
                  style={{ flexShrink: 0 }}
                  disabled={exitingClaude || checking || fixing}
                  onClick={() => void safeExitClaude()}
                >
                  {exitingClaude ? (
                    <Loader2 size={12} strokeWidth={1.85} className="guard-spin" />
                  ) : (
                    <Power size={12} strokeWidth={1.55} />
                  )}
                  <span>{exitingClaude ? "正在清退..." : "立即清退 Claude 并盯防"}</span>
                </button>
              </div>
            )}

            <div>
              <div style={partHdStyle}>
                <span style={partTitleStyle}>一、必须通过</span>
                {/* 终审覆盖点 B：统一展示「通过 X/Y 后安全启动」（打满无色、未打满仅数字标柔丹红，不包红框胶囊） */}
                <span
                  data-testid="console-must-summary"
                  className="tabular"
                  style={{ fontSize: 11.5, color: "var(--text-3)", textAlign: "right" }}
                >
                  通过{" "}
                  <span
                    style={
                      mustOk < mustAll.length
                        ? { color: "var(--bad-fg)", fontWeight: 500 }
                        : undefined
                    }
                  >
                    {mustOk}/{mustAll.length}
                  </span>{" "}
                  后安全启动
                </span>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                {MUST_CATEGORIES.map((cat) => {
                  const catItems = mustAll.filter((x) => x.cat === cat);
                  return (
                    <div key={cat}>
                      <div
                        style={{
                          fontSize: 11,
                          fontWeight: 400,
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
            </div>

            <div>
              <div style={partHdStyle}>
                <span style={partTitleStyle}>二、建议优化</span>
                <span className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
                  {`${optOk}/${optAll.length} · 不阻断启动`}
                </span>
              </div>
              <div className="guard-card">{optAll.map(renderCheckRow)}</div>
            </div>
          </div>
        </ThinScrollArea>

        <ThinScrollArea>
          <aside
            style={{
              padding: "16px 16px 22px",
              display: "flex",
              flexDirection: "column",
              gap: 10,
            }}
          >
            {selectedItem && (
              <div
                key={selectedItem.id}
                className="insp-enter"
                style={{ display: "flex", flexDirection: "column", gap: 10 }}
              >
                {/* 详情卡 1：干净图标 + 标题 + 精简副标题（已移除右上角重复状态胶囊） */}
                <div className="guard-card" style={{ padding: "14px" }}>
                  <div style={{ display: "flex", alignItems: "flex-start", gap: 11 }}>
                    <div
                      className={
                        selectedItem.status === "fail"
                          ? "guard-icon-box is-fail"
                          : selectedItem.status === "warn"
                          ? "guard-icon-box is-warn"
                          : "guard-icon-box"
                      }
                      style={{ width: 32, height: 32, borderRadius: 8 }}
                    >
                      <CheckIcon name={selectedItem.icon} size={15} />
                    </div>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <h2
                        data-testid="detail-item-title"
                        style={{
                          fontSize: 14,
                          fontWeight: 500,
                          lineHeight: 1.35,
                          color: "var(--text-strong)",
                          margin: 0,
                        }}
                      >
                        {selectedItem.title}
                      </h2>
                      <div
                        className="tabular"
                        style={{
                          marginTop: 4,
                          display: "flex",
                          alignItems: "center",
                          gap: 6,
                          fontSize: 11,
                          color: "var(--text-3)",
                          flexWrap: "wrap",
                        }}
                      >
                        <span>{selectedItem.part === "must" ? "启动必须项" : "建议优化"}</span>
                        <span style={{ color: "var(--text-4)" }}>·</span>
                        <span>{selectedItem.mode}</span>
                        {preflight.checkedAt && (
                          <>
                            <span style={{ color: "var(--text-4)" }}>·</span>
                            <span>{preflight.checkedAt}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                  <p
                    style={{
                      fontSize: 11.5,
                      color: "var(--text-2)",
                      margin: "10px 0 0",
                      lineHeight: 1.55,
                    }}
                  >
                    {selectedItem.summary}
                  </p>
                </div>

                {/* 详情卡 2：实测数据（优先展示结构化键值行 + 折叠原始日志；复杂文本平滑降级原样代码块） */}
                {(() => {
                  const kvRows = parseEvidenceKv(selectedItem.evidence);
                  const copyEvidenceText = async () => {
                    const text = `[${selectedItem.title}] (${selectedItem.status})\n${selectedItem.summary}\n${selectedItem.evidence}`;
                    try {
                      await navigator.clipboard?.writeText(text);
                      setCopiedEvidence(true);
                      pushToast("已复制实测诊断摘要", selectedItem.title, "ok");
                      window.setTimeout(() => setCopiedEvidence(false), 1800);
                    } catch {
                      pushToast("复制失败", "当前环境不支持剪贴板写入，请直接选中文本复制。", "info");
                    }
                  };
                  return (
                    <div className="guard-card" style={{ padding: "12px 14px" }}>
                      <div
                        style={{
                          ...detLblStyle,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between",
                          gap: 8,
                        }}
                      >
                        <span>真实探针实测数据</span>
                        <button
                          type="button"
                          onClick={() => void copyEvidenceText()}
                          style={{
                            border: "none",
                            background: "transparent",
                            color: copiedEvidence ? "var(--ok-fg)" : "var(--text-3)",
                            fontSize: 11,
                            fontFamily: "var(--font-sans)",
                            display: "inline-flex",
                            alignItems: "center",
                            gap: 4,
                            cursor: "pointer",
                            padding: 0,
                          }}
                        >
                          {copiedEvidence ? (
                            <Check size={11.5} strokeWidth={1.9} />
                          ) : (
                            <Copy size={11.5} strokeWidth={1.5} />
                          )}
                          <span>{copiedEvidence ? "已复制" : "复制诊断"}</span>
                        </button>
                      </div>

                      {kvRows ? (
                        <>
                          <div className="c-kv-list tabular">
                            {kvRows.map((row) => (
                              <div key={`${row.k}-${row.v}`} className="c-kv-row">
                                <span className="c-kv-k">{row.k}</span>
                                <span
                                  className={`c-kv-v ${
                                    row.tone === "bad"
                                      ? "is-bad"
                                      : row.tone === "warn"
                                      ? "is-warn"
                                      : row.tone === "ok"
                                      ? "is-ok"
                                      : ""
                                  }`}
                                >
                                  {row.v}
                                </span>
                              </div>
                            ))}
                          </div>
                          <div
                            style={{
                              marginTop: 8,
                              paddingTop: 7,
                              borderTop: "1px solid var(--divider)",
                            }}
                          >
                            <button
                              type="button"
                              onClick={() => setShowRawEvidence((v) => !v)}
                              style={{
                                border: "none",
                                background: "transparent",
                                padding: 0,
                                color: "var(--text-3)",
                                fontSize: 11,
                                fontFamily: "var(--font-sans)",
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 4,
                                cursor: "pointer",
                              }}
                            >
                              <ChevronDown
                                size={12}
                                strokeWidth={1.6}
                                style={{
                                  transform: showRawEvidence ? "rotate(180deg)" : "none",
                                  transition: "transform 140ms var(--ease)",
                                }}
                              />
                              <span>{showRawEvidence ? "收起原始探针日志" : "查看原始探针日志"}</span>
                            </button>
                            {showRawEvidence && (
                              <div
                                className="font-mono-code tabular"
                                style={{
                                  marginTop: 7,
                                  background: "var(--code-bg)",
                                  border: "1px solid var(--divider)",
                                  borderRadius: 6,
                                  padding: "8px 10px",
                                  fontSize: 10.5,
                                  lineHeight: 1.58,
                                  color: "var(--code-fg)",
                                  whiteSpace: "pre-wrap",
                                  wordBreak: "break-all",
                                  userSelect: "text",
                                }}
                              >
                                {selectedItem.evidence}
                              </div>
                            )}
                          </div>
                        </>
                      ) : (
                        <div
                          className="font-mono-code tabular"
                          style={{
                            background: "var(--code-bg)",
                            border: "1px solid var(--divider)",
                            borderRadius: 6,
                            padding: "9px 11px",
                            fontSize: 11,
                            lineHeight: 1.6,
                            color: "var(--code-fg)",
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-all",
                            userSelect: "text",
                          }}
                        >
                          {selectedItem.evidence}
                        </div>
                      )}
                    </div>
                  );
                })()}

                {/* 详情卡 3：处理方式与验证说明（去除二次嵌套 .guide-box，直接清爽排版） */}
                <div className="guard-card" style={{ padding: "12px 14px" }}>
                  <div
                    style={{
                      ...detLblStyle,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                    }}
                  >
                    <span>处理方式与验证说明</span>
                    <span>{selectedItem.mode}</span>
                  </div>
                  <div
                    data-testid="guide-plaintext"
                    style={{
                      fontSize: 12,
                      color: isAcctHighRisk ? "var(--bad-fg)" : "var(--text-2)",
                      lineHeight: 1.65,
                      userSelect: "text",
                    }}
                  >
                    {selectedItem.guide || "该项已通过真实探针验证。"}
                  </div>
                </div>

                {/* 详情卡 4：行动与排障区（核心处理恒主蓝，排障包全态统一边框按钮） */}
                <div
                  className="guard-card"
                  style={{
                    padding: "12px 14px",
                    display: "flex",
                    flexDirection: "column",
                    gap: 8,
                  }}
                >
                  {selectedItem.status === "ok" ? (
                    <>
                      <div style={{ fontSize: 11.5, color: "var(--ok-fg)", lineHeight: 1.5 }}>
                        该项已通过真实探针验收，无需额外操作。
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                        <button
                          type="button"
                          className="guard-btn guard-btn-flat"
                          disabled={checking || fixing}
                          onClick={() => void refreshPreflight()}
                        >
                          {checking ? (
                            <Loader2 size={12.5} strokeWidth={1.85} className="guard-spin" />
                          ) : (
                            <RefreshCw size={12.5} strokeWidth={1.45} style={{ color: "var(--text-2)" }} />
                          )}
                          <span>{checking ? "复测中..." : "重新实测"}</span>
                        </button>
                        <button
                          type="button"
                          data-testid="btn-export-ai-diag"
                          disabled={exportingDiag}
                          className="guard-btn guard-btn-flat"
                          onClick={() => void handleExportDiag(selectedItem.id)}
                        >
                          {exportingDiag ? (
                            <Loader2 size={12.5} strokeWidth={1.85} className="guard-spin" />
                          ) : (
                            <ExternalLink size={12.5} strokeWidth={1.45} style={{ color: "var(--text-2)" }} />
                          )}
                          <span>{exportingDiag ? "导出中..." : "导出诊断"}</span>
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      {(selectedItem.id === "opt_exit_geo" || selectedItem.id === "node_geo") &&
                      selectedItem.status === "warn" &&
                      selectedItem.evidence.includes("DRIFT DETECTED") ? (
                        <>
                          <button
                            type="button"
                            data-testid="btn-reset-drift-baseline"
                            disabled={resettingDrift || checking || fixing}
                            className="guard-btn guard-btn-primary"
                            style={{ width: "100%", height: 32 }}
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
                            {resettingDrift && (
                              <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />
                            )}
                            <span>
                              {resettingDrift
                                ? "重置并复测中..."
                                : "确认当前 IP 已稳定（重置漂移基准）"}
                            </span>
                          </button>
                          <button
                            type="button"
                            data-testid="btn-goto-nodes-fallback"
                            className="guard-btn guard-btn-flat"
                            disabled={fixing || checking || resettingDrift}
                            style={{ width: "100%" }}
                            onClick={() => setActiveTab("nodes")}
                          >
                            <span>前往「节点流量」更换稳定节点 →</span>
                          </button>
                        </>
                      ) : selectedItem.fixLabel ? (
                        <button
                          type="button"
                          className={`guard-btn ${
                            isAcctHighRisk ? "guard-btn-danger-soft" : "guard-btn-primary"
                          }`}
                          disabled={fixing || checking}
                          style={{ width: "100%", height: 32 }}
                          onClick={() => handleFixItemClick(selectedItem)}
                        >
                          {fixing && fixingItemId === selectedItem.id && (
                            <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />
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
                            fontSize: 11.5,
                            color: "var(--text-2)",
                            lineHeight: 1.55,
                          }}
                        >
                          请按上方说明处理后点击右上角「重新实测」完成验收。
                        </div>
                      )}

                      <button
                        type="button"
                        data-testid="btn-export-ai-diag"
                        disabled={exportingDiag}
                        className="guard-btn guard-btn-flat"
                        style={{ width: "100%" }}
                        onClick={() => void handleExportDiag(selectedItem.id)}
                      >
                        {exportingDiag ? (
                          <Loader2 size={12.5} strokeWidth={1.85} className="guard-spin" />
                        ) : (
                          <ExternalLink size={12.5} strokeWidth={1.45} style={{ color: "var(--text-2)" }} />
                        )}
                        <span>
                          {exportingDiag
                            ? "正在打包脱敏诊断包与运行日志..."
                            : "导出脱敏问题包给 AI 分析"}
                        </span>
                      </button>
                    </>
                  )}
                </div>
              </div>
            )}
          </aside>
        </ThinScrollArea>
      </div>
    </section>
  );
}

const partHdStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 10,
  marginBottom: 10,
  padding: "0 2px",
};

const partTitleStyle: React.CSSProperties = {
  fontSize: 12.5,
  fontWeight: 500,
  color: "var(--text-strong)",
  whiteSpace: "nowrap",
  flexShrink: 0,
};

const detLblStyle: React.CSSProperties = {
  fontSize: 11,
  fontWeight: 400,
  color: "var(--text-3)",
  marginBottom: 7,
};
