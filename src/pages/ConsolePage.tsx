import { useEffect, useState } from "react";
import { BookOpen, ChevronRight, KeyRound, Loader2, Lock, Play, Power, RefreshCw } from "lucide-react";
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

/** 未激活免费体验态仅公开展示 3 项基础连通探针（左右标题与状态全公开），其余核心防封项左右均隐藏 */
const FREE_PREVIEW_CHECK_IDS = new Set(["node_proxy", "node_tun", "sys_ipv6"]);

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
  const licenseStatus = useGuardStore((s) => s.licenseStatus);
  const setLicenseModalOpen = useGuardStore((s) => s.setLicenseModalOpen);

  const isLicensed = !licenseStatus.commercialFeatureEnabled || licenseStatus.licensed;

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

  const isItemLocked = (id: string) => !isLicensed && !FREE_PREVIEW_CHECK_IDS.has(id);
  const freeItems = items.filter((x) => FREE_PREVIEW_CHECK_IDS.has(x.id));
  const freeOkCount = freeItems.filter((x) => x.status === "ok").length;
  const lockedCount = items.length - freeItems.length;
  const mustLockedCount = mustAll.filter((x) => !FREE_PREVIEW_CHECK_IDS.has(x.id)).length;

  // 为未激活隐藏项分配稳定编号，确保前端在任何模式下都不泄漏原始检测项目名称
  const lockedOrderMap = new Map<string, string>();
  let hiddenCursor = 0;
  for (const it of items) {
    if (!FREE_PREVIEW_CHECK_IDS.has(it.id)) {
      hiddenCursor += 1;
      lockedOrderMap.set(it.id, String(hiddenCursor).padStart(2, "0"));
    }
  }
  const getDisplayTitle = (it: PreflightItem) =>
    isItemLocked(it.id)
      ? `核心防封深度检测项 #${lockedOrderMap.get(it.id) ?? "00"}`
      : it.title;

  const blocked = mustFail > 0 || snapshot.killSwitchActive || snapshot.nodeDown;
  const guardStatusPill = !isLicensed
    ? {
        dotClass: "guard-dot",
        dotStyle: { background: "var(--text-3)" } as React.CSSProperties,
        label: "体验模式",
        color: "var(--text-2)",
        cursor: "pointer" as const,
        title: "免费基础体验模式，点击输入激活密钥解锁全量守护",
        onClick: () => setLicenseModalOpen(true),
      }
    : snapshot.killSwitchActive
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
        title: "11 项必须项均已实测通过，与悬浮窗守护状态一致",
        onClick: undefined,
      };
  const selectedItem = items.find((x) => x.id === selectedId) ?? items[0];
  const selectedLocked = selectedItem ? isItemLocked(selectedItem.id) : false;
  const isAcctHighRisk =
    selectedItem?.id === "claude_acct" &&
    selectedItem.status === "fail" &&
    (selectedItem.summary.includes("最高危连坐") || selectedItem.summary.includes("受限"));
  const hitCount = isLicensed ? snapshot.triggeredPlaybookIds.length : 0;

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
    if (item.id === "node_geo") {
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
      const orgMatch = item.evidence.match(/Observed(?: Unique)? orgIds(?:\s*\(\d+\))?:\s*([^\n]+)/);
      const observedOrgs = (orgMatch?.[1] ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s && s !== "None");
      const latestOrg = observedOrgs[observedOrgs.length - 1] ?? "";
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
          : "绝不擅自乱删你的账号目录；清理登录态后会自动解绑旧主号，并同时消除本地封号残留与混号记录",
        rows: [
          {
            label: "当前检测",
            value: item.summary,
            tone: "danger",
          },
          {
            label: "分项清理",
            value:
              "打开透明分项清单（勾选清理 Cookie / 日志 / 缓存，默认保留 MCP 与 VM 镜像），清完自动重置主号绑定",
            tone: "ok",
          },
          {
            label: "仅换绑主号",
            value: latestOrg
              ? `不删目录，直接将本机绑定主号更新为 ${latestOrg}...（仅在确认本机无混号风险时使用）`
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
    const locked = isItemLocked(it.id);
    const displayTitle = getDisplayTitle(it);
    const boxCls = locked
      ? "guard-icon-box"
      : it.status === "fail"
      ? "guard-icon-box is-fail"
      : it.status === "warn"
      ? "guard-icon-box is-warn"
      : "guard-icon-box";
    const chip = locked ? (
      <span className="guard-chip guard-chip-mode" data-testid={`check-locked-chip-${it.id}`}>
        <Lock size={10} strokeWidth={2} />
        <span>已隐藏</span>
      </span>
    ) : it.status === "fail" ? (
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
            {locked ? <Lock size={14} strokeWidth={1.85} /> : <CheckIcon name={it.icon} />}
          </div>
          <div style={{ minWidth: 0 }}>
            {locked ? (
              <div
                data-testid={`check-locked-title-${it.id}`}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                  fontSize: 13.5,
                  fontWeight: 500,
                  color: "var(--text-3)",
                  lineHeight: 1.3,
                }}
              >
                <span>{displayTitle}</span>
                <span
                  aria-hidden="true"
                  style={{
                    display: "inline-block",
                    width: 64,
                    height: 10,
                    borderRadius: 4,
                    background:
                      "repeating-linear-gradient(-45deg, rgba(128,128,140,0.20), rgba(128,128,140,0.20) 4px, rgba(128,128,140,0.06) 4px, rgba(128,128,140,0.06) 8px)",
                    border: "1px solid var(--border)",
                  }}
                />
              </div>
            ) : (
              <div style={{ fontSize: 14, fontWeight: 500, color: "var(--text-1)", lineHeight: 1.3 }}>
                {displayTitle}
              </div>
            )}
            <div
              style={{
                fontSize: 12,
                color: locked ? "var(--text-3)" : "var(--text-2)",
                marginTop: 2,
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
                maxWidth: 320,
              }}
            >
              {locked ? "输入激活密钥后公开检测内容与实测状态" : it.summary}
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
            <span>控制台</span>
            {licenseStatus.commercialFeatureEnabled && !isLicensed && (
              <button
                type="button"
                data-testid="console-license-chip"
                onClick={() => setLicenseModalOpen(true)}
                className="guard-chip guard-chip-mode"
                style={{ cursor: "pointer", fontWeight: 500 }}
              >
                未激活 · 点击激活
              </button>
            )}
            {isLicensed && snapshot.killSwitchActive && (
              <span
                data-testid="console-killswitch-status"
                style={{ display: "inline-flex", alignItems: "center", gap: 6, marginLeft: 4 }}
              >
                <span
                  className="guard-chip guard-chip-fail"
                  style={{ fontWeight: 600 }}
                  title="防火墙已锁死 Claude 全部出站流量，请确认代理环境安全后解除熔断"
                >
                  已自动熔断
                </span>
                <button
                  type="button"
                  data-testid="btn-console-release-killswitch"
                  disabled={releasingKs}
                  className="guard-btn guard-btn-flat guard-btn-xs"
                  onClick={() => {
                    openRiskModal({
                      tone: "warn",
                      badge: "解除自动熔断",
                      title: "确认解除防火墙出站熔断锁？",
                      subtitle: "解除后将删除 FDClaudeGuard_KillSwitch 防火墙阻断规则，允许重新通信",
                      rows: [
                        {
                          label: "当前状态",
                          value: "防火墙已自动熔断并阻断 Claude 全部出站流量",
                          tone: "danger",
                        },
                        {
                          label: "放行建议",
                          value:
                            mustFail > 0
                              ? `当前仍有 ${mustFail} 项必须体检未通过，建议解除熔断前先修复异常项`
                              : "当前 11 项必须体检已全部通过，可安全解除熔断",
                          tone: mustFail > 0 ? "danger" : "ok",
                        },
                      ],
                      primaryLabel: "确认解除熔断并复测",
                      onPrimary: async () => {
                        setReleasingKs(true);
                        try {
                          await ipc.forceReleaseKillswitch(true);
                          pushToast(
                            "已解除自动熔断",
                            "防火墙阻断规则已清理，正在重跑真实探针复核。",
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
                  }}
                >
                  {releasingKs ? "解除中..." : "解除熔断"}
                </button>
              </span>
            )}
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
            <span>
              {isLicensed
                ? `启动前实测体检 · 事件实时监听中 · ${auditCountdownLabel}`
                : "免费基础体验体检"}
            </span>
            {isLicensed ? (
              <>
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
              </>
            ) : (
              <>
                <span className="guard-chip guard-chip-ok">
                  基础体验 {freeOkCount}/{freeItems.length}
                </span>
                <span className="guard-chip guard-chip-mode">
                  其余 {lockedCount} 项深度体检待解锁
                </span>
                {deepAudit.running && (
                  <span
                    data-testid="console-deep-audit-badge"
                    className="guard-chip guard-chip-mode tabular"
                    style={{ display: "inline-flex", alignItems: "center", gap: 5 }}
                    title="后台正在预先静默核验节点质量，激活后即可直接查看"
                  >
                    <Loader2 size={10} strokeWidth={2.2} className="guard-spin" />
                    <span>
                      后台预核验节点 {deepAudit.currentIndex}/{deepAudit.total || "?"}
                    </span>
                  </span>
                )}
              </>
            )}
          </div>
        </div>

        {/* 单一蓝色主 CTA 原则：未激活态统一引导激活解锁；已激活按待办数智能分配唯一蓝主焦点 */}
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
            onClick={() => {
              if (!isLicensed) {
                setLicenseModalOpen(true);
                return;
              }
              setPlaybookOpen(true);
            }}
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
            <span>{checking ? "实测中..." : isLicensed ? "重新实测" : "刷新体验项"}</span>
          </button>

          {!isLicensed ? (
            <button
              type="button"
              data-testid="btn-batch-fix-all"
              className="guard-btn guard-btn-primary"
              onClick={() => setLicenseModalOpen(true)}
            >
              <KeyRound size={14} strokeWidth={1.9} />
              <span>激活解锁全量体检</span>
            </button>
          ) : mustFail >= 2 ? (
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
          ) : blocked ? (
            <button type="button" className="guard-btn guard-btn-primary" disabled>
              <Lock size={14} strokeWidth={1.9} />
              <span>
                {snapshot.killSwitchActive
                  ? "已熔断 · 请先解除熔断"
                  : snapshot.nodeDown && mustFail === 0
                  ? "当前节点不可用 · 请更换节点"
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
              onClick={() => {
                if (!isLicensed) {
                  setLicenseModalOpen(true);
                  return;
                }
                void safeLaunchClaude();
              }}
            >
              {launching ? (
                <Loader2 size={14} strokeWidth={2} className="guard-spin" />
              ) : !isLicensed ? (
                <Lock size={14} strokeWidth={1.9} />
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
          <div>
            <div style={partHdStyle}>
              <div style={{ ...partTitleStyle, whiteSpace: "nowrap", flexShrink: 0 }}>
                <span>一、必须通过</span>
                {!isLicensed && (
                  <span className="guard-chip guard-chip-mode tabular">
                    体验 {freeItems.length}/{mustAll.length}
                  </span>
                )}
              </div>
              <span
                className="tabular"
                style={{ fontSize: 12, color: "var(--text-3)", textAlign: "right" }}
              >
                {isLicensed ? (
                  <>
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
                  </>
                ) : (
                  `仅公开 ${freeItems.length} 项基础体验，其余 ${mustLockedCount} 项核心检测名称与状态均已隐藏`
                )}
              </span>
            </div>

            {MUST_CATEGORIES.map((cat) => {
              const catItems = mustAll.filter((x) => x.cat === cat);
              const hasAnyPublic = catItems.some((x) => FREE_PREVIEW_CHECK_IDS.has(x.id));
              const catLabel =
                !isLicensed && !hasAnyPublic ? "3. 核心隐私与防封深度审计（激活后公开）" : cat;
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
                    {catLabel}
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
                  {isLicensed ? `${optOk}/${optAll.length}` : "激活后公开"}
                </span>
              </div>
              <span style={{ fontSize: 12, color: "var(--text-3)" }}>
                {isLicensed
                  ? "含启动项、时区与浏览器隐私监测，不阻断启动"
                  : "输入激活密钥后公开检测内容与实测状态"}
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
                    selectedLocked
                      ? "guard-icon-box"
                      : selectedItem.status === "fail"
                      ? "guard-icon-box is-fail"
                      : selectedItem.status === "warn"
                      ? "guard-icon-box is-warn"
                      : "guard-icon-box"
                  }
                  style={{ width: 36, height: 36 }}
                >
                  {selectedLocked ? (
                    <Lock size={17} strokeWidth={1.85} />
                  ) : (
                    <CheckIcon name={selectedItem.icon} size={17} />
                  )}
                </div>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                    <h2
                      data-testid="detail-item-title"
                      style={{ fontSize: 16, fontWeight: 600, lineHeight: 1.3, margin: 0 }}
                    >
                      {getDisplayTitle(selectedItem)}
                    </h2>
                    {selectedLocked ? (
                      <span className="guard-chip guard-chip-mode">
                        <Lock size={10} strokeWidth={2} />
                        <span>检测内容与状态已隐藏</span>
                      </span>
                    ) : (
                      <>
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
                      </>
                    )}
                  </div>
                  <p
                    style={{
                      fontSize: 12,
                      color: "var(--text-2)",
                      margin: "4px 0 0",
                      lineHeight: 1.55,
                    }}
                  >
                    {selectedLocked
                      ? "该项属于核心防封深度实测，具体检测项目、实测状态与修复步骤均已隐藏，输入一次性激活密钥后立即开启。"
                      : selectedItem.summary}
                  </p>
                </div>
              </div>

              <div>
                <div style={detLblStyle}>真实探针实测数据</div>
                {selectedLocked ? (
                  <div
                    role="button"
                    tabIndex={0}
                    data-testid="evidence-mosaic-locked"
                    aria-label="已锁定的实测数据，点击输入激活密钥解锁"
                    title="点击输入激活密钥解锁深度实测数据"
                    className="guide-box is-locked"
                    onClick={() => setLicenseModalOpen(true)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setLicenseModalOpen(true);
                      }
                    }}
                  >
                    <div className="guide-blur-txt" aria-hidden="true">
                      LOCKED PROBE DATA ████████████████████████████████████████
                      ████████████████████████████████████████████████████
                    </div>
                    <div className="guide-lock-overlay" />
                  </div>
                ) : (
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
                )}
              </div>

              <div>
                <div style={detLblStyle}>处理方式与验证说明</div>
                {!isLicensed && (selectedLocked || selectedItem.status !== "ok") ? (
                  /* 增量 19：未激活态纯净毛玻璃斜纹马赛克，前端绝无明文，遮罩内不放居中文字胶囊 */
                  <div
                    role="button"
                    tabIndex={0}
                    data-testid="guide-mosaic-locked"
                    aria-label="已加密的处理方案，点击输入激活密钥解锁"
                    title="点击输入激活密钥解锁清晰处理步骤"
                    className="guide-box is-locked"
                    onClick={() => setLicenseModalOpen(true)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setLicenseModalOpen(true);
                      }
                    }}
                  >
                    <div className="guide-blur-txt" aria-hidden="true">
                      AES-256-GCM 密文占位 ████████████████████████████████████████
                      ████████████████████████████████████████████████████
                    </div>
                    <div className="guide-lock-overlay" />
                  </div>
                ) : (
                  <div
                    data-testid="guide-plaintext"
                    className="guide-box"
                    style={isAcctHighRisk ? { borderLeftColor: "var(--danger)" } : undefined}
                  >
                    {selectedItem.guide || "该项已通过真实探针验证。"}
                  </div>
                )}
              </div>

              {!selectedLocked && selectedItem.status === "ok" ? (
                <div style={{ fontSize: 12, color: "var(--success)", fontWeight: 500 }}>
                  该项已通过真实探针验收，无需额外操作。
                </div>
              ) : !isLicensed ? (
                /* 未激活态唯一行动焦点：高对比白色主按钮，且隐藏底部「导出脱敏问题包给 AI 分析」链接 */
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  <button
                    type="button"
                    data-testid="btn-unlock-license-cta"
                    className="guard-btn guard-btn-secondary"
                    style={{ padding: 10 }}
                    onClick={() => setLicenseModalOpen(true)}
                  >
                    <KeyRound size={14} strokeWidth={2} />
                    <span>输入激活密钥 · 解锁步骤并一键处理</span>
                  </button>
                </div>
              ) : (
                /* 已激活态严格保留 ISS-009：只要 status !== "ok" 始终显示排障包导出 */
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {selectedItem.id === "node_geo" && selectedItem.status === "warn" ? (
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
