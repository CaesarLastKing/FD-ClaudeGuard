import { useCallback, useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  Check,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  Globe,
  Info,
  LifeBuoy,
  Loader2,
  Play,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { XBrandIcon } from "@/components/SupportModal";
import { ThinScrollArea } from "@/components/ThinScrollArea";
import { ipc } from "@/lib/ipc";
import {
  OFFICIAL_AUTHOR_X_HANDLE,
  OFFICIAL_AUTHOR_X_URL,
  OFFICIAL_CLASH_VERGE_RELEASES_URL,
  OFFICIAL_CLASH_VERGE_REPO_URL,
  OFFICIAL_GITHUB_RELEASES_URL,
  OFFICIAL_GITHUB_REPO_URL,
} from "@/lib/protocol";
import { useGuardStore } from "@/stores/guardStore";
import type {
  AppConfig,
  BackupInfo,
  ClaudeDataRootsSummary,
  NetworkRescueReport,
  RollbackOverview,
  SettingsModalTab,
} from "@/types/guard";

type BoolConfigKey =
  | "showHud"
  | "notifyEnabled"
  | "bootStart"
  | "bootHudOnly"
  | "wakePreblockGuard"
  | "antiNakedGuard"
  | "autoKillSwitch"
  | "antiUploadFlush"
  | "safeExitPrompt"
  | "calm24h"
  | "lockCfAndStripeToClaude";

interface PopoverState {
  title: string;
  body: string;
  left: number;
  top: number;
}

const TAB_META: Record<SettingsModalTab, { title: string; sub: string }> = {
  general: { title: "常规开关", sub: "悬浮窗、开机自启与诊断日志隐私设置" },
  policy: { title: "安全策略", sub: "全链路 4 层纵深防护 · 悬停 ⓘ 查看详解" },
  recovery: { title: "清理恢复", sub: "" },
  update: { title: "版本更新", sub: "官方签名更新通道，优先走本机代理" },
};

const STARTUP_ADVICE_MAP: Record<string, { rec: string; fallback: string }> = {
  "Clash Verge": {
    rec: "建议开启 · ",
    fallback: "让代理早于 Claude 启动，避免开机直连",
  },
  "Claude Desktop": {
    rec: "建议关闭 · ",
    fallback: "防止早于代理抢跑启动导致真实 IP 暴露",
  },
  "FD Claude 安全启动器": {
    rec: "建议开启 · ",
    fallback: "随系统后台静默守护，第一时间拦截风险",
  },
};

function kindLabel(k: string): string {
  if (k === "pre-restore") return "还原前安全点";
  if (k === "clean") return "清理前备份";
  if (k === "manual") return "手动快照";
  return "历史快照";
}

/**
 * 居中双栏「系统设置」模态弹窗（UI v3.0 精修终版）
 * 严格 1:1 对齐 docs/mockups/ui-v3-settings-modal-preview.html 与 docs/prompt-ui-v3-settings-modal.md
 */
export function SettingsModal() {
  const open = useGuardStore((s) => s.settingsModalOpen);
  const tab = useGuardStore((s) => s.settingsModalTab);
  const setTab = useGuardStore((s) => s.setSettingsModalTab);
  const close = useGuardStore((s) => s.closeSettingsModal);
  const config: AppConfig = useGuardStore((s) => s.config);
  const snapshot = useGuardStore((s) => s.snapshot);
  const startupAudit = useGuardStore((s) => s.startupAudit);
  const updateConfig = useGuardStore((s) => s.updateConfig);
  const updateInfo = useGuardStore((s) => s.updateInfo);
  const updateChecking = useGuardStore((s) => s.updateChecking);
  const updateInstalling = useGuardStore((s) => s.updateInstalling);
  const updateProgress = useGuardStore((s) => s.updateProgress);
  const updateError = useGuardStore((s) => s.updateError);
  const checkForAppUpdate = useGuardStore((s) => s.checkForAppUpdate);
  const installAppUpdate = useGuardStore((s) => s.installAppUpdate);
  const openRiskModal = useGuardStore((s) => s.openRiskModal);
  const openCleanModal = useGuardStore((s) => s.openCleanModal);
  const refreshPreflight = useGuardStore((s) => s.refreshPreflight);
  const pushToast = useGuardStore((s) => s.pushToast);
  const networkRescueAlert = useGuardStore((s) => s.networkRescueAlert);
  const setNetworkRescueAlert = useGuardStore((s) => s.setNetworkRescueAlert);

  const [popover, setPopover] = useState<PopoverState | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [copiedX, setCopiedX] = useState(false);
  const [overview, setOverview] = useState<RollbackOverview | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(false);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [rescueReport, setRescueReport] = useState<NetworkRescueReport | null>(null);
  const [backups, setBackups] = useState<BackupInfo[]>([]);
  const [rootsSummary, setRootsSummary] = useState<ClaudeDataRootsSummary>({
    classicDetected: true,
    msixPackages: [],
    telemetryExists: true,
  });

  const autoUpdateCheckedRef = useRef(false);

  const loadRecoveryData = useCallback(async () => {
    setOverviewLoading(true);
    setOverviewError(null);
    try {
      const [ov, baks, roots] = await Promise.all([
        ipc.inspectRollbackStatus(),
        ipc.listBackups().catch(() => [] as BackupInfo[]),
        ipc.inspectClaudeDataRoots().catch(() => ({
          classicDetected: true,
          msixPackages: [],
          telemetryExists: true,
        })),
      ]);
      setOverview(ov);
      setBackups(baks);
      setRootsSummary(roots);
      const hasLoopbackDns = (ov.loopbackDnsAdapters?.length ?? 0) > 0;
      const hasResidualFw = Boolean(ov.activeFirewallRules) && !useGuardStore.getState().snapshot.killSwitchActive;
      setNetworkRescueAlert(hasLoopbackDns || hasResidualFw);
    } catch (err) {
      setOverviewError(String(err));
    } finally {
      setOverviewLoading(false);
    }
  }, [setNetworkRescueAlert]);

  useEffect(() => {
    if (!open) {
      setPopover(null);
      return;
    }
    if (tab === "recovery") {
      void loadRecoveryData();
    } else if (tab === "update" && !autoUpdateCheckedRef.current && !updateInfo && !updateChecking && !updateError) {
      autoUpdateCheckedRef.current = true;
      void checkForAppUpdate(true);
    }
  }, [open, tab, loadRecoveryData, updateInfo, updateChecking, updateError, checkForAppUpdate]);

  // Esc 仅在无上层弹窗（SupportModal / CleanConfirmModal / RiskModal / PlaybookDrawer）打开时关闭系统设置
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      const st = useGuardStore.getState();
      if (st.supportModalOpen || st.cleanModal?.open || st.riskModal?.open || st.playbookOpen) {
        return;
      }
      close();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, close]);

  if (!open) return null;

  const busy = busyKey !== null;
  const appVersionLabel =
    typeof __APP_VERSION__ === "string" && __APP_VERSION__ ? `v${__APP_VERSION__}` : "v0.4.0";

  const showPopover = (el: HTMLElement, title: string, body: string) => {
    const rect = el.getBoundingClientRect();
    const pw = 308;
    const ph = 96;
    let left = rect.left - 12;
    if (left + pw > window.innerWidth - 16) left = window.innerWidth - pw - 16;
    if (left < 16) left = 16;
    let top = rect.bottom + 8;
    if (top + ph > window.innerHeight - 16) top = Math.max(16, rect.top - ph - 8);
    setPopover({ title, body, left, top });
  };

  const hidePopover = () => setPopover(null);

  const renderInfoBtn = (title: string, body: string) => (
    <button
      type="button"
      className="info-trigger"
      aria-label={`查看「${title}」详细说明`}
      onMouseEnter={(e) => showPopover(e.currentTarget, title, body)}
      onMouseLeave={hidePopover}
      onClick={(e) => {
        e.stopPropagation();
        showPopover(e.currentTarget, title, body);
      }}
    >
      <Info size={12.5} strokeWidth={1.65} />
    </button>
  );

  const handleToggle = (key: BoolConfigKey, next: boolean, label: string) => {
    void updateConfig({ [key]: next }, label);
  };

  const renderSwitchRow = (opts: {
    configKey: BoolConfigKey;
    title: string;
    desc: string;
    fullDesc?: string;
    badge?: { text: string; tone: "ok" | "neutral" | "warn" };
    checked: boolean;
    disabled?: boolean;
  }) => {
    const { configKey, title, desc, fullDesc, badge, checked, disabled } = opts;
    const doToggle = () => {
      if (disabled) return;
      handleToggle(configKey, !checked, title);
    };
    const pillCls =
      badge?.tone === "ok"
        ? "guard-chip-pass"
        : badge?.tone === "warn"
        ? "guard-chip-warn"
        : "guard-chip-neutral";
    return (
      <div
        className={`s-row ${disabled ? "is-disabled" : "is-clickable"}`}
        onClick={doToggle}
      >
        <div className="s-row-info">
          <div className="s-row-top">
            <span className="s-row-title">{title}</span>
            {fullDesc && renderInfoBtn(title, fullDesc)}
          </div>
          <div className="s-row-desc">{desc}</div>
        </div>
        <div className="s-row-ctrl">
          {badge && (
            <span className={`guard-chip ${pillCls}`} style={{ minWidth: 66 }}>
              {badge.text}
            </span>
          )}
          <button
            type="button"
            role="switch"
            aria-checked={checked}
            aria-label={title}
            disabled={disabled}
            className={`s-switch ${checked ? "on" : ""}`}
            onClick={(e) => {
              e.stopPropagation();
              doToggle();
            }}
          />
        </div>
      </div>
    );
  };

  const renderBuiltinRow = (title: string, desc: string, fullDesc: string) => (
    <div className="s-row is-builtin">
      <div className="s-row-info">
        <div className="s-row-top">
          <span className="s-row-title">{title}</span>
          {renderInfoBtn(`${title}（系统常驻开启）`, fullDesc)}
        </div>
        <div className="s-row-desc">{desc}</div>
      </div>
      <div className="s-row-ctrl">
        <span
          className="guard-chip guard-chip-neutral"
          style={{ minWidth: 66, color: "var(--text-3)" }}
        >
          常驻开启
        </span>
        <button
          type="button"
          role="switch"
          aria-checked="true"
          aria-label={`${title}（系统常驻开启）`}
          disabled
          title="系统核心防线，常驻开启不可关闭"
          className="s-switch is-locked"
        />
      </div>
    </div>
  );

  // 真实 IPC 操作集合
  const handleManualUploadDiag = async () => {
    setBusyKey("upload_diag");
    try {
      const res = await ipc.submitAnonymousFeedbackReport();
      pushToast(
        `脱敏诊断日志已上传 · 单号 ${res.ticketId}`,
        `已脱敏上传 ${Math.max(1, Math.round(res.uploadedBytes / 1024))} KB 诊断摘要（14 天自动清理），反馈问题时附上该单号即可精准定位。`,
        "ok",
        {
          durationMs: 8000,
          action: {
            label: "复制单号",
            onClick: () => {
              void navigator.clipboard?.writeText(res.ticketId).catch(() => {});
              pushToast("已复制排障单号", res.ticketId, "ok");
            },
          },
        }
      );
    } catch (err) {
      pushToast("脱敏日志上传失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleOpenExternal = async (url: string) => {
    try {
      await ipc.openExternalUrl(url);
    } catch (err) {
      pushToast("打开外部链接失败", String(err), "danger");
    }
  };

  const handleOpenLogDir = async () => {
    try {
      const dir = await ipc.openGuardLogsDir();
      pushToast("已打开结构化运行日志目录", dir, "ok");
    } catch (err) {
      pushToast("打开日志目录失败", String(err), "danger");
    }
  };

  const handleExportDiag = async () => {
    setBusyKey("export_diag");
    try {
      const res = await ipc.exportAiDiagnosticBundle();
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(res.promptMarkdown).catch(() => {});
      }
      pushToast(
        "已导出脱敏诊断包并复制 AI 排障提示词",
        `保存路径：${res.zipPath}`,
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
      setBusyKey(null);
    }
  };

  const handleToggleKillswitch = async () => {
    if (snapshot.killSwitchActive) {
      openRiskModal({
        tone: "danger",
        badge: "高危操作",
        title: "强制解除防火墙熔断",
        subtitle: "仅在确认当前网络已安全或暂不使用 Claude 时临时解除",
        rows: [
          {
            label: "当前状态",
            value: `熔断生效中 · 后台 Claude 进程 ${snapshot.bgClaudeProcs} 个`,
            tone: "danger",
          },
          {
            label: "安全建议",
            value: "建议先切回安全节点并完成启动前体检复测，系统将自动恢复放行。",
          },
        ],
        primaryLabel: "暂不解除，保持保护",
        onPrimary: () => {},
        dangerLabel: "忽略风险，强制解除",
        onDanger: async () => {
          const ks = await ipc.forceReleaseKillswitch(true);
          pushToast("已解除防火墙熔断", ks.reason, "info");
          void refreshPreflight(true);
        },
      });
    } else {
      setBusyKey("killswitch");
      try {
        const ks = await ipc.triggerKillswitch("用户在系统设置安全策略页手动触发 4 层紧急防回传");
        pushToast(
          "已激活 4 层紧急防回传熔断",
          `已掐断 ${ks.claudeConnectionsClosed} 条连接、强杀 ${ks.killedProcesses} 个进程并清扫 ${ks.telemetryClearedBytes} B 遥测缓存。`,
          "danger"
        );
      } catch (err) {
        pushToast("触发紧急熔断失败", String(err), "danger");
      } finally {
        setBusyKey(null);
      }
    }
  };

  const handleRunRescue = async () => {
    setBusyKey("rescue");
    try {
      const rep = await ipc.runNetworkEmergencyRescue();
      setRescueReport(rep);
      await loadRecoveryData();
      pushToast(
        rep.ok ? "网络急救完成" : "网络急救已执行（请查看明细）",
        rep.summary,
        rep.ok ? "ok" : "info"
      );
      void refreshPreflight(true);
    } catch (err) {
      pushToast("网络急救失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleCleanupAllFirewall = async () => {
    setBusyKey("fw_rescue");
    try {
      const msg = await ipc.cleanupAllGuardFirewallRules();
      await loadRecoveryData();
      pushToast("防火墙防自锁清理完成", msg, "ok");
      void refreshPreflight(true);
    } catch (err) {
      pushToast("清理防火墙规则失败", String(err), "danger");
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
          pushToast(rep.ok ? "单项撤回完成" : "单项撤回未完成", rep.message, rep.ok ? "ok" : "danger");
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
          pushToast(rep.allOk ? "已还原全部改动" : "部分项目撤回需关注", rep.summary, rep.allOk ? "ok" : "info");
          void refreshPreflight(true);
        } catch (err) {
          pushToast("批量撤回失败", String(err), "danger");
        } finally {
          setBusyKey(null);
        }
      },
    });
  };

  const handleKillAndClean = async () => {
    setBusyKey("kill");
    try {
      const rep = await ipc.killClaudeProcesses(true);
      pushToast("已完成应急清理", rep.message, "ok");
      void refreshPreflight(true);
    } catch (err) {
      pushToast("强制退出失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleManualBackup = async () => {
    setBusyKey("manual_backup");
    try {
      const info = await ipc.createManualBackup();
      await loadRecoveryData();
      pushToast("已创建手动快照", `已保存 ${info.fileName}（${info.sizeLabel}）。`, "ok");
    } catch (err) {
      pushToast("创建快照失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleRestore = async (fileName: string) => {
    setBusyKey(`restore:${fileName}`);
    try {
      const msg = await ipc.restoreBackup(fileName);
      await loadRecoveryData();
      pushToast("原子快照还原完成", msg, "ok");
      void refreshPreflight(true);
    } catch (err) {
      pushToast("还原快照失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleDeleteOne = async (fileName: string) => {
    setBusyKey(`delete:${fileName}`);
    try {
      const msg = await ipc.deleteBackup(fileName);
      await loadRecoveryData();
      pushToast("已删除备份快照", msg, "ok");
    } catch (err) {
      pushToast("删除备份失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleClearAllBackups = () => {
    openRiskModal({
      tone: "danger",
      badge: "不可逆清理",
      title: "清空全部历史备份快照",
      subtitle: `将永久删除 ~/FDtools-Backups/ 下的全部 ${backups.length} 份 ZIP 快照`,
      rows: [
        { label: "将删除数量", value: `${backups.length} 份历史 ZIP 快照`, tone: "danger" },
        { label: "安全说明", value: "仅删除本地备份归档，不会影响你当前的 Claude 登录态与项目代码。" },
      ],
      primaryLabel: "取消，保留备份",
      onPrimary: () => {},
      dangerLabel: "确认清空全部备份",
      onDanger: async () => {
        setBusyKey("clear_all");
        try {
          const cnt = await ipc.clearAllBackups();
          await loadRecoveryData();
          pushToast("已清空全部历史备份", `共删除 ${cnt} 份备份快照。`, "ok");
        } catch (err) {
          pushToast("清空备份失败", String(err), "danger");
        } finally {
          setBusyKey(null);
        }
      },
    });
  };

  const scrollToBlock = (blockId: string) => {
    const el = document.getElementById(blockId);
    if (el && typeof el.scrollIntoView === "function") {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const hasLoopbackDns = (overview?.loopbackDnsAdapters?.length ?? 0) > 0;
  const hasResidualFw = Boolean(overview?.activeFirewallRules) && !snapshot.killSwitchActive;
  const hasAlert = hasLoopbackDns || hasResidualFw || networkRescueAlert;
  const touchedCount = overview?.touchedCount ?? 0;

  const installBtnText = !updateInstalling
    ? `立即更新 v${updateInfo?.latestVersion ?? ""}`
    : updateProgress?.stage === "verifying"
    ? "正在校验签名..."
    : updateProgress?.percent != null
    ? `下载中 ${updateProgress.percent}%`
    : "正在下载更新包...";

  const meta = TAB_META[tab];

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="系统设置"
      data-testid="settings-modal"
      className="s-modal-scrim"
      onClick={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <div className="s-modal-shell">
        {/* 左栏 204px（扁平 4 项、去大分类标题、去平时数字角标） */}
        <aside className="s-modal-aside">
          <div>
            <div className="s-modal-brand">
              <span className="s-modal-brand-title">系统设置</span>
              <span className="s-modal-ver tabular">{appVersionLabel}</span>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
              <button
                type="button"
                data-testid="settings-tab-general"
                className={`s-nav-item ${tab === "general" ? "active" : ""}`}
                onClick={() => {
                  hidePopover();
                  setTab("general");
                }}
              >
                <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <SlidersHorizontal size={14} strokeWidth={1.45} />
                  <span>常规开关</span>
                </span>
              </button>

              <button
                type="button"
                data-testid="settings-tab-policy"
                className={`s-nav-item ${tab === "policy" ? "active" : ""}`}
                onClick={() => {
                  hidePopover();
                  setTab("policy");
                }}
              >
                <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <ShieldCheck size={14} strokeWidth={1.45} />
                  <span>安全策略</span>
                </span>
              </button>

              <button
                type="button"
                data-testid="settings-tab-recovery"
                className={`s-nav-item ${tab === "recovery" ? "active" : ""}`}
                onClick={() => {
                  hidePopover();
                  setTab("recovery");
                }}
              >
                <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <LifeBuoy size={14} strokeWidth={1.45} />
                  <span>清理恢复</span>
                </span>
                {hasAlert && (
                  <span
                    data-testid="settings-recovery-alert-dot"
                    style={{
                      width: 6,
                      height: 6,
                      borderRadius: "50%",
                      background: "var(--bad-dot)",
                      display: "inline-block",
                    }}
                  />
                )}
              </button>

              <button
                type="button"
                data-testid="settings-tab-update"
                className={`s-nav-item ${tab === "update" ? "active" : ""}`}
                onClick={() => {
                  hidePopover();
                  setTab("update");
                }}
              >
                <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <Download size={14} strokeWidth={1.45} />
                  <span>版本更新</span>
                </span>
              </button>
            </div>
          </div>

          <div className="s-modal-aside-foot">
            <span>修改即时生效</span>
            <span className="s-kbd-chip">Esc</span>
          </div>
        </aside>

        {/* 右栏主内容区 */}
        <section className="s-modal-main">
          <div className="s-modal-hd">
            <div style={{ display: "flex", alignItems: "baseline", gap: 9, minWidth: 0 }}>
              <h2 className="s-modal-hd-title">{meta.title}</h2>
              {tab === "recovery" ? (
                <span style={{ display: "inline-flex", alignItems: "center", gap: 2, fontSize: 11, color: "var(--text-3)" }}>
                  <button type="button" className="s-anchor-btn" onClick={() => scrollToBlock("s-blk-rescue")}>
                    网络急救
                  </button>
                  <span>·</span>
                  <button type="button" className="s-anchor-btn" onClick={() => scrollToBlock("s-blk-rollback")}>
                    配置撤回
                  </button>
                  <span>·</span>
                  <button type="button" className="s-anchor-btn" onClick={() => scrollToBlock("s-blk-clean")}>
                    本地清理
                  </button>
                  <span>·</span>
                  <button type="button" className="s-anchor-btn" onClick={() => scrollToBlock("s-blk-backup")}>
                    历史快照
                  </button>
                </span>
              ) : (
                <span className="s-modal-hd-sub">{meta.sub}</span>
              )}
            </div>
            <button
              type="button"
              aria-label="关闭系统设置"
              data-testid="btn-close-settings-modal"
              className="modal-close-btn"
              onClick={close}
            >
              <X size={14} strokeWidth={1.6} />
            </button>
          </div>

          <ThinScrollArea onScrollCapture={hidePopover}>
            <div className="s-modal-body">
              {/* ==================== 1. 常规开关 ==================== */}
              {tab === "general" && (
                <>
                  <div>
                    <div className="s-sec-hd">
                      <span className="s-sec-title">悬浮窗、通知与开机自启</span>
                      <span className="s-sec-note">苔绿标建议保持开启</span>
                    </div>
                    <div className="guard-card">
                      {renderSwitchRow({
                        configKey: "showHud",
                        title: "显示桌面悬浮状态窗",
                        desc: "桌面常驻小卡片看节点与流量，支持拖拽和靠右贴边",
                        fullDesc:
                          "开启后在桌面显示轻量悬浮状态窗，实时查看出口节点、日志与流量异常；支持任意位置拖拽、靠右贴边隐藏和双击顶栏折叠，与主窗口顶栏及托盘开关实时同步。",
                        badge: { text: "推荐开启", tone: "ok" },
                        checked: config.showHud,
                      })}
                      {renderSwitchRow({
                        configKey: "notifyEnabled",
                        title: "桌面预警消息提醒",
                        desc: "悬浮窗隐藏时发系统通知提醒，危急熔断不受静音影响",
                        fullDesc:
                          "当悬浮窗隐藏或贴边收起时，通过 Windows 原生通知推送预警；关闭此开关仅静音普通预警，遇到防火墙熔断或防裸奔拦截仍会强制强提醒。",
                        badge: { text: "推荐开启", tone: "ok" },
                        checked: config.notifyEnabled,
                      })}
                      {renderSwitchRow({
                        configKey: "bootStart",
                        title: "开机自动启动 FD Claude 安全启动器",
                        desc: "随系统开机在后台静默启动，先于 Claude 建立代理保护",
                        fullDesc:
                          "通过 Windows 高权限计划任务随开机静默启动守护引擎，确保在打开 Claude 之前就已建立防裸奔与网络监听。",
                        badge: { text: "推荐开启", tone: "ok" },
                        checked: config.bootStart,
                      })}
                      {renderSwitchRow({
                        configKey: "bootHudOnly",
                        title: "开机时仅显示桌面悬浮窗",
                        desc: config.bootStart
                          ? "开机不弹出大窗口，只在桌面安静显示悬浮状态卡（依赖开机自启）"
                          : "需先开启上方「开机自动启动」后才可配置此项",
                        badge: { text: "推荐开启", tone: "ok" },
                        checked: config.bootHudOnly,
                        disabled: !config.bootStart,
                      })}
                    </div>
                  </div>

                  <div>
                    <div className="s-sec-hd">
                      <span className="s-sec-title">开机启动项检查</span>
                      <span className="s-sec-note">仅只读检测，绝不擅自删除你的系统启动项</span>
                    </div>
                    <div className="guard-card">
                      {startupAudit.entries.map((entry) => {
                        const advice = STARTUP_ADVICE_MAP[entry.app];
                        const descText = advice
                          ? entry.detail?.startsWith("建议")
                            ? entry.detail
                            : `${advice.rec}${entry.detail || advice.fallback}`
                          : entry.detail;
                        const pillCls =
                          entry.riskLevel === "ok"
                            ? "guard-chip-pass"
                            : entry.riskLevel === "warn"
                            ? "guard-chip-warn"
                            : "guard-chip-neutral";
                        return (
                          <div key={entry.app} className="s-row">
                            <div className="s-row-info">
                              <div className="s-row-title">{entry.app}</div>
                              <div className="s-row-desc" title={descText}>
                                {descText}
                              </div>
                            </div>
                            <span
                              data-testid={`settings-startup-chip-${entry.app}`}
                              className={`guard-chip ${pillCls}`}
                              style={{ minWidth: 52 }}
                            >
                              {entry.enabled ? "已开启" : "未开启"}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div>
                    <div className="s-sec-hd">
                      <span className="s-sec-title">诊断日志与隐私</span>
                      <span className="s-sec-note">上报与导出前自动全量脱敏，绝不碰对话与代码</span>
                    </div>
                    <div className="guard-card">
                      {/* 真实脱敏诊断日志自动上传开关（Cloudflare Worker + D1，14 天自动清理，随时可关） */}
                      {(() => {
                        const autoUploadOn = Boolean(
                          config.telemetryToolDiagEnabled || config.telemetryClaudeSummaryEnabled
                        );
                        const toggleAutoUpload = () => {
                          const next = !autoUploadOn;
                          void updateConfig(
                            {
                              telemetryToolDiagEnabled: next,
                              telemetryClaudeSummaryEnabled: next,
                            },
                            next ? "已开启自动上传脱敏诊断日志" : "已关闭自动上传脱敏诊断日志"
                          );
                        };
                        return (
                          <div
                            className="s-row is-clickable"
                            data-testid="row-auto-upload-diag"
                            onClick={toggleAutoUpload}
                          >
                            <div className="s-row-info">
                              <div className="s-row-top">
                                <span className="s-row-title">允许自动上传脱敏诊断日志</span>
                                {renderInfoBtn(
                                  "允许自动上传脱敏诊断日志",
                                  "仅在发生真实故障（如 4 层热熔断、修复失败、封号实锤报错）时低频上传强脱敏摘要（每日上限 10 条、14 天自动销毁），绝不采集对话、代码、明文邮箱或 Token；可随时关闭。"
                                )}
                              </div>
                              <div className="s-row-desc">
                                仅遇严重异常时低频上报脱敏诊断摘要（14 天自动清理），协助定位兼容性问题
                              </div>
                            </div>
                            <div className="s-row-ctrl">
                              <span
                                className={`guard-chip ${
                                  autoUploadOn ? "guard-chip-pass" : "guard-chip-neutral"
                                }`}
                                style={{ minWidth: 66 }}
                              >
                                {autoUploadOn ? "已开启" : "已关闭"}
                              </span>
                              <button
                                type="button"
                                role="switch"
                                aria-checked={autoUploadOn}
                                aria-label="允许自动上传脱敏诊断日志"
                                className={`s-switch ${autoUploadOn ? "on" : ""}`}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggleAutoUpload();
                                }}
                              />
                            </div>
                          </div>
                        );
                      })()}

                      {renderBuiltinRow(
                        "敏感信息自动脱敏处理",
                        "自动打码邮箱、Cookie、密钥与本机路径，不采集对话与代码",
                        "所有日志上传与 AI 诊断包导出均强制经过本地与服务端双重脱敏引擎，自动替换邮箱、sk-ant 密钥、Session Cookie、组织 ID 原文与 Windows 用户名路径，无法关闭。"
                      )}

                      <div className="s-row">
                        <div className="s-row-info">
                          <div className="s-row-top">
                            <span className="s-row-title">手动排查与日志工具</span>
                            {renderInfoBtn(
                              "手动排查与日志工具",
                              "日志目录：打开本机结构化 JSONL 日志文件夹；导出 AI 诊断包：打包近 7 天脱敏日志并复制排障提示词；主动上传：一键上传脱敏诊断并生成唯一排障单号（FD-YYYYMMDD-XXXXXXXX），便于发给作者定位。"
                            )}
                          </div>
                          <div className="s-row-desc">
                            遇到疑难排障时可导出脱敏诊断包，或一键主动上传获取排障单号
                          </div>
                        </div>
                        <div className="s-row-ctrl">
                          <button
                            type="button"
                            data-testid="btn-settings-open-log-dir"
                            className="guard-btn guard-btn-flat guard-btn-xs"
                            onClick={() => void handleOpenLogDir()}
                          >
                            日志目录
                          </button>
                          <button
                            type="button"
                            data-testid="btn-settings-export-diag"
                            disabled={busy}
                            className="guard-btn guard-btn-flat guard-btn-xs"
                            onClick={() => void handleExportDiag()}
                          >
                            {busyKey === "export_diag" && <Loader2 size={11} className="guard-spin" />}
                            <span>导出 AI 诊断包</span>
                          </button>
                          <button
                            type="button"
                            data-testid="btn-settings-manual-upload"
                            disabled={busy}
                            title="一键匿名上传强脱敏诊断摘要并返回唯一排障单号"
                            className="guard-btn guard-btn-flat guard-btn-xs"
                            style={{
                              color: "var(--primary)",
                              borderColor: "var(--primary-border)",
                              background: "var(--primary-soft)",
                              boxShadow: "none",
                            }}
                            onClick={() => void handleManualUploadDiag()}
                          >
                            {busyKey === "upload_diag" && <Loader2 size={11} className="guard-spin" />}
                            <span>{busyKey === "upload_diag" ? "上传中..." : "主动上传"}</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </>
              )}

              {/* ==================== 2. 安全策略 ==================== */}
              {tab === "policy" && (
                <>
                  {/* 上方独立卡片：核心特色与 4 步运行闭环 */}
                  <div className="s-flow-card">
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
                      <span
                        style={{
                          fontSize: 12,
                          fontWeight: 500,
                          color: "var(--text-strong)",
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                        }}
                      >
                        <Shield size={13.5} strokeWidth={1.6} style={{ color: "var(--primary)" }} />
                        <span>核心特色 · 4 层纵深防护与 2 秒热熔断闭环</span>
                      </span>
                      <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                        灰蓝开关为系统常驻 · 亮蓝开关可按需调节
                      </span>
                    </div>

                    <div className="s-flow-steps">
                      <div className="s-flow-step">
                        <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11.5, fontWeight: 500, color: "var(--text-strong)", whiteSpace: "nowrap" }}>
                          <span className="s-flow-step-num tabular">1</span>
                          <span>启动前拦裸奔</span>
                        </div>
                        <div style={{ marginTop: 3, fontSize: 10.5, color: "var(--text-2)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                          必须项未全绿禁止直连
                        </div>
                      </div>
                      <div style={{ color: "var(--text-4)", display: "grid", placeItems: "center" }}>
                        <ArrowRight size={11.5} strokeWidth={1.7} />
                      </div>
                      <div className="s-flow-step">
                        <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11.5, fontWeight: 500, color: "var(--text-strong)", whiteSpace: "nowrap" }}>
                          <span className="s-flow-step-num tabular">2</span>
                          <span>运行中锁链路</span>
                        </div>
                        <div style={{ marginTop: 3, fontSize: 10.5, color: "var(--text-2)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                          业务域入 Fixed + 查脱组
                        </div>
                      </div>
                      <div style={{ color: "var(--text-4)", display: "grid", placeItems: "center" }}>
                        <ArrowRight size={11.5} strokeWidth={1.7} />
                      </div>
                      <div className="s-flow-step is-accent">
                        <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11.5, fontWeight: 500, color: "var(--text-strong)", whiteSpace: "nowrap" }}>
                          <span className="s-flow-step-num tabular">3</span>
                          <span>异常断流秒热熔断</span>
                        </div>
                        <div style={{ marginTop: 3, fontSize: 10.5, color: "var(--text-2)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                          毫秒级熔断 + 防火墙封出站
                        </div>
                      </div>
                      <div style={{ color: "var(--text-4)", display: "grid", placeItems: "center" }}>
                        <ArrowRight size={11.5} strokeWidth={1.7} />
                      </div>
                      <div className="s-flow-step">
                        <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11.5, fontWeight: 500, color: "var(--text-strong)", whiteSpace: "nowrap" }}>
                          <span className="s-flow-step-num tabular">4</span>
                          <span>强杀后防回传</span>
                        </div>
                        <div style={{ marginTop: 3, fontSize: 10.5, color: "var(--text-2)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                          清遥测 + 250ms 盯防
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* 下方独立区块：用户紧急措施 */}
                  <div>
                    <div className="s-sec-hd">
                      <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                        <span className="s-sec-title">用户紧急措施</span>
                        <span className={`guard-chip ${snapshot.killSwitchActive ? "guard-chip-fail" : "guard-chip-pass"}`}>
                          {snapshot.killSwitchActive ? "熔断封锁中" : "自动守护待命"}
                        </span>
                      </div>
                      <span className="s-sec-note">自动检测并触发，极端异常时用户也可手动触发</span>
                    </div>
                    <div
                      className="guard-card"
                      style={{
                        padding: "13px 15px",
                        borderColor: snapshot.killSwitchActive ? "var(--bad-border)" : undefined,
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0, flex: 1 }}>
                          <div
                            className={`guard-icon-box ${snapshot.killSwitchActive ? "is-fail" : ""}`}
                            style={
                              !snapshot.killSwitchActive
                                ? {
                                    background: "var(--primary-soft)",
                                    color: "var(--primary)",
                                    borderColor: "var(--primary-border)",
                                  }
                                : undefined
                            }
                          >
                            <ShieldAlert size={14} strokeWidth={1.6} />
                          </div>
                          <div className="s-row-info">
                            <div className="s-row-top">
                              <span style={{ fontSize: 13, fontWeight: 500, color: "var(--text-strong)" }}>
                                4 层紧急熔断控制
                              </span>
                              {renderInfoBtn(
                                "4 层紧急熔断控制",
                                "平时由 L3 自动策略静默检测并触发；若你在极端异常时刻需要立即手动断网，点击右侧「手动触发熔断」将毫秒级掐断全部 Claude 连接、写入 Defender 防火墙阻断规则并开启防复活盯防。确认网络安全后点「解除熔断保护」恢复。"
                              )}
                            </div>
                            <div className="s-row-desc">
                              {snapshot.killSwitchActive
                                ? "防火墙已封锁 Claude 全部出站并锁定防复活，确认网络恢复后可解除"
                                : "一键强制掐断全部 Claude 连接、防火墙封死出站并启动防复活盯防"}
                            </div>
                          </div>
                        </div>
                        <button
                          type="button"
                          data-testid="btn-settings-killswitch"
                          disabled={busy}
                          className={snapshot.killSwitchActive ? "guard-btn guard-btn-flat" : "guard-btn-danger-hero"}
                          onClick={() => void handleToggleKillswitch()}
                        >
                          {busyKey === "killswitch" && <Loader2 size={12.5} className="guard-spin" />}
                          <span>{snapshot.killSwitchActive ? "解除熔断保护" : "手动触发熔断"}</span>
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* L1：入口防线 */}
                  <div>
                    <div className="s-sec-hd">
                      <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                        <span className="s-layer-tag tabular">L1</span>
                        <span className="s-sec-title">入口防线 · 启动前与切网拦截</span>
                      </div>
                      <span className="s-sec-note">先检门禁 → 再拦裸奔 → 再护唤醒切网</span>
                    </div>
                    <div className="guard-card">
                      {renderBuiltinRow(
                        "启动前必须项硬门禁",
                        "未通过代理、TUN、Fake-IP、IPv6、出口与卫生体检前锁定安全启动",
                        "系统内置强门禁（不可关闭）：涵盖代理端口、Claude-Fixed 策略组、TUN 虚拟网卡、Fake-IP 防 DNS 泄漏、IPv6 禁用、出口合规与封号污染排查，全部通过后才放行「安全启动 Claude」。"
                      )}
                      {renderSwitchRow({
                        configKey: "antiNakedGuard",
                        title: "防裸奔自动接管",
                        desc: "环境没全绿直接双击 Claude 时自动拦下并切回控制台",
                        fullDesc:
                          "检测到你在启动前必须项未全绿时直接双击桌面原生 Claude 图标，500ms 内自动写入防火墙出站拦截并唤起控制台提示修复，彻底杜绝误点导致真实 IP 暴露。",
                        badge: { text: "推荐开启", tone: "ok" },
                        checked: config.antiNakedGuard,
                      })}
                      {renderSwitchRow({
                        configKey: "wakePreblockGuard",
                        title: "休眠唤醒 / 切网 15 秒预阻断",
                        desc: "电脑醒来或切换网络时先暂停联网，等代理稳了自动放行",
                        fullDesc:
                          "监听笔记本合盖唤醒或切换 Wi-Fi 瞬间，先挂上最长 15 秒临时出站保护；待 Clash 命名管道、TUN 虚拟网卡与白名单节点全部复测通过后毫秒级自动放行，超时未恢复自动转入熔断。",
                        badge: { text: "推荐开启", tone: "ok" },
                        checked: config.wakePreblockGuard,
                      })}
                    </div>
                  </div>

                  {/* L2：链路防线 */}
                  <div>
                    <div className="s-sec-hd">
                      <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                        <span className="s-layer-tag tabular">L2</span>
                        <span className="s-sec-title">链路防线 · 业务域锁 Fixed 与防串线</span>
                      </div>
                      <span className="s-sec-note">同步业务域 → 锁盾/支付 → 实时查脱组 → 敏感期锁区</span>
                    </div>
                    <div className="guard-card">
                      {renderBuiltinRow(
                        "业务域名与桥接进程自动同步至 Claude-Fixed",
                        "自动把 Claude 全家桶域名、KYC 域与桥接进程更新至 Fixed，并屏蔽 14 条遥测域",
                        "系统内置规则引擎（不可关闭）：无损增量更新 Clash 覆写脚本 Script.js（保留你自定义的 AGY/Google 规则），自动将 claude.ai、api.anthropic.com、anthropic.org、clau.de、withpersona.com 及 Claude/chrome-native-host 进程锁死在手动策略组 Claude-Fixed，并在规则层 REJECT 拦截 14 条第三方纯遥测域名。"
                      )}
                      {renderSwitchRow({
                        configKey: "lockCfAndStripeToClaude",
                        title: "同步锁定人机盾与 Stripe 支付至 Claude-Fixed",
                        desc: "网页弹盾或升级付费时也走同一个 Claude 节点，切换自动热同步",
                        fullDesc:
                          "将 challenges.cloudflare.com、stripe.com、stripe.network 同步写入 Claude-Fixed 规则并即时热生效，防止弹盾或绑卡付费发生双 IP 串线；若同时使用 ChatGPT 等其他 CF 站点，建议将主代理组与 Claude-Fixed 选同一节点，或按需关闭此项。",
                        badge: { text: "推荐开启", tone: "ok" },
                        checked: config.lockCfAndStripeToClaude ?? true,
                      })}
                      {renderBuiltinRow(
                        "实时连接脱组监测与落地 IP 漂移审计",
                        "持续盯防 Claude 实时连接流，抓出脱组直连、禁区落地与未收录新域",
                        "系统内置实时雷达（不可关闭）：毫秒级扫描 Mihomo 活跃连接，识别走 DIRECT 或脱出 Claude-Fixed 的异常连接并标红告警，同步比对历史落地 IP 检测静默换区，并自动标出 Claude.exe 发起的未收录新域。"
                      )}
                      {renderSwitchRow({
                        configKey: "calm24h",
                        title: "新号 / 刚付费 24h 冷静保护",
                        desc: "新号或刚付费前 24 小时禁切节点、加强 401/403 监控",
                        fullDesc:
                          "用于新注册账号或刚升级付费后的前 24 小时审核敏感期：开启后切换节点将弹出高危拦截确认，并提高 401/403 与高并发监控级别，助你平稳度过异步风控审核。",
                        badge: { text: "按需开启", tone: "neutral" },
                        checked: config.calm24h,
                      })}
                    </div>
                  </div>

                  {/* L3：断流防线 */}
                  <div>
                    <div className="s-sec-hd">
                      <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                        <span className="s-layer-tag tabular">L3</span>
                        <span className="s-sec-title">断流防线 · 实时监测与 2 秒热熔断</span>
                      </div>
                      <span className="s-sec-note">先监测发现 → 再 2 秒自动掐流封出站</span>
                    </div>
                    <div className="guard-card">
                      {renderBuiltinRow(
                        "事件驱动 + 15 分钟全量巡检双引擎",
                        "断连/关 TUN/切网毫秒级响应，后台每 15 分钟自动复测外网与官方状态",
                        "系统内置双引擎调度（不可关闭）：代理断连、网卡切换、休眠唤醒与高危日志报错均毫秒级即时响应；后台每 15 分钟静默复测一次外网出口、DNS 与 Anthropic 官方服务状态页，第一时间区分官方宕机与本地风控。"
                      )}
                      {renderSwitchRow({
                        configKey: "autoKillSwitch",
                        title: "异常自动紧急断流（4 层热熔断）",
                        desc: "代理断开、关 TUN、脱组或切禁区时，2 秒内切断全部 Claude 出站",
                        fullDesc:
                          "Claude 运行中一旦检测到代理意外离线、TUN 关闭、节点切入禁区或流量脱组，2 秒内自动触发 4 层热熔断：立刻通过 Clash 掐断现有连接，同时写入 Windows Defender 规则 FDClaudeGuard_KillSwitch_* 封死出站，100% 止损。",
                        badge: { text: "推荐开启", tone: "ok" },
                        checked: config.autoKillSwitch,
                      })}
                    </div>
                  </div>

                  {/* L4：收口防线 */}
                  <div>
                    <div className="s-sec-hd">
                      <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                        <span className="s-layer-tag tabular">L4</span>
                        <span className="s-sec-title">收口防线 · 防回传、进程防复活与自愈留痕</span>
                      </div>
                      <span className="s-sec-note">清队列 → 防复活 → 事务押运 → 退出防呆 → 归因审计</span>
                    </div>
                    <div className="guard-card">
                      {renderSwitchRow({
                        configKey: "antiUploadFlush",
                        title: "熔断恢复前强杀并清遥测缓存",
                        desc: "恢复联网前先杀进程清空待发缓存，防止风险记录补发",
                        fullDesc:
                          "仅在触发熔断后生效：恢复网络前先直接强杀 Claude 进程（跳过客户端正常退出时的清理上报钩子），并清空 ~/.claude/telemetry/ 离线缓存，避免断网期间积攒的报错记录在重连瞬间集中补发给 Anthropic。",
                        badge: { text: "仅熔断生效", tone: "neutral" },
                        checked: config.antiUploadFlush,
                      })}

                      <div className="s-row">
                        <div className="s-row-info">
                          <div className="s-row-top">
                            <span className="s-row-title">强杀防复活盯防时长（Kill-Hold）</span>
                            {renderInfoBtn(
                              "强杀防复活盯防时长（Kill-Hold）",
                              "每次手动或自动强杀 Claude 后，后台以 250ms 频率盯防全部关联进程树（含 MSIX 与 Chrome 桥接宿主），冒头即强杀并自动顺延 +15 秒；点击「安全启动 Claude」前会自动优雅释放。"
                            )}
                          </div>
                          <div className="s-row-desc">强杀 Claude 后持续盯防，防止后台悄悄自启复活</div>
                        </div>
                        <div className="in-seg" style={{ height: 27 }} data-testid="settings-kill-hold-selector">
                          {([30, 45, 60] as const).map((secs) => (
                            <button
                              key={secs}
                              type="button"
                              className={`in-seg-btn tabular ${(config.killHoldSeconds ?? 45) === secs ? "active" : ""}`}
                              style={{ fontSize: 11.5, padding: "0 9px" }}
                              onClick={() =>
                                void updateConfig({ killHoldSeconds: secs }, `防复活盯防时长 (${secs}s)`)
                              }
                            >
                              {secs}s
                            </button>
                          ))}
                        </div>
                      </div>

                      {renderBuiltinRow(
                        "事务级押运锁与卸载 / 退出自愈",
                        "清理备份与切节点全程防复活，正常退出与卸载自动清防火墙规则",
                        "系统内置安全阀（不可关闭）：执行备份清理、快照还原或切节点期间自动锁死 Claude 进程防止文件占用或偷跑；正常退出确认或通过 Windows 卸载本软件时，自动清空所有 FDClaudeGuard_KillSwitch_* 防火墙规则与计划任务，绝不自锁电脑。"
                      )}

                      {renderSwitchRow({
                        configKey: "safeExitPrompt",
                        title: "安全退出防呆提醒",
                        desc: "关闭工具或代理前，如果 Claude 仍在后台会弹窗提醒",
                        fullDesc:
                          "准备关闭本启动器或停用代理前，若检测到 Claude 仍有后台残留进程，立即弹出防呆确认窗，支持一键先强杀再安全退出，避免工具退了但 Claude 还在后台裸连。",
                        badge: { text: "推荐开启", tone: "ok" },
                        checked: config.safeExitPrompt,
                      })}

                      {renderBuiltinRow(
                        "72h 风控日志归因审计",
                        "实时识别 401/403/429 与跨号污染并过滤无关噪音",
                        "系统内置本地审计（不可关闭）：只读监听 Claude 本地日志，精准识别 401/403/429 限流、封号污染残留与跨 orgId 混号竞态，自动过滤合盖休眠与第三方 503 等无关噪音。"
                      )}
                    </div>
                  </div>
                </>
              )}

              {/* ==================== 3. 清理恢复 ==================== */}
              {tab === "recovery" && (
                <>
                  {/* 区块 1：网络急救 */}
                  <div id="s-blk-rescue">
                    <div className="s-sec-hd">
                      <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                        <span className="s-sec-title">网络急救</span>
                        {hasLoopbackDns ? (
                          <span className="guard-chip guard-chip-fail">
                            检测到死 DNS：{overview?.loopbackDnsAdapters.join("、")}
                          </span>
                        ) : hasResidualFw ? (
                          <span className="guard-chip guard-chip-fail">检测到残留防火墙规则</span>
                        ) : (
                          <span className="guard-chip guard-chip-pass">网络正常</span>
                        )}
                      </div>
                      <span className="s-sec-note">含防火墙防自锁清理，无异常项自动跳过</span>
                    </div>

                    <div
                      className="guard-card"
                      style={{
                        padding: "13px 15px",
                        display: "flex",
                        flexDirection: "column",
                        gap: 10,
                        borderColor: hasAlert ? "var(--bad-border)" : undefined,
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0, flex: 1 }}>
                          <div
                            className={`guard-icon-box ${hasAlert ? "is-fail" : ""}`}
                            style={
                              !hasAlert
                                ? {
                                    background: "var(--primary-soft)",
                                    color: "var(--primary)",
                                    borderColor: "var(--primary-border)",
                                  }
                                : undefined
                            }
                          >
                            <LifeBuoy size={14} strokeWidth={1.55} />
                          </div>
                          <div className="s-row-info">
                            <div className="s-row-top">
                              <span style={{ fontSize: 13, fontWeight: 500, color: "var(--text-strong)" }}>
                                一键恢复上网与防自锁救援
                              </span>
                              {renderInfoBtn(
                                "一键网络急救（4 步）",
                                "依次执行 4 步并自动跳过正常项：① 重置物理网卡残留的 127.0.0.1 死 DNS 为 DHCP；② 关闭指向死端口的失效系统代理；③ 清空本工具写入的全部防火墙阻断规则；④ 刷新 DNS 缓存并现场实测国内直连。"
                              )}
                            </div>
                            <div className="s-row-desc">
                              关代理/关 TUN 断网、导不了订阅或防火墙残留锁死时一键修复
                            </div>
                          </div>
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: 7, flexShrink: 0 }}>
                          <button
                            type="button"
                            disabled={busy}
                            className="guard-btn guard-btn-flat"
                            onClick={() => void handleCleanupAllFirewall()}
                          >
                            {busyKey === "fw_rescue" && <Loader2 size={12.5} className="guard-spin" />}
                            <span>仅清防火墙</span>
                          </button>
                          <button
                            type="button"
                            data-testid="btn-settings-network-rescue"
                            disabled={busy}
                            className="guard-btn guard-btn-primary"
                            onClick={() => void handleRunRescue()}
                          >
                            {busyKey === "rescue" && <Loader2 size={12.5} className="guard-spin" />}
                            <span>一键网络急救</span>
                          </button>
                        </div>
                      </div>

                      {rescueReport && (
                        <div
                          style={{
                            padding: "9px 12px",
                            borderRadius: 8,
                            background: "var(--bg-card-band)",
                            border: "1px solid var(--divider)",
                            fontSize: 11,
                            color: "var(--text-2)",
                            lineHeight: 1.55,
                          }}
                        >
                          <div
                            style={{
                              color: rescueReport.ok ? "var(--ok-fg)" : "var(--warning-fg)",
                              fontWeight: 500,
                              marginBottom: 3,
                            }}
                          >
                            {rescueReport.ok ? "✓ " : "! "}
                            {rescueReport.summary}
                          </div>
                          <div>
                            {rescueReport.steps.map((s) => `${s.step}：${s.detail}`).join(" · ")}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* 区块 2：配置撤回 */}
                  <div id="s-blk-rollback">
                    <div className="s-sec-hd">
                      <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                        <span className="s-sec-title">配置撤回</span>
                        <span className="guard-chip guard-chip-neutral tabular">
                          {overviewError ? "读取失败" : `已改动 ${touchedCount} 项`}
                        </span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <button
                          type="button"
                          disabled={busy || overviewLoading}
                          className="guard-btn guard-btn-flat guard-btn-xs"
                          onClick={() => void loadRecoveryData()}
                        >
                          刷新
                        </button>
                        <button
                          type="button"
                          disabled={busy || touchedCount === 0}
                          className="guard-btn guard-btn-flat guard-btn-xs tabular"
                          onClick={handleRollbackAll}
                        >
                          撤回全部 ({touchedCount})
                        </button>
                      </div>
                    </div>

                    <div className="guard-card">
                      {overviewLoading && !overview ? (
                        <div style={{ padding: "14px", fontSize: 12, color: "var(--text-3)" }}>
                          正在读取系统与 Clash 首次基线快照...
                        </div>
                      ) : overviewError && !overview ? (
                        <div style={{ padding: "12px 14px", fontSize: 12, color: "var(--bad-fg)" }}>
                          读取撤回基线失败：{overviewError}
                        </div>
                      ) : (overview?.items ?? []).length === 0 ? (
                        <div style={{ padding: "14px", fontSize: 12, color: "var(--text-3)" }}>
                          当前暂无系统或 Clash 改动记录。
                        </div>
                      ) : (
                        (overview?.items ?? []).map((item) => {
                          const itemBusy = busyKey === `one:${item.id}`;
                          return (
                            <div key={item.id} className="s-row">
                              <div className="s-row-info">
                                <div className="s-row-top">
                                  <span className="guard-chip guard-chip-neutral">{item.category}</span>
                                  <span className="s-row-title">{item.title}</span>
                                  {renderInfoBtn(
                                    item.title,
                                    `当前：${item.currentSummary}；原态：${item.originalSummary}。${item.riskNote}`
                                  )}
                                </div>
                                <div className="s-row-desc">
                                  当前：{item.currentSummary} | 原态：{item.originalSummary}
                                </div>
                              </div>
                              <div className="s-row-ctrl">
                                <span
                                  className={`guard-chip ${
                                    item.touchedByGuard ? "guard-chip-warn" : "guard-chip-pass"
                                  }`}
                                  style={{ minWidth: 52 }}
                                >
                                  {item.touchedByGuard ? "可撤回" : "未改动"}
                                </span>
                                <button
                                  type="button"
                                  disabled={busy || !item.touchedByGuard}
                                  className="guard-btn guard-btn-flat guard-btn-xs"
                                  style={{ minWidth: 48 }}
                                  title={item.touchedByGuard ? "按首次基线精准撤回此项" : "与原始基线一致，无需撤回"}
                                  onClick={() => handleRollbackOne(item.id, item.title, item.riskNote)}
                                >
                                  {itemBusy ? <Loader2 size={11} className="guard-spin" /> : "撤回"}
                                </button>
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>

                  {/* 区块 3：本地清理 */}
                  <div id="s-blk-clean">
                    <div className="s-sec-hd">
                      <span className="s-sec-title">本地清理</span>
                      <span className="s-sec-note">均不触碰项目代码与云端对话记录</span>
                    </div>
                    <div className="guard-card">
                      <div className="s-row">
                        <div className="s-row-info">
                          <div className="s-row-top">
                            <span className="s-row-title">强杀并清待上传遥测缓存</span>
                            {renderInfoBtn(
                              "强杀并清待上传遥测缓存",
                              "仅在代理突然断线或节点漂移等紧急时刻使用：立即强杀 Claude 进程丢弃内存中待发事件，并清空 ~/.claude/telemetry/ 离线缓存；会中断正在生成的当前对话，不影响登录态、项目代码与云端记录。"
                            )}
                          </div>
                          <div className="s-row-desc">仅终止进程并清本机待上传遥测，保留登录态</div>
                        </div>
                        <div className="s-row-ctrl">
                          <span className="guard-chip guard-chip-warn">仅应急</span>
                          <button
                            type="button"
                            disabled={busy}
                            className="guard-btn guard-btn-flat guard-btn-xs"
                            onClick={() => void handleKillAndClean()}
                          >
                            {busyKey === "kill" && <Loader2 size={11} className="guard-spin" />}
                            <span>应急清理</span>
                          </button>
                        </div>
                      </div>

                      <div className="s-row">
                        <div className="s-row-info">
                          <div className="s-row-top">
                            <span className="s-row-title">退出登录并清理本地污染目录</span>
                            {renderInfoBtn(
                              "退出登录并清理本地污染目录",
                              `不碰项目代码与云端对话：先彻底结束 Claude 进程并自动打包备份至 ~/FDtools-Backups/，再清空经典安装目录（${
                                rootsSummary.classicDetected ? "已识别" : "未检测到"
                              }）、微软商店 MSIX（${
                                rootsSummary.msixPackages.length > 0
                                  ? `已识别 ${rootsSummary.msixPackages.length} 个实例`
                                  : "未安装，后续自动纳入"
                              }）的本地登录态 Cookie 与遥测目录。`
                            )}
                          </div>
                          <div className="s-row-desc">先自动打包备份，再清空本机登录态与污染目录</div>
                        </div>
                        <div className="s-row-ctrl">
                          <button
                            type="button"
                            disabled={busy}
                            className="guard-btn guard-btn-flat guard-btn-xs"
                            onClick={() => void handleManualBackup()}
                          >
                            {busyKey === "manual_backup" && <Loader2 size={11} className="guard-spin" />}
                            <span>仅备份快照</span>
                          </button>
                          <button
                            type="button"
                            disabled={busy}
                            className="guard-btn guard-btn-flat guard-btn-xs"
                            style={{
                              color: "var(--primary)",
                              borderColor: "var(--primary-border)",
                              background: "var(--primary-soft)",
                              boxShadow: "none",
                            }}
                            onClick={() =>
                              openCleanModal({
                                sourceLabel: "来自系统设置 · 清理恢复",
                                onCompleted: async () => {
                                  await loadRecoveryData();
                                },
                              })
                            }
                          >
                            退出并清理
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* 区块 4：历史备份快照（5 列等距紧凑表） */}
                  <div id="s-blk-backup">
                    <div className="s-sec-hd">
                      <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                        <span className="s-sec-title">历史备份快照</span>
                        <span className="s-sec-note">按时间倒序 · 自动保留最近 10 份</span>
                      </div>
                      {backups.length > 0 && (
                        <button
                          type="button"
                          disabled={busy}
                          className="guard-btn guard-btn-danger-soft guard-btn-xs tabular"
                          onClick={handleClearAllBackups}
                        >
                          清空全部 ({backups.length})
                        </button>
                      )}
                    </div>
                    <div className="guard-card">
                      {backups.length === 0 ? (
                        <div style={{ padding: "14px", fontSize: 12, color: "var(--text-3)" }}>
                          暂无历史备份快照（执行清理或手动备份后将在此生成原子 ZIP 快照并支持一键还原）。
                        </div>
                      ) : (
                        <>
                          <div className="s-bak-head">
                            <span>备份文件</span>
                            <span>类型</span>
                            <span>创建时间</span>
                            <span>体积</span>
                            <span style={{ textAlign: "right" }}>操作</span>
                          </div>
                          {backups.map((b) => {
                            const restoring = busyKey === `restore:${b.fileName}`;
                            const deleting = busyKey === `delete:${b.fileName}`;
                            return (
                              <div key={b.fileName} className="s-bak-row">
                                <span
                                  className="font-mono-code"
                                  title={b.fileName}
                                  style={{
                                    fontSize: 11,
                                    color: "var(--text-1)",
                                    whiteSpace: "nowrap",
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                  }}
                                >
                                  {b.fileName}
                                </span>
                                <span>
                                  <span className="guard-chip guard-chip-neutral">{kindLabel(b.kind)}</span>
                                </span>
                                <span className="tabular" style={{ fontSize: 11, color: "var(--text-2)" }}>
                                  {b.createdAt}
                                </span>
                                <span className="tabular" style={{ fontSize: 11, color: "var(--text-2)" }}>
                                  {b.sizeLabel}
                                </span>
                                <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 6 }}>
                                  <button
                                    type="button"
                                    disabled={busy}
                                    className="guard-btn guard-btn-flat guard-btn-xs"
                                    onClick={() => void handleRestore(b.fileName)}
                                  >
                                    {restoring ? <Loader2 size={11} className="guard-spin" /> : "一键还原"}
                                  </button>
                                  <button
                                    type="button"
                                    disabled={busy}
                                    aria-label={`删除备份 ${b.fileName}`}
                                    className="guard-btn guard-btn-danger-soft guard-btn-xs"
                                    onClick={() => void handleDeleteOne(b.fileName)}
                                  >
                                    {deleting ? <Loader2 size={11} className="guard-spin" /> : "删除"}
                                  </button>
                                </div>
                              </div>
                            );
                          })}
                        </>
                      )}
                    </div>
                  </div>
                </>
              )}

              {/* ==================== 4. 版本更新（顺序：联系作者 → Clash Verge 代理核心 → 客户端版本更新） ==================== */}
              {tab === "update" && (
                <>
                  {/* 1. 最上面：联系作者与社区交流（与下方两张卡片严格统一为标准 31px 按钮高度） */}
                  <div>
                    <div className="s-sec-hd">
                      <span className="s-sec-title">联系作者与社区交流</span>
                      <span className="s-sec-note">欢迎反馈问题、建议与关注版本更新</span>
                    </div>
                    <div className="guard-card">
                      <div className="s-row">
                        <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0, flex: 1 }}>
                          <div className="guard-icon-box" style={{ color: "var(--text-strong)" }}>
                            <XBrandIcon size={13.5} />
                          </div>
                          <div className="s-row-info">
                            <div className="s-row-top">
                              <span className="s-row-title">作者 X（Twitter）</span>
                              <span className="guard-chip guard-chip-neutral">
                                {OFFICIAL_AUTHOR_X_HANDLE}
                              </span>
                            </div>
                            <div className="s-row-desc">问题交流、防封经验同步与新版本发布通知</div>
                          </div>
                        </div>
                        <div className="s-row-ctrl">
                          <button
                            type="button"
                            data-testid="btn-settings-copy-x"
                            className="guard-btn guard-btn-flat"
                            onClick={async () => {
                              const fallbackCopy = (): boolean => {
                                try {
                                  const ta = document.createElement("textarea");
                                  ta.value = OFFICIAL_AUTHOR_X_HANDLE;
                                  ta.setAttribute("readonly", "");
                                  ta.style.position = "fixed";
                                  ta.style.opacity = "0";
                                  document.body.appendChild(ta);
                                  ta.select();
                                  const ok = document.execCommand("copy");
                                  document.body.removeChild(ta);
                                  return ok;
                                } catch {
                                  return false;
                                }
                              };
                              let ok = false;
                              if (navigator.clipboard?.writeText) {
                                ok = await navigator.clipboard
                                  .writeText(OFFICIAL_AUTHOR_X_HANDLE)
                                  .then(() => true)
                                  .catch(() => false);
                              }
                              if (!ok) ok = fallbackCopy();
                              if (ok) {
                                setCopiedX(true);
                                pushToast("已复制作者 X 账号", OFFICIAL_AUTHOR_X_HANDLE, "ok");
                                window.setTimeout(() => setCopiedX(false), 2000);
                              } else {
                                pushToast("请手动复制账号", OFFICIAL_AUTHOR_X_HANDLE, "info");
                              }
                            }}
                          >
                            {copiedX ? <Check size={12.5} strokeWidth={1.8} /> : <Copy size={12.5} strokeWidth={1.5} />}
                            <span>{copiedX ? "已复制" : "复制账号"}</span>
                          </button>
                          <button
                            type="button"
                            data-testid="btn-settings-open-x"
                            className="guard-btn guard-btn-flat"
                            style={{
                              color: "var(--primary)",
                              borderColor: "var(--primary-border)",
                              background: "var(--primary-soft)",
                              boxShadow: "none",
                            }}
                            onClick={() => void handleOpenExternal(OFFICIAL_AUTHOR_X_URL)}
                          >
                            <span>前往 X 主页 ↗</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* 2. 中间：Clash Verge Rev 代理核心（自动识别已安装/未安装：仅未安装显示「下载安装」，已安装未运行显示「启动 Clash」） */}
                  <div>
                    <div className="s-sec-hd">
                      <span className="s-sec-title">代理核心依赖 · Clash Verge Rev</span>
                      <span className="s-sec-note">启动器依赖 Clash Verge Rev 提供 TUN 与规则分流</span>
                    </div>
                    <div className="guard-card" data-testid="settings-clash-verge-card">
                      <div className="s-row">
                        <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0, flex: 1 }}>
                          <div
                            className="guard-icon-box"
                            style={{
                              background: snapshot.clashOnline ? "var(--ok-bg)" : "var(--bg-subtle)",
                              color: snapshot.clashOnline ? "var(--ok-fg)" : "var(--text-2)",
                              borderColor: snapshot.clashOnline ? "var(--ok-border)" : "var(--icon-border)",
                            }}
                          >
                            <Globe size={14} strokeWidth={1.55} />
                          </div>
                          <div className="s-row-info">
                            <div className="s-row-top">
                              <span className="s-row-title">Clash Verge Rev</span>
                              <span
                                className={`guard-chip ${
                                  snapshot.clashOnline ? "guard-chip-pass" : "guard-chip-neutral"
                                }`}
                              >
                                {snapshot.clashOnline
                                  ? `已运行 · ${snapshot.clashVersion}`
                                  : snapshot.clashInstalled
                                  ? "已安装 · 未运行"
                                  : "未安装"}
                              </span>
                            </div>
                            <div className="s-row-desc">
                              {snapshot.clashOnline
                                ? "代理核心已在线运行，如需更新内核可前往官方 GitHub 仓库查看"
                                : snapshot.clashInstalled
                                ? "已检测到本机安装 Clash Verge Rev，点击右侧可直接拉起启动"
                                : "尚未检测到本机安装 Clash Verge Rev，请先前往官方发布页下载安装"}
                            </div>
                          </div>
                        </div>
                        <div className="s-row-ctrl">
                          {!snapshot.clashOnline && !snapshot.clashInstalled && (
                            <button
                              type="button"
                              data-testid="btn-settings-install-clash"
                              className="guard-btn guard-btn-primary"
                              onClick={() => void handleOpenExternal(OFFICIAL_CLASH_VERGE_RELEASES_URL)}
                            >
                              <Download size={12.5} strokeWidth={1.65} />
                              <span>下载安装</span>
                            </button>
                          )}
                          {!snapshot.clashOnline && snapshot.clashInstalled && (
                            <button
                              type="button"
                              data-testid="btn-settings-launch-clash"
                              disabled={busy}
                              className="guard-btn guard-btn-primary"
                              onClick={async () => {
                                setBusyKey("launch_clash");
                                try {
                                  const res = await ipc.fixPreflightItem("node_proxy");
                                  pushToast(
                                    res.success ? "已启动 Clash Verge Rev" : "启动提示",
                                    res.message,
                                    res.success ? "ok" : "info"
                                  );
                                  void refreshPreflight(true);
                                } catch (err) {
                                  pushToast("启动 Clash Verge 失败", String(err), "danger");
                                } finally {
                                  setBusyKey(null);
                                }
                              }}
                            >
                              {busyKey === "launch_clash" ? (
                                <Loader2 size={12.5} className="guard-spin" />
                              ) : (
                                <Play size={11.5} strokeWidth={1.8} fill="currentColor" />
                              )}
                              <span>启动 Clash</span>
                            </button>
                          )}
                          <button
                            type="button"
                            data-testid="btn-settings-clash-github"
                            className="guard-btn guard-btn-flat"
                            onClick={() => void handleOpenExternal(OFFICIAL_CLASH_VERGE_REPO_URL)}
                          >
                            <ExternalLink size={12.5} strokeWidth={1.5} />
                            <span>GitHub 官网</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* 3. 最下面：客户端版本与签名更新 */}
                  <div>
                    <div className="s-sec-hd">
                      <span className="s-sec-title">客户端版本与签名更新</span>
                      <span className="s-sec-note">Ed25519 官方公钥验签</span>
                    </div>
                    <div
                      className="guard-card"
                      data-testid="settings-updater-card"
                      style={{ padding: "13px 15px", display: "flex", flexDirection: "column", gap: 10 }}
                    >
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 14 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0, flex: 1 }}>
                          <div
                            className="guard-icon-box"
                            style={{
                              background: "var(--primary-soft)",
                              color: "var(--primary)",
                              borderColor: "var(--primary-border)",
                            }}
                          >
                            <Download size={14} strokeWidth={1.55} />
                          </div>
                          <div className="s-row-info">
                            <div className="s-row-top">
                              <span style={{ fontSize: 13, fontWeight: 500, color: "var(--text-strong)" }}>
                                FD Claude 安全启动器
                              </span>
                              <span className="guard-chip guard-chip-neutral tabular">
                                v{updateInfo?.currentVersion ?? appVersionLabel.replace(/^v/, "")}
                              </span>
                              {updateInfo?.available && updateInfo.latestVersion ? (
                                <span className="guard-chip guard-chip-pass tabular">
                                  发现新版本 v{updateInfo.latestVersion}
                                </span>
                              ) : updateError ? (
                                <span className="guard-chip guard-chip-warn">检查失败</span>
                              ) : (
                                <span className="guard-chip guard-chip-pass">
                                  <CheckCircle2 size={11} strokeWidth={1.8} />
                                  <span>已是最新</span>
                                </span>
                              )}
                              {renderInfoBtn(
                                "官方签名更新通道",
                                "所有客户端更新包均通过 GitHub Releases 官方渠道分发，并在安装前经过 Ed25519 公钥签名强校验，下载过程优先走本机代理，确保安全与高速。"
                              )}
                            </div>
                            <div className="s-row-desc">
                              {updateError ? (
                                <>
                                  <span>{updateError} </span>
                                  <button
                                    type="button"
                                    className="guard-text-link"
                                    style={{ padding: 0, fontSize: 11 }}
                                    onClick={() => void handleOpenExternal(OFFICIAL_GITHUB_RELEASES_URL)}
                                  >
                                    手动前往 Releases ↗
                                  </button>
                                </>
                              ) : (
                                "走 GitHub 官方签名通道下载，优先复用本机代理"
                              )}
                            </div>
                          </div>
                        </div>

                        <div style={{ display: "flex", alignItems: "center", gap: 7, flexShrink: 0 }}>
                          {updateInfo?.available ? (
                            <button
                              type="button"
                              disabled={updateInstalling}
                              className="guard-btn guard-btn-primary"
                              onClick={() => void installAppUpdate()}
                            >
                              {updateInstalling ? (
                                <Loader2 size={12.5} className="guard-spin" />
                              ) : (
                                <Download size={12.5} strokeWidth={1.6} />
                              )}
                              <span className="tabular">{installBtnText}</span>
                            </button>
                          ) : (
                            <button
                              type="button"
                              data-testid="btn-settings-check-update"
                              disabled={updateChecking || updateInstalling}
                              className="guard-btn guard-btn-flat"
                              onClick={() => void checkForAppUpdate(false)}
                            >
                              {updateChecking ? (
                                <Loader2 size={12.5} className="guard-spin" />
                              ) : (
                                <RefreshCw size={12.5} strokeWidth={1.5} />
                              )}
                              <span>{updateChecking ? "检查中..." : "检查更新"}</span>
                            </button>
                          )}
                          <button
                            type="button"
                            className="guard-btn guard-btn-flat"
                            onClick={() => void handleOpenExternal(OFFICIAL_GITHUB_REPO_URL)}
                          >
                            <ExternalLink size={12.5} strokeWidth={1.5} />
                            <span>GitHub 官网</span>
                          </button>
                        </div>
                      </div>

                      {updateInfo?.available && updateInfo.notes && (
                        <pre
                          className="font-mono-code"
                          style={{
                            margin: 0,
                            padding: "8px 11px",
                            borderRadius: 8,
                            background: "var(--bg-card-band)",
                            border: "1px solid var(--divider)",
                            fontSize: 11,
                            color: "var(--text-2)",
                            whiteSpace: "pre-wrap",
                            lineHeight: 1.55,
                          }}
                        >
                          {updateInfo.notes}
                        </pre>
                      )}

                      <div
                        style={{
                          padding: "9px 12px",
                          borderRadius: 8,
                          background: "var(--bg-card-band)",
                          border: "1px solid var(--divider)",
                          fontSize: 11,
                          color: "var(--text-2)",
                          lineHeight: 1.55,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between",
                          gap: 12,
                        }}
                      >
                        <span>
                          开源透明，所有诊断日志导出均先做本地脱敏，严禁采集对话、代码与账号密钥。
                        </span>
                        <span className="guard-chip guard-chip-neutral">MIT 开源</span>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          </ThinScrollArea>
        </section>
      </div>

      {/* 全站统一 0ms 悬停/点击 ⓘ 解释气泡 */}
      {popover && (
        <div
          role="tooltip"
          className="settings-popover"
          style={{ left: popover.left, top: popover.top }}
        >
          <div className="settings-popover-hd">{popover.title}</div>
          <div className="settings-popover-body">{popover.body}</div>
        </div>
      )}
    </div>
  );
}
