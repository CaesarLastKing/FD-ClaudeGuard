import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  BookOpen,
  Clock,
  EyeOff,
  Globe,
  Link2,
  Loader2,
  RefreshCw,
  Shield,
  Users,
} from "lucide-react";
import { ipc } from "@/lib/ipc";
import { LogAnalysisPage } from "@/pages/LogAnalysisPage";
import { useGuardStore } from "@/stores/guardStore";
import type { AccountAuditReport } from "@/types/guard";

function extractSkFromInput(raw: string): string | null {
  if (!raw) return null;
  const m = raw.match(/sk-ant-sid[0-9a-zA-Z_-]{16,}/);
  return m ? m[0] : null;
}

interface MetricAction {
  label: string;
  primary?: boolean;
  disabled?: boolean;
  busy?: boolean;
  onClick?: () => void;
}

interface MetricCell {
  k: string;
  v: string;
  cls: "ok" | "warn" | "danger";
  boxState?: "" | "is-warn" | "is-danger";
  btn?: MetricAction;
}

interface ReadonlyCell {
  k: string;
  v: string;
  cls?: "" | "warn";
  boxState?: "" | "is-warn";
}

interface AuditGroupView {
  part: "user" | "tool";
  id: string;
  icon: React.ReactNode;
  prefix: string;
  prefixCls: "redline" | "warn-exp" | "privacy-low";
  title: string;
  status: "ok" | "pending" | "warn" | "danger";
  statusText: string;
  summary: string;
  isSkPanel?: boolean;
  readonlyMetrics?: ReadonlyCell[];
  cols?: 1 | 2 | 3;
  metrics?: MetricCell[];
  advice?: string;
  allowReverify?: boolean;
}

function formatBytesReadable(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function scoreColorCss(colorToken: string): { pillCls: string; barColor: string } {
  switch (colorToken) {
    case "red":
      return { pillCls: "s-crit", barColor: "var(--danger)" };
    case "orange":
      return { pillCls: "s-mid", barColor: "#fb923c" };
    case "amber":
      return { pillCls: "s-watch", barColor: "var(--warning)" };
    default:
      return { pillCls: "s-safe", barColor: "var(--success)" };
  }
}

export function AccountAuditPage() {
  const report = useGuardStore((s) => s.accountAudit);
  const loading = useGuardStore((s) => s.accountAuditLoading);
  const auditError = useGuardStore((s) => s.accountAuditError);
  const subTab = useGuardStore((s) => s.auditSubTab);
  const setSubTab = useGuardStore((s) => s.setAuditSubTab);
  const refreshAccountAudit = useGuardStore((s) => s.refreshAccountAudit);
  const setAccountAudit = useGuardStore((s) => s.setAccountAudit);
  const refreshPreflight = useGuardStore((s) => s.refreshPreflight);
  const setActiveTab = useGuardStore((s) => s.setActiveTab);
  const setNodesSubTab = useGuardStore((s) => s.setNodesSubTab);
  const setSnapshot = useGuardStore((s) => s.setSnapshot);
  const openCleanModal = useGuardStore((s) => s.openCleanModal);
  const openRiskModal = useGuardStore((s) => s.openRiskModal);
  const pushToast = useGuardStore((s) => s.pushToast);
  const snapshot = useGuardStore((s) => s.snapshot);
  const config = useGuardStore((s) => s.config);

  const [openGroupId, setOpenGroupId] = useState<string | null>(null);
  const [subShowExpire, setSubShowExpire] = useState(false);
  const [showKycExplain, setShowKycExplain] = useState(false);
  const [guideOpen, setGuideOpen] = useState(false);
  const [weightTableOpen, setWeightTableOpen] = useState(false);
  const [forceSkInputMode, setForceSkInputMode] = useState(false);
  const [skInput, setSkInput] = useState("");
  const [showHowSk, setShowHowSk] = useState(false);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [logFilter, setLogFilter] = useState<"all" | "403" | "net">("all");
  const [showDenoised, setShowDenoised] = useState(false);
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
  const [showFullLogConsole, setShowFullLogConsole] = useState(false);

  const skInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!report && !loading && !auditError) {
      void refreshAccountAudit(true);
    }
  }, [report, loading, auditError, refreshAccountAudit]);

  useEffect(() => {
    if (!guideOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setGuideOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [guideOpen]);

  const extractedSk = useMemo(() => extractSkFromInput(skInput), [skInput]);

  const focusCloudVerifyInput = () => {
    setGuideOpen(false);
    setSubTab("audit");
    setForceSkInputMode(true);
    setOpenGroupId("g-cloud");
    window.setTimeout(() => skInputRef.current?.focus(), 40);
  };

  const handleVerifyCloud = async (allowSwitchPrimary = false) => {
    if (!extractedSk || busyKey) return;
    setBusyKey("verify_sk");
    try {
      const updated = await ipc.verifyAccountCloudWithSk(skInput, undefined, allowSwitchPrimary);
      setSkInput("");
      setForceSkInputMode(false);
      setAccountAudit(updated);
      setOpenGroupId("g-cloud");
      pushToast(
        `云端核验完成（第 ${Math.max(1, updated.verifyCount)} 次，明文已清零）`,
        "已同步顶部账号状态、官方属地与实时额度窗口。",
        "ok"
      );
      void refreshPreflight(true);
    } catch (err) {
      const msg = String(err);
      if (!allowSwitchPrimary && msg.includes("[ORG_MISMATCH_CONFIRM]")) {
        const cleanMsg = msg.replace(/^.*\[ORG_MISMATCH_CONFIRM\]\s*/, "");
        openRiskModal({
          tone: "warn",
          badge: "跨端账号确认",
          title: "浏览器账号与本机 CLI 账号不同，确认以此号为主力核验？",
          subtitle:
            "大多数用户以桌面端/网页端为主力号；确认后将以当前浏览器账号写入主审计档案，不影响本机 CLI 文件",
          rows: [
            {
              label: "账号对比",
              value: cleanMsg,
              tone: "danger",
            },
            {
              label: "继续核验",
              value: "以当前浏览器/桌面端账号为主力档案完成云端核验，并在「多号混登」中如实保留 CLI 残留提示",
              tone: "ok",
            },
          ],
          primaryLabel: "以此浏览器/桌面端账号核验",
          onPrimary: async () => {
            await handleVerifyCloud(true);
          },
        });
      } else {
        pushToast("云端核验未通过", msg, "danger");
      }
    } finally {
      setBusyKey(null);
    }
  };

  const handleFixTelemetryEnv = async () => {
    if (busyKey) return;
    setBusyKey("fix_tel_env");
    try {
      const res = await ipc.fixClaudeTelemetryEnv();
      if (res.report) setAccountAudit(res.report);
      pushToast("已补齐 4/4 隐私降噪开关", res.message, "ok");
      void refreshPreflight(true);
    } catch (err) {
      pushToast("写入隐私降噪失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleCleanTelemetryDir = async () => {
    if (busyKey) return;
    setBusyKey("clean_tel_dir");
    try {
      const res = await ipc.cleanClaudeTelemetryDir();
      if (res.report) setAccountAudit(res.report);
      pushToast("已清空待传遥测目录", res.message, "ok");
      void refreshPreflight(true);
    } catch (err) {
      pushToast("清空遥测目录失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleRestoreOfficialEndpoint = async () => {
    if (busyKey) return;
    setBusyKey("restore_endpoint");
    try {
      const res = await ipc.restoreClaudeOfficialEndpoint();
      if (res.report) setAccountAudit(res.report);
      pushToast("已还原官方原生端点", res.message, "ok");
      void refreshPreflight(true);
    } catch (err) {
      pushToast("还原官方端点失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleCleanCliWithBackup = async () => {
    if (busyKey) return;
    setBusyKey("clean_cli");
    try {
      const res = await ipc.cleanClaudeCliCredentialsWithBackup();
      if (res.report) setAccountAudit(res.report);
      pushToast("已完成 CLI 原子备份并清理", res.message, "ok");
      void refreshPreflight(true);
    } catch (err) {
      pushToast("清理 CLI 凭据失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const handleEnableHold = async () => {
    if (busyKey) return;
    setBusyKey("enable_hold");
    try {
      const defaultSecs = config.killHoldSeconds ?? 45;
      const rep = await ipc.killClaudeProcesses(true);
      const latest = useGuardStore.getState().snapshot;
      setSnapshot({
        ...latest,
        bgClaudeProcs: rep.afterCount,
        killHoldActive: rep.killHoldActive ?? true,
        killHoldRemainingSecs: rep.killHoldRemainingSecs ?? defaultSecs,
      });
      pushToast(`已开启 ${defaultSecs}s 防复活盯防`, rep.message, "ok");
      void refreshAccountAudit(true);
    } catch (err) {
      pushToast("开启防复活盯防失败", String(err), "danger");
    } finally {
      setBusyKey(null);
    }
  };

  const unreadLogsCount = snapshot.unreadLogAnomalies ?? 0;

  // 组装上下两段共 7 项（严格对齐 v12 结构）
  const groups = useMemo<AuditGroupView[]>(() => {
    if (!report) return [];
    const { local, cloudSnapshot, cloudVerified, cloudStale, geoConsistency } = report;
    const isRealLocal = !cloudVerified;

    const regDays = report.accountAgeDays;
    const subDays = report.subscriptionAgeDays;
    const kycHours = cloudSnapshot?.personaKycAgeHours ?? null;
    const inNewWindow = regDays != null && regDays < 7;
    const inPayWindow = subDays != null && subDays <= 1;
    const inKycWindow = kycHours != null && kycHours <= 72;
    const planChanged = local.desktop.planChangedHits > 0;
    const windowAnyWarn = inNewWindow || inPayWindow || inKycWindow || planChanged;

    const gWindow: AuditGroupView = {
      part: "user",
      id: "g-window",
      icon: <Clock size={15} strokeWidth={1.8} />,
      prefix: "经验预警",
      prefixCls: "warn-exp",
      title: "新号、支付与 KYC 后高敏观察窗",
      status: windowAnyWarn ? "warn" : "ok",
      statusText: windowAnyWarn ? "高敏观察" : "已过观察",
      summary: isRealLocal
        ? `注册 ${regDays ?? "未知"} 天、订阅 ${subDays ?? "未知"} 天、${local.desktop.planChangedHits} 次套餐跳变；KYC 复核窗待云端核验。`
        : `注册 ${regDays ?? "未知"} 天、订阅 ${subDays ?? "未知"} 天、${
            cloudSnapshot?.personaKycStatus === "verified"
              ? inKycWindow
                ? `过 KYC 仅 ${kycHours} 小时（观察期内）`
                : "Persona KYC 已过 3 天经验复核期"
              : "未命中 KYC 复核观察"
          }、${local.desktop.planChangedHits} 次套餐跳变。`,
      cols: 2,
      metrics: [
        {
          k: "新号注册观察窗 (<7 天)",
          v:
            regDays == null
              ? "未读到注册时间"
              : inNewWindow
              ? `仅注册 ${regDays} 天 · 高敏观察期内`
              : `已注册 ${regDays} 天 · 已过观察`,
          cls: inNewWindow ? "warn" : "ok",
          boxState: inNewWindow ? "is-warn" : "",
        },
        {
          k: "支付 / 升级复审窗 (<=24h)",
          v:
            subDays == null
              ? "未读到订阅开通时间"
              : inPayWindow
              ? `刚订阅 ${subDays} 天 · 24h 复审窗内`
              : `已订阅 ${subDays} 天 · 已过复审`,
          cls: inPayWindow ? "warn" : "ok",
          boxState: inPayWindow ? "is-warn" : "",
        },
        {
          k: "过 KYC 后复核窗 (<=72h · 社区经验)",
          v: isRealLocal
            ? "待核 KYC 时间（仅前 3 天偏敏感）"
            : cloudSnapshot?.personaKycStatus === "verified"
            ? inKycWindow
              ? `通过不足 72h（${kycHours}h）· 建议稳健使用`
              : "已过 3 天 · 实名护城河缓冲"
            : "当前无实名复核观察记录",
          cls: inKycWindow ? "warn" : "ok",
          boxState: inKycWindow ? "is-warn" : "",
        },
        {
          k: "近期套餐变动 (plan_changed)",
          v: planChanged ? `检出 ${local.desktop.planChangedHits} 次套餐跳变` : "0 次异常跳变",
          cls: planChanged ? "warn" : "ok",
          boxState: planChanged ? "is-warn" : "",
        },
      ],
      advice:
        "属社区经验参考（非官方明文规则）：新号(<7天)、支付/升级(<=24h)及过 KYC 前 72h 容错率偏低，期间建议锁死单一稳定节点低频使用；升级 Max 或换卡时发卡国、账单区、出口 IP 与证件地尽量一致，有助于降低复审概率。",
    };

    const activeSchedCount =
      local.hygiene.activeScheduledTasksCount ?? local.hygiene.scheduledTasksCount;
    const histSchedCount = local.hygiene.historicalScheduledTasksCount ?? 0;
    const schedWarn = activeSchedCount >= 6;
    const rhythmBad = local.behavior.overnightBotRhythmSuspected;
    const rate429High = local.desktop.rateLimit429Hits >= 3 || local.desktop.highSideSessionHits > 0;
    const rate429Mild = !rate429High && local.desktop.rateLimit429Hits > 0;
    const autoDanger = rhythmBad || rate429High;
    const autoWarn = !autoDanger && (rate429Mild || schedWarn);

    const gAuto: AuditGroupView = {
      part: "user",
      id: "g-auto",
      icon: <Activity size={15} strokeWidth={1.8} />,
      prefix: "官方红线",
      prefixCls: "redline",
      title: "自动化机刷与人机节律监测",
      status: autoDanger ? "danger" : autoWarn ? "warn" : "ok",
      statusText: autoDanger
        ? "存在机刷"
        : schedWarn && !rate429Mild
        ? "定时任务偏多"
        : autoWarn
        ? "偶发限流"
        : "节律正常",
      summary: autoDanger
        ? `检测到跨夜活跃 ${local.behavior.activeHours24h} 小时、429 限流 ${local.desktop.rateLimit429Hits} 次、活跃定时任务 ${activeSchedCount} 个，建议恢复常规人工节奏。`
        : schedWarn
        ? `检测到 ${activeSchedCount} 个近期活跃定时任务（≥6 轻度提醒阈值），另有 ${histSchedCount} 个历史留存脚本（不计风险），建议控制执行频率。`
        : `近 5h/24h 无异常跨夜机刷循环，子代理 ${local.behavior.subagentRatio24hPct}%，活跃定时任务 ${activeSchedCount} 个${
            histSchedCount > 0 ? `（历史留存 ${histSchedCount} 个不计风险）` : ""
          }，${local.desktop.rateLimit429Hits} 次 429 限流。`,
      cols: 2,
      metrics: [
        {
          k: "离线 .jsonl 跨夜节律（CLI + 桌面端 Code 模式）",
          v: rhythmBad
            ? `24h 活跃 ${local.behavior.activeHours24h}h (${local.behavior.last24h.assistantTurns} 轮) · 疑似机刷`
            : `人工停顿正常 · 子代理 ${local.behavior.subagentRatio24hPct}%${
                (local.behavior.desktopSessionsFiles7d ?? 0) > 0
                  ? `（含桌面端 ${local.behavior.desktopSessionsFiles7d} 份会话）`
                  : ""
              }`,
          cls: rhythmBad ? "danger" : "ok",
          boxState: rhythmBad ? "is-danger" : "",
        },
        {
          k: "定时任务 (活跃 ≥6 轻度提示 · 历史不计分)",
          v:
            histSchedCount > 0
              ? `活跃 ${activeSchedCount} 个 · 历史留存 ${histSchedCount} 个（>72h 不计风险）`
              : `活跃 ${activeSchedCount} 个（0~5 个正常）`,
          cls: schedWarn ? "warn" : "ok",
          boxState: schedWarn ? "is-warn" : "",
          btn:
            local.hygiene.scheduledTasksDir && (activeSchedCount > 0 || histSchedCount > 0)
              ? {
                  label: "打开目录查看",
                  primary: false,
                  onClick: () => {
                    if (local.hygiene.scheduledTasksDir) {
                      void ipc.openFileFolder(local.hygiene.scheduledTasksDir);
                    }
                  },
                }
              : undefined,
        },
        {
          k: "多开并发峰值 (sideSessions) & 429",
          v: `峰值 ${local.desktop.maxSideSessionsSeen} · ${local.desktop.rateLimit429Hits} 次 429`,
          cls: rate429High ? "danger" : rate429Mild ? "warn" : "ok",
          boxState: rate429High ? "is-danger" : rate429Mild ? "is-warn" : "",
        },
        {
          k: "缓存 5h / 7d 水位与软锁",
          v: `${report.quota.fiveHourPct ?? "—"}% / ${report.quota.sevenDayPct ?? "—"}% · ${
            report.quota.softLocked ? "命中软锁" : "无软锁"
          }`,
          cls: report.quota.softLocked ? "warn" : "ok",
          boxState: report.quota.softLocked ? "is-warn" : "",
        },
      ],
      advice:
        "官方支持正常的定时任务能力：仅近期活跃定时任务 ≥6 个时做轻微提醒，超过 72h 未变动的历史脚本不扣分且绝不自动删除；仅真实跨夜 24×7 循环、高频 429 或高并发才会触发红灯预警。离线 .jsonl 节律已同时覆盖 CLI 与桌面端 Code/Agent 本地会话；桌面端普通云端聊天的正文与轮次仅存在官方云端、不落盘本地，此处显示 0 轮属正常边界。",
    };

    // 第 3 项：注册归属地与出口一致性核对
    const showSkInput = isRealLocal || forceSkInputMode;
    const isCrossMismatch = geoConsistency === "cross_continent_mismatch";
    const geoLabel = report.workspaceGeo ?? "待核";
    const exitLabel = `${report.exitCountry ?? "未知"}${
      report.exitColo ? `(${report.exitColo})` : ""
    }`;

    const gCloud: AuditGroupView = showSkInput
      ? {
          part: "tool",
          id: "g-cloud",
          icon: <Globe size={15} strokeWidth={1.8} />,
          prefix: "官方红线",
          prefixCls: "redline",
          title: "注册归属地与出口一致性核对",
          status: isCrossMismatch ? "danger" : isRealLocal ? "pending" : "ok",
          statusText: isCrossMismatch ? "跨洲错配" : isRealLocal ? "待核归属" : "重验核对",
          summary:
            "输入一次性 sk，同步顶部 4 项账号云端本体状态，并绑定隐藏注册归属地长期自动比对出口。",
          isSkPanel: true,
        }
      : {
          part: "tool",
          id: "g-cloud",
          icon: <Globe size={15} strokeWidth={1.8} />,
          prefix: "官方红线",
          prefixCls: "redline",
          title: "注册归属地与出口一致性核对",
          status: isCrossMismatch ? "danger" : "ok",
          statusText: isCrossMismatch ? "跨洲错配" : "同区一致",
          summary: isCrossMismatch
            ? `账号注册属地 ${geoLabel} 与当前出口 ${exitLabel} 跨洲错配，强烈建议切回同区稳定节点。`
            : cloudStale
            ? `已绑定注册属地 ${geoLabel}（与当前出口 ${exitLabel} 一致）；云端状态为 ${
                report.cloudAgeDays ?? 8
              } 天前快照，建议按需重验。`
            : `账号注册属地 ${geoLabel} 与当前出口 ${exitLabel} 同区一致。`,
          readonlyMetrics: [
            {
              k: "出口 IP 纯净度",
              v: report.exitIpPurity ?? "节点流量体检联动中",
            },
            {
              k: "属地绑定状态",
              v: cloudStale
                ? `属地 ${geoLabel} 长期有效 · 云端 ${report.cloudAgeDays ?? 8} 天前核验`
                : `已绑定属地 ${geoLabel} · 第 ${Math.max(1, report.verifyCount)} 次核验`,
              cls: cloudStale ? "warn" : "",
              boxState: cloudStale ? "is-warn" : "",
            },
          ],
          cols: 1,
          metrics: [
            {
              k: "注册属地 × 当前出口节点",
              v: isCrossMismatch
                ? `${geoLabel} × ${exitLabel} · 跨洲错配（高风险诱因）`
                : `${geoLabel} × ${exitLabel} · 同区一致（持续自动比对）`,
              cls: isCrossMismatch ? "danger" : "ok",
              boxState: isCrossMismatch ? "is-danger" : "",
              btn: isCrossMismatch
                ? {
                    label: "前往切换同区节点 →",
                    primary: true,
                    onClick: () => {
                      setActiveTab("nodes");
                      setNodesSubTab("quality");
                    },
                  }
                : { label: "节点已匹配", primary: false, disabled: true },
            },
          ],
          advice: isCrossMismatch
            ? "归属地与出口跨洲错配属已知高风险诱因，强烈建议切回同区稳定节点；切换后随时可点击右侧「重验 sk」刷新云端状态。"
            : "绑定注册属地后工具会自动持续比对当前出口；如需更新对话状态、警告标或实时额度，可随时点击右侧重验。",
          allowReverify: true,
        };

    // 第 4 项：多号混登、设备指纹与旧号残留防连坐（100% 由单一真源 report.topology 6 态驱动，彻底告别假绿与按钮误置灰）
    const cliOrg = local.claudeJson.orgUuidPrefix8;
    const desktopOrgs = local.desktop.orgIdPrefixes;
    const detectedList = report.detectedAccounts ?? [];
    const lookupOrgLabel = (org: string) =>
      detectedList.find((d) => d.orgPrefix8.toLowerCase() === org.toLowerCase())?.displayLabel ??
      `org ${org}`;
    const topo = report.topology;
    const hygieneState =
      topo?.hygieneState ??
      (local.desktop.accountBannedHits > 0 || local.desktop.crossOrg404Hits > 0
        ? "high_risk_ban_contamination"
        : local.crossClientOrgMismatch || desktopOrgs.length > 1
        ? "cross_surface_mix"
        : desktopOrgs.length === 0 && !cliOrg
        ? "clean_empty"
        : desktopOrgs.length > 0 && cliOrg
        ? "clean_synced_single"
        : "single_surface_clean");

    const cliLabel = topo?.cliAccount ?? (cliOrg ? lookupOrgLabel(cliOrg) : "未登录");
    const desktopLabel =
      topo && topo.desktopAccounts.length > 0
        ? topo.desktopAccounts.join(" / ")
        : desktopOrgs.length > 0
        ? desktopOrgs.map(lookupOrgLabel).join(" / ")
        : "桌面端已清空（无登录态）";

    const isHighRiskMix = hygieneState === "high_risk_ban_contamination";
    const isCrossMix = hygieneState === "cross_surface_mix";
    const isCliStaleOrPolluted = hygieneState === "single_surface_stale_or_polluted";
    const mixWarnOrBad = isHighRiskMix || isCrossMix || isCliStaleOrPolluted;

    const backupSummary =
      local.hygiene.backupAccounts.length > 0
        ? local.hygiene.backupAccounts
            .map(
              (b) =>
                `${b.backupCount} 份备份：${b.emailMasked ?? b.orgPrefix}${
                  b.planLabel ? ` (${b.planLabel})` : ""
                }`
            )
            .join(" · ")
        : "0 份历史旧备份";
    const cliHasCleanupTarget =
      topo?.hasCliCleanupTarget ??
      (local.hygiene.backupFileCount > 0 ||
        local.credentials.exists ||
        Boolean(cliOrg) ||
        Boolean(local.claudeJson.cachedUsage));
    const cliReasonsText =
      topo && topo.cliStaleReasons.length > 0 ? `（${topo.cliStaleReasons.join("；")}）` : "";
    const orphanCount = topo?.sessionDirOrphans.length ?? local.desktop.sessionDirOrgPrefixes?.length ?? 0;

    const gMixStatusText =
      hygieneState === "high_risk_ban_contamination"
        ? "高危污染"
        : hygieneState === "cross_surface_mix"
        ? "跨端混登"
        : hygieneState === "single_surface_stale_or_polluted"
        ? "CLI 残留预警"
        : hygieneState === "clean_empty"
        ? "双端已空"
        : hygieneState === "clean_synced_single"
        ? "双端一致"
        : "单端纯净";

    const gMix: AuditGroupView = {
      part: "tool",
      id: "g-mix",
      icon: <Users size={15} strokeWidth={1.8} />,
      prefix: "官方红线",
      prefixCls: "redline",
      title: "多号混登、设备指纹与旧号残留防连坐",
      status: isHighRiskMix ? "danger" : isCrossMix || isCliStaleOrPolluted ? "warn" : "ok",
      statusText: gMixStatusText,
      summary:
        topo?.headline ??
        (mixWarnOrBad
          ? `桌面端 [${desktopLabel}] 与 CLI [${cliLabel}] 存在账号差异或残留。`
          : `本机单端纯净（桌面端：${desktopLabel} · CLI：${cliLabel}）。`),
      readonlyMetrics: [
        {
          k: "本机设备指纹（换号前后对照）",
          v: `machineID ${local.claudeJson.machineIdPrefix8 ?? "—"} · userID ${
            local.claudeJson.userIdPrefix8 ?? "—"
          }`,
        },
        {
          k: "跨组织 404 / 封禁残留 / 会话目录",
          v: `${local.desktop.crossOrg404Hits} 次 404 · ${local.desktop.accountBannedHits} 封禁残留${
            orphanCount > 0 ? ` · ${orphanCount} 个旧会话目录` : ""
          }`,
          cls: isHighRiskMix || orphanCount > 0 ? "warn" : "",
          boxState: isHighRiskMix ? "is-warn" : "",
        },
      ],
      cols: 2,
      metrics: [
        {
          k: "桌面端登录态（Cookies / 日志）",
          v:
            desktopOrgs.length === 0
              ? orphanCount > 0
                ? `已清空登录态（Claude-Data 尚留 ${orphanCount} 个旧会话目录）`
                : "已清空（无登录态与组织残留）"
              : isCrossMix || isHighRiskMix
              ? desktopLabel
              : `${desktopLabel}（单端纯净）`,
          cls: isHighRiskMix ? "danger" : isCrossMix ? "warn" : "ok",
          boxState: isHighRiskMix ? "is-danger" : isCrossMix ? "is-warn" : "",
          btn: {
            label:
              isHighRiskMix || isCrossMix
                ? "分项清理（桌面+CLI可选）→"
                : "打开分项清理清单 →",
            primary: isHighRiskMix || isCrossMix,
            onClick: () =>
              openCleanModal({
                sourceLabel: "来自账户审计 · 多号与残留分项清理",
                onCompleted: () => void refreshAccountAudit(true),
              }),
          },
        },
        {
          k: "CLI 账号态、失效凭据与历史备份",
          v: cliHasCleanupTarget
            ? `${cliLabel}${cliReasonsText} · ${backupSummary}`
            : "CLI 已彻底清空（0 登录态 · 0 历史备份）",
          cls: isCliStaleOrPolluted || isCrossMix || local.hygiene.backupAccounts.length > 1 ? "warn" : "ok",
          boxState:
            isCliStaleOrPolluted || isCrossMix || local.hygiene.backupAccounts.length > 1
              ? "is-warn"
              : "",
          btn: cliHasCleanupTarget
            ? {
                label:
                  busyKey === "clean_cli"
                    ? "备份清理中..."
                    : isCliStaleOrPolluted
                    ? "立即清理 CLI 残留与备份"
                    : "清理 CLI 凭据与备份",
                primary: isCliStaleOrPolluted || local.hygiene.backupAccounts.length > 1,
                disabled: false,
                busy: busyKey === "clean_cli",
                onClick: () => void handleCleanCliWithBackup(),
              }
            : { label: "CLI 已纯净", primary: false, disabled: true },
        },
      ],
      advice:
        topo?.detail ??
        "打开「分项清理」默认同时勾选桌面端与 CLI 登录态并展示各自脱敏账号，取消勾选即可保留指定端；只要存在 CLI 旧号/备份，随时可点击右侧按钮一键先备份再彻底清除。",
    };

    // 第 5 项：官方 API 端点防反代检测
    const settingsEpBad = Boolean(local.hygiene.settingsNonOfficialEndpoint);
    const sysEnvEpBad = local.hygiene.systemEnvEndpointConflicts.length > 0;
    const epBad = settingsEpBad || sysEnvEpBad;

    const gEndpoint: AuditGroupView = {
      part: "tool",
      id: "g-endpoint",
      icon: <Link2 size={15} strokeWidth={1.8} />,
      prefix: "官方红线",
      prefixCls: "redline",
      title: "官方 API 端点防反代检测",
      status: epBad ? "danger" : "ok",
      statusText: epBad ? "非官端点" : "原生端点",
      summary: epBad
        ? `检出非官方端点改写（${
            local.hygiene.settingsNonOfficialEndpoint ??
            local.hygiene.systemEnvEndpointConflicts[0]
          }），强烈建议还原官方原生端点。`
        : "未检出非官方 ANTHROPIC_BASE_URL / API_URL 改写，消费级订阅直连原生官方端点。",
      cols: 2,
      metrics: [
        {
          k: "settings.json ANTHROPIC_BASE_URL",
          v: local.hygiene.settingsNonOfficialEndpoint ?? "默认官方（未改写）",
          cls: settingsEpBad ? "danger" : "ok",
          boxState: settingsEpBad ? "is-danger" : "",
          btn: settingsEpBad
            ? {
                label: busyKey === "restore_endpoint" ? "还原中..." : "一键备份还原官方端点",
                primary: true,
                busy: busyKey === "restore_endpoint",
                onClick: () => void handleRestoreOfficialEndpoint(),
              }
            : undefined,
        },
        {
          k: "系统环境变量 API 端点冲突",
          v: sysEnvEpBad
            ? local.hygiene.systemEnvEndpointConflicts.join(" · ")
            : "0 冲突 · 原生直连",
          cls: sysEnvEpBad ? "danger" : "ok",
          boxState: sysEnvEpBad ? "is-danger" : "",
          btn: sysEnvEpBad
            ? {
                label: busyKey === "restore_endpoint" ? "还原中..." : "一键清理系统端点冲突",
                primary: true,
                busy: busyKey === "restore_endpoint",
                onClick: () => void handleRestoreOfficialEndpoint(),
              }
            : undefined,
        },
      ],
      advice:
        "消费级订阅强烈建议直连官方原生端点，避免叠加第三方共享反代中转池引发连坐。",
    };

    // 第 6 项：Clash 断连回传 Cookie 403 防护（5 重严格防漏链判定：运行中全就绪绝不误判漏链，任一缺口精准标出）
    const disProxyBad = !report.runtimeProxyOk;
    const holdActiveNow = Boolean(snapshot.killHoldActive || report.runtimeKillHoldActive);
    const bgProcsNow = snapshot.bgClaudeProcs ?? report.runtimeBgProcs;
    const disGaps = report.runtimeDisconnectGaps ?? [];
    const disGuardOk =
      report.runtimeDisconnectGuardOk !== undefined
        ? report.runtimeDisconnectGuardOk
        : !disProxyBad;
    const disRuntimeGap = !disGuardOk || disGaps.length > 0;
    const dis403Bad = local.desktop.cookie403Hits > 0;
    const disHasIssue = disProxyBad || disRuntimeGap || dis403Bad;
    const isRunningGuarded = bgProcsNow > 0 && !holdActiveNow && !disHasIssue;

    const gDisconnect: AuditGroupView = {
      part: "tool",
      id: "g-disconnect",
      icon: <Shield size={15} strokeWidth={1.8} />,
      prefix: "经验防护",
      prefixCls: "warn-exp",
      title: "Clash 断连回传 Cookie 403 防护",
      status: disProxyBad || dis403Bad ? "danger" : disRuntimeGap ? "warn" : "ok",
      statusText: disHasIssue
        ? "存在漏链"
        : isRunningGuarded
        ? "运行护航中"
        : "防护就绪",
      summary: disHasIssue
        ? `${
            disGaps.length > 0
              ? `5 重防漏链存在缺口：${disGaps.join("、")}`
              : disProxyBad
              ? "TUN 代理离线或异常"
              : "运行护航存在缺口"
          }；日志捕获 ${local.desktop.cookie403Hits} 次退出回传 Cookie 403。`
        : isRunningGuarded
        ? `Claude 正在运行（${bgProcsNow} 进程），Clash/TUN、规则锁死、Fake-IP DNS、0 异常直连与自动 4 层热熔断 5 重防护已全就绪，0 次 Cookie 403。`
        : "代理 TUN 接管在线、5 重防漏链与防复活盯防就绪、日志 0 次断连回传 Cookie 403。",
      cols: 3,
      metrics: [
        {
          k: "5 重防漏链底座（TUN / 规则 / DNS / 热熔断）",
          v: disProxyBad
            ? "TUN 离线 / 代理异常"
            : disGaps.length > 0
            ? `缺口：${disGaps[0]}`
            : "5 重防漏链全部在线就绪",
          cls: disProxyBad ? "danger" : disRuntimeGap ? "warn" : "ok",
          boxState: disProxyBad ? "is-danger" : disRuntimeGap ? "is-warn" : "",
          btn:
            disProxyBad || disRuntimeGap
              ? {
                  label: "前往控制台补齐 →",
                  primary: true,
                  onClick: () => setActiveTab("console"),
                }
              : {
                  label: "查看控制台",
                  primary: false,
                  onClick: () => setActiveTab("console"),
                },
        },
        {
          k: "运行护航 & 切代理防复活盯防",
          v: holdActiveNow
            ? `${snapshot.killHoldRemainingSecs ?? 45}s 盯防保护中`
            : bgProcsNow > 0
            ? disRuntimeGap
              ? `${bgProcsNow} 进程运行中 · 建议补齐防漏链或先清退`
              : `${bgProcsNow} 进程正常运行 · 自动热熔断护航中`
            : "0 后台残留 · 盯防就绪",
          cls: bgProcsNow > 0 && disRuntimeGap ? "warn" : "ok",
          boxState: bgProcsNow > 0 && disRuntimeGap ? "is-warn" : "",
          btn:
            bgProcsNow > 0 && !holdActiveNow
              ? {
                  label:
                    busyKey === "enable_hold"
                      ? "强杀盯防中..."
                      : disRuntimeGap
                      ? `立即清退并盯防 ${config.killHoldSeconds ?? 45}s`
                      : `切代理前清退并盯防 ${config.killHoldSeconds ?? 45}s`,
                  primary: disRuntimeGap,
                  busy: busyKey === "enable_hold",
                  onClick: () => void handleEnableHold(),
                }
              : {
                  label: holdActiveNow ? "已开启盯防" : "盯防就绪",
                  primary: false,
                  disabled: true,
                },
        },
        {
          k: "断连回传 Cookie 403",
          v: dis403Bad
            ? `近期命中 ${local.desktop.cookie403Hits} 次前兆`
            : "0 次命中",
          cls: dis403Bad ? "danger" : "ok",
          boxState: dis403Bad ? "is-danger" : "",
          btn: {
            label: dis403Bad ? "查看日志异常 →" : "查看日志异常",
            primary: dis403Bad,
            onClick: () => setSubTab("logs"),
          },
        },
      ],
      advice:
        `Claude 正常使用时需满足 5 重硬防线（Clash 在线、TUN 接管、策略组规则锁死、Fake-IP DNS 无泄漏且 0 异常直连、开启运行中自动 4 层热熔断）；平时正常使用无需手动强杀，仅在准备手动切换节点、重启或关闭 Clash 代理前再点「清退并盯防 ${config.killHoldSeconds ?? 45}s」即可阻断断连瞬间的裸连回传。`,
    };

    // 第 7 项：本机遥测开关与缓存清理（2 列固定位，未装 CLI 且 0 B 缓存自动豁免）
    const cliInstalled = local.hygiene.cliInstalled !== false;
    const telDirBad = local.hygiene.telemetryTotalBytes > 0;
    const cliTelExempt = !cliInstalled && !telDirBad;
    const telEnvBad = !cliTelExempt && local.hygiene.privacyMissingKeys.length > 0;
    const telAnyBad = telEnvBad || telDirBad;

    const gTelemetry: AuditGroupView = {
      part: "tool",
      id: "g-telemetry",
      icon: <EyeOff size={15} strokeWidth={1.8} />,
      prefix: "隐私降噪",
      prefixCls: "privacy-low",
      title: "本机遥测开关与缓存清理（仅作用于 CLI）",
      status: telAnyBad ? "warn" : "ok",
      statusText: cliTelExempt ? "未装 CLI · 豁免" : telAnyBad ? "缺降噪项" : "降噪已全",
      summary: cliTelExempt
        ? "本机未检测到 Claude Code CLI 且 ~/.claude/telemetry 为 0 B，已自动豁免通过（仅作用于命令行 CLI，不影响桌面端）。"
        : telAnyBad
        ? `${
            telEnvBad
              ? `settings.json 缺 ${local.hygiene.privacyMissingKeys.length} 项 CLI 降噪变量`
              : "4/4 CLI 降噪变量已全"
          }，${
            telDirBad
              ? `telemetry 目录存在 ${formatBytesReadable(local.hygiene.telemetryTotalBytes)} 待传缓存`
              : "telemetry 目录 0 B"
          }。`
        : "4/4 官方 CLI 隐私降噪环境变量均已开启（已关闭非必要遥测与错误上报），待传 telemetry 目录为 0 B。",
      cols: 2,
      metrics: [
        {
          k: "settings.json 4 项降噪开关（仅 CLI）",
          v: cliTelExempt
            ? "未安装 Claude Code CLI（自动豁免）"
            : telEnvBad
            ? `仅 ${local.hygiene.privacyEnabledCount} / 4（缺 ${local.hygiene.privacyMissingKeys
                .map((k) => k.replace(/^DISABLE_/, ""))
                .join(" & ")}）`
            : "4 / 4 已全部开启（非必要上报已关闭）",
          cls: telEnvBad ? "warn" : "ok",
          boxState: telEnvBad ? "is-warn" : "",
          btn: cliTelExempt
            ? { label: "未装 CLI · 已豁免", primary: false, disabled: true }
            : telEnvBad
            ? {
                label: busyKey === "fix_tel_env" ? "写入中..." : "一键补齐 4/4 开关",
                primary: true,
                busy: busyKey === "fix_tel_env",
                onClick: () => void handleFixTelemetryEnv(),
              }
            : { label: "配置已完整", primary: false, disabled: true },
        },
        {
          k: "~/.claude/telemetry 待传遥测队列",
          v: telDirBad
            ? `待传 ${local.hygiene.telemetryFileCount} 个文件 (${formatBytesReadable(
                local.hygiene.telemetryTotalBytes
              )})`
            : "0 文件 (0 B · 无需清理)",
          cls: telDirBad ? "warn" : "ok",
          boxState: telDirBad ? "is-warn" : "",
          btn: telDirBad
            ? {
                label: busyKey === "clean_tel_dir" ? "清空中..." : "一键清空待传遥测",
                primary: true,
                busy: busyKey === "clean_tel_dir",
                onClick: () => void handleCleanTelemetryDir(),
              }
            : { label: "目录已干净", primary: false, disabled: true },
        },
      ],
      advice:
        "【遥测与降噪是什么】「遥测（Telemetry）」是 Claude Code CLI 后台自动向官方发送的使用统计、崩溃堆栈与版本检查请求，断网失败后会囤积在 ~/.claude/telemetry/ 等联网重试；开启「4 项官方降噪开关」代表通知 CLI 关闭这些非必要后台上报（减少无关设备指纹与断网回传噪音，完全不影响正常对话与登录）。补齐开关前会自动保存首次基线，随时可一键撤回；安全退出或熔断时也会自动清空待传目录。",
    };

    return [gWindow, gAuto, gCloud, gMix, gEndpoint, gDisconnect, gTelemetry];
  }, [
    report,
    forceSkInputMode,
    busyKey,
    snapshot.killHoldActive,
    snapshot.killHoldRemainingSecs,
    snapshot.bgClaudeProcs,
    config.killHoldSeconds,
    setActiveTab,
    setNodesSubTab,
    openCleanModal,
    refreshAccountAudit,
    setSubTab,
  ]);

  const userGroups = groups.filter((g) => g.part === "user");
  const toolGroups = groups.filter((g) => g.part === "tool");

  const renderGroupList = (list: AuditGroupView[]) =>
    list.map((g) => {
      const isOpen = openGroupId === g.id;
      const iconCls =
        g.status === "danger" ? "is-fail" : g.status === "warn" ? "is-warn" : "";
      const stCls =
        g.status === "danger"
          ? "st-danger"
          : g.status === "warn"
          ? "st-warn"
          : g.status === "pending"
          ? "st-pending"
          : "st-ok";

      return (
        <div
          key={g.id}
          data-testid={`audit-group-${g.id}`}
          className={`audit-group ${isOpen ? "is-open" : ""} ${
            g.status === "danger" ? "is-danger-row" : ""
          }`}
        >
          <div
            className="audit-row"
            role="button"
            tabIndex={0}
            onClick={() => setOpenGroupId(isOpen ? null : g.id)}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                setOpenGroupId(isOpen ? null : g.id);
              }
            }}
          >
            <div className="audit-left">
              <div className={`guard-icon-box ${iconCls}`}>{g.icon}</div>
              <div className="audit-text">
                <div className="audit-title-line">
                  <span className={`audit-prefix-tag ${g.prefixCls}`}>
                    <span className="audit-pt-dot" />
                    {g.prefix}
                  </span>
                  <span className="audit-title">{g.title}</span>
                </div>
                <div className="audit-summary">{g.summary}</div>
              </div>
            </div>
            <div className="audit-right">
              <span className={`audit-status-pill ${stCls}`}>{g.statusText}</span>
              <span
                style={{
                  color: "var(--text-3)",
                  fontSize: 11,
                  width: 12,
                  textAlign: "center",
                }}
              >
                {isOpen ? "▴" : "▾"}
              </span>
            </div>
          </div>

          {isOpen && (
            <div className="audit-detail tabular">
              {g.isSkPanel ? (
                <div className="audit-sk-box">
                  <div className="audit-sk-row">
                    <input
                      ref={skInputRef}
                      data-testid="audit-sk-input"
                      className="audit-sk-input"
                      type="text"
                      autoComplete="off"
                      spellCheck={false}
                      value={skInput}
                      onChange={(e) => setSkInput(e.target.value)}
                      placeholder="粘贴 sessionKey 的 Value（sk-ant-sid...）或 Copy as cURL 整段"
                    />
                    <button
                      type="button"
                      data-testid="btn-verify-cloud-sk"
                      className="guard-btn guard-btn-primary guard-btn-sm"
                      disabled={!extractedSk || busyKey === "verify_sk"}
                      onClick={() => void handleVerifyCloud(false)}
                    >
                      {busyKey === "verify_sk" && (
                        <Loader2 size={13} strokeWidth={2} className="guard-spin" />
                      )}
                      <span>{busyKey === "verify_sk" ? "核验中..." : "开始核验"}</span>
                    </button>
                  </div>
                  <div className="audit-sk-sub">
                    <span
                      data-testid="audit-sk-feedback"
                      style={{
                        color: extractedSk
                          ? "var(--success)"
                          : skInput.trim().length > 0
                          ? "var(--danger-bright)"
                          : "var(--text-3)",
                      }}
                    >
                      {extractedSk
                        ? `已提取有效 sessionKey（${extractedSk.slice(
                            0,
                            14
                          )}••••${extractedSk.slice(-4)}），其余内容已忽略且绝不落盘`
                        : skInput.trim().length > 0
                        ? "未识别到有效 sessionKey（需以 sk-ant-sid 开头）：请勿粘贴网页/JS 链接，点击右侧「怎么 10 秒复制？」从 Cookies 复制 sessionKey 的 Value"
                        : `经本机代理 (${
                            report?.runtimeClashPort ?? 7890
                          }) 只读查询一次并绑定档案，同步回填顶部对话可用、警告与实名状态，明文用完即焚`}
                    </span>
                    <button
                      type="button"
                      data-testid="btn-toggle-sk-how"
                      className="audit-text-btn"
                      onClick={() => setShowHowSk((v) => !v)}
                    >
                      怎么 10 秒复制？ {showHowSk ? "▴" : "▾"}
                    </button>
                  </div>
                  {showHowSk && (
                    <div className="audit-sk-how" data-testid="audit-sk-how-panel">
                      <div style={{ marginBottom: 8, color: "var(--text-1)", fontWeight: 500 }}>
                        推荐方式（Chrome / Edge 10 秒定位，准确率 100%）：
                      </div>
                      <ol
                        style={{
                          margin: "0 0 10px 18px",
                          padding: 0,
                          display: "flex",
                          flexDirection: "column",
                          gap: 4,
                          lineHeight: 1.55,
                        }}
                      >
                        <li>
                          先确认浏览器当前登录的 <span className="font-mono-code">claude.ai</span>{" "}
                          是你想核验的目标账号
                          {report?.emailMasked && report.emailMasked !== "未检测到本机账号"
                            ? `（本机当前展示：${report.emailMasked}）`
                            : ""}
                          。
                        </li>
                        <li>
                          按 <strong>F12</strong> 打开开发者工具 → 顶部切到{" "}
                          <strong>Application（应用）</strong> → 左侧展开{" "}
                          <strong>Storage（存储）→ Cookies</strong> → 点击{" "}
                          <span className="font-mono-code">https://claude.ai</span>。
                        </li>
                        <li>
                          在右侧列表中找到 <strong>sessionKey</strong> 一行，复制其{" "}
                          <strong>Value</strong>（以{" "}
                          <span className="font-mono-code">sk-ant-sid...</span>{" "}
                          开头），粘贴到上方输入框点击「开始核验」。
                        </li>
                      </ol>

                      {/* 轻量深浅主题自适应 SVG 定位引导图（零隐私泄露） */}
                      <svg
                        viewBox="0 0 620 158"
                        role="img"
                        aria-label="Chrome DevTools Application Storage Cookies sessionKey 复制步骤示意图"
                        style={{
                          width: "100%",
                          maxWidth: 620,
                          height: "auto",
                          display: "block",
                          borderRadius: 8,
                          border: "1px solid var(--border)",
                          background: "var(--bg-card)",
                          marginBottom: 8,
                        }}
                      >
                        {/* 顶栏 Tabs */}
                        <rect x="0" y="0" width="620" height="28" fill="var(--bg-subtle)" />
                        <line x1="0" y1="28" x2="620" y2="28" stroke="var(--border)" />
                        <text x="16" y="18" fontSize="10.5" fill="var(--text-3)">Elements</text>
                        <text x="76" y="18" fontSize="10.5" fill="var(--text-3)">Console</text>
                        <text x="132" y="18" fontSize="10.5" fill="var(--text-3)">Network</text>
                        <rect x="188" y="4" width="112" height="20" rx="5" fill="var(--primary)" fillOpacity="0.16" stroke="var(--primary)" />
                        <text x="197" y="18" fontSize="10.5" fontWeight="600" fill="var(--primary)">① Application / 应用</text>

                        {/* 左侧 Storage 树 */}
                        <rect x="0" y="28" width="186" height="130" fill="var(--bg-subtle)" fillOpacity="0.45" />
                        <line x1="186" y1="28" x2="186" y2="158" stroke="var(--border)" />
                        <text x="14" y="48" fontSize="10" fontWeight="600" fill="var(--text-2)">Storage（存储）</text>
                        <text x="22" y="68" fontSize="10" fill="var(--text-3)">▸ Local Storage</text>
                        <text x="22" y="86" fontSize="10" fill="var(--text-3)">▸ Session Storage</text>
                        <text x="22" y="104" fontSize="10" fontWeight="600" fill="var(--text-1)">▾ ② Cookies</text>
                        <rect x="26" y="112" width="148" height="22" rx="5" fill="var(--primary)" fillOpacity="0.18" stroke="var(--primary)" />
                        <text x="34" y="127" fontSize="10.5" fontWeight="600" fill="var(--primary)">https://claude.ai</text>

                        {/* 右侧 Cookie 表 */}
                        <text x="202" y="47" fontSize="10" fontWeight="600" fill="var(--text-3)">Name</text>
                        <text x="336" y="47" fontSize="10" fontWeight="600" fill="var(--text-3)">Value（双击此格复制）</text>
                        <line x1="186" y1="54" x2="620" y2="54" stroke="var(--border)" />
                        <text x="202" y="72" fontSize="10" fill="var(--text-3)">lastActiveOrg</text>
                        <text x="336" y="72" fontSize="10" fill="var(--text-3)">a4722ea6-xxxx-xxxx...</text>

                        {/* 高亮 sessionKey 行 */}
                        <rect x="194" y="82" width="416" height="28" rx="6" fill="var(--success)" fillOpacity="0.14" stroke="var(--success)" />
                        <text x="202" y="100" fontSize="11" fontWeight="700" fill="var(--text-1)">③ sessionKey</text>
                        <text x="336" y="100" fontSize="11" fontWeight="600" fill="var(--success)" fontFamily="monospace">sk-ant-sid01-••••••••••••</text>

                        <text x="202" y="130" fontSize="10" fill="var(--text-3)">cf_clearance</text>
                        <text x="336" y="130" fontSize="10" fill="var(--text-3)">无需复制</text>
                        <text x="202" y="148" fontSize="9.5" fill="var(--text-3)">提示：也可在 Network 右键 API 请求点 Copy as cURL 整段粘贴，工具会自动提取</text>
                      </svg>
                    </div>
                  )}
                </div>
              ) : (
                <>
                  {g.readonlyMetrics && g.readonlyMetrics.length > 0 && (
                    <div className="audit-readonly-strip">
                      {g.readonlyMetrics.map((rm) => (
                        <div key={rm.k} className={`audit-readonly-box ${rm.boxState ?? ""}`}>
                          <span className="k">{rm.k}</span>
                          <span className={`v ${rm.cls ?? ""}`}>{rm.v}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {g.metrics && g.metrics.length > 0 && (
                    <div
                      className={`audit-metric-strip ${
                        g.cols === 1 ? "cols-1" : g.cols === 2 ? "cols-2" : ""
                      }`}
                    >
                      {g.metrics.map((m) => (
                        <div key={m.k} className={`audit-metric-box ${m.boxState ?? ""}`}>
                          <div>
                            <div className="k">{m.k}</div>
                            <div className={`v ${m.cls}`}>{m.v}</div>
                          </div>
                          {m.btn && (
                            <div className="audit-metric-act">
                              <button
                                type="button"
                                className={`guard-btn ${
                                  m.btn.primary ? "guard-btn-primary" : "guard-btn-flat"
                                } guard-btn-xs`}
                                disabled={m.btn.disabled || m.btn.busy}
                                onClick={m.btn.onClick}
                              >
                                {m.btn.busy && (
                                  <Loader2 size={11} strokeWidth={2} className="guard-spin" />
                                )}
                                <span>{m.btn.label}</span>
                              </button>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {g.advice && (
                    <div className="audit-advice-bar">
                      <span>
                        <strong>{g.part === "tool" ? "说明：" : "避坑提示："}</strong>
                        {g.advice}
                      </span>
                      {g.allowReverify && (
                        <button
                          type="button"
                          className="audit-text-btn"
                          style={{ flexShrink: 0 }}
                          onClick={focusCloudVerifyInput}
                        >
                          重验 sk
                        </button>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      );
    });

  const renderTopCloudStats = (r: AccountAuditReport) => {
    const snap = r.cloudSnapshot;
    const stale = r.cloudStale;
    const staleTag = r.cloudAgeDays ? `（${r.cloudAgeDays} 天前）` : "（超 7 天）";

    if (!r.cloudVerified || !snap) {
      return (
        <div className="audit-profile-stats">
          <div className="audit-pstat">
            <div className="audit-pstat-k">
              <span>对话可用状态</span>
            </div>
            <div className="audit-pstat-v muted">待 sk 实证</div>
            <div className="audit-pstat-sub">
              {r.local.desktop.accountBannedHits > 0
                ? `本地命中 ${r.local.desktop.accountBannedHits} 次封号残留`
                : "本地 0 封号 · 待云端实证"}
            </div>
          </div>

          <div className="audit-pstat">
            <div className="audit-pstat-k">
              <span>官方警告与静默标</span>
              <button
                type="button"
                className="audit-help-btn"
                title="查看官方静默标、Persona 与 Portal 风控区别"
                onClick={() => setShowKycExplain((v) => !v)}
              >
                ?
              </button>
            </div>
            <div className="audit-pstat-v muted">待 sk 实证</div>
            <div className="audit-pstat-sub">后台隐性观察标 · 容错率预警</div>
          </div>

          <div className="audit-pstat">
            <div className="audit-pstat-k">
              <span>Persona 实名 KYC</span>
              <button
                type="button"
                className="audit-help-btn"
                title="查看官方静默标、Persona 与 Portal 风控区别"
                onClick={() => setShowKycExplain((v) => !v)}
              >
                ?
              </button>
            </div>
            <div className="audit-pstat-v muted">待 sk 实证</div>
            <div className="audit-pstat-sub">敏感/付费抽检 · 过审抗风险提升</div>
          </div>

          <div className="audit-pstat">
            <div className="audit-pstat-k">
              <span>Portal 风控门户</span>
              <button
                type="button"
                className="audit-help-btn"
                title="查看官方静默标、Persona 与 Portal 风控区别"
                onClick={() => setShowKycExplain((v) => !v)}
              >
                ?
              </button>
            </div>
            <div className="audit-pstat-v muted" data-testid="portal-unverified-value">
              待 sk 实证
            </div>
            <div className="audit-pstat-sub">
              {r.local.desktop.portalVerifyHits > 0
                ? `本地命中 ${r.local.desktop.portalVerifyHits} 次 · 待 sk 云端复核`
                : "本地 0 拦截 · 需 sk 查云端挂起"}
            </div>
          </div>
        </div>
      );
    }

    const kycVerified = snap.personaKycStatus === "verified";
    const kycNotReq = snap.personaKycStatus === "not_required";
    const kycBlocked =
      snap.personaKycStatus != null && !kycVerified && !kycNotReq && snap.personaKycStatus !== "approved";

    return (
      <div className="audit-profile-stats">
        {/* 1. 对话可用状态 */}
        <div className="audit-pstat">
          <div className="audit-pstat-k">
            <span>对话可用状态</span>
          </div>
          <div
            className={`audit-pstat-v ${
              stale ? "muted" : snap.isBanned || !snap.chatAvailable ? "danger" : ""
            }`}
          >
            {!stale && (
              <span
                className={`guard-dot ${
                  snap.isBanned || !snap.chatAvailable ? "danger" : ""
                }`}
              />
            )}
            <span>
              {snap.isBanned
                ? "账号已封禁"
                : !snap.chatAvailable
                ? "对话受限"
                : stale
                ? `对话可用${staleTag}`
                : "对话可用"}
            </span>
          </div>
          <div className="audit-pstat-sub">
            {snap.isBanned
              ? snap.appealsRedirectEnabled
                ? "官方实锤封禁 · 允许提交申诉"
                : "官方实锤封禁 · 无申诉入口"
              : stale
              ? "核验超 7 天，建议重验刷新"
              : "对话畅通 · 无封禁限制"}
          </div>
        </div>

        {/* 2. 官方警告与静默标 */}
        <div className="audit-pstat">
          <div className="audit-pstat-k">
            <span>官方警告与静默标</span>
            <button
              type="button"
              className="audit-help-btn"
              title="查看官方静默标、Persona 与 Portal 风控区别"
              onClick={() => setShowKycExplain((v) => !v)}
            >
              ?
            </button>
          </div>
          <div
            className={`audit-pstat-v ${
              stale ? "muted" : snap.hasMonitoringNotice ? "warn" : ""
            }`}
          >
            {!stale && (
              <span className={`guard-dot ${snap.hasMonitoringNotice ? "warn" : ""}`} />
            )}
            <span>
              {snap.hasMonitoringNotice
                ? stale
                  ? `存在警告标${staleTag}`
                  : `${snap.activeFlagTypes.length} 条静默监控`
                : stale
                ? `0 警告${staleTag}`
                : "0 警告 · 干净"}
            </span>
          </div>
          <div className="audit-pstat-sub">
            {snap.hasMonitoringNotice
              ? snap.warningSummaryZh
                ? `命中：${snap.warningSummaryZh}`
                : "已进后台观察 · 疑跨区/高频诱发"
              : stale
              ? "上次无后台观察标 · 建议重验"
              : "无官方警告与后台观察标"}
          </div>
        </div>

        {/* 3. Persona 实名 KYC */}
        <div className="audit-pstat">
          <div className="audit-pstat-k">
            <span>Persona 实名 KYC</span>
            <button
              type="button"
              className="audit-help-btn"
              title="查看官方静默标、Persona 与 Portal 风控区别"
              onClick={() => setShowKycExplain((v) => !v)}
            >
              ?
            </button>
          </div>
          <div
            className={`audit-pstat-v ${stale ? "muted" : kycBlocked ? "warn" : ""}`}
          >
            {!stale && (
              <span className={`guard-dot ${kycBlocked ? "warn" : ""}`} />
            )}
            <span>
              {kycVerified
                ? stale
                  ? `已通过${staleTag}`
                  : "已通过 (verified)"
                : kycNotReq
                ? stale
                  ? `无需验证${staleTag}`
                  : "无需验证"
                : kycBlocked
                ? "待验证"
                : "状态正常"}
            </span>
          </div>
          <div className="audit-pstat-sub">
            {kycVerified
              ? "已过实名 · 抗误杀能力提升 (+5)"
              : kycBlocked
              ? "请保持固定干净节点完成官方核验"
              : "未触发实名抽检"}
          </div>
        </div>

        {/* 4. Portal 风控门户 */}
        <div className="audit-pstat">
          <div className="audit-pstat-k">
            <span>Portal 风控门户</span>
            <button
              type="button"
              className="audit-help-btn"
              title="查看官方静默标、Persona 与 Portal 风控区别"
              onClick={() => setShowKycExplain((v) => !v)}
            >
              ?
            </button>
          </div>
          {(() => {
            const isPortalHold =
              snap.portalHold || snap.portalState === "hold" || snap.portalState === "local_hold";
            const isPortalUnknown = !isPortalHold && snap.portalState === "unknown";
            return (
              <>
                <div
                  className={`audit-pstat-v ${
                    isPortalHold ? "danger" : stale || isPortalUnknown ? "muted" : ""
                  }`}
                >
                  {!stale && !isPortalUnknown && (
                    <span className={`guard-dot ${isPortalHold ? "danger" : ""}`} />
                  )}
                  <span>
                    {isPortalHold
                      ? "触发挂起"
                      : isPortalUnknown
                      ? "接口未返回"
                      : stale
                      ? `无挂起${staleTag}`
                      : "无挂起 (clear)"}
                  </span>
                </div>
                <div className="audit-pstat-sub">
                  {snap.portalState === "local_hold"
                    ? "本地日志实锤该账号触发 Portal 挂起 · 请核实申诉"
                    : isPortalHold
                    ? "风控极高危 · 已限制并需申诉"
                    : isPortalUnknown
                    ? "官方未暴露该接口字段 · 请结合本地日志与实发对话确认"
                    : stale
                    ? "风险极高项 · 本地持续 0 拦截"
                    : "未被风控挂起 · 正常放行"}
                </div>
              </>
            );
          })()}
        </div>
      </div>
    );
  };

  if (!report) {
    if (subTab === "logs") {
      return (
        <section className="audit-page" data-testid="account-audit-page">
          <div className="audit-page-hd">
            <div style={{ minWidth: 0 }}>
              <h1 className="audit-page-title">账户审计</h1>
              <p className="audit-page-sub">本地只读体检与按需云端核验，提前排查账号风控隐患</p>
            </div>
            <div className="audit-hd-btns">
              <button
                type="button"
                className="guard-btn guard-btn-flat guard-btn-sm"
                onClick={() => setSubTab("audit")}
              >
                返回账号审计
              </button>
            </div>
          </div>
          <div style={{ flex: 1, minHeight: 0, display: "flex", flexDirection: "column" }}>
            <LogAnalysisPage />
          </div>
        </section>
      );
    }
    return (
      <section className="audit-page" style={{ alignItems: "center", justifyContent: "center" }}>
        {loading ? (
          <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-2)" }}>
            <Loader2 size={16} strokeWidth={2} className="guard-spin" />
            <span>正在执行本地只读账户审计...</span>
          </div>
        ) : (
          <div
            className="guard-card"
            data-testid="audit-load-error-card"
            style={{
              maxWidth: 420,
              padding: "20px 22px",
              display: "flex",
              flexDirection: "column",
              gap: 10,
              alignItems: "flex-start",
            }}
          >
            <div style={{ fontSize: 15, fontWeight: 600, color: "var(--danger-bright)" }}>
              本地账户审计加载失败
            </div>
            <div style={{ fontSize: 12.5, color: "var(--text-2)", lineHeight: 1.55 }}>
              {auditError || "未能完成本地账号与日志扫描，请点击下方按钮重试。"}
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
              <button
                type="button"
                data-testid="btn-retry-account-audit"
                className="guard-btn guard-btn-primary guard-btn-sm"
                onClick={() => void refreshAccountAudit(false)}
              >
                <RefreshCw size={13} strokeWidth={2} />
                <span>重试审计</span>
              </button>
              <button
                type="button"
                className="guard-btn guard-btn-flat guard-btn-sm"
                onClick={() => setSubTab("logs")}
              >
                查看实时异常日志流
              </button>
            </div>
          </div>
        )}
      </section>
    );
  }

  const { scoreResult } = report;
  const { pillCls, barColor } = scoreColorCss(scoreResult.colorToken);
  const needCloudPrompt = !report.cloudVerified || report.cloudStale;

  const visibleFlowLogs = report.logFlowItems.filter((item) => {
    if (!showDenoised && item.denoised) return false;
    if (logFilter === "all") return true;
    return item.cat === logFilter;
  });

  const nonDenoisedLogCount = report.logFlowItems.filter((i) => !i.denoised).length;
  const log403Count = report.logFlowItems.filter((i) => i.cat === "403" && !i.denoised).length;
  const logNetCount = report.logFlowItems.filter((i) => i.cat === "net").length;

  return (
    <section className="audit-page" data-testid="account-audit-page">
      {/* 页头 */}
      <div className="audit-page-hd">
        <div style={{ minWidth: 0 }}>
          <h1 className="audit-page-title">账户审计</h1>
          <p className="audit-page-sub">本地只读体检与按需云端核验，提前排查账号风控隐患</p>
        </div>
        <div className="audit-hd-btns">
          <button
            type="button"
            data-testid="btn-open-anti-ban-guide"
            className="audit-guide-btn"
            onClick={() => setGuideOpen(true)}
          >
            <BookOpen size={13.5} strokeWidth={2} />
            <span>防封宝典</span>
          </button>

          <div className="audit-seg-wrap" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={subTab === "audit"}
              data-testid="tab-account-audit"
              className={`audit-seg-btn ${subTab === "audit" ? "active" : ""}`}
              onClick={() => setSubTab("audit")}
            >
              账号安全审计
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={subTab === "logs"}
              data-testid="tab-account-logs"
              className={`audit-seg-btn ${subTab === "logs" ? "active" : ""}`}
              onClick={() => setSubTab("logs")}
            >
              <span>实时异常日志流</span>
              {unreadLogsCount > 0 && (
                <span
                  className="guard-chip guard-chip-warn tabular"
                  style={{ padding: "0 5px", fontSize: 10.5 }}
                >
                  {unreadLogsCount}
                </span>
              )}
            </button>
          </div>

          <button
            type="button"
            data-testid="btn-rescan-account-audit"
            disabled={loading}
            className="guard-btn guard-btn-flat guard-btn-sm"
            onClick={() => void refreshAccountAudit(false)}
          >
            {loading ? (
              <Loader2 size={13.5} strokeWidth={2} className="guard-spin" />
            ) : (
              <RefreshCw size={13.5} strokeWidth={2} />
            )}
            <span>{loading ? "审计中..." : "重新审计"}</span>
          </button>
        </div>
      </div>

      {/* Master-Detail 双栏骨架 */}
      <div className="audit-workspace">
        {/* 左栏 244px */}
        <section className="audit-acct-pane">
          <div className="audit-acct-top">
            {(() => {
              const extraAccounts = (report.detectedAccounts ?? []).filter((a) => !a.isPrimary);
              const totalAccounts = Math.max(1, (report.detectedAccounts ?? []).length);
              return (
                <>
                  <div className="audit-pane-hd">
                    <span className="audit-pane-title tabular">当前档案 ({totalAccounts})</span>
                    {totalAccounts > 1 ? (
                      <span
                        className="guard-chip guard-chip-warn"
                        data-testid="audit-multi-account-chip"
                        style={{ padding: "1px 6px", fontSize: 10.5 }}
                      >
                        {totalAccounts === 2 ? "双号" : `${totalAccounts} 号`}
                      </span>
                    ) : (
                      <span style={{ fontSize: 11, color: "var(--text-3)" }}>本机激活</span>
                    )}
                  </div>

                  <div
                    className="audit-acct-card tabular"
                    onClick={() => setSubTab("audit")}
                    role="button"
                    tabIndex={0}
                  >
                    <div className="audit-acct-row1">
                      <div className="audit-acct-mail">
                        <span
                          className={`guard-dot ${
                            report.hasDangerIssue
                              ? "danger"
                              : report.pendingIssueCount > 0 || totalAccounts > 1
                              ? "warn"
                              : ""
                          }`}
                        />
                        <span className="audit-acct-mail-txt">
                          {!report.cloudVerified &&
                          report.orgIdPrefix8 &&
                          report.emailMasked.startsWith("桌面端账号")
                            ? `新号 · ${report.orgIdPrefix8}`
                            : report.emailMasked}
                        </span>
                      </div>
                      <span className="guard-chip guard-chip-neutral">
                        {!report.cloudVerified && report.plan === "未知" ? "待核验" : report.plan}
                      </span>
                    </div>

                    <div className="audit-acct-sub">
                      <span
                        style={{
                          color:
                            report.geoConsistency === "cross_continent_mismatch"
                              ? "var(--danger-bright)"
                              : "var(--text-3)",
                        }}
                      >
                        {report.workspaceGeo
                          ? `归属 ${report.workspaceGeo} · 出口 ${
                              report.exitColo ?? report.exitCountry ?? "未知"
                            }`
                          : `属地待核 · 出口 ${report.exitCountry ?? "未知"}`}
                      </span>
                      <span
                        title={report.quota.stampTooltip}
                        style={{
                          color:
                            !report.cloudVerified && totalAccounts > 1
                              ? "var(--primary-hover)"
                              : "var(--text-3)",
                          fontWeight: !report.cloudVerified && totalAccounts > 1 ? 500 : 400,
                          flexShrink: 0,
                        }}
                      >
                        {!report.cloudVerified && totalAccounts > 1 ? "新登录" : report.quota.stampShort}
                      </span>
                    </div>

                    <div className="audit-acct-quota">
                      <div
                        className="audit-q-row"
                        title={report.quota.fiveHourOfflineNote ?? report.quota.stampTooltip}
                      >
                        <span>5h 额度</span>
                        <span style={{ fontWeight: 600 }}>
                          {report.quota.fiveHourPct != null ? `${report.quota.fiveHourPct}%` : "—"}
                        </span>
                      </div>
                      <div className="audit-q-track">
                        <div
                          className="audit-q-fill"
                          style={{ width: `${report.quota.fiveHourPct ?? 0}%` }}
                        />
                      </div>
                      <div
                        className="audit-q-row"
                        style={{ marginTop: 2 }}
                        title={report.quota.sevenDayOfflineNote ?? report.quota.stampTooltip}
                      >
                        <span>7d 额度</span>
                        <span>
                          {report.quota.sevenDayPct != null
                            ? `${report.quota.sevenDayPct}%`
                            : report.quota.sevenDayOfflineNote
                            ? "已过窗·待核"
                            : "—"}
                        </span>
                      </div>
                      <div className="audit-q-track">
                        <div
                          className="audit-q-fill soft"
                          style={{ width: `${report.quota.sevenDayPct ?? 0}%` }}
                        />
                      </div>
                    </div>

                    <div className="audit-acct-tags">
                      <span
                        style={{
                          color: report.hasDangerIssue
                            ? "var(--danger-bright)"
                            : report.pendingIssueCount > 0
                            ? "var(--warning)"
                            : "var(--text-2)",
                          fontWeight: report.pendingIssueCount > 0 ? 600 : 500,
                        }}
                      >
                        {report.pendingIssueCount > 0
                          ? `${report.pendingIssueCount} 项待处理`
                          : "状态安全"}
                      </span>
                      <span style={{ color: "var(--text-3)" }}>
                        {report.accountAgeDays != null
                          ? `${report.accountAgeDays} 天`
                          : !report.cloudVerified
                          ? "未核验"
                          : "年龄未知"}
                      </span>
                    </div>
                  </div>

                  {extraAccounts.map((acc) => (
                    <div
                      key={acc.orgPrefix8}
                      data-testid={`audit-extra-account-${acc.orgPrefix8}`}
                      className="audit-acct-extra tabular"
                    >
                      <div className="audit-acct-row1">
                        <div className="audit-acct-mail" style={{ fontSize: 12.5 }}>
                          <span className="guard-dot warn" />
                          <span className="audit-acct-mail-txt">
                            {acc.emailMasked ?? `组织 ${acc.orgPrefix8}`}
                          </span>
                        </div>
                        {acc.plan && (
                          <span
                            className="guard-chip guard-chip-neutral"
                            style={{ fontSize: 10.5, padding: "1px 6px" }}
                          >
                            {acc.plan}
                          </span>
                        )}
                      </div>
                      <div className="audit-acct-sub">
                        <span>
                          旧残留 · {acc.orgPrefix8}
                        </span>
                        <button
                          type="button"
                          onClick={() => openCleanModal({ sourceLabel: "来自账户审计多号残留" })}
                          style={{
                            border: "none",
                            background: "transparent",
                            padding: 0,
                            color: "var(--primary-hover)",
                            fontSize: 11,
                            fontWeight: 500,
                            cursor: "pointer",
                          }}
                        >
                          去清理 →
                        </button>
                      </div>
                    </div>
                  ))}
                </>
              );
            })()}

            <button
              type="button"
              data-testid="audit-pulse-card"
              className="audit-live-pulse"
              onClick={() => setSubTab("logs")}
            >
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  fontSize: 12,
                  fontWeight: 600,
                }}
              >
                <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span className={`guard-dot ${unreadLogsCount > 0 ? "warn" : ""}`} />
                  实时异常日志流
                </span>
                <span
                  className="tabular"
                  style={{
                    fontSize: 11,
                    color: unreadLogsCount > 0 ? "var(--warning)" : "var(--text-3)",
                  }}
                >
                  {unreadLogsCount} 未读
                </span>
              </div>
              <div style={{ fontSize: 11.5, color: "var(--text-2)", lineHeight: 1.48 }}>
                {report.local.desktop.cookie403Hits > 0
                  ? `捕获 ${report.local.desktop.cookie403Hits} 条退出回传 Cookie 403 高危前兆；${report.denoisedOauth403Count} 条 OAuth 403 已降噪。`
                  : report.local.desktop.cfShield403Hits > 0
                  ? `403 消歧：${report.local.desktop.cfShield403Hits} 条 CF 入口盾（非封号）；${report.denoisedOauth403Count} 条背景 OAuth 403 已自动降噪。`
                  : `近 24 小时日志平稳；${report.denoisedOauth403Count} 条背景 OAuth 403 已静默降噪。`}
              </div>
              <div style={{ fontSize: 11.5, color: "var(--primary)", fontWeight: 500 }}>
                进入日志流 →
              </div>
            </button>
          </div>

          <div className="audit-foot-hint">
            Anthropic 风控为黑盒模型，无“集齐必封”公式；本页仅保留经真机验证有效的防封项。
          </div>
        </section>

        {/* 右栏视图 A：账号安全审计 */}
        {subTab === "audit" ? (
          <section className="audit-detail-pane" data-testid="audit-detail-view">
            {/* 顶部双层档案总览卡 */}
            <div className="guard-card tabular">
              <div className="audit-profile-top">
                <div style={{ display: "flex", flexDirection: "column", gap: 4, minWidth: 0 }}>
                  <div className="audit-profile-id-line">
                    <span className="audit-profile-email">{report.emailMasked}</span>
                    <span
                      className="guard-chip guard-chip-neutral"
                      style={{ padding: "1px 6px" }}
                      title={
                        report.cloudVerified
                          ? "云端实时核验套餐"
                          : "来自本机配置文件缓存（若已到期降级为 Free，请点击右侧「云端核验」实时刷新）"
                      }
                    >
                      {report.cloudVerified ? report.plan : `${report.plan} · 缓存`}
                    </span>
                    {report.primarySource && report.primarySource !== "none" && (
                      <span
                        className={`guard-chip ${
                          report.primarySource === "cli_stale" ? "guard-chip-warn" : "guard-chip-mode"
                        }`}
                        style={{ padding: "1px 6px" }}
                        title="当前顶部主档案的识别来源"
                      >
                        {report.primarySource === "desktop_web"
                          ? "桌面/网页主号"
                          : report.primarySource === "cli_and_desktop"
                          ? "桌面+CLI 同号"
                          : report.primarySource === "cli_stale"
                          ? "CLI 残留 · 凭据失效/跨号"
                          : "仅 CLI 账号"}
                      </span>
                    )}
                    {!report.plan.toLowerCase().includes("free") && (
                      <button
                        type="button"
                        data-testid="btn-sub-toggle"
                        className="audit-sub-toggle"
                        title="点击切换「已订阅天数」与「预计到期/续费日」"
                        onClick={() => setSubShowExpire((v) => !v)}
                      >
                        <span>
                          {subShowExpire
                            ? report.subscriptionRenewLabel
                            : report.subscriptionAgeDays != null
                            ? `订阅 ${report.subscriptionAgeDays} 天`
                            : "订阅时长未知"}
                        </span>
                        <span style={{ opacity: 0.55, fontSize: 10 }}>⇄</span>
                      </button>
                    )}
                    <span>{report.merchantChannel}</span>
                  </div>

                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 7,
                      fontSize: 11.5,
                      color: "var(--text-3)",
                      flexWrap: "wrap",
                    }}
                  >
                    <span>
                      组织{" "}
                      <span className="font-mono-code" style={{ color: "var(--text-2)" }}>
                        {report.orgIdPrefix8 ?? "未知"}
                      </span>
                    </span>
                    <span style={{ opacity: 0.55 }}>·</span>
                    <span
                      className={`audit-geo-pill ${report.workspaceGeo ? "is-verified" : ""}`}
                    >
                      {report.workspaceGeo ? `属地 ${report.workspaceGeo}` : "属地 待核"}
                    </span>
                    <span style={{ opacity: 0.55 }}>·</span>
                    <span>
                      注册 {report.accountAgeDays != null ? `${report.accountAgeDays} 天` : "未知"}
                    </span>
                    <span style={{ opacity: 0.55 }}>·</span>
                    <span>
                      本机{" "}
                      {report.localDeviceAgeDays != null
                        ? `${report.localDeviceAgeDays} 天`
                        : "未知"}
                    </span>
                  </div>
                </div>

                <div className="audit-profile-actions">
                  {needCloudPrompt ? (
                    <button
                      type="button"
                      data-testid="btn-cloud-prompt-pill"
                      className="audit-verify-age is-prompt tabular"
                      title="云端核验后可补全官方本体状态与归属地，评分更真实完整"
                      onClick={focusCloudVerifyInput}
                    >
                      <span className="audit-pulse-blue-dot" />
                      <span>
                        {!report.cloudVerified
                          ? "本地估上限85 · 补验云端更准 →"
                          : `${report.cloudAgeDays ?? 8}天前核验 · 重验更新更准 →`}
                      </span>
                    </button>
                  ) : (
                    <span className="audit-verify-age tabular">
                      刚刚同步{report.verifyCount > 1 ? ` (第 ${report.verifyCount} 次)` : ""}
                    </span>
                  )}

                  <button
                    type="button"
                    data-testid="btn-score-pill"
                    className={`audit-score-pill ${pillCls} tabular`}
                    title="点击查看账户风险评分明细与防封宝典权重依据"
                    onClick={() => setGuideOpen(true)}
                  >
                    {!report.cloudVerified
                      ? `${scoreResult.score} 分 · 本地估`
                      : `${scoreResult.score} 分 · ${scoreResult.levelLabel}`}
                  </button>

                  <button
                    type="button"
                    data-testid="btn-top-cloud-verify"
                    className={`guard-btn ${
                      needCloudPrompt ? "guard-btn-primary" : "guard-btn-flat"
                    } guard-btn-sm`}
                    onClick={focusCloudVerifyInput}
                  >
                    {!report.cloudVerified ? "云端核验" : "重验 sk"}
                  </button>
                </div>
              </div>

              {renderTopCloudStats(report)}

              {showKycExplain && (
                <div className="audit-kyc-explain" data-testid="kyc-explain-box">
                  <div>
                    <div>
                      <strong>官方警告与静默标</strong>
                      ：账号仍可正常对话，但后台已挂入观察队列或计费提示；接口若返回具体标记会直接译出，否则属黑盒观察标（常由跨区漂移、高频 429 或异常计费诱发）。
                    </div>
                    <div>
                      <strong>Persona 实名 KYC</strong>
                      ：第三方证件/人脸核验，常见于高敏区或升级/付费抽检；
                      <strong>通过并平稳度过 72h 后能显著提升账号抗误杀能力</strong>
                      ，与「无需验证」不同。
                    </div>
                    <div>
                      <strong>Portal 风控门户</strong>：<strong>风险极高！</strong>
                      代表 Anthropic 风控已主动挂起账号要求强制申诉；一旦触发，建议在彻底清洗本机环境前不要同机切换备用号。
                    </div>
                  </div>
                  <button
                    type="button"
                    className="audit-text-btn"
                    onClick={() => setShowKycExplain(false)}
                  >
                    收起
                  </button>
                </div>
              )}
            </div>

            {/* 一、需用户自行注意与克制 */}
            <div className="audit-part-block">
              <div className="audit-part-hd">
                <div className="audit-part-title">一、需用户自行注意与克制</div>
                <span className="audit-part-sub">事前监测预警，避免不当使用习惯触发风控</span>
              </div>
              <div className="guard-card">{renderGroupList(userGroups)}</div>
            </div>

            {/* 二、工具可介入防御与修复 */}
            <div className="audit-part-block">
              <div className="audit-part-hd">
                <div className="audit-part-title">二、工具可介入防御与修复</div>
                <span className="audit-part-sub">发现隐患可点开直接处理或联动修复</span>
              </div>
              <div className="guard-card">{renderGroupList(toolGroups)}</div>
            </div>
          </section>
        ) : (
          /* 右栏视图 B：实时异常日志流（403 精准消歧 + 完整实时取证日志控制台切换） */
          <section className="audit-detail-pane" data-testid="audit-logs-view">
            <div className="audit-log-banner">
              <span>
                <strong>7 类 403 精准消歧引擎：</strong>结合本机 {report.plan} 套餐自动区分「无害背景
                OAuth 403」「CF 入口盾」「断连回传 Cookie 403」与「官方实锤封号」。
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                <span className="guard-chip guard-chip-neutral tabular">
                  已自动降噪 {report.denoisedOauth403Count} 条
                </span>
                <button
                  type="button"
                  className="guard-btn guard-btn-flat guard-btn-xs"
                  onClick={() => setShowFullLogConsole((v) => !v)}
                >
                  {showFullLogConsole ? "返回消歧精简流" : "打开完整取证日志台"}
                </button>
              </div>
            </div>

            {showFullLogConsole ? (
              <div
                className="guard-card"
                style={{ flex: 1, minHeight: 480, display: "flex", flexDirection: "column" }}
              >
                <LogAnalysisPage />
              </div>
            ) : (
              <>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 12,
                    flexWrap: "wrap",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <button
                      type="button"
                      className={`audit-filter-pill ${logFilter === "all" ? "active" : ""}`}
                      onClick={() => setLogFilter("all")}
                    >
                      全部安全异常 ({nonDenoisedLogCount})
                    </button>
                    <button
                      type="button"
                      className={`audit-filter-pill ${logFilter === "403" ? "active" : ""}`}
                      onClick={() => setLogFilter("403")}
                    >
                      403 精准消歧 ({log403Count} + {report.denoisedOauth403Count}降噪)
                    </button>
                    <button
                      type="button"
                      className={`audit-filter-pill ${logFilter === "net" ? "active" : ""}`}
                      onClick={() => setLogFilter("net")}
                    >
                      代理断连 ({logNetCount})
                    </button>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                    <label
                      style={{
                        fontSize: 12,
                        color: "var(--text-2)",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 5,
                        cursor: "pointer",
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={showDenoised}
                        onChange={(e) => setShowDenoised(e.target.checked)}
                      />
                      显示已降噪的 OAuth 403 ({report.denoisedOauth403Count})
                    </label>
                    <button
                      type="button"
                      className="guard-btn guard-btn-flat guard-btn-sm"
                      onClick={() => {
                        const allIds = report.logFlowItems.map((i) => i.id);
                        useGuardStore.getState().ackAllLogIds(allIds);
                        pushToast("已全部标为已读", "未读角标已同步清零。", "ok");
                      }}
                    >
                      全部标为已读
                    </button>
                  </div>
                </div>

                <div className="guard-card">
                  {visibleFlowLogs.length === 0 ? (
                    <div
                      style={{
                        padding: 20,
                        fontSize: 12.5,
                        color: "var(--text-2)",
                        lineHeight: 1.6,
                      }}
                    >
                      当前筛选下暂无异常日志；如需查看全部原始运行事件或模拟测试，可点右上「打开完整取证日志台」。
                    </div>
                  ) : (
                    visibleFlowLogs.map((l) => {
                      const exp = expandedLogId === l.id;
                      const chipCls =
                        l.chipTone === "danger"
                          ? "guard-chip-fail"
                          : l.chipTone === "warn"
                          ? "guard-chip-warn"
                          : "guard-chip-neutral";
                      return (
                        <div
                          key={l.id}
                          className="audit-log-item"
                          onClick={() => setExpandedLogId(exp ? null : l.id)}
                        >
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "space-between",
                              gap: 12,
                            }}
                          >
                            <div
                              style={{
                                display: "flex",
                                alignItems: "center",
                                gap: 8,
                                fontSize: 13,
                                fontWeight: 500,
                              }}
                            >
                              <span className={`guard-chip ${chipCls}`}>{l.chipLabel}</span>
                              <span>{l.title}</span>
                            </div>
                            <span
                              className="font-mono-code tabular"
                              style={{ fontSize: 11, color: "var(--text-3)", flexShrink: 0 }}
                            >
                              {l.timeLabel}
                            </span>
                          </div>
                          <div
                            style={{
                              marginTop: 4,
                              fontSize: 12,
                              color: "var(--text-2)",
                              lineHeight: 1.5,
                            }}
                          >
                            {l.desc}
                          </div>
                          {exp && <div className="audit-log-raw">{l.rawSanitized}</div>}
                        </div>
                      );
                    })
                  )}
                </div>
              </>
            )}
          </section>
        )}
      </div>

      {/* 右侧滑出「防封宝典」白皮书级抽屉（零卡片套娃 + 底部折叠 100 分权重表） */}
      {guideOpen && (
        <div
          className="audit-drawer-backdrop"
          data-testid="anti-ban-guide-drawer"
          role="dialog"
          aria-modal="true"
          aria-label="防封宝典"
          onClick={(e) => {
            if (e.target === e.currentTarget) setGuideOpen(false);
          }}
        >
          <div className="audit-drawer-panel">
            <div className="audit-drawer-hd">
              <div
                style={{
                  fontSize: 15,
                  fontWeight: 600,
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                }}
              >
                <BookOpen size={16} strokeWidth={2} style={{ color: "var(--primary-hover)" }} />
                <span>防封宝典 · 风险权重与审计依据</span>
              </div>
              <button
                type="button"
                className="guard-btn guard-btn-flat guard-btn-xs"
                onClick={() => setGuideOpen(false)}
              >
                关闭
              </button>
            </div>

            <div className="audit-drawer-body">
              {/* 单层动态评分卡（零嵌套子卡片） */}
              <div className="audit-score-card tabular">
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 10,
                  }}
                >
                  <div>
                    <div style={{ fontSize: 11.5, color: "var(--text-3)" }}>
                      当前账户防御参考分（基准 100 · 非官方黑盒分）
                    </div>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "baseline",
                        gap: 8,
                        marginTop: 4,
                      }}
                    >
                      <span
                        style={{
                          fontSize: 24,
                          fontWeight: 700,
                          lineHeight: 1,
                          color: barColor,
                        }}
                      >
                        {scoreResult.score}
                      </span>
                      <span style={{ fontSize: 12, color: "var(--text-2)" }}>
                        / 100 · <strong>{scoreResult.levelLabel}</strong>
                      </span>
                    </div>
                  </div>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, flexShrink: 0 }}>
                    <span
                      className={`audit-score-pill ${pillCls}`}
                      style={{ cursor: "default" }}
                    >
                      {scoreResult.confidenceLabel}
                    </span>
                    <button
                      type="button"
                      className={`guard-btn ${
                        needCloudPrompt ? "guard-btn-primary" : "guard-btn-flat"
                      } guard-btn-xs`}
                      onClick={focusCloudVerifyInput}
                    >
                      {needCloudPrompt ? "立即云端核验 →" : "重验 sk"}
                    </button>
                  </div>
                </div>

                <div className="audit-score-track">
                  <div
                    className="audit-score-bar"
                    style={{ width: `${scoreResult.score}%`, background: barColor }}
                  />
                </div>

                {scoreResult.blindSpotNote && (
                  <div
                    style={{
                      fontSize: 11.5,
                      color: "var(--text-2)",
                      background: "rgba(0,111,238,0.08)",
                      border: "1px solid rgba(51,142,247,0.28)",
                      borderRadius: 7,
                      padding: "7px 9px",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 8,
                    }}
                  >
                    <span>{scoreResult.blindSpotNote}</span>
                    <button
                      type="button"
                      className="audit-text-btn"
                      onClick={focusCloudVerifyInput}
                    >
                      去核验 →
                    </button>
                  </div>
                )}

                <div className="audit-deduct-list">
                  {scoreResult.deductions.length > 0 ? (
                    scoreResult.deductions.map((d) => {
                      const col =
                        d.tone === "danger"
                          ? "var(--danger-bright)"
                          : d.tone === "warn"
                          ? "var(--warning)"
                          : d.tone === "ok"
                          ? "var(--success)"
                          : "var(--text-3)";
                      return (
                        <div key={d.id} className="audit-deduct-item">
                          <div style={{ minWidth: 0 }}>
                            <div
                              style={{
                                fontSize: 12.5,
                                fontWeight: 600,
                                color: "var(--text-1)",
                                lineHeight: 1.4,
                              }}
                            >
                              {d.title}
                            </div>
                            <div
                              style={{
                                fontSize: 11.5,
                                color: "var(--text-3)",
                                marginTop: 2,
                                lineHeight: 1.5,
                              }}
                            >
                              {d.desc}
                            </div>
                          </div>
                          <span
                            className="font-mono-code"
                            style={{
                              fontSize: 12,
                              fontWeight: 700,
                              color: col,
                              whiteSpace: "nowrap",
                              flexShrink: 0,
                            }}
                          >
                            {d.deltaLabel}
                          </span>
                        </div>
                      );
                    })
                  ) : (
                    <div className="audit-deduct-item">
                      <div>
                        <div
                          style={{
                            fontSize: 12.5,
                            fontWeight: 600,
                            color: "var(--text-1)",
                          }}
                        >
                          全部检查项均无扣分
                        </div>
                        <div style={{ fontSize: 11.5, color: "var(--text-3)", marginTop: 2 }}>
                          本地环境与云端状态均处于稳健区间
                        </div>
                      </div>
                      <span
                        className="font-mono-code"
                        style={{ color: "var(--success)", fontWeight: 700 }}
                      >
                        100
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* 正文：白皮书级防封知识流 */}
              <section className="audit-doc-section">
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    justifyContent: "space-between",
                    gap: 8,
                  }}
                >
                  <span style={{ fontSize: 14, fontWeight: 700, color: "var(--text-1)" }}>
                    一、最易触发封号的 4 大核心雷区
                  </span>
                  <span style={{ fontSize: 11.5, color: "var(--text-3)" }}>建议优先排查</span>
                </div>

                <div className="audit-doc-entry is-high">
                  <div className="audit-doc-title">
                    <span>1. 账号属地与出口 IP 错配、机房 IP 或高频换城</span>
                    <span className="audit-w-pill w-high">高危诱因</span>
                  </div>
                  <div className="audit-doc-body">
                    Anthropic 严格执行支持国家与地区政策。若账号注册属地（如美区）与当前代理出口跨洲错配（如连澳洲/日本节点），或使用已知商业
                    VPN、云机房 IP 段、对话中途频繁跳城市，极易触发自动风控。
                    <strong>建议长期锁死单一、稳定、与属地一致的原生住宅类节点。</strong>
                  </div>
                </div>

                <div className="audit-doc-entry is-high">
                  <div className="audit-doc-title">
                    <span>2. 虚拟 U 卡、共享代充与多号同机连坐</span>
                    <span className="audit-w-pill w-high">高危连坐</span>
                  </div>
                  <div className="audit-doc-body">
                    <ul className="audit-doc-bullets">
                      <li>
                        <strong>切勿复用封号卡：</strong>
                        曾给已封禁账号付过款的银行卡或虚拟 U 卡，绑到新号上极易秒触发审核甚至直接连坐封号。
                      </li>
                      <li>
                        <strong>警惕共享代充与高危 U 卡段：</strong>
                        低价代充常拿同一张卡给几十个号付款，或虚拟卡段被大面积滥用，同卡/同渠道只要有账号违规，其他正常号也容易被批量波及。
                      </li>
                      <li>
                        <strong>换号前彻底清理残留：</strong>
                        同机 CLI 与桌面端混登不同账号、或未清理旧封号目录与设备指纹（machineID/userID），容易牵连新号。换号建议按序：①
                        开防复活盯防强杀进程 → ② 备份清理桌面端与 CLI 残留 → ③ 核对设备指纹刷新 → ④
                        使用独立干净节点与未关联支付方式。
                      </li>
                    </ul>
                  </div>
                </div>

                <div className="audit-doc-entry is-high">
                  <div className="audit-doc-title">
                    <span>3. 消费级订阅接入第三方共享反代</span>
                    <span className="audit-w-pill w-high">官方红线</span>
                  </div>
                  <div className="audit-doc-body">
                    个人 Pro / Max 订阅若通过 <code>ANTHROPIC_BASE_URL</code>{" "}
                    走第三方共享反代中转池，会与大量陌生账号混用出口与请求特征，极易引发批量连坐。强烈建议消费级账号直连官方原生端点。
                  </div>
                </div>

                <div className="audit-doc-entry is-high">
                  <div className="audit-doc-title">
                    <span>4. 自动化脚本机刷与持续撞击 429 限流</span>
                    <span className="audit-w-pill w-high">官方红线</span>
                  </div>
                  <div className="audit-doc-body">
                    24×7 无人值守定时脚本、失控的子代理循环或持续压线高频触发 429
                    限流，容易被识别为非人工自动化滥用。建议保持常规人工交互节奏，留意定时任务与异常并发。
                  </div>
                </div>
              </section>

              <section className="audit-doc-section">
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    justifyContent: "space-between",
                    gap: 8,
                  }}
                >
                  <span style={{ fontSize: 14, fontWeight: 700, color: "var(--text-1)" }}>
                    二、3 个关键防翻车阶段与护航习惯
                  </span>
                  <span style={{ fontSize: 11.5, color: "var(--text-3)" }}>社区高频实战经验</span>
                </div>

                <div className="audit-doc-entry is-mid">
                  <div className="audit-doc-title">
                    <span>1. 守好 3 个高敏脆弱观察窗</span>
                    <span className="audit-w-pill w-mid">经验预警</span>
                  </div>
                  <div className="audit-doc-body">
                    <strong>新号注册不满 7 天</strong>、<strong>绑卡或升级套餐后 24 小时</strong>
                    、以及<strong>刚通过 KYC 或解封后的前 72 小时</strong>
                    ，风控容错率明显偏低。此期间倾向于锁死单一稳定节点并保持低频人工对话，避免大幅波动。
                  </div>
                </div>

                <div className="audit-doc-entry is-mid">
                  <div className="audit-doc-title">
                    <span>2. 升级 Max 或换卡时的「四码一致」建议</span>
                    <span className="audit-w-pill w-mid">付费避坑</span>
                  </div>
                  <div className="audit-doc-body">
                    升级高阶套餐或更换支付方式时较容易抽检触发实名核验。尽量保证
                    <strong>发卡行国家、账单区、代理出口 IP 与实名证件签发地</strong>
                    一致，有助于降低触发二次复审的概率。
                  </div>
                </div>

                <div className="audit-doc-entry is-mid">
                  <div className="audit-doc-title">
                    <span>3. 防止代理断连瞬间裸奔回传（Cookie 403）</span>
                    <span className="audit-w-pill w-mid">经验防护</span>
                  </div>
                  <div className="audit-doc-body">
                    Clash 断开或切换节点瞬间，后台残留的 Claude
                    进程发送退出清理请求可能直接暴露本地真实网络特征。切节点或重启代理前建议先开启「防复活盯防」。
                  </div>
                </div>
              </section>

              <section className="audit-doc-section">
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    justifyContent: "space-between",
                    gap: 8,
                  }}
                >
                  <span style={{ fontSize: 14, fontWeight: 700, color: "var(--text-1)" }}>
                    三、云端状态、403 报错与数据边界速查
                  </span>
                  <span style={{ fontSize: 11.5, color: "var(--text-3)" }}>看懂信号不误判</span>
                </div>

                <div className="audit-doc-entry is-info">
                  <div className="audit-doc-title">
                    <span>1. 读懂 3 个云端官方风控状态</span>
                  </div>
                  <div className="audit-doc-body">
                    <ul className="audit-doc-bullets">
                      <li>
                        <strong>Portal 风控门户（风险极高）：</strong>
                        代表账号已被风控主动挂起要求申诉；触发后切勿未清理环境就同机切备用号。
                      </li>
                      <li>
                        <strong>官方静默标（后台观察）：</strong>
                        还能正常对话，但后台已被贴上观察标记，常与跨区漂移、高频 429
                        或计费异常相关，需格外稳健使用。
                      </li>
                      <li>
                        <strong>Persona 实名 KYC（抗风控护城河）：</strong>
                        敏感区或付费抽检触发的证件核验；通过并平稳度过 72
                        小时后，抗误杀能力显著高于未验证账号。
                      </li>
                    </ul>
                  </div>
                </div>

                <div className="audit-doc-entry is-info">
                  <div className="audit-doc-title">
                    <span>2. 别把普通 403 当封号（4 类速辨）</span>
                  </div>
                  <div className="audit-doc-body">
                    <strong>CF 入口盾 403</strong> 是节点 IP 弹盾（换干净同区节点即可，非封号）；
                    <strong>背景 OAuth 403</strong> 是套餐权限边界（无害，工具已自动降噪）；
                    <strong>退出回传 Cookie 403</strong> 是断连漏 IP 前兆；只有命中{" "}
                    <strong>account_banned</strong> 才是官方实锤封号。
                  </div>
                </div>

                <div className="audit-doc-entry is-info">
                  <div className="audit-doc-title">
                    <span>3. 工具能查什么 / 不能查什么</span>
                  </div>
                  <div className="audit-doc-body">
                    可自动获取：<strong>出口 IP/地区</strong>（本地）、<strong>账户属地</strong>
                    （输 sk）、<strong>商户渠道</strong>（Stripe/Apple/Google）；受支付与隐私隔离保护，
                    <strong>银行卡/U 卡发卡国与 KYC 证件签发国绝不可由任何软件读取</strong>
                    ，需由你自行核对。
                  </div>
                </div>
              </section>

              {/* 底部默认折叠的 100 分权重表 */}
              <section className="audit-doc-section" style={{ paddingBottom: 6 }}>
                <button
                  type="button"
                  data-testid="btn-toggle-weight-table"
                  className="audit-weight-btn"
                  onClick={() => setWeightTableOpen((v) => !v)}
                >
                  <span>查看 100 分制评分权重明细（8 项总分 = 100 分）</span>
                  <span style={{ color: "var(--text-3)", fontSize: 12 }}>
                    {weightTableOpen ? "收起 ▴" : "展开 ▾"}
                  </span>
                </button>
                {weightTableOpen && (
                  <div className="audit-weight-table tabular" data-testid="weight-table-box">
                    <div className="audit-weight-row">
                      <span>归属地与出口 IP 一致性</span>
                      <span className="audit-w-pill w-high">占 24 分</span>
                    </div>
                    <div className="audit-weight-row">
                      <span>官方 API 端点纯净度（防反代）</span>
                      <span className="audit-w-pill w-high">占 16 分</span>
                    </div>
                    <div className="audit-weight-row">
                      <span>多号隔离与设备指纹防连坐</span>
                      <span className="audit-w-pill w-high">占 16 分</span>
                    </div>
                    <div className="audit-weight-row">
                      <span>官方警告与静默监控标（封号/Portal 熔断 ≤15）</span>
                      <span className="audit-w-pill w-high">占 12 分</span>
                    </div>
                    <div className="audit-weight-row">
                      <span>高敏观察窗（新号 / 支付 / 过 KYC）</span>
                      <span className="audit-w-pill w-mid">占 10 分</span>
                    </div>
                    <div className="audit-weight-row">
                      <span>人机节律与 429 并发安全</span>
                      <span className="audit-w-pill w-mid">占 10 分</span>
                    </div>
                    <div className="audit-weight-row">
                      <span>Clash 断连回传 Cookie 403 防护</span>
                      <span className="audit-w-pill w-mid">占 8 分</span>
                    </div>
                    <div className="audit-weight-row">
                      <span>本机隐私遥测与待传缓存</span>
                      <span className="audit-w-pill w-low">占 4 分</span>
                    </div>
                    <div className="audit-weight-row">
                      <span>Persona 实名护城河（过 72h 额外缓冲，封顶 100）</span>
                      <span className="audit-w-pill w-ok">额外 +5 分</span>
                    </div>
                  </div>
                )}
              </section>

              <div
                style={{
                  fontSize: 11,
                  color: "var(--text-3)",
                  lineHeight: 1.55,
                  padding: "4px 2px",
                }}
              >
                免责与客观声明：本工具的「安全评分」是基于公开政策、本机实测特征与社区高频样本构建的
                <strong>启发式防御参考分</strong>
                ，绝不等同于 Anthropic 内部黑盒风控分；高分不承诺永不封号，低分仅代表存在较多已知可优化隐患。
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
