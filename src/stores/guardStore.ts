import { create } from "zustand";
import {
  DEFAULT_CONFIG,
  FALLBACK_PREFLIGHT,
  FALLBACK_SNAPSHOT,
  FALLBACK_STARTUP_AUDIT,
  ipc,
} from "@/lib/ipc";
import type {
  AccountAuditReport,
  AppConfig,
  AppConfigPatch,
  AppUpdateInfo,
  AuditSubTab,
  BackupInfo,
  DeepAuditProgress,
  GuardSnapshot,
  NavTab,
  NodeReport,
  PreflightReport,
  RiskModalState,
  StartupAuditReport,
  ToastAction,
  ToastMessage,
} from "@/types/guard";

const IDLE_DEEP_AUDIT: DeepAuditProgress = {
  running: false,
  phase: "idle",
  currentIndex: 0,
  total: 0,
  currentNode: "",
  originalNode: "",
  currentNodeVerified: false,
  message: "",
};

const EMPTY_NODES: NodeReport = {
  connected: false,
  endpoint: "待探测",
  groupName: "Claude-Fixed",
  currentNode: "未连接",
  totalRawNodes: 0,
  filteredBlockedCount: 0,
  nodes: [],
};

export interface CleanModalState {
  open: boolean;
  sourceLabel?: string;
  onCompleted?: (info: BackupInfo, selectedCategories: string[]) => void | Promise<void>;
}

interface GuardStore {
  config: AppConfig;
  snapshot: GuardSnapshot;
  preflight: PreflightReport;
  startupAudit: StartupAuditReport;
  nodeReport: NodeReport;
  deepAudit: DeepAuditProgress;
  supportModalOpen: boolean;
  checking: boolean;
  fixing: boolean;
  fixingItemId: string | null;
  launching: boolean;
  exitingClaude: boolean;
  switchingNodeName: string | null;
  activeTab: NavTab;
  auditSubTab: AuditSubTab;
  nodesSubTab: "quality" | "traffic";
  accountAudit: AccountAuditReport | null;
  accountAuditLoading: boolean;
  accountAuditError: string | null;
  selectedCheckId: string;
  playbookOpen: boolean;
  playbookFocusId: string | null;
  playbookFocusSeq: number;
  ackedLogIds: string[];
  ackedFlowIds: string[];
  toasts: ToastMessage[];
  riskModal: RiskModalState | null;
  cleanModal: CleanModalState | null;
  updateInfo: AppUpdateInfo | null;
  updateChecking: boolean;
  updateInstalling: boolean;
  updateProgress: {
    stage: string;
    downloadedBytes: number;
    totalBytes?: number | null;
    percent?: number | null;
  } | null;
  updateError: string | null;
  initialized: boolean;

  bootstrap: () => Promise<void>;
  refreshPreflight: (silent?: boolean) => Promise<void>;
  fixPreflightItem: (itemId: string) => Promise<void>;
  oneClickFixAll: () => Promise<void>;
  safeLaunchClaude: () => Promise<void>;
  safeExitClaude: () => Promise<void>;
  refreshNodes: (force?: boolean) => Promise<boolean>;
  startDeepNodeAudit: (forceAll?: boolean, targetNode?: string) => Promise<void>;
  cancelDeepNodeAudit: () => Promise<void>;
  setDeepAuditFromEvent: (progress: DeepAuditProgress) => void;
  switchNode: (name: string, forceIgnoreRisk?: boolean) => Promise<void>;
  updateConfig: (patch: AppConfigPatch, toastLabel?: string) => Promise<void>;
  setActiveTab: (tab: NavTab) => void;
  setAuditSubTab: (sub: AuditSubTab) => void;
  setNodesSubTab: (sub: "quality" | "traffic") => void;
  refreshAccountAudit: (silent?: boolean) => Promise<void>;
  setAccountAudit: (report: AccountAuditReport) => void;
  setSelectedCheckId: (id: string) => void;
  focusFirstUnhealthyCheck: () => void;
  setPlaybookOpen: (open: boolean) => void;
  openPlaybookFocus: (ruleId: string) => void;
  ackLogId: (id: string) => Promise<boolean>;
  ackLogIds: (ids: string[]) => Promise<boolean>;
  ackAllLogIds: (ids: string[]) => Promise<boolean>;
  ackAllFlowIds: (ids: string[]) => Promise<boolean>;
  pushToast: (
    title: string,
    body: string,
    type?: ToastMessage["type"],
    options?: { badge?: string; action?: ToastAction; durationMs?: number }
  ) => void;
  dismissToast: (id: string) => void;
  openRiskModal: (modal: Omit<RiskModalState, "open">) => void;
  closeRiskModal: () => void;
  openCleanModal: (modal?: Omit<CleanModalState, "open">) => void;
  closeCleanModal: () => void;
  setSnapshot: (snap: GuardSnapshot) => void;
  setPreflightFromEvent: (report: PreflightReport) => void;
  setConfigFromEvent: (cfg: AppConfig) => void;
  setSupportModalOpen: (open: boolean) => void;
  checkForAppUpdate: (silent?: boolean) => Promise<AppUpdateInfo | null>;
  installAppUpdate: () => Promise<void>;
  setUpdateProgress: (
    progress: {
      stage: string;
      downloadedBytes: number;
      totalBytes?: number | null;
      percent?: number | null;
    } | null
  ) => void;
}

function applyThemeToDom(theme: "dark" | "light") {
  if (typeof document !== "undefined") {
    document.documentElement.setAttribute("data-theme", theme);
  }
}

// Toast 定时器注册表：支持手动关闭或挤压淘汰时及时 clearTimeout，彻底避免泄漏
const toastTimers = new Map<string, ReturnType<typeof setTimeout>>();
// 深度核验进度触发的节点列表刷新合并防抖（400ms 单飞），避免高频连续 IPC
let deepAuditNodesRefreshTimer: ReturnType<typeof setTimeout> | null = null;
let nodesRefreshInFlight = false;
// 请求代际序号：防止慢响应乱序覆盖新状态
let preflightReqSeq = 0;
let nodesReqSeq = 0;
let ackLogReqSeq = 0;
let accountAuditReqSeq = 0;
let configReqSeq = 0;
// 深度核验事件版本号：防止 invoke 返回值晚于事件终态倒灌 running:true 永锁主按钮
let deepAuditEventSeq = 0;

export const useGuardStore = create<GuardStore>((set, get) => ({
  config: DEFAULT_CONFIG,
  snapshot: FALLBACK_SNAPSHOT,
  preflight: FALLBACK_PREFLIGHT,
  startupAudit: FALLBACK_STARTUP_AUDIT,
  nodeReport: EMPTY_NODES,
  deepAudit: IDLE_DEEP_AUDIT,
  supportModalOpen: false,
  checking: false,
  fixing: false,
  fixingItemId: null,
  launching: false,
  exitingClaude: false,
  switchingNodeName: null,
  activeTab: "console",
  auditSubTab: "audit",
  nodesSubTab: "quality",
  accountAudit: null,
  accountAuditLoading: false,
  accountAuditError: null,
  selectedCheckId: "node_proxy",
  playbookOpen: false,
  playbookFocusId: null,
  playbookFocusSeq: 0,
  ackedLogIds: [],
  ackedFlowIds: [],
  toasts: [],
  riskModal: null,
  cleanModal: null,
  updateInfo: null,
  updateChecking: false,
  updateInstalling: false,
  updateProgress: null,
  updateError: null,
  initialized: false,

  async bootstrap() {
    const seqPre = ++preflightReqSeq;
    const seqNode = ++nodesReqSeq;
    const seqAudit = ++accountAuditReqSeq;
    const seqCfg = ++configReqSeq;
    const beforeAuditEvSeq = deepAuditEventSeq;
    set({ checking: true });
    try {
      let auditErr: string | null = null;
      const [config, preflight, startupAudit, nodeReport, deepAudit, accountAudit] =
        await Promise.all([
          ipc.getConfig(),
          ipc.runPreflightChecks(false),
          ipc.auditStartupItems(),
          ipc.getNodesAndQuality(),
          ipc.getDeepAuditStatus(),
          ipc.auditAccountLocal().catch((e) => {
            auditErr = String(e);
            return null;
          }),
        ]);
      const snapshot = await ipc.getSnapshot();
      applyThemeToDom(config.theme);
      const firstFail =
        preflight.items.find((x) => x.part === "must" && x.status !== "ok") ??
        preflight.items[0];
      set((state) => ({
        config: seqCfg === configReqSeq ? config : state.config,
        snapshot,
        preflight: seqPre === preflightReqSeq ? preflight : state.preflight,
        startupAudit,
        nodeReport: seqNode === nodesReqSeq ? nodeReport : state.nodeReport,
        deepAudit:
          deepAuditEventSeq === beforeAuditEvSeq ? deepAudit : state.deepAudit,
        accountAudit: seqAudit === accountAuditReqSeq ? accountAudit : state.accountAudit,
        accountAuditError: seqAudit === accountAuditReqSeq ? auditErr : state.accountAuditError,
        ackedLogIds: Array.isArray(config.ackedLogIds) ? config.ackedLogIds : [],
        selectedCheckId: firstFail?.id ?? "node_proxy",
        initialized: true,
        checking: false,
      }));
    } catch (err) {
      set({ checking: false, initialized: true });
      get().pushToast("初始化探测失败", String(err), "danger");
    }
  },

  async refreshPreflight(silent = false) {
    const seq = ++preflightReqSeq;
    set({ checking: true });
    try {
      const [preflight, startupAudit, nodeReport] = await Promise.all([
        ipc.runPreflightChecks(true),
        ipc.auditStartupItems(),
        ipc.getNodesAndQuality(),
      ]);
      const snapshot = await ipc.getSnapshot();
      if (seq !== preflightReqSeq) return;
      set({ preflight, snapshot, startupAudit, nodeReport, checking: false });
      if (!silent) {
        get().pushToast(
          "已重跑全部真实探针",
          `必须项通过 ${snapshot.mustPassed}/${snapshot.mustTotal}，建议项通过 ${snapshot.optPassed}/${snapshot.optTotal}，15 分钟自动巡检已重置。`,
          snapshot.mustPassed === snapshot.mustTotal ? "ok" : "info"
        );
      }
    } catch (err) {
      if (seq === preflightReqSeq) {
        set({ checking: false });
      }
      get().pushToast("重新实测失败", String(err), "danger");
    }
  },

  async fixPreflightItem(itemId) {
    if (get().fixing) return;
    const seqPre = ++preflightReqSeq;
    const seqNode = ++nodesReqSeq;
    set({ fixing: true, fixingItemId: itemId });
    try {
      const res = await ipc.fixPreflightItem(itemId);
      const [startupAudit, nodeReport] = await Promise.all([
        ipc.auditStartupItems(),
        ipc.getNodesAndQuality(),
      ]);
      set((state) => ({
        preflight: seqPre === preflightReqSeq ? res.report : state.preflight,
        snapshot: res.snapshot,
        startupAudit,
        nodeReport: seqNode === nodesReqSeq ? nodeReport : state.nodeReport,
        fixing: false,
        fixingItemId: null,
      }));
      get().pushToast(
        res.success && !res.requiresManualStep
          ? "已自动修复并实测通过"
          : "需要你手动完成操作",
        res.message,
        res.success && !res.requiresManualStep ? "ok" : "info"
      );
    } catch (err) {
      set({ fixing: false, fixingItemId: null });
      get().pushToast("单项修复失败", String(err), "danger");
    }
  },

  async oneClickFixAll() {
    if (get().fixing) return;
    const seqPre = ++preflightReqSeq;
    const seqNode = ++nodesReqSeq;
    set({ fixing: true, fixingItemId: "__all__" });
    try {
      const res = await ipc.oneClickFixAll();
      const [startupAudit, nodeReport] = await Promise.all([
        ipc.auditStartupItems(),
        ipc.getNodesAndQuality(),
      ]);
      set((state) => ({
        preflight: seqPre === preflightReqSeq ? res.report : state.preflight,
        snapshot: res.snapshot,
        startupAudit,
        nodeReport: seqNode === nodesReqSeq ? nodeReport : state.nodeReport,
        selectedCheckId: res.skippedManualId ?? state.selectedCheckId,
        fixing: false,
        fixingItemId: null,
      }));
      get().pushToast(
        res.skippedManualId ? "已完成可自动修复项，请配合处理剩余项" : "全部必须项已处理完毕",
        res.summary,
        res.skippedManualId ? "info" : "ok"
      );
    } catch (err) {
      set({ fixing: false, fixingItemId: null });
      get().pushToast("一键处理失败", String(err), "danger");
    }
  },

  async safeLaunchClaude() {
    set({ launching: true });
    try {
      const msg = await ipc.safeLaunchClaude();
      get().pushToast("安全启动 Claude", msg, "ok");
    } catch (err) {
      get().pushToast("启动门禁拦截", String(err), "danger");
      void get().refreshPreflight(true);
    } finally {
      set({ launching: false });
    }
  },

  async safeExitClaude() {
    set({ exitingClaude: true });
    try {
      const rep = await ipc.killClaudeProcesses(true);
      get().pushToast("已安全退出 Claude", rep.message, "ok");
      void get().refreshPreflight(true);
    } catch (err) {
      get().pushToast("退出 Claude 失败", String(err), "danger");
    } finally {
      set({ exitingClaude: false });
    }
  },

  async refreshNodes(force = false) {
    const seq = ++nodesReqSeq;
    try {
      const nodeReport = await ipc.getNodesAndQuality(force);
      if (seq !== nodesReqSeq) return true;
      set({ nodeReport });
      return true;
    } catch (err) {
      get().pushToast("刷新节点列表失败", String(err), "danger");
      return false;
    }
  },

  async startDeepNodeAudit(forceAll = false, targetNode?: string) {
    const beforeSeq = deepAuditEventSeq;
    try {
      const progress = await ipc.startDeepNodeAudit(forceAll, targetNode);
      // BUG-P0-15：若期间已收到后端推送的更新事件（尤其是 done/cancelled 终态），绝不拿滞后的 invoke 返回值把 running 覆写回 true
      if (deepAuditEventSeq === beforeSeq) {
        set({ deepAudit: progress });
      }
      if (!progress.running && progress.message) {
        get().pushToast("节点深度核验", progress.message, progress.phase === "blocked" ? "danger" : "info");
      }
    } catch (err) {
      get().pushToast("无法启动节点深度核验", String(err), "danger");
    }
  },

  async cancelDeepNodeAudit() {
    const beforeSeq = deepAuditEventSeq;
    try {
      const progress = await ipc.cancelDeepNodeAudit();
      if (deepAuditEventSeq === beforeSeq) {
        set({ deepAudit: progress });
      }
      get().pushToast("已停止深度核验", progress.message || "正在恢复原锁定节点...", "info");
    } catch (err) {
      get().pushToast("停止深度核验失败", String(err), "danger");
    }
  },

  setDeepAuditFromEvent(progress) {
    deepAuditEventSeq += 1;
    const prev = get().deepAudit;
    set({ deepAudit: progress });
    const finishedNow = !progress.running && prev.running;
    if (finishedNow) {
      if (deepAuditNodesRefreshTimer) {
        clearTimeout(deepAuditNodesRefreshTimer);
        deepAuditNodesRefreshTimer = null;
      }
      void get().refreshNodes(false);
    } else if (progress.message.startsWith("已核验")) {
      // 合并高频翻牌刷新：400ms 防抖且单飞，杜绝并行堆积
      if (!deepAuditNodesRefreshTimer && !nodesRefreshInFlight) {
        deepAuditNodesRefreshTimer = setTimeout(() => {
          deepAuditNodesRefreshTimer = null;
          if (!nodesRefreshInFlight) {
            nodesRefreshInFlight = true;
            void get()
              .refreshNodes(false)
              .finally(() => {
                nodesRefreshInFlight = false;
              });
          }
        }, 400);
      }
    }
    if (finishedNow && progress.message) {
      get().pushToast(
        progress.phase === "cancelled" ? "深度核验已停止" : "节点深度核验完成",
        progress.message,
        progress.phase === "cancelled" ? "info" : "ok"
      );
    }
  },

  async switchNode(name, forceIgnoreRisk = false) {
    if (get().fixing) return;
    const seqPre = ++preflightReqSeq;
    const seqNode = ++nodesReqSeq;
    set({ fixing: true, switchingNodeName: name });
    try {
      const res = await ipc.switchLockedNode(name, forceIgnoreRisk);
      const nodeReport = await ipc.getNodesAndQuality();
      set((state) => ({
        preflight: seqPre === preflightReqSeq ? res.report : state.preflight,
        snapshot: res.snapshot,
        nodeReport: seqNode === nodesReqSeq ? nodeReport : state.nodeReport,
        fixing: false,
        switchingNodeName: null,
      }));
      get().pushToast("已切换锁定节点", res.message, "ok");
      // 切换锁定节点后同步静默刷新账户审计，让出口地区与跨洲一致性立即联动更新
      void get().refreshAccountAudit(true);
    } catch (err) {
      set({ fixing: false, switchingNodeName: null });
      get().pushToast("切换节点被拦截或失败", String(err), "danger");
    }
  },

  async updateConfig(patch, toastLabel) {
    const seq = ++configReqSeq;
    try {
      const updated = await ipc.updateConfig(patch);
      if (seq !== configReqSeq) return;
      applyThemeToDom(updated.theme);
      // 仅修改自启相关配置时才重新扫描开机启动项，改主题/静音/遥测等不再无谓扫注册表
      const needsStartupReaudit =
        patch.bootStart !== undefined || patch.bootHudOnly !== undefined;
      const startupAudit = needsStartupReaudit
        ? await ipc.auditStartupItems().catch(() => get().startupAudit)
        : get().startupAudit;
      if (seq !== configReqSeq) return;
      set((state) => {
        const ids = new Set(state.snapshot.triggeredPlaybookIds);
        if (updated.calm24h) ids.add("pb_24h");
        else ids.delete("pb_24h");
        return {
          config: updated,
          startupAudit,
          snapshot: {
            ...state.snapshot,
            triggeredPlaybookIds: Array.from(ids),
          },
        };
      });

      if (toastLabel) {
        const enabled = Object.values(patch)[0];
        const isBool = typeof enabled === "boolean";
        const suffix = isBool ? (enabled ? "已开启" : "已关闭") : "已更新";
        const detail =
          patch.bootHudOnly === true
            ? "下次开机将只显示桌面悬浮状态卡，不弹出主控制台。"
            : patch.notifyEnabled === false
            ? "已静音普通预警；熔断与防裸奔等危急警报仍保持强制提醒。"
            : "配置策略已实时保存。";
        get().pushToast(`${toastLabel}${suffix}`, detail, enabled === false ? "info" : "ok");
      }
    } catch (err) {
      get().pushToast("保存配置失败", String(err), "danger");
    }
  },

  setActiveTab(tab) {
    if (tab === "logs") {
      set({ activeTab: "audit", auditSubTab: "logs" });
      void get().refreshAccountAudit(true);
      return;
    }
    set({ activeTab: tab });
    if (tab === "nodes") {
      void get().refreshNodes();
    } else if (tab === "audit") {
      void get().refreshAccountAudit(true);
    }
  },

  setAuditSubTab(sub) {
    set({ auditSubTab: sub });
  },

  async refreshAccountAudit(silent = false) {
    const seq = ++accountAuditReqSeq;
    set({ accountAuditLoading: true, accountAuditError: null });
    try {
      const report = await ipc.auditAccountLocal();
      if (seq !== accountAuditReqSeq) return;
      set({ accountAudit: report, accountAuditLoading: false, accountAuditError: null });
      if (!silent) {
        get().pushToast(
          "本地只读审计已刷新",
          "已重扫 ~/.claude.json、备份残留、settings.json、离线行为与桌面端日志。",
          "ok"
        );
      }
    } catch (err) {
      if (seq !== accountAuditReqSeq) return;
      const msg = String(err);
      set({ accountAuditLoading: false, accountAuditError: msg });
      if (!silent) {
        get().pushToast("账户审计刷新失败", msg, "danger");
      }
    }
  },

  setAccountAudit(report) {
    accountAuditReqSeq += 1;
    set({ accountAudit: report, accountAuditError: null });
  },

  setNodesSubTab(sub) {
    set({ nodesSubTab: sub });
  },

  setSelectedCheckId(id) {
    set({ selectedCheckId: id });
  },

  focusFirstUnhealthyCheck() {
    const items = get().preflight.items;
    const first =
      items.find((x) => x.part === "must" && x.status !== "ok") ??
      items.find((x) => x.status !== "ok") ??
      items[0];
    if (first) {
      set({ activeTab: "console", selectedCheckId: first.id });
    }
  },

  setPlaybookOpen(open) {
    set({ playbookOpen: open });
  },

  openPlaybookFocus(ruleId) {
    set((state) => ({
      playbookOpen: true,
      playbookFocusId: ruleId,
      playbookFocusSeq: state.playbookFocusSeq + 1,
    }));
  },

  async ackLogId(id) {
    return get().ackLogIds([id]);
  },

  async ackLogIds(ids) {
    const uniq = Array.from(new Set(ids.filter(Boolean)));
    if (uniq.length === 0) return true;
    const seq = ++ackLogReqSeq;
    const prevAcked = get().ackedLogIds;
    set((state) => ({
      ackedLogIds: Array.from(new Set([...state.ackedLogIds, ...uniq])),
    }));
    try {
      const snap = await ipc.ackLogEvents(uniq);
      if (seq === ackLogReqSeq) {
        set({ snapshot: snap });
      }
      return true;
    } catch (err) {
      if (seq === ackLogReqSeq) {
        set({ ackedLogIds: prevAcked });
      }
      get().pushToast("同步已读游标失败", String(err), "danger");
      return false;
    }
  },

  async ackAllLogIds(ids) {
    const uniq = Array.from(new Set(ids.filter(Boolean)));
    const seq = ++ackLogReqSeq;
    const prevAcked = get().ackedLogIds;
    const prevSnap = get().snapshot;
    set((state) => ({
      ackedLogIds: Array.from(new Set([...state.ackedLogIds, ...uniq])),
      snapshot: {
        ...state.snapshot,
        unreadLogAnomalies: 0,
        unreadLogCritical: 0,
        unreadLogWarnings: 0,
      },
    }));
    // 统一走后端 ack_all_log_events，将 watchdog 真实未读事件及折叠子 ID 一次性持久化标为已读并广播归零快照
    try {
      const snap = await ipc.ackAllLogEvents();
      if (seq === ackLogReqSeq) {
        set({ snapshot: snap });
      }
      return true;
    } catch (err) {
      if (seq === ackLogReqSeq) {
        set({ ackedLogIds: prevAcked, snapshot: prevSnap });
      }
      get().pushToast("同步全部已读失败", String(err), "danger");
      return false;
    }
  },

  async ackAllFlowIds(ids) {
    const uniq = Array.from(new Set(ids.filter(Boolean)));
    const prevAcked = get().ackedFlowIds;
    const prevSnap = get().snapshot;
    set((state) => ({
      ackedFlowIds: Array.from(new Set([...state.ackedFlowIds, ...uniq])),
    }));
    try {
      const snap = await ipc.ackFlowAnomalies(uniq);
      set({ snapshot: snap });
      return true;
    } catch (err) {
      set({ ackedFlowIds: prevAcked, snapshot: prevSnap });
      get().pushToast("同步流量已处理状态失败", String(err), "danger");
      return false;
    }
  },

  pushToast(title, body, type = "info", options) {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    set((state) => {
      const dropped = state.toasts.length >= 4 ? state.toasts.slice(0, state.toasts.length - 3) : [];
      for (const d of dropped) {
        const tm = toastTimers.get(d.id);
        if (tm) {
          clearTimeout(tm);
          toastTimers.delete(d.id);
        }
      }
      return {
        toasts: [
          ...state.toasts.slice(-3),
          { id, title, body, type, badge: options?.badge, action: options?.action },
        ],
      };
    });
    const timer = setTimeout(() => {
      toastTimers.delete(id);
      get().dismissToast(id);
    }, options?.durationMs ?? 4800);
    toastTimers.set(id, timer);
  },

  dismissToast(id) {
    const tm = toastTimers.get(id);
    if (tm) {
      clearTimeout(tm);
      toastTimers.delete(id);
    }
    set((state) => ({
      toasts: state.toasts.filter((t) => t.id !== id),
    }));
  },

  openRiskModal(modal) {
    set({ riskModal: { ...modal, open: true } });
  },

  closeRiskModal() {
    set({ riskModal: null });
  },

  openCleanModal(modal) {
    set({ cleanModal: { ...(modal ?? {}), open: true } });
  },

  closeCleanModal() {
    set({ cleanModal: null });
  },

  setSnapshot(snap) {
    set({ snapshot: snap });
  },

  setPreflightFromEvent(report) {
    const prevGeo = get().preflight.items.find((x) => x.id === "node_geo");
    const nextGeo = report.items.find((x) => x.id === "node_geo");
    const geoChanged =
      prevGeo?.status !== nextGeo?.status || prevGeo?.summary !== nextGeo?.summary;
    set({ preflight: report });
    // 后台 15 分钟全量巡检或节点事件触发出口状态变更时，同步静默刷新节点表，保证控制台与节点流量页同源
    if (get().initialized && (geoChanged || get().activeTab === "nodes")) {
      void ipc
        .getNodesAndQuality(false)
        .then((nodeReport) => set({ nodeReport }))
        .catch(() => {});
    }
  },

  setConfigFromEvent(cfg) {
    applyThemeToDom(cfg.theme);
    set({ config: cfg });
  },

  setSupportModalOpen(open) {
    set({ supportModalOpen: open });
  },

  async checkForAppUpdate(silent = false) {
    if (get().updateChecking || get().updateInstalling) return get().updateInfo;
    set({ updateChecking: true, updateError: null });
    try {
      const info = await ipc.checkAppUpdate();
      set({ updateInfo: info });
      if (!silent) {
        get().pushToast(
          info.available ? `发现新版本 v${info.latestVersion ?? ""}` : "当前已是最新版本",
          info.message,
          info.available ? "info" : "ok"
        );
      } else if (info.available && info.latestVersion) {
        get().pushToast(
          `发现新版本 v${info.latestVersion}`,
          "已通过 GitHub Releases 官方更新通道检测到新版本，可点击顶栏更新标签或前往「守卫配置」一键验签升级。",
          "info",
          {
            durationMs: 7000,
            action: {
              label: "前往更新",
              onClick: () => get().setActiveTab("config"),
            },
          }
        );
      }
      return info;
    } catch (err) {
      const msg = String(err);
      if (!silent) {
        set({ updateError: msg });
        get().pushToast("检查更新失败", msg, "danger");
      }
      return null;
    } finally {
      set({ updateChecking: false });
    }
  },

  setUpdateProgress(progress) {
    set({ updateProgress: progress });
  },

  async installAppUpdate() {
    if (get().updateInstalling) return;
    set({ updateInstalling: true, updateProgress: null, updateError: null });
    try {
      const msg = await ipc.installAppUpdate();
      get().pushToast("更新包校验通过", msg, "ok");
    } catch (err) {
      const msg = String(err);
      set({ updateError: msg });
      get().pushToast("自动更新安装失败", msg, "danger");
    } finally {
      set({ updateInstalling: false, updateProgress: null });
    }
  },
}));
