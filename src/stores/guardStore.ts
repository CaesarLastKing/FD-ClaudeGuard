import { create } from "zustand";
import {
  DEFAULT_CONFIG,
  FALLBACK_PREFLIGHT,
  FALLBACK_SNAPSHOT,
  FALLBACK_STARTUP_AUDIT,
  ipc,
  isTauriRuntime,
} from "@/lib/ipc";
import type {
  AppConfig,
  AppConfigPatch,
  BackupInfo,
  DeepAuditProgress,
  GuardSnapshot,
  LicenseStatus,
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

const DEFAULT_LICENSE_STATUS: LicenseStatus = {
  commercialFeatureEnabled: true,
  // 真实 Tauri 商业版客户端严格 Fail-Closed（等待后端离线验签返回后再解锁）；浏览器预览保留可读体验
  licensed: !isTauriRuntime(),
  activatedAt: null,
  batchId: null,
  installIdShort: null,
  machineFpShort: null,
  apiEndpoint: null,
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
  licenseStatus: LicenseStatus;
  licenseModalOpen: boolean;
  supportModalOpen: boolean;
  checking: boolean;
  fixing: boolean;
  fixingItemId: string | null;
  launching: boolean;
  exitingClaude: boolean;
  switchingNodeName: string | null;
  activeTab: NavTab;
  nodesSubTab: "quality" | "traffic";
  selectedCheckId: string;
  playbookOpen: boolean;
  playbookFocusId: string | null;
  playbookFocusSeq: number;
  ackedLogIds: string[];
  ackedFlowIds: string[];
  toasts: ToastMessage[];
  riskModal: RiskModalState | null;
  cleanModal: CleanModalState | null;
  initialized: boolean;

  bootstrap: () => Promise<void>;
  refreshPreflight: (silent?: boolean) => Promise<void>;
  fixPreflightItem: (itemId: string) => Promise<void>;
  oneClickFixAll: () => Promise<void>;
  safeLaunchClaude: () => Promise<void>;
  safeExitClaude: () => Promise<void>;
  refreshNodes: (force?: boolean) => Promise<void>;
  startDeepNodeAudit: (forceAll?: boolean, targetNode?: string) => Promise<void>;
  cancelDeepNodeAudit: () => Promise<void>;
  setDeepAuditFromEvent: (progress: DeepAuditProgress) => void;
  switchNode: (name: string, forceIgnoreRisk?: boolean) => Promise<void>;
  updateConfig: (patch: AppConfigPatch, toastLabel?: string) => Promise<void>;
  setActiveTab: (tab: NavTab) => void;
  setNodesSubTab: (sub: "quality" | "traffic") => void;
  setSelectedCheckId: (id: string) => void;
  focusFirstUnhealthyCheck: () => void;
  setPlaybookOpen: (open: boolean) => void;
  openPlaybookFocus: (ruleId: string) => void;
  ackLogId: (id: string) => void;
  ackLogIds: (ids: string[]) => void;
  ackAllLogIds: (ids: string[]) => void;
  ackAllFlowIds: (ids: string[]) => void;
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
  setLicenseStatus: (status: LicenseStatus) => void;
  setLicenseModalOpen: (open: boolean) => void;
  setSupportModalOpen: (open: boolean) => void;
  activateLicense: (licenseKey: string) => Promise<void>;
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

export const useGuardStore = create<GuardStore>((set, get) => ({
  config: DEFAULT_CONFIG,
  snapshot: FALLBACK_SNAPSHOT,
  preflight: FALLBACK_PREFLIGHT,
  startupAudit: FALLBACK_STARTUP_AUDIT,
  nodeReport: EMPTY_NODES,
  deepAudit: IDLE_DEEP_AUDIT,
  licenseStatus: DEFAULT_LICENSE_STATUS,
  licenseModalOpen: false,
  supportModalOpen: false,
  checking: false,
  fixing: false,
  fixingItemId: null,
  launching: false,
  exitingClaude: false,
  switchingNodeName: null,
  activeTab: "console",
  nodesSubTab: "quality",
  selectedCheckId: "node_proxy",
  playbookOpen: false,
  playbookFocusId: null,
  playbookFocusSeq: 0,
  ackedLogIds: [],
  ackedFlowIds: [],
  toasts: [],
  riskModal: null,
  cleanModal: null,
  initialized: false,

  async bootstrap() {
    set({ checking: true });
    try {
      const [config, preflight, startupAudit, nodeReport, licenseStatus, deepAudit] =
        await Promise.all([
          ipc.getConfig(),
          ipc.runPreflightChecks(false),
          ipc.auditStartupItems(),
          ipc.getNodesAndQuality(),
          ipc.getLicenseStatus(),
          ipc.getDeepAuditStatus(),
        ]);
      const snapshot = await ipc.getSnapshot();
      applyThemeToDom(config.theme);
      const firstFail =
        preflight.items.find((x) => x.part === "must" && x.status !== "ok") ??
        preflight.items[0];
      set({
        config,
        snapshot,
        preflight,
        startupAudit,
        nodeReport,
        licenseStatus,
        deepAudit,
        ackedLogIds: Array.isArray(config.ackedLogIds) ? config.ackedLogIds : [],
        selectedCheckId: firstFail?.id ?? "node_proxy",
        initialized: true,
        checking: false,
      });
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
    set({ fixing: true, fixingItemId: itemId });
    try {
      const res = await ipc.fixPreflightItem(itemId);
      const [startupAudit, nodeReport] = await Promise.all([
        ipc.auditStartupItems(),
        ipc.getNodesAndQuality(),
      ]);
      set({
        preflight: res.report,
        snapshot: res.snapshot,
        startupAudit,
        nodeReport,
        fixing: false,
        fixingItemId: null,
      });
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
    set({ fixing: true, fixingItemId: "__all__" });
    try {
      const res = await ipc.oneClickFixAll();
      const [startupAudit, nodeReport] = await Promise.all([
        ipc.auditStartupItems(),
        ipc.getNodesAndQuality(),
      ]);
      set((state) => ({
        preflight: res.report,
        snapshot: res.snapshot,
        startupAudit,
        nodeReport,
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
      if (seq !== nodesReqSeq) return;
      set({ nodeReport });
    } catch (err) {
      get().pushToast("刷新节点列表失败", String(err), "danger");
    }
  },

  async startDeepNodeAudit(forceAll = false, targetNode?: string) {
    try {
      const progress = await ipc.startDeepNodeAudit(forceAll, targetNode);
      set({ deepAudit: progress });
      if (!progress.running && progress.message) {
        get().pushToast("节点深度核验", progress.message, progress.phase === "blocked" ? "danger" : "info");
      }
    } catch (err) {
      get().pushToast("无法启动节点深度核验", String(err), "danger");
    }
  },

  async cancelDeepNodeAudit() {
    try {
      const progress = await ipc.cancelDeepNodeAudit();
      set({ deepAudit: progress });
      get().pushToast("已停止深度核验", progress.message || "正在恢复原锁定节点...", "info");
    } catch (err) {
      get().pushToast("停止深度核验失败", String(err), "danger");
    }
  },

  setDeepAuditFromEvent(progress) {
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
    set({ fixing: true, switchingNodeName: name });
    try {
      const res = await ipc.switchLockedNode(name, forceIgnoreRisk);
      const nodeReport = await ipc.getNodesAndQuality();
      set({
        preflight: res.report,
        snapshot: res.snapshot,
        nodeReport,
        fixing: false,
        switchingNodeName: null,
      });
      get().pushToast("已切换锁定节点", res.message, "ok");
    } catch (err) {
      set({ fixing: false, switchingNodeName: null });
      get().pushToast("切换节点被拦截或失败", String(err), "danger");
    }
  },

  async updateConfig(patch, toastLabel) {
    try {
      const updated = await ipc.updateConfig(patch);
      applyThemeToDom(updated.theme);
      // 仅修改自启相关配置时才重新扫描开机启动项，改主题/静音/遥测等不再无谓扫注册表
      const needsStartupReaudit =
        patch.bootStart !== undefined || patch.bootHudOnly !== undefined;
      const startupAudit = needsStartupReaudit
        ? await ipc.auditStartupItems().catch(() => get().startupAudit)
        : get().startupAudit;
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
    set({ activeTab: tab });
    const lic = get().licenseStatus;
    const isLic = !lic.commercialFeatureEnabled || lic.licensed;
    if (tab === "nodes" && isLic) {
      void get().refreshNodes();
    }
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

  ackLogId(id) {
    get().ackLogIds([id]);
  },

  ackLogIds(ids) {
    const uniq = Array.from(new Set(ids.filter(Boolean)));
    if (uniq.length === 0) return;
    const seq = ++ackLogReqSeq;
    set((state) => ({
      ackedLogIds: Array.from(new Set([...state.ackedLogIds, ...uniq])),
    }));
    void ipc
      .ackLogEvents(uniq)
      .then((snap) => {
        if (seq === ackLogReqSeq) {
          set({ snapshot: snap });
        }
      })
      .catch((err) => {
        get().pushToast("同步已读游标失败", String(err), "danger");
      });
  },

  ackAllLogIds(ids) {
    const uniq = Array.from(new Set(ids.filter(Boolean)));
    const seq = ++ackLogReqSeq;
    set((state) => ({
      ackedLogIds: Array.from(new Set([...state.ackedLogIds, ...uniq])),
      snapshot: {
        ...state.snapshot,
        unreadLogAnomalies: 0,
        unreadLogCritical: 0,
        unreadLogWarnings: 0,
      },
    }));
    if (uniq.length > 0) {
      void ipc
        .ackLogEvents(uniq)
        .then((snap) => {
          if (seq === ackLogReqSeq) {
            set({ snapshot: snap });
          }
        })
        .catch((err) => {
          get().pushToast("同步全部已读失败", String(err), "danger");
        });
    }
  },

  ackAllFlowIds(ids) {
    set((state) => ({
      ackedFlowIds: Array.from(new Set([...state.ackedFlowIds, ...ids])),
    }));
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
    set({ preflight: report });
  },

  setConfigFromEvent(cfg) {
    applyThemeToDom(cfg.theme);
    set({ config: cfg });
  },

  setLicenseStatus(status) {
    set({ licenseStatus: status });
  },

  setLicenseModalOpen(open) {
    set({ licenseModalOpen: open });
  },

  setSupportModalOpen(open) {
    set({ supportModalOpen: open });
  },

  async activateLicense(licenseKey) {
    const res = await ipc.activateLicense(licenseKey);
    const nextStatus = await ipc.getLicenseStatus().catch(() => ({
      ...get().licenseStatus,
      licensed: res.licensed,
      activatedAt: res.activatedAt,
      batchId: res.batchId,
    }));
    set({
      licenseStatus: {
        ...nextStatus,
        licensed: true,
        activatedAt: res.activatedAt,
        batchId: res.batchId,
      },
    });
    get().pushToast(
      "核销激活成功 · 已永久绑定当前安装实例",
      res.message,
      "ok",
      { durationMs: 6000 }
    );
    // 激活成功后主动触发一次静默全量复测，避免仅依赖异步广播事件
    void get().refreshPreflight(true);
  },
}));
