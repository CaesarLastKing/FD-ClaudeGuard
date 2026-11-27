import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { DIAG_MANIFEST_MAGIC, FULL_AUDIT_INTERVAL_MS } from "@/lib/protocol";
import type {
  AccountAuditActionResult,
  AccountAuditReport,
  AppConfig,
  AppConfigPatch,
  AppUpdateInfo,
  ArchivedAccountSummary,
  BackupInfo,
  BatchFixResult,
  ClaudeConn,
  ClaudeDataRootsSummary,
  CleanupPlanPreview,
  DeepAuditProgress,
  DiagnosticBundleResult,
  FeedbackReportResult,
  FixResult,
  GuardSnapshot,
  KillHoldSnapshot,
  KillReport,
  KillSwitchState,
  LogAnalysisReport,
  LogEvent,
  NavigatePayload,
  NavTab,
  NetworkRescueReport,
  NodeReport,
  PreflightReport,
  RollbackActionReport,
  RollbackBatchReport,
  RollbackOverview,
  StartupAuditReport,
  SwitchNodeResult,
  TelemetryInspection,
} from "@/types/guard";

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

function isQaPreviewMode(): boolean {
  if (typeof window === "undefined") return false;
  return new URLSearchParams(window.location.search).get("qa") === "1";
}

export const DEFAULT_CONFIG: AppConfig = {
  theme: "dark",
  showHud: true,
  notifyEnabled: true,
  bootStart: true,
  bootHudOnly: true,
  wakePreblockGuard: true,
  antiNakedGuard: true,
  autoKillSwitch: true,
  antiUploadFlush: true,
  safeExitPrompt: true,
  calm24h: false,
  lockCfAndStripeToClaude: true,
  hudPinned: true,
  hudFolded: false,
  hudEdgeDocked: false,
  hudPosition: null,
  killHoldSeconds: 45,
  ackedLogIds: [],
  telemetryToolDiagEnabled: true,
  telemetryClaudeSummaryEnabled: true,
};

export const FALLBACK_SNAPSHOT: GuardSnapshot = {
  healthLevel: "warn",
  statusLabel: "12 项待办",
  currentNode: "等待连接 Mihomo",
  regionCode: "GL",
  exitIpMasked: "待探测出口 IP",
  latencyMs: null,
  latencyLabel: "待测",
  bgClaudeProcs: 0,
  killSwitchActive: false,
  killHoldActive: false,
  killHoldRemainingSecs: 0,
  killHoldBlockedCount: 0,
  killHoldTxLocked: false,
  killHoldReason: "",
  nodeDown: false,
  nodeDriftWarn: false,
  mustPassed: 0,
  mustTotal: 12,
  optPassed: 0,
  optTotal: 7,
  clashVersion: "待探测",
  clashPort: 7890,
  clashOnline: false,
  anthropicStatusIndicator: "none",
  anthropicStatusDesc: "All Systems Operational",
  unreadLogAnomalies: 0,
  unreadLogCritical: 0,
  unreadLogWarnings: 0,
  activeFlowAnomalies: 0,
  liveFlowAnomalies: 0,
  nextFullAuditEpochMs: Date.now() + FULL_AUDIT_INTERVAL_MS,
  triggeredPlaybookIds: [],
  hudEvents: [
    {
      message: "请在桌面客户端中执行两级三防线真实探针实测",
      time: "--:--",
      level: "warn",
      targetTab: "console",
    },
  ],
};

export const FALLBACK_PREFLIGHT: PreflightReport = {
  checkedAt: "",
  stage: "v0.2.7",
  items: [
    // 1. 代理与节点（改 Clash 配置 · 5 项）
    {
      id: "node_proxy",
      part: "must",
      cat: "1. 代理与节点（改 Clash 配置）",
      icon: "proxy",
      mode: "自动一键",
      title: "代理引擎在线与端口独占",
      status: "fail",
      summary: "等待直连 Clash Verge Mihomo 命名管道与端口冲突检测",
      evidence: "Endpoint: Named Pipe \\\\.\\pipe\\verge-mihomo-*",
      guide: "请启动 Clash Verge Rev 并确保本地代理端口无多客户端冲突。",
      fixLabel: null,
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "node_group",
      part: "must",
      cat: "1. 代理与节点（改 Clash 配置）",
      icon: "group",
      mode: "向导 + 实测验收",
      title: "策略组与全家桶规则锁死",
      status: "fail",
      summary: "尚未校验 Claude-Fixed (select) 策略组、全家桶规则与 Mihomo ipv6:false",
      evidence: "Mihomo GET /proxies: 待实查 Claude-Fixed",
      guide: "仅备份并写入 Clash Verge profiles\\Script.js 策略组与规则，重载后通过实测验收。",
      fixLabel: "写入 Script.js 覆写脚本并实测验收",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "node_tun",
      part: "must",
      cat: "1. 代理与节点（改 Clash 配置）",
      icon: "fw",
      mode: "向导 + 实测验收",
      title: "虚拟网卡接管（Clash TUN）",
      status: "fail",
      summary: "尚未实查 Mihomo tun.enable 与 Wintun 虚拟网卡在线状态",
      evidence: "Mihomo tun.enable: 待实测 | Wintun Adapter: 待实测",
      guide: "在 Clash Verge 首页开启虚拟网卡模式 (TUN) 后点击重新实测验收。",
      fixLabel: "打开 Clash 指引并实测验收 TUN",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "node_dns",
      part: "must",
      cat: "1. 代理与节点（改 Clash 配置）",
      icon: "dns",
      mode: "向导 + 实测验收",
      title: "DNS 防泄漏（Clash Fake-IP）",
      status: "fail",
      summary: "尚未实测 claude.ai 解析是否落入 198.18.0.0/15 Fake-IP 网段",
      evidence: "Real DNS Probe (claude.ai): 待实测",
      guide: "仅写入 Fake-IP DNS 段至 Clash 覆写配置，重载后实测 claude.ai 返回 198.18.x.x 变绿。",
      fixLabel: "写入 Fake-IP 配置并实测验收 DNS",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "node_geo",
      part: "must",
      cat: "1. 代理与节点（改 Clash 配置）",
      icon: "geo",
      mode: "自动一键 / 选节点",
      title: "出口节点真实可达性",
      status: "fail",
      summary: "尚未探测出口是否避开禁区、ASN 安全底线与 Anthropic 真实可达性",
      evidence: "Proxy Exit GeoIP & Anthropic Stateless Probe: 待探测",
      guide: "强制经本地代理探测出口国家（非禁区）、非高危滥用节点与 api.anthropic.com 无状态可达性（筛除 CF 403）。",
      fixLabel: null,
      isKillItem: false,
      isFailover: false,
    },
    // 2. Windows 系统环境（改系统 · 3 项）
    {
      id: "sys_ipv6",
      part: "must",
      cat: "2. Windows 系统环境（改系统）",
      icon: "ipv6",
      mode: "管理员一键 + 实测",
      title: "Windows 网卡 IPv6 禁用",
      status: "fail",
      summary: "尚未执行 Windows 活跃网卡 ms_tcpip6 绑定与外网 IPv6 探针实测",
      evidence: "Windows ms_tcpip6 & External IPv6 Probe: 待实测",
      guide: "仅对 Windows 活跃网卡禁用 ms_tcpip6 绑定（不改 Clash、不碰 Claude 目录），实测外网 IPv6 不可达变绿。",
      fixLabel: "管理员一键禁用网卡 IPv6 并实测验收",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "sys_env",
      part: "must",
      cat: "2. Windows 系统环境（改系统）",
      icon: "startup",
      mode: "自动一键",
      title: "系统代理与环境变量冲突排查",
      status: "fail",
      summary: "尚未扫描 HTTP_PROXY / NO_PROXY / ANTHROPIC_BASE_URL 与 WinINET 三端同 IP 一致性",
      evidence: "CLI Proxy ENV & WinINET ProxyServer: 待审计",
      guide: "仅备份并清理冲突环境变量或校准 WinINET 端口，绝不碰 Claude 账号目录。",
      fixLabel: "一键备份并清理冲突环境变量",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "sys_location",
      part: "must",
      cat: "2. Windows 系统环境（改系统）",
      icon: "location",
      mode: "管理员一键 + 实测",
      title: "Windows 系统定位服务关闭",
      status: "fail",
      summary: "尚未检查 Windows 定位权限（HKLM/HKCU/NonPackaged）与 lfsvc 地理定位服务状态",
      evidence: "Windows Location ConsentStore & lfsvc Service: 待实测",
      guide: "仅关闭 Windows 系统/用户/桌面应用定位权限（置为 Deny）并停止禁用 lfsvc 服务，防 Claude 获取真实位置。",
      fixLabel: "管理员一键关闭系统定位并禁用 lfsvc",
      isKillItem: false,
      isFailover: false,
    },
    // 3. Claude 本机卫生（改 Claude · 3 项）
    {
      id: "claude_ban",
      part: "must",
      cat: "3. Claude 本机卫生（改 Claude）",
      icon: "ban",
      mode: "自动一键",
      title: "本地封号污染残留审查",
      status: "fail",
      summary: "尚未扫描本地 Claude 日志与目录封号/403 污染残留",
      evidence: "Local Contamination Scan: 待扫描",
      guide: "检出污染时自动结束进程、原子 ZIP 备份并清理污染目录，重扫 0 残留变绿。",
      fixLabel: "一键原子备份并清理本地污染目录",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "claude_acct",
      part: "must",
      cat: "3. Claude 本机卫生（改 Claude）",
      icon: "userLock",
      mode: "引导确认",
      title: "单号卫生锁（防混号与跨 orgId）",
      status: "fail",
      summary: "尚未核对本机登录 orgId 与跨账号竞态记录",
      evidence: "Bound Primary orgId & Cross-orgId Scan: 待审计",
      guide: "绝不擅自乱删：检出混号或 OAuth 403 异常时引导二选一确认（备份重置目录 或 二次确认更换主号）。",
      fixLabel: "引导处理单号冲突（二选一确认）",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "claude_endpoint",
      part: "must",
      cat: "3. Claude 本机卫生（改 Claude）",
      icon: "endpoint",
      mode: "自动一键",
      title: "官方 API 端点防反代校验",
      status: "fail",
      summary: "尚未核对 settings.json 与环境变量是否改写非官方 API 端点",
      evidence: "ANTHROPIC_BASE_URL / API_URL: 待检测",
      guide: "消费级订阅强烈建议直连官方原生端点；点击一键备份后移除非官方端点，随时可撤回。",
      fixLabel: "一键备份并还原官方原生端点",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "claude_tel",
      part: "must",
      cat: "3. Claude 本机卫生（改 Claude）",
      icon: "privacy",
      mode: "自动一键",
      title: "官方隐私降噪开关 & 遥测缓存",
      status: "fail",
      summary: "尚未检查 ~/.claude/settings.json 隐私降噪配置",
      evidence: "File: ~/.claude/settings.json (待检测)",
      guide: "仅合并写入官方降噪环境变量并清空本地 telemetry 缓存，绝不碰登录态与聊天记录。",
      fixLabel: "一键写入隐私降噪并清空缓存",
      isKillItem: false,
      isFailover: false,
    },
    // 二、建议优化（3 项均有独立处理闭环）
    {
      id: "opt_boot",
      part: "opt",
      cat: "系统辅助优化",
      icon: "startup",
      mode: "只读风险监测",
      title: "开机启动项顺序风险检查（Clash / Claude）",
      status: "warn",
      summary: "只读审计 Windows 启动项顺序风险（绝不擅自删除启动项）",
      evidence: "Read-only Startup Audit: 待检测",
      guide: "绝不擅自修改或删除你的开机启动项；点击打开 Windows 启动应用管理页手动关闭 Claude 自启后复扫变绿。",
      fixLabel: "打开 Windows 启动应用管理页",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "opt_ntp",
      part: "opt",
      cat: "系统辅助优化",
      icon: "clock",
      mode: "管理员一键",
      title: "系统时钟 NTP 同步偏差",
      status: "warn",
      summary: "尚未执行 UTC NTP 时间偏差探测",
      evidence: "NTP Drift Probe: 待探测",
      guide: "偏差超 ±30s 时管理员一键执行 w32tm /resync /force 同步并复测变绿。",
      fixLabel: "管理员一键 NTP 校准对时",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "opt_fw",
      part: "opt",
      cat: "系统辅助优化",
      icon: "fw",
      mode: "管理员一键",
      title: "防火墙 Kill Switch 权限就绪",
      status: "warn",
      summary: "尚未安装免 UAC 守护计划任务，紧急断流将触发系统弹窗确认",
      evidence: "Elevated Helper Task: Not Installed\nRule Prefix: FDClaudeGuard_KillSwitch_*",
      guide: "一键安装本地免 UAC 守护计划任务并实测读写一条 FDClaudeGuard_KillSwitch_* 规则，卸载时自动清空。",
      fixLabel: "安装免 UAC 守护权限并实测",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "opt_webrtc",
      part: "opt",
      cat: "系统辅助优化",
      icon: "privacy",
      mode: "自动一键",
      title: "浏览器 WebRTC 防泄露策略",
      status: "warn",
      summary: "尚未检测本机 Chrome / Edge 是否锁定 WebRTC 防直连 UDP 泄露策略",
      evidence: "Browser WebRtcIPHandling Policy: 待检测",
      guide: "零 UAC 写入 Chrome / Edge 官方策略 WebRtcIPHandling = disable_non_proxied_udp，防网页登录暴露真实 IP。",
      fixLabel: "一键锁死 Chrome / Edge WebRTC 防泄露",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "opt_tz",
      part: "opt",
      cat: "系统辅助优化",
      icon: "clock",
      mode: "只读风险监测",
      title: "系统时区与出口地区一致性",
      status: "warn",
      summary: "尚未比对本机系统时区与当前出口国家时差",
      evidence: "System Timezone vs Exit Region: 待检测",
      guide: "仅做温和提示，绝不强改电脑时钟；新号敏感期建议优先选日/台/新/澳等近时区节点。",
      fixLabel: "打开 Windows 日期与时间设置",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "opt_exit_geo",
      part: "opt",
      cat: "系统辅助优化",
      icon: "geo",
      mode: "只读风险监测",
      title: "出口节点合规性与属地一致性",
      status: "warn",
      summary: "尚未比对账号注册属地、24h 落地 IP 漂移与网页 CF 弹盾状态",
      evidence: "Exit Geo Compliance & 24h Drift: 待探测",
      guide: "用于持续追踪账号属地跨洲一致性、24h 落地 IP 稳定性、网页 CF 弹盾与 IP 类型参考，不阻断正常启动。",
      fixLabel: "前往「节点流量」核对并切换稳定节点",
      isKillItem: false,
      isFailover: false,
    },
    {
      id: "opt_browser_ext",
      part: "opt",
      cat: "系统辅助优化",
      icon: "group",
      mode: "只读风险监测",
      title: "浏览器独立代理插件冲突审计",
      status: "warn",
      summary: "尚未扫描本机 Chrome / Edge 是否安装了独立代理分流插件",
      evidence: "Browser Proxy Extensions Audit: 待检测",
      guide: "绝不擅自删除你的浏览器扩展；若检出独立代理插件，请确认未对 claude.ai 单独分流。",
      fixLabel: null,
      isKillItem: false,
      isFailover: false,
    },
  ],
};

export const FALLBACK_STARTUP_AUDIT: StartupAuditReport = {
  claudeAutostartRisk: false,
  entries: [
    {
      app: "FD Claude Guard",
      enabled: true,
      riskLevel: "ok",
      detail: "已开启开机自启（默认仅显悬浮窗，开机自动护航）",
    },
    {
      app: "Clash Verge Rev",
      enabled: true,
      riskLevel: "ok",
      detail: "建议保持开机自启，确保代理早于应用就绪",
    },
    {
      app: "Claude Desktop",
      enabled: false,
      riskLevel: "ok",
      detail: "未发现 Claude 开机自启项，无抢跑裸奔风险",
    },
  ],
};

let memoryConfig: AppConfig = { ...DEFAULT_CONFIG };

export const MOCK_BACKUPS: BackupInfo[] = [
  {
    fileName: "claude-backup-clean-20261124-173940-578.zip",
    fullPath: "~/FDtools-Backups/claude-backup-clean-20261124-173940-578.zip",
    kind: "clean",
    createdAt: "2026-11-24 17:39:40",
    createdTs: 1795501180000,
    sizeBytes: 4_120_320,
    sizeLabel: "3.93 MB",
  },
];
const MOCK_CLEANED_CATS = new Set<string>();
const MOCK_ACKED_LOG_IDS = new Set<string>();

export const ipc = {
  async getConfig(): Promise<AppConfig> {
    if (!isTauriRuntime()) return { ...memoryConfig };
    return invoke<AppConfig>("get_config");
  },

  async updateConfig(patch: AppConfigPatch): Promise<AppConfig> {
    if (!isTauriRuntime()) {
      memoryConfig = { ...memoryConfig, ...patch };
      if (patch.bootStart === false) memoryConfig.bootHudOnly = false;
      return { ...memoryConfig };
    }
    return invoke<AppConfig>("update_config", { patch });
  },

  async syncClashRulePolicy(): Promise<string> {
    if (!isTauriRuntime()) {
      return memoryConfig.lockCfAndStripeToClaude !== false
        ? "已热同步开启 CF 盾与 Stripe 锁定规则。"
        : "已热同步取消 CF 盾与 Stripe 锁定规则。";
    }
    return invoke<string>("sync_clash_rule_policy");
  },

  async setHudPinned(pinned: boolean): Promise<AppConfig> {
    if (!isTauriRuntime()) {
      memoryConfig = { ...memoryConfig, hudPinned: pinned };
      return { ...memoryConfig };
    }
    return invoke<AppConfig>("set_hud_pinned", { pinned });
  },

  async setHudFolded(folded: boolean): Promise<AppConfig> {
    if (!isTauriRuntime()) {
      memoryConfig = { ...memoryConfig, hudFolded: folded };
      return { ...memoryConfig };
    }
    return invoke<AppConfig>("set_hud_folded", { folded });
  },

  async setHudEdgeDocked(docked: boolean, expanded = false): Promise<AppConfig> {
    if (!isTauriRuntime()) {
      memoryConfig = { ...memoryConfig, hudEdgeDocked: docked };
      return { ...memoryConfig };
    }
    return invoke<AppConfig>("set_hud_edge_docked", { docked, expanded });
  },

  async resizeHudHeight(height: number, width?: number, dpr?: number): Promise<void> {
    if (!isTauriRuntime()) return;
    const effectiveDpr =
      typeof dpr === "number" && Number.isFinite(dpr) && dpr > 0
        ? dpr
        : typeof window !== "undefined" && Number.isFinite(window.devicePixelRatio)
        ? window.devicePixelRatio
        : null;
    await invoke("resize_hud_height", {
      height,
      width: width ?? null,
      dpr: effectiveDpr,
    });
  },

  async quitApp(killClaudeFirst = false): Promise<void> {
    if (!isTauriRuntime()) return;
    await invoke("quit_app", { killClaudeFirst });
  },

  async logFrontendEvent(level: "INFO" | "WARN" | "ERROR", module: string, message: string): Promise<void> {
    if (!isTauriRuntime()) return;
    await invoke("log_frontend_event", { level, module, message }).catch(() => {});
  },

  async openGuardLogsDir(): Promise<string> {
    if (!isTauriRuntime()) return "~/.fd-claude-guard/logs";
    return invoke<string>("open_guard_logs_dir");
  },

  async openFileFolder(path: string): Promise<void> {
    if (!isTauriRuntime()) return;
    await invoke("open_file_folder", { path });
  },

  async getRecentGuardLogs(limit = 100): Promise<string[]> {
    if (!isTauriRuntime()) return [];
    return invoke<string[]>("get_recent_guard_logs", { limit });
  },

  async showMainWindow(options?: {
    tab?: NavTab;
    subTab?: string | null;
    focusItemId?: string | null;
    openPlaybook?: boolean;
  }): Promise<void> {
    if (!isTauriRuntime()) return;
    await invoke("show_main_window", {
      tab: options?.tab ?? "console",
      subTab: options?.subTab ?? null,
      focusItemId: options?.focusItemId ?? null,
      openPlaybook: options?.openPlaybook ?? null,
    });
  },

  async hideMainWindow(): Promise<void> {
    if (!isTauriRuntime()) return;
    await invoke("hide_main_window");
  },

  async toggleHudWindow(visible?: boolean): Promise<boolean> {
    if (!isTauriRuntime()) {
      const next = visible ?? !memoryConfig.showHud;
      memoryConfig = { ...memoryConfig, showHud: next };
      return next;
    }
    return invoke<boolean>("toggle_hud_window", { visible: visible ?? null });
  },

  async getSnapshot(): Promise<GuardSnapshot> {
    if (!isTauriRuntime()) return FALLBACK_SNAPSHOT;
    return invoke<GuardSnapshot>("get_snapshot");
  },

  async runPreflightChecks(force = true): Promise<PreflightReport> {
    if (!isTauriRuntime()) return FALLBACK_PREFLIGHT;
    return invoke<PreflightReport>("run_preflight_checks", { force });
  },

  async fixPreflightItem(itemId: string): Promise<FixResult> {
    if (!isTauriRuntime()) {
      return {
        itemId,
        success: false,
        requiresManualStep: true,
        message: "浏览器预览模式无法调用原生探针修复，请在桌面客户端中执行。",
        report: FALLBACK_PREFLIGHT,
        snapshot: FALLBACK_SNAPSHOT,
      };
    }
    return invoke<FixResult>("fix_preflight_item", { itemId });
  },

  async oneClickFixAll(): Promise<BatchFixResult> {
    if (!isTauriRuntime()) {
      return {
        fixedIds: [],
        skippedManualId: "node_group",
        summary: "浏览器预览模式无法执行系统修复，请在桌面客户端中运行。",
        report: FALLBACK_PREFLIGHT,
        snapshot: FALLBACK_SNAPSHOT,
      };
    }
    return invoke<BatchFixResult>("one_click_fix_all");
  },

  async safeLaunchClaude(): Promise<string> {
    if (!isTauriRuntime()) {
      throw new Error("请在桌面客户端中通过全部必须项实测后启动 Claude");
    }
    return invoke<string>("safe_launch_claude");
  },

  async getNodesAndQuality(force = false): Promise<NodeReport> {
    if (!isTauriRuntime()) {
      if (isQaPreviewMode()) {
        return {
          connected: true,
          endpoint: "Named Pipe (QA 预览样本)",
          groupName: "Claude-Fixed",
          currentNode: "US-LA-Static-01",
          currentExitSummary: "104.28.214.18 · ISP · 42 ms",
          totalRawNodes: 6,
          filteredBlockedCount: 2,
          nodes: [
            {
              name: "US-LA-Static-01",
              regionCode: "US",
              regionLabel: "美国洛杉矶 · 主节点",
              nodeType: "Vless",
              delayMs: 42,
              jitterMs: 3,
              dropRatePct: 0,
              blocked: false,
              isCurrent: true,
              score: 96,
              recommendation: "双 AI 推荐",
              asnPurity: "ISP 住宅/静态",
              asnShort: "ISP",
              anthropicProbe: "Claude ✓",
              cfBlocked: false,
              claudeStatus: "ok",
              claudeLabel: "Claude ✓",
              geminiStatus: "ok",
              geminiLabel: "Gemini ✓",
              dualAiOk: true,
            },
            {
              name: "US-LA-Static-02",
              regionCode: "US",
              regionLabel: "美国洛杉矶 · 同区热备",
              nodeType: "Vless",
              delayMs: 46,
              jitterMs: 4,
              dropRatePct: 0.1,
              blocked: false,
              isCurrent: false,
              score: 94,
              recommendation: "同区热备",
              asnPurity: "ISP 住宅/静态",
              asnShort: "ISP",
              anthropicProbe: "Claude ✓",
              cfBlocked: false,
              claudeStatus: "ok",
              claudeLabel: "Claude ✓",
              geminiStatus: "ok",
              geminiLabel: "Gemini ✓",
              dualAiOk: true,
            },
            {
              name: "JP-Tokyo-02",
              regionCode: "JP",
              regionLabel: "日本东京 · 跨国次选",
              nodeType: "Trojan",
              delayMs: 58,
              jitterMs: 8,
              dropRatePct: 0.2,
              blocked: false,
              isCurrent: false,
              score: 84,
              recommendation: "仅 Claude",
              asnPurity: "机房 Hosting",
              asnShort: "机房",
              anthropicProbe: "Claude ✓",
              cfBlocked: false,
              claudeStatus: "ok",
              claudeLabel: "Claude ✓",
              geminiStatus: "restricted",
              geminiLabel: "Gemini ✗",
              dualAiOk: false,
            },
            {
              name: "TW-Taipei-04",
              regionCode: "TW",
              regionLabel: "中国台湾 · 备选",
              nodeType: "Vless",
              delayMs: 72,
              jitterMs: 11,
              dropRatePct: 0.3,
              blocked: false,
              isCurrent: false,
              score: 78,
              recommendation: "仅 Claude",
              asnPurity: "机房 Hosting",
              asnShort: "机房",
              anthropicProbe: "Claude ✓",
              cfBlocked: false,
              claudeStatus: "ok",
              claudeLabel: "Claude ✓",
              geminiStatus: "cn_redirect",
              geminiLabel: "Gemini 限区",
              dualAiOk: false,
              driftCount24h: 0,
              riskLevel: "hosting",
              riskDetail: "0 滥用记录",
              webCfChallenge: false,
            },
            {
              name: "SG-Shared-09",
              regionCode: "SG",
              regionLabel: "新加坡 · 共享节点",
              nodeType: "Vmess",
              delayMs: 215,
              jitterMs: 28,
              dropRatePct: 6.8,
              blocked: false,
              isCurrent: false,
              score: 28,
              recommendation: "拉黑不可用",
              asnPurity: "高危滥用",
              asnShort: "高危滥用",
              anthropicProbe: "Claude 拉黑",
              cfBlocked: true,
              claudeStatus: "cf_403",
              claudeLabel: "Claude 拉黑",
              geminiStatus: "restricted",
              geminiLabel: "Gemini 限区",
              dualAiOk: false,
              driftCount24h: 3,
              riskLevel: "abuser",
              riskDetail: "命中滥用黑名单",
              webCfChallenge: false,
            },
          ],
        };
      }
      return {
        connected: false,
        endpoint: "预览模式",
        groupName: "Claude-Fixed",
        currentNode: "未连接",
        totalRawNodes: 0,
        filteredBlockedCount: 0,
        nodes: [],
      };
    }
    return invoke<NodeReport>("get_nodes_and_quality", { force });
  },

  async switchLockedNode(name: string, forceIgnoreRisk = false): Promise<SwitchNodeResult> {
    if (!isTauriRuntime()) {
      throw new Error("预览模式无法切换节点");
    }
    return invoke<SwitchNodeResult>("switch_locked_node", { name, forceIgnoreRisk });
  },

  async getLiveConnections(): Promise<ClaudeConn[]> {
    if (!isTauriRuntime()) {
      if (isQaPreviewMode()) {
        return [
          {
            id: "qa-conn-kyc",
            anomaly: true,
            process: "chrome.exe",
            host: "inquiry.withpersona.com:443",
            rule: "Match",
            chain: "DIRECT",
            action: "风险连接（建议立即掐断）",
            time: "18:35:02",
            startedAtMs: Date.now() - 96_000,
            bytesLabel: "4.8 KB",
            domainCategory: "kyc_verify",
            purposeLabel: "KYC 身份核验",
            purposeDetail: "Anthropic 风控复审与 Persona 身份验证接口（需与主站同节点）",
            isUnlistedDomain: false,
          },
          {
            id: "qa-conn-api",
            anomaly: false,
            process: "Claude.exe",
            host: "api.anthropic.com:443",
            rule: "DomainSuffix",
            chain: "Claude-Fixed → 🇺🇸美国1|流媒体AI",
            action: "正常放行",
            time: "18:35:05",
            startedAtMs: Date.now() - 944_000,
            bytesLabel: "1.42 MB",
            domainCategory: "core_api",
            purposeLabel: "核心 API",
            purposeDetail: "Anthropic 官方模型推理、桌面端与 Claude Code 核心接口",
            isUnlistedDomain: false,
          },
          {
            id: "qa-conn-flag",
            anomaly: false,
            process: "Claude.exe",
            host: "statsig.anthropic.com:443",
            rule: "DomainSuffix",
            chain: "Claude-Fixed → 🇺🇸美国1|流媒体AI",
            action: "正常放行",
            time: "18:35:06",
            startedAtMs: Date.now() - 412_000,
            bytesLabel: "9.1 KB",
            domainCategory: "feature_flag",
            purposeLabel: "功能开关",
            purposeDetail: "Claude 模型列表、Artifacts 与新特性灰度开关（刻意保留不拦截）",
            isUnlistedDomain: false,
          },
          {
            id: "qa-conn-tel",
            anomaly: false,
            process: "Claude.exe",
            host: "browser-intake-datadoghq.com:443",
            rule: "DomainSuffix",
            chain: "REJECT",
            action: "已拦截（防回传）",
            time: "18:35:08",
            bytesLabel: "0 B",
            domainCategory: "telemetry",
            purposeLabel: "遥测 · 行为监控",
            purposeDetail: "Datadog 客户端/网页指纹与性能事件上报（建议 REJECT 拦截）",
            isUnlistedDomain: false,
          },
          {
            id: "qa-conn-new",
            anomaly: false,
            process: "Claude.exe",
            host: "cowork-edge.anthropic-labs.dev:443",
            rule: "Process",
            chain: "Claude-Fixed → 🇺🇸美国1|流媒体AI",
            action: "进程兜底放行",
            time: "18:35:10",
            startedAtMs: Date.now() - 185_000,
            bytesLabel: "2.3 KB",
            domainCategory: "unknown_new",
            purposeLabel: "未收录新域",
            purposeDetail: "Claude 进程访问的新外部域名，已由进程规则兜底走 Claude-Fixed",
            isUnlistedDomain: true,
          },
        ];
      }
      return [];
    }
    return invoke<ClaudeConn[]>("get_live_connections");
  },

  async ackFlowAnomalies(ids: string[]): Promise<GuardSnapshot> {
    if (!isTauriRuntime()) {
      return {
        ...FALLBACK_SNAPSHOT,
        liveFlowAnomalies: 0,
        activeFlowAnomalies: FALLBACK_SNAPSHOT.nodeDown || FALLBACK_SNAPSHOT.nodeDriftWarn ? 1 : 0,
      };
    }
    return invoke<GuardSnapshot>("ack_flow_anomalies", { ids });
  },

  async closeConnection(id: string): Promise<void> {
    if (!isTauriRuntime()) return;
    await invoke("close_connection", { id });
  },

  async killClaudeProcesses(cleanTelemetry: boolean): Promise<KillReport> {
    if (!isTauriRuntime()) {
      return {
        beforeCount: 0,
        afterCount: 0,
        telemetryClearedBytes: 0,
        message: "预览模式：无 Claude 后台进程，已启动 45s 防复活持续盯防锁。",
        killHoldActive: true,
        killHoldRemainingSecs: memoryConfig.killHoldSeconds ?? 45,
      };
    }
    return invoke<KillReport>("kill_claude_processes", { cleanTelemetry });
  },

  async startKillHold(durationSecs?: number, reason?: string): Promise<KillHoldSnapshot> {
    if (!isTauriRuntime()) {
      return {
        active: true,
        remainingSecs: durationSecs ?? memoryConfig.killHoldSeconds ?? 45,
        blockedCount: 0,
        txLocked: false,
        reason: reason ?? "预览模式防复活盯防",
      };
    }
    return invoke<KillHoldSnapshot>("start_kill_hold_cmd", {
      durationSecs: durationSecs ?? null,
      reason: reason ?? null,
    });
  },

  async releaseKillHold(): Promise<KillHoldSnapshot> {
    if (!isTauriRuntime()) {
      return {
        active: false,
        remainingSecs: 0,
        blockedCount: 0,
        txLocked: false,
        reason: "",
      };
    }
    return invoke<KillHoldSnapshot>("release_kill_hold_cmd");
  },

  async triggerKillswitch(reason?: string): Promise<KillSwitchState> {
    if (!isTauriRuntime()) {
      return {
        active: true,
        ruleName: "FDClaudeGuard_KillSwitch_BlockOut",
        targetExe: null,
        firewallApplied: false,
        claudeConnectionsClosed: 0,
        killedProcesses: 0,
        telemetryClearedBytes: 0,
        reason: reason ?? "预览模拟熔断",
        updatedAt: "--:--",
      };
    }
    return invoke<KillSwitchState>("trigger_killswitch", { reason: reason ?? null });
  },

  async forceReleaseKillswitch(confirmed: boolean): Promise<KillSwitchState> {
    if (!isTauriRuntime()) {
      return {
        active: false,
        ruleName: "FDClaudeGuard_KillSwitch_BlockOut",
        targetExe: null,
        firewallApplied: false,
        claudeConnectionsClosed: 0,
        killedProcesses: 0,
        telemetryClearedBytes: 0,
        reason: "预览已解除",
        updatedAt: "--:--",
      };
    }
    return invoke<KillSwitchState>("force_release_killswitch", { confirmed });
  },

  async getLogAnalysis(): Promise<LogAnalysisReport> {
    if (!isTauriRuntime()) {
      const cleanedLogs = MOCK_CLEANED_CATS.has("logs");
      const mockAckedAll = MOCK_ACKED_LOG_IDS.has("__ALL__");
      const events: LogEvent[] = cleanedLogs
        ? []
        : [
            {
              id: "mock-oauth-v2-72",
              ruleId: "pb_pay",
              anomaly: true,
              simulated: false,
              acked: mockAckedAll || MOCK_ACKED_LOG_IDS.has("mock-oauth-v2-72"),
              level: "warn",
              tag: "OAuth v2 鉴权",
              time: "2026-11-25 04:47:45",
              file: "main.log:72 ~ 336 (共 5 次)",
              line: 72,
              repeatCount: 5,
              collapsedIds: [
                "mock-oauth-v2-72",
                "mock-oauth-v2-73",
                "mock-oauth-v2-334",
                "mock-oauth-v2-335",
                "mock-oauth-v2-336",
              ],
              title: "OAuth v2 令牌交换失败（auth_error，风险提醒 · 非 403）",
              cause:
                "风险原因：桌面端后台尝试换取或刷新 OAuth v2 令牌时返回 auth_error（非 HTTP 403，非确认永久封号）。常见原因：① 当前套餐无对应功能权限（如 Free 号后台探测 Pro/Cowork Scope）；② 本地 sessionKey 过久触发 session_stale_relogin 需重新交互登录；③ 默认浏览器与桌面端登录了不同账号或本地凭据失步。",
              context:
                "2026-11-25 04:47:42 [info] [oauth-v2] fresh exchange failed for orgId=<REDACTED:2W> (auth_error)\n...（60 秒内同类重复 5 次，合并行号范围：72 ~ 336）",
            },
            {
              id: "mock-unauth-ok",
              ruleId: null,
              anomaly: false,
              simulated: false,
              acked: false,
              level: "ok",
              tag: "未登录",
              time: "2026-11-24 17:15:02",
              file: "main.log:118",
              line: 118,
              title: "本地会话未登录或凭证已失效",
              cause:
                "触发归因：当前尚未登录 Claude 或旧登录 Cookie 已过期，属于正常鉴权提醒。处理建议：确认代理合规后在 Claude 客户端重新登录即可。",
              context: "2026-11-24 17:15:02 [info] No sessionKey cookie found; awaiting sign-in",
            },
          ];
      const crit = events.filter((e) => e.anomaly && !e.acked && e.level === "fail").length;
      const warn = events.filter((e) => e.anomaly && !e.acked && e.level === "warn").length;
      return {
        events,
        stats: {
          totalAnomalies: crit + warn,
          criticalCount: crit,
          warningCount: warn,
          regionOrRateCount: events.filter((e) => e.anomaly).length,
          disconnectCount: 0,
          telemetryOrDeviceCount: 0,
          watchingFiles: ["MSIX\\LocalCache\\Roaming\\Claude\\logs\\main.log"],
          ignoredNoiseCount: 3,
          ignoredNoiseBreakdown: [{ label: "正常启动/心跳信息", count: 3 }],
          timezoneJumpWarning: null,
        },
      };
    }
    return invoke<LogAnalysisReport>("get_log_analysis");
  },

  async ackLogEvents(ids: string[]): Promise<GuardSnapshot> {
    if (!isTauriRuntime()) {
      for (const id of ids) {
        if (id) MOCK_ACKED_LOG_IDS.add(id);
      }
      return {
        ...FALLBACK_SNAPSHOT,
        unreadLogAnomalies: 0,
        unreadLogCritical: 0,
        unreadLogWarnings: 0,
      };
    }
    return invoke<GuardSnapshot>("ack_log_events", { ids });
  },

  async ackAllLogEvents(): Promise<GuardSnapshot> {
    if (!isTauriRuntime()) {
      MOCK_ACKED_LOG_IDS.add("__ALL__");
      return {
        ...FALLBACK_SNAPSHOT,
        unreadLogAnomalies: 0,
        unreadLogCritical: 0,
        unreadLogWarnings: 0,
      };
    }
    return invoke<GuardSnapshot>("ack_all_log_events");
  },

  async previewAnonymousFeedbackPayload(): Promise<string> {
    if (!isTauriRuntime()) {
      return JSON.stringify(
        {
          schemaVersion: 2,
          appVersion: __APP_VERSION__,
          installIdHash: "9f2a8c1d",
          toolDiagnostics: {
            clashVersion: "Mihomo v1.19.23",
            clashPort: 7897,
            clashOnline: true,
            regionCode: "AU",
            killSwitchActive: false,
            mustPassed: 12,
            mustTotal: 12,
            failedChecks: [],
            recentToolErrors: [],
          },
          claudeErrorEvents: [
            {
              tag: "OAuth v2 鉴权",
              level: "warn",
              repeatCount: 5,
              signature: "[oauth-v2] fresh exchange failed for orgId=<REDACTED:2W> (auth_error)",
            },
          ],
          preBanAttribution72h: {
            uniqueOrgHashCount: 1,
            crossOrgRaceDetected: false,
            disconnectToQuit403Count: 0,
            rateLimit429Count: 0,
            tzJumpDetected: false,
            topRiskFactors: [],
          },
        },
        null,
        2
      );
    }
    return invoke<string>("preview_anonymous_feedback_payload");
  },

  async submitAnonymousFeedbackReport(): Promise<FeedbackReportResult> {
    if (!isTauriRuntime()) {
      const now = new Date();
      const ymd = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, "0")}${String(
        now.getDate()
      ).padStart(2, "0")}`;
      const ticketId = `FD-${ymd}-7A3F`;
      return {
        ticketId,
        createdAt: now.toISOString(),
        uploadedBytes: 642,
        endpointUsed: "preview://api/v1/feedback/report",
        message: `预览模式：已通过统一脱敏管线生成排障单号 ${ticketId}`,
      };
    }
    return invoke<FeedbackReportResult>("submit_anonymous_feedback_report_cmd");
  },

  async simulateLogAnomaly(): Promise<LogEvent> {
    if (!isTauriRuntime()) {
      return {
        id: `sim-${Date.now()}`,
        ruleId: "pb_rate",
        anomaly: true,
        simulated: true,
        level: "warn",
        tag: "高并发 429",
        time: new Date().toTimeString().slice(0, 8),
        file: "simulated:57688",
        line: 57688,
        title: "【模拟演示】检测到连续 429 限流与 4 个并行 sideSession",
        cause: "模拟演示触发（非真实日志）：用于演练日志异常联动点亮安全守则的效果，随时可一键清空模拟记录。",
        context: "57688 [warn] [SIMULATED] HTTP 429 rate_limit_error (active sideSessions=4)",
      };
    }
    return invoke<LogEvent>("simulate_log_anomaly");
  },

  async clearSimulatedLogs(): Promise<number> {
    if (!isTauriRuntime()) return 0;
    return invoke<number>("clear_simulated_logs");
  },

  async inspectTelemetryData(): Promise<TelemetryInspection> {
    if (!isTauriRuntime()) {
      return {
        telemetryDir: "~/.claude/telemetry",
        totalFiles: 0,
        totalBytes: 0,
        totalSizeLabel: "0 B",
        explanation:
          "Claude 遥测与设备记录主要包含 EventLogging 事件队列缓存（~/.claude/telemetry/）与 get_device_info 设备元数据；所有预览内容均已脱敏。",
        files: [],
      };
    }
    return invoke<TelemetryInspection>("inspect_telemetry_data");
  },

  async cleanupAllGuardFirewallRules(): Promise<string> {
    if (!isTauriRuntime()) {
      return "预览模式：已清空全部 FDClaudeGuard_KillSwitch_* 防火墙规则。";
    }
    return invoke<string>("cleanup_all_guard_firewall_rules_cmd");
  },

  async confirmPrimaryOrgBinding(orgId: string): Promise<PreflightReport> {
    if (!isTauriRuntime()) return FALLBACK_PREFLIGHT;
    return invoke<PreflightReport>("confirm_primary_org_binding", { orgId });
  },

  async listBackups(): Promise<BackupInfo[]> {
    if (!isTauriRuntime()) return [...MOCK_BACKUPS];
    return invoke<BackupInfo[]>("list_backups");
  },

  async deleteBackup(fileName: string): Promise<string> {
    if (!isTauriRuntime()) {
      const idx = MOCK_BACKUPS.findIndex((b) => b.fileName === fileName);
      if (idx >= 0) MOCK_BACKUPS.splice(idx, 1);
      return `预览模式：已删除备份 ${fileName}`;
    }
    return invoke<string>("delete_backup", { fileName });
  },

  async clearAllBackups(): Promise<number> {
    if (!isTauriRuntime()) {
      const count = MOCK_BACKUPS.length;
      MOCK_BACKUPS.length = 0;
      return count;
    }
    return invoke<number>("clear_all_backups");
  },

  async previewClaudeCleanupPlan(): Promise<CleanupPlanPreview> {
    if (!isTauriRuntime()) {
      const fmt = (bytes: number) =>
        bytes >= 1024 * 1024
          ? `${(bytes / (1024 * 1024)).toFixed(1)} MB`
          : bytes >= 1024
          ? `${(bytes / 1024).toFixed(0)} KB`
          : `${bytes} B`;
      const makeCat = (
        id: string,
        title: string,
        description: string,
        defaultSelected: boolean,
        willBackup: boolean,
        fileCount: number,
        totalBytes: number,
        samplePaths: string[],
        accountSummary?: string
      ) => {
        const cleared = MOCK_CLEANED_CATS.has(id);
        const bytes = cleared ? 0 : totalBytes;
        return {
          id,
          title,
          description,
          defaultSelected,
          willBackup,
          fileCount: cleared ? 0 : fileCount,
          totalBytes: bytes,
          sizeLabel: fmt(bytes),
          samplePaths: cleared ? [] : samplePaths,
          accountSummary: cleared ? "当前未检测到登录态残留" : accountSummary,
        };
      };
      return {
        detectedInstallModes: ["微软商店 MSIX 版", "经典安装版 (Roaming/Local)", "Claude Code CLI"],
        activeClaudeProcs: 0,
        categories: [
          makeCat(
            "auth",
            "桌面端登录态、Cookie 与 OAuth 凭证",
            "清除后立即退出本地桌面端登录态（Cookies / Local Storage / Session Storage / OAuth config.json）；若需保留桌面端账号请取消勾选。",
            true,
            true,
            18,
            2_516_582,
            [
              "MSIX\\AnthropicPBC.Claude\\Roaming\\Claude\\Network\\Cookies",
              "%LOCALAPPDATA%\\Claude-Data\\anthropicpbc.claude\\config.json",
            ],
            "当前桌面端账号：桌面端账号 (本地不含邮箱 · org a4722ea6)"
          ),
          makeCat(
            "cli_auth_and_backups",
            "CLI 登录态与历史旧号备份（~/.claude）",
            "默认勾选保障本机环境彻底干净：先 ZIP 备份后清除 ~/.claude.json 的 oauthAccount、.credentials.json 与 backups/；若需保留此 CLI 账号请取消勾选。",
            true,
            true,
            7,
            1_226_000,
            ["~\\.claude.json (仅清除 oauthAccount)", "~\\.claude\\.credentials.json", "~\\.claude\\backups\\"],
            "当前 CLI 账号：stev***88@gmail.com (Pro · CLI · 7aacf131) · 含 5 份历史备份"
          ),
          makeCat(
            "logs",
            "本地运行日志与风控记录",
            "清除旧的 main.log / window.log，避免历史 403/429 与旧账号 orgId 持续触发单号锁和日志报警。",
            true,
            true,
            6,
            1_887_436,
            ["MSIX\\AnthropicPBC.Claude\\Roaming\\Claude\\logs\\main.log", "%APPDATA%\\Claude\\logs\\window.log"]
          ),
          makeCat(
            "telemetry",
            "离线遥测与崩溃上报队列",
            "清空断网期间暂存的遥测事件与 Crashpad，防止恢复联网后补传异常日志给 Anthropic。",
            true,
            true,
            11,
            430_080,
            ["~\\.claude\\telemetry\\event-queue.json", "MSIX\\AnthropicPBC.Claude\\Roaming\\Claude\\Crashpad"]
          ),
          makeCat(
            "cache",
            "浏览器内核临时缓存（可再生）",
            "Cache / Code Cache / GPUCache / Service Worker 等网页渲染缓存，不打包可避免卡死，重启自动重建。",
            true,
            false,
            642,
            195_559_424,
            ["MSIX\\AnthropicPBC.Claude\\Roaming\\Claude\\Cache", "Code Cache / GPUCache / blob_storage"]
          ),
          makeCat(
            "mcp_sessions",
            "个人 MCP 配置与本地工作会话",
            "包含 claude_desktop_config.json（MCP 服务器配置）及 local-agent-mode-sessions，仅需彻底重置时再勾选。",
            false,
            true,
            9,
            3_250_585,
            [
              "%APPDATA%\\Claude\\claude_desktop_config.json",
              "%LOCALAPPDATA%\\Claude-Data\\anthropicpbc.claude\\local-agent-mode-sessions",
            ]
          ),
        ],
        protected: {
          fileCount: 3,
          totalBytes: 2_297_807_667,
          sizeLabel: "2.14 GB",
          reasons: [
            "Cowork / Claude Code 虚拟机镜像目录 (vm_bundles)",
            "经典安装版 Claude 程序本体与 WindowsApps",
            "符号链接 / NTFS Junction 外部目标、项目代码与云端对话",
          ],
        },
        scannedMs: 18,
      };
    }
    return invoke<CleanupPlanPreview>("preview_claude_cleanup_plan_cmd");
  },

  async backupAndCleanClaude(selectedCategories?: string[]): Promise<BackupInfo> {
    if (!isTauriRuntime()) {
      const cats = selectedCategories && selectedCategories.length > 0
        ? selectedCategories
        : ["auth", "logs", "telemetry", "cache"];
      cats.forEach((c) => MOCK_CLEANED_CATS.add(c));
      const now = new Date();
      const stamp = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, "0")}${String(
        now.getDate()
      ).padStart(2, "0")}-${String(now.getHours()).padStart(2, "0")}${String(
        now.getMinutes()
      ).padStart(2, "0")}${String(now.getSeconds()).padStart(2, "0")}`;
      const info: BackupInfo = {
        fileName: `claude-backup-clean-${stamp}.zip`,
        fullPath: `~/FDtools-Backups/claude-backup-clean-${stamp}.zip`,
        kind: "clean",
        createdAt: now.toLocaleString("zh-CN", { hour12: false }),
        createdTs: now.getTime(),
        sizeBytes: 4_834_098,
        sizeLabel: "4.61 MB",
      };
      MOCK_BACKUPS.unshift(info);
      return info;
    }
    return invoke<BackupInfo>("backup_and_clean_claude", {
      selectedCategories: selectedCategories ?? null,
    });
  },

  async createManualBackup(): Promise<BackupInfo> {
    if (!isTauriRuntime()) {
      const now = new Date();
      const info: BackupInfo = {
        fileName: `claude-backup-manual-${Date.now()}.zip`,
        fullPath: `~/FDtools-Backups/claude-backup-manual-${Date.now()}.zip`,
        kind: "manual",
        createdAt: "刚刚",
        createdTs: now.getTime(),
        sizeBytes: 4_834_098,
        sizeLabel: "4.61 MB",
      };
      MOCK_BACKUPS.unshift(info);
      return info;
    }
    return invoke<BackupInfo>("create_manual_backup");
  },

  async restoreBackup(fileName: string): Promise<string> {
    if (!isTauriRuntime()) return `预览模式：已自动建立安全点并还原 ${fileName}`;
    return invoke<string>("restore_backup", { fileName });
  },

  async exportAiDiagnosticBundle(contextItemId?: string): Promise<DiagnosticBundleResult> {
    if (!isTauriRuntime()) {
      return {
        zipPath: "%USERPROFILE%\\Desktop\\FDClaudeGuard-诊断包-20261123.zip",
        promptMarkdown: "# FD Claude Guard 脱敏排障上下文（预览）",
        manifestMagic: DIAG_MANIFEST_MAGIC,
      };
    }
    return invoke<DiagnosticBundleResult>("export_ai_diagnostic_bundle_cmd", {
      contextItemId: contextItemId ?? null,
    });
  },

  async auditStartupItems(): Promise<StartupAuditReport> {
    if (!isTauriRuntime()) return FALLBACK_STARTUP_AUDIT;
    return invoke<StartupAuditReport>("audit_startup_items");
  },

  async minimizeCurrentWindow(): Promise<void> {
    if (!isTauriRuntime()) return;
    await getCurrentWindow().minimize();
  },

  async toggleMaximizeCurrentWindow(): Promise<void> {
    if (!isTauriRuntime()) return;
    await getCurrentWindow().toggleMaximize();
  },

  async startDraggingCurrentWindow(): Promise<void> {
    if (!isTauriRuntime()) return;
    await getCurrentWindow().startDragging();
  },

  async listenSnapshot(cb: (snap: GuardSnapshot) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<GuardSnapshot>("guard://snapshot", (e) => cb(e.payload));
  },

  async listenPreflightUpdated(cb: (rep: PreflightReport) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<PreflightReport>("guard://preflight-updated", (e) => cb(e.payload));
  },

  async listenConfigChanged(cb: (cfg: AppConfig) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<AppConfig>("guard://config-changed", (e) => cb(e.payload));
  },

  async listenNavigate(cb: (nav: NavigatePayload) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<NavigatePayload>("guard://navigate", (e) => cb(e.payload));
  },

  async listenConfirmExit(cb: (bgProcs: number) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<number>("guard://confirm-exit", (e) => cb(e.payload));
  },

  async listenNakedLaunchIntercepted(cb: (count: number) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<number>("guard://naked-launch-intercepted", (e) => cb(e.payload));
  },

  async listenUpdateProgress(
    cb: (progress: {
      stage: string;
      downloadedBytes: number;
      totalBytes?: number | null;
      percent?: number | null;
    }) => void
  ): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen("guard://update-progress", (e) =>
      cb(
        e.payload as {
          stage: string;
          downloadedBytes: number;
          totalBytes?: number | null;
          percent?: number | null;
        }
      )
    );
  },

  async getDeepAuditStatus(): Promise<DeepAuditProgress> {
    if (!isTauriRuntime()) {
      return {
        running: false,
        phase: "idle",
        currentIndex: 0,
        total: 0,
        currentNode: "",
        originalNode: "",
        currentNodeVerified: false,
        message: "",
      };
    }
    return invoke<DeepAuditProgress>("get_deep_audit_status");
  },

  async startDeepNodeAudit(
    forceAll = false,
    targetNode?: string,
    targetNodes?: string[]
  ): Promise<DeepAuditProgress> {
    if (!isTauriRuntime()) {
      return {
        running: false,
        phase: "done",
        currentIndex: 0,
        total: 0,
        currentNode: "",
        originalNode: "",
        currentNodeVerified: true,
        message: "预览模式：深度核验仅在桌面客户端中执行真实代理探测。",
      };
    }
    return invoke<DeepAuditProgress>("start_deep_node_audit", {
      forceAll,
      targetNode: targetNode ?? null,
      targetNodes: targetNodes && targetNodes.length > 0 ? targetNodes : null,
    });
  },

  async cancelDeepNodeAudit(): Promise<DeepAuditProgress> {
    if (!isTauriRuntime()) {
      return {
        running: false,
        phase: "cancelled",
        currentIndex: 0,
        total: 0,
        currentNode: "",
        originalNode: "",
        currentNodeVerified: false,
        message: "预览模式已停止核验",
      };
    }
    return invoke<DeepAuditProgress>("cancel_deep_node_audit");
  },

  async resetNodeDriftBaseline(): Promise<string> {
    if (!isTauriRuntime()) {
      return "预览模式：已重置当前节点的 24h 漂移基准。";
    }
    return invoke<string>("reset_node_drift_baseline");
  },

  async inspectClaudeDataRoots(): Promise<ClaudeDataRootsSummary> {
    if (!isTauriRuntime()) {
      return {
        classicDetected: true,
        msixPackages: ["AnthropicPBC.Claude_fnn82j28hfe8t"],
        telemetryExists: true,
      };
    }
    return invoke<ClaudeDataRootsSummary>("inspect_claude_data_roots");
  },

  async listenNodeAuditProgress(
    cb: (progress: DeepAuditProgress) => void
  ): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<DeepAuditProgress>("guard://node-audit-progress", (e) => cb(e.payload));
  },

  async inspectRollbackStatus(): Promise<RollbackOverview> {
    if (!isTauriRuntime()) {
      const items = mockRollbackItems.map((it) => ({ ...it }));
      return {
        baselineExists: true,
        baselinePath: "~/.fd-claude-guard/system-baseline.json",
        isElevated: true,
        loopbackDnsAdapters: [...mockLoopbackDnsAdapters],
        activeFirewallRules: false,
        touchedCount: items.filter((i) => i.touchedByGuard).length,
        items,
      };
    }
    return invoke<RollbackOverview>("inspect_rollback_status_cmd");
  },

  async rollbackSingleItem(itemId: string): Promise<RollbackActionReport> {
    if (!isTauriRuntime()) {
      const target = mockRollbackItems.find((i) => i.id === itemId);
      if (target) {
        target.touchedByGuard = false;
        target.canRollback = false;
        target.currentSummary = "已按首次基线快照精准还原至使用前原状";
      }
      const overview = await ipc.inspectRollbackStatus();
      return {
        itemId,
        ok: true,
        message: `预览模式：已完成「${target?.title ?? itemId}」精准撤回并复测无残留。`,
        overview,
      };
    }
    return invoke<RollbackActionReport>("rollback_single_item_cmd", { itemId });
  },

  async rollbackAllChanges(): Promise<RollbackBatchReport> {
    if (!isTauriRuntime()) {
      const revertedIds: string[] = [];
      const skippedIds: string[] = [];
      for (const it of mockRollbackItems) {
        if (it.touchedByGuard) {
          it.touchedByGuard = false;
          it.canRollback = false;
          it.currentSummary = "已按首次基线快照精准还原至使用前原状";
          revertedIds.push(it.id);
        } else {
          skippedIds.push(it.id);
        }
      }
      const overview = await ipc.inspectRollbackStatus();
      return {
        allOk: true,
        revertedIds,
        skippedIds,
        failed: [],
        summary: `预览模式：已成功撤回全部 ${revertedIds.length} 项系统/Clash 改动，电脑已还原至使用前状态。`,
        overview,
      };
    }
    return invoke<RollbackBatchReport>("rollback_all_changes_cmd");
  },

  async runNetworkEmergencyRescue(): Promise<NetworkRescueReport> {
    if (!isTauriRuntime()) {
      mockLoopbackDnsAdapters.length = 0;
      return {
        ok: true,
        isElevated: true,
        directConnectivityOk: true,
        steps: [
          {
            step: "恢复物理网卡 DNS",
            ok: true,
            detail: "已将 以太网(#6) 的死 DNS (127.0.0.1) 恢复为自动获取 (DHCP) 并复测通过。",
          },
          {
            step: "清理失效系统代理",
            ok: true,
            detail: "未检测到悬空失效的 Windows 系统代理。",
          },
          {
            step: "清除防火墙阻断规则",
            ok: true,
            detail: "当前无本工具残留的防火墙阻断规则。",
          },
          {
            step: "刷新 DNS 并实测国内直连",
            ok: true,
            detail: "已刷新系统 DNS 缓存，实测国内直连可达（无需开 TUN 也可正常上网与导入订阅）。",
          },
        ],
        summary: "网络急救完成！物理网卡 DNS、系统代理与防火墙均已恢复正常，国内直连实测畅通。",
      };
    }
    return invoke<NetworkRescueReport>("run_network_emergency_rescue_cmd");
  },

  async auditAccountLocal(profileId?: string): Promise<AccountAuditReport> {
    if (!isTauriRuntime()) {
      return buildMockAccountAuditReport(profileId ?? "default");
    }
    return invoke<AccountAuditReport>("audit_account_local", {
      profileId: profileId ?? null,
    });
  },

  async getAccountAuditHistoryReport(orgPrefix8: string): Promise<AccountAuditReport | null> {
    if (!isTauriRuntime()) {
      const key = orgPrefix8.trim().toLowerCase();
      return buildMockHistoryReportByOrg(key);
    }
    return invoke<AccountAuditReport | null>("get_account_audit_history_report", {
      orgPrefix8,
    });
  },

  async deleteAccountAuditHistory(orgPrefix8: string): Promise<ArchivedAccountSummary[]> {
    if (!isTauriRuntime()) {
      const key = orgPrefix8.trim().toLowerCase();
      mockDeletedHistoryOrgs.add(key);
      return buildMockArchivedSummaries();
    }
    return invoke<ArchivedAccountSummary[]>("delete_account_audit_history", {
      orgPrefix8,
    });
  },

  async verifyAccountCloudWithSk(
    rawInput: string,
    profileId?: string,
    allowSwitchPrimary = false
  ): Promise<AccountAuditReport> {
    if (!isTauriRuntime()) {
      mockAccountCloudVerifiedCount += 1;
      return buildMockAccountAuditReport(profileId ?? "default");
    }
    return invoke<AccountAuditReport>("verify_account_cloud_with_sk", {
      profileId: profileId ?? null,
      rawInput,
      allowSwitchPrimary,
    });
  },

  async fixClaudeTelemetryEnv(profileId?: string): Promise<AccountAuditActionResult> {
    if (!isTauriRuntime()) {
      mockTelemetryEnvFixed = true;
      const report = buildMockAccountAuditReport(profileId ?? "default");
      return {
        ok: true,
        action: "fix_claude_telemetry_env",
        message: "已无损补齐 4/4 隐私降噪环境变量（已锁定首次基线，可随时精准撤回）。",
        report,
      };
    }
    return invoke<AccountAuditActionResult>("fix_claude_telemetry_env", {
      profileId: profileId ?? null,
    });
  },

  async cleanClaudeTelemetryDir(profileId?: string): Promise<AccountAuditActionResult> {
    if (!isTauriRuntime()) {
      mockTelemetryDirBytes = 0;
      const report = buildMockAccountAuditReport(profileId ?? "default");
      return {
        ok: true,
        action: "clean_claude_telemetry_dir",
        message: "已清空 ~/.claude/telemetry 待传目录。",
        report,
      };
    }
    return invoke<AccountAuditActionResult>("clean_claude_telemetry_dir", {
      profileId: profileId ?? null,
    });
  },

  async restoreClaudeOfficialEndpoint(profileId?: string): Promise<AccountAuditActionResult> {
    if (!isTauriRuntime()) {
      const report = buildMockAccountAuditReport(profileId ?? "default");
      return {
        ok: true,
        action: "restore_claude_official_endpoint",
        message: "已备份并还原官方原生 API 端点。",
        report,
      };
    }
    return invoke<AccountAuditActionResult>("restore_claude_official_endpoint", {
      profileId: profileId ?? null,
    });
  },

  async cleanClaudeCliCredentialsWithBackup(
    profileId?: string
  ): Promise<AccountAuditActionResult> {
    if (!isTauriRuntime()) {
      const report = buildMockAccountAuditReport(profileId ?? "default");
      return {
        ok: true,
        action: "clean_claude_cli_credentials_with_backup",
        message: "已先原子备份再清理 CLI 旧凭据与历史备份，重新登录同一主号即可。",
        report,
      };
    }
    return invoke<AccountAuditActionResult>("clean_claude_cli_credentials_with_backup", {
      profileId: profileId ?? null,
    });
  },

  async checkAppUpdate(): Promise<AppUpdateInfo> {
    if (!isTauriRuntime()) {
      return {
        currentVersion: __APP_VERSION__,
        available: false,
        latestVersion: __APP_VERSION__,
        publishedAt: null,
        notes: null,
        viaProxy: false,
        message: `当前已是最新版本 v${__APP_VERSION__}（浏览器预览模式）。`,
      };
    }
    return invoke<AppUpdateInfo>("check_app_update");
  },

  async installAppUpdate(): Promise<string> {
    if (!isTauriRuntime()) {
      return "浏览器预览模式不执行安装包下载。";
    }
    return invoke<string>("install_app_update");
  },

  async openExternalUrl(url: string): Promise<void> {
    if (!isTauriRuntime()) {
      if (typeof window !== "undefined") {
        window.open(url, "_blank", "noopener,noreferrer");
      }
      return;
    }
    await invoke<void>("open_external_url", { url });
  },
};

let mockAccountCloudVerifiedCount = 0;
let mockTelemetryEnvFixed = false;
let mockTelemetryDirBytes = 0;
const mockDeletedHistoryOrgs = new Set<string>();

function buildMockArchivedSummaries(): ArchivedAccountSummary[] {
  const all: ArchivedAccountSummary[] = [
    {
      orgPrefix8: "a4722ea6",
      emailMasked: "jaso***11@gmail.com",
      plan: "Free",
      workspaceGeo: "US",
      exitCountry: "US",
      score: 96,
      scoreLevel: "safe",
      scoreLevelLabel: "低危稳健",
      scoreColorToken: "green",
      cloudVerified: true,
      verifyCount: 2,
      hasDangerIssue: false,
      pendingIssueCount: 0,
      personaKycStatus: "verified",
      hasMonitoringNotice: false,
      isBanned: false,
      portalHold: false,
      fiveHourPct: 12,
      sevenDayPct: 28,
      auditedAtMs: Date.now() - 3 * 3600_000,
      hasFullReport: true,
    },
    {
      orgPrefix8: "0ffb0302",
      emailMasked: "star***at@outlook.com",
      plan: "Free",
      workspaceGeo: "US",
      exitCountry: "US",
      score: 88,
      scoreLevel: "safe",
      scoreLevelLabel: "低危稳健",
      scoreColorToken: "green",
      cloudVerified: true,
      verifyCount: 1,
      hasDangerIssue: false,
      pendingIssueCount: 1,
      personaKycStatus: "expired",
      hasMonitoringNotice: true,
      isBanned: false,
      portalHold: false,
      fiveHourPct: null,
      sevenDayPct: null,
      auditedAtMs: Date.now() - 45 * 60_000,
      hasFullReport: true,
    },
  ];
  return all.filter((x) => !mockDeletedHistoryOrgs.has(x.orgPrefix8.toLowerCase()));
}

function buildMockHistoryReportByOrg(orgKey: string): AccountAuditReport | null {
  if (mockDeletedHistoryOrgs.has(orgKey)) return null;
  const base = buildMockAccountAuditReport("default");
  if (orgKey === "a4722ea6") {
    return {
      ...base,
      profileId: "history:a4722ea6",
      auditedAtMs: Date.now() - 3 * 3600_000,
      emailMasked: "jaso***11@gmail.com",
      orgIdPrefix8: "a4722ea6",
      plan: "Free",
      merchantChannel: "Free 无订阅",
      accountAgeDays: 85,
      subscriptionAgeDays: null,
      subscriptionRenewLabel: "Free 无订阅",
      workspaceGeo: "US",
      exitCountry: "US",
      exitColo: "SJC",
      geoConsistency: "match",
      cloudVerified: true,
      cloudStale: false,
      cloudAgeDays: 0,
      verifyCount: 2,
      cloudSnapshot: {
        verifiedAtMs: Date.now() - 3 * 3600_000,
        checkedAtIso: new Date(Date.now() - 3 * 3600_000).toISOString(),
        emailMasked: "jaso***11@gmail.com",
        orgIdPrefix8: "a4722ea6",
        plan: "Free",
        merchantChannel: "Free 无订阅",
        workspaceGeo: "US",
        edgeCountry: "US",
        edgeColo: "SJC",
        accountAgeDays: 85,
        subscriptionAgeDays: null,
        subscriptionEndsAt: null,
        chatAvailable: true,
        isBanned: false,
        appealsRedirectEnabled: false,
        hasMonitoringNotice: false,
        activeFlagTypes: [],
        warningSummaryZh: null,
        personaKycStatus: "verified",
        personaKycCompletedAt: "2026-11-20T06:02:33Z",
        personaKycAgeHours: 140,
        portalHold: false,
        portalState: "clear",
        fiveHourPct: 12,
        fiveHourResetsAt: null,
        sevenDayPct: 28,
        sevenDayResetsAt: null,
        warnings: [],
      },
      quota: {
        ...base.quota,
        fiveHourPct: 12,
        sevenDayPct: 28,
        stampShort: "3小时前",
      },
      scoreResult: {
        ...base.scoreResult,
        score: 96,
        level: "safe",
        levelLabel: "低危稳健",
        colorToken: "green",
        confidence: "full_combined",
        confidenceLabel: "本地+云端综合",
        blindSpotNote: null,
        deductions: [],
      },
      pendingIssueCount: 0,
      hasDangerIssue: false,
      archivedAccounts: [],
    };
  }
  if (orgKey === "0ffb0302") {
    return {
      ...base,
      profileId: "history:0ffb0302",
      auditedAtMs: Date.now() - 45 * 60_000,
      emailMasked: "star***at@outlook.com",
      orgIdPrefix8: "0ffb0302",
      plan: "Free",
      merchantChannel: "Free 无订阅",
      accountAgeDays: 86,
      subscriptionAgeDays: null,
      subscriptionRenewLabel: "Free 无订阅",
      workspaceGeo: "US",
      exitCountry: "US",
      exitColo: "SJC",
      geoConsistency: "match",
      cloudVerified: true,
      cloudStale: false,
      cloudAgeDays: 0,
      verifyCount: 1,
      cloudSnapshot: {
        verifiedAtMs: Date.now() - 45 * 60_000,
        checkedAtIso: new Date(Date.now() - 45 * 60_000).toISOString(),
        emailMasked: "star***at@outlook.com",
        orgIdPrefix8: "0ffb0302",
        plan: "Free",
        merchantChannel: "Free 无订阅",
        workspaceGeo: "US",
        edgeCountry: "US",
        edgeColo: "SJC",
        accountAgeDays: 86,
        subscriptionAgeDays: null,
        subscriptionEndsAt: null,
        chatAvailable: true,
        isBanned: false,
        appealsRedirectEnabled: false,
        hasMonitoringNotice: true,
        activeFlagTypes: ["access_block", "api_disabled:kyc_pending"],
        warningSummaryZh: "访问封锁 · API 受限(kyc_pending)",
        personaKycStatus: "expired",
        personaKycCompletedAt: null,
        personaKycAgeHours: null,
        portalHold: false,
        portalState: "unknown",
        fiveHourPct: null,
        fiveHourResetsAt: null,
        sevenDayPct: null,
        sevenDayResetsAt: null,
        warnings: [],
      },
      scoreResult: {
        ...base.scoreResult,
        score: 88,
        level: "safe",
        levelLabel: "低危稳健",
        colorToken: "green",
        confidence: "full_combined",
        confidenceLabel: "本地+云端综合",
        blindSpotNote: null,
      },
      pendingIssueCount: 1,
      hasDangerIssue: false,
      archivedAccounts: [],
    };
  }
  return null;
}

export function buildMockAccountAuditReport(profileId = "default"): AccountAuditReport {
  const verified = mockAccountCloudVerifiedCount > 0;
  const secondVerify = mockAccountCloudVerifiedCount >= 2;
  const telMissing = mockTelemetryEnvFixed
    ? []
    : ["DISABLE_TELEMETRY", "DISABLE_BUG_COMMAND"];
  // 严格与 100 分权重模型一致：未核验封顶 85（100 - 10 混登 - 3 遥测 = 87 → 封顶 85）
  const localRawScore = 100 - 10 - (telMissing.length > 0 ? 3 : 0);
  const score = !verified ? Math.min(85, localRawScore) : secondVerify ? 98 : 69;

  return {
    profileId,
    auditedAtMs: Date.now(),
    emailMasked: "stev***88@gmail.com",
    orgIdPrefix8: "7aacf131",
    plan: "Pro",
    merchantChannel: "Stripe 直付",
    accountAgeDays: 33,
    subscriptionAgeDays: 33,
    localDeviceAgeDays: 28,
    subscriptionRenewLabel: verified ? "到期 2026-12-22" : "预计续费 ~12-22",
    subscriptionRenewIsEstimated: !verified,
    workspaceGeo: verified ? "US" : null,
    exitCountry: verified && !secondVerify ? "AU" : "US",
    exitColo: verified && !secondVerify ? "SYD" : "SJC",
    exitIpPurity: "住宅段",
    geoConsistency: !verified
      ? "pending"
      : secondVerify
      ? "match"
      : "cross_continent_mismatch",
    cloudVerified: verified,
    cloudStale: false,
    cloudAgeDays: verified ? 0 : null,
    verifyCount: mockAccountCloudVerifiedCount,
    cloudSnapshot: verified
      ? {
          verifiedAtMs: Date.now(),
          checkedAtIso: new Date().toISOString(),
          emailMasked: "stev***88@gmail.com",
          orgIdPrefix8: "7aacf131",
          plan: "Pro",
          merchantChannel: "Stripe 直付",
          workspaceGeo: "US",
          edgeCountry: secondVerify ? "US" : "AU",
          edgeColo: secondVerify ? "SJC" : "SYD",
          accountAgeDays: 33,
          subscriptionAgeDays: 33,
          subscriptionEndsAt: "2026-12-22",
          chatAvailable: true,
          isBanned: false,
          appealsRedirectEnabled: false,
          hasMonitoringNotice: !secondVerify,
          activeFlagTypes: secondVerify ? [] : ["monitoring_notice"],
          warningSummaryZh: secondVerify ? null : "后台观察标",
          personaKycStatus: "verified",
          personaKycCompletedAt: "2026-10-24T00:00:00Z",
          personaKycAgeHours: 720,
          portalHold: false,
          portalState: "clear",
          fiveHourPct: secondVerify ? 18 : 34,
          sevenDayPct: secondVerify ? 42 : 64,
          warnings: [],
        }
      : null,
    quota: {
      fiveHourPct: !verified ? 22 : secondVerify ? 18 : 34,
      sevenDayPct: !verified ? 72 : secondVerify ? 42 : 64,
      stampShort: verified ? "刚刚" : "9天前",
      stampTooltip: verified ? "云端核验 · 刚刚同步" : "本地缓存 · 9 天前采样",
      fiveHourOfflineNote: null,
      softLocked: false,
      source: verified ? "official_probe" : "local_config",
    },
    scoreResult: {
      score,
      maxScore: 100,
      level: score >= 85 ? "safe" : score >= 70 ? "watch" : "mid_high",
      levelLabel: score >= 85 ? "低危稳健" : score >= 70 ? "建议优化" : "中高风险",
      colorToken: score >= 85 ? "green" : score >= 70 ? "amber" : "orange",
      confidence: verified ? "full_combined" : "local_only",
      confidenceLabel: verified ? "本地+云端综合" : "本地评估",
      disclaimer:
        "防御参考分（非 Anthropic 官方黑盒风控分）；高分不承诺永不封号，低分仅代表存在可优化隐患。",
      blindSpotNote: verified
        ? null
        : "当前仅基于本地数据评估（封顶 85）；云端核验后可补全官方警告、KYC 与真实属地，评分更真实完整",
      deductions: [
        ...(verified && !secondVerify
          ? [
              {
                id: "geo_mismatch",
                weightMax: 24,
                delta: -24,
                deltaLabel: "-24",
                tone: "danger",
                title: "归属地与出口跨洲错配（权重 24 分）",
                desc: "账号属地 US 与当前出口 AU(SYD) 跨洲，建议尽快切回美区稳定节点",
              },
              {
                id: "monitoring_notice",
                weightMax: 12,
                delta: -12,
                deltaLabel: "-12",
                tone: "warn",
                title: "云端命中后台观察标（权重 12 分）",
                desc: "对话仍可用，但账号已进观察队列，容错率下降",
              },
            ]
          : []),
        ...(!secondVerify
          ? [
              {
                id: "multi_account_mix",
                weightMax: 16,
                delta: -10,
                deltaLabel: "-10",
                tone: "warn",
                title: "CLI 与桌面端混登不同组织（权重 16 分）",
                desc: "CLI (7aacf131) 与桌面端日志 (a4722ea6) 不一致，存在跨端残留风险",
              },
            ]
          : []),
        ...(telMissing.length > 0
          ? [
              {
                id: "telemetry_env_missing",
                weightMax: 4,
                delta: -3,
                deltaLabel: "-3",
                tone: "muted",
                title: "隐私遥测降噪开关未补齐（权重 4 分）",
                desc: `settings.json 缺少 ${telMissing.length} 项降噪变量，可一键补齐并支持撤回`,
              },
            ]
          : []),
        ...(verified
          ? [
              {
                id: "persona_kyc_buffer",
                weightMax: 5,
                delta: 5,
                deltaLabel: "+5",
                tone: "ok",
                title: "已通过 Persona 实名认证（护城河缓冲）",
                desc: "已过 72h 稳定期，账号抗误杀能力显著高于白号",
              },
            ]
          : [
              {
                id: "local_blind_spot_cap",
                weightMax: 85,
                delta: 0,
                deltaLabel: "封顶 85",
                tone: "muted",
                title: "尚未完成云端核验（存在云端盲区）",
                desc: "暂无法读取官方静默标、KYC 与隐藏属地，本地评估上限封顶 85 分",
              },
            ]),
      ],
    },
    local: {
      profileId,
      scannedAtMs: Date.now(),
      claudeJson: {
        exists: true,
        emailMasked: "stev***88@gmail.com",
        orgUuidPrefix8: "7aacf131",
        planLabel: "Pro",
        billingType: "stripe_subscription",
        merchantChannel: "Stripe 直付",
        accountAgeDays: 33,
        subscriptionAgeDays: 33,
        localDeviceAgeDays: 28,
        machineIdPrefix8: "4cfdc2d2",
        userIdPrefix8: "e084f6b6",
      },
      credentials: {
        exists: true,
        subscriptionType: "pro",
        scopes: ["user:inference"],
        mcpOauthProviders: [],
      },
      hygiene: {
        cliInstalled: true,
        settingsExists: true,
        privacyEnvFlags: {
          DISABLE_TELEMETRY: mockTelemetryEnvFixed,
          DISABLE_ERROR_REPORTING: true,
          CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: true,
          DISABLE_BUG_COMMAND: mockTelemetryEnvFixed,
        },
        privacyEnabledCount: mockTelemetryEnvFixed ? 4 : 2,
        privacyMissingKeys: telMissing,
        settingsNonOfficialEndpoint: null,
        systemEnvEndpointConflicts: [],
        telemetryFileCount: mockTelemetryDirBytes > 0 ? 3 : 0,
        telemetryTotalBytes: mockTelemetryDirBytes,
        scheduledTasksCount: 0,
        activeScheduledTasksCount: 0,
        historicalScheduledTasksCount: 0,
        scheduledTasksDir: null,
        backupFileCount: 5,
        backupAccounts: [
          {
            orgPrefix: "7aacf131",
            emailMasked: "stev***88@gmail.com",
            planLabel: "Pro",
            merchantChannel: "Stripe 直付",
            backupCount: 5,
          },
        ],
      },
      behavior: {
        projectsDirExists: true,
        filesScanned7d: 4,
        last5h: { assistantTurns: 8, sidechainTurns: 0, inputTokens: 12000, outputTokens: 3000, cacheReadTokens: 8000 },
        last24h: { assistantTurns: 36, sidechainTurns: 0, inputTokens: 60000, outputTokens: 18000, cacheReadTokens: 40000 },
        last7d: { assistantTurns: 180, sidechainTurns: 4, inputTokens: 320000, outputTokens: 90000, cacheReadTokens: 210000 },
        subagentRatio24hPct: 0,
        activeHours24h: 6,
        overnightBotRhythmSuspected: false,
      },
      desktop: {
        discoveredDirs: ["LocalAppData"],
        scannedLogFiles: 5,
        orgIdPrefixes: secondVerify ? ["7aacf131"] : ["a4722ea6"],
        accountBannedHits: 0,
        portalVerifyHits: 0,
        crossOrg404Hits: 0,
        oauth403Hits: 7,
        cookie403Hits: 0,
        cfShield403Hits: 1,
        rateLimit429Hits: 0,
        planChangedHits: 0,
        fiveHourSoftLockHits: 0,
        maxSideSessionsSeen: 0,
        highSideSessionHits: 0,
        mcpErrorHits: 0,
        mcpErrorStorm: false,
        disconnectHits: 10,
        recentSamples: [],
      },
      crossClientOrgMismatch: !secondVerify,
      allObservedOrgPrefixes: secondVerify ? ["7aacf131"] : ["7aacf131", "a4722ea6"],
    },
    runtimeClashPort: 7890,
    runtimeProxyOk: true,
    runtimeBgProcs: 0,
    runtimeKillHoldActive: false,
    runtimeKillHoldSecs: 0,
    runtimeDisconnectGuardOk: true,
    runtimeDisconnectGaps: [],
    denoisedOauth403Count: 7,
    logFlowItems: [
      {
        id: "audit-sample-cf_403",
        cat: "403",
        denoised: false,
        chipLabel: "403 消歧 · CF 入口盾",
        chipTone: "warn",
        title: "Cloudflare 网页拦截盾（出口节点 IP 问题，非账号封禁）",
        desc: "main.log 捕获 1 次网页 403 挑战盾，属于节点 IP 弹盾；建议前往「节点流量」切换干净同区节点。",
        timeLabel: "19:41:18 · main.log:3512",
        rawSanitized: "[2026-11-25 19:41:18] navigation to https://claude.ai/ failed with status code 403",
        count: 1,
      },
      {
        id: "audit-sample-disconnect",
        cat: "net",
        denoised: false,
        chipLabel: "代理断连 · x10",
        chipTone: "neutral",
        title: "代理长连接瞬时断开（0 次回传 Cookie 403）",
        desc: "节点短暂抖动导致连接重置，期间未检出高危退出回传 Cookie 403。",
        timeLabel: "16:05:00 · main.log:3069",
        rawSanitized: "[2026-11-25 16:05:00] Request failed: net::ERR_CONNECTION_CLOSED",
        count: 10,
      },
      {
        id: "audit-sample-oauth_403",
        cat: "403",
        denoised: true,
        chipLabel: "已自动降噪 · 背景 OAuth 403 · x7",
        chipTone: "neutral",
        title: "客户端背景轮询未开通特性接口返回 OAuth 403 (permission_error)",
        desc: "结合当前 Pro 套餐事实已归类为正常特性权限边界（非 KYC、非封号），默认静默降噪。",
        timeLabel: "近期 · main.log",
        rawSanitized: "authorize returned 403 permission_error (len=164)",
        count: 7,
      },
    ],
    pendingIssueCount: secondVerify ? 0 : (mockTelemetryEnvFixed ? 1 : 2) + (verified ? 1 : 0),
    hasDangerIssue: verified && !secondVerify,
    primarySource: secondVerify ? "cli_and_desktop" : "desktop_web",
    detectedAccounts: secondVerify
      ? [
          {
            orgPrefix8: "7aacf131",
            emailMasked: "stev***88@gmail.com",
            plan: "Pro",
            clientSource: "桌面端+CLI",
            displayLabel: "stev***88@gmail.com (Pro · 桌面端+CLI · 7aacf131)",
            isPrimary: true,
          },
        ]
      : [
          {
            orgPrefix8: "7aacf131",
            emailMasked: "stev***88@gmail.com",
            plan: "Pro",
            clientSource: "CLI",
            displayLabel: "stev***88@gmail.com (Pro · CLI · 7aacf131)",
            isPrimary: true,
          },
          {
            orgPrefix8: "a4722ea6",
            emailMasked: null,
            plan: null,
            clientSource: "桌面端",
            displayLabel: "桌面端账号 (本地不含邮箱 · org a4722ea6)",
            isPrimary: false,
          },
        ],
    topology: secondVerify
      ? {
          hygieneState: "clean_synced_single",
          headline: "桌面端与 CLI 同号一致（stev***88@gmail.com），无混登或跨 orgId 竞态",
          detail: "双端组织完全一致、无失效凭据与跨号残留。",
          desktopStatus: "single",
          desktopAccounts: ["stev***88@gmail.com (Pro · 桌面端+CLI · 7aacf131)"],
          cliStatus: "active",
          cliAccount: "stev***88@gmail.com (Pro · 桌面端+CLI · 7aacf131)",
          cliStaleReasons: [],
          sessionDirOrphans: [],
          hasCliCleanupTarget: true,
        }
      : {
          hygieneState: "cross_surface_mix",
          headline:
            "跨端混登预警：桌面端 [桌面端账号 (本地不含邮箱 · org a4722ea6)] 与 CLI [stev***88@gmail.com (Pro · CLI · 7aacf131)] 账号不一致",
          detail:
            "桌面端与 CLI 当前记录属于不同账号；打开分项清理弹窗可默认双端全清，也可取消勾选保留你想留的那一端。",
          desktopStatus: "single",
          desktopAccounts: ["桌面端账号 (本地不含邮箱 · org a4722ea6)"],
          cliStatus: "active",
          cliAccount: "stev***88@gmail.com (Pro · CLI · 7aacf131)",
          cliStaleReasons: [],
          sessionDirOrphans: [],
          hasCliCleanupTarget: true,
        },
    archivedAccounts: buildMockArchivedSummaries(),
  };
}

const mockLoopbackDnsAdapters: string[] = ["以太网 (#6)"];
const mockRollbackItems: RollbackOverview["items"] = [
  {
    id: "clash_rules",
    title: "Clash 策略组与覆写脚本（Claude-Fixed）",
    category: "Clash 配置",
    touchedByGuard: true,
    canRollback: true,
    originalSummary: "原无 Claude-Fixed 策略组与全局 Script.js",
    currentSummary: "当前 Clash 配置中存在 Claude-Fixed 规则/脚本",
    riskNote: "精准移除 Claude-Fixed 策略组与规则并热重载，100% 保留你后续新导入的所有订阅。",
  },
  {
    id: "sys_ipv6",
    title: "物理网卡 IPv6 绑定与系统优先策略",
    category: "Windows 网络",
    touchedByGuard: true,
    canRollback: true,
    originalSummary: "已记录 1 张物理网卡原态；DisabledComponents 原值=8",
    currentSummary: "已由本工具禁用物理网卡 IPv6",
    riskNote: "若校园网、内网或 NAS 依赖 IPv6，可随时一键恢复修改前的精确原值。",
  },
  {
    id: "sys_location",
    title: "Windows 系统定位权限与 lfsvc 服务",
    category: "Windows 隐私",
    touchedByGuard: true,
    canRollback: true,
    originalSummary: "HKLM=Allow / HKCU=Allow / lfsvc Start=3",
    currentSummary: "已由本工具关闭定位并停用 lfsvc",
    riskNote: "撤回后将恢复天气、地图、自动时区等依赖 Windows 定位的系统功能。",
  },
  {
    id: "sys_webrtc",
    title: "Chrome / Edge WebRTC 浏览器组策略",
    category: "浏览器策略",
    touchedByGuard: false,
    canRollback: false,
    originalSummary: "本工具未写入过浏览器组策略",
    currentSummary: "保持系统原状",
    riskNote: "撤回后可消除浏览器「由你的组织管理」提示，并恢复网页视频会议直连 UDP。",
  },
  {
    id: "sys_env",
    title: "系统代理（WinINET）与环境变量",
    category: "Windows 网络",
    touchedByGuard: false,
    canRollback: false,
    originalSummary: "本工具未修改过系统代理或环境变量",
    currentSummary: "保持系统原状",
    riskNote: "撤回后恢复修改前的环境变量、WinINET 代理与 Claude settings.json 原值。",
  },
  {
    id: "firewall",
    title: "Defender 防火墙熔断规则与守护计划任务",
    category: "Windows 安全",
    touchedByGuard: false,
    canRollback: false,
    originalSummary: "使用前无 FDClaudeGuard 防火墙规则与计划任务",
    currentSummary: "防火墙规则：已放行(0)｜计划任务：未安装",
    riskNote: "卸载前或排障时一键彻底清除所有本工具防火墙拦截规则与守护任务，防止永久封死 Claude。",
  },
];
