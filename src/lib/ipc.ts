import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { DIAG_MANIFEST_MAGIC, FULL_AUDIT_INTERVAL_MS } from "@/lib/protocol";
import type {
  ActivateLicenseResult,
  AppConfig,
  AppConfigPatch,
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
  LicenseStatus,
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
  statusLabel: "11 项待办",
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
  mustTotal: 11,
  optPassed: 0,
  optTotal: 6,
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
      title: "出口节点合规与真实可达性",
      status: "fail",
      summary: "尚未探测出口白名单、落地 IP 防漂移、ASN 纯净度与 Anthropic 真实可达性",
      evidence: "Proxy Exit GeoIP & Anthropic Stateless Probe: 待探测",
      guide: "强制经本地代理探测出口国家、ASN 纯净度与 api.anthropic.com 无状态可达性（筛除 CF 403）。",
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
        currentNode: "US-LA-Static-01",
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
    if (!isTauriRuntime()) return [];
    return invoke<ClaudeConn[]>("get_live_connections");
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
      const events: LogEvent[] = cleanedLogs
        ? []
        : [
            {
              id: "mock-oauth-v2-72",
              ruleId: "pb_pay",
              anomaly: true,
              simulated: false,
              acked: false,
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
      return {
        ...FALLBACK_SNAPSHOT,
        unreadLogAnomalies: 0,
        unreadLogCritical: 0,
        unreadLogWarnings: 0,
      };
    }
    return invoke<GuardSnapshot>("ack_log_events", { ids });
  },

  async previewAnonymousFeedbackPayload(): Promise<string> {
    if (!isTauriRuntime()) {
      return JSON.stringify(
        {
          schemaVersion: 2,
          appVersion: "0.2.7",
          installIdHash: "9f2a8c1d",
          toolDiagnostics: {
            clashVersion: "Mihomo v1.19.23",
            clashPort: 7897,
            clashOnline: true,
            regionCode: "AU",
            killSwitchActive: false,
            mustPassed: 11,
            mustTotal: 11,
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
        samplePaths: string[]
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
        };
      };
      return {
        detectedInstallModes: ["微软商店 MSIX 版", "经典安装版 (Roaming/Local)", "Claude Code CLI"],
        activeClaudeProcs: 0,
        categories: [
          makeCat(
            "auth",
            "桌面端登录态、Cookie 与 OAuth 凭证",
            "清除后立即退出本地桌面端登录态（Cookies / Local Storage / Session Storage / OAuth config.json）。",
            true,
            true,
            18,
            2_516_582,
            [
              "MSIX\\AnthropicPBC.Claude\\Roaming\\Claude\\Network\\Cookies",
              "%LOCALAPPDATA%\\Claude-Data\\anthropicpbc.claude\\config.json",
            ]
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

  async getLicenseStatus(): Promise<LicenseStatus> {
    if (!isTauriRuntime()) {
      if (typeof window !== "undefined") {
        const params = new URLSearchParams(window.location.search);
        const licParam = params.get("licensed");
        if (licParam === "0" || (isQaPreviewMode() && licParam !== "1")) {
          return {
            commercialFeatureEnabled: true,
            licensed: false,
            activatedAt: null,
            batchId: null,
            installIdShort: "qa-inst01",
            machineFpShort: "qa-fp9981",
            apiEndpoint: "https://license.fdclaudeguard.workers.dev/api/v1/activate",
          };
        }
      }
      return {
        commercialFeatureEnabled: true,
        licensed: true,
        activatedAt: "2026-11-24T00:00:00Z",
        batchId: "PREVIEW",
        installIdShort: "preview01",
        machineFpShort: "previewfp",
        apiEndpoint: "https://license.fdclaudeguard.workers.dev/api/v1/activate",
      };
    }
    return invoke<LicenseStatus>("get_license_status_cmd");
  },

  async activateLicense(licenseKey: string): Promise<ActivateLicenseResult> {
    if (!isTauriRuntime()) {
      const cleaned = licenseKey.trim().toUpperCase();
      if (!/^FDG-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(cleaned)) {
        throw new Error("激活密钥格式错误（应为 FDG-XXXX-XXXX-XXXX）");
      }
      return {
        licensed: true,
        activatedAt: new Date().toISOString(),
        batchId: "PREVIEW",
        message: "预览模式核销成功：已解锁清晰方案与自动修复。",
      };
    }
    return invoke<ActivateLicenseResult>("activate_license_cmd", { licenseKey });
  },

  async listenLicenseChanged(cb: (status: LicenseStatus) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<LicenseStatus>("guard://license-changed", (e) => cb(e.payload));
  },

  async listenConfirmExit(cb: (bgProcs: number) => void): Promise<UnlistenFn> {
    if (!isTauriRuntime()) return () => {};
    return listen<number>("guard://confirm-exit", (e) => cb(e.payload));
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
    targetNode?: string
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
};

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
