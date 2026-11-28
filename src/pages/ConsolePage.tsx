import { useEffect, useState } from "react";
import { Check, ChevronRight, Copy, ExternalLink, Loader2, Lock, Play, Power, RefreshCw } from "lucide-react";
import { CheckIcon } from "@/components/CheckIcon";
import { ThinScrollArea } from "@/components/ThinScrollArea";
import { ipc, isTauriRuntime } from "@/lib/ipc";
import { FULL_AUDIT_INTERVAL_MS, formatCleanNodeName } from "@/lib/protocol";
import { useGuardStore } from "@/stores/guardStore";
import type { PreflightItem } from "@/types/guard";

export interface EvidenceKvRow {
  k: string;
  v: string;
  tone?: "bad" | "warn" | "ok";
}

/** 剥离 Windows WebView2 下退化为灰色小字母 us/cn 的国旗 Emoji，保持控制台摘要整洁可读 */
function stripFlagEmoji(text: string): string {
  return (text || "").replace(/[\u{1F1E6}-\u{1F1FF}]{2}\s*/gu, "");
}

/** 将底层探针全部英文键名 100% 映射为自然易读的中文标签（覆盖 19 项预检与 Rust 真实探针） */
export function formatEvidenceKeyZh(rawKey: string): string {
  const k = rawKey.trim().replace(/^\d+\.\s+/, "");
  const exactMap: Record<string, string> = {
    Endpoint: "通信管道",
    Kernel: "代理内核",
    "Mihomo GET /proxies": "代理组接口",
    "Mihomo tun.enable": "虚拟网卡开关",
    "Mihomo dns.enhanced-mode": "内核 DNS 解析模式",
    "TUN 接管开关": "虚拟网卡接管",
    "Wintun Adapter": "虚拟网卡状态",
    "Wintun / Mihomo Adapter": "虚拟网卡状态",
    "Clash Verge Service": "代理系统服务",
    "Clash 系统服务": "代理系统服务",
    "Real DNS Probe (claude.ai)": "主站 DNS 解析",
    "Claude 真实 DNS": "主站 DNS 解析",
    "Fake-IP (198.18.0.0/15)": "虚拟 DNS 网段",
    "Proxy Exit GeoIP & Anthropic Stateless Probe": "出口属地与连通",
    "Windows ms_tcpip6 & External IPv6 Probe": "网卡 IPv6 探针",
    "Windows IPv6": "网卡 IPv6 绑定",
    "物理网卡 ms_tcpip6": "物理网卡 IPv6",
    "注册表 Tcpip6 DisabledComponents": "系统 IPv6 注册表",
    "CLI Proxy ENV & WinINET ProxyServer": "环境变量与系统代理",
    "Windows Location ConsentStore & lfsvc Service": "定位权限与服务状态",
    "Windows Location": "Windows 定位服务",
    "Local Contamination Scan": "本地污染残留扫描",
    "Bound Primary orgId & Cross-orgId Scan": "绑定主号与跨号扫描",
    "ANTHROPIC_BASE_URL / API_URL": "官方接口校验",
    ANTHROPIC_BASE_URL: "官方接口校验",
    "官方 API 地址校验": "官方接口校验",
    "settings.json ANTHROPIC_BASE_URL / API_URL": "配置文件接口",
    "System ENV (HKCU/HKLM) API Endpoints": "系统环境变量接口",
    "CLI Env (HTTP/HTTPS/ALL_PROXY & NO_PROXY)": "终端代理变量",
    "CLI 代理环境变量": "终端代理变量",
    WinINET: "系统代理设置",
    "系统代理 (WinINET)": "系统代理设置",
    File: "配置文件",
    "Claude Code CLI Installed": "命令行客户端",
    "Claude Code CLI": "命令行客户端",
    "Telemetry Cache (~/.claude/telemetry)": "遥测待传缓存",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "关闭非必要后台流量",
    DISABLE_TELEMETRY: "关闭遥测统计",
    DISABLE_ERROR_REPORTING: "关闭错误堆栈上报",
    DISABLE_BUG_COMMAND: "关闭诊断反馈",
    "关闭 /bug 上报": "关闭诊断反馈",
    "Read-only Startup Audit": "开机自启项审计",
    "FD Claude Guard": "本守护启动器",
    "Clash Verge Rev": "代理客户端自启",
    "Claude Desktop": "桌面端自启",
    "NTP Drift Probe": "时钟同步探针",
    "NTP Server": "对时服务器",
    "NTP 对时服务器": "对时服务器",
    "UTC Drift": "时钟偏差",
    "UTC 时钟偏差": "时钟偏差",
    "SNTP Probe Error": "对时探测错误",
    "Elevated Helper Task": "免弹窗守护任务",
    "Rule Prefix": "防火墙规则前缀",
    "Rule Probe (FDClaudeGuard_KillSwitch_*)": "防火墙读写实测",
    "Browser WebRtcIPHandling Policy": "浏览器防泄露策略",
    "WebRTC Policy": "浏览器防泄露策略",
    "Google Chrome (已安装)": "谷歌浏览器策略",
    "Microsoft Edge (已安装)": "微软浏览器策略",
    "System Timezone vs Exit Region": "系统时区与出口比对",
    "Exit Geo Compliance & 24h Drift": "出口合规与稳定性",
    "Browser Proxy Extensions Audit": "浏览器代理插件审计",
    "Scanned Browser Profiles": "已扫描浏览器配置",
    "Proxy / VPN Extensions Found": "检出代理插件数",
    "Detected Proxy Extensions": "检出的代理插件",
    "Scanned Log Files": "已扫描日志文件",
    "Scanned Claude Log Files": "已扫描日志文件",
    "Confirmed Ban / Region Contamination Hits": "封号/禁区污染命中",
    "KYC / Permission-Pending (len=164) Notice": "实名与权限提示",
    "Topology Hygiene State": "多端拓扑卫生状态",
    "Desktop Accounts": "桌面端账号",
    "CLI (~/.claude.json)": "终端登录态",
    "Bound Primary Account": "已绑定主号",
    "Primary Candidate Label": "主号候选标识",
    "Observed Unique orgIds": "观测到账号组织",
    "Observed Unique accountIds": "关联账户数",
    "Cross-orgId Race Hits": "跨号并发冲突数",
    "CLI Stale / Cross-Polluted Reasons": "终端失效/跨号原因",
    "Claude-Data Session Dir Orphans": "残留会话目录",
    "Restricted / Portal-Verify Accounts": "受限/待核验账号",
    "Latest Cross-Account Sample": "最近跨号样本",
    "Clash Mode": "代理路由模式",
    "Claude-Fixed": "固定策略组",
    Group: "锁定策略组",
    "Node Safe": "节点安全基线",
    "Claude Rules": "核心分流规则",
    "Matched Claude Rules": "核心分流规则",
    "Claude 命中规则": "核心分流规则",
    "Core/KYC": "认证与服务分流",
    "核心与 KYC 分流": "认证与服务分流",
    "Exit Probe": "出口实时探针",
    "Telemetry REJECT": "遥测拦截规则",
    "CF Shield & Stripe": "人机盾与支付分流",
    "CF 盾与 Stripe 分流": "人机盾与支付分流",
    "Cross-Group": "跨组冲突检查",
    "Cross-Group CF/Stripe Advisory": "跨组冲突提示",
    Processes: "进程兜底规则",
    "find-process-mode": "进程识别模式",
    ipv6: "内核网络 IPv6",
    "Mihomo ipv6": "内核网络 IPv6",
    "内核 IPv6 开关": "内核网络 IPv6",
    "dns.ipv6": "域名解析 IPv6",
    "DNS IPv6 开关": "域名解析 IPv6",
    "Reference Active Node": "当前活跃参考节点",
    "Probe Status": "探针状态",
    Proxy: "本地代理地址",
    Source: "探测来源",
    Latency: "实测延迟",
    "Exit IP": "真实出口地址",
    "ASN / Org": "归属运营商",
    "归属运营商 / ASN": "归属运营商",
    "Anthropic API (api.anthropic.com)": "官方接口连通",
    "Anthropic API 连通": "官方接口连通",
    "Target Locked Node": "目标锁定节点",
    "Deep Audit Running": "后台核验进度",
    "Current Probing": "当前探测节点",
    "Local Logs": "本地日志审计",
    Timezone: "系统时区",
    "24h Landing IP Drift": "24h 落地稳定性",
    "24h 落地 IP 漂移": "24h 落地稳定性",
    "Bound Account Geo vs Exit": "属地与出口比对",
    "账号属地与出口比对": "属地与出口比对",
    "Claude Web (claude.ai/login)": "网页端登录入口",
    Error: "错误详情",
  };
  if (exactMap[k]) return exactMap[k];
  if (/^Port\s+\d+/i.test(k)) return k.replace(/^Port\s+/i, "代理端口 ");
  if (/^Conflict Ports/i.test(k)) return "冲突端口";
  if (/^Observed(?: Unique)? orgIds/i.test(k)) return k.replace(/^Observed(?: Unique)? orgIds/i, "关联组织数");
  if (/^Observed(?: Unique)? accountIds/i.test(k)) return k.replace(/^Observed(?: Unique)? accountIds/i, "关联账户数");
  if (/^Single-Account KYC\/Auth Notice/i.test(k)) return "单号认证说明";
  if (/^外网 IPv6 连通探针/.test(k)) return "外网 IPv6 连通";
  if (/^Mihomo GET /i.test(k)) return "代理组接口";
  return k;
}

/** 将常见底层英文探针值转为温和简洁中文（查看原始探针代码时仍保留 100% 原文） */
export function formatEvidenceValueZh(rawVal: string): string {
  const v = rawVal.trim();
  const exactValMap: Record<string, string> = {
    "Not Installed": "未安装",
    Inactive: "未激活",
    "Default Official": "官方默认",
    Yes: "已安装",
    "No (Auto-Exempt)": "未安装（自动豁免）",
    Missing: "未配置",
    "Not Set": "未写入",
    "Blocked / Unreachable (OK)": "已阻断 / 不可达（安全）",
    "REACHABLE (LEAK!)": "可直连（存在泄漏）",
    "All Physical Adapters Disabled (OK)": "全部物理网卡已禁用",
    SingleSurfaceClean: "单端纯净（安全）",
    "未登录 [status=empty]": "未登录",
    "Running (clash_verge_service)": "运行中（系统服务）",
    "MATCHED (OK)": "已命中（安全）",
    "Safe (合规范围)": "合规安全",
    Writable: "可读写（就绪）",
    Online: "在线",
    normal: "标准模式",
    "0 (Clean)": "0 命中（安全）",
    "0 files (0 B)": "无待传缓存",
    "WebRtcIPHandling = disable_non_proxied_udp": "已禁用非代理直连",
    "HKLM / HKCU\\Software\\Policies\\{Google\\Chrome, Microsoft\\Edge}": "系统 / 用户策略注册表",
    true: "已开启",
    false: "已关闭",
    None: "无",
  };
  if (exactValMap[v]) return exactValMap[v];
  if (/^\\\\\.\\pipe\\verge-mihomo/i.test(v)) return "Mihomo 命名管道（在线）";
  if (/^Named Pipe\s+/i.test(v)) return v.replace(/^Named Pipe\s+/i, "命名管道 ");
  if (/^Online\s*\((.+)\)$/i.test(v)) return v.replace(/^Online\s*\((.+)\)$/i, "在线 ($1)");
  if (/^Offline\b/i.test(v)) return v.replace(/^Offline\b/i, "离线");
  if (/^Exempt\s*\((.+)\)$/i.test(v)) return v.replace(/^Exempt\s*\((.+)\)$/i, "已豁免 ($1)");
  if (/^Enabled on:\s*/i.test(v)) return v.replace(/^Enabled on:\s*/i, "仍启用：");
  if (/^Stable \(24h 内未漂移\) \(count=0\)$/i.test(v)) return "稳定未漂移（0 次）";
  if (/^"?1"?\s*\(已开启降噪\)$/.test(v)) return "已开启降噪";
  if (/^\d+\/\d+\s+OK$/i.test(v)) return v.replace(/\s+OK$/i, " 已覆盖（安全）");
  if (/^\d+\/\d+\s+同源\s+OK$/i.test(v)) return v.replace(/\s+OK$/i, "（安全）");
  if (/REJECT 已拦截 \(OK\)$/i.test(v)) return v.replace(/REJECT 已拦截 \(OK\)$/, "已拦截（安全）");
  return formatCleanNodeName(v)
    .replace(/\s*\(手动固定单节点=true\)/g, "（手动固定）")
    .replace(/\s*\[status=[^\]]+\]/gi, "")
    .replace(/\s*\(count=(\d+)\)/gi, "（$1 次）")
    .replace(/→\s*(?:[\u{1F1E6}-\u{1F1FF}]{2}\s*)+/gu, "→ ");
}

function splitEvidencePair(part: string): [string, string] | null {
  // 1. 优先按 ": " 或 "：" 拆分，防止将 IPv6 (2606:4700::1111) 或 len=164 拆断
  const colonSpace = part.match(/^([^：]{1,72}?)(?::\s+|：\s*)(.+)$/);
  if (colonSpace) {
    return [colonSpace[1].trim(), colonSpace[2].trim()];
  }
  // 2. 次选不包含括号内参数的 Key=Value 或紧凑 Key:Value
  const eqMatch = part.match(/^([^:=：\s()]{1,64})\s*=\s*(.+)$/);
  if (eqMatch) {
    return [eqMatch[1].trim(), eqMatch[2].trim()];
  }
  const fallback = part.match(/^([^:=：]{1,64}?)\s*[:=：]\s*(.+)$/);
  if (fallback) {
    return [fallback[1].trim(), fallback[2].trim()];
  }
  return null;
}

/**
 * 安全可降级的实测证据键值解析器：
 * 支持单行及多行 Key: Value / Key=Value 解析，直接以中文结构化指标行清晰展示；
 * 仅对无法解析的纯堆栈/长代码串降级由折叠代码框承载。
 */
export function isAutoFixableByOneClick(item: PreflightItem): boolean {
  switch (item.id) {
    case "node_group":
    case "node_dns":
    case "sys_env":
    case "claude_endpoint":
    case "claude_tel":
      return true;
    case "node_proxy":
      return !item.summary.includes("占用");
    case "node_tun":
      return !item.summary.includes("未安装") && !item.evidence.includes("Not Installed");
    case "node_geo":
      return item.status === "warn";
    case "sys_ipv6":
    case "sys_location":
    case "claude_ban":
    case "claude_acct":
      return false;
    default:
      return false;
  }
}

export function parseEvidenceKv(evidence: string): EvidenceKvRow[] | null {
  if (!evidence) return null;
  const rawParts = evidence
    .split(/\r?\n|\s+\|\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (rawParts.length < 1) return null;

  const rows: EvidenceKvRow[] = [];
  for (const part of rawParts) {
    if (/^说明[:：]/.test(part)) continue;
    const pair = splitEvidencePair(part);
    if (!pair) return null;
    const [rawK, rawV] = pair;
    if (
      !rawK ||
      !rawV ||
      /^https?$/i.test(rawK) ||
      rawK.includes("\\") ||
      /^[A-Za-z]$/.test(rawK)
    ) {
      return null;
    }
    const k = formatEvidenceKeyZh(rawK);
    const v = formatEvidenceValueZh(rawV);
    // 单号卫生锁中「主号候选标识」若与「已绑定主号」完全重复，跳过冗余行
    if (
      k === "主号候选标识" &&
      rows.some((prev) => prev.k === "已绑定主号" && prev.v === v)
    ) {
      continue;
    }

    const isSafeText =
      /^(ok|pass|true|enabled|online|clean|0\s*(?:项|条|个)?[^。\n]*冲突|0\s*(?:命中|项|命中（干净）|\(clean\))|已通过|正常|在线|无泄漏|官方默认|管理员直写就绪|未登录|未登录（环境纯净）|已确认继续使用当前号|已核实放行（本次会话）|无)$/i.test(
        v
      ) ||
      /\(OK\)|（安全）|（就绪）|已阻断|无直连豁免|原生直连|已开启降噪|已豁免|已禁用非代理|全部物理网卡已禁用|稳定未漂移|已拦截/i.test(
        `${rawV} ${v}`
      );
    const isSoftNotice =
      /非封号|不阻断启动|待确认当前号|仍为上次污染节点|存在旧凭据或会话残留|warn|drift|待实测|待探测|待审计|待实查|待检测|待核对|待扫描|警告/i.test(
        `${rawV} ${v}`
      );

    let tone: EvidenceKvRow["tone"];
    if (isSafeText) {
      tone = "ok";
    } else if (isSoftNotice) {
      tone = "warn";
    } else if (
      /fail|error|leak|deny|offline|not installed|inactive|missing|requires admin|portal_verification|persona_kyc_verification|实锤|清记录 \+ 换节点|异常|失败|未通过|离线|未安装|未激活|未配置|泄漏|检出多账号遗留|需更换当前节点|已失效|交叉残留/i.test(
        `${rawV} ${v}`
      ) ||
      (/冲突/i.test(`${rawV} ${v}`) && !/0\s*(?:项|条|个)?[^。\n]*冲突/i.test(`${rawV} ${v}`))
    ) {
      tone = "bad";
    }
    rows.push({ k, v, tone });
  }
  return rows.length >= 1 ? rows : null;
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
  const [confirmingAcct, setConfirmingAcct] = useState(false);
  const [ackingBanWarn, setAckingBanWarn] = useState(false);
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
  const mustPending = mustAll.length - mustOk;
  const mustFail = mustPending;
  const hardFailCount = mustAll.filter((x) => x.status === "fail").length;
  const warnCount = mustAll.filter((x) => x.status === "warn").length;
  const autoFixableCount = mustAll.filter(
    (x) => x.status !== "ok" && isAutoFixableByOneClick(x)
  ).length;
  const optAll = items.filter((x) => x.part === "opt");
  const optOk = optAll.filter((x) => x.status === "ok").length;

  const blocked = mustFail > 0 || snapshot.killSwitchActive || snapshot.nodeDown;
  const guardStatusPill = snapshot.killSwitchActive
    ? {
        dotClass: "guard-dot danger",
        label: "已自动熔断",
        color: "var(--bad-fg)",
        cursor: "pointer" as const,
        title: "防火墙已锁死 Claude 全部出站流量，点击前往「安全策略」解除或处理",
        onClick: () => useGuardStore.getState().openSettingsModal("policy"),
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

  const handleConfirmCurrentAccount = async () => {
    if (confirmingAcct || checking || fixing) return;
    setConfirmingAcct(true);
    try {
      const nextReport = await ipc.confirmCurrentAccount();
      useGuardStore.getState().setPreflightFromEvent(nextReport);
      if (isTauriRuntime()) {
        const snap = await ipc.getSnapshot().catch(() => null);
        if (snap) useGuardStore.getState().setSnapshot(snap);
      } else {
        const mustItems = nextReport.items.filter((x) => x.part === "must");
        const okCount = mustItems.filter((x) => x.status === "ok").length;
        const curSnap = useGuardStore.getState().snapshot;
        useGuardStore.getState().setSnapshot({
          ...curSnap,
          mustPassed: okCount,
          mustTotal: mustItems.length,
        });
      }
      pushToast("已确认继续使用当前号", "单号卫生锁已放行，本机未检出其他账号混登。", "ok");
    } catch (err) {
      pushToast("确认当前号失败", String(err), "danger");
    } finally {
      setConfirmingAcct(false);
    }
  };

  const handleAckBanWarn = async (toastTitle: string) => {
    if (ackingBanWarn || checking || fixing) return;
    setAckingBanWarn(true);
    try {
      const nextReport = await ipc.acknowledgeBanWarnSession();
      useGuardStore.getState().setPreflightFromEvent(nextReport);
      if (isTauriRuntime()) {
        const snap = await ipc.getSnapshot().catch(() => null);
        if (snap) useGuardStore.getState().setSnapshot(snap);
      } else {
        const mustItems = nextReport.items.filter((x) => x.part === "must");
        const okCount = mustItems.filter((x) => x.status === "ok").length;
        const curSnap = useGuardStore.getState().snapshot;
        useGuardStore.getState().setSnapshot({
          ...curSnap,
          mustPassed: okCount,
          mustTotal: mustItems.length,
        });
      }
      pushToast(toastTitle, "当前会话已核实并放行本次风险提示。", "ok");
    } catch (err) {
      pushToast("确认放行失败", String(err), "danger");
    } finally {
      setAckingBanWarn(false);
    }
  };

  /**
   * 控制台必须项点击处理：
   * - claude_ban：弹出透明分项清理弹窗，或引导前往节点流量换节点
   * - claude_acct：单号 Warn 时确认当前号或清理；多号 Fail 时仅引导清理全部登录状态
   */
  const handleFixItemClick = (item: PreflightItem) => {
    if (item.id === "node_geo" || item.id === "opt_exit_geo") {
      setActiveTab("nodes");
      setNodesSubTab("quality");
      return;
    }
    if (item.id === "claude_ban") {
      if (item.status === "warn" && item.fixLabel?.includes("节点流量")) {
        setActiveTab("nodes");
        setNodesSubTab("quality");
        return;
      }
      openCleanModal({
        sourceLabel: "来自控制台 · 本地封号与身份认证审查",
      });
      return;
    }

    if (item.id === "claude_acct") {
      if (
        item.status === "warn" &&
        (item.fixLabel?.includes("确认继续使用当前号") || item.summary.includes("确认"))
      ) {
        void handleConfirmCurrentAccount();
        return;
      }
      openCleanModal({
        sourceLabel: "来自控制台 · 单号卫生锁（清理登录状态）",
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
              {stripFlagEmoji(it.summary)}
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
              onClick={() => useGuardStore.getState().openSettingsModal("policy")}
              title="已开启 24h 冷静保护期，点击前往「安全策略」调整"
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
          ) : mustPending >= 2 && autoFixableCount >= 1 ? (
            <button
              type="button"
              data-testid="btn-batch-fix-all"
              className="guard-btn guard-btn-primary"
              disabled={checking || fixing}
              onClick={() => void oneClickFixAll()}
            >
              {fixing && <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />}
              <span>{fixing ? "处理中..." : `一键处理全部 (${autoFixableCount})`}</span>
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
                {snapshot.nodeDown && mustPending === 0
                  ? "节点不可用 · 请更换"
                  : hardFailCount > 0
                  ? `请先处理 ${hardFailCount} 项未通过`
                  : `请先确认 ${Math.max(1, warnCount)} 项风险`}
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

      {/* 黄金双栏 + 各自独立 3×46px ThinScrollArea（收窄右栏让主列表更舒展） */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: "grid",
          gridTemplateColumns: "minmax(0, 1fr) clamp(292px, 27%, 340px)",
        }}
      >
        <ThinScrollArea style={{ borderRight: "1px solid var(--divider)" }}>
          <div
            style={{
              padding: "14px 12px 20px",
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
                        ? {
                            color: hardFailCount > 0 ? "var(--bad-fg)" : "var(--warning-fg)",
                            fontWeight: 500,
                          }
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
              padding: "14px 12px 20px",
              display: "flex",
              flexDirection: "column",
              gap: 10,
            }}
          >
            {selectedItem && (
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {/* 右侧顶部无外框标题头：与左侧「一、必须通过 + 分类标题」水平齐平，使下方内容卡片与左侧列表卡片顶齐 */}
                <div
                  style={{
                    minHeight: 42,
                    padding: "2px 2px 4px",
                    display: "flex",
                    alignItems: "center",
                    gap: 10,
                  }}
                >
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
                      title={selectedItem.title}
                      style={{
                        fontSize: 13.5,
                        fontWeight: 500,
                        lineHeight: 1.3,
                        color: "var(--text-strong)",
                        margin: 0,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                    >
                      {selectedItem.title}
                    </h2>
                    <div
                      className="tabular"
                      style={{
                        marginTop: 3,
                        display: "flex",
                        alignItems: "center",
                        gap: 6,
                        fontSize: 11,
                        color: "var(--text-3)",
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
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

                {/* 详情卡 1：当前状态摘要（与左侧第一张卡片顶边齐平） */}
                <div className="guard-card" style={{ padding: "12px 14px" }}>
                  <p
                    style={{
                      fontSize: 12,
                      color: "var(--text-1)",
                      margin: 0,
                      lineHeight: 1.58,
                      minHeight: 38,
                    }}
                  >
                    {stripFlagEmoji(selectedItem.summary)}
                  </p>
                </div>

                {/* 详情卡 2：实测探针数据直接展示；原始代码探针日志点击折叠查看 */}
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
                      <div className="c-det-hd">
                        <span className="c-det-title">真实探针实测数据</span>
                        <button
                          type="button"
                          className={`c-copy-btn ${copiedEvidence ? "is-copied" : ""}`}
                          onClick={() => void copyEvidenceText()}
                        >
                          {copiedEvidence ? (
                            <Check size={11.5} strokeWidth={1.9} />
                          ) : (
                            <Copy size={11.5} strokeWidth={1.5} />
                          )}
                          <span>{copiedEvidence ? "已复制" : "复制诊断"}</span>
                        </button>
                      </div>

                      {kvRows && (
                        <div
                          className="c-kv-list tabular"
                          style={{ maxHeight: 260, overflowY: "auto" }}
                        >
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
                      )}

                      <div style={{ marginTop: kvRows ? 9 : 2 }}>
                        <button
                          type="button"
                          data-testid="btn-toggle-probe-evidence"
                          aria-expanded={showRawEvidence}
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
                            whiteSpace: "nowrap",
                          }}
                        >
                          <ChevronRight
                            size={12}
                            strokeWidth={1.65}
                            style={{
                              transform: showRawEvidence ? "rotate(90deg)" : "none",
                              transition: "transform 140ms var(--ease)",
                              flexShrink: 0,
                            }}
                          />
                          <span>{showRawEvidence ? "收起原始探针代码" : "查看原始探针代码"}</span>
                        </button>

                        {showRawEvidence && (
                          <div
                            className="font-mono-code tabular"
                            style={{
                              marginTop: 7,
                              maxHeight: 180,
                              overflowY: "auto",
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
                    </div>
                  );
                })()}

                {/* 详情卡 3：处理方式与验证说明 */}
                <div className="guard-card" style={{ padding: "12px 14px" }}>
                  <div className="c-det-hd">
                    <span className="c-det-title">处理方式与验证说明</span>
                    <span className="c-det-meta">{selectedItem.mode}</span>
                  </div>
                  <div
                    data-testid="guide-plaintext"
                    style={{
                      fontSize: 12,
                      color: "var(--text-2)",
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
                      ) : selectedItem.id === "claude_ban" ? (
                        <>
                          {selectedItem.status === "fail" ? (
                            <>
                              <button
                                type="button"
                                data-testid="btn-ban-clean-records"
                                className="guard-btn guard-btn-primary"
                                disabled={fixing || checking}
                                style={{ width: "100%", height: 32 }}
                                onClick={() =>
                                  openCleanModal({
                                    sourceLabel: "来自控制台 · 本地封号与身份认证审查",
                                  })
                                }
                              >
                                <span>清理账户记录（备份）</span>
                              </button>
                              <button
                                type="button"
                                data-testid="btn-ban-switch-node"
                                className="guard-btn guard-btn-flat"
                                disabled={fixing || checking}
                                style={{ width: "100%" }}
                                onClick={() => {
                                  setActiveTab("nodes");
                                  setNodesSubTab("quality");
                                }}
                              >
                                <span>前往「节点流量」更换节点 →</span>
                              </button>
                            </>
                          ) : (
                            <>
                              <button
                                type="button"
                                data-testid="btn-ban-switch-node"
                                className="guard-btn guard-btn-primary"
                                disabled={fixing || checking || ackingBanWarn}
                                style={{ width: "100%", height: 32 }}
                                onClick={() => {
                                  setActiveTab("nodes");
                                  setNodesSubTab("quality");
                                }}
                              >
                                <span>前往「节点流量」更换节点 →</span>
                              </button>
                              <button
                                type="button"
                                data-testid="btn-ban-ack-warn"
                                className="guard-btn guard-btn-flat"
                                disabled={fixing || checking || ackingBanWarn}
                                style={{ width: "100%" }}
                                onClick={() => void handleAckBanWarn("已确认节点 IP 已更换")}
                              >
                                {ackingBanWarn && (
                                  <Loader2 size={12.5} strokeWidth={1.85} className="guard-spin" />
                                )}
                                <span>已确认节点 IP 已更换，本次放行</span>
                              </button>
                            </>
                          )}
                        </>
                      ) : selectedItem.id === "claude_acct" ? (
                        <>
                          {selectedItem.status === "warn" &&
                          (selectedItem.fixLabel?.includes("确认继续使用当前号") ||
                            selectedItem.summary.includes("确认")) ? (
                            <>
                              <button
                                type="button"
                                data-testid="btn-acct-confirm-current"
                                className="guard-btn guard-btn-primary"
                                disabled={confirmingAcct || fixing || checking}
                                style={{ width: "100%", height: 32 }}
                                onClick={() => void handleConfirmCurrentAccount()}
                              >
                                {confirmingAcct && (
                                  <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />
                                )}
                                <span>
                                  {confirmingAcct ? "正在确认当前号..." : "确认继续使用当前号"}
                                </span>
                              </button>
                              <button
                                type="button"
                                data-testid="btn-acct-clean-state"
                                className="guard-btn guard-btn-flat"
                                disabled={confirmingAcct || fixing || checking}
                                style={{ width: "100%" }}
                                onClick={() =>
                                  openCleanModal({
                                    sourceLabel: "来自控制台 · 单号卫生锁（清理登录状态）",
                                  })
                                }
                              >
                                <span>不是当前号，清理登录状态</span>
                              </button>
                            </>
                          ) : (
                            <button
                              type="button"
                              data-testid="btn-acct-clean-state"
                              className="guard-btn guard-btn-primary"
                              disabled={fixing || checking}
                              style={{ width: "100%", height: 32 }}
                              onClick={() =>
                                openCleanModal({
                                  sourceLabel: "来自控制台 · 单号卫生锁（清理登录状态）",
                                })
                              }
                            >
                              <span>{selectedItem.fixLabel || "清理登录状态（先备份）"}</span>
                            </button>
                          )}
                        </>
                      ) : selectedItem.fixLabel ? (
                        <button
                          type="button"
                          className="guard-btn guard-btn-primary"
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
