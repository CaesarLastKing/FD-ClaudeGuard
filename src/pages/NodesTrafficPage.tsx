import { useEffect, useState } from "react";
import { Check, Loader2, RefreshCw, Search } from "lucide-react";
import { HoverTooltip, useHoverTooltip } from "@/components/HoverTooltip";
import { ThinScrollArea } from "@/components/ThinScrollArea";
import { ipc } from "@/lib/ipc";
import { DROP_RATE_REDLINE, extractRegionCode, isSameRegionSwitch } from "@/lib/protocol";
import { useGuardStore } from "@/stores/guardStore";
import type { ClaudeConn, NodeItem } from "@/types/guard";

type NodeFilterTab = "usable" | "same" | "quarantine";
type FlowFilterTab = "all" | "anomaly" | "rejected" | "unlisted";

/** 大白话状态悬停解释（0ms 浮现，让普通用户一秒看懂拉黑/弹盾/落地禁区/AGY 限区/超时原因） */
function getClaudeBadgeTip(status: string, label: string, detail?: string): string {
  const detailSuffix = detail && detail.trim() ? `\n实测明细：${detail.trim()}` : "";
  if (status === "cf_403" || label.includes("拉黑")) {
    return `拉黑：该节点出口 IP 已被 Cloudflare 403 或 Anthropic 封禁，无法访问 Claude，已隔离禁用。${detailSuffix}`;
  }
  if (status === "cf_challenge" || label.includes("弹盾")) {
    return `弹盾：API 勉强能通，但 claude.ai 网页登录触发 Cloudflare 人机拦截盾；桌面端/网页端易反复弹验证并提高风控，仅标风险不禁用，不推荐作主力。${detailSuffix}`;
  }
  if (status === "blocked" || label.includes("禁区")) {
    return `落地禁区：节点名称虽看似合规，但实测真实出口 IP 落入 HK / MO / CN / RU 等 Anthropic 禁区黑名单（常见于广播 IP 或香港落地伪装线路），严禁使用 Claude。${detailSuffix}`;
  }
  if (status === "offline" || label.includes("超时")) {
    return `Claude 超时：节点在 Clash 中基础网络可能正常，但访问 api.anthropic.com 连续 2 次超时或连接被重置；仅短缓存 5 分钟，可点右上「重测超时类」批量复核。${detailSuffix}`;
  }
  if (status === "ok") {
    return `Anthropic API 与 claude.ai 网页登录均实测畅通，无 Cloudflare 拦截盾。${detailSuffix}`;
  }
  return "尚未完成真实代理深度核验（我们绝不造假绿灯）；后台会自动逐个慢速核验，也可点右上角「深度核验全部」或按分类重测立即实测。";
}

function getGeminiBadgeTip(status: string, label: string): string {
  if (
    status === "cn_redirect" ||
    status === "restricted" ||
    status === "limited" ||
    label.includes("限区") ||
    label.includes("送中")
  ) {
    return "AGY 限区（标记风险 · 不禁用）：Google 将该节点出口识别为中国香港或受限地区（如跳转 google.com.hk / 返回地区不支持），说明该 IP 在 Google 侧存在地区混杂或送中风险，Antigravity (AGY) 不可用；但实测 Claude 畅通，故仅标记风险、允许继续用于 Claude。";
  }
  if (status === "ok") {
    return "Google Antigravity (AGY) 地区准入附带参考探针实测放行可用。";
  }
  if (label.includes("离线")) {
    return "节点基础网络超时离线，无法探测 AGY 服务。";
  }
  return "尚未完成 Antigravity (AGY) 附带参考实测；逐个深度核验后将自动记录结果。";
}

function getNodeTypeTip(riskLevel: string, asnShort: string): string {
  if (riskLevel === "abuser" || asnShort.includes("滥用") || asnShort.includes("拉黑")) {
    return "高危滥用：该出口 IP 命中公开滥用/黑名单情报库，极易触发 Claude 封号或 403，控制台将阻断启动。";
  }
  if (riskLevel === "proxy" || asnShort.includes("共享代理")) {
    return "共享代理：该出口 IP 被标记为公共 VPN / 多人共享代理段，控制台将阻断启动，强烈建议避开。";
  }
  if (riskLevel === "isp" || asnShort.includes("ISP")) {
    return "ISP 住宅：经 IP 情报核验为原生住宅宽带或静态 ISP 线路，无代理黑名单标记，防封最稳。";
  }
  if (riskLevel === "hosting" || asnShort.includes("机房")) {
    return "常规机房：云服务商机房段（0 滥用记录、非公共 VPN），控制台允许通过，建议配合稳定不漂移使用。";
  }
  if (asnShort.includes("禁区")) {
    return "落地禁区：实测该节点真实出口国家落入 Anthropic 禁区黑名单（例如挂台湾名实际落地香港 HK），严禁使用。";
  }
  return "尚未对该节点执行真实出口 IP 核验；核验结果将永久缓存 24 小时（超时节点仅缓存 5 分钟，发生漂移会自动失效重测）。";
}

/** 隐藏常规 HTTPS 默认 :443 端口，保留非 443 端口 */
function formatDisplayHost(rawHost: string): string {
  if (!rawHost) return "";
  return rawHost.endsWith(":443") ? rawHost.slice(0, -4) : rawHost;
}

/** 将 Mihomo 原始 rule 字段精炼为去重后的中文规则名 + 简短类型码（彻底去除与左侧主机重复的域名后缀） */
function formatRuleSummary(
  rawRule: string,
  isRejected: boolean,
  isAnomaly: boolean
): { label: string; code: string; tip: string } {
  const trimmed = (rawRule || "Match").trim();
  const baseType = trimmed.split(/[(\s,]/)[0] || trimmed;
  const upper = baseType.toUpperCase();

  let label = "分流规则";
  if (isRejected) {
    label = "防回传拦截";
  } else if (upper === "MATCH") {
    label = isAnomaly ? "兜底直连" : "兜底规则";
  } else if (upper.includes("PROCESS")) {
    label = "进程兜底";
  } else if (upper === "DOMAINSUFFIX" || upper === "DOMAIN-SUFFIX") {
    label = "域名规则";
  } else if (upper === "DOMAINKEYWORD" || upper === "DOMAIN-KEYWORD") {
    label = "关键词规则";
  } else if (upper === "DOMAIN") {
    label = "精确域名";
  } else if (upper.includes("IPCIDR") || upper.includes("IP-CIDR")) {
    label = "IP 网段";
  } else if (upper.includes("RULESET") || upper.includes("RULE-SET")) {
    label = "规则集";
  }

  return {
    label,
    code: baseType,
    tip: `原始命中规则：${trimmed}`,
  };
}

/** 解析出口链路：正常经 Claude-Fixed 放行默认隐藏组名前缀只显示落地节点；仅异常或阻断展示完整状态 */
function formatChainSummary(
  conn: ClaudeConn,
  groupName: string,
  isRejected: boolean
): { main: string; sub: string; tone: "ok" | "bad" | "muted"; tip: string } {
  const parts = (conn.chain || "")
    .split("→")
    .map((s) => s.trim())
    .filter(Boolean);
  const lastNode = parts[parts.length - 1] || conn.chain || "DIRECT";

  if (conn.anomaly) {
    return {
      main: lastNode,
      sub: `脱出 ${groupName}`,
      tone: "bad",
      tip: `完整链路：${conn.chain}\n该连接未走锁定策略组 ${groupName}，存在暴露真实 IP 或串区风险。`,
    };
  }
  if (isRejected) {
    return {
      main: lastNode,
      sub: "防回传已阻断",
      tone: "muted",
      tip: `完整链路：${conn.chain}\n已由防回传规则自动静默拦截，不影响正常对话。`,
    };
  }
  const withoutGroup = parts.filter((p) => p !== groupName);
  const cleanExit = withoutGroup[withoutGroup.length - 1] || lastNode;
  return {
    main: cleanExit,
    sub: "",
    tone: "ok",
    tip: `完整链路：${conn.chain}\n常规连接已默认隐藏策略组前缀 ${groupName}。`,
  };
}

/** 基于 startedAtMs 实时格式化持续时长；阻断态显「已阻断」；缺时间戳优雅回退 c.time */
function formatConnDuration(conn: ClaudeConn, nowMs: number, isRejected: boolean): string {
  if (isRejected) return "已阻断";
  if (typeof conn.startedAtMs === "number" && Number.isFinite(conn.startedAtMs)) {
    const secs = Math.max(0, Math.floor((nowMs - conn.startedAtMs) / 1000));
    if (secs < 60) return `${secs}s`;
    const mins = Math.floor(secs / 60);
    const remS = secs % 60;
    if (mins < 60) return `${mins}m ${String(remS).padStart(2, "0")}s`;
    const hours = Math.floor(mins / 60);
    const remM = mins % 60;
    return `${hours}h ${String(remM).padStart(2, "0")}m`;
  }
  return conn.time || "--:--:--";
}

export function NodesTrafficPage() {
  const subTab = useGuardStore((s) => s.nodesSubTab);
  const setSubTab = useGuardStore((s) => s.setNodesSubTab);
  const [nodeFilter, setNodeFilter] = useState<NodeFilterTab>("usable");
  const [flowFilter, setFlowFilter] = useState<FlowFilterTab>("all");
  const [conns, setConns] = useState<ClaudeConn[]>([]);
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const [refreshingNodes, setRefreshingNodes] = useState(false);
  const [loadingConns, setLoadingConns] = useState(false);
  const [closingConnId, setClosingConnId] = useState<string | null>(null);
  const { tip, showTip, hideTip } = useHoverTooltip();

  const snapshot = useGuardStore((s) => s.snapshot);
  const nodeReport = useGuardStore((s) => s.nodeReport);
  const deepAudit = useGuardStore((s) => s.deepAudit);
  const config = useGuardStore((s) => s.config);
  const fixing = useGuardStore((s) => s.fixing);
  const switchingNodeName = useGuardStore((s) => s.switchingNodeName);
  const ackedFlowIds = useGuardStore((s) => s.ackedFlowIds);
  const ackAllFlowIds = useGuardStore((s) => s.ackAllFlowIds);
  const refreshNodes = useGuardStore((s) => s.refreshNodes);
  const startDeepNodeAudit = useGuardStore((s) => s.startDeepNodeAudit);
  const cancelDeepNodeAudit = useGuardStore((s) => s.cancelDeepNodeAudit);
  const switchNode = useGuardStore((s) => s.switchNode);
  const openRiskModal = useGuardStore((s) => s.openRiskModal);
  const pushToast = useGuardStore((s) => s.pushToast);

  const loadConns = async () => {
    if (loadingConns) return;
    setLoadingConns(true);
    try {
      const list = await ipc.getLiveConnections();
      setConns(list);
      setNowMs(Date.now());
    } catch (err) {
      pushToast("拉取实时连接失败", String(err), "danger");
    } finally {
      setLoadingConns(false);
    }
  };

  useEffect(() => {
    hideTip();
    if (subTab !== "traffic") return;
    let cancelled = false;
    void ipc
      .getLiveConnections()
      .then((list) => {
        if (!cancelled) {
          setConns(list);
          setNowMs(Date.now());
        }
      })
      .catch(() => {});
    const timer = window.setInterval(() => {
      setNowMs(Date.now());
    }, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [subTab, hideTip]);

  const handleCloseConn = async (id: string) => {
    if (closingConnId) return;
    setClosingConnId(id);
    try {
      await ipc.closeConnection(id);
      pushToast("已掐断异常连接", `已调用 Mihomo DELETE /connections/${id.slice(0, 8)}。`, "ok");
      await loadConns();
    } catch (err) {
      pushToast("掐断连接失败", String(err), "danger");
    } finally {
      setClosingConnId(null);
    }
  };

  const handleAckAllFlows = async () => {
    if (snapshot.killSwitchActive) {
      pushToast(
        "当前正处于熔断阻断状态",
        "必须先切回安全节点并实测通过后才可解除流量红灯。",
        "danger"
      );
      return;
    }
    const anomIds = conns.filter((c) => c.anomaly).map((c) => c.id);
    const ok = await ackAllFlowIds(anomIds);
    if (ok) {
      pushToast(
        "已清零当前异常拦截角标",
        "已同步消除侧边栏与悬浮窗报警灯，历史拦截明细仍保留在下方列表供查验。",
        "ok"
      );
    }
  };

  /** 严格比对当前节点与目标节点地区前缀（绝不将 JP -> US 误判为同区热备） */
  const requestSwitch = (nodeName: string) => {
    const curNode = nodeReport.currentNode;
    const sameRegion = isSameRegionSwitch(curNode, nodeName);
    const fromCode = extractRegionCode(curNode);
    const toCode = extractRegionCode(nodeName);
    const hasProcs = snapshot.bgClaudeProcs > 0;
    const calmLocked = config.calm24h && !snapshot.nodeDown;

    openRiskModal({
      tone: snapshot.nodeDown || calmLocked ? "danger" : sameRegion ? "ok" : "warn",
      badge: calmLocked ? "24h 冷静期硬锁" : sameRegion ? "同区热备" : "跨洲切换",
      title: snapshot.nodeDown
        ? "主节点故障 · 应急容灾切换"
        : calmLocked
        ? "24h 冷静保护期 · 严禁切换节点"
        : "节点切换风险评估",
      subtitle: calmLocked
        ? "当前节点健康可用，新号 / 刚付费 24 小时支付反欺诈复审窗口内默认禁止切换节点"
        : sameRegion
        ? "同地区热备切换，清零后台进程后可立即无缝接管"
        : "跨地区/跨洲切换，建议切换后静默等待 15 ~ 30 分钟再使用 Claude",
      routeCompare: {
        fromCode,
        fromName: curNode,
        fromRole: snapshot.nodeDown ? "当前失效" : "当前锁定",
        fromDanger: snapshot.nodeDown,
        toCode,
        toName: nodeName,
        toRole: sameRegion ? "同地区热备" : "跨区目标节点",
      },
      rows: [
        {
          label: "当前状态",
          value: hasProcs
            ? `检测到 ${snapshot.bgClaudeProcs} 个 Claude 后台进程运行中；防火墙守护中`
            : "Claude 后台进程为 0（安全）；防火墙守护中",
          tone: hasProcs ? "danger" : "ok",
        },
        {
          label: "建议等待",
          value: sameRegion
            ? "同地区热备切换：清零进程后可立即接管，无需等待跨洲静默期"
            : "跨国/跨洲切换：建议完成后静默等待 15 ~ 30 分钟再启动 Claude，避免瞬移风控",
        },
        {
          label: "风控提示",
          value: calmLocked
            ? "24h 冷静保护已生效：当前节点正常时已默认拦截切点（仅节点真不可用时允许容灾切换）"
            : "确认切换将更新策略组并立即重跑出口 IP 实测",
          tone: calmLocked ? "danger" : "normal",
        },
      ],
      footTip: calmLocked
        ? "如需关闭冷静保护，可前往「守卫配置」关闭 24h 冷静保护模式"
        : hasProcs
        ? undefined
        : "切换后自动重跑出口归属地实测",
      primaryLabel: calmLocked
        ? "保持当前节点，取消切换"
        : hasProcs
        ? "先清零 Claude 进程并切换"
        : "确认切换并重测出口",
      onPrimary: calmLocked
        ? () => {}
        : async () => {
            if (hasProcs) {
              await ipc.killClaudeProcesses(true);
            }
            await switchNode(nodeName, true);
          },
      dangerLabel: calmLocked
        ? "忽略 24h 冷静保护，强制切换"
        : hasProcs
        ? "忽略风险，直接切换"
        : undefined,
      onDanger: calmLocked
        ? async () => {
            if (hasProcs) {
              await ipc.killClaudeProcesses(true);
            }
            await switchNode(nodeName, true);
          }
        : hasProcs
        ? () => void switchNode(nodeName, true)
        : undefined,
    });
  };

  // ---- 节点分类统计 ----
  const usableNodes = nodeReport.nodes.filter((n) => !n.blocked && !n.cfBlocked);
  const unusableNodes = nodeReport.nodes.filter((n) => n.blocked || n.cfBlocked);
  const curNodeItem = nodeReport.nodes.find((n) => n.isCurrent);
  const curRegionCode =
    curNodeItem?.regionCode || extractRegionCode(nodeReport.currentNode) || "GL";
  const sameRegionUsableNodes = usableNodes.filter(
    (n) =>
      n.isCurrent ||
      isSameRegionSwitch(nodeReport.currentNode, n.name) ||
      (curNodeItem && n.regionCode === curNodeItem.regionCode)
  );
  const landingBlockedNodes = unusableNodes.filter(
    (n) =>
      n.claudeStatus === "blocked" ||
      n.claudeLabel?.includes("禁区") ||
      n.asnShort?.includes("禁区") ||
      n.recommendation?.includes("禁区")
  );
  const otherUnusableNodes = unusableNodes.filter((n) => !landingBlockedNodes.includes(n));
  const timeoutNodes = unusableNodes.filter(
    (n) => n.claudeStatus === "offline" || n.claudeLabel?.includes("超时")
  );
  const nameBlockedCount =
    nodeReport.nameBlockedCount ??
    Math.max(0, nodeReport.filteredBlockedCount - landingBlockedNodes.length);
  const subscriptionTotalNodes =
    nodeReport.subscriptionTotalNodes && nodeReport.subscriptionTotalNodes >= nodeReport.nodes.length
      ? nodeReport.subscriptionTotalNodes
      : nodeReport.nodes.length + nameBlockedCount;

  const displayedNodes =
    nodeFilter === "usable"
      ? usableNodes
      : nodeFilter === "same"
      ? sameRegionUsableNodes
      : unusableNodes;

  const scopeRetestLabel =
    nodeFilter === "usable"
      ? "重测可用节点"
      : nodeFilter === "same"
      ? "重测同区热备"
      : "重测隔离区";

  // ---- 实时流量统计 ----
  const isConnRejected = (c: ClaudeConn) =>
    c.chain.toUpperCase().includes("REJECT") || c.action.includes("已拦截");
  const activeAnomCount = conns.filter((c) => c.anomaly && !ackedFlowIds.includes(c.id)).length;
  const totalAnomCount = conns.filter((c) => c.anomaly).length;
  const rejectedCount = conns.filter(isConnRejected).length;
  const safeCount = conns.filter((c) => !c.anomaly && !isConnRejected(c)).length;
  const unlistedDomainCount = conns.filter((c) => c.isUnlistedDomain).length;

  const shownConns =
    flowFilter === "anomaly"
      ? conns.filter((c) => c.anomaly)
      : flowFilter === "rejected"
      ? conns.filter(isConnRejected)
      : flowFilter === "unlisted"
      ? conns.filter((c) => c.isUnlistedDomain)
      : conns;

  const renderNodeRow = (n: NodeItem) => {
    const isQ = n.blocked || n.cfBlocked;
    const isSwitchingThis = switchingNodeName === n.name;
    const isAuditingThis = deepAudit.running && deepAudit.currentNode === n.name;
    const isSame =
      !isQ &&
      !n.isCurrent &&
      (isSameRegionSwitch(nodeReport.currentNode, n.name) ||
        (curNodeItem != null && n.regionCode === curNodeItem.regionCode));

    const claudeStatus = n.claudeStatus ?? (n.cfBlocked ? "cf_403" : isQ ? "blocked" : "ok");
    const claudeLabel =
      n.claudeLabel ?? (n.cfBlocked ? "Claude 拉黑" : isQ ? "落地禁区" : "Claude ✓");
    const claudeTip = getClaudeBadgeTip(claudeStatus, claudeLabel, n.claudeProbeDetail);
    const claudeIsOk = claudeStatus === "ok" && !isQ && !n.webCfChallenge;
    const claudeIsWarn = !isQ && (claudeStatus === "cf_challenge" || Boolean(n.webCfChallenge));

    const geminiStatus = n.geminiStatus ?? "unknown";
    const geminiLabel =
      n.geminiLabel === "Gemini 送中" ||
      n.geminiLabel === "Gemini ✗" ||
      n.geminiLabel === "Gemini 限区"
        ? "AGY 限区"
        : n.geminiLabel === "Gemini ✓"
        ? "AGY ✓"
        : n.geminiLabel ?? "AGY 待测";
    const geminiTip = getGeminiBadgeTip(geminiStatus, geminiLabel);
    const geminiIsOk = geminiStatus === "ok";
    const geminiIsWarn =
      geminiStatus === "cn_redirect" ||
      geminiStatus === "restricted" ||
      geminiStatus === "limited" ||
      geminiLabel.includes("限区");

    const riskLevel =
      n.riskLevel ??
      (n.cfBlocked
        ? "abuser"
        : n.asnPurity?.includes("高危")
        ? "abuser"
        : n.asnPurity?.includes("共享")
        ? "proxy"
        : n.asnPurity?.includes("ISP")
        ? "isp"
        : n.asnPurity?.includes("机房")
        ? "hosting"
        : isQ
        ? "blocked"
        : "unknown");
    const asnShort =
      n.asnShort ??
      (riskLevel === "abuser"
        ? "高危滥用"
        : riskLevel === "proxy"
        ? "共享代理"
        : riskLevel === "isp"
        ? "ISP 住宅"
        : riskLevel === "hosting"
        ? "常规机房"
        : isQ
        ? "落地禁区"
        : "待验 IP");
    const riskDetail =
      n.riskDetail ??
      (riskLevel === "abuser"
        ? "命中滥用黑名单"
        : riskLevel === "proxy"
        ? "公共 VPN / 代理段"
        : riskLevel === "isp"
        ? "无代理标记"
        : riskLevel === "hosting"
        ? "0 滥用记录"
        : isQ
        ? "已隔离"
        : "切入后实测 IP");
    const nodeTypeTip = getNodeTypeTip(riskLevel, asnShort);
    const isTypeWarn = !isQ && riskLevel === "proxy";

    const driftCount = n.driftCount24h ?? 0;
    const dropFail = n.dropRatePct >= DROP_RATE_REDLINE;
    const dropWarn = !isQ && !dropFail && n.dropRatePct > 0.5;
    const stabWarn = !isQ && (driftCount > 0 || n.jitterMs >= 25);
    const stabilityTip =
      driftCount > 0
        ? `最近 24 小时检测到该节点落地 IP 静默切换 ${driftCount} 次（抖动 ±${n.jitterMs} ms），会话中途变 IP 易触发风控。`
        : `多轮实测延迟抖动 ±${n.jitterMs} ms，最近 24 小时落地 IP 稳定（0 次漂移）。`;

    const boxCls = isQ
      ? "is-bad"
      : n.isCurrent
      ? "is-cur"
      : claudeIsWarn || isTypeWarn
      ? "is-warn"
      : "";
    const scoreWarn = !isQ && (n.score < 75 || claudeIsWarn || driftCount > 0 || isTypeWarn);
    const scoreColor = isQ
      ? "var(--text-3)"
      : scoreWarn
      ? "var(--warning-fg)"
      : "var(--text-strong)";
    const barColor = isQ
      ? "var(--bad-dot)"
      : scoreWarn
      ? "var(--warning-dot)"
      : "var(--ok-dot)";
    const subRegion = n.regionLabel ?? `${n.regionCode} · ${n.nodeType}`;

    return (
      <div key={n.name} className={`node-row-grid tabular ${n.isCurrent ? "is-cur" : ""}`}>
        {/* 列 1：节点 / 出口 IP */}
        <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0 }}>
          <div className={`region-box ${boxCls}`}>{n.regionCode || "GL"}</div>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div
              className="row-main"
              style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}
            >
              <span
                title={n.name}
                style={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  color: isQ
                    ? "var(--text-2)"
                    : n.isCurrent
                    ? "var(--text-strong)"
                    : "var(--text-1)",
                  fontWeight: n.isCurrent ? 500 : 400,
                }}
              >
                {n.name}
              </span>
              {isSame && (
                <span
                  style={{
                    fontSize: 10,
                    padding: "0.5px 5px",
                    borderRadius: 4,
                    background: "var(--bg-subtle)",
                    color: "var(--text-3)",
                    flexShrink: 0,
                  }}
                >
                  同区
                </span>
              )}
            </div>
            <div
              className="row-sub"
              style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
            >
              {subRegion}
            </div>
          </div>
        </div>

        {/* 列 2：平台支持 / 阻断原因 */}
        <div style={{ display: "flex", alignItems: "center", gap: 9, minWidth: 0 }}>
          {isAuditingThis ? (
            <span className="guard-chip guard-chip-warn" style={{ height: 19, fontSize: 10.5 }}>
              <Loader2 size={10} strokeWidth={2} className="guard-spin" />
              <span>检测中...</span>
            </span>
          ) : (
            <>
              {claudeIsOk ? (
                <span
                  className="plat-ok"
                  onMouseEnter={(e) => showTip(e, claudeTip)}
                  onMouseLeave={hideTip}
                >
                  <Check size={11} strokeWidth={2} />
                  <span>Claude</span>
                </span>
              ) : (
                <span
                  className={`guard-chip ${claudeIsWarn ? "guard-chip-warn" : "guard-chip-fail"}`}
                  style={{ height: 19, fontSize: 10.5, cursor: "help" }}
                  onMouseEnter={(e) => showTip(e, claudeTip)}
                  onMouseLeave={hideTip}
                >
                  {claudeLabel}
                </span>
              )}

              {geminiIsOk ? (
                <span
                  className="plat-ok"
                  onMouseEnter={(e) => showTip(e, geminiTip)}
                  onMouseLeave={hideTip}
                >
                  <Check size={11} strokeWidth={2} />
                  <span>AGY</span>
                </span>
              ) : (
                <span
                  className={`guard-chip ${
                    geminiIsWarn
                      ? "guard-chip-warn"
                      : geminiLabel.includes("离线")
                      ? "guard-chip-fail"
                      : "guard-chip-neutral"
                  }`}
                  style={{ height: 19, fontSize: 10.5, cursor: "help" }}
                  onMouseEnter={(e) => showTip(e, geminiTip)}
                  onMouseLeave={hideTip}
                >
                  {geminiLabel}
                </span>
              )}
            </>
          )}
        </div>

        {/* 列 3：节点类型 */}
        <div style={{ minWidth: 0 }}>
          <div
            style={{ display: "inline-block", maxWidth: "100%", cursor: "help" }}
            onMouseEnter={(e) => showTip(e, nodeTypeTip)}
            onMouseLeave={hideTip}
          >
            <div
              className="row-main"
              style={{
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                color: isTypeWarn
                  ? "var(--warning-fg)"
                  : isQ
                  ? "var(--text-2)"
                  : "var(--text-1)",
              }}
            >
              {asnShort}
            </div>
            <div
              className="row-sub"
              style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
            >
              {riskDetail}
            </div>
          </div>
        </div>

        {/* 列 4：延迟 / 断连 / 稳定性 */}
        <div style={{ minWidth: 0 }}>
          <div
            className="row-main"
            style={{
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              color: isQ ? "var(--text-2)" : "var(--text-1)",
            }}
          >
            <span>{n.delayMs !== null ? `${n.delayMs} ms` : "超时"}</span>
            <span style={{ margin: "0 4px", color: "var(--text-4)" }}>·</span>
            <span
              style={{
                color: dropFail
                  ? "var(--bad-fg)"
                  : dropWarn
                  ? "var(--warning-fg)"
                  : "var(--text-2)",
              }}
            >
              {n.dropRatePct.toFixed(1)}% 断连
            </span>
          </div>
          <div
            className="row-sub"
            style={{
              display: "inline-block",
              maxWidth: "100%",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              cursor: "help",
              color: stabWarn ? "var(--warning-fg)" : "var(--text-3)",
            }}
            onMouseEnter={(e) => showTip(e, stabilityTip)}
            onMouseLeave={hideTip}
          >
            抖动 ±{n.jitterMs} ms · {driftCount > 0 ? `漂移 ${driftCount} 次` : "0 漂移"}
          </div>
        </div>

        {/* 列 5：质量评分 */}
        <div style={{ minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 12.5, fontWeight: 500, color: scoreColor }}>
              {n.score}{" "}
              <span style={{ fontSize: 10.5, fontWeight: 400, color: "var(--text-3)" }}>分</span>
            </span>
            <div className="mini-bar-track">
              <div
                className="mini-bar-fill"
                style={{
                  width: `${Math.min(100, Math.max(0, n.score))}%`,
                  background: barColor,
                }}
              />
            </div>
          </div>
          <div
            className="row-sub"
            style={{
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              color: scoreWarn ? "var(--warning-fg)" : "var(--text-3)",
            }}
          >
            {n.recommendation || (isQ ? "不可用" : "可用")}
          </div>
        </div>

        {/* 列 6：操作 / 状态（已移除单行重测按钮，改由列表顶部分类批量重测） */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end" }}>
          {n.isCurrent ? (
            <span className="guard-chip guard-chip-ok">当前锁定</span>
          ) : isQ ? (
            <span className="guard-chip guard-chip-fail">已隔离</span>
          ) : (
            <button
              type="button"
              disabled={fixing}
              className="guard-btn guard-btn-flat guard-btn-xs"
              onClick={() => requestSwitch(n.name)}
            >
              {isSwitchingThis && <Loader2 size={11} strokeWidth={2} className="guard-spin" />}
              <span>{isSwitchingThis ? "切换中..." : "切换锁定"}</span>
            </button>
          )}
        </div>
      </div>
    );
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
      <HoverTooltip tip={tip} testId="node-hover-tooltip" />

      {/* 58px 单行页头 */}
      <div className="page-hd">
        <div className="page-hd-left">
          <h1 className="page-title">节点流量</h1>
          <span className="page-sub">Claude + AGY 双平台评估 · 同区容灾 · 12h 流量监控</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          {subTab === "traffic" && activeAnomCount > 0 && !snapshot.killSwitchActive && (
            <button
              type="button"
              className="guard-btn guard-btn-flat"
              onClick={() => void handleAckAllFlows()}
            >
              <Check size={13} strokeWidth={1.55} style={{ color: "var(--text-2)" }} />
              <span>全部标为已处理</span>
            </button>
          )}

          {subTab === "quality" &&
            (deepAudit.running ? (
              <button
                type="button"
                data-testid="btn-cancel-deep-audit"
                className="guard-btn guard-btn-flat tabular"
                style={{ color: "var(--warning-fg)", borderColor: "var(--warning-border)" }}
                onClick={() => void cancelDeepNodeAudit()}
                title={deepAudit.message}
              >
                <Loader2 size={12.5} strokeWidth={1.9} className="guard-spin" />
                <span>
                  核验中 {deepAudit.currentIndex}/{deepAudit.total || "?"} · 停止
                </span>
              </button>
            ) : (
              <button
                type="button"
                data-testid="btn-start-deep-audit"
                disabled={refreshingNodes || fixing}
                className="guard-btn guard-btn-flat"
                onClick={() => void startDeepNodeAudit(true)}
                title="在 Claude 0 进程时慢速逐个实测全部节点的真实 IP 类型、CF 盾与 AGY 限区并永久缓存 24h"
              >
                <Search size={13} strokeWidth={1.45} style={{ color: "var(--text-2)" }} />
                <span>深度核验全部</span>
              </button>
            ))}

          <button
            type="button"
            disabled={refreshingNodes || loadingConns}
            className="guard-btn guard-btn-flat"
            onClick={async () => {
              if (subTab === "quality") {
                setRefreshingNodes(true);
                try {
                  const ok = await refreshNodes(false);
                  if (ok) {
                    const latest = useGuardStore.getState().nodeReport;
                    pushToast(
                      "已刷新节点状态",
                      `已加载 ${latest.nodes.length} 个合规节点的实时状态与持久化核验缓存。`,
                      "ok"
                    );
                  }
                } finally {
                  setRefreshingNodes(false);
                }
              } else {
                void loadConns();
              }
            }}
          >
            {refreshingNodes || loadingConns ? (
              <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />
            ) : (
              <RefreshCw size={13} strokeWidth={1.45} style={{ color: "var(--text-2)" }} />
            )}
            <span>
              {subTab === "quality"
                ? refreshingNodes
                  ? "刷新中..."
                  : "刷新列表"
                : "刷新连接"}
            </span>
          </button>

          <span
            aria-hidden="true"
            style={{ width: 1, height: 16, background: "var(--divider-strong)", margin: "0 2px" }}
          />

          <div className="in-seg" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={subTab === "quality"}
              className={`in-seg-btn ${subTab === "quality" ? "active" : ""}`}
              onClick={() => setSubTab("quality")}
            >
              节点质量与容灾
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={subTab === "traffic"}
              className={`in-seg-btn ${subTab === "traffic" ? "active" : ""}`}
              onClick={() => setSubTab("traffic")}
            >
              实时流量分析
            </button>
          </div>
        </div>
      </div>

      {/* 主滚动区（单列全宽通透布局 + ThinScrollArea） */}
      <ThinScrollArea onScrollCapture={hideTip}>
        <div
          style={{
            padding: "16px 24px 24px",
            display: "flex",
            flexDirection: "column",
            gap: 14,
          }}
        >
          {subTab === "quality" ? (
            <>
              {/* 顶部 4 段一体化统计条（策略组名归位第 4 格副行，管道文案沿用防歧义「管道已连接」） */}
              <div className="guard-card metric-strip-nodes tabular">
                <div className="metric-cell">
                  <div style={metricLblStyle}>当前锁定节点</div>
                  <div
                    style={{
                      marginTop: 4,
                      display: "flex",
                      alignItems: "center",
                      gap: 7,
                      minWidth: 0,
                    }}
                  >
                    <span
                      style={{
                        fontSize: 10,
                        padding: "1px 5.5px",
                        borderRadius: 4,
                        background: nodeReport.connected ? "var(--ok-bg)" : "var(--bg-subtle)",
                        color: nodeReport.connected ? "var(--ok-fg)" : "var(--text-3)",
                        border: `1px solid ${
                          nodeReport.connected ? "var(--ok-border)" : "var(--divider)"
                        }`,
                        flexShrink: 0,
                      }}
                    >
                      {curRegionCode}
                    </span>
                    <span
                      title={nodeReport.currentNode}
                      style={{
                        fontSize: 13.5,
                        fontWeight: 500,
                        color: "var(--text-strong)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {nodeReport.currentNode}
                    </span>
                  </div>
                  <div
                    title={nodeReport.currentExitSummary ?? undefined}
                    style={metricSubStyle}
                  >
                    {nodeReport.currentExitSummary ||
                      (curNodeItem
                        ? `${curNodeItem.asnShort ?? curNodeItem.nodeType} · ${
                            curNodeItem.delayMs !== null ? `${curNodeItem.delayMs} ms` : "待测"
                          }`
                        : "等待探测出口信息")}
                  </div>
                </div>

                <div className="metric-cell">
                  <div style={metricLblStyle}>可用节点</div>
                  <div style={{ marginTop: 4, display: "flex", alignItems: "baseline", gap: 5 }}>
                    <span data-testid="nodes-usable-count" style={metricValStyle}>
                      {usableNodes.length}
                    </span>
                    <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                      / 订阅 {subscriptionTotalNodes}
                    </span>
                  </div>
                  <div data-testid="nodes-usable-breakdown" style={metricSubStyle}>
                    {nodeReport.nodes.length === 0
                      ? "暂无评估节点"
                      : `含 ${sameRegionUsableNodes.length} 个同区热备`}
                  </div>
                </div>

                <div className="metric-cell">
                  <div style={metricLblStyle}>隔离与禁区</div>
                  <div style={{ marginTop: 4, display: "flex", alignItems: "baseline", gap: 6 }}>
                    <span
                      data-testid="nodes-blocked-count"
                      style={{ ...metricValStyle, color: "var(--text-1)" }}
                    >
                      {unusableNodes.length}
                    </span>
                    <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                      · 名称禁区 {nameBlockedCount}
                    </span>
                  </div>
                  <div data-testid="nodes-blocked-breakdown" style={metricSubStyle}>
                    落地禁区 {landingBlockedNodes.length} · 拉黑/超时 {otherUnusableNodes.length}
                  </div>
                </div>

                <div className="metric-cell">
                  <div style={metricLblStyle}>Mihomo 管道</div>
                  <div
                    data-testid="mihomo-conn-status"
                    style={{
                      marginTop: 4,
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      minWidth: 0,
                    }}
                  >
                    <span
                      className={`guard-dot ${nodeReport.connected ? "" : "danger"}`}
                      style={{ width: 5.5, height: 5.5 }}
                    />
                    <span
                      style={{
                        fontSize: 13.5,
                        fontWeight: 500,
                        color: nodeReport.connected ? "var(--ok-fg)" : "var(--bad-fg)",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {nodeReport.connected ? "管道已连接" : "管道未连接"}
                    </span>
                  </div>
                  <div style={metricSubStyle}>
                    {`${nodeReport.groupName} · ${snapshot.clashVersion} · :${snapshot.clashPort}`}
                  </div>
                </div>
              </div>

              {/* 中段过滤胶囊 + 按类型批量重测 */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 12,
                  paddingTop: 2,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <button
                    type="button"
                    data-testid="tab-nodes-usable"
                    className={`filter-tab ${nodeFilter === "usable" ? "active" : ""}`}
                    onClick={() => setNodeFilter("usable")}
                  >
                    <span>可用节点</span>
                    <span className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
                      {usableNodes.length}
                    </span>
                  </button>
                  <button
                    type="button"
                    data-testid="tab-nodes-same"
                    className={`filter-tab ${nodeFilter === "same" ? "active" : ""}`}
                    onClick={() => setNodeFilter("same")}
                  >
                    <span>同区热备</span>
                    <span className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
                      {sameRegionUsableNodes.length}
                    </span>
                  </button>
                  <button
                    type="button"
                    data-testid="tab-nodes-quarantine"
                    className={`filter-tab ${nodeFilter === "quarantine" ? "active" : ""}`}
                    onClick={() => setNodeFilter("quarantine")}
                  >
                    <span>隔离区</span>
                    <span className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
                      {unusableNodes.length}
                    </span>
                  </button>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                    悬停标签可看说明 · 核验缓存 24h
                  </span>
                  {nodeFilter === "quarantine" && (
                    <button
                      type="button"
                      data-testid="btn-retest-timeout"
                      disabled={deepAudit.running || fixing || timeoutNodes.length === 0}
                      className="guard-btn guard-btn-flat guard-btn-xs"
                      onClick={() =>
                        void startDeepNodeAudit(
                          true,
                          undefined,
                          timeoutNodes.map((n) => n.name)
                        )
                      }
                    >
                      <span>重测超时类 ({timeoutNodes.length})</span>
                    </button>
                  )}
                  <button
                    type="button"
                    data-testid="btn-scope-retest"
                    disabled={deepAudit.running || fixing || displayedNodes.length === 0}
                    className="guard-btn guard-btn-flat guard-btn-xs"
                    onClick={() =>
                      void startDeepNodeAudit(
                        true,
                        undefined,
                        displayedNodes.map((n) => n.name)
                      )
                    }
                  >
                    {deepAudit.running ? (
                      <Loader2 size={11} strokeWidth={1.9} className="guard-spin" />
                    ) : (
                      <RefreshCw size={11} strokeWidth={1.5} style={{ color: "var(--text-2)" }} />
                    )}
                    <span>{deepAudit.running ? "重测中..." : scopeRetestLabel}</span>
                  </button>
                </div>
              </div>

              {/* 6 列实宽紧贴 + space-between 等距列表 */}
              <div className="guard-card">
                <div className="table-scroll-x" data-testid="nodes-eval-table">
                  <div className="node-col-head">
                    <span>{nodeFilter === "quarantine" ? "隔离节点 / 协议" : "节点 / 出口 IP"}</span>
                    <span>{nodeFilter === "quarantine" ? "阻断原因" : "平台支持"}</span>
                    <span>节点类型</span>
                    <span>延迟 / 断连 / 稳定性</span>
                    <span>质量评分</span>
                    <span style={{ textAlign: "right" }}>
                      {nodeFilter === "quarantine" ? "状态" : "操作"}
                    </span>
                  </div>

                  {displayedNodes.length === 0 ? (
                    <div
                      style={{
                        padding: "28px 18px",
                        textAlign: "center",
                        fontSize: 12,
                        color: "var(--text-3)",
                      }}
                    >
                      {!nodeReport.connected
                        ? "尚未检测到在线的 Clash Verge Mihomo 命名管道，请先启动 Clash Verge Rev。"
                        : nodeFilter === "quarantine"
                        ? "当前隔离区为空，所有已评估节点均处于可用状态。"
                        : nodeFilter === "same"
                        ? "当前策略组内暂无同区热备节点。"
                        : nodeReport.nodes.length > 0
                        ? "当前组内评估节点均已移入隔离区，请切换「隔离区」查看或更换订阅。"
                        : "当前策略组中暂无非禁区代理节点，请检查 Clash 订阅或完成 Script.js 覆写配置。"}
                    </div>
                  ) : (
                    <div>{displayedNodes.map(renderNodeRow)}</div>
                  )}
                </div>
              </div>
            </>
          ) : (
            <>
              {/* 实时流量顶部严格 4 等分统计条 */}
              <div className="guard-card metric-strip-equal tabular">
                <div className="metric-cell">
                  <div style={metricLblStyle}>12h 未确认异常</div>
                  <div style={{ marginTop: 4, display: "flex", alignItems: "baseline", gap: 4 }}>
                    <span
                      style={{
                        ...metricValStyle,
                        color: activeAnomCount > 0 ? "var(--bad-fg)" : "var(--ok-fg)",
                      }}
                    >
                      {activeAnomCount}
                    </span>
                    <span style={{ fontSize: 11, color: "var(--text-3)" }}>条</span>
                  </div>
                  <div style={metricSubStyle}>含防回传拦截 {rejectedCount} 条</div>
                </div>

                <div className="metric-cell">
                  <div style={metricLblStyle}>活跃安全连接</div>
                  <div style={{ marginTop: 4, display: "flex", alignItems: "baseline", gap: 4 }}>
                    <span style={{ ...metricValStyle, color: "var(--ok-fg)" }}>{safeCount}</span>
                    <span style={{ fontSize: 11, color: "var(--text-3)" }}>条</span>
                  </div>
                  <div style={metricSubStyle}>均经锁定出口稳定放行</div>
                </div>

                <div className="metric-cell">
                  <div style={metricLblStyle}>Claude 总连接</div>
                  <div style={{ marginTop: 4, display: "flex", alignItems: "baseline", gap: 4 }}>
                    <span style={metricValStyle}>{conns.length}</span>
                    <span style={{ fontSize: 11, color: "var(--text-3)" }}>条</span>
                  </div>
                  <div style={metricSubStyle}>桌面端 / CLI / 网页端</div>
                </div>

                <div className="metric-cell">
                  <div style={metricLblStyle}>锁定策略组</div>
                  <div
                    style={{
                      marginTop: 4,
                      fontSize: 13.5,
                      fontWeight: 500,
                      color: "var(--text-strong)",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {nodeReport.groupName}
                  </div>
                  <div style={metricSubStyle}>常规连接已省略此组名前缀</div>
                </div>
              </div>

              {/* 中段过滤胶囊 */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  gap: 12,
                  paddingTop: 2,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <button
                    type="button"
                    className={`filter-tab ${flowFilter === "all" ? "active" : ""}`}
                    onClick={() => setFlowFilter("all")}
                  >
                    <span>全部连接</span>
                    <span className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
                      {conns.length}
                    </span>
                  </button>
                  <button
                    type="button"
                    className={`filter-tab ${flowFilter === "anomaly" ? "active" : ""}`}
                    onClick={() => setFlowFilter("anomaly")}
                  >
                    <span>仅看异常</span>
                    <span className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
                      {totalAnomCount}
                    </span>
                  </button>
                  <button
                    type="button"
                    className={`filter-tab ${flowFilter === "rejected" ? "active" : ""}`}
                    onClick={() => setFlowFilter("rejected")}
                  >
                    <span>遥测拦截</span>
                    <span className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
                      {rejectedCount}
                    </span>
                  </button>
                  {unlistedDomainCount > 0 && (
                    <button
                      type="button"
                      data-testid="btn-filter-unlisted-domains"
                      className={`filter-tab ${flowFilter === "unlisted" ? "active" : ""}`}
                      onClick={() => setFlowFilter("unlisted")}
                    >
                      <span>未收录新域</span>
                      <span className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
                        {unlistedDomainCount}
                      </span>
                    </button>
                  )}
                </div>

                <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                  默认省略 :443 与 {nodeReport.groupName} · 悬停查看原始明细
                </span>
              </div>

              {/* 7 列实宽紧贴 + space-between 绝对均分实时连接表 */}
              <div className="guard-card">
                <div className="table-scroll-x" data-testid="live-conns-table">
                  <div className="conn-col-head">
                    <span>目标 / 进程</span>
                    <span>链路意图</span>
                    <span>状态</span>
                    <span>命中规则</span>
                    <span>出口 / 异常链路</span>
                    <span>时长 / 流量</span>
                    <span style={{ textAlign: "right" }}>操作</span>
                  </div>

                  {shownConns.length === 0 ? (
                    <div
                      style={{
                        padding: "28px 18px",
                        textAlign: "center",
                        fontSize: 12,
                        color: "var(--text-3)",
                      }}
                    >
                      {!nodeReport.connected
                        ? "尚未连接 Clash Verge Mihomo 命名管道，暂无法采集实时连接流量。"
                        : flowFilter === "unlisted"
                        ? "当前连接均已命中已知 Claude 业务或遥测清单，未发现未收录新域名。"
                        : "当前条件下无实时连接记录。"}
                    </div>
                  ) : (
                    <div>
                      {shownConns.map((c) => {
                        const acked = ackedFlowIds.includes(c.id);
                        const isRejected = isConnRejected(c);
                        const cleanHost = formatDisplayHost(c.host);
                        const hostTip = `完整目标：${c.host}\n来源进程：${c.process}`;
                        const ruleInfo = formatRuleSummary(c.rule, isRejected, c.anomaly);
                        const chainInfo = formatChainSummary(c, nodeReport.groupName, isRejected);
                        const durText = formatConnDuration(c, nowMs, isRejected);
                        const durTip = isRejected
                          ? `触发时刻：${c.time}\n该连接已被规则即时阻断，未建立实际传输。`
                          : `建连时刻：${c.time}\n当前持续时长 ${durText}，累计流量 ${c.bytesLabel}。`;
                        const purposeLabel = c.purposeLabel || "业务连接";
                        const purposeDetail = c.purposeDetail || c.action;
                        const purposeTip = `${purposeLabel}\n${purposeDetail}`;

                        const pillCls = c.anomaly
                          ? acked
                            ? "guard-chip-neutral"
                            : "guard-chip-fail"
                          : isRejected
                          ? "guard-chip-neutral"
                          : "guard-chip-ok";
                        const pillTxt = c.anomaly
                          ? acked
                            ? "已确认"
                            : "脱组风险"
                          : isRejected
                          ? "已拦截"
                          : "安全放行";

                        return (
                          <div key={c.id} className="conn-row-grid tabular">
                            {/* 列 1：目标 / 进程 */}
                            <div style={{ minWidth: 0 }}>
                              <div
                                style={{ display: "inline-block", maxWidth: "100%", cursor: "help" }}
                                onMouseEnter={(e) => showTip(e, hostTip)}
                                onMouseLeave={hideTip}
                              >
                                <div
                                  className="row-main"
                                  style={{
                                    color: "var(--text-strong)",
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {cleanHost}
                                </div>
                                <div
                                  className="row-sub"
                                  style={{
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {c.process}
                                </div>
                              </div>
                            </div>

                            {/* 列 2：链路意图 */}
                            <div style={{ minWidth: 0 }}>
                              <div
                                data-testid={`conn-purpose-${c.id}`}
                                style={{ display: "inline-block", maxWidth: "100%", cursor: "help" }}
                                onMouseEnter={(e) => showTip(e, purposeTip)}
                                onMouseLeave={hideTip}
                              >
                                <div
                                  className="row-main"
                                  style={{
                                    color: c.isUnlistedDomain
                                      ? "var(--warning-fg)"
                                      : isRejected
                                      ? "var(--text-2)"
                                      : "var(--text-1)",
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {purposeLabel}
                                </div>
                                <div
                                  className="row-sub"
                                  style={{
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {purposeDetail}
                                </div>
                              </div>
                            </div>

                            {/* 列 3：状态 */}
                            <div>
                              <span className={`guard-chip ${pillCls}`}>{pillTxt}</span>
                            </div>

                            {/* 列 4：命中规则 */}
                            <div style={{ minWidth: 0 }}>
                              <div
                                style={{ display: "inline-block", maxWidth: "100%", cursor: "help" }}
                                onMouseEnter={(e) => showTip(e, ruleInfo.tip)}
                                onMouseLeave={hideTip}
                              >
                                <div
                                  className="row-main"
                                  style={{
                                    color: c.anomaly ? "var(--bad-fg)" : "var(--text-1)",
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {ruleInfo.label}
                                </div>
                                <div
                                  className="row-sub"
                                  style={{
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {ruleInfo.code}
                                </div>
                              </div>
                            </div>

                            {/* 列 5：出口 / 异常链路 */}
                            <div style={{ minWidth: 0 }}>
                              <div
                                style={{ display: "inline-block", maxWidth: "100%", cursor: "help" }}
                                onMouseEnter={(e) => showTip(e, chainInfo.tip)}
                                onMouseLeave={hideTip}
                              >
                                <div
                                  className="row-main"
                                  style={{
                                    color:
                                      chainInfo.tone === "bad"
                                        ? "var(--bad-fg)"
                                        : chainInfo.tone === "muted"
                                        ? "var(--text-2)"
                                        : "var(--text-1)",
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {chainInfo.main}
                                </div>
                                {chainInfo.sub && (
                                  <div
                                    className="row-sub"
                                    style={{
                                      color:
                                        chainInfo.tone === "bad" ? "var(--bad-fg)" : "var(--text-3)",
                                      opacity: chainInfo.tone === "bad" ? 0.85 : 1,
                                      overflow: "hidden",
                                      textOverflow: "ellipsis",
                                      whiteSpace: "nowrap",
                                    }}
                                  >
                                    {chainInfo.sub}
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* 列 6：时长 / 流量（左对齐与表头齐平） */}
                            <div style={{ minWidth: 0 }}>
                              <div
                                style={{ display: "inline-block", maxWidth: "100%", cursor: "help" }}
                                onMouseEnter={(e) => showTip(e, durTip)}
                                onMouseLeave={hideTip}
                              >
                                <div
                                  className="row-main"
                                  style={{
                                    color: isRejected ? "var(--text-3)" : "var(--text-1)",
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {durText}
                                </div>
                                <div
                                  className="row-sub"
                                  style={{
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                    whiteSpace: "nowrap",
                                  }}
                                >
                                  {c.bytesLabel}
                                </div>
                              </div>
                            </div>

                            {/* 列 7：操作（右对齐贴边） */}
                            <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end" }}>
                              <button
                                type="button"
                                disabled={closingConnId !== null}
                                className={`guard-btn ${
                                  c.anomaly && !acked ? "guard-btn-danger-soft" : "guard-btn-flat"
                                } guard-btn-xs`}
                                onClick={() => void handleCloseConn(c.id)}
                              >
                                {closingConnId === c.id ? "掐断中..." : "掐断"}
                              </button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      </ThinScrollArea>
    </section>
  );
}

const metricLblStyle: React.CSSProperties = {
  fontSize: 11,
  color: "var(--text-3)",
};

const metricValStyle: React.CSSProperties = {
  fontSize: 15,
  fontWeight: 500,
  lineHeight: 1.2,
  color: "var(--text-strong)",
};

const metricSubStyle: React.CSSProperties = {
  marginTop: 3,
  fontSize: 10.5,
  color: "var(--text-3)",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};
