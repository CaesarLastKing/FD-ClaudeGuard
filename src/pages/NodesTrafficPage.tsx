import { useEffect, useState, type MouseEvent } from "react";
import { ChevronDown, ChevronRight, Loader2, RefreshCw, ShieldAlert } from "lucide-react";
import { ipc } from "@/lib/ipc";
import { DROP_RATE_REDLINE, extractRegionCode, isSameRegionSwitch } from "@/lib/protocol";
import { useGuardStore } from "@/stores/guardStore";
import type { ClaudeConn, NodeItem } from "@/types/guard";

/** 大白话状态悬停解释（鼠标放上 0ms 浮现，让普通用户一秒看懂拉黑/弹盾/落地禁区/AGY 限区/超时原因） */
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
    return `Claude 超时：节点在 Clash 中基础网络可能正常，但访问 api.anthropic.com 连续 2 次超时或连接被重置；仅短缓存 5 分钟，可点右侧「重测」单独复核。${detailSuffix}`;
  }
  if (status === "ok") {
    return `Anthropic API 与 claude.ai 网页登录均实测畅通，无 Cloudflare 拦截盾。${detailSuffix}`;
  }
  return "尚未完成真实代理深度核验（我们绝不造假绿灯）；后台会自动逐个慢速核验，也可点右上角「深度核验全部」或切换锁定立即实测。";
}

function getGeminiBadgeTip(status: string, label: string): string {
  if (status === "cn_redirect" || status === "restricted" || label.includes("限区") || label.includes("送中")) {
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

export function NodesTrafficPage() {
  const subTab = useGuardStore((s) => s.nodesSubTab);
  const setSubTab = useGuardStore((s) => s.setNodesSubTab);
  const [flowFilter, setFlowFilter] = useState<"anomaly" | "all">("all");
  const [conns, setConns] = useState<ClaudeConn[]>([]);
  const [refreshingNodes, setRefreshingNodes] = useState(false);
  const [loadingConns, setLoadingConns] = useState(false);
  const [closingConnId, setClosingConnId] = useState<string | null>(null);
  const [hoverTip, setHoverTip] = useState<{
    text: string;
    x: number;
    y: number;
    placeBelow: boolean;
  } | null>(null);
  const [showQuarantine, setShowQuarantine] = useState(true);
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
    } catch (err) {
      pushToast("拉取实时连接失败", String(err), "danger");
    } finally {
      setLoadingConns(false);
    }
  };

  useEffect(() => {
    setHoverTip(null);
    if (subTab !== "traffic") return;
    let cancelled = false;
    void ipc
      .getLiveConnections()
      .then((list) => {
        if (!cancelled) setConns(list);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [subTab]);

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

  /**
   * 增量 8：严格比对当前节点与目标节点地区前缀（修复 JP -> US 误判同区热备）
   */
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

  const activeAnomCount = conns.filter((c) => c.anomaly && !ackedFlowIds.includes(c.id)).length;
  const totalAnomCount = conns.filter((c) => c.anomaly).length;
  const shownConns = flowFilter === "anomaly" ? conns.filter((c) => c.anomaly) : conns;
  // 严格互斥分类，确保所有数字加总 100% 与订阅总节点数对得上：
  // 订阅总数 = 名称直筛禁区(未入组) + 入组评估数(可用 + 实测落地禁区 + 其他不可用)
  const usableNodes = nodeReport.nodes.filter((n) => !n.blocked && !n.cfBlocked);
  const unusableNodes = nodeReport.nodes.filter((n) => n.blocked || n.cfBlocked);
  const landingBlockedNodes = unusableNodes.filter(
    (n) =>
      n.claudeStatus === "blocked" ||
      n.claudeLabel?.includes("禁区") ||
      n.asnShort?.includes("禁区") ||
      n.recommendation?.includes("禁区")
  );
  const otherUnusableNodes = unusableNodes.filter((n) => !landingBlockedNodes.includes(n));
  const nameBlockedCount =
    nodeReport.nameBlockedCount ??
    Math.max(0, nodeReport.filteredBlockedCount - landingBlockedNodes.length);
  const subscriptionTotalNodes =
    nodeReport.subscriptionTotalNodes && nodeReport.subscriptionTotalNodes >= nodeReport.nodes.length
      ? nodeReport.subscriptionTotalNodes
      : nodeReport.nodes.length + nameBlockedCount;
  const totalUnavailableAndBlocked = nameBlockedCount + unusableNodes.length;
  const usableNodeCount = usableNodes.length;
  const unusableInListCount = unusableNodes.length;

  const showTip = (e: MouseEvent<HTMLElement>, text: string) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = Math.max(150, Math.min(window.innerWidth - 150, rect.left + rect.width / 2));
    const placeBelow = rect.top < 160;
    const y = placeBelow ? rect.bottom + 8 : rect.top - 8;
    setHoverTip({ text, x, y, placeBelow });
  };
  const hideTip = () => setHoverTip(null);

  return (
    <section
      style={{ display: "flex", flex: 1, minHeight: 0, flexDirection: "column" }}
      onScrollCapture={hideTip}
    >
      {hoverTip && (
        <div
          role="tooltip"
          data-testid="node-hover-tooltip"
          style={{
            position: "fixed",
            left: hoverTip.x,
            top: hoverTip.y,
            transform: hoverTip.placeBelow ? "translate(-50%, 0)" : "translate(-50%, -100%)",
            maxWidth: 270,
            padding: "7px 10px",
            borderRadius: 8,
            background: "var(--bg-card)",
            border: "1px solid var(--border-strong)",
            color: "var(--text-1)",
            fontSize: 11.5,
            lineHeight: 1.5,
            whiteSpace: "pre-line",
            boxShadow: "0 10px 28px rgba(0, 0, 0, 0.28)",
            pointerEvents: "none",
            zIndex: 9999,
          }}
        >
          {hoverTip.text}
        </div>
      )}
      <div style={pageHdStyle}>
        <div>
          <h1 style={pageTitleStyle}>节点流量</h1>
          <div style={pageSubStyle}>
            Claude + Google Antigravity (AGY) 双平台风控评估 · 主备同区容灾 · 12 小时滚动流量监控
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {subTab === "traffic" && activeAnomCount > 0 && !snapshot.killSwitchActive && (
            <button
              type="button"
              className="guard-btn guard-btn-flat guard-btn-sm"
              onClick={handleAckAllFlows}
            >
              全部标为已处理
            </button>
          )}
          {subTab === "quality" &&
            (deepAudit.running ? (
              <button
                type="button"
                data-testid="btn-cancel-deep-audit"
                className="guard-btn guard-btn-flat guard-btn-sm"
                style={{ color: "var(--warning)" }}
                onClick={() => void cancelDeepNodeAudit()}
                title={deepAudit.message}
              >
                <Loader2 size={13} strokeWidth={2} className="guard-spin" />
                <span>
                  核验中 {deepAudit.currentIndex}/{deepAudit.total || "?"} · 停止
                </span>
              </button>
            ) : (
              <button
                type="button"
                data-testid="btn-start-deep-audit"
                disabled={refreshingNodes || fixing}
                className="guard-btn guard-btn-flat guard-btn-sm"
                onClick={() => void startDeepNodeAudit(true)}
                title="在 Claude 0 进程时按 1.5s/个慢速逐个实测全部节点的真实 IP 类型、CF 盾与 AGY 限区并永久缓存 24h（漂移自动重测）"
              >
                <RefreshCw size={13} strokeWidth={1.85} />
                <span>深度核验全部</span>
              </button>
            ))}
          <button
            type="button"
            disabled={refreshingNodes || loadingConns}
            className="guard-btn guard-btn-flat guard-btn-sm"
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
            {refreshingNodes ? (
              <Loader2 size={13} strokeWidth={2} className="guard-spin" />
            ) : (
              <RefreshCw size={13} strokeWidth={1.85} />
            )}
            <span>
              {subTab === "quality"
                ? refreshingNodes
                  ? "刷新中..."
                  : "刷新列表"
                : "刷新连接"}
            </span>
          </button>
          <div style={segWrapStyle}>
            <button
              type="button"
              style={segBtnStyle(subTab === "quality")}
              onClick={() => setSubTab("quality")}
            >
              节点质量与容灾
            </button>
            <button
              type="button"
              style={segBtnStyle(subTab === "traffic")}
              onClick={() => setSubTab("traffic")}
            >
              实时流量分析
            </button>
          </div>
        </div>
      </div>

      <div
        style={{
          padding: "16px 22px",
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          gap: 16,
        }}
      >
        {subTab === "quality" ? (
          <>
            <div
              className="tabular"
              style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}
            >
              <div className="guard-card" style={statPadStyle}>
                <div style={statLblStyle}>当前策略组 / 节点</div>
                <div
                  style={{
                    fontSize: 14.5,
                    fontWeight: 600,
                    marginTop: 6,
                    lineHeight: 1.35,
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                  title={nodeReport.currentNode}
                >
                  {nodeReport.currentNode}
                </div>
                {nodeReport.currentExitSummary && (
                  <div
                    style={{
                      fontSize: 11,
                      color: "var(--text-3)",
                      marginTop: 4,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                    title={nodeReport.currentExitSummary}
                  >
                    {nodeReport.currentExitSummary}
                  </div>
                )}
              </div>
              <div className="guard-card" style={statPadStyle}>
                <div style={statLblStyle}>受支持可用节点</div>
                <div data-testid="nodes-usable-count" style={statNumStyle}>
                  {usableNodeCount}
                  <span style={statUnitStyle}>个</span>
                </div>
                <div
                  data-testid="nodes-usable-breakdown"
                  style={{ fontSize: 11, color: "var(--text-3)", marginTop: 3 }}
                >
                  订阅共 {subscriptionTotalNodes} · 评估 {nodeReport.nodes.length}
                  {nodeReport.nodes.length === 0
                    ? "（暂无评估节点）"
                    : unusableInListCount > 0
                    ? `（${unusableInListCount} 个不可用）`
                    : "（全部可用）"}
                </div>
              </div>
              <div className="guard-card" style={statPadStyle}>
                <div style={statLblStyle}>已屏蔽禁区与不可用</div>
                <div
                  data-testid="nodes-blocked-count"
                  style={{ ...statNumStyle, color: "var(--text-2)" }}
                >
                  {totalUnavailableAndBlocked}
                  <span style={statUnitStyle}>个</span>
                </div>
                <div
                  data-testid="nodes-blocked-breakdown"
                  style={{ fontSize: 11, color: "var(--text-3)", marginTop: 3 }}
                >
                  名称禁区 {nameBlockedCount} · 落地禁区 {landingBlockedNodes.length}
                  {otherUnusableNodes.length > 0 ? ` · 其他不可用 ${otherUnusableNodes.length}` : ""}
                </div>
              </div>
              <div className="guard-card" style={statPadStyle}>
                <div style={statLblStyle}>Mihomo 连接状态</div>
                <div
                  data-testid="mihomo-conn-status"
                  style={{
                    fontSize: 14.5,
                    fontWeight: 600,
                    marginTop: 6,
                    lineHeight: 1.35,
                    color: nodeReport.connected ? "var(--success)" : "var(--danger-bright)",
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {nodeReport.connected ? `管道已连接 (${nodeReport.groupName})` : "未连接"}
                </div>
              </div>
            </div>

            <div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: 10,
                }}
              >
                <div style={{ fontSize: 14, fontWeight: 600 }}>
                  可用节点评估（{usableNodes.length} 个）
                </div>
                <span style={{ fontSize: 12, color: "var(--text-3)" }}>
                  {deepAudit.running
                    ? deepAudit.message
                    : "已剔除 HK / MO / CN / RU 禁区 · 核验结果持久化缓存 24h（漂移自动重测）· AGY 仅作附带参考"}
                </span>
              </div>
              <div className="guard-card" style={{ overflowX: "auto" }}>
                {usableNodes.length === 0 ? (
                  <div style={{ padding: 18, fontSize: 12.5, color: "var(--text-2)" }}>
                    {nodeReport.connected
                      ? nodeReport.nodes.length > 0
                        ? "当前组内评估节点均已移入下方不可用隔离区，请更换订阅或重新深度核验。"
                        : "当前策略组中暂无非禁区代理节点，请检查 Clash 订阅或完成 Script.js 覆写配置。"
                      : "尚未检测到在线的 Clash Verge Mihomo 命名管道，请先启动 Clash Verge Rev。"}
                  </div>
                ) : (
                  <table
                    data-testid="nodes-eval-table"
                    style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}
                  >
                    <colgroup>
                      <col style={{ width: "20%" }} />
                      <col style={{ width: "20%" }} />
                      <col style={{ width: "14%" }} />
                      <col style={{ width: "22%" }} />
                      <col style={{ width: "12%" }} />
                      <col style={{ width: "12%" }} />
                    </colgroup>
                    <thead>
                      <tr
                        style={{
                          borderBottom: "1px solid var(--border)",
                          color: "var(--text-3)",
                          fontSize: 11.5,
                        }}
                      >
                        <th style={thStyle}>节点 / 地区</th>
                        <th style={thCompactStyle}>平台支持</th>
                        <th style={thCompactStyle}>节点类型</th>
                        <th style={thCompactStyle}>延迟 / 断连 / 稳定性</th>
                        <th style={thCompactStyle}>质量评分</th>
                        <th style={{ ...thStyle, textAlign: "right" }}>操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {usableNodes.map((n: NodeItem) => {
                        const isSwitchingThis = switchingNodeName === n.name;
                        const isAuditingThis =
                          deepAudit.running && deepAudit.currentNode === n.name;
                        const claudeStatus = n.claudeStatus ?? (n.cfBlocked ? "cf_403" : "ok");
                        const claudeLabel = n.claudeLabel ?? (n.cfBlocked ? "Claude 拉黑" : "Claude ✓");
                        const claudeTip = getClaudeBadgeTip(claudeStatus, claudeLabel, n.claudeProbeDetail);
                        const claudeCls =
                          n.cfBlocked ||
                          claudeStatus === "cf_403" ||
                          claudeStatus === "blocked" ||
                          claudeStatus === "offline"
                            ? "guard-chip-fail"
                            : claudeStatus === "cf_challenge" || n.webCfChallenge
                            ? "guard-chip-warn"
                            : "guard-chip-neutral";

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
                        const geminiCls =
                          geminiStatus === "cn_redirect" || geminiStatus === "restricted"
                            ? "guard-chip-warn"
                            : "guard-chip-neutral";

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
                            : "切入后实测 IP");
                        const nodeTypeTip = getNodeTypeTip(riskLevel, asnShort);
                        const isTypeFail = riskLevel === "abuser" || asnShort.includes("禁区") || asnShort.includes("拉黑");
                        const isTypeWarn = riskLevel === "proxy";

                        const driftCount = n.driftCount24h ?? 0;
                        const dropFail = n.dropRatePct >= DROP_RATE_REDLINE;
                        const dropWarn = !dropFail && n.dropRatePct > 0.5;
                        const stabWarn = driftCount > 0 || n.jitterMs >= 25;
                        const stabilityTip =
                          driftCount > 0
                            ? `最近 24 小时检测到该节点落地 IP 静默切换 ${driftCount} 次（抖动 ±${n.jitterMs} ms），会话中途变 IP 易触发风控。`
                            : `多轮实测延迟抖动 ±${n.jitterMs} ms，最近 24 小时落地 IP 稳定（0 次漂移）。`;

                        const isUnusable = n.blocked || n.cfBlocked;
                        const scoreFail = isUnusable;
                        const scoreWarn = !scoreFail && (n.score < 75 || n.webCfChallenge || driftCount > 0 || isTypeWarn);
                        const scoreColor = scoreFail
                          ? "var(--danger-bright)"
                          : scoreWarn
                          ? "var(--warning)"
                          : "var(--text-1)";
                        const evalColor = scoreFail
                          ? "var(--danger-bright)"
                          : scoreWarn
                          ? "var(--warning)"
                          : "var(--text-3)";

                        const subRegion = n.regionLabel ?? `${n.regionCode} · ${n.nodeType}`;

                        return (
                          <tr key={n.name} style={{ borderBottom: "1px solid var(--border)" }}>
                            <td style={tdStyle}>
                              <div
                                style={{
                                  fontWeight: n.isCurrent ? 600 : 500,
                                  color: n.isCurrent ? "var(--success)" : "var(--text-1)",
                                  whiteSpace: "nowrap",
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                }}
                                title={n.name}
                              >
                                {n.name}
                              </div>
                              <div style={{ fontSize: 11, color: "var(--text-3)", marginTop: 2 }}>
                                {subRegion}
                              </div>
                            </td>
                            <td style={tdCompactStyle}>
                              {isAuditingThis ? (
                                <span
                                  className="guard-chip guard-chip-warn"
                                  style={{ display: "inline-flex", alignItems: "center", gap: 5 }}
                                >
                                  <Loader2 size={10} strokeWidth={2.2} className="guard-spin" />
                                  <span>逐项检测中...</span>
                                </span>
                              ) : (
                                <div className="plat-badges" style={{ flexWrap: "nowrap" }}>
                                  <span
                                    className={`guard-chip ${claudeCls}`}
                                    style={{ cursor: "help" }}
                                    title={claudeTip}
                                    onMouseEnter={(e) => showTip(e, claudeTip)}
                                    onMouseLeave={hideTip}
                                  >
                                    {claudeLabel}
                                  </span>
                                  <span
                                    className={`guard-chip ${geminiCls}`}
                                    style={{ cursor: "help" }}
                                    title={geminiTip}
                                    onMouseEnter={(e) => showTip(e, geminiTip)}
                                    onMouseLeave={hideTip}
                                  >
                                    {geminiLabel}
                                  </span>
                                </div>
                              )}
                            </td>
                            <td style={tdCompactStyle}>
                              {isAuditingThis ? (
                                <div
                                  style={{
                                    display: "inline-flex",
                                    alignItems: "center",
                                    gap: 5,
                                    color: "var(--warning)",
                                    fontSize: 12,
                                  }}
                                >
                                  <Loader2 size={11} strokeWidth={2} className="guard-spin" />
                                  <span>核验 IP 中...</span>
                                </div>
                              ) : (
                                <div
                                  style={{ display: "inline-block", cursor: "help" }}
                                  title={nodeTypeTip}
                                  onMouseEnter={(e) => showTip(e, nodeTypeTip)}
                                  onMouseLeave={hideTip}
                                >
                                  {isTypeFail ? (
                                    <span className="guard-chip guard-chip-fail">{asnShort}</span>
                                  ) : isTypeWarn ? (
                                    <span className="guard-chip guard-chip-warn">{asnShort}</span>
                                  ) : (
                                    <div
                                      style={{
                                        fontWeight: 500,
                                        color: riskLevel === "isp" ? "var(--text-1)" : "var(--text-2)",
                                      }}
                                    >
                                      {asnShort}
                                    </div>
                                  )}
                                  <div
                                    style={{
                                      fontSize: 11,
                                      color: isTypeFail ? "var(--danger-bright)" : "var(--text-3)",
                                      marginTop: 2,
                                    }}
                                  >
                                    {riskDetail}
                                  </div>
                                </div>
                              )}
                            </td>
                            <td className="tabular" style={tdCompactStyle}>
                              <div style={{ color: "var(--text-1)" }}>
                                <span>{n.delayMs !== null ? `${n.delayMs} ms` : "超时"}</span>
                                <span style={{ color: "var(--text-3)", margin: "0 4px" }}>/</span>
                                <span
                                  style={{
                                    color: dropFail
                                      ? "var(--danger-bright)"
                                      : dropWarn
                                      ? "var(--warning)"
                                      : "var(--text-2)",
                                    fontWeight: dropFail || dropWarn ? 500 : 400,
                                  }}
                                >
                                  {n.dropRatePct.toFixed(1)}% 断连
                                </span>
                              </div>
                              <div
                                style={{
                                  fontSize: 11,
                                  marginTop: 2,
                                  color: stabWarn ? "var(--warning)" : "var(--text-3)",
                                  fontWeight: stabWarn ? 500 : 400,
                                  cursor: "help",
                                  display: "inline-block",
                                }}
                                title={stabilityTip}
                                onMouseEnter={(e) => showTip(e, stabilityTip)}
                                onMouseLeave={hideTip}
                              >
                                抖动 ±{n.jitterMs} ms ·{" "}
                                {driftCount > 0 ? `漂移 ${driftCount}次` : "0 漂移"}
                              </div>
                            </td>
                            <td className="tabular" style={tdCompactStyle}>
                              <div
                                style={{
                                  display: "flex",
                                  flexDirection: "column",
                                  alignItems: "flex-start",
                                  gap: 2,
                                }}
                              >
                                <div
                                  style={{
                                    fontSize: 18,
                                    fontWeight: 700,
                                    lineHeight: 1.1,
                                    letterSpacing: "-0.02em",
                                    color: scoreColor,
                                  }}
                                >
                                  {n.score}
                                  <span
                                    style={{
                                      fontSize: 11,
                                      fontWeight: 400,
                                      color: "var(--text-3)",
                                      marginLeft: 2,
                                    }}
                                  >
                                    分
                                  </span>
                                </div>
                                <div style={{ fontSize: 11, color: evalColor }}>
                                  {n.recommendation || (n.cfBlocked ? "拉黑不可用" : "可用")}
                                </div>
                              </div>
                            </td>
                            <td style={{ ...tdStyle, textAlign: "right" }}>
                              {n.isCurrent ? (
                                <span
                                  className="guard-chip guard-chip-ok"
                                  style={{ padding: "4px 9px", fontSize: 11.5 }}
                                >
                                  当前锁定
                                </span>
                              ) : (
                                <button
                                  type="button"
                                  disabled={fixing || isUnusable}
                                  className="guard-btn guard-btn-flat guard-btn-xs"
                                  onClick={() => requestSwitch(n.name)}
                                >
                                  {isSwitchingThis && (
                                    <Loader2 size={12} strokeWidth={2} className="guard-spin" />
                                  )}
                                  <span>
                                    {isSwitchingThis
                                      ? "切换中..."
                                      : isUnusable
                                      ? "不可用"
                                      : "切换锁定"}
                                  </span>
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </div>

            {unusableNodes.length > 0 && (
              <div data-testid="nodes-quarantine-section">
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => setShowQuarantine((v) => !v)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setShowQuarantine((v) => !v);
                    }
                  }}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    marginBottom: 8,
                    cursor: "pointer",
                    userSelect: "none",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 13.5, fontWeight: 600, color: "var(--danger-bright)" }}>
                    {showQuarantine ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                    <ShieldAlert size={14.5} strokeWidth={1.9} />
                    <span>隔离区：不可用与落地禁区节点（{unusableNodes.length} 个）</span>
                    <span className="guard-chip guard-chip-fail" style={{ fontWeight: 500 }}>
                      落地禁区 {landingBlockedNodes.length}
                      {otherUnusableNodes.length > 0 ? ` · 超时/拉黑 ${otherUnusableNodes.length}` : ""}
                    </span>
                  </div>
                  <span style={{ fontSize: 11.5, color: "var(--text-3)" }}>
                    已与可用节点隔离，禁止切换锁定 · 点击{showQuarantine ? "收起" : "展开"}
                  </span>
                </div>

                {showQuarantine && (
                  <div
                    className="guard-card"
                    style={{
                      overflowX: "auto",
                      borderColor: "rgba(239, 68, 68, 0.28)",
                      background: "var(--bg-subtle)",
                    }}
                  >
                    <table
                      data-testid="nodes-quarantine-table"
                      style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}
                    >
                      <colgroup>
                        <col style={{ width: "20%" }} />
                        <col style={{ width: "20%" }} />
                        <col style={{ width: "14%" }} />
                        <col style={{ width: "22%" }} />
                        <col style={{ width: "12%" }} />
                        <col style={{ width: "12%" }} />
                      </colgroup>
                      <thead>
                        <tr
                          style={{
                            borderBottom: "1px solid var(--border)",
                            color: "var(--text-3)",
                            fontSize: 11.5,
                          }}
                        >
                          <th style={thStyle}>隔离节点 / 实测落地</th>
                          <th style={thCompactStyle}>阻断原因</th>
                          <th style={thCompactStyle}>节点类型</th>
                          <th style={thCompactStyle}>延迟 / 断连 / 稳定性</th>
                          <th style={thCompactStyle}>质量评分</th>
                          <th style={{ ...thStyle, textAlign: "right" }}>状态</th>
                        </tr>
                      </thead>
                      <tbody>
                        {unusableNodes.map((n: NodeItem) => {
                          const isAuditingThis =
                            deepAudit.running && deepAudit.currentNode === n.name;
                          const claudeStatus = n.claudeStatus ?? (n.cfBlocked ? "cf_403" : "blocked");
                          const claudeLabel = n.claudeLabel ?? (n.cfBlocked ? "Claude 拉黑" : "落地禁区");
                          const claudeTip = getClaudeBadgeTip(claudeStatus, claudeLabel, n.claudeProbeDetail);
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
                          const geminiCls =
                            geminiStatus === "cn_redirect" || geminiStatus === "restricted"
                              ? "guard-chip-warn"
                              : "guard-chip-neutral";
                          const riskLevel = n.riskLevel ?? (claudeStatus === "blocked" ? "blocked" : "unknown");
                          const asnShort = n.asnShort ?? (claudeStatus === "blocked" ? "落地禁区" : "不可用");
                          const nodeTypeTip = getNodeTypeTip(riskLevel, asnShort);
                          const subRegion = n.regionLabel ?? `${n.regionCode} · ${n.nodeType}`;
                          return (
                            <tr
                              key={n.name}
                              style={{ borderBottom: "1px solid var(--border)", opacity: 0.92 }}
                            >
                              <td style={tdStyle}>
                                <div
                                  style={{
                                    fontWeight: 500,
                                    color: "var(--text-2)",
                                    whiteSpace: "nowrap",
                                    overflow: "hidden",
                                    textOverflow: "ellipsis",
                                  }}
                                  title={n.name}
                                >
                                  {n.name}
                                </div>
                                <div style={{ fontSize: 11, color: "var(--text-3)", marginTop: 2 }}>
                                  {subRegion}
                                </div>
                              </td>
                              <td style={tdCompactStyle}>
                                <div className="plat-badges" style={{ flexWrap: "nowrap" }}>
                                  <span
                                    className="guard-chip guard-chip-fail"
                                    style={{ cursor: "help" }}
                                    title={claudeTip}
                                    onMouseEnter={(e) => showTip(e, claudeTip)}
                                    onMouseLeave={hideTip}
                                  >
                                    {claudeLabel}
                                  </span>
                                  <span
                                    className={`guard-chip ${geminiCls}`}
                                    style={{ cursor: "help" }}
                                    title={geminiTip}
                                    onMouseEnter={(e) => showTip(e, geminiTip)}
                                    onMouseLeave={hideTip}
                                  >
                                    {geminiLabel}
                                  </span>
                                </div>
                              </td>
                              <td style={tdCompactStyle}>
                                <div
                                  style={{ display: "inline-block", cursor: "help" }}
                                  title={nodeTypeTip}
                                  onMouseEnter={(e) => showTip(e, nodeTypeTip)}
                                  onMouseLeave={hideTip}
                                >
                                  <span className="guard-chip guard-chip-fail">{asnShort}</span>
                                  <div style={{ fontSize: 11, color: "var(--danger-bright)", marginTop: 2 }}>
                                    {n.riskDetail ?? "已隔离"}
                                  </div>
                                </div>
                              </td>
                              <td className="tabular" style={tdCompactStyle}>
                                <div style={{ color: "var(--text-2)" }}>
                                  <span>{n.delayMs !== null ? `${n.delayMs} ms` : "超时"}</span>
                                  <span style={{ color: "var(--text-3)", margin: "0 4px" }}>/</span>
                                  <span>{n.dropRatePct.toFixed(1)}% 断连</span>
                                </div>
                                <div style={{ fontSize: 11, color: "var(--text-3)", marginTop: 2 }}>
                                  抖动 ±{n.jitterMs} ms · {n.driftCount24h ?? 0} 漂移
                                </div>
                              </td>
                              <td className="tabular" style={tdCompactStyle}>
                                <div style={{ fontSize: 18, fontWeight: 700, color: "var(--danger-bright)", lineHeight: 1.1 }}>
                                  {n.score}
                                  <span style={{ fontSize: 11, fontWeight: 400, color: "var(--text-3)", marginLeft: 2 }}>分</span>
                                </div>
                                <div style={{ fontSize: 11, color: "var(--danger-bright)", marginTop: 2 }}>
                                  {n.recommendation || "不可用"}
                                </div>
                              </td>
                              <td style={{ ...tdStyle, textAlign: "right" }}>
                                <div style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                                  <button
                                    type="button"
                                    data-testid={`btn-reprobe-node-${n.name}`}
                                    disabled={deepAudit.running || fixing}
                                    className="guard-btn guard-btn-flat guard-btn-xs"
                                    title="仅单独重新实测该节点的真实出口与 Claude 可达性（无需全量重测）"
                                    onClick={() => void startDeepNodeAudit(false, n.name)}
                                  >
                                    {isAuditingThis ? (
                                      <Loader2 size={11} strokeWidth={2} className="guard-spin" />
                                    ) : (
                                      <RefreshCw size={11} strokeWidth={1.85} />
                                    )}
                                    <span>{isAuditingThis ? "重测中" : "重测"}</span>
                                  </button>
                                  <span className="guard-chip guard-chip-fail">已隔离</span>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}
          </>
        ) : (
          <>
            <div
              className="tabular"
              style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12 }}
            >
              <div className="guard-card" style={statPadStyle}>
                <div style={statLblStyle}>12h 未确认拦截</div>
                <div
                  style={{
                    ...statNumStyle,
                    color: activeAnomCount > 0 ? "var(--danger-bright)" : "var(--success)",
                  }}
                >
                  {activeAnomCount}
                  <span style={statUnitStyle}>条</span>
                </div>
              </div>
              <div className="guard-card" style={statPadStyle}>
                <div style={statLblStyle}>活跃安全连接</div>
                <div style={{ ...statNumStyle, color: "var(--success)" }}>
                  {conns.length - totalAnomCount}
                  <span style={statUnitStyle}>条</span>
                </div>
              </div>
              <div className="guard-card" style={statPadStyle}>
                <div style={statLblStyle}>Claude 总连接数</div>
                <div style={statNumStyle}>
                  {conns.length}
                  <span style={statUnitStyle}>条</span>
                </div>
              </div>
              <div className="guard-card" style={statPadStyle}>
                <div style={statLblStyle}>锁定策略组</div>
                <div style={{ fontSize: 14.5, fontWeight: 600, marginTop: 6, lineHeight: 1.35 }}>
                  {nodeReport.groupName}
                </div>
              </div>
            </div>

            <div className="guard-card">
              <div
                style={{
                  padding: "10px 14px",
                  background: activeAnomCount > 0 ? "var(--danger-soft)" : "var(--bg-subtle)",
                  color: activeAnomCount > 0 ? "var(--danger-bright)" : "var(--text-1)",
                  fontSize: 13,
                  fontWeight: 600,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                <span>Claude 实时连接监控（Mihomo /connections · 12h 滚动拦截窗口）</span>
                <div style={segWrapStyle}>
                  <button
                    type="button"
                    style={segBtnStyle(flowFilter === "anomaly")}
                    onClick={() => setFlowFilter("anomaly")}
                  >
                    仅看异常 ({totalAnomCount})
                  </button>
                  <button
                    type="button"
                    style={segBtnStyle(flowFilter === "all")}
                    onClick={() => setFlowFilter("all")}
                  >
                    全部实时连接 ({conns.length})
                  </button>
                </div>
              </div>

              {shownConns.length === 0 ? (
                <div style={{ padding: 18, fontSize: 12.5, color: "var(--text-2)" }}>
                  {!nodeReport.connected
                    ? "尚未连接 Clash Verge Mihomo 命名管道，暂无法采集实时连接流量。"
                    : "近 12 小时无异常拦截流量，全部连接均纯净通过锁定节点。"}
                </div>
              ) : (
                shownConns.map((c) => {
                  const acked = ackedFlowIds.includes(c.id);
                  return (
                    <div
                      key={c.id}
                      style={{
                        padding: "12px 14px",
                        borderBottom: "1px solid var(--border)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        gap: 12,
                      }}
                    >
                      <div>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <span
                            className={`guard-chip ${
                              c.anomaly
                                ? acked
                                  ? "guard-chip-neutral"
                                  : "guard-chip-fail"
                                : "guard-chip-ok"
                            }`}
                          >
                            {c.anomaly ? (acked ? "已确认 · 历史拦截" : "异常风险") : "安全放行"}
                          </span>
                          <span className="font-mono-code" style={{ fontSize: 12.5, fontWeight: 500 }}>
                            {c.process} → {c.host}
                          </span>
                        </div>
                        <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 3 }}>
                          规则：{c.rule} · 链路：{c.chain} · {c.action}
                        </div>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
                        <div style={{ textAlign: "right" }}>
                          <div className="tabular" style={{ fontSize: 11, color: "var(--text-3)" }}>
                            {c.time}
                          </div>
                          <div className="tabular" style={{ fontSize: 11, color: "var(--text-2)" }}>
                            {c.bytesLabel}
                          </div>
                        </div>
                        <button
                          type="button"
                          disabled={closingConnId !== null}
                          className={`guard-btn ${
                            c.anomaly ? "guard-btn-danger-soft" : "guard-btn-flat"
                          } guard-btn-xs`}
                          onClick={() => void handleCloseConn(c.id)}
                        >
                          {closingConnId === c.id ? "掐断中..." : "掐断"}
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </>
        )}
      </div>
    </section>
  );
}

const pageHdStyle: React.CSSProperties = {
  padding: "16px 22px 14px",
  borderBottom: "1px solid var(--border)",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 14,
  flexShrink: 0,
};

const pageTitleStyle: React.CSSProperties = {
  fontSize: 20,
  fontWeight: 600,
  letterSpacing: "-0.02em",
  margin: 0,
};

const pageSubStyle: React.CSSProperties = {
  fontSize: 12,
  color: "var(--text-2)",
  marginTop: 4,
};

const segWrapStyle: React.CSSProperties = {
  display: "inline-flex",
  padding: 2,
  borderRadius: 8,
  background: "var(--bg-subtle)",
  border: "1px solid var(--border)",
  gap: 2,
};

function segBtnStyle(active: boolean): React.CSSProperties {
  return {
    border: "none",
    background: active ? "var(--bg-card)" : "transparent",
    color: active ? "var(--text-1)" : "var(--text-2)",
    padding: "4px 10px",
    borderRadius: 6,
    fontFamily: "var(--font-sans)",
    fontSize: 12,
    fontWeight: active ? 600 : 500,
    cursor: "pointer",
  };
}

const statPadStyle: React.CSSProperties = { padding: "12px 15px" };
const statLblStyle: React.CSSProperties = { fontSize: 12, color: "var(--text-2)" };
const statNumStyle: React.CSSProperties = {
  fontSize: 18,
  fontWeight: 600,
  letterSpacing: "-0.01em",
  marginTop: 6,
  lineHeight: 1.25,
};
const statUnitStyle: React.CSSProperties = {
  fontSize: 12,
  fontWeight: 500,
  color: "var(--text-3)",
  marginLeft: 3,
};
const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "10px 14px",
  fontWeight: 500,
  whiteSpace: "nowrap",
};
const thCompactStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "10px 12px",
  fontWeight: 500,
  whiteSpace: "nowrap",
};
const tdStyle: React.CSSProperties = {
  padding: "11px 14px",
  verticalAlign: "middle",
  whiteSpace: "nowrap",
};
const tdCompactStyle: React.CSSProperties = {
  padding: "11px 12px",
  verticalAlign: "middle",
  whiteSpace: "nowrap",
};
