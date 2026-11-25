import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  ArrowLeftFromLine,
  ArrowRightToLine,
  ChevronLeft,
  ChevronUp,
  Home,
  Pin,
  X,
} from "lucide-react";
import { DEFAULT_CONFIG, FALLBACK_SNAPSHOT, ipc, isTauriRuntime } from "@/lib/ipc";
import { extractRegionCode } from "@/lib/protocol";
import type { AppConfig, GuardSnapshot, NavTab } from "@/types/guard";

interface HudCardProps {
  initialConfig?: AppConfig;
  initialSnapshot?: GuardSnapshot;
  onGoConsole?: (focusFirstFail?: boolean, tab?: NavTab, subTab?: string | null) => void;
}

/**
 * 桌面悬浮状态卡（v2.2：348px 黄金宽 + 三段式去重架构 + 整卡 5px 死区拖拽 + 20x84px 单坐标零偏移贴边）
 * 红线：纯状态雷达与跳转入口，不直接执行业务操作；开关图标无彩色底块与下划线。
 */
export function HudCard({ initialConfig, initialSnapshot, onGoConsole }: HudCardProps) {
  const [config, setConfig] = useState<AppConfig>(initialConfig ?? DEFAULT_CONFIG);
  const [snapshot, setSnapshot] = useState<GuardSnapshot>(initialSnapshot ?? FALLBACK_SNAPSHOT);
  const [dockedOpen, setDockedOpen] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [shellPos, setShellPos] = useState<{ left: number | null; top: number }>({
    left: null,
    top: 64,
  });

  const cardRef = useRef<HTMLDivElement | null>(null);
  const shellRef = useRef<HTMLDivElement | null>(null);
  const dockCloseTimerRef = useRef<number | null>(null);
  const suppressClickTimerRef = useRef<number | null>(null);
  const lastReportedSizeRef = useRef<{ w: number; h: number; dpr: number } | null>(null);

  // 整卡任意位置拖拽状态（5px 防误触死区）
  const dragStateRef = useRef({
    pending: false,
    active: false,
    suppressClick: false,
    startX: 0,
    startY: 0,
    grabOffsetX: 0,
    grabOffsetY: 0,
  });

  const tauriMode = isTauriRuntime();

  // 支持非 Tauri 预览通过 URL 参数快速切换深浅主题/状态（仅预览/QA 自审有效）
  useEffect(() => {
    if (tauriMode || initialSnapshot) return;
    const params = new URLSearchParams(window.location.search);
    const themeParam = params.get("theme");
    if (themeParam === "light" || themeParam === "dark") {
      document.documentElement.setAttribute("data-theme", themeParam);
      setConfig((c) => ({ ...c, theme: themeParam }));
    }
    const stateParam = params.get("state");
    if (stateParam === "ok") {
      setSnapshot((s) => ({
        ...s,
        healthLevel: "ok",
        statusLabel: "守护正常",
        currentNode: "US-LA-Static-01",
        regionCode: "US",
        exitIpMasked: "104.28.xx.xx",
        latencyMs: 42,
        latencyLabel: "42 ms",
        mustPassed: 11,
        mustTotal: 11,
        clashOnline: true,
        killSwitchActive: false,
        nodeDown: false,
        unreadLogAnomalies: 0,
        activeFlowAnomalies: 0,
        bgClaudeProcs: 0,
        hudEvents: [
          { message: "11 项启动前真实探针与卫生检查全部通过", time: "21:01", level: "ok", targetTab: "console" },
          { message: "开机监测：Claude 设了自启，留意裸奔风险", time: "21:00", level: "warn", targetTab: "config" },
        ],
      }));
    } else if (stateParam === "danger") {
      setSnapshot((s) => ({
        ...s,
        healthLevel: "danger",
        statusLabel: "已自动熔断",
        currentNode: "HK-Edge-03 · 禁区阻断",
        regionCode: "HK",
        exitIpMasked: "防火墙已锁死全部出站",
        latencyMs: null,
        latencyLabel: "已阻断",
        mustPassed: 9,
        mustTotal: 11,
        clashOnline: true,
        killSwitchActive: true,
        nodeDown: false,
        unreadLogAnomalies: 2,
        activeFlowAnomalies: 3,
        bgClaudeProcs: 0,
        hudEvents: [
          { message: "防火墙已锁死 Claude 全部出站流量", time: "21:02", level: "danger", targetTab: "console" },
          { message: "Clash 已强掐 HK-Edge-03 禁区连接", time: "21:02", level: "danger", targetTab: "nodes" },
        ],
      }));
    } else if (stateParam === "warn") {
      setSnapshot((s) => ({
        ...s,
        healthLevel: "warn",
        statusLabel: "2 项待办",
        currentNode: "US-LA-Static-01",
        regionCode: "US",
        exitIpMasked: "104.28.xx.xx",
        latencyMs: 42,
        latencyLabel: "42 ms",
        mustPassed: 9,
        mustTotal: 11,
        clashOnline: true,
        killSwitchActive: false,
        nodeDown: false,
        unreadLogAnomalies: 1,
        activeFlowAnomalies: 1,
        bgClaudeProcs: 2,
        hudEvents: [
          { message: "主日志检出跨账号 orgId 竞态高危记录", time: "13:00", level: "danger", targetTab: "logs" },
          { message: "拦截漏规则连接 HK-Edge-03（已自动掐断）", time: "20:54", level: "warn", targetTab: "nodes" },
        ],
      }));
    } else if (stateParam === "hold") {
      setSnapshot((s) => ({
        ...s,
        healthLevel: "ok",
        statusLabel: "守护正常",
        currentNode: "US-LA-Static-01",
        regionCode: "US",
        exitIpMasked: "104.28.xx.xx",
        latencyMs: 42,
        latencyLabel: "42 ms",
        mustPassed: 10,
        mustTotal: 10,
        clashOnline: true,
        killSwitchActive: false,
        killHoldActive: true,
        killHoldRemainingSecs: 45,
        killHoldBlockedCount: 1,
        killHoldTxLocked: false,
        nodeDown: false,
        unreadLogAnomalies: 0,
        activeFlowAnomalies: 0,
        bgClaudeProcs: 0,
        hudEvents: [
          { message: "防复活持续盯防中（45s · 已拦截 1 次复活）", time: "21:05", level: "ok", targetTab: "console" },
          { message: "10 项启动前真实探针与卫生检查全部通过", time: "21:01", level: "ok", targetTab: "console" },
        ],
      }));
    }
  }, [tauriMode, initialSnapshot]);

  // 动态贴合 Tauri 独立窗口物理尺寸（带尺寸去重与 32ms 防抖，杜绝 ResizeObserver 高频 IPC 与冗余重建）
  useLayoutEffect(() => {
    if (!tauriMode) return;
    if (config.hudEdgeDocked && !dockedOpen) return;
    const el = cardRef.current;
    if (!el) return;
    let debounceTimer: number | null = null;
    const syncSize = () => {
      const h = Math.ceil(el.offsetHeight);
      const w = Math.max(348, Math.ceil(el.offsetWidth));
      if (h > 40) {
        const dpr = typeof window !== "undefined" ? window.devicePixelRatio || 1 : 1;
        const prev = lastReportedSizeRef.current;
        if (prev && prev.w === w && prev.h === h && prev.dpr === dpr) {
          return;
        }
        lastReportedSizeRef.current = { w, h, dpr };
        void ipc.resizeHudHeight(h + 12, w + 12, dpr);
      }
    };
    const scheduleSync = () => {
      if (debounceTimer !== null) {
        window.clearTimeout(debounceTimer);
      }
      debounceTimer = window.setTimeout(syncSize, 32);
    };
    syncSize();
    const rafId = window.requestAnimationFrame(syncSize);
    let ro: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      ro = new ResizeObserver(scheduleSync);
      ro.observe(el);
    }
    return () => {
      window.cancelAnimationFrame(rafId);
      if (debounceTimer !== null) {
        window.clearTimeout(debounceTimer);
      }
      ro?.disconnect();
    };
  }, [tauriMode, config.hudFolded, config.hudEdgeDocked, dockedOpen]);

  useEffect(() => {
    let mounted = true;
    const params = !tauriMode ? new URLSearchParams(window.location.search) : null;
    const hasPreviewOverride = Boolean(params && (params.get("state") || params.get("theme")));
    const sync = async () => {
      try {
        const [cfg, snap] = await Promise.all([ipc.getConfig(), ipc.getSnapshot()]);
        if (!mounted) return;
        if (!hasPreviewOverride) {
          document.documentElement.setAttribute("data-theme", cfg.theme);
          setConfig(cfg);
          setSnapshot(snap);
        }
      } catch {
        // 忽略启动瞬态 IPC 异常
      }
    };
    if (!initialConfig && !hasPreviewOverride) {
      void sync();
    } else if (initialConfig) {
      document.documentElement.setAttribute("data-theme", initialConfig.theme);
    }

    const unsubs: Array<() => void> = [];
    const register = (p: Promise<() => void>) => {
      void p.then((fn) => {
        if (!mounted) {
          fn();
        } else {
          unsubs.push(fn);
        }
      });
    };
    register(
      ipc.listenSnapshot((snap) => {
        if (mounted) setSnapshot(snap);
      })
    );
    register(
      ipc.listenConfigChanged((cfg) => {
        if (!mounted) return;
        document.documentElement.setAttribute("data-theme", cfg.theme);
        setConfig(cfg);
      })
    );

    return () => {
      mounted = false;
      unsubs.forEach((fn) => fn());
      if (dockCloseTimerRef.current !== null) {
        window.clearTimeout(dockCloseTimerRef.current);
      }
      if (suppressClickTimerRef.current !== null) {
        window.clearTimeout(suppressClickTimerRef.current);
      }
    };
  }, [initialConfig, tauriMode]);

  const clearDockTimer = useCallback(() => {
    if (dockCloseTimerRef.current !== null) {
      window.clearTimeout(dockCloseTimerRef.current);
      dockCloseTimerRef.current = null;
    }
  }, []);

  const handleTogglePin = async () => {
    const next = !config.hudPinned;
    setConfig((c) => ({ ...c, hudPinned: next }));
    await ipc.setHudPinned(next);
  };

  const handleToggleFold = async () => {
    const next = !config.hudFolded;
    setConfig((c) => ({ ...c, hudFolded: next }));
    await ipc.setHudFolded(next);
  };

  const handleToggleEdgeDock = useCallback(async () => {
    clearDockTimer();
    const next = !config.hudEdgeDocked;
    if (next) {
      // 贴边收起：清除拖拽 left，以右距 16px 为单坐标锚点
      setShellPos((p) => ({ left: null, top: p.top }));
      setDockedOpen(false);
    } else {
      // 解除贴边：保持当前 Y 与右距 16px，零偏移还原为固定态
      setShellPos((p) => ({ left: null, top: p.top }));
      setDockedOpen(false);
    }
    setConfig((c) => ({ ...c, hudEdgeDocked: next }));
    await ipc.setHudEdgeDocked(next, false);
  }, [clearDockTimer, config.hudEdgeDocked]);

  const handleEdgeEnter = useCallback(() => {
    if (!config.hudEdgeDocked) return;
    clearDockTimer();
    setDockedOpen(true);
    if (tauriMode) {
      void ipc.setHudEdgeDocked(true, true);
    }
  }, [clearDockTimer, config.hudEdgeDocked, tauriMode]);

  const handleShellLeave = useCallback(() => {
    if (!config.hudEdgeDocked || dragStateRef.current.active) return;
    clearDockTimer();
    dockCloseTimerRef.current = window.setTimeout(() => {
      setDockedOpen(false);
      if (tauriMode) {
        void ipc.setHudEdgeDocked(true, false);
      }
    }, 220);
  }, [clearDockTimer, config.hudEdgeDocked, tauriMode]);

  const handleNavigate = useCallback(
    (tab: NavTab = "console", subTab: string | null = null, focusFirstFail = false) => {
      if (dragStateRef.current.suppressClick) return;
      if (onGoConsole) {
        onGoConsole(focusFirstFail, tab, subTab);
        return;
      }
      void ipc.showMainWindow({
        tab,
        subTab,
        focusItemId: focusFirstFail ? "__first_fail__" : null,
      });
    },
    [onGoConsole]
  );

  // 整卡任意位置拖拽（5px 防误触死区）
  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      const ds = dragStateRef.current;
      if (!ds.pending) return;

      if (!ds.active) {
        const dist = Math.hypot(e.clientX - ds.startX, e.clientY - ds.startY);
        if (dist < 5) return;
        ds.active = true;
        setDragging(true);

        // 若处于贴边滑出态开始拖拽，自动无缝解除贴边
        if (config.hudEdgeDocked) {
          clearDockTimer();
          setDockedOpen(false);
          setConfig((c) => ({ ...c, hudEdgeDocked: false }));
          void ipc.setHudEdgeDocked(false, false);
        }

        if (tauriMode) {
          // 交由系统窗口原生拖拽，同时释放 JS 监听并设置短暂防误触标记
          ds.pending = false;
          ds.active = false;
          ds.suppressClick = true;
          setDragging(false);
          if (suppressClickTimerRef.current !== null) {
            window.clearTimeout(suppressClickTimerRef.current);
          }
          suppressClickTimerRef.current = window.setTimeout(() => {
            ds.suppressClick = false;
            suppressClickTimerRef.current = null;
          }, 120);
          void ipc.startDraggingCurrentWindow();
          return;
        }
      }

      if (!tauriMode) {
        const cardH = cardRef.current?.offsetHeight || 260;
        const maxLeft = Math.max(8, window.innerWidth - 356);
        const maxTop = Math.max(16, window.innerHeight - Math.min(cardH, 240) - 16);
        const clampedLeft = Math.max(8, Math.min(maxLeft, e.clientX - ds.grabOffsetX));
        const clampedTop = Math.max(16, Math.min(maxTop, e.clientY - ds.grabOffsetY));
        setShellPos({ left: clampedLeft, top: clampedTop });
      }
    };

    const onMouseUp = () => {
      const ds = dragStateRef.current;
      if (!ds.pending) return;
      if (ds.active) {
        ds.suppressClick = true;
        if (suppressClickTimerRef.current !== null) {
          window.clearTimeout(suppressClickTimerRef.current);
        }
        suppressClickTimerRef.current = window.setTimeout(() => {
          ds.suppressClick = false;
          suppressClickTimerRef.current = null;
        }, 80);
      }
      ds.pending = false;
      ds.active = false;
      setDragging(false);
    };

    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, [clearDockTimer, config.hudEdgeDocked, tauriMode]);

  const handleCardMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.button !== 0) return;
    if ((e.target as HTMLElement).closest("button")) return;
    const rect = cardRef.current?.getBoundingClientRect();
    dragStateRef.current = {
      pending: true,
      active: false,
      suppressClick: false,
      startX: e.clientX,
      startY: e.clientY,
      grabOffsetX: rect ? e.clientX - rect.left : 0,
      grabOffsetY: rect ? e.clientY - rect.top : 0,
    };
  };

  const handleCardClickCapture = (e: React.MouseEvent<HTMLDivElement>) => {
    if (dragStateRef.current.suppressClick) {
      e.stopPropagation();
      e.preventDefault();
    }
  };

  const isDanger = snapshot.killSwitchActive || snapshot.nodeDown;
  const mustFail = Math.max(0, snapshot.mustTotal - snapshot.mustPassed);
  const regionCode =
    snapshot.regionCode && snapshot.regionCode !== "GL"
      ? snapshot.regionCode
      : extractRegionCode(snapshot.currentNode);

  const chipClass = isDanger
    ? "guard-chip guard-chip-fail"
    : mustFail > 0
    ? "guard-chip guard-chip-warn"
    : "guard-chip guard-chip-ok";

  const chipText = snapshot.killSwitchActive
    ? "已自动熔断"
    : snapshot.nodeDown
    ? "节点不可用"
    : mustFail > 0
    ? `${mustFail} 项待办`
    : "守护正常";

  const dotClass = isDanger ? "guard-dot danger" : mustFail > 0 ? "guard-dot warn" : "guard-dot";

  const logTotalCount = snapshot.unreadLogAnomalies ?? 0;
  const hasExplicitSplit =
    snapshot.unreadLogCritical !== undefined || snapshot.unreadLogWarnings !== undefined;
  const logCritCount = hasExplicitSplit ? snapshot.unreadLogCritical ?? 0 : logTotalCount;
  const logWarnCount = hasExplicitSplit ? snapshot.unreadLogWarnings ?? 0 : 0;
  const logAnomCount = hasExplicitSplit ? logCritCount + logWarnCount : logTotalCount;
  const logTileLabel =
    logCritCount > 0 && logWarnCount > 0
      ? `风险 ${logWarnCount} · 异常 ${logCritCount}`
      : logCritCount > 0
      ? `异常 ${logCritCount}`
      : logWarnCount > 0
      ? `风险 ${logWarnCount}`
      : "正常";
  const flowAnomCount = snapshot.activeFlowAnomalies ?? 0;
  const liveFlowCount = snapshot.liveFlowAnomalies ?? 0;
  const hasNodeDrift =
    Boolean(snapshot.nodeDriftWarn) || (!snapshot.nodeDown && flowAnomCount > 0 && liveFlowCount === 0);
  const flowRouteSubTab =
    snapshot.killSwitchActive || liveFlowCount > 0
      ? "traffic"
      : snapshot.nodeDown || hasNodeDrift
      ? "quality"
      : "traffic";

  const nodeMetaText = snapshot.killSwitchActive
    ? "防火墙已锁死全部出站"
    : snapshot.nodeDown
    ? "当前节点不可用 · 请手动更换"
    : flowAnomCount > 0
    ? `${snapshot.exitIpMasked} · 存在漂移风险`
    : `${snapshot.exitIpMasked} · 稳定锁定`;

  const logTileTone = logCritCount > 0 ? "is-fail" : logWarnCount > 0 ? "is-warn" : "is-ok";
  const flowTileTone =
    snapshot.killSwitchActive || snapshot.nodeDown
      ? "is-fail"
      : liveFlowCount > 0 || hasNodeDrift
      ? "is-warn"
      : "is-ok";
  const holdActive = Boolean(snapshot.killHoldActive);
  const holdSecs = snapshot.killHoldRemainingSecs ?? 0;
  const holdTx = Boolean(snapshot.killHoldTxLocked);
  const procTileTone = holdActive ? "is-hold" : snapshot.bgClaudeProcs > 0 ? "is-warn" : "is-ok";

  const ctaClass = isDanger ? "hud-cta is-danger" : "hud-cta";
  const logOnlyFocus = !isDanger && mustFail === 0 && logAnomCount > 0;
  const ctaText = snapshot.killSwitchActive
    ? "前往控制台应急处理熔断 →"
    : snapshot.nodeDown
    ? "节点不可用 · 前往手动更换节点 →"
    : mustFail > 0
    ? `前往控制台处理 ${mustFail} 项待办 →`
    : logOnlyFocus
    ? `前往账户审计查看日志（${logTileLabel}） →`
    : "前往控制台安全启动 Claude →";
  const ctaTargetTab: NavTab = snapshot.nodeDown
    ? "nodes"
    : logOnlyFocus
    ? "audit"
    : "console";

  // 贴边收起态（Tauri 原生窗口模式直接全窗渲染 20x84px 耳标）
  const isDockedCollapsed = config.hudEdgeDocked && !dockedOpen;

  if (tauriMode && isDockedCollapsed) {
    return (
      <div
        data-testid="hud-shell"
        className="hud-shell docked"
        style={{ position: "fixed", inset: 0, width: 20, height: 84, right: 0, top: 0 }}
        onMouseEnter={handleEdgeEnter}
      >
        <div
          data-testid="edge-tab"
          className={`edge-tab ${isDanger ? "danger" : ""}`}
          title="鼠标悬浮展开 FD Claude Guard"
          style={{ display: "flex" }}
        >
          <span className={dotClass} />
          <span className="edge-grip" />
          <ChevronLeft size={10} strokeWidth={2} className="edge-chev" />
        </div>
        <style>{HUD_STYLES}</style>
      </div>
    );
  }

  const shellClassName = [
    "hud-shell",
    !config.hudPinned ? "unpinned" : "",
    !tauriMode && config.hudEdgeDocked ? "docked" : "",
    !tauriMode && config.hudEdgeDocked && dockedOpen ? "docked-open" : "",
  ]
    .filter(Boolean)
    .join(" ");

  const shellStyle: React.CSSProperties = tauriMode
    ? {
        position: "relative",
        width: "100%",
        height: "100%",
        padding: 6,
      }
    : config.hudEdgeDocked
    ? {
        position: "fixed",
        top: shellPos.top,
        right: 0,
        left: "auto",
      }
    : shellPos.left !== null
    ? {
        position: "fixed",
        top: shellPos.top,
        left: shellPos.left,
        right: "auto",
      }
    : {
        position: "fixed",
        top: shellPos.top,
        right: 16,
        left: "auto",
      };

  return (
    <div
      ref={shellRef}
      data-testid="hud-shell"
      className={shellClassName}
      style={shellStyle}
      onMouseEnter={config.hudEdgeDocked && dockedOpen ? clearDockTimer : undefined}
      onMouseLeave={handleShellLeave}
    >
      {/* 非 Tauri 预览/测试态：20x84px 精致贴边耳标 */}
      {!tauriMode && (
        <div
          data-testid="edge-tab"
          className={`edge-tab ${isDanger ? "danger" : ""}`}
          title="鼠标悬浮展开 FD Claude Guard"
          onMouseEnter={handleEdgeEnter}
        >
          <span className={dotClass} />
          <span className="edge-grip" />
          <ChevronLeft size={10} strokeWidth={2} className="edge-chev" />
        </div>
      )}

      {/* 348px 黄金宽悬浮卡片主体 */}
      <div
        ref={cardRef}
        data-testid="hud-card"
        className={`hud-v2 ${isDanger ? "danger" : ""} ${config.hudFolded ? "is-folded" : ""} ${
          dragging ? "is-dragging" : ""
        }`}
        onMouseDown={handleCardMouseDown}
        onClickCapture={handleCardClickCapture}
      >
        {/* 顶栏：42px 高 + 左侧状态识别 + 右侧 Lucide 标准图标（支持双击顶栏快捷展开/收起） */}
        <div
          className="hud-hd"
          data-testid="hud-header"
          onDoubleClick={(e) => {
            if ((e.target as HTMLElement).closest("button")) return;
            void handleToggleFold();
          }}
        >
          <div className="hud-id">
            <img
              src="/app-icon.png"
              alt="FD Claude Guard"
              data-testid="hud-app-icon"
              width={16}
              height={16}
              style={{ width: 16, height: 16, borderRadius: 4, flexShrink: 0, display: "block" }}
            />
            <span className={dotClass} />
            <span>FD Guard</span>
            <span className={chipClass}>{chipText}</span>
          </div>

          <div className="hud-ctrls">
            {/* 贴边自动隐藏 */}
            <button
              type="button"
              data-testid="hud-btn-edge"
              aria-label={config.hudEdgeDocked ? "取消贴边自动隐藏" : "靠右贴边自动隐藏"}
              aria-pressed={config.hudEdgeDocked}
              title={config.hudEdgeDocked ? "已贴边自动隐藏（点击恢复固定）" : "靠右贴边自动隐藏"}
              onClick={() => void handleToggleEdgeDock()}
              className={`h-btn ${config.hudEdgeDocked ? "is-active" : ""}`}
            >
              {config.hudEdgeDocked ? (
                <ArrowLeftFromLine size={14} strokeWidth={1.85} />
              ) : (
                <ArrowRightToLine size={14} strokeWidth={1.85} />
              )}
            </button>

            {/* 图钉：纯图标变实加亮，绝无蓝底无下划线 */}
            <button
              type="button"
              data-testid="hud-btn-pin"
              aria-label={config.hudPinned ? "取消固定置顶" : "固定置顶"}
              aria-pressed={config.hudPinned}
              title={config.hudPinned ? "已固定置顶（点击取消置顶）" : "点击固定置顶"}
              onClick={() => void handleTogglePin()}
              className={`h-btn ${config.hudPinned ? "is-active" : ""}`}
            >
              <Pin
                size={14}
                strokeWidth={1.85}
                fill={config.hudPinned ? "currentColor" : "none"}
              />
            </button>

            {/* 折叠/展开：ChevronUp 180° 平滑旋转 */}
            <button
              type="button"
              data-testid="hud-btn-fold"
              aria-label={config.hudFolded ? "展开悬浮窗" : "收起悬浮窗"}
              aria-pressed={config.hudFolded}
              title={config.hudFolded ? "展开详情与实时动态" : "折叠为紧凑模式"}
              onClick={() => void handleToggleFold()}
              className={`h-btn ${config.hudFolded ? "is-folded" : ""}`}
            >
              <ChevronUp size={14} strokeWidth={1.85} />
            </button>

            <span className="hud-sep" aria-hidden="true" />

            {/* 返回控制台 */}
            <button
              type="button"
              data-testid="hud-btn-home"
              aria-label="返回控制台"
              title="返回控制台"
              onClick={() => handleNavigate("console", null, false)}
              className="h-btn"
            >
              <Home size={14} strokeWidth={1.85} />
            </button>

            {/* 隐藏到托盘（双向同步 showHud: false） */}
            <button
              type="button"
              data-testid="hud-btn-close"
              aria-label="隐藏到托盘"
              title="隐藏到托盘"
              onClick={() => {
                setConfig((c) => ({ ...c, showHud: false }));
                void ipc.toggleHudWindow(false);
              }}
              className="h-btn close"
            >
              <X size={14} strokeWidth={1.85} />
            </button>
          </div>
        </div>

        {/* 第一段：出口节点 Hero 区 */}
        <div
          className="hud-node"
          data-testid="hud-node-hero"
          title="点击前往控制台查看节点质量与容灾"
          onClick={() => handleNavigate("nodes", "quality", false)}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
            <div
              data-testid="hud-region-badge"
              className={`hud-region-badge ${isDanger ? "is-fail" : ""}`}
            >
              {regionCode}
            </div>
            <div style={{ minWidth: 0 }}>
              <div
                style={{
                  fontSize: 13,
                  fontWeight: 600,
                  color: "var(--text-1)",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {snapshot.currentNode}
              </div>
              <div
                className="tabular"
                style={{
                  fontSize: 11,
                  color: "var(--text-3)",
                  marginTop: 1,
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {nodeMetaText}
              </div>
            </div>
          </div>
          <div className="hud-lat-wrap">
            <span className={`sig-bars ${isDanger || !snapshot.clashOnline ? "is-fail" : ""}`}>
              <i />
              <i />
              <i />
            </span>
            <span className={`hud-lat-txt tabular ${isDanger ? "is-fail" : ""}`}>
              {snapshot.latencyLabel}
            </span>
          </div>
        </div>

        {/* 第二段：三维实时监测微卡片矩阵（仅两行精炼指标，无第三行副注，折叠态常驻） */}
        <div className="hud-metrics tabular" data-testid="hud-metrics">
          <div
            data-testid="hud-tile-log"
            className={`hm-tile ${logTileTone}`}
            title={
              logAnomCount > 0
                ? `点击前往日志分析（风险 ${logWarnCount} · 异常 ${logCritCount}）`
                : "点击前往日志分析"
            }
            onClick={() => handleNavigate("audit", "logs", false)}
          >
            <div className="hm-top">
              <span>日志</span>
              <span
                className={`guard-dot ${
                  logCritCount > 0 ? "danger" : logWarnCount > 0 ? "warn" : ""
                }`}
              />
            </div>
            <div className="hm-val">{logTileLabel}</div>
          </div>

          <div
            data-testid="hud-tile-flow"
            className={`hm-tile ${flowTileTone}`}
            title={
              snapshot.killSwitchActive
                ? "已触发熔断断流 · 点击查看实时流量监控"
                : liveFlowCount > 0
                ? "检测到实时异常连接拦截 · 点击前往实时流量监控"
                : snapshot.nodeDown || hasNodeDrift
                ? "当前节点存在不可用或漂移风险 · 点击前往节点质量与容灾"
                : "点击前往实时流量监控"
            }
            onClick={() => handleNavigate("nodes", flowRouteSubTab, false)}
          >
            <div className="hm-top">
              <span>流量</span>
              <span
                className={`guard-dot ${
                  snapshot.killSwitchActive || snapshot.nodeDown
                    ? "danger"
                    : liveFlowCount > 0 || hasNodeDrift
                    ? "warn"
                    : ""
                }`}
              />
            </div>
            <div className="hm-val">
              {snapshot.killSwitchActive
                ? "已断流"
                : snapshot.nodeDown
                ? "节点异常"
                : liveFlowCount > 0
                ? `${liveFlowCount} 拦截`
                : hasNodeDrift
                ? "节点漂移"
                : "纯净"}
            </div>
          </div>

          <div
            data-testid="hud-tile-proc"
            className={`hm-tile ${procTileTone}`}
            title={
              holdActive
                ? `Kill-Hold 防复活持续盯防中（已拦 ${snapshot.killHoldBlockedCount ?? 0} 次）`
                : "点击前往环境维护"
            }
            onClick={() => handleNavigate("maintain", null, false)}
          >
            <div className="hm-top">
              <span>进程</span>
              <span
                className={`guard-dot ${
                  holdActive ? "hold" : snapshot.bgClaudeProcs > 0 ? "warn" : ""
                }`}
              />
            </div>
            <div className="hm-val">
              {holdActive
                ? holdTx
                  ? "事务盯防"
                  : `盯防 ${holdSecs}s`
                : snapshot.bgClaudeProcs > 0
                ? `${snapshot.bgClaudeProcs} 存活`
                : "0 残留"}
            </div>
          </div>
        </div>

        {/* 第三段：去重动态流 + 克制高质感底部 CTA（仅展开态显示） */}
        {!config.hudFolded && (
          <div className="hud-body" data-testid="hud-body">
            <div className="hud-feed">
              {snapshot.hudEvents.slice(0, 2).map((ev, i) => (
                <div
                  key={`${ev.time}-${i}`}
                  className={`hud-ev ${ev.level === "danger" ? "danger" : ev.level === "warn" ? "warn" : ""}`}
                  onClick={() => handleNavigate(ev.targetTab ?? "console", null, ev.level !== "ok")}
                >
                  <span className="hud-ev-l">
                    <span className="hud-ev-bar" />
                    <span className="em">{ev.message}</span>
                  </span>
                  <span
                    className="tabular"
                    style={{ fontSize: 10.5, color: "var(--text-3)", flexShrink: 0 }}
                  >
                    {ev.time}
                  </span>
                </div>
              ))}
            </div>

            <button
              type="button"
              data-testid="hud-cta"
              className={ctaClass}
              onClick={() => handleNavigate(ctaTargetTab, null, mustFail > 0 || isDanger)}
            >
              {ctaText}
            </button>
          </div>
        )}
      </div>

      <style>{HUD_STYLES}</style>
    </div>
  );
}

const HUD_STYLES = `
  .hud-shell {
    width: 348px;
    z-index: 80;
    transition: opacity 0.16s cubic-bezier(0.2, 0.8, 0.2, 1);
  }
  .hud-shell.unpinned {
    opacity: 0.9;
  }
  .hud-shell.docked {
    width: 20px;
    height: 84px;
    pointer-events: none;
  }
  .hud-shell.docked.docked-open {
    width: 364px;
    height: auto;
    pointer-events: auto;
  }
  .edge-tab {
    display: none;
    position: absolute;
    right: 0;
    top: 0;
    width: 20px;
    height: 84px;
    border-radius: 10px 0 0 10px;
    background: var(--hud-bg);
    backdrop-filter: blur(20px) saturate(160%);
    border: 1px solid var(--border-strong);
    border-right: none;
    box-shadow: -4px 6px 20px rgba(0, 0, 0, 0.32);
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 8px;
    cursor: pointer;
    pointer-events: auto;
    transition: opacity 0.15s cubic-bezier(0.2, 0.8, 0.2, 1), border-color 0.16s;
  }
  .edge-tab:hover {
    border-color: var(--text-3);
  }
  .edge-tab.danger {
    border-color: rgba(239, 68, 68, 0.65);
    box-shadow: -4px 0 18px rgba(239, 68, 68, 0.28);
  }
  .edge-grip {
    width: 2px;
    height: 22px;
    border-radius: 99px;
    background: var(--text-3);
    opacity: 0.45;
  }
  .edge-chev {
    color: var(--text-3);
    opacity: 0.65;
  }
  .hud-shell.docked .edge-tab {
    display: flex;
  }
  .hud-shell.docked .hud-v2 {
    position: absolute;
    right: 16px;
    top: 0;
    opacity: 0;
    pointer-events: none;
    transform: translateX(6px);
  }
  .hud-shell.docked.docked-open .edge-tab {
    opacity: 0;
    pointer-events: none;
  }
  .hud-shell.docked.docked-open .hud-v2 {
    opacity: 1;
    pointer-events: auto;
    transform: translateX(0);
  }

  .hud-v2 {
    width: 348px;
    background: var(--hud-bg);
    backdrop-filter: blur(22px) saturate(160%);
    border-radius: 14px;
    border: 1px solid var(--border-strong);
    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.42), 0 0 0 1px rgba(255, 255, 255, 0.03) inset;
    overflow: hidden;
    cursor: grab;
    transition: transform 0.18s cubic-bezier(0.2, 0.8, 0.2, 1), opacity 0.16s, border-color 0.2s;
  }
  [data-theme="light"] .hud-v2 {
    box-shadow: 0 16px 40px rgba(9, 9, 11, 0.12), 0 1px 3px rgba(9, 9, 11, 0.06);
  }
  .hud-v2.danger {
    border-color: rgba(239, 68, 68, 0.65);
    box-shadow: 0 18px 46px rgba(239, 68, 68, 0.22);
  }
  .hud-v2.is-dragging {
    cursor: grabbing !important;
    transition: none !important;
  }
  .hud-v2.is-dragging * {
    cursor: grabbing !important;
  }

  .hud-hd {
    height: 42px;
    padding: 0 10px 0 14px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    cursor: grab;
  }
  .hud-id {
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 12.5px;
    font-weight: 600;
    letter-spacing: -0.01em;
    white-space: nowrap;
    color: var(--text-1);
  }
  .hud-ctrls {
    display: flex;
    align-items: center;
    gap: 2px;
    flex-shrink: 0;
  }
  .hud-sep {
    width: 1px;
    height: 12px;
    background: var(--border-strong);
    margin: 0 3px;
    opacity: 0.7;
  }
  .h-btn {
    width: 26px;
    height: 26px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--text-2);
    opacity: 0.72;
    cursor: pointer;
    display: grid;
    place-items: center;
    transition: color 0.14s, opacity 0.14s, background-color 0.14s;
  }
  .h-btn svg {
    transition: transform 0.18s cubic-bezier(0.2, 0.8, 0.2, 1);
  }
  .h-btn:hover {
    background: var(--bg-subtle);
    color: var(--text-1);
    opacity: 1;
  }
  .h-btn.is-active {
    color: var(--text-1);
    opacity: 1;
    background: transparent;
  }
  .h-btn.is-folded svg {
    transform: rotate(180deg);
  }
  .h-btn.close:hover {
    background: rgba(239, 68, 68, 0.16);
    color: var(--danger-bright);
    opacity: 1;
  }

  .hud-node {
    padding: 12px 14px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    cursor: pointer;
    transition: background-color 0.14s;
  }
  .hud-node:hover {
    background: rgba(128, 128, 140, 0.04);
  }
  .hud-region-badge {
    width: 34px;
    height: 34px;
    border-radius: 9px;
    flex-shrink: 0;
    position: relative;
    background: var(--bg-subtle);
    border: 1px solid var(--border);
    display: grid;
    place-items: center;
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 700;
    color: var(--text-1);
    letter-spacing: 0.02em;
  }
  .hud-region-badge.is-fail {
    background: var(--danger-soft);
    border-color: rgba(239, 68, 68, 0.35);
    color: var(--danger-bright);
  }
  .hud-region-badge::after {
    content: "";
    position: absolute;
    right: -2px;
    bottom: -2px;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--success);
    border: 2px solid var(--bg-card);
  }
  .hud-region-badge.is-fail::after {
    background: var(--danger);
  }
  .hud-lat-wrap {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }
  .sig-bars {
    display: inline-flex;
    align-items: flex-end;
    gap: 2px;
    height: 11px;
  }
  .sig-bars i {
    width: 2.5px;
    border-radius: 1px;
    background: var(--success);
    display: block;
  }
  .sig-bars i:nth-child(1) { height: 4px; }
  .sig-bars i:nth-child(2) { height: 7px; }
  .sig-bars i:nth-child(3) { height: 11px; }
  .sig-bars.is-fail i {
    background: var(--danger);
    opacity: 0.35;
  }
  .sig-bars.is-fail i:nth-child(1) {
    opacity: 1;
  }
  .hud-lat-txt {
    font-size: 12px;
    font-weight: 600;
    color: var(--success);
  }
  .hud-lat-txt.is-fail {
    color: var(--danger-bright);
  }

  .hud-metrics {
    padding: 0 12px 12px;
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 7px;
  }
  .hm-tile {
    background: rgba(128, 128, 140, 0.055);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 8px 9px;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 3px;
    transition: border-color 0.14s, background-color 0.14s;
  }
  .hm-tile:hover {
    border-color: var(--border-strong);
    background: rgba(128, 128, 140, 0.095);
  }
  .hm-tile.is-fail {
    border-color: rgba(239, 68, 68, 0.32);
    background: rgba(239, 68, 68, 0.065);
  }
  .hm-tile.is-warn {
    border-color: rgba(245, 165, 36, 0.3);
    background: rgba(245, 165, 36, 0.06);
  }
  .hm-tile.is-hold {
    border-color: rgba(0, 111, 238, 0.36);
    background: rgba(0, 111, 238, 0.08);
  }
  .hm-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 10.5px;
    color: var(--text-3);
  }
  .hm-val {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-1);
    line-height: 1.25;
    white-space: nowrap;
  }
  .hm-tile.is-fail .hm-val { color: var(--danger-bright); }
  .hm-tile.is-warn .hm-val { color: var(--warning); }
  .hm-tile.is-hold .hm-val { color: var(--primary); }
  .hm-tile.is-ok .hm-val { color: var(--success); }

  .hud-v2.is-folded .hud-node { padding: 10px 14px 9px; }
  .hud-v2.is-folded .hud-metrics { padding: 0 12px 11px; gap: 6px; }
  .hud-v2.is-folded .hm-tile { padding: 6px 8px; gap: 2px; }

  .hud-body {
    padding: 10px 12px 12px;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 10px;
    background: rgba(128, 128, 140, 0.02);
  }
  .hud-feed {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }
  .hud-ev {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    font-size: 11.5px;
    color: var(--text-2);
    padding: 4px 6px;
    border-radius: 6px;
    cursor: pointer;
    transition: background-color 0.12s;
  }
  .hud-ev:hover {
    background: var(--bg-subtle);
  }
  .hud-ev-l {
    display: flex;
    align-items: center;
    gap: 7px;
    min-width: 0;
  }
  .hud-ev-bar {
    width: 2.5px;
    height: 12px;
    border-radius: 99px;
    background: var(--success);
    flex-shrink: 0;
  }
  .hud-ev.danger .hud-ev-bar { background: var(--danger); }
  .hud-ev.warn .hud-ev-bar { background: var(--warning); }
  .hud-ev .em {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: var(--text-2);
  }
  .hud-ev.danger .em { color: var(--text-1); font-weight: 500; }
  .hud-ev.warn .em { color: var(--text-1); }

  .hud-cta {
    width: 100%;
    height: 34px;
    border-radius: 9px;
    border: 1px solid transparent;
    background: var(--primary);
    color: #ffffff;
    font-family: var(--font-sans);
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    transition: background-color 0.15s, border-color 0.15s;
  }
  .hud-cta:hover {
    background: var(--primary-hover);
  }
  .hud-cta.is-danger {
    background: var(--danger-soft);
    border-color: rgba(239, 68, 68, 0.45);
    color: var(--danger-bright);
  }
  .hud-cta.is-danger:hover {
    background: rgba(239, 68, 68, 0.22);
  }
`;
