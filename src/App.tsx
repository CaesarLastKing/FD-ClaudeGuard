import { useEffect } from "react";
import { CleanConfirmModal } from "@/components/CleanConfirmModal";
import { PlaybookDrawer } from "@/components/PlaybookDrawer";
import { RiskModal } from "@/components/RiskModal";
import { SettingsModal } from "@/components/SettingsModal";
import { Sidebar } from "@/components/Sidebar";
import { SupportModal } from "@/components/SupportModal";
import { ToastStack } from "@/components/ToastStack";
import { WindowChrome } from "@/components/WindowChrome";
import { ipc, isTauriRuntime } from "@/lib/ipc";
import { AccountAuditPage } from "@/pages/AccountAuditPage";
import { AiToolsPage } from "@/pages/AiToolsPage";
import { ConsolePage } from "@/pages/ConsolePage";
import { NodesTrafficPage } from "@/pages/NodesTrafficPage";
import { useGuardStore } from "@/stores/guardStore";

export function App() {
  const activeTab = useGuardStore((s) => s.activeTab);
  const bootstrap = useGuardStore((s) => s.bootstrap);
  const setSnapshot = useGuardStore((s) => s.setSnapshot);
  const setPreflightFromEvent = useGuardStore((s) => s.setPreflightFromEvent);
  const setConfigFromEvent = useGuardStore((s) => s.setConfigFromEvent);
  const setStartupAudit = useGuardStore((s) => s.setStartupAudit);
  const setDeepAuditFromEvent = useGuardStore((s) => s.setDeepAuditFromEvent);
  const setActiveTab = useGuardStore((s) => s.setActiveTab);
  const setAuditSubTab = useGuardStore((s) => s.setAuditSubTab);
  const setNodesSubTab = useGuardStore((s) => s.setNodesSubTab);
  const setSelectedCheckId = useGuardStore((s) => s.setSelectedCheckId);
  const focusFirstUnhealthyCheck = useGuardStore((s) => s.focusFirstUnhealthyCheck);
  const setPlaybookOpen = useGuardStore((s) => s.setPlaybookOpen);
  const openRiskModal = useGuardStore((s) => s.openRiskModal);
  const pushToast = useGuardStore((s) => s.pushToast);
  const hydrateCachedUpdateInfo = useGuardStore((s) => s.hydrateCachedUpdateInfo);
  const setUpdateInfo = useGuardStore((s) => s.setUpdateInfo);
  const setUpdateProgress = useGuardStore((s) => s.setUpdateProgress);
  const toggleSettingsModal = useGuardStore((s) => s.toggleSettingsModal);
  const openSettingsModal = useGuardStore((s) => s.openSettingsModal);

  useEffect(() => {
    const onGlobalKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === ",") {
        e.preventDefault();
        toggleSettingsModal();
      }
    };
    window.addEventListener("keydown", onGlobalKeyDown);
    return () => window.removeEventListener("keydown", onGlobalKeyDown);
  }, [toggleSettingsModal]);

  useEffect(() => {
    void bootstrap();

    // 启动 0s 零网络秒读本地持久化 update-state.json 恢复顶栏微标；并检测升级后首次启动弹轻确认提示（E-04）
    if (isTauriRuntime()) {
      void hydrateCachedUpdateInfo();
      void ipc
        .getCachedAppUpdate()
        .then((info) => {
          const clean = (info?.currentVersion || "").replace(/^v/i, "").trim();
          if (!clean) return;
          try {
            const prev = window.localStorage.getItem("fd_last_launched_version");
            if (prev && prev !== clean) {
              const parse = (s: string) => s.split(".").map((n) => parseInt(n, 10) || 0);
              const a = parse(prev);
              const b = parse(clean);
              const upgraded =
                (b[0] ?? 0) > (a[0] ?? 0) ||
                ((b[0] ?? 0) === (a[0] ?? 0) && (b[1] ?? 0) > (a[1] ?? 0)) ||
                ((b[0] ?? 0) === (a[0] ?? 0) &&
                  (b[1] ?? 0) === (a[1] ?? 0) &&
                  (b[2] ?? 0) > (a[2] ?? 0));
              if (upgraded) {
                pushToast(
                  `已成功升级至 v${clean}`,
                  `已从 v${prev} 平滑更新，原有安全策略与账号归档均已保留。`,
                  "ok",
                  { durationMs: 5000 }
                );
              }
            }
            window.localStorage.setItem("fd_last_launched_version", clean);
          } catch {
            // 忽略受限环境 localStorage 异常
          }
        })
        .catch(() => {});
    }

    const onWindowError = (e: ErrorEvent) => {
      void ipc.logFrontendEvent("ERROR", "window.onerror", `${e.message} (${e.filename}:${e.lineno})`);
    };
    const onUnhandledRejection = (e: PromiseRejectionEvent) => {
      void ipc.logFrontendEvent("ERROR", "unhandledrejection", String(e.reason));
    };
    window.addEventListener("error", onWindowError);
    window.addEventListener("unhandledrejection", onUnhandledRejection);

    let disposed = false;
    const unsubs: Array<() => void> = [];
    const register = (p: Promise<() => void>) => {
      void p.then((fn) => {
        if (disposed) {
          fn();
        } else {
          unsubs.push(fn);
        }
      });
    };

    register(ipc.listenSnapshot((snap) => setSnapshot(snap)));
    register(ipc.listenPreflightUpdated((rep) => setPreflightFromEvent(rep)));
    register(ipc.listenConfigChanged((cfg) => setConfigFromEvent(cfg)));
    register(ipc.listenStartupAuditUpdated((rep) => setStartupAudit(rep)));
    register(
      ipc.listenKillswitch((ks) => {
        if (ks.active) {
          pushToast(
            "已触发 4 层紧急热熔断",
            ks.reason || `已强制掐断 ${ks.claudeConnectionsClosed} 条连接并封死出站防回传`,
            "danger",
            { durationMs: 8000 }
          );
        }
      })
    );
    register(ipc.listenNodeAuditProgress((prog) => setDeepAuditFromEvent(prog)));
    register(
      ipc.listenNavigate((nav) => {
        if (nav.tab === "config") {
          openSettingsModal("general");
          return;
        }
        if (nav.tab === "maintain") {
          openSettingsModal("recovery");
          return;
        }
        setActiveTab(nav.tab);
        if (nav.tab === "audit" && (nav.subTab === "audit" || nav.subTab === "logs")) {
          setAuditSubTab(nav.subTab);
        }
        if (nav.tab === "nodes" && (nav.subTab === "quality" || nav.subTab === "traffic")) {
          setNodesSubTab(nav.subTab);
        }
        if (nav.focusItemId === "__first_fail__" && nav.tab === "console") {
          focusFirstUnhealthyCheck();
        } else if (nav.focusItemId && nav.focusItemId !== "__first_fail__") {
          setSelectedCheckId(nav.focusItemId);
        }
        if (nav.openPlaybook) {
          setPlaybookOpen(true);
        }
      })
    );
    register(
      ipc.listenConfirmExit((bgProcs) => {
        const hasProcs = bgProcs > 0;
        openRiskModal({
          tone: "danger",
          badge: "安全退出防呆",
          title: hasProcs ? "检测到 Claude 仍在后台运行" : "检测到防火墙熔断规则仍在生效",
          subtitle: hasProcs
            ? "直接退出安全启动器将失去实时断流与防裸奔保护"
            : "确认退出将自动清空本工具写入的 Defender 出站阻断规则以恢复网络",
          rows: [
            {
              label: "当前状态",
              value: hasProcs
                ? `检测到 ${bgProcs} 个 Claude 后台进程存活`
                : "Claude 进程为 0，但出站熔断防火墙规则处于激活态",
              tone: "danger",
            },
            {
              label: "安全建议",
              value: hasProcs
                ? "建议先强杀 Claude 进程丢弃内存遥测队列，再安全退出本工具。"
                : "点击「清理规则并安全退出」会自动清除防火墙规则并恢复网络。",
            },
          ],
          primaryLabel: hasProcs ? "先强杀 Claude 并退出" : "清理规则并安全退出",
          onPrimary: () => void ipc.quitApp(hasProcs),
          dangerLabel: hasProcs ? "忽略风险，直接退出" : undefined,
          onDanger: hasProcs ? () => void ipc.quitApp(false) : undefined,
        });
      })
    );
    register(ipc.listenUpdateProgress((prog) => setUpdateProgress(prog)));
    register(ipc.listenUpdateAvailable((info) => setUpdateInfo(info)));
    register(
      ipc.listenNakedLaunchIntercepted((count) => {
        pushToast(
          "已拦截非安全直接启动 Claude",
          `检测到未全绿状态下直接启动 Claude（${count} 个进程），已自动阻断出站并切回控制台，请先修复必须项后再点「安全启动 Claude」。`,
          "danger",
          { durationMs: 7000 }
        );
      })
    );

    return () => {
      disposed = true;
      window.removeEventListener("error", onWindowError);
      window.removeEventListener("unhandledrejection", onUnhandledRejection);
      unsubs.forEach((fn) => fn());
    };
  }, [
    bootstrap,
    hydrateCachedUpdateInfo,
    setUpdateInfo,
    focusFirstUnhealthyCheck,
    openRiskModal,
    openSettingsModal,
    pushToast,
    setActiveTab,
    setAuditSubTab,
    setConfigFromEvent,
    setNodesSubTab,
    setPlaybookOpen,
    setSelectedCheckId,
    setPreflightFromEvent,
    setSnapshot,
    setDeepAuditFromEvent,
    setUpdateProgress,
  ]);

  return (
    <div
      style={{
        width: "100vw",
        height: "100vh",
        background: "var(--bg-canvas)",
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        border: "1px solid var(--divider)",
      }}
    >
      <WindowChrome />
      <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
        <Sidebar />
        <main style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
          {activeTab === "console" && <ConsolePage />}
          {(activeTab === "audit" || activeTab === "logs") && <AccountAuditPage />}
          {activeTab === "nodes" && <NodesTrafficPage />}
          {activeTab === "aitools" && <AiToolsPage />}
        </main>
      </div>
      <SettingsModal />
      <PlaybookDrawer />
      <RiskModal />
      <CleanConfirmModal />
      <SupportModal />
      <ToastStack />
    </div>
  );
}

export default App;
