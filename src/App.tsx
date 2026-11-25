import { useEffect } from "react";
import { HeroUIProvider } from "@heroui/react";
import { CleanConfirmModal } from "@/components/CleanConfirmModal";
import { PlaybookDrawer } from "@/components/PlaybookDrawer";
import { RiskModal } from "@/components/RiskModal";
import { Sidebar } from "@/components/Sidebar";
import { SupportModal } from "@/components/SupportModal";
import { ToastStack } from "@/components/ToastStack";
import { WindowChrome } from "@/components/WindowChrome";
import { ipc, isTauriRuntime } from "@/lib/ipc";
import { AccountAuditPage } from "@/pages/AccountAuditPage";
import { ConsolePage } from "@/pages/ConsolePage";
import { MaintenancePage } from "@/pages/MaintenancePage";
import { NodesTrafficPage } from "@/pages/NodesTrafficPage";
import { SettingsPage } from "@/pages/SettingsPage";
import { useGuardStore } from "@/stores/guardStore";

export function App() {
  const activeTab = useGuardStore((s) => s.activeTab);
  const bootstrap = useGuardStore((s) => s.bootstrap);
  const setSnapshot = useGuardStore((s) => s.setSnapshot);
  const setPreflightFromEvent = useGuardStore((s) => s.setPreflightFromEvent);
  const setConfigFromEvent = useGuardStore((s) => s.setConfigFromEvent);
  const setDeepAuditFromEvent = useGuardStore((s) => s.setDeepAuditFromEvent);
  const setActiveTab = useGuardStore((s) => s.setActiveTab);
  const setAuditSubTab = useGuardStore((s) => s.setAuditSubTab);
  const setNodesSubTab = useGuardStore((s) => s.setNodesSubTab);
  const setSelectedCheckId = useGuardStore((s) => s.setSelectedCheckId);
  const focusFirstUnhealthyCheck = useGuardStore((s) => s.focusFirstUnhealthyCheck);
  const setPlaybookOpen = useGuardStore((s) => s.setPlaybookOpen);
  const openRiskModal = useGuardStore((s) => s.openRiskModal);
  const pushToast = useGuardStore((s) => s.pushToast);

  useEffect(() => {
    void bootstrap();

    // T-059：仅真实桌面端在启动 3.5s 后静默检查一次更新，发现新版本时温和提示（绝不弹窗打扰或强制重启）
    let updateTimer: number | null = null;
    if (isTauriRuntime()) {
      updateTimer = window.setTimeout(() => {
        void ipc
          .checkAppUpdate()
          .then((info) => {
            if (info.available && info.latestVersion) {
              pushToast(
                `发现新版本 v${info.latestVersion}`,
                "已通过 GitHub Releases 官方更新通道检测到新版本，可前往「守卫配置」一键验签升级。",
                "info",
                {
                  durationMs: 7000,
                  action: {
                    label: "前往更新",
                    onClick: () => setActiveTab("config"),
                  },
                }
              );
            }
          })
          .catch(() => {
            // 静默忽略离线或超时错误
          });
      }, 3500);
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
    register(ipc.listenNodeAuditProgress((prog) => setDeepAuditFromEvent(prog)));
    register(
      ipc.listenNavigate((nav) => {
        setActiveTab(nav.tab);
        if (nav.tab === "audit" && (nav.subTab === "audit" || nav.subTab === "logs")) {
          setAuditSubTab(nav.subTab);
        }
        if (nav.tab === "nodes" && (nav.subTab === "quality" || nav.subTab === "traffic")) {
          setNodesSubTab(nav.subTab);
        }
        if (nav.focusItemId === "__first_fail__") {
          focusFirstUnhealthyCheck();
        } else if (nav.focusItemId) {
          setSelectedCheckId(nav.focusItemId);
        }
        if (nav.openPlaybook) {
          setPlaybookOpen(true);
        }
      })
    );
    register(
      ipc.listenConfirmExit((bgProcs) => {
        openRiskModal({
          tone: "danger",
          badge: "安全退出防呆",
          title: "检测到 Claude 仍在后台运行",
          subtitle: "直接退出安全启动器将失去实时断流与防裸奔保护",
          rows: [
            {
              label: "当前状态",
              value: `检测到 ${bgProcs} 个 Claude 后台进程存活`,
              tone: "danger",
            },
            {
              label: "安全建议",
              value: "建议先强杀 Claude 进程丢弃内存遥测队列，再安全退出本工具。",
            },
          ],
          primaryLabel: "先强杀 Claude 并退出",
          onPrimary: () => void ipc.quitApp(true),
          dangerLabel: "忽略风险，直接退出",
          onDanger: () => void ipc.quitApp(false),
        });
      })
    );

    return () => {
      disposed = true;
      if (updateTimer !== null) {
        window.clearTimeout(updateTimer);
      }
      window.removeEventListener("error", onWindowError);
      window.removeEventListener("unhandledrejection", onUnhandledRejection);
      unsubs.forEach((fn) => fn());
    };
  }, [
    bootstrap,
    focusFirstUnhealthyCheck,
    openRiskModal,
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
  ]);

  return (
    <HeroUIProvider>
      <div
        style={{
          width: "100vw",
          height: "100vh",
          background: "var(--bg-canvas)",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
          border: "1px solid var(--border-strong)",
        }}
      >
        <WindowChrome />
        <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
          <Sidebar />
          <main style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
            {activeTab === "console" && <ConsolePage />}
            {(activeTab === "audit" || activeTab === "logs") && <AccountAuditPage />}
            {activeTab === "nodes" && <NodesTrafficPage />}
            {activeTab === "maintain" && <MaintenancePage />}
            {activeTab === "config" && <SettingsPage />}
          </main>
        </div>
        <PlaybookDrawer />
        <RiskModal />
        <CleanConfirmModal />
        <SupportModal />
        <ToastStack />
      </div>
    </HeroUIProvider>
  );
}

export default App;
