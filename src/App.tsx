import { useEffect } from "react";
import { HeroUIProvider } from "@heroui/react";
import { CleanConfirmModal } from "@/components/CleanConfirmModal";
import { LicenseModal } from "@/components/LicenseModal";
import { PlaybookDrawer } from "@/components/PlaybookDrawer";
import { RiskModal } from "@/components/RiskModal";
import { Sidebar } from "@/components/Sidebar";
import { SupportModal } from "@/components/SupportModal";
import { ToastStack } from "@/components/ToastStack";
import { WindowChrome } from "@/components/WindowChrome";
import { ipc } from "@/lib/ipc";
import { ConsolePage } from "@/pages/ConsolePage";
import { LogAnalysisPage } from "@/pages/LogAnalysisPage";
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
  const setLicenseStatus = useGuardStore((s) => s.setLicenseStatus);
  const setDeepAuditFromEvent = useGuardStore((s) => s.setDeepAuditFromEvent);
  const setActiveTab = useGuardStore((s) => s.setActiveTab);
  const setNodesSubTab = useGuardStore((s) => s.setNodesSubTab);
  const setSelectedCheckId = useGuardStore((s) => s.setSelectedCheckId);
  const focusFirstUnhealthyCheck = useGuardStore((s) => s.focusFirstUnhealthyCheck);
  const setPlaybookOpen = useGuardStore((s) => s.setPlaybookOpen);
  const openRiskModal = useGuardStore((s) => s.openRiskModal);

  useEffect(() => {
    void bootstrap();

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
    register(ipc.listenLicenseChanged((st) => setLicenseStatus(st)));
    register(ipc.listenNodeAuditProgress((prog) => setDeepAuditFromEvent(prog)));
    register(
      ipc.listenNavigate((nav) => {
        setActiveTab(nav.tab);
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
      window.removeEventListener("error", onWindowError);
      window.removeEventListener("unhandledrejection", onUnhandledRejection);
      unsubs.forEach((fn) => fn());
    };
  }, [
    bootstrap,
    focusFirstUnhealthyCheck,
    openRiskModal,
    setActiveTab,
    setConfigFromEvent,
    setNodesSubTab,
    setPlaybookOpen,
    setSelectedCheckId,
    setPreflightFromEvent,
    setSnapshot,
    setLicenseStatus,
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
            {activeTab === "nodes" && <NodesTrafficPage />}
            {activeTab === "logs" && <LogAnalysisPage />}
            {activeTab === "maintain" && <MaintenancePage />}
            {activeTab === "config" && <SettingsPage />}
          </main>
        </div>
        <PlaybookDrawer />
        <RiskModal />
        <CleanConfirmModal />
        <LicenseModal />
        <SupportModal />
        <ToastStack />
      </div>
    </HeroUIProvider>
  );
}

export default App;
