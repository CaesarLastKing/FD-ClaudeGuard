import { useEffect, useState } from "react";
import { Activity, Loader2, ShieldOff, Trash2, X } from "lucide-react";
import { NetworkRescueRollbackPanel } from "@/components/NetworkRescueRollbackPanel";
import { ipc } from "@/lib/ipc";
import { useGuardStore } from "@/stores/guardStore";
import type { BackupInfo, ClaudeDataRootsSummary, FeedbackReportResult } from "@/types/guard";

export function MaintenancePage() {
  const [backups, setBackups] = useState<BackupInfo[]>([]);
  const [rootsSummary, setRootsSummary] = useState<ClaudeDataRootsSummary>({
    classicDetected: true,
    msixPackages: [],
    telemetryExists: true,
  });
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [reportSubmitting, setReportSubmitting] = useState(false);
  const [reportResult, setReportResult] = useState<FeedbackReportResult | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const snapshot = useGuardStore((s) => s.snapshot);
  const openRiskModal = useGuardStore((s) => s.openRiskModal);
  const openCleanModal = useGuardStore((s) => s.openCleanModal);
  const pushToast = useGuardStore((s) => s.pushToast);
  const refreshPreflight = useGuardStore((s) => s.refreshPreflight);

  const busy = busyAction !== null;

  const loadBackups = async () => {
    const list = await ipc.listBackups();
    setBackups(list);
  };

  useEffect(() => {
    let cancelled = false;
    void ipc
      .listBackups()
      .then((list) => {
        if (!cancelled) setBackups(list);
      })
      .catch(() => {});
    void ipc
      .inspectClaudeDataRoots()
      .then((res) => {
        if (!cancelled) setRootsSummary(res);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!reportModalOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !reportSubmitting) {
        setReportModalOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [reportModalOpen, reportSubmitting]);

  const handleKillAndClean = async () => {
    setBusyAction("kill");
    try {
      const rep = await ipc.killClaudeProcesses(true);
      pushToast("已完成应急清理", rep.message, "ok");
      void refreshPreflight(true);
    } catch (err) {
      pushToast("强制退出失败", String(err), "danger");
    } finally {
      setBusyAction(null);
    }
  };

  const handleBackupAndClean = () => {
    openCleanModal({
      sourceLabel: "来自环境维护",
      onCompleted: async () => {
        await loadBackups();
      },
    });
  };

  const handleManualBackup = async () => {
    setBusyAction("manual_backup");
    try {
      const info = await ipc.createManualBackup();
      await loadBackups();
      pushToast("已创建手动快照", `已保存 ${info.fileName}（${info.sizeLabel}）。`, "ok");
    } catch (err) {
      pushToast("创建快照失败", String(err), "danger");
    } finally {
      setBusyAction(null);
    }
  };

  const handleRestore = async (fileName: string) => {
    setBusyAction(`restore:${fileName}`);
    try {
      const msg = await ipc.restoreBackup(fileName);
      await loadBackups();
      pushToast("原子快照还原完成", msg, "ok");
      void refreshPreflight(true);
    } catch (err) {
      pushToast("还原快照失败", String(err), "danger");
    } finally {
      setBusyAction(null);
    }
  };

  const handleDeleteOne = async (fileName: string) => {
    setBusyAction(`delete:${fileName}`);
    try {
      const msg = await ipc.deleteBackup(fileName);
      await loadBackups();
      pushToast("已删除备份快照", msg, "ok");
    } catch (err) {
      pushToast("删除备份失败", String(err), "danger");
    } finally {
      setBusyAction(null);
    }
  };

  const handleClearAllBackups = () => {
    openRiskModal({
      tone: "danger",
      badge: "不可逆清理",
      title: "清空全部历史备份快照",
      subtitle: `将永久删除 ~/FDtools-Backups/ 下的全部 ${backups.length} 份 ZIP 快照`,
      rows: [
        { label: "将删除数量", value: `${backups.length} 份历史 ZIP 快照`, tone: "danger" },
        { label: "安全说明", value: "仅删除本地备份归档，不会影响你当前的 Claude 登录态与项目代码。" },
      ],
      primaryLabel: "取消，保留备份",
      onPrimary: () => {},
      dangerLabel: "确认清空全部备份",
      onDanger: async () => {
        setBusyAction("clear_all");
        try {
          const cnt = await ipc.clearAllBackups();
          await loadBackups();
          pushToast("已清空全部历史备份", `共删除 ${cnt} 份备份快照。`, "ok");
        } catch (err) {
          pushToast("清空备份失败", String(err), "danger");
        } finally {
          setBusyAction(null);
        }
      },
    });
  };

  const handleCleanupAllFirewall = async () => {
    setBusyAction("fw_rescue");
    try {
      const msg = await ipc.cleanupAllGuardFirewallRules();
      pushToast("防自锁救援完成", msg, "ok");
      void refreshPreflight(true);
    } catch (err) {
      pushToast("清理防火墙规则失败", String(err), "danger");
    } finally {
      setBusyAction(null);
    }
  };

  const handleExportDiag = async () => {
    setBusyAction("export_diag");
    try {
      const res = await ipc.exportAiDiagnosticBundle();
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(res.promptMarkdown).catch(() => {});
      }
      pushToast(
        "已导出脱敏诊断包并复制 AI 排障提示词",
        `保存路径：${res.zipPath}（含最近 7 天脱敏 guard-runtime-*.jsonl 与 ai-review-prompt.md 复盘模板）`,
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
      setBusyAction(null);
    }
  };

  const handleToggleKillswitch = async () => {
    if (snapshot.killSwitchActive) {
      openRiskModal({
        tone: "danger",
        badge: "高危操作",
        title: "强制解除防火墙熔断",
        subtitle: "仅在确认当前网络已安全或暂不使用 Claude 时临时解除",
        rows: [
          {
            label: "当前状态",
            value: `熔断生效中 · 后台 Claude 进程 ${snapshot.bgClaudeProcs} 个`,
            tone: "danger",
          },
          {
            label: "安全建议",
            value: "建议先切回安全节点并完成启动前体检复测，系统将自动恢复放行。",
          },
        ],
        primaryLabel: "暂不解除，保持保护",
        onPrimary: () => {},
        dangerLabel: "忽略风险，强制解除",
        onDanger: async () => {
          const ks = await ipc.forceReleaseKillswitch(true);
          pushToast("已解除防火墙熔断", ks.reason, "info");
          void refreshPreflight(true);
        },
      });
    } else {
      setBusyAction("killswitch");
      try {
        const ks = await ipc.triggerKillswitch("用户在环境维护页手动触发 4 层紧急防回传");
        pushToast(
          "已激活 4 层紧急防回传熔断",
          `已掐断 ${ks.claudeConnectionsClosed} 条连接、强杀 ${ks.killedProcesses} 个进程并清扫 ${ks.telemetryClearedBytes} B 遥测缓存。`,
          "danger"
        );
      } finally {
        setBusyAction(null);
      }
    }
  };

  const kindLabel = (k: string) => {
    if (k === "pre-restore") return "还原前安全点";
    if (k === "clean") return "清理前备份";
    if (k === "manual") return "手动快照";
    return "历史快照";
  };

  return (
    <section style={{ display: "flex", flex: 1, minHeight: 0, flexDirection: "column" }}>
      <div
        style={{
          padding: "16px 22px 14px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 14,
          flexShrink: 0,
        }}
      >
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 600, letterSpacing: "-0.02em", margin: 0 }}>
            环境维护
          </h1>
          <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4 }}>
            进程强杀清队列 · 原子快照还原 · 防自锁救援 · 结构化 JSONL 运行日志与 AI 复盘诊断包
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            type="button"
            className="guard-btn guard-btn-flat guard-btn-sm"
            onClick={async () => {
              try {
                const dir = await ipc.openGuardLogsDir();
                pushToast("已打开结构化运行日志目录", dir, "ok");
              } catch (err) {
                pushToast("打开日志目录失败", String(err), "danger");
              }
            }}
          >
            打开运行日志目录
          </button>
          <button
            type="button"
            disabled={busy}
            className="guard-btn guard-btn-flat guard-btn-sm"
            onClick={() => void handleExportDiag()}
          >
            {busyAction === "export_diag" && <Loader2 size={13} className="guard-spin" />}
            <span>{busyAction === "export_diag" ? "导出中..." : "导出脱敏 AI 诊断包"}</span>
          </button>
          <button
            type="button"
            data-testid="btn-anonymous-report"
            disabled={busy}
            className="guard-btn guard-btn-flat guard-btn-sm"
            onClick={() => {
              setReportResult(null);
              setReportError(null);
              setReportModalOpen(true);
            }}
          >
            <span>一键匿名上报排障</span>
          </button>
        </div>
      </div>

      {/* 关键修复（问题 1）：flex: 1 + minHeight: 0 配合子卡 flexShrink: 0，备份再多也流畅滚动绝不挤压变形 */}
      <div
        style={{
          flex: 1,
          minHeight: 0,
          padding: "16px 22px",
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          gap: 14,
        }}
      >
        <div style={{ flexShrink: 0 }}>
          <NetworkRescueRollbackPanel />
        </div>
        <div className="guard-card" style={actionCardStyle}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, display: "flex", alignItems: "center", gap: 8 }}>
              <span>强制退出 Claude 并清理待上传遥测缓存</span>
              <span className="guard-chip guard-chip-warn">仅应急使用</span>
            </div>
            <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4, lineHeight: 1.55 }}>
              平时无需手动点击（触发熔断时自动执行）。仅在代理突然断网或节点漂移等紧急时刻，强制终止进程丢弃内存中待发遥测并清空{" "}
              <code className="font-mono-code">~/.claude/telemetry/</code>。
              <br />
              <span style={{ color: "var(--text-3)" }}>
                风险提示：会中断正在生成中的当前对话，不影响你的项目代码与云端历史记录。
              </span>
            </div>
          </div>
          <button
            type="button"
            disabled={busy}
            className="guard-btn guard-btn-flat guard-btn-sm"
            style={{ flexShrink: 0 }}
            onClick={() => void handleKillAndClean()}
          >
            {busyAction === "kill" && <Loader2 size={13} className="guard-spin" />}
            <span>{busyAction === "kill" ? "清理中..." : "应急清理缓存"}</span>
          </button>
        </div>

        <div className="guard-card" style={actionCardStyle}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, display: "flex", alignItems: "center", gap: 8 }}>
              <span>4 层紧急防回传熔断控制（Clash 掐流 + 防火墙封锁）</span>
              <span className="guard-chip guard-chip-neutral">自动守护 · 支持手动触发</span>
            </div>
            <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4, lineHeight: 1.6 }}>
              <div>
                <strong style={{ color: "var(--text-1)", fontWeight: 500 }}>自动触发场景</strong>
                （已在「守卫配置」默认开启）：① 必须项未全绿时直接启动 Claude（防裸奔拦截）；② Claude 运行中代理突然断开 / 关 TUN / 切直连 / 脱组 / 切禁区时 2 秒自动热熔断（先封出站再强杀，跳过退出清理防带 Cookie 403）；③ 系统休眠唤醒最长 15 秒校验预阻断安全窗（校验 Clash + TUN + 非直连）。
              </div>
              <div style={{ color: "var(--text-3)", marginTop: 2 }}>
                触发后将毫秒级掐断所有 Claude 连接、写入 Defender 规则{" "}
                <code className="font-mono-code">FDClaudeGuard_KillSwitch_*</code>{" "}
                并开启防复活持续盯防锁。平时无需手动点击，仅作紧急手动断网兜底。
              </div>
            </div>
          </div>
          <button
            type="button"
            disabled={busy}
            className={`guard-btn ${
              snapshot.killSwitchActive ? "guard-btn-flat" : "guard-btn-danger-soft"
            } guard-btn-sm`}
            style={{ flexShrink: 0 }}
            onClick={() => void handleToggleKillswitch()}
          >
            {busyAction === "killswitch" && <Loader2 size={13} className="guard-spin" />}
            <span>
              {busyAction === "killswitch"
                ? "执行中..."
                : snapshot.killSwitchActive
                ? "解除熔断保护..."
                : "立即触发紧急熔断"}
            </span>
          </button>
        </div>

        {/* 增量 15：防火墙防自锁救援卡片 */}
        <div className="guard-card" style={actionCardStyle}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, display: "flex", alignItems: "center", gap: 8 }}>
              <ShieldOff size={15} strokeWidth={1.8} />
              <span>清除本工具全部防火墙规则（防自锁救援）</span>
              <span className="guard-chip guard-chip-neutral">安全阀</span>
            </div>
            <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4, lineHeight: 1.55 }}>
              若因异常断电或崩溃导致残留 <code className="font-mono-code">FDClaudeGuard_KillSwitch_*</code>{" "}
              阻断规则，点此一键清空全部规则并恢复 Claude 出站放行。通过 Windows{" "}
              <strong style={{ color: "var(--text-1)", fontWeight: 500 }}>
                设置 → 应用 → 已安装的应用 → FD Claude 安全启动器 → 卸载
              </strong>{" "}
              正常卸载时，也会由安装包卸载钩子自动清空全部防火墙规则、计划任务及本地凭证。
            </div>
          </div>
          <button
            type="button"
            disabled={busy}
            className="guard-btn guard-btn-flat guard-btn-sm"
            style={{ flexShrink: 0 }}
            onClick={() => void handleCleanupAllFirewall()}
          >
            {busyAction === "fw_rescue" && <Loader2 size={13} className="guard-spin" />}
            <span>{busyAction === "fw_rescue" ? "清理中..." : "一键防自锁救援"}</span>
          </button>
        </div>

        <div className="guard-card" style={actionCardStyle}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600 }}>
              退出登录并清理（备份）本地污染目录
            </div>
            <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4 }}>
              不碰代码与云端对话；先彻底结束本地 Claude 进程并自动打包至 ~/FDtools-Backups/，再清空桌面端（含 MSIX）本地登录态 Cookie 与污染目录（若网页端登录了 claude.ai 需在浏览器内自行退出）。
            </div>
            <div
              data-testid="maintenance-roots-summary"
              className="font-mono-code"
              style={{ fontSize: 11.5, color: "var(--text-3)", marginTop: 6 }}
            >
              当前自动覆盖：经典目录（{rootsSummary.classicDetected ? "已识别" : "未检测到"}） · 微软商店 MSIX（
              {rootsSummary.msixPackages.length > 0
                ? `已识别 ${rootsSummary.msixPackages.length} 个实例`
                : "未安装，若后续安装将自动纳入"}
              ） · ~/.claude/telemetry/
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
            <button
              type="button"
              disabled={busy}
              className="guard-btn guard-btn-flat guard-btn-sm"
              onClick={() => void handleManualBackup()}
            >
              {busyAction === "manual_backup" && <Loader2 size={13} className="guard-spin" />}
              <span>{busyAction === "manual_backup" ? "创建中..." : "仅创建快照"}</span>
            </button>
            <button
              type="button"
              disabled={busy}
              className="guard-btn guard-btn-primary guard-btn-sm"
              onClick={() => void handleBackupAndClean()}
            >
              {busyAction === "backup_clean" && <Loader2 size={13} className="guard-spin" />}
              <span>
                {busyAction === "backup_clean" ? "备份清理中..." : "退出登录并清理（备份）"}
              </span>
            </button>
          </div>
        </div>

        <div style={{ flexShrink: 0 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: 10,
              gap: 12,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span style={{ fontSize: 14, fontWeight: 600 }}>历史备份快照管理</span>
              {backups.length > 0 && (
                <button
                  type="button"
                  disabled={busy}
                  className="guard-btn guard-btn-danger-soft guard-btn-xs"
                  onClick={handleClearAllBackups}
                >
                  {busyAction === "clear_all" ? (
                    <Loader2 size={12} className="guard-spin" />
                  ) : (
                    <Trash2 size={12} strokeWidth={1.85} />
                  )}
                  <span>清空全部备份 ({backups.length})</span>
                </button>
              )}
            </div>
            <span style={{ fontSize: 12, color: "var(--text-3)" }}>
              按时间倒序 · 精确到秒 · 滚动保留最近 10 份
            </span>
          </div>
          <div className="guard-card">
            {backups.length === 0 ? (
              <div style={{ padding: 18, fontSize: 12.5, color: "var(--text-2)" }}>
                暂无历史备份快照（执行清理或手动备份后将在此生成带唯一时间戳的原子 ZIP 快照并支持一键还原）。
              </div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                <thead>
                  <tr
                    style={{
                      borderBottom: "1px solid var(--border)",
                      color: "var(--text-3)",
                      fontSize: 12,
                    }}
                  >
                    <th style={thStyle}>备份文件</th>
                    <th style={thStyle}>类型</th>
                    <th style={thStyle}>创建时间（精确到秒）</th>
                    <th style={thStyle}>体积</th>
                    <th style={{ ...thStyle, textAlign: "right" }}>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {backups.map((b) => {
                    const restoring = busyAction === `restore:${b.fileName}`;
                    const deleting = busyAction === `delete:${b.fileName}`;
                    return (
                      <tr key={b.fileName} style={{ borderBottom: "1px solid var(--border)" }}>
                        <td className="font-mono-code" style={{ ...tdStyle, fontSize: 12 }}>
                          {b.fileName}
                        </td>
                        <td style={tdStyle}>
                          <span className="guard-chip guard-chip-neutral">{kindLabel(b.kind)}</span>
                        </td>
                        <td className="tabular" style={{ ...tdStyle, color: "var(--text-2)" }}>
                          {b.createdAt}
                        </td>
                        <td className="tabular" style={tdStyle}>
                          {b.sizeLabel}
                        </td>
                        <td style={{ ...tdStyle, textAlign: "right" }}>
                          <div
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              justifyContent: "flex-end",
                              gap: 6,
                            }}
                          >
                            <button
                              type="button"
                              disabled={busy}
                              className="guard-btn guard-btn-flat guard-btn-xs"
                              onClick={() => void handleRestore(b.fileName)}
                            >
                              {restoring && <Loader2 size={12} className="guard-spin" />}
                              <span>{restoring ? "还原中..." : "一键还原"}</span>
                            </button>
                            <button
                              type="button"
                              disabled={busy}
                              aria-label={`删除备份 ${b.fileName}`}
                              className="guard-btn guard-btn-danger-soft guard-btn-xs"
                              onClick={() => void handleDeleteOne(b.fileName)}
                            >
                              {deleting ? (
                                <Loader2 size={12} className="guard-spin" />
                              ) : (
                                <Trash2 size={12} strokeWidth={1.85} />
                              )}
                              <span>{deleting ? "删除中..." : "删除"}</span>
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* T-303：标准 496px 三段式一键匿名上报排障模态框（遵循 ui-design-system 4.4） */}
      {reportModalOpen && (
        <div
          data-testid="anonymous-report-modal"
          onClick={() => {
            if (!reportSubmitting) setReportModalOpen(false);
          }}
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 90,
            background: "rgba(0, 0, 0, 0.62)",
            backdropFilter: "blur(5px)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: 16,
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: 496,
              maxWidth: "96vw",
              background: "var(--bg-card)",
              border: "1px solid var(--border-strong)",
              borderRadius: 14,
              overflow: "hidden",
              boxShadow: "0 24px 64px rgba(0, 0, 0, 0.45)",
            }}
          >
            <div
              style={{
                padding: "18px 20px 14px",
                display: "flex",
                alignItems: "flex-start",
                justifyContent: "space-between",
                gap: 12,
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: 10,
                    background: "var(--primary-soft)",
                    color: "var(--primary)",
                    display: "grid",
                    placeItems: "center",
                    flexShrink: 0,
                  }}
                >
                  <Activity size={18} strokeWidth={1.85} />
                </div>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 15.5, fontWeight: 600 }}>一键匿名上报排障诊断</span>
                    <span className="guard-chip guard-chip-ok">已全量脱敏</span>
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 2 }}>
                    将发送脱敏运行故障与 72h 封号前置归因快照并生成单号
                  </div>
                </div>
              </div>
              <button
                type="button"
                aria-label="关闭弹窗"
                disabled={reportSubmitting}
                onClick={() => setReportModalOpen(false)}
                style={{
                  width: 28,
                  height: 28,
                  borderRadius: 7,
                  border: "none",
                  background: "transparent",
                  color: "var(--text-2)",
                  cursor: "pointer",
                  display: "grid",
                  placeItems: "center",
                }}
              >
                <X size={15} strokeWidth={1.85} />
              </button>
            </div>

            <div style={{ padding: "0 20px 18px", display: "flex", flexDirection: "column", gap: 10 }}>
              <div
                style={{
                  background: "var(--bg-subtle)",
                  border: "1px solid var(--border)",
                  borderRadius: 10,
                  padding: "10px 12px",
                  display: "flex",
                  flexDirection: "column",
                  gap: 7,
                  fontSize: 12,
                }}
              >
                <div style={{ display: "grid", gridTemplateColumns: "78px 1fr", gap: 10 }}>
                  <span style={{ color: "var(--text-3)" }}>上传内容</span>
                  <span style={{ color: "var(--text-1)" }}>
                    FDtools 近 7 天脱敏故障 + Claude 报错类型 + 72h 前置因子
                  </span>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "78px 1fr", gap: 10 }}>
                  <span style={{ color: "var(--text-3)" }}>已剔除隐私</span>
                  <span style={{ color: "var(--success)" }}>
                    邮箱 / Token / 机场订阅 URL / 真实 IP / 用户名 / 对话内容
                  </span>
                </div>
              </div>

              {reportResult && (
                <div
                  data-testid="anonymous-report-ticket"
                  style={{
                    padding: "10px 12px",
                    borderRadius: 8,
                    background: "var(--success-soft)",
                    color: "var(--success)",
                    fontSize: 12,
                    lineHeight: 1.55,
                  }}
                >
                  已生成排障单号：
                  <strong className="font-mono-code">{reportResult.ticketId}</strong>
                  （已复制，发给开发者即可快速定位）
                </div>
              )}

              {reportError && (
                <div
                  style={{
                    padding: "10px 12px",
                    borderRadius: 8,
                    background: "var(--danger-soft)",
                    color: "var(--danger-bright)",
                    fontSize: 12,
                    lineHeight: 1.55,
                  }}
                >
                  {reportError}
                </div>
              )}
            </div>

            <div
              style={{
                padding: "12px 20px",
                borderTop: "1px solid var(--border)",
                background: "rgba(128, 128, 140, 0.03)",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 10,
              }}
            >
              <span style={{ fontSize: 11.5, color: "var(--text-3)" }}>数据经统一脱敏管线处理</span>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  type="button"
                  disabled={reportSubmitting}
                  className="guard-btn guard-btn-flat guard-btn-sm"
                  onClick={() => setReportModalOpen(false)}
                >
                  {reportResult ? "关闭" : "取消"}
                </button>
                {!reportResult && (
                  <button
                    type="button"
                    data-testid="btn-confirm-anonymous-report"
                    disabled={reportSubmitting}
                    className="guard-btn guard-btn-primary guard-btn-sm"
                    onClick={async () => {
                      setReportSubmitting(true);
                      setReportError(null);
                      try {
                        const res = await ipc.submitAnonymousFeedbackReport();
                        setReportResult(res);
                        try {
                          await navigator.clipboard.writeText(res.ticketId);
                        } catch {
                          // 剪贴板不可用时静默降级
                        }
                        pushToast("已匿名上报排障快照", `排障单号：${res.ticketId}`, "ok");
                      } catch (err) {
                        setReportError(String(err));
                      } finally {
                        setReportSubmitting(false);
                      }
                    }}
                  >
                    {reportSubmitting && <Loader2 size={13} className="guard-spin" />}
                    <span>{reportSubmitting ? "上报中..." : "确认匿名上报"}</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

const actionCardStyle: React.CSSProperties = {
  padding: 16,
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: 16,
  flexShrink: 0,
};

const thStyle: React.CSSProperties = { textAlign: "left", padding: "10px 14px", fontWeight: 500 };
const tdStyle: React.CSSProperties = { padding: "11px 14px" };
