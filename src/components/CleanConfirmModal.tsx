import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Check, Loader2, ShieldCheck, User, X } from "lucide-react";
import { ThinScrollArea } from "@/components/ThinScrollArea";
import { ipc } from "@/lib/ipc";
import { useGuardStore } from "@/stores/guardStore";
import type { CleanupPlanPreview } from "@/types/guard";

function formatBytesLabel(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(0)} KB`;
  }
  return `${bytes} B`;
}

/**
 * 清理前透明清单确认弹窗（v3.0 双主题轻遮罩/轻投影 + ThinScrollArea + 主题自适应复选框 + FD-Fine 数值）
 */
export function CleanConfirmModal() {
  const modal = useGuardStore((s) => s.cleanModal);
  const close = useGuardStore((s) => s.closeCleanModal);
  const pushToast = useGuardStore((s) => s.pushToast);
  const refreshPreflight = useGuardStore((s) => s.refreshPreflight);
  const setActiveTab = useGuardStore((s) => s.setActiveTab);

  const [loading, setLoading] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [preview, setPreview] = useState<CleanupPlanPreview | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  useEffect(() => {
    if (!modal?.open) {
      setPreview(null);
      setScanError(null);
      setSelectedIds([]);
      setLoading(false);
      setExecuting(false);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setScanError(null);

    void ipc
      .previewClaudeCleanupPlan()
      .then((res) => {
        if (cancelled) return;
        setPreview(res);
        // 仅默认勾选 defaultSelected === true 的项目（MCP 配置与本地会话默认不勾选防错删）
        const defaults = res.categories
          .filter((c) => c.defaultSelected)
          .map((c) => c.id);
        setSelectedIds(defaults);
      })
      .catch((err) => {
        if (cancelled) return;
        setScanError(String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [modal?.open]);

  useEffect(() => {
    if (!modal?.open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !executing) {
        close();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [modal?.open, executing, close]);

  const stats = useMemo(() => {
    if (!preview) {
      return { selectedCount: 0, totalCount: 0, backupBytes: 0, cleanBytes: 0 };
    }
    const sel = new Set(selectedIds);
    let backupBytes = 0;
    let cleanBytes = 0;
    for (const c of preview.categories) {
      if (sel.has(c.id)) {
        cleanBytes += c.totalBytes;
        if (c.willBackup) {
          backupBytes += c.totalBytes;
        }
      }
    }
    return {
      selectedCount: selectedIds.length,
      totalCount: preview.categories.length,
      backupBytes,
      cleanBytes,
    };
  }, [preview, selectedIds]);

  if (!modal || !modal.open) return null;

  const toggleId = (id: string) => {
    if (executing) return;
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const handleConfirm = async () => {
    if (selectedIds.length === 0 || executing) return;
    setExecuting(true);
    try {
      const info = await ipc.backupAndCleanClaude(selectedIds);
      const onCompleted = modal.onCompleted;
      const fromMaintain = modal.sourceLabel?.includes("环境维护");
      close();
      pushToast(
        "已完成原子备份并按勾选项清理",
        `已归档至 ${info.fileName}（${info.sizeLabel}），未勾选项与受保护项（程序本体 / VM 镜像）保持 100% 完好。`,
        "ok",
        {
          durationMs: 6500,
          action: fromMaintain
            ? {
                label: "打开所在文件夹",
                onClick: () => void ipc.openFileFolder(info.fullPath),
              }
            : {
                label: "前往环境维护查看快照",
                onClick: () => setActiveTab("maintain"),
              },
        }
      );
      if (onCompleted) {
        try {
          await onCompleted(info, selectedIds);
        } catch (cbErr) {
          pushToast("清理后刷新视图提示", String(cbErr), "info");
        }
      }
      // 无论从哪一页发起清理，统一静默刷新体检与账户审计，消除侧边栏红标滞留
      void refreshPreflight(true);
      void useGuardStore.getState().refreshAccountAudit(true);
    } catch (err) {
      pushToast("备份清理失败", String(err), "danger");
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="确认本地清理与备份清单"
      data-testid="clean-confirm-modal"
      onClick={(e) => {
        if (e.target === e.currentTarget && !executing) close();
      }}
      style={{
        position: "fixed",
        inset: 0,
        background: "var(--modal-backdrop)",
        backdropFilter: "blur(4px)",
        zIndex: 160,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 18,
      }}
    >
      <div
        style={{
          width: 688,
          maxWidth: "96vw",
          maxHeight: "90vh",
          background: "var(--bg-card)",
          border: "1px solid var(--border-card)",
          borderRadius: 13,
          boxShadow: "var(--shadow-modal)",
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: "15px 18px 13px",
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 12,
            borderBottom: "1px solid var(--divider)",
            flexShrink: 0,
          }}
        >
          <div style={{ display: "flex", alignItems: "flex-start", gap: 12, minWidth: 0 }}>
            <div
              style={{
                width: 34,
                height: 34,
                borderRadius: 9,
                display: "grid",
                placeItems: "center",
                flexShrink: 0,
                background: "var(--warning-soft)",
                border: "1px solid var(--warning-border)",
                color: "var(--warning-fg)",
              }}
            >
              <AlertTriangle size={16} strokeWidth={1.5} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                <h3
                  style={{
                    fontSize: 15,
                    fontWeight: 500,
                    color: "var(--text-strong)",
                    letterSpacing: "-0.01em",
                    margin: 0,
                  }}
                >
                  确认本地清理与备份清单
                </h3>
                <span className="guard-chip guard-chip-warn">分项透明可控</span>
                {modal.sourceLabel && (
                  <span className="guard-chip guard-chip-neutral">{modal.sourceLabel}</span>
                )}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 3, lineHeight: 1.48 }}>
                默认同时勾选<span style={{ color: "var(--text-strong)", fontWeight: 500 }}>桌面端与 CLI 登录态</span>以保障本机环境彻底干净；如需保留某端账号，直接取消勾选对应项即可。带「先备份 ZIP」标记的数据将原子打包后删除，随时可在环境维护页一键还原。
              </div>
            </div>
          </div>
          <button
            type="button"
            aria-label="关闭清理确认弹窗"
            disabled={executing}
            className="modal-close-btn"
            onClick={close}
          >
            <X size={15} strokeWidth={1.5} />
          </button>
        </div>

        {/* Body（接入 ThinScrollArea 悬浮细滑块，确保下方隐藏项与保护项清晰可感知） */}
        <ThinScrollArea style={{ flex: 1, minHeight: 0 }}>
          <div
            style={{
              padding: "12px 18px 16px",
              display: "flex",
              flexDirection: "column",
              gap: 10,
            }}
          >
            {loading && (
              <div
                style={{
                  padding: "36px 16px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: 10,
                  color: "var(--text-2)",
                  fontSize: 12.5,
                }}
              >
                <Loader2 size={15} strokeWidth={1.7} className="guard-spin" />
                <span>正在异步扫描本机全部 Claude 安装目录与文件体积...</span>
              </div>
            )}

            {!loading && scanError && (
              <div
                style={{
                  padding: "13px 15px",
                  borderRadius: 9,
                  border: "1px solid var(--bad-border)",
                  background: "var(--bad-bg)",
                  color: "var(--bad-fg)",
                  fontSize: 12,
                }}
              >
                扫描本机目录失败：{scanError}
              </div>
            )}

            {!loading && preview && (
              <>
                {/* 已识别安装形态概览条 */}
                <div
                  data-testid="clean-detected-modes"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 10,
                    padding: "8px 12px",
                    borderRadius: 9,
                    background: "var(--bg-card-band)",
                    border: "1px solid var(--divider)",
                    fontSize: 11.5,
                    flexWrap: "wrap",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                    <span style={{ color: "var(--text-3)", marginRight: 2 }}>已识别安装形态：</span>
                    {preview.detectedInstallModes.map((mode) => (
                      <span key={mode} className="guard-chip guard-chip-neutral">
                        {mode}
                      </span>
                    ))}
                  </div>
                  <span
                    className="tabular"
                    style={{
                      fontSize: 11.5,
                      color: "var(--text-3)",
                      whiteSpace: "nowrap",
                    }}
                  >
                    活跃进程 {preview.activeClaudeProcs} 个 · 扫描 {preview.scannedMs} ms
                  </span>
                </div>

                {/* 分项清单卡片 */}
                <div
                  style={{
                    border: "1px solid var(--divider)",
                    borderRadius: 10,
                    background: "var(--bg-card)",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      padding: "7.5px 13px",
                      background: "var(--bg-card-band)",
                      borderBottom: "1px solid var(--divider)",
                      fontSize: 11,
                      color: "var(--text-3)",
                    }}
                  >
                    <span>清理项目与对应目录（未勾选项目将原样保留 · 共 {preview.categories.length} 项可向下滚动）</span>
                    <span>体积 / 文件数</span>
                  </div>

                  {preview.categories.map((cat) => {
                    const checked = selectedIds.includes(cat.id);
                    const isOptional = !cat.defaultSelected;
                    return (
                      <label
                        key={cat.id}
                        data-testid={`clean-cat-${cat.id}`}
                        style={{
                          display: "grid",
                          gridTemplateColumns: "20px 1fr auto",
                          gap: 10,
                          alignItems: "flex-start",
                          padding: "10px 13px",
                          borderBottom: "1px solid var(--divider)",
                          cursor: executing ? "not-allowed" : "pointer",
                          opacity: cat.fileCount === 0 ? 0.62 : 1,
                        }}
                      >
                        <input
                          type="checkbox"
                          className="guard-checkbox"
                          checked={checked}
                          disabled={executing}
                          onChange={() => toggleId(cat.id)}
                          data-testid={`clean-check-${cat.id}`}
                          style={{ marginTop: 2 }}
                        />
                        <div style={{ minWidth: 0 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap" }}>
                            <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--text-strong)" }}>
                              {cat.title}
                            </span>
                            {isOptional ? (
                              <span className="guard-chip guard-chip-warn">默认保留防错删</span>
                            ) : cat.willBackup ? (
                              <span className="guard-chip guard-chip-ok">先备份 ZIP</span>
                            ) : (
                              <span className="guard-chip guard-chip-neutral">仅清理 · 不入 ZIP</span>
                            )}
                          </div>
                          <div
                            style={{
                              fontSize: 11.5,
                              color: "var(--text-2)",
                              marginTop: 3,
                              lineHeight: 1.48,
                            }}
                          >
                            {cat.description}
                          </div>
                          {cat.accountSummary && (
                            <div
                              data-testid={`clean-account-${cat.id}`}
                              className="tabular"
                              style={{
                                display: "inline-flex",
                                alignItems: "center",
                                gap: 6,
                                marginTop: 5.5,
                                padding: "3px 8px",
                                borderRadius: 6,
                                background: checked ? "var(--warning-soft)" : "var(--bg-subtle)",
                                border: `1px solid ${checked ? "var(--warning-border)" : "var(--divider)"}`,
                                fontSize: 11,
                                color: checked ? "var(--text-1)" : "var(--text-2)",
                                maxWidth: "100%",
                              }}
                            >
                              <User size={11.5} strokeWidth={1.6} style={{ flexShrink: 0, opacity: 0.8 }} />
                              <span
                                style={{
                                  overflow: "hidden",
                                  textOverflow: "ellipsis",
                                  whiteSpace: "nowrap",
                                }}
                                title={cat.accountSummary}
                              >
                                {cat.accountSummary}
                              </span>
                              {!checked && (
                                <span
                                  style={{
                                    fontSize: 10.5,
                                    color: "var(--ok-fg)",
                                    fontWeight: 500,
                                    flexShrink: 0,
                                  }}
                                >
                                  · 将保留
                                </span>
                              )}
                            </div>
                          )}
                          {cat.samplePaths.length > 0 && (
                            <div
                              title={cat.samplePaths.join(" | ")}
                              className="font-mono-code"
                              style={{
                                fontSize: 10.5,
                                color: "var(--text-3)",
                                marginTop: 4.5,
                                whiteSpace: "nowrap",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                              }}
                            >
                              {cat.samplePaths.join(", ")}
                            </div>
                          )}
                        </div>
                        <div
                          className="tabular"
                          style={{
                            textAlign: "right",
                            whiteSpace: "nowrap",
                            display: "flex",
                            flexDirection: "column",
                            alignItems: "flex-end",
                            gap: 2.5,
                          }}
                        >
                          <span
                            style={{
                              fontSize: 12,
                              fontWeight: 500,
                              color: "var(--text-strong)",
                            }}
                          >
                            {cat.sizeLabel}
                          </span>
                          <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                            {cat.fileCount} 个文件
                          </span>
                        </div>
                      </label>
                    );
                  })}

                  {/* 始终锁定保护行 */}
                  <div
                    data-testid="clean-protected-row"
                    style={{
                      display: "grid",
                      gridTemplateColumns: "20px 1fr auto",
                      gap: 10,
                      alignItems: "flex-start",
                      padding: "10px 13px",
                      background: "var(--ok-bg)",
                    }}
                  >
                    <div
                      style={{
                        width: 15,
                        height: 15,
                        marginTop: 2,
                        display: "grid",
                        placeItems: "center",
                        color: "var(--ok-fg)",
                      }}
                    >
                      <ShieldCheck size={15} strokeWidth={1.6} />
                    </div>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap" }}>
                        <span style={{ fontSize: 12.5, fontWeight: 500, color: "var(--text-strong)" }}>
                          自动保护项（绝不打包、绝不删除）
                        </span>
                        <span className="guard-chip guard-chip-ok">已安全跳过</span>
                      </div>
                      <div
                        style={{
                          fontSize: 11.5,
                          color: "var(--text-2)",
                          marginTop: 3,
                          lineHeight: 1.48,
                        }}
                      >
                        已自动排除虚拟机镜像（vm_bundles）、Claude 程序本体（WindowsApps / Local\Claude\app-*）、软链接外部目标、项目代码与云端对话。
                      </div>
                      <div
                        className="font-mono-code"
                        style={{
                          fontSize: 10.5,
                          color: "var(--text-3)",
                          marginTop: 4.5,
                          whiteSpace: "nowrap",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                        }}
                      >
                        {preview.protected.reasons.join(" · ")}
                      </div>
                    </div>
                    <div
                      className="tabular"
                      style={{
                        textAlign: "right",
                        whiteSpace: "nowrap",
                        display: "flex",
                        flexDirection: "column",
                        alignItems: "flex-end",
                        gap: 2.5,
                      }}
                    >
                      <span style={{ fontSize: 12, fontWeight: 500, color: "var(--ok-fg)" }}>
                        {preview.protected.totalBytes > 0 ? preview.protected.sizeLabel : "全程保护"}
                      </span>
                      <span style={{ fontSize: 11, color: "var(--text-3)" }}>已保护</span>
                    </div>
                  </div>
                </div>

                <div
                  style={{
                    fontSize: 11.5,
                    color: "var(--text-2)",
                    lineHeight: 1.55,
                    padding: "8px 12px",
                    borderRadius: 8,
                    border: "1px dashed var(--divider-strong)",
                    background: "var(--bg-card-band)",
                  }}
                >
                  提示：执行时将自动结束 Claude 桌面端进程并等待文件句柄释放；浏览器网页版{" "}
                  <span className="font-mono-code" style={{ color: "var(--text-1)" }}>
                    claude.ai
                  </span>{" "}
                  登录态需在浏览器内手动退出。
                </div>
              </>
            )}
          </div>
        </ThinScrollArea>

        {/* Footer */}
        <div
          style={{
            padding: "12px 18px",
            background: "var(--bg-card-band)",
            borderTop: "1px solid var(--divider)",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 12,
            flexShrink: 0,
            flexWrap: "wrap",
          }}
        >
          <div className="tabular" style={{ fontSize: 12, color: "var(--text-2)" }} data-testid="clean-modal-summary">
            已选 <span style={{ color: "var(--text-strong)", fontWeight: 500 }}>{stats.selectedCount} / {stats.totalCount}</span>{" "}
            项 · 预计备份{" "}
            <span style={{ color: "var(--text-strong)", fontWeight: 500 }}>
              {formatBytesLabel(stats.backupBytes)}
            </span>{" "}
            · 预计清理{" "}
            <span style={{ color: "var(--text-strong)", fontWeight: 500 }}>
              {formatBytesLabel(stats.cleanBytes)}
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <button
              type="button"
              disabled={executing}
              className="guard-btn guard-btn-flat guard-btn-sm"
              onClick={close}
            >
              取消
            </button>
            <button
              type="button"
              data-testid="btn-clean-modal-confirm"
              disabled={loading || executing || stats.selectedCount === 0}
              className="guard-btn guard-btn-primary guard-btn-sm"
              onClick={() => void handleConfirm()}
            >
              {executing ? (
                <Loader2 size={13} strokeWidth={1.85} className="guard-spin" />
              ) : (
                <Check size={13} strokeWidth={1.9} />
              )}
              <span>
                {executing
                  ? "异步备份与清理中..."
                  : `先备份并清理已选 ${stats.selectedCount} 项`}
              </span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
