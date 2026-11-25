import { useEffect, useState } from "react";
import { Activity, Bell, Download, Loader2, RefreshCw, ShieldAlert, X } from "lucide-react";
import { CheckIcon } from "@/components/CheckIcon";
import { ipc } from "@/lib/ipc";
import { useGuardStore } from "@/stores/guardStore";
import type { AppConfig, AppUpdateInfo } from "@/types/guard";

type BoolConfigKey =
  | "showHud"
  | "notifyEnabled"
  | "bootStart"
  | "bootHudOnly"
  | "wakePreblockGuard"
  | "antiNakedGuard"
  | "autoKillSwitch"
  | "antiUploadFlush"
  | "safeExitPrompt"
  | "calm24h"
  | "telemetryToolDiagEnabled"
  | "telemetryClaudeSummaryEnabled";

interface SwitchRowProps {
  configKey: BoolConfigKey;
  icon: string;
  customIcon?: React.ReactNode;
  title: string;
  desc: string;
  badge?: { text: string; tone: "ok" | "neutral" | "warn" };
  checked: boolean;
  disabled?: boolean;
  subRow?: boolean;
  onToggle: (key: BoolConfigKey, next: boolean, label: string) => void;
}

function SwitchRow({
  configKey,
  icon,
  customIcon,
  title,
  desc,
  badge,
  checked,
  disabled,
  subRow,
  onToggle,
}: SwitchRowProps) {
  const handleToggle = () => {
    if (disabled) return;
    onToggle(configKey, !checked, title);
  };

  return (
    <div
      className={`guard-row ${subRow ? "sub-row" : ""}`}
      onClick={handleToggle}
      style={{ opacity: disabled ? 0.58 : 1, cursor: disabled ? "not-allowed" : "pointer" }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0, flex: 1 }}>
        <div className="guard-icon-box">{customIcon ?? <CheckIcon name={icon} />}</div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 14, fontWeight: 500, color: "var(--text-1)", lineHeight: 1.3 }}>
            {title}
          </div>
          {/* 全宽配置页副文允许完整折行，严禁窄栏截断 */}
          <div
            style={{
              fontSize: 12,
              color: "var(--text-2)",
              marginTop: 2,
              whiteSpace: "normal",
              lineHeight: 1.48,
            }}
          >
            {desc}
          </div>
        </div>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
        {badge && (
          <span
            className={`guard-chip ${
              badge.tone === "ok"
                ? "guard-chip-ok"
                : badge.tone === "warn"
                ? "guard-chip-warn"
                : "guard-chip-neutral"
            }`}
          >
            {badge.text}
          </span>
        )}
        <button
          type="button"
          role="switch"
          aria-checked={checked}
          aria-label={title}
          disabled={disabled}
          className={`guard-switch ${checked ? "on" : ""}`}
          onClick={(e) => {
            e.stopPropagation();
            handleToggle();
          }}
        />
      </div>
    </div>
  );
}

export function SettingsPage() {
  const [sampleOpen, setSampleOpen] = useState(false);
  const [sampleJson, setSampleJson] = useState("");
  const [sampleLoading, setSampleLoading] = useState(false);
  const [updateChecking, setUpdateChecking] = useState(false);
  const [updateInstalling, setUpdateInstalling] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<AppUpdateInfo | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const config: AppConfig = useGuardStore((s) => s.config);
  const startupAudit = useGuardStore((s) => s.startupAudit);
  const updateConfig = useGuardStore((s) => s.updateConfig);
  const pushToast = useGuardStore((s) => s.pushToast);

  useEffect(() => {
    if (!sampleOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setSampleOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [sampleOpen]);

  const handleToggle = (key: BoolConfigKey, next: boolean, label: string) => {
    void updateConfig({ [key]: next }, label);
  };

  const handleCheckUpdate = async () => {
    if (updateChecking || updateInstalling) return;
    setUpdateChecking(true);
    setUpdateError(null);
    try {
      const info = await ipc.checkAppUpdate();
      setUpdateInfo(info);
      pushToast(
        info.available ? `发现新版本 v${info.latestVersion ?? ""}` : "当前已是最新版本",
        info.message,
        info.available ? "info" : "ok"
      );
    } catch (err) {
      const msg = String(err);
      setUpdateError(msg);
      pushToast("检查更新失败", msg, "danger");
    } finally {
      setUpdateChecking(false);
    }
  };

  const handleInstallUpdate = async () => {
    if (updateInstalling) return;
    setUpdateInstalling(true);
    setUpdateError(null);
    try {
      const msg = await ipc.installAppUpdate();
      pushToast("更新包校验通过", msg, "ok");
    } catch (err) {
      const msg = String(err);
      setUpdateError(msg);
      pushToast("自动更新安装失败", msg, "danger");
    } finally {
      setUpdateInstalling(false);
    }
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
            守卫配置
          </h1>
          <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 4 }}>
            所有自动防护策略默认开启，均可按需手动开关 · 含客户端签名更新与开机启动项监测
          </div>
        </div>
        <button
          type="button"
          data-testid="btn-check-app-update"
          disabled={updateChecking || updateInstalling}
          className="guard-btn guard-btn-flat guard-btn-sm"
          onClick={() => void handleCheckUpdate()}
          style={{ whiteSpace: "nowrap", flexShrink: 0 }}
        >
          {updateChecking ? (
            <Loader2 size={13.5} className="guard-spin" />
          ) : (
            <RefreshCw size={13.5} strokeWidth={1.85} />
          )}
          <span>{updateChecking ? "正在检查更新..." : "检查更新"}</span>
        </button>
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
        {/* 客户端版本与自动更新卡片 */}
        <div
          className="guard-card"
          data-testid="app-updater-card"
          style={{
            padding: "12px 14px",
            display: "flex",
            flexDirection: "column",
            gap: 8,
            flexShrink: 0,
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: 12,
              flexWrap: "wrap",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0, flex: 1 }}>
              <div className="guard-icon-box">
                <Download size={16} strokeWidth={1.75} />
              </div>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                  <span style={{ fontSize: 14, fontWeight: 500, color: "var(--text-1)" }}>
                    客户端版本与自动更新
                  </span>
                  <span className="guard-chip guard-chip-neutral tabular">
                    v{updateInfo?.currentVersion ?? "0.3.0"}
                  </span>
                  {updateInfo?.available && updateInfo.latestVersion && (
                    <span className="guard-chip guard-chip-ok tabular">
                      发现新版本 v{updateInfo.latestVersion}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 2, lineHeight: 1.48 }}>
                  {updateError
                    ? `检查更新遇到问题：${updateError}`
                    : updateInfo
                    ? updateInfo.message
                    : "基于 GitHub Releases 官方签发通道（Ed25519 公钥验签），自动复用本机代理并在失败时回退直连。"}
                </div>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
              {updateInfo?.available && (
                <button
                  type="button"
                  data-testid="btn-install-app-update"
                  disabled={updateInstalling}
                  className="guard-btn guard-btn-primary guard-btn-sm"
                  onClick={() => void handleInstallUpdate()}
                  style={{ whiteSpace: "nowrap" }}
                >
                  {updateInstalling ? (
                    <Loader2 size={13.5} className="guard-spin" />
                  ) : (
                    <Download size={13.5} strokeWidth={1.9} />
                  )}
                  <span>{updateInstalling ? "正在下载并校验签名..." : "一键下载并安装"}</span>
                </button>
              )}
            </div>
          </div>
          {updateInfo?.available && updateInfo.notes && (
            <pre
              className="font-mono-code"
              style={{
                margin: 0,
                padding: "8px 10px",
                borderRadius: 8,
                background: "var(--bg-subtle)",
                border: "1px solid var(--border)",
                fontSize: 11.5,
                color: "var(--text-2)",
                whiteSpace: "pre-wrap",
                lineHeight: 1.5,
              }}
            >
              {updateInfo.notes}
            </pre>
          )}
        </div>
        <div>
          <div style={sectionHeaderStyle}>
            <span>桌面悬浮窗、消息提醒与开机保护</span>
            <span style={{ fontSize: 12, color: "var(--text-3)", fontWeight: 400 }}>
              绿标为强烈推荐保持开启
            </span>
          </div>
          <div className="guard-card">
            <SwitchRow
              configKey="showHud"
              icon="hudIcon"
              title="显示桌面悬浮状态窗"
              desc="常驻展示节点、日志与流量健康状态，支持整卡拖拽与靠右贴边（与主窗口右上角开关、托盘实时同步）"
              badge={{ text: "推荐开启", tone: "ok" }}
              checked={config.showHud}
              onToggle={handleToggle}
            />
            <SwitchRow
              configKey="notifyEnabled"
              icon="startup"
              customIcon={<Bell size={16} strokeWidth={1.75} />}
              title="桌面预警消息提醒（可一键静音普通预警）"
              desc="悬浮窗隐藏或贴边时，事件驱动触发预警立即通过 Windows 原生通知推送；关闭后仅静音普通预警，熔断与防裸奔等危急警报仍保持强提醒"
              badge={{ text: "推荐开启", tone: "ok" }}
              checked={config.notifyEnabled}
              onToggle={handleToggle}
            />
            <SwitchRow
              configKey="bootStart"
              icon="startup"
              title="开机自动启动 FD Claude 安全启动器"
              desc="随 Windows 开机在后台静默启动守护引擎"
              badge={{ text: "推荐开启", tone: "ok" }}
              checked={config.bootStart}
              onToggle={handleToggle}
            />
            <SwitchRow
              configKey="bootHudOnly"
              icon="hudIcon"
              title="开机时仅显示桌面悬浮窗，不弹出主控制台"
              desc="零打扰呈现桌面状态卡，支持靠右贴边自动隐藏，点击随时回到控制台"
              badge={{ text: "推荐开启", tone: "ok" }}
              checked={config.bootHudOnly}
              disabled={!config.bootStart}
              subRow
              onToggle={handleToggle}
            />
            <SwitchRow
              configKey="wakePreblockGuard"
              icon="clock"
              title="休眠唤醒 / 切网最长 15 秒预阻断安全窗"
              desc="监测笔记本休眠唤醒或切网瞬间，先挂上最长 15 秒临时出站阻断，待 Clash 命名管道、TUN 与白名单节点复测通过后再毫秒级自动放行，超时未恢复则自动转入 4 层熔断"
              badge={{ text: "推荐开启", tone: "ok" }}
              checked={config.wakePreblockGuard}
              onToggle={handleToggle}
            />
            <SwitchRow
              configKey="antiNakedGuard"
              icon="ban"
              title="防裸奔自动接管（拦截直接双击原生 Claude）"
              desc="检测到直接启动 Claude 且环境未全绿时，500ms 内防火墙拦截出站并自动唤起控制台"
              badge={{ text: "推荐开启", tone: "ok" }}
              checked={config.antiNakedGuard}
              onToggle={handleToggle}
            />
          </div>
        </div>

        <div>
          <div style={sectionHeaderStyle}>
            <span>紧急断流与 4 层防回传策略</span>
            <span style={{ fontSize: 12, color: "var(--text-3)", fontWeight: 400 }}>
              平时静默护航，仅在异常时刻介入
            </span>
          </div>
          <div className="guard-card">
            <SwitchRow
              configKey="autoKillSwitch"
              icon="fw"
              title="异常全自动紧急断流（Clash 掐流 + 防火墙封死出站）"
              desc="地区漂移或代理断开时毫秒级阻断 100% 出站流量"
              badge={{ text: "推荐开启", tone: "ok" }}
              checked={config.autoKillSwitch}
              onToggle={handleToggle}
            />
            <SwitchRow
              configKey="antiUploadFlush"
              icon="privacy"
              title="熔断恢复前强杀进程丢弃内存队列 + 清离线遥测缓存"
              desc="跳过 onQuitCleanup 防止积攒的风险事件在恢复联网时补发给 Anthropic"
              badge={{ text: "仅熔断生效", tone: "neutral" }}
              checked={config.antiUploadFlush}
              onToggle={handleToggle}
            />
            <SwitchRow
              configKey="safeExitPrompt"
              icon="userLock"
              title="安全退出防呆提醒"
              desc="关闭守卫或停用代理前若检测到 Claude 仍有后台残留进程，立即弹窗提醒"
              badge={{ text: "推荐开启", tone: "ok" }}
              checked={config.safeExitPrompt}
              onToggle={handleToggle}
            />
            <SwitchRow
              configKey="calm24h"
              icon="clock"
              title="新号 / 刚付费 24h 冷静保护模式"
              desc="度过支付反欺诈异步审核期：严禁切节点、低并发提醒、最高级监控 401/403"
              badge={{ text: "按需开启", tone: "neutral" }}
              checked={config.calm24h}
              onToggle={handleToggle}
            />
            <div className="guard-row" style={{ cursor: "default" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0, flex: 1 }}>
                <div className="guard-icon-box">
                  <CheckIcon name="ban" />
                </div>
                <div style={{ minWidth: 0, flex: 1 }}>
                  <div style={{ fontSize: 14, fontWeight: 500, color: "var(--text-1)", lineHeight: 1.3 }}>
                    强杀防复活持续盯防锁时长（Kill-Hold）
                  </div>
                  <div
                    style={{
                      fontSize: 12,
                      color: "var(--text-2)",
                      marginTop: 2,
                      whiteSpace: "normal",
                      lineHeight: 1.48,
                    }}
                  >
                    每次手动或自动强杀 Claude 进程后，每 250ms 持续盯防关联进程树，冒头即强杀并自动顺延 +15s；点击「安全启动 Claude」前自动优雅释放
                  </div>
                </div>
              </div>
              <div
                data-testid="kill-hold-duration-selector"
                style={{
                  display: "inline-flex",
                  padding: 2,
                  borderRadius: 8,
                  background: "var(--bg-subtle)",
                  border: "1px solid var(--border)",
                  gap: 2,
                  flexShrink: 0,
                }}
              >
                {([30, 45, 60] as const).map((secs) => {
                  const active = (config.killHoldSeconds ?? 45) === secs;
                  return (
                    <button
                      key={secs}
                      type="button"
                      onClick={() =>
                        void updateConfig({ killHoldSeconds: secs }, `防复活盯防时长 (${secs}s)`)
                      }
                      style={{
                        border: "none",
                        background: active ? "var(--bg-card)" : "transparent",
                        color: active ? "var(--text-1)" : "var(--text-2)",
                        padding: "4px 10px",
                        borderRadius: 6,
                        fontFamily: "var(--font-sans)",
                        fontSize: 12,
                        fontWeight: active ? 600 : 500,
                        cursor: "pointer",
                      }}
                    >
                      {secs}s
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        <div>
          <div style={sectionHeaderStyle}>
            <span>匿名诊断与封号归因遥测（可随时关闭）</span>
            <span style={{ fontSize: 12, color: "var(--text-3)", fontWeight: 400 }}>
              严格脱敏，绝不上传账号 / Token / IP / 对话
            </span>
          </div>
          <div className="guard-card">
            <SwitchRow
              configKey="telemetryToolDiagEnabled"
              icon="startup"
              customIcon={<Activity size={16} strokeWidth={1.75} />}
              title="上报本工具运行异常与一键修复诊断"
              desc="日常体检与一般业务日志仅本地记录；仅当自动修复真实失败或触发 4 层热熔断时低频上报脱敏错误摘要（跨重启去重、单机每日上限 10 条，超时 2 秒静默跳过）"
              badge={{ text: "推荐开启", tone: "ok" }}
              checked={config.telemetryToolDiagEnabled ?? true}
              onToggle={handleToggle}
            />
            <SwitchRow
              configKey="telemetryClaudeSummaryEnabled"
              icon="ban"
              customIcon={<ShieldAlert size={16} strokeWidth={1.75} />}
              title="上报 Claude 高危异常与 72h 封号前置归因摘要"
              desc="仅在命中高危实锤事件（封号 / 验证受限 / 地区封锁 / 跨号连坐 / 退出回传 403）时低频上报类型摘要与 72h 6 维匿名因子，普通提醒（如 Free/KYC 403、529）仅记本地不发网"
              badge={{ text: "按需开启", tone: "neutral" }}
              checked={config.telemetryClaudeSummaryEnabled ?? true}
              onToggle={handleToggle}
            />
          </div>
          <div style={{ marginTop: 6 }}>
            <button
              type="button"
              data-testid="btn-preview-telemetry-sample"
              className="guard-text-link"
              onClick={async () => {
                setSampleOpen(true);
                setSampleLoading(true);
                try {
                  const text = await ipc.previewAnonymousFeedbackPayload();
                  setSampleJson(text);
                } catch (err) {
                  setSampleJson(`读取示例失败：${String(err)}`);
                } finally {
                  setSampleLoading(false);
                }
              }}
            >
              查看实际上传的脱敏数据结构示例 ↗
            </button>
          </div>
        </div>

        <div>
          <div style={sectionHeaderStyle}>
            <span>开机启动项风险监测（只读检测，绝不擅自删除你的启动项）</span>
          </div>
          <div className="guard-card">
            {startupAudit.entries.map((entry) => (
              <div key={entry.app} className="guard-row" style={{ cursor: "default" }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 14, fontWeight: 500, color: "var(--text-1)" }}>
                    {entry.app}
                  </div>
                  <div
                    style={{
                      fontSize: 12,
                      color: "var(--text-2)",
                      marginTop: 2,
                      whiteSpace: "normal",
                      lineHeight: 1.48,
                    }}
                  >
                    {entry.detail}
                  </div>
                </div>
                <span
                  data-testid={`startup-chip-${entry.app}`}
                  className={`guard-chip ${
                    entry.riskLevel === "ok"
                      ? "guard-chip-ok"
                      : entry.riskLevel === "warn"
                      ? "guard-chip-warn"
                      : "guard-chip-neutral"
                  }`}
                >
                  {entry.riskLevel === "warn"
                    ? entry.enabled
                      ? "已开启（有风险）"
                      : "未开启（建议开启）"
                    : entry.enabled
                    ? "已开启自启"
                    : "未开启"}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* T-302：标准 496px 三段式脱敏遥测样本只读预览窗 */}
      {sampleOpen && (
        <div
          data-testid="telemetry-sample-modal"
          onClick={() => setSampleOpen(false)}
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
                    <span style={{ fontSize: 15.5, fontWeight: 600 }}>脱敏遥测数据结构示例</span>
                    <span className="guard-chip guard-chip-ok">只读零隐私</span>
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 2 }}>
                    所有邮箱、Token、机场订阅 URL、公网 IP 与完整 orgId 均已剥离
                  </div>
                </div>
              </div>
              <button
                type="button"
                aria-label="关闭弹窗"
                onClick={() => setSampleOpen(false)}
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
            <div style={{ padding: "0 20px 18px" }}>
              <pre
                className="font-mono-code"
                style={{
                  margin: 0,
                  background: "var(--bg-subtle)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--r-btn)",
                  padding: "10px 12px",
                  fontSize: 11.5,
                  color: "var(--text-2)",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  maxHeight: 280,
                  overflowY: "auto",
                  lineHeight: 1.55,
                }}
              >
                {sampleLoading ? "正在生成本机实时脱敏载荷示例..." : sampleJson}
              </pre>
            </div>
            <div
              style={{
                padding: "12px 20px",
                borderTop: "1px solid var(--border)",
                background: "rgba(128, 128, 140, 0.03)",
                display: "flex",
                justifyContent: "flex-end",
              }}
            >
              <button
                type="button"
                className="guard-btn guard-btn-primary guard-btn-sm"
                onClick={() => setSampleOpen(false)}
              >
                我知道了
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

const sectionHeaderStyle: React.CSSProperties = {
  fontSize: 14,
  fontWeight: 600,
  marginBottom: 10,
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
};
