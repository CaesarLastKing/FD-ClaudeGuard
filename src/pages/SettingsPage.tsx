import { useEffect, useRef } from "react";
import { Bell, CheckCircle2, Download, ExternalLink, Loader2, RefreshCw } from "lucide-react";
import { CheckIcon } from "@/components/CheckIcon";
import { ipc } from "@/lib/ipc";
import { useGuardStore } from "@/stores/guardStore";
import type { AppConfig } from "@/types/guard";

const GITHUB_OFFICIAL_URL = "https://github.com/CaesarLastKing/FD-ClaudeGuard";
const GITHUB_RELEASES_URL = "https://github.com/CaesarLastKing/FD-ClaudeGuard/releases";

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
  | "lockCfAndStripeToClaude";

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
  const config: AppConfig = useGuardStore((s) => s.config);
  const startupAudit = useGuardStore((s) => s.startupAudit);
  const updateConfig = useGuardStore((s) => s.updateConfig);
  const pushToast = useGuardStore((s) => s.pushToast);
  const updateInfo = useGuardStore((s) => s.updateInfo);
  const updateChecking = useGuardStore((s) => s.updateChecking);
  const updateInstalling = useGuardStore((s) => s.updateInstalling);
  const updateProgress = useGuardStore((s) => s.updateProgress);
  const updateError = useGuardStore((s) => s.updateError);
  const checkForAppUpdate = useGuardStore((s) => s.checkForAppUpdate);
  const installAppUpdate = useGuardStore((s) => s.installAppUpdate);

  const autoUpdateCheckedRef = useRef(false);

  useEffect(() => {
    if (autoUpdateCheckedRef.current) return;
    if (!updateInfo && !updateChecking && !updateError) {
      autoUpdateCheckedRef.current = true;
      void checkForAppUpdate(true);
    }
  }, [updateInfo, updateChecking, updateError, checkForAppUpdate]);

  const handleToggle = (key: BoolConfigKey, next: boolean, label: string) => {
    void updateConfig({ [key]: next }, label);
  };

  const handleCheckUpdate = async () => {
    await checkForAppUpdate(false);
  };

  const handleInstallUpdate = async () => {
    await installAppUpdate();
  };

  const handleOpenExternal = async (url: string) => {
    try {
      await ipc.openExternalUrl(url);
    } catch (err) {
      pushToast("打开外部链接失败", String(err), "danger");
    }
  };

  const installBtnText = !updateInstalling
    ? `立即更新 v${updateInfo?.latestVersion ?? ""}`
    : updateProgress?.stage === "verifying"
    ? "正在校验签名..."
    : updateProgress?.percent != null
    ? `下载中 ${updateProgress.percent}%`
    : "正在下载更新包...";

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
        {/* 客户端版本与自动更新卡片：状态文案（徽章）与单一检测/更新按钮严格分离 */}
        <div
          className="guard-card"
          data-testid="app-updater-card"
          style={{
            padding: "14px 16px",
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
                    v{updateInfo?.currentVersion ?? __APP_VERSION__}
                  </span>
                  {updateInfo?.available && updateInfo.latestVersion ? (
                    <span className="guard-chip guard-chip-ok tabular" data-testid="updater-status-badge">
                      发现新版本 v{updateInfo.latestVersion}
                    </span>
                  ) : updateError ? (
                    <span className="guard-chip guard-chip-warn" data-testid="updater-status-badge">
                      检查失败
                    </span>
                  ) : updateInfo ? (
                    <span
                      className="guard-chip guard-chip-ok"
                      data-testid="updater-status-badge"
                      style={{ display: "inline-flex", alignItems: "center", gap: 4 }}
                    >
                      <CheckCircle2 size={12} strokeWidth={2} />
                      <span>已是最新版本</span>
                    </span>
                  ) : null}
                </div>
                <div style={{ fontSize: 12, color: "var(--text-2)", marginTop: 3, lineHeight: 1.48 }}>
                  {updateError ? (
                    <>
                      <span>{updateError}</span>{" "}
                      <button
                        type="button"
                        className="guard-text-link"
                        onClick={() => void handleOpenExternal(GITHUB_RELEASES_URL)}
                      >
                        前往 Releases 手动下载 ↗
                      </button>
                    </>
                  ) : (
                    "GitHub Releases 官方签名通道（Ed25519 验签），优先走本机代理。"
                  )}
                </div>
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0, flexWrap: "wrap" }}>
              {updateInfo?.available ? (
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
                  <span className="tabular">{installBtnText}</span>
                </button>
              ) : (
                <button
                  type="button"
                  data-testid="btn-check-app-update"
                  disabled={updateChecking || updateInstalling}
                  className="guard-btn guard-btn-flat guard-btn-sm"
                  onClick={() => void handleCheckUpdate()}
                  style={{ whiteSpace: "nowrap" }}
                >
                  {updateChecking ? (
                    <Loader2 size={13.5} className="guard-spin" />
                  ) : (
                    <RefreshCw size={13.5} strokeWidth={1.85} />
                  )}
                  <span>{updateChecking ? "检查中..." : "检查更新"}</span>
                </button>
              )}

              <button
                type="button"
                data-testid="btn-open-github-official"
                className="guard-btn guard-btn-flat guard-btn-sm"
                onClick={() => void handleOpenExternal(GITHUB_OFFICIAL_URL)}
                title={`前往项目官方 GitHub 仓库：${GITHUB_OFFICIAL_URL}`}
                style={{ whiteSpace: "nowrap" }}
              >
                <ExternalLink size={13.5} strokeWidth={1.85} />
                <span>GitHub 官网</span>
              </button>
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
            <SwitchRow
              configKey="lockCfAndStripeToClaude"
              icon="group"
              title="同步锁定 Cloudflare 人机盾与 Stripe 支付至 Claude-Fixed"
              desc="防止 claude.ai 网页弹盾或升级付费时与主代理组发生跨节点双 IP 串线；切换后自动热同步分流规则。若同时在浏览器使用其他 Cloudflare 站点（如 ChatGPT），建议将主代理组与 Claude-Fixed 选在同一节点，或按需关闭此项"
              badge={{ text: "推荐开启", tone: "ok" }}
              checked={config.lockCfAndStripeToClaude ?? true}
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
