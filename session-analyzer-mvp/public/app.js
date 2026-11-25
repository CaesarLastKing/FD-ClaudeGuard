/**
 * FD Claude 账户分析平台 MVP — 前端交互逻辑
 * 纯本地运行，调用同源 127.0.0.1 接口。
 */

const state = {
  demoMode: false,
  probing: false,
  abortController: null,
  probeResults: [],
  selectedProbeIdx: -1,
  activeRawTab: "organizations",
  accounts: [],
  selectedAccountFp: null,
  analytics: null,
};

const $ = (id) => document.getElementById(id);

function escapeHtml(val) {
  return String(val ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function showToast(msg) {
  const el = $("toastEl");
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => {
    el.hidden = true;
  }, 2600);
}

function statusChipHtml(status) {
  if (status === "alive") return `<span class="chip ch-neutral">正常存活</span>`;
  if (status === "alive-but-restricted") return `<span class="chip ch-warn">存活 · 受限</span>`;
  if (status === "invalid") return `<span class="chip ch-fail">失效 (403)</span>`;
  return `<span class="chip ch-fail">错误 / 拦截</span>`;
}

function formatTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("zh-CN", { hour12: false });
}

/* ======================== 初始化与配置 ======================== */

async function loadConfig() {
  try {
    const res = await fetch("/api/config");
    const data = await res.json();
    $("bindInfoText").textContent = `${data.bindHost}:${data.port} 仅本机 · 零明文落盘 · 上限 ${data.maxBatch}/批`;
    const bar = $("detectedProxiesBar");
    const dot = $("proxyStatusDot");
    const statusText = $("proxyStatusText");

    if (Array.isArray(data.detectedProxies) && data.detectedProxies.length > 0) {
      dot.className = "dot dot-ok";
      statusText.textContent = `已发现 ${data.detectedProxies[0].label}`;
      bar.innerHTML =
        `<span class="muted">本机活跃代理：</span>` +
        data.detectedProxies
          .map(
            (p) =>
              `<button class="proxy-pill" type="button" data-proxy="${escapeHtml(p.url)}">${escapeHtml(p.label)}</button>`
          )
          .join("");
      // 若代理框为空，自动填入首个发现的本机代理端口，减少配置成本
      if (!$("proxyInput").value.trim()) {
        $("proxyInput").value = data.detectedProxies[0].url;
      }
      bar.querySelectorAll(".proxy-pill").forEach((btn) => {
        btn.addEventListener("click", () => {
          $("proxyInput").value = btn.dataset.proxy || "";
          showToast(`已填入本机代理 ${btn.dataset.proxy}`);
        });
      });
    } else {
      dot.className = "dot dot-warn";
      statusText.textContent = "未发现常见本地端口 (直连)";
      bar.innerHTML = `<span class="muted">未检测到 7890/7897 等本地端口，可手动填写或留空直连</span>`;
    }
  } catch (err) {
    showToast(`读取本地服务配置失败: ${err.message}`);
  }
}

/* ======================== 导航与主题切换 ======================== */

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.id === `tab-${tab}`));
    if (tab === "timeline") loadAccounts();
    if (tab === "analytics") loadAnalytics();
  });
});

$("themeToggleBtn").addEventListener("click", () => {
  const html = document.documentElement;
  const next = html.getAttribute("data-theme") === "dark" ? "light" : "dark";
  html.setAttribute("data-theme", next);
  $("themeToggleBtn").textContent = next === "dark" ? "切换浅色" : "切换深色";
});

$("demoModeToggle").addEventListener("change", async (e) => {
  state.demoMode = e.target.checked;
  if (state.demoMode) {
    showToast("已开启演示样例模式（内存隔离，不写入本地数据库）");
    await loadAccounts();
    state.probeResults = state.accounts.map((a, idx) => ({
      ...a.latest,
      index: idx,
      keyFingerprint: a.keyFingerprint,
      keyMask: a.keyMask,
      email: a.emailMasked,
      emailMasked: a.emailMasked,
      rawPayloads: {
        organizations: a.latest.org,
        account: { email_address: a.emailMasked, created_at: a.latest.createdAt },
        usage: a.latest.usage,
        portal: { hold_notice: a.latest.portalKyc?.hasHoldNotice ? { reason: "identity_hold" } : null },
      },
    }));
    state.selectedProbeIdx = state.probeResults.length > 0 ? 0 : -1;
    renderProbeTable();
    renderProbeDetail();
    await loadAnalytics();
  } else {
    showToast("已切回真实本地数据");
    state.probeResults = [];
    state.selectedProbeIdx = -1;
    renderProbeTable();
    renderProbeDetail();
    await loadAccounts();
    await loadAnalytics();
  }
});

/* ======================== 实时探测台 ======================== */

let parseTimer = null;
$("sessionInput").addEventListener("input", () => {
  clearTimeout(parseTimer);
  parseTimer = setTimeout(async () => {
    const text = $("sessionInput").value;
    if (!text.trim()) {
      $("parseMetaText").textContent = "已识别 0 条";
      return;
    }
    try {
      const res = await fetch("/api/parse-preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      const data = await res.json();
      const dupText = data.duplicateCount > 0 ? ` · 去重 ${data.duplicateCount}` : "";
      const unrecText = data.unrecognizedLines > 0 ? ` · 忽略 ${data.unrecognizedLines} 行` : "";
      $("parseMetaText").textContent = `已识别 ${data.count} 条${dupText}${unrecText}`;
    } catch {
      $("parseMetaText").textContent = "解析失败";
    }
  }, 180);
});

$("clearInputBtn").addEventListener("click", () => {
  $("sessionInput").value = "";
  $("parseMetaText").textContent = "已识别 0 条";
});

$("startProbeBtn").addEventListener("click", async () => {
  const text = $("sessionInput").value.trim();
  if (!text) {
    showToast("请先粘贴至少一条 sk-ant-sid... sessionKey");
    return;
  }

  // 如果处于演示模式，先自动关闭演示模式切回真实探测
  if (state.demoMode) {
    state.demoMode = false;
    $("demoModeToggle").checked = false;
  }

  state.probing = true;
  state.probeResults = [];
  state.selectedProbeIdx = -1;
  state.abortController = new AbortController();

  $("startProbeBtn").disabled = true;
  $("stopProbeBtn").hidden = false;
  $("probeProgressText").textContent = "正在连接…";
  renderProbeTable();
  renderProbeDetail();

  try {
    const resp = await fetch("/api/probe-stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text,
        transport: $("transportSelect").value,
        proxyUrl: $("proxyInput").value.trim(),
        baseUrl: $("baseUrlInput").value.trim() || "https://claude.ai",
        delayBetweenMs: Number($("delayInput").value || 600),
        includeOptionalProbes: $("optProbesCheck").checked,
        saveSnapshot: $("saveSnapshotCheck").checked,
        maskEmailInResult: $("maskEmailCheck").checked,
      }),
      signal: state.abortController.signal,
    });

    if (!resp.ok) {
      const errObj = await resp.json().catch(() => ({}));
      showToast(errObj.error || `探测请求失败 (HTTP ${resp.status})`);
      return;
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let nlIdx;
      while ((nlIdx = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nlIdx).trim();
        buffer = buffer.slice(nlIdx + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        if (msg.type === "result") {
          state.probeResults.push(msg.data);
          if (state.selectedProbeIdx === -1) state.selectedProbeIdx = 0;
          renderProbeTable();
          renderProbeDetail();
        } else if (msg.type === "progress") {
          $("probeProgressText").textContent = `进度 ${msg.tested} / ${msg.total}`;
        } else if (msg.type === "done") {
          $("probeProgressText").textContent = `完成 · 共 ${msg.summary.total} 条`;
          showToast(`探测完成：存活 ${msg.summary.alive} · 受限 ${msg.summary.restricted} · 失效 ${msg.summary.invalid}`);
        }
      }
    }
    await loadAccounts();
  } catch (err) {
    if (err.name === "AbortError") {
      $("probeProgressText").textContent = "已手动停止";
      showToast("已停止探测");
    } else {
      showToast(`探测出错: ${err.message}`);
    }
  } finally {
    state.probing = false;
    state.abortController = null;
    $("startProbeBtn").disabled = false;
    $("stopProbeBtn").hidden = true;
  }
});

$("stopProbeBtn").addEventListener("click", () => {
  if (state.abortController) {
    state.abortController.abort();
  }
});

function renderProbeTable() {
  const rows = state.probeResults;
  let alive = 0;
  let restricted = 0;
  let invalid = 0;
  let error = 0;
  for (const r of rows) {
    if (r.status === "alive") alive += 1;
    else if (r.status === "alive-but-restricted") restricted += 1;
    else if (r.status === "invalid") invalid += 1;
    else error += 1;
  }
  $("statTotal").textContent = String(rows.length);
  $("statAlive").textContent = String(alive);
  $("statRestricted").textContent = String(restricted);
  $("statInvalid").textContent = String(invalid);
  $("statError").textContent = String(error);

  const tbody = $("probeTableBody");
  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">输入 sessionKey 点击右上角「开始只读探测」，或开启右上角「演示样例」预览完整能力。</td></tr>`;
    return;
  }

  tbody.innerHTML = rows
    .map((r, idx) => {
      const kycLabel =
        r.portalKyc?.state === "required"
          ? `<span class="chip ch-warn">Portal 受限</span>`
          : r.kyc?.clear === false
            ? `<span class="chip ch-warn">${escapeHtml(r.kyc.label)}</span>`
            : r.kyc?.clear === true
              ? `<span class="chip ch-neutral">${escapeHtml(r.kyc.label)}</span>`
              : `<span class="muted">未知</span>`;
      const ageText = r.accountAgeDays !== null && r.accountAgeDays !== undefined ? `${r.accountAgeDays} 天` : "—";
      return `
        <tr data-idx="${idx}" class="${idx === state.selectedProbeIdx ? "selected" : ""}">
          <td class="tabular muted">${idx + 1}</td>
          <td>${statusChipHtml(r.status)}</td>
          <td>
            <div>${escapeHtml(r.email || r.emailMasked || "—")}</div>
            <div class="mono muted" style="font-size:11px">${escapeHtml(r.keyMask)}</div>
          </td>
          <td><span class="chip ch-neutral">${escapeHtml(r.planLabel || "—")}</span></td>
          <td>${kycLabel}</td>
          <td class="tabular">${ageText}</td>
          <td class="tabular muted">${r.latencyMs ?? 0} ms</td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll("tr[data-idx]").forEach((tr) => {
    tr.addEventListener("click", () => {
      state.selectedProbeIdx = Number(tr.dataset.idx);
      renderProbeTable();
      renderProbeDetail();
    });
  });
}

function renderUsageSection(usage) {
  if (!usage) {
    return `<div class="muted">该账号未返回用量窗口数据（可能接口 404/不可用或账号已失效）</div>`;
  }
  const bars = [
    { label: "5 小时滚动窗口", pct: usage.fiveHourPct, reset: usage.fiveHourResetAt },
    { label: "7 天总用量窗口", pct: usage.sevenDayPct, reset: usage.sevenDayResetAt },
    { label: "7 天 Opus 窗口", pct: usage.sevenDayOpusPct, reset: null },
  ].filter((b) => b.pct !== null && b.pct !== undefined);

  if (bars.length === 0) {
    return `<div class="muted">用量响应中未包含具体百分比字段</div>`;
  }

  return `<div class="usage-bars">
    ${bars
      .map((b) => {
        const val = Math.max(0, Math.min(100, Number(b.pct) || 0));
        const cls = val >= 90 ? "danger" : val >= 75 ? "warn" : "";
        return `
          <div class="bar-row">
            <div class="bar-meta tabular">
              <span>${escapeHtml(b.label)}${b.reset ? ` · 重置 ${escapeHtml(formatTime(b.reset))}` : ""}</span>
              <strong>${val}%</strong>
            </div>
            <div class="bar-track"><div class="bar-fill ${cls}" style="width:${val}%"></div></div>
          </div>
        `;
      })
      .join("")}
  </div>`;
}

function renderProbeDetail() {
  const container = $("probeDetailBody");
  const copyBtn = $("copySanitizedBundleBtn");
  const item = state.probeResults[state.selectedProbeIdx];

  if (!item) {
    copyBtn.disabled = true;
    container.innerHTML = `<div class="empty-detail">点击左侧任意一条探测记录，查看 6 维端点矩阵、用量窗口、双路 KYC 状态、风险评估与完整脱敏原始 JSON。</div>`;
    return;
  }

  copyBtn.disabled = false;
  const alertCls =
    item.status === "alive" ? "alert-ok" : item.status === "alive-but-restricted" ? "alert-warn" : "alert-danger";

  const rawTabs = Object.keys(item.rawPayloads || {});
  if (!rawTabs.includes(state.activeRawTab)) {
    state.activeRawTab = rawTabs[0] || "organizations";
  }

  const endpointsHtml = (item.endpoints || [])
    .map((ep) => {
      let badge = `<span class="chip ch-neutral">跳过</span>`;
      if (!ep.skipped) {
        if (ep.cfBlocked) badge = `<span class="chip ch-fail">CF 拦截</span>`;
        else if (ep.expectedForPlan && ep.note) badge = `<span class="chip ch-neutral">${escapeHtml(ep.note)}</span>`;
        else if (ep.reasonCode === "non_json_html") badge = `<span class="chip ch-neutral">非 JSON</span>`;
        else if (ep.ok) badge = `<span class="chip ch-ok">HTTP ${ep.statusCode}</span>`;
        else badge = `<span class="chip ch-warn">HTTP ${ep.statusCode || 0}</span>`;
      }
      return `
        <div class="endpoint-row">
          <div>
            <div class="endpoint-name">${escapeHtml(ep.name)}</div>
            <div class="endpoint-path mono">${escapeHtml(ep.path)}</div>
          </div>
          <div style="display:flex;align-items:center;gap:8px">
            <span class="muted tabular">${ep.latencyMs || 0} ms</span>
            ${badge}
          </div>
        </div>
      `;
    })
    .join("");

  const adviceHtml =
    Array.isArray(item.antiBanAdvice) && item.antiBanAdvice.length > 0
      ? `<div>
          <div class="section-hd">防封画像诊断与行动建议</div>
          <div class="endpoint-list">
            ${item.antiBanAdvice
              .map((a) => {
                const chipCls =
                  a.level === "danger" ? "ch-fail" : a.level === "warn" ? "ch-warn" : a.level === "ok" ? "ch-ok" : "ch-neutral";
                const tag = a.level === "danger" ? "高危" : a.level === "warn" ? "注意" : a.level === "ok" ? "良好" : "提示";
                return `
                  <div class="timeline-item">
                    <div class="timeline-item-hd">
                      <strong>${escapeHtml(a.title)}</strong>
                      <span class="chip ${chipCls}">${tag}</span>
                    </div>
                    <div class="muted" style="font-size:12px">${escapeHtml(a.detail)}</div>
                  </div>
                `;
              })
              .join("")}
          </div>
        </div>`
      : "";

  const geoCompareText = item.workspaceGeo
    ? `归属 ${String(item.workspaceGeo).toUpperCase()}${item.cfEdge?.colo ? ` · 本次边缘 ${item.cfEdge.colo}${item.cfEdge.country ? ` (${item.cfEdge.country.toUpperCase()})` : ""}` : ""}`
    : item.cfEdge?.colo
      ? `本次边缘 ${item.cfEdge.colo}`
      : "—";

  const modelText = item.modelSummary
    ? `${item.modelSummary.activeCount} 个活跃模型 · 上限 ${item.modelSummary.maxHardLimit ? `${Math.round(item.modelSummary.maxHardLimit / 1000)}K` : "—"}`
    : "—";

  container.innerHTML = `
    <div class="alert-banner ${alertCls}">
      <strong>体检结论：</strong>${escapeHtml(item.reasonText || "—")}
    </div>

    ${adviceHtml}

    <div>
      <div class="section-hd">高价值防封画像与套餐</div>
      <div class="kv-grid">
        <div class="kv-box"><div class="kv-k">邮箱</div><div class="kv-v">${escapeHtml(item.email || item.emailMasked || "—")}</div></div>
        <div class="kv-box"><div class="kv-k">套餐 / 限流分级</div><div class="kv-v">${escapeHtml(item.planLabel)} ${item.planTier ? `(${escapeHtml(item.planTier)})` : ""}${item.analyticsPlan ? ` · ${escapeHtml(item.analyticsPlan)}` : ""}</div></div>
        <div class="kv-box"><div class="kv-k">归属地 vs 本次出口边缘</div><div class="kv-v">${escapeHtml(geoCompareText)}</div></div>
        <div class="kv-box"><div class="kv-k">主组织年龄 / 账号总年龄</div><div class="kv-v tabular">主组织 ${item.orgAgeDays ?? item.accountAgeDays ?? "—"} 天${item.accountTotalAgeDays !== null && item.accountTotalAgeDays !== undefined && item.accountTotalAgeDays !== item.orgAgeDays ? ` · 账号 ${item.accountTotalAgeDays} 天` : ""}</div></div>
        <div class="kv-box"><div class="kv-k">计费类型 / 收款商户 / 免费额度</div><div class="kv-v">${escapeHtml(item.billingType || "—")} / ${escapeHtml(item.merchantOfRecord || "—")}${item.freeCreditsStatus ? ` · 免费额:${escapeHtml(item.freeCreditsStatus)}` : ""}</div></div>
        <div class="kv-box"><div class="kv-k">下发模型与上下文硬上限</div><div class="kv-v tabular">${escapeHtml(modelText)}</div></div>
        <div class="kv-box"><div class="kv-k">主组织 / 组织总数</div><div class="kv-v">${escapeHtml(item.org?.name || "—")} (共 ${item.orgCount || 0} 个)</div></div>
        <div class="kv-box"><div class="kv-k">能力标签 (capabilities)</div><div class="kv-v mono" style="font-size:11.5px">${escapeHtml((item.capabilities || []).join(", ") || "—")}</div></div>
      </div>
    </div>

    ${
      Array.isArray(item.allOrgs) && item.allOrgs.length > 1
        ? `<div>
            <div class="section-hd">关联多组织透视（共 ${item.allOrgs.length} 个）</div>
            <div class="endpoint-list">
              ${item.allOrgs
                .map(
                  (o) => `
                <div class="endpoint-row">
                  <div>
                    <div class="endpoint-name">${escapeHtml(o.name || "未命名组织")}</div>
                    <div class="endpoint-path mono">${escapeHtml((o.capabilities || []).join(", ") || "—")}</div>
                  </div>
                  <div>
                    <span class="chip ${o.apiDisabledReason ? "ch-warn" : "ch-neutral"}">${escapeHtml(o.apiDisabledReason ? `禁用: ${o.apiDisabledReason}` : o.planLabel || "正常")}</span>
                  </div>
                </div>`
                )
                .join("")}
            </div>
          </div>`
        : ""
    }

    <div>
      <div class="section-hd">双路 KYC、验证与组织风控标记</div>
      <div class="kv-grid">
        <div class="kv-box"><div class="kv-k">订阅 KYC 状态</div><div class="kv-v">${escapeHtml(item.kyc?.label || "未知")}${item.kyc?.hasInquiryLink ? " · 含 Persona 链接" : ""}</div></div>
        <div class="kv-box"><div class="kv-k">Portal KYC / hold_notice</div><div class="kv-v">${escapeHtml(item.portalKyc?.label || "未知")}</div></div>
        <div class="kv-box"><div class="kv-k">账号验证态（邮箱 / 年龄 / 手机）</div><div class="kv-v">${item.accountMeta ? `邮箱:${item.accountMeta.isVerified ? "已验" : "未验"} · 年龄:${item.accountMeta.ageIsVerified ? "已验" : "未验"} · 手机:${item.phoneVerified ? "已绑" : "未绑"}` : "—"}</div></div>
        <div class="kv-box"><div class="kv-k">原生风控槽位 (access/billing/monitor)</div><div class="kv-v">${item.org?.accessBlock || item.org?.billingIssue || item.org?.subscriptionPause || item.org?.monitoringNotice ? "存在异常标记" : "全 null（无异常）"}</div></div>
        <div class="kv-box"><div class="kv-k">API 禁用原因 / 截止</div><div class="kv-v">${escapeHtml(item.org?.apiDisabledReason || "无")} ${item.org?.apiDisabledUntil ? `/ ${escapeHtml(item.org.apiDisabledUntil)}` : ""}</div></div>
        <div class="kv-box"><div class="kv-k">计费暂停 / 活跃标记</div><div class="kv-v">${escapeHtml(item.org?.billableUsagePausedUntil || "无")} · Flags: ${escapeHtml((item.org?.activeFlags || []).length)}</div></div>
      </div>
    </div>

    <div>
      <div class="section-hd">实时用量窗口（高频满载预警）</div>
      ${renderUsageSection(item.usage)}
    </div>

    <div>
      <div class="section-hd">7 维只读端点探测矩阵</div>
      <div class="endpoint-list">${endpointsHtml}</div>
    </div>

    <div>
      <div class="section-hd">脱敏原始 JSON（便于发掘新风控字段）</div>
      <div class="raw-tabs">
        ${rawTabs
          .map(
            (t) =>
              `<button class="raw-tab-btn ${t === state.activeRawTab ? "active" : ""}" data-raw-tab="${escapeHtml(t)}" type="button">${escapeHtml(t)}</button>`
          )
          .join("")}
      </div>
      <pre class="json-pre mono">${escapeHtml(JSON.stringify(item.rawPayloads?.[state.activeRawTab] ?? null, null, 2))}</pre>
    </div>
  `;

  container.querySelectorAll(".raw-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.activeRawTab = btn.dataset.rawTab;
      renderProbeDetail();
    });
  });
}

$("copySanitizedBundleBtn").addEventListener("click", async () => {
  const item = state.probeResults[state.selectedProbeIdx];
  if (!item) return;
  try {
    const res = await fetch("/api/export-sanitized", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ result: item }),
    });
    const data = await res.json();
    const jsonText = JSON.stringify(data.bundle, null, 2);
    await navigator.clipboard.writeText(jsonText);
    showToast("已复制强脱敏诊断包到剪贴板（已剔除 key、邮箱、姓名与 UUID）");
  } catch (err) {
    showToast(`导出失败: ${err.message}`);
  }
});

/* ======================== 账号时间线与标签 ======================== */

async function loadAccounts() {
  try {
    const res = await fetch(`/api/accounts${state.demoMode ? "?demo=1" : ""}`);
    const data = await res.json();
    state.accounts = data.accounts || [];
    const badge = $("navAccountCount");
    badge.textContent = String(state.accounts.length);
    badge.hidden = state.accounts.length === 0;
    $("timelineCountText").textContent = `${state.accounts.length} 个账号${state.demoMode ? " (演示)" : ""}`;

    if (state.accounts.length > 0 && !state.accounts.some((a) => a.keyFingerprint === state.selectedAccountFp)) {
      state.selectedAccountFp = state.accounts[0].keyFingerprint;
    } else if (state.accounts.length === 0) {
      state.selectedAccountFp = null;
    }

    renderTimelineTable();
    renderTimelineDetail();
  } catch (err) {
    showToast(`加载账号列表失败: ${err.message}`);
  }
}

function renderTimelineTable() {
  const tbody = $("timelineTableBody");
  if (state.accounts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-cell">暂无归档账号，执行一次探测或开启「演示样例」即可查看。</td></tr>`;
    return;
  }

  tbody.innerHTML = state.accounts
    .map((acc) => {
      const latest = acc.latest || {};
      const tagSummary = [acc.tags?.proxyType, acc.tags?.paymentChannel, acc.tags?.clientType]
        .filter(Boolean)
        .join(" · ");
      return `
        <tr data-fp="${escapeHtml(acc.keyFingerprint)}" class="${acc.keyFingerprint === state.selectedAccountFp ? "selected" : ""}">
          <td>
            <div>${escapeHtml(acc.emailMasked || "—")}</div>
            <div class="mono muted" style="font-size:11px">${escapeHtml(acc.keyMask)}</div>
          </td>
          <td>${statusChipHtml(latest.status)}</td>
          <td><span class="chip ch-neutral">${escapeHtml(latest.planLabel || "—")}</span></td>
          <td class="tabular">${(acc.history || []).length} 次</td>
          <td class="muted">${escapeHtml(tagSummary || "未标注")}</td>
        </tr>
      `;
    })
    .join("");

  tbody.querySelectorAll("tr[data-fp]").forEach((tr) => {
    tr.addEventListener("click", () => {
      state.selectedAccountFp = tr.dataset.fp;
      renderTimelineTable();
      renderTimelineDetail();
    });
  });
}

function renderTimelineDetail() {
  const container = $("timelineDetailBody");
  const delBtn = $("deleteAccountBtn");
  const acc = state.accounts.find((a) => a.keyFingerprint === state.selectedAccountFp);
  if (!acc) {
    delBtn.hidden = true;
    container.innerHTML = `<div class="empty-detail">选择左侧账号，查看完整状态变化 Diff 并维护环境归因标签。</div>`;
    return;
  }

  delBtn.hidden = state.demoMode;
  const tags = acc.tags || {};

  const historyHtml = (acc.history || [])
    .map((h) => {
      const diffsHtml =
        Array.isArray(h.diffs) && h.diffs.length > 0
          ? `<div class="diff-list">
              ${h.diffs
                .map(
                  (d) =>
                    `<div><span class="chip ch-warn">变更</span> <strong>${escapeHtml(d.label)}</strong>：<span class="muted">${escapeHtml(JSON.stringify(d.before))}</span> → <strong>${escapeHtml(JSON.stringify(d.after))}</strong></div>`
                )
                .join("")}
            </div>`
          : "";
      return `
        <div class="timeline-item">
          <div class="timeline-item-hd">
            <span class="tabular muted">${escapeHtml(formatTime(h.checkedAt))}</span>
            ${statusChipHtml(h.status)}
          </div>
          <div style="font-size:12px">${escapeHtml(h.reasonText || "—")}</div>
          <div class="muted tabular" style="font-size:11px">
            套餐: ${escapeHtml(h.planLabel || "—")} · HTTP ${h.statusCode ?? "—"} · KYC: ${escapeHtml(h.kycStatus || "未知")} · Portal: ${escapeHtml(h.portalState || "未知")}
          </div>
          ${diffsHtml}
        </div>
      `;
    })
    .join("");

  container.innerHTML = `
    <div>
      <div class="section-hd">环境归因标签${state.demoMode ? "（演示态只读）" : ""}</div>
      <form class="tag-form" id="accountTagForm">
        <label class="cfg-item">
          <span>常用地区 / 出口</span>
          <input class="ctrl" name="region" value="${escapeHtml(tags.region || "")}" placeholder="如 日本住宅 / 美西" ${state.demoMode ? "disabled" : ""} />
        </label>
        <label class="cfg-item">
          <span>代理节点类型</span>
          <input class="ctrl" name="proxyType" value="${escapeHtml(tags.proxyType || "")}" placeholder="如 固定 ISP 住宅 / 共享机房" ${state.demoMode ? "disabled" : ""} />
        </label>
        <label class="cfg-item">
          <span>支付渠道</span>
          <input class="ctrl" name="paymentChannel" value="${escapeHtml(tags.paymentChannel || "")}" placeholder="如 Apple 内购 / 虚拟卡 Stripe" ${state.demoMode ? "disabled" : ""} />
        </label>
        <label class="cfg-item">
          <span>主要客户端</span>
          <input class="ctrl" name="clientType" value="${escapeHtml(tags.clientType || "")}" placeholder="如 Desktop + CLI / Web" ${state.demoMode ? "disabled" : ""} />
        </label>
        <label class="cfg-item full-span">
          <span>观测备注</span>
          <input class="ctrl" name="notes" value="${escapeHtml(tags.notes || "")}" placeholder="记录操作变化、切节点事件等，便于后续归因" ${state.demoMode ? "disabled" : ""} />
        </label>
        ${state.demoMode ? "" : `<div class="full-span"><button class="btn btn-flat btn-sm" type="submit">保存归因标签</button></div>`}
      </form>
    </div>

    <div>
      <div class="section-hd">状态跃迁时间线（共 ${(acc.history || []).length} 次采样）</div>
      <div class="timeline-list">${historyHtml}</div>
    </div>
  `;

  const form = $("accountTagForm");
  if (form && !state.demoMode) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const fd = new FormData(form);
      const payload = Object.fromEntries(fd.entries());
      const res = await fetch(`/api/accounts/${encodeURIComponent(acc.keyFingerprint)}/tags`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        showToast("归因标签已保存");
        await loadAccounts();
      } else {
        showToast("保存失败");
      }
    });
  }
}

$("refreshTimelineBtn").addEventListener("click", loadAccounts);

$("deleteAccountBtn").addEventListener("click", async () => {
  if (!state.selectedAccountFp || state.demoMode) return;
  const res = await fetch(`/api/accounts/${encodeURIComponent(state.selectedAccountFp)}`, { method: "DELETE" });
  if (res.ok) {
    showToast("已删除该账号快照记录");
    await loadAccounts();
    await loadAnalytics();
  }
});

$("clearAllStorageBtn").addEventListener("click", async () => {
  if (state.demoMode) {
    showToast("当前为演示模式，未修改本地数据");
    return;
  }
  if (!confirm("确认清空本地保存的全部脱敏快照与归因标签吗？")) return;
  const res = await fetch("/api/accounts", { method: "DELETE" });
  if (res.ok) {
    showToast("已清空本地快照库");
    await loadAccounts();
    await loadAnalytics();
  }
});

/* ======================== 风控归因分析看板 ======================== */

async function loadAnalytics() {
  try {
    const res = await fetch(`/api/analytics${state.demoMode ? "?demo=1" : ""}`);
    const data = await res.json();
    state.analytics = data.analytics;
    renderAnalytics();
  } catch (err) {
    showToast(`加载归因统计失败: ${err.message}`);
  }
}

function renderBucketCard(title, items) {
  if (!items || items.length === 0) {
    return `<div class="card"><div class="card-hd"><span class="card-title">${escapeHtml(title)}</span></div><div class="empty-detail">暂无样本</div></div>`;
  }
  return `
    <div class="card">
      <div class="card-hd"><span class="card-title">${escapeHtml(title)}</span><span class="muted">受限/失效率</span></div>
      <div class="bucket-list">
        ${items
          .map((item) => {
            const okW = Math.round((item.alive / item.total) * 100);
            const warnW = Math.round((item.restricted / item.total) * 100);
            const failW = Math.round((item.invalid / item.total) * 100);
            const rateCls = item.riskRate >= 50 ? "ch-fail" : item.riskRate > 0 ? "ch-warn" : "ch-neutral";
            return `
              <div class="bucket-row">
                <div class="bucket-hd">
                  <span>${escapeHtml(item.label)} <span class="muted tabular">(${item.total})</span></span>
                  <span class="chip ${rateCls} tabular">风险率 ${item.riskRate}%</span>
                </div>
                <div class="bucket-bar" title="存活 ${item.alive} / 受限 ${item.restricted} / 失效 ${item.invalid}">
                  <div class="seg-ok" style="width:${okW}%"></div>
                  <div class="seg-warn" style="width:${warnW}%"></div>
                  <div class="seg-danger" style="width:${failW}%"></div>
                </div>
              </div>
            `;
          })
          .join("")}
      </div>
    </div>
  `;
}

function renderAnalytics() {
  const body = $("analyticsBody");
  const a = state.analytics;
  if (!a || a.totals.total === 0) {
    body.innerHTML = `<div class="card"><div class="empty-detail">本地尚未积累分析样本。请先执行探测或开启右上角「演示样例」预览归因分析效果。</div></div>`;
    return;
  }

  const reasonsHtml =
    a.topReasons.length > 0
      ? a.topReasons
          .map(
            (r) => `
          <div class="endpoint-row">
            <span>${escapeHtml(r.reason)}</span>
            <span class="chip ch-warn tabular">${r.count} 次</span>
          </div>
        `
          )
          .join("")
      : `<div class="muted">当前样本中暂无受限或失效记录</div>`;

  body.innerHTML = `
    <div class="stats-row">
      <div class="stat-card"><span class="stat-label">样本账号总数</span><span class="stat-val tabular">${a.totals.total}</span></div>
      <div class="stat-card"><span class="stat-label">正常存活</span><span class="stat-val tabular val-ok">${a.totals.alive}</span></div>
      <div class="stat-card"><span class="stat-label">存活 · 受限</span><span class="stat-val tabular val-warn">${a.totals.restricted}</span></div>
      <div class="stat-card"><span class="stat-label">失效 (403)</span><span class="stat-val tabular val-danger">${a.totals.invalid}</span></div>
      <div class="stat-card"><span class="stat-label">网络 / 拦截错误</span><span class="stat-val tabular">${a.totals.error}</span></div>
    </div>

    <div class="analytics-grid">
      ${renderBucketCard("按收款商户 / 计费渠道归因", a.byMerchant)}
      ${renderBucketCard("按账号年龄段归因", a.byAge)}
      ${renderBucketCard("按代理节点类型归因（需打标）", a.byProxyType)}
      ${renderBucketCard("按客户端类型归因（需打标）", a.byClientType)}
      ${renderBucketCard("按套餐等级归因", a.byPlan)}
      <div class="card">
        <div class="card-hd"><span class="card-title">高频受限 / 封禁信号 Top</span></div>
        <div class="bucket-list">${reasonsHtml}</div>
      </div>
    </div>
  `;
}

$("refreshAnalyticsBtn").addEventListener("click", loadAnalytics);

/* 启动加载 */
loadConfig();
loadAccounts();
loadAnalytics();
