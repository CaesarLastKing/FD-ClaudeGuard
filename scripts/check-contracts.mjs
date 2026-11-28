#!/usr/bin/env node
/**
 * FD Claude Guard 1 秒跨界静态契约防错检查脚本（替代低效高频全量单测，专杀跨端漂移与低级隐患）
 * 校验 9 大维度：
 * 1. Rust #[tauri::command] & 参数 <-> src/lib/ipc.ts invoke 1:1 对齐
 * 2. Rust app.emit(...) <-> 前端 listen(...) 双向对齐
 * 3. diag-worker/src/index.js SQL 列名 <-> diag-worker/schema.sql 表定义一致
 * 4. 全站 CSS var(--*) 变量均在 src/styles/theme.css 或组件内定义
 * 5. 版本真源多端一致 & 协议统一 GPL-3.0
 * 6. 活跃 UI/Rust 用户文案不含已废弃页面称谓，严禁死页面遗留或引用 archive/
 * 7. sk 云端核验防裸连红线（非本机回环地址禁止无代理发送 sessionKey）
 * 8. Gate 0 防错红线（非测试代码严禁对 clash-verge 执行 taskkill 强杀）
 * 9. 关键配置原子写盘（禁止固定 .json.tmp 或裸写 settings_path）与 PowerShell UTF-8 编码头
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];

function walk(dir, exts, out = []) {
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (["node_modules", "target", "dist", ".git"].includes(ent.name)) continue;
      walk(p, exts, out);
    } else if (exts.some((e) => ent.name.endsWith(e))) {
      out.push(p);
    }
  }
  return out;
}

const toCamel = (s) => s.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());
const rsFiles = walk(path.join(ROOT, "src-tauri/src"), [".rs"]);
const tsFiles = walk(path.join(ROOT, "src"), [".ts", ".tsx", ".css"]);

// 1. Command & 参数检查
const libRs = fs.readFileSync(path.join(ROOT, "src-tauri/src/lib.rs"), "utf8");
const ghMatch = libRs.match(/tauri::generate_handler!\s*\[([\s\S]*?)\]/);
const registeredCmds = ghMatch
  ? ghMatch[1]
      .split(",")
      .map((s) => s.replace(/\/\/.*$/gm, "").trim())
      .filter(Boolean)
  : [];

const cmdDefs = new Map();
const cmdRegex =
  /#\[tauri::command(?:\(([^)]*)\))?\]\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*\(([\s\S]*?)\)\s*(?:->|\{)/g;
for (const f of rsFiles) {
  const txt = fs.readFileSync(f, "utf8");
  let m;
  while ((m = cmdRegex.exec(txt))) {
    const renameAllSnake = /rename_all\s*=\s*"snake_case"/.test(m[1] || "");
    const params = [];
    let cur = "";
    let depth = 0;
    for (const ch of m[3]) {
      if (ch === "<" || ch === "(" || ch === "[" || ch === "{") depth++;
      else if (ch === ">" || ch === ")" || ch === "]" || ch === "}") depth--;
      if (ch === "," && depth === 0) {
        if (cur.trim()) params.push(cur.trim());
        cur = "";
      } else {
        cur += ch;
      }
    }
    if (cur.trim()) params.push(cur.trim());

    const expectedKeys = [];
    const optionalKeys = new Set();
    for (const p of params) {
      const pm = p.match(/^(?:mut\s+)?([A-Za-z0-9_]+)\s*:\s*([\s\S]+)$/);
      if (!pm) continue;
      if (/^(State<|AppHandle|tauri::AppHandle|Window|WebviewWindow|tauri::)/.test(pm[2].trim())) {
        continue;
      }
      const wire = renameAllSnake ? pm[1] : toCamel(pm[1]);
      expectedKeys.push(wire);
      if (/^Option</.test(pm[2].trim())) optionalKeys.add(wire);
    }
    cmdDefs.set(m[2], { expectedKeys, optionalKeys });
  }
}

const ipcTs = fs.readFileSync(path.join(ROOT, "src/lib/ipc.ts"), "utf8");
const invRegex = /invoke(?:<[^>]*>)?\(\s*"([A-Za-z0-9_]+)"\s*(?:,\s*\{([\s\S]*?)\}\s*)?\)/g;
let im;
const invokedCmds = new Set();
while ((im = invRegex.exec(ipcTs))) {
  const cmd = im[1];
  invokedCmds.add(cmd);
  if (!registeredCmds.includes(cmd)) {
    errors.push(`[Command] ipc.ts 调用了未注册的后端命令: ${cmd}`);
    continue;
  }
  const def = cmdDefs.get(cmd);
  if (!def) continue;
  const passedKeys = (im[2] || "")
    .split(",")
    .map((x) => x.trim().match(/^([A-Za-z0-9_]+)\s*(?::|$)/)?.[1])
    .filter(Boolean);
  for (const pk of passedKeys) {
    if (!def.expectedKeys.includes(pk)) {
      errors.push(`[Command] ${cmd} 传入了后端不存在的参数键 "${pk}" (期望: ${def.expectedKeys.join(", ")})`);
    }
  }
  for (const ek of def.expectedKeys) {
    if (!def.optionalKeys.has(ek) && !passedKeys.includes(ek)) {
      errors.push(`[Command] ${cmd} 缺少必填参数键 "${ek}"`);
    }
  }
}
for (const rc of registeredCmds) {
  if (!invokedCmds.has(rc)) errors.push(`[Command] 后端注册了前端未调用的孤儿命令: ${rc}`);
}

// 2. Event 双向对齐
const emitted = new Set();
const listened = new Set();
for (const f of rsFiles) {
  const txt = fs.readFileSync(f, "utf8");
  for (const m of txt.matchAll(/\.emit(?:_to)?\(\s*(?:[^,]+,\s*)?"(guard:\/\/[^"]+)"/g)) {
    emitted.add(m[1]);
  }
}
for (const f of tsFiles) {
  if (f.includes("__tests__") || f.includes("src/test/")) continue;
  const txt = fs.readFileSync(f, "utf8");
  for (const m of txt.matchAll(/listen(?:<[^>]*>)?\(\s*"(guard:\/\/[^"]+)"/g)) {
    listened.add(m[1]);
  }
}
for (const ev of emitted) {
  if (!listened.has(ev)) errors.push(`[Event] 后端发送了前端未监听的事件: ${ev}`);
}
for (const ev of listened) {
  if (!emitted.has(ev)) errors.push(`[Event] 前端监听了后端未发送的事件: ${ev}`);
}

// 3. diag-worker D1 SQL 列名 vs schema.sql
const schemaSql = fs.readFileSync(path.join(ROOT, "diag-worker/schema.sql"), "utf8");
const tableCols = new Map();
for (const tm of schemaSql.matchAll(/CREATE TABLE IF NOT EXISTS\s+([a-z_]+)\s*\(([\s\S]*?)\);/gi)) {
  const cols = tm[2]
    .split("\n")
    .map((l) => l.trim().replace(/--.*$/, ""))
    .filter((l) => l && !/^(PRIMARY|UNIQUE|CHECK|FOREIGN)/i.test(l))
    .map((l) => l.split(/\s+/)[0]);
  tableCols.set(tm[1], new Set(cols));
}
const workerJs = fs.readFileSync(path.join(ROOT, "diag-worker/src/index.js"), "utf8");
for (const qm of workerJs.matchAll(/SELECT\s+([\s\S]+?)\s+FROM\s+([a-z_]+)/gi)) {
  const cols = tableCols.get(qm[2]);
  if (!cols) {
    errors.push(`[Worker SQL] 引用了 schema.sql 不存在的表: ${qm[2]}`);
    continue;
  }
  for (const selCol of qm[1].split(",").map((s) => s.trim())) {
    if (!cols.has(selCol)) {
      errors.push(`[Worker SQL] 表 ${qm[2]} 中不存在列 "${selCol}"`);
    }
  }
}

// 4. CSS 变量完整性
const definedVars = new Set();
const usedVars = [];
for (const f of tsFiles) {
  if (f.includes("__tests__") || f.includes("src/test/")) continue;
  const txt = fs.readFileSync(f, "utf8");
  for (const m of txt.matchAll(/(--[A-Za-z0-9_-]+)\s*:/g)) definedVars.add(m[1]);
  for (const m of txt.matchAll(/var\(\s*(--[A-Za-z0-9_-]+)\s*(?:,|\))/g)) {
    usedVars.push({ v: m[1], file: path.relative(ROOT, f) });
  }
}
for (const u of usedVars) {
  if (!definedVars.has(u.v)) errors.push(`[CSS] ${u.file} 使用了未定义的变量 ${u.v}`);
}

// 5. 版本真源 & GPL-3.0 协议一致性
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
const tauriConf = JSON.parse(fs.readFileSync(path.join(ROOT, "src-tauri/tauri.conf.json"), "utf8"));
const cargoToml = fs.readFileSync(path.join(ROOT, "src-tauri/Cargo.toml"), "utf8");
const cargoVer = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const cargoLic = cargoToml.match(/^license\s*=\s*"([^"]+)"/m)?.[1];
if (pkg.version !== tauriConf.version || pkg.version !== cargoVer) {
  errors.push(`[Version] 版本不一致: package=${pkg.version}, tauri=${tauriConf.version}, Cargo=${cargoVer}`);
}
if (pkg.license !== "GPL-3.0" || cargoLic !== "GPL-3.0") {
  errors.push(`[License] 协议非 GPL-3.0: package=${pkg.license}, Cargo=${cargoLic}`);
}
const settingsTsx = fs.readFileSync(path.join(ROOT, "src/components/SettingsModal.tsx"), "utf8");
if (settingsTsx.includes("MIT 开源") || !settingsTsx.includes("GPL-3.0 开源")) {
  errors.push(`[License] SettingsModal.tsx 开源标签未统一为 "GPL-3.0 开源"`);
}

// 6. 活跃 UI/后端文案废弃页面称谓、archive 引用与死页面检查
const activeTsSrcs = tsFiles.filter((f) => {
  const rel = path.relative(ROOT, f).replace(/\\/g, "/");
  return !rel.includes("__tests__") && !rel.startsWith("src/test/");
});
for (const f of [...rsFiles, ...activeTsSrcs]) {
  const rel = path.relative(ROOT, f).replace(/\\/g, "/");
  const raw = fs.readFileSync(f, "utf8");
  if (raw.includes("archive/")) {
    errors.push(`[ArchiveLeak] ${rel} 不应引用已归档目录 archive/`);
  }
  const lines = raw.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (/^\s*(\/\/|\/\*|\*|\/\/!|\/\/\/)/.test(ln)) continue;
    if (rel === "src/components/CleanConfirmModal.tsx" && ln.includes("清理恢复")) continue;
    if (/环境维护|日志分析|守卫配置/.test(ln)) {
      errors.push(`[StaleCopy] ${rel}:${i + 1} 仍包含已废弃页面称谓: ${ln.trim().slice(0, 80)}`);
    }
  }
}
const pageDir = path.join(ROOT, "src/pages");
for (const ent of fs.readdirSync(pageDir, { withFileTypes: true })) {
  if (!ent.isFile() || !ent.name.endsWith(".tsx")) continue;
  const pageName = ent.name.replace(/\.tsx$/, "");
  const pageRel = `src/pages/${ent.name}`;
  const usedElsewhere = activeTsSrcs.some((f) => {
    const rel = path.relative(ROOT, f).replace(/\\/g, "/");
    if (rel === pageRel) return false;
    return fs.readFileSync(f, "utf8").includes(pageName);
  });
  if (!usedElsewhere) {
    errors.push(`[DeadPage] ${pageRel} 未在任何活跃前端源码中被引用，请清理或归档`);
  }
}

// Helper: 截取 Rust 文件非测试代码段（#[cfg(test)] 之前）
const stripRustTests = (txt) => txt.split(/#\[\s*cfg\s*\(\s*test\s*\)\s*\]/)[0];

// 7. sk 云端核验防裸连红线
const cloudProbeRs = stripRustTests(
  fs.readFileSync(path.join(ROOT, "src-tauri/src/account_audit/cloud_probe.rs"), "utf8")
);
const accountAuditRs = stripRustTests(
  fs.readFileSync(path.join(ROOT, "src-tauri/src/account_audit/mod.rs"), "utf8")
);
if (!cloudProbeRs.includes("is_loopback_base_url") || !cloudProbeRs.includes("validated_proxy.is_none()")) {
  errors.push(`[AntiNakedSk] cloud_probe.rs 缺失 is_loopback_base_url 或 validated_proxy.is_none() 裸连拦截`);
}
if (!/run_desktop_cloud_verify[\s\S]*?if\s+proxy_url\.is_none\(\)/.test(accountAuditRs)) {
  errors.push(`[AntiNakedSk] account_audit/mod.rs 的 run_desktop_cloud_verify 缺失 proxy_url.is_none() 拦截`);
}

// 8. Gate 0 红线：非测试源码严禁强杀 clash-verge
for (const f of rsFiles) {
  const rel = path.relative(ROOT, f).replace(/\\/g, "/");
  const lines = stripRustTests(fs.readFileSync(f, "utf8")).split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!/taskkill/i.test(lines[i])) continue;
    const win = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 4)).join("\n");
    if (/clash-verge/i.test(win)) {
      errors.push(`[NoTaskkillClash] ${rel}:${i + 1} 违规出现强杀 clash-verge 的 taskkill 调用`);
    }
  }
}

// 9. 关键配置原子写与 PowerShell UTF-8 编码防回潮
const atomicCheckedFiles = [
  "src-tauri/src/account_audit/mod.rs",
  "src-tauri/src/maintenance/mod.rs",
  "src-tauri/src/updater/mod.rs",
  "src-tauri/src/mihomo/mod.rs",
  "src-tauri/src/config/mod.rs",
];
for (const rel of atomicCheckedFiles) {
  const prod = stripRustTests(fs.readFileSync(path.join(ROOT, rel), "utf8"));
  if (/\.with_extension\(\s*"json\.tmp"\s*\)/.test(prod)) {
    errors.push(`[AtomicWrite] ${rel} 仍使用固定 .with_extension("json.tmp")，请改为带 pid/seq 唯一临时文件`);
  }
  if (/fs::write\(\s*&settings_path\s*,/.test(prod)) {
    errors.push(`[AtomicWrite] ${rel} 对 settings_path 使用了裸 fs::write，请改用原子替换`);
  }
}
const rollbackRs = stripRustTests(
  fs.readFileSync(path.join(ROOT, "src-tauri/src/rollback/mod.rs"), "utf8")
);
for (const fnName of [
  "run_ps_elevated_checked",
  "detect_loopback_dns_physical_adapters",
  "capture_ipv6_baseline_if_needed",
]) {
  const m = rollbackRs.match(new RegExp(`pub\\s+fn\\s+${fnName}[\\s\\S]{0,1200}?OutputEncoding\\s*=\\s*\\[System\\.Text\\.Encoding\\]::UTF8`));
  if (!m) {
    errors.push(`[WinUtf8] rollback/mod.rs 中的 ${fnName} 缺失 PowerShell UTF-8 输出编码头`);
  }
}

if (errors.length > 0) {
  console.error("❌ 跨界静态契约检查未通过:\n" + errors.map((e) => `  - ${e}`).join("\n"));
  process.exit(1);
}

console.log(
  `✅ 静态契约检查通过 (9 维门禁全绿 | ${registeredCmds.length} commands, ${emitted.size} events, ${definedVars.size} CSS vars, v${pkg.version}, ${pkg.license})`
);
