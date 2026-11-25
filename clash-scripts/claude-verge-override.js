/**
 * FD Claude Guard — Clash Verge Rev 全局扩展覆写脚本标准模板
 * 作用：
 * 1. 创建固定手动选择策略组 Claude-Fixed (type: select)，自动剔除禁区节点 (HK/MO/CN/RU 等高危/不支持地区)
 * 2. 严格分流隔离：仅将 Claude 全家桶域名、Claude.exe 进程与出口 IP 监测域名强制路由至 Claude-Fixed（不干扰其他软件/AGY 分流）
 * 3. REJECT 第三方纯遥测域名（第 3 层防回传），并关闭 Clash 内核 IPv6 防止代理隧道泄漏
 */

const BLOCKED_REGION_RE = /(香港|Hong\s*Kong|\bHK\b|澳门|澳門|Macau|\bMO\b|中国|中國|国内|China|\bCN\b|俄罗斯|俄羅斯|俄国|Russia|\bRU\b|白俄|\bBY\b|朝鲜|朝鮮|\bKP\b|伊朗|\bIR\b)/i;
const BLOCKED_EXCLUDE_FILTER = "(?i)(香港|Hong\\s*Kong|\\bHK\\b|澳门|澳門|Macau|\\bMO\\b|中国|中國|国内|China|\\bCN\\b|俄罗斯|俄羅斯|俄国|Russia|\\bRU\\b|白俄|\\bBY\\b|朝鲜|朝鮮|\\bKP\\b|伊朗|\\bIR\\b)";

const CLAUDE_RULES = [
  // 第 3 层防回传：拦截第三方纯遥测上报域名
  "DOMAIN-SUFFIX,sentry.io,REJECT",
  "DOMAIN-SUFFIX,datadoghq.com,REJECT",
  "DOMAIN-SUFFIX,statsigapi.net,REJECT",
  "DOMAIN-SUFFIX,statsig.com,REJECT",
  "DOMAIN-SUFFIX,intercom.io,REJECT",
  "DOMAIN-SUFFIX,intercomcdn.com,REJECT",
  // Claude 全家桶域名强制锁死 Claude-Fixed
  "DOMAIN-SUFFIX,anthropic.com,Claude-Fixed",
  "DOMAIN-SUFFIX,claude.ai,Claude-Fixed",
  "DOMAIN-SUFFIX,claude.com,Claude-Fixed",
  "DOMAIN-SUFFIX,claudeusercontent.com,Claude-Fixed",
  // 出口 IP 合规监测域名强制走 Claude-Fixed（保证体检与实际 Claude 出口 100% 同源）
  "DOMAIN-SUFFIX,ip-api.com,Claude-Fixed",
  "DOMAIN-SUFFIX,ipapi.is,Claude-Fixed",
  "DOMAIN-SUFFIX,ipinfo.io,Claude-Fixed",
  // 进程级兜底锁死（仅锁定 Claude 与本安全启动器探针进程，不影响其他应用分流）
  "PROCESS-NAME,Claude.exe,Claude-Fixed",
  "PROCESS-NAME,claude.exe,Claude-Fixed",
  "PROCESS-NAME,FD Claude Guard.exe,Claude-Fixed",
  "PROCESS-NAME,fd-claude-guard.exe,Claude-Fixed"
];

function main(config) {
  config = config || {};
  config.ipv6 = false;
  // 若机场订阅关闭了进程匹配，恢复为 strict 以确保 PROCESS-NAME,Claude.exe 规则生效
  if (typeof config["find-process-mode"] === "string" && config["find-process-mode"].toLowerCase() === "off") {
    config["find-process-mode"] = "strict";
  }

  const proxies = Array.isArray(config.proxies) ? config.proxies : [];
  const safeNodes = proxies
    .map((p) => p && p.name)
    .filter((name) => typeof name === "string" && !BLOCKED_REGION_RE.test(name));

  const providerNames =
    config["proxy-providers"] && typeof config["proxy-providers"] === "object"
      ? Object.keys(config["proxy-providers"]).filter((k) => typeof k === "string" && k.length > 0)
      : [];

  config["proxy-groups"] = Array.isArray(config["proxy-groups"]) ? config["proxy-groups"] : [];
  const existingIdx = config["proxy-groups"].findIndex((g) => g && g.name === "Claude-Fixed");

  const claudeGroup = {
    name: "Claude-Fixed",
    type: "select"
  };
  if (safeNodes.length > 0) {
    claudeGroup.proxies = safeNodes;
    if (providerNames.length > 0) {
      claudeGroup.use = providerNames;
      claudeGroup["exclude-filter"] = BLOCKED_EXCLUDE_FILTER;
    }
  } else if (providerNames.length > 0) {
    claudeGroup.use = providerNames;
    claudeGroup["exclude-filter"] = BLOCKED_EXCLUDE_FILTER;
  } else {
    claudeGroup.proxies = ["DIRECT"];
  }

  if (existingIdx >= 0) {
    config["proxy-groups"][existingIdx] = claudeGroup;
  } else {
    config["proxy-groups"].unshift(claudeGroup);
  }

  const oldRules = Array.isArray(config.rules) ? config.rules : [];
  const dedupedOld = oldRules.filter((r) => !CLAUDE_RULES.includes(r));
  config.rules = [...CLAUDE_RULES, ...dedupedOld];

  return config;
}
