/**
 * FD Claude Guard — Clash Verge Rev 全局扩展覆写脚本标准模板
 * // FD-CLAUDE-GUARD-SCHEMA: v2
 * 作用：
 * 1. 创建固定手动选择策略组 Claude-Fixed (type: select)，自动剔除禁区节点 (HK/MO/CN/RU/BY/KP/IR/SY/CU) 且绝不误杀 🇨🇳台湾 合规节点
 * 2. 严格分流隔离：仅将 Claude 全家桶/KYC 核验、可选 CF 盾与 Stripe 支付、出口 IP 监测与 Claude 进程强制路由至 Claude-Fixed（不干扰 AGY / 其他软件分流）
 * 3. REJECT 第三方纯遥测域名（第 3 层防回传，刻意保留 statsig.anthropic.com 功能开关），关闭内核与 DNS IPv6 并加固 Fake-IP 防泄漏
 */

// === FD-CLAUDE-GUARD:BLOCKED-REGION:BEGIN ===
const BLOCKED_REGION_RE = /(香港|Hong\s*Kong|🇭🇰|澳门|澳門|Macau|Macao|🇲🇴|中国|中國|国内|回国|回國|China|俄罗斯|俄羅斯|俄国|Russia|🇷🇺|白俄|Belarus|🇧🇾|朝鲜|朝鮮|North\s*Korea|🇰🇵|伊朗|Iran|🇮🇷|叙利亚|敘利亞|Syria|🇸🇾|古巴|Cuba|🇨🇺|(?:^|[^a-z])(HK|MO|CN|RU|BY|KP|IR|SY|CU)(?:[^a-z]|$))/i;
const BLOCKED_EXCLUDE_FILTER = "(?i)(香港|Hong\\s*Kong|🇭🇰|澳门|澳門|Macau|Macao|🇲🇴|中国|中國|国内|回国|回國|China|俄罗斯|俄羅斯|俄国|Russia|🇷🇺|白俄|Belarus|🇧🇾|朝鲜|朝鮮|North\\s*Korea|🇰🇵|伊朗|Iran|🇮🇷|叙利亚|敘利亞|Syria|🇸🇾|古巴|Cuba|🇨🇺|(?:^|[^a-z])(HK|MO|CN|RU|BY|KP|IR|SY|CU)(?:[^a-z]|$))";
const TAIWAN_SAFE_RE = /(台湾|臺灣|Taiwan|🇹🇼)/i;
const BLOCKED_HARD_CONFLICT_RE = /(香港|Hong\s*Kong|🇭🇰|澳门|澳門|Macau|Macao|🇲🇴|中国大陆|中國大陸|国内|直连|中转|回国|China\s*Mainland)/i;
function isBlockedClaudeNodeName(name) {
  if (typeof name !== "string" || !name) return false;
  if (TAIWAN_SAFE_RE.test(name) && !BLOCKED_HARD_CONFLICT_RE.test(name)) return false;
  return BLOCKED_REGION_RE.test(name);
}
// === FD-CLAUDE-GUARD:BLOCKED-REGION:END ===

// === FD-CLAUDE-GUARD:CLAUDE-RULES:BEGIN ===
const CLAUDE_RULES = [
  // 第 3 层防回传：拦截第三方纯遥测上报域名（刻意不拦 statsig.anthropic.com 功能开关）
  "DOMAIN-SUFFIX,sentry.io,REJECT",
  "DOMAIN-SUFFIX,datadoghq.com,REJECT",
  "DOMAIN-SUFFIX,browser-intake-datadoghq.com,REJECT",
  "DOMAIN-SUFFIX,datadoghq.eu,REJECT",
  "DOMAIN-SUFFIX,statsigapi.net,REJECT",
  "DOMAIN-SUFFIX,statsig.com,REJECT",
  "DOMAIN-SUFFIX,statsigcdn.com,REJECT",
  "DOMAIN-SUFFIX,featureassets.org,REJECT",
  "DOMAIN-SUFFIX,prodregistryv2.org,REJECT",
  "DOMAIN-SUFFIX,intercom.io,REJECT",
  "DOMAIN-SUFFIX,intercomcdn.com,REJECT",
  "DOMAIN-SUFFIX,segment.io,REJECT",
  "DOMAIN-SUFFIX,api.segment.com,REJECT",
  "DOMAIN-SUFFIX,honeycomb.io,REJECT",
  // Claude 官方全家桶 & KYC 核验域强制锁死 Claude-Fixed
  "DOMAIN-SUFFIX,anthropic.com,Claude-Fixed",
  "DOMAIN-SUFFIX,claude.ai,Claude-Fixed",
  "DOMAIN-SUFFIX,claude.com,Claude-Fixed",
  "DOMAIN-SUFFIX,claudeusercontent.com,Claude-Fixed",
  "DOMAIN-SUFFIX,anthropic.org,Claude-Fixed",
  "DOMAIN-SUFFIX,clau.de,Claude-Fixed",
  "DOMAIN-SUFFIX,servd-anthropic-website.b-cdn.net,Claude-Fixed",
  "DOMAIN-SUFFIX,withpersona.com,Claude-Fixed",
  // Cloudflare 人机盾 & Stripe 支付同源（防跨节点双 IP 串线；可在「系统设置 → 安全策略」中按需关闭）
  "DOMAIN-SUFFIX,challenges.cloudflare.com,Claude-Fixed",
  "DOMAIN-SUFFIX,stripe.com,Claude-Fixed",
  "DOMAIN-SUFFIX,stripe.network,Claude-Fixed",
  // 出口 IP 合规监测域名强制走 Claude-Fixed（保证体检与实际 Claude 出口 100% 同源）
  "DOMAIN-SUFFIX,ip-api.com,Claude-Fixed",
  "DOMAIN-SUFFIX,ipapi.is,Claude-Fixed",
  "DOMAIN-SUFFIX,ipinfo.io,Claude-Fixed",
  // 进程级兜底锁死（仅锁定 Claude、官方 Chrome 桥接宿主与本启动器探针，不锁 node.exe）
  "PROCESS-NAME,Claude.exe,Claude-Fixed",
  "PROCESS-NAME,claude.exe,Claude-Fixed",
  "PROCESS-NAME,chrome-native-host.exe,Claude-Fixed",
  "PROCESS-NAME,FD Claude Guard.exe,Claude-Fixed",
  "PROCESS-NAME,fd-claude-guard.exe,Claude-Fixed"
];
// === FD-CLAUDE-GUARD:CLAUDE-RULES:END ===

function main(config) {
  config = config || {};
  config.ipv6 = false;
  // 保障 DNS Fake-IP 防泄漏开启并关闭 DNS IPv6（保留用户原有 nameserver / fallback / fake-ip-filter）
  config.dns = config.dns && typeof config.dns === "object" ? config.dns : {};
  config.dns.enable = true;
  config.dns.ipv6 = false;
  config.dns["enhanced-mode"] = "fake-ip";
  if (!config.dns["fake-ip-range"]) {
    config.dns["fake-ip-range"] = "198.18.0.1/16";
  }
  if (!Array.isArray(config.dns.nameserver) || config.dns.nameserver.length === 0) {
    config.dns.nameserver = ["223.5.5.5", "119.29.29.29"];
  }
  if (!Array.isArray(config.dns.fallback) || config.dns.fallback.length === 0) {
    config.dns.fallback = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"];
    if (!config.dns["fallback-filter"] || typeof config.dns["fallback-filter"] !== "object") {
      config.dns["fallback-filter"] = {
        geoip: true,
        "geoip-code": "CN",
        ipcidr: ["240.0.0.0/4"]
      };
    }
  }
  if (!Array.isArray(config.dns["fake-ip-filter"]) || config.dns["fake-ip-filter"].length === 0) {
    config.dns["fake-ip-filter"] = [
      "*.lan",
      "*.local",
      "localhost.ptlogin2.qq.com",
      "time.windows.com",
      "time.nist.gov",
      "ntp.*.com"
    ];
  }
  // 若机场订阅关闭了进程匹配，恢复为 strict 以确保 PROCESS-NAME,Claude.exe 规则生效
  if (typeof config["find-process-mode"] === "string" && config["find-process-mode"].toLowerCase() === "off") {
    config["find-process-mode"] = "strict";
  }

  const proxies = Array.isArray(config.proxies) ? config.proxies : [];
  const safeNodes = proxies
    .map((p) => p && p.name)
    .filter((name) => typeof name === "string" && !isBlockedClaudeNodeName(name));

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
