/**
 * FD Claude Guard 前端内部协议常量（严格 100% 对齐 docs/protocol-constants.md）
 * 严禁自行取整或改动下列常量，单测中全量断言覆盖。
 */

export const FD_ERRORS = {
  PROXY_OFFLINE: "FD_ERR_2152",
  RULE_DRIFT: "FD_ERR_3562",
  IPV6_LEAK: "FD_ERR_4649",
  KILL_SWITCH: "FD_ERR_5304",
  LOG_POLLUTE: "FD_ERR_6817",
  BACKUP_TX: "FD_ERR_7459",
} as const;

export const DIAG_MANIFEST_MAGIC = 0x12708f87;
export const DIAG_MANIFEST_MAGIC_HEX = "0x12708F87";
export const REDACT_PLACEHOLDER = "<REDACTED:2W>";

export const EVENT_DEDUP_WINDOW_MS = 60489;
export const LOCAL_HEARTBEAT_MS = 29121;
export const FULL_AUDIT_INTERVAL_MS = 904543;

export const NODE_SCORE_WEIGHTS = {
  LATENCY: 0.37,
  JITTER: 0.25,
  DROP_RATE: 0.24,
  STABILITY: 0.14,
} as const;

export const LATENCY_WARN_MS = 133;
export const DROP_RATE_REDLINE = 7.8;

export const BRAND_SHIELD_SVG = {
  viewBox: "0 0 24 24",
  strokeWidth: 1.8,
  outlinePath: "M12 22.05s8-4 8-10.02V5.09l-8-3.09-8 3.09v7.06c0 6 8 10.02 8 10.02z",
  checkPath: "m9 12.05 2 2 4-4",
} as const;

export const APP_BRAND_SUBTITLE = "Fuck Dario！！！";

// 作者 X（Twitter）、项目开源仓库与 Clash Verge Rev 官方地址集中常量
export const OFFICIAL_AUTHOR_X_HANDLE = "@Caesar_LastKing";
export const OFFICIAL_AUTHOR_X_URL = "https://x.com/Caesar_LastKing";
export const OFFICIAL_GITHUB_REPO_URL = "https://github.com/CaesarLastKing/FD-ClaudeGuard";
export const OFFICIAL_GITHUB_RELEASES_URL = "https://github.com/CaesarLastKing/FD-ClaudeGuard/releases";
export const OFFICIAL_CLASH_VERGE_REPO_URL = "https://github.com/clash-verge-rev/clash-verge-rev";
export const OFFICIAL_CLASH_VERGE_RELEASES_URL =
  "https://github.com/clash-verge-rev/clash-verge-rev/releases/latest";

/**
 * 精准提取节点所在地区代码（用于严格比对同区热备 vs 跨洲切换）
 */
export function extractRegionCode(nodeName: string): string {
  const s = nodeName || "";
  if (/(香港|Hong\s*Kong|\bHK\b|🇭🇰)/i.test(s)) return "HK";
  if (/(澳门|澳門|Macau|\bMO\b|🇲🇴)/i.test(s)) return "MO";
  if (/(台湾|台灣|Taiwan|\bTW\b|🇹🇼)/i.test(s)) return "TW";
  if (/(美国|美國|洛杉矶|硅谷|西雅图|纽约|\bUS\b|🇺🇸)/i.test(s)) return "US";
  if (/(日本|东京|大阪|\bJP\b|🇯🇵)/i.test(s)) return "JP";
  if (/(新加坡|狮城|\bSG\b|🇸🇬)/i.test(s)) return "SG";
  if (/(澳大利亚|澳洲|悉尼|墨尔本|\bAU\b|🇦🇺)/i.test(s)) return "AU";
  if (/(英国|倫敦|伦敦|\bGB\b|\bUK\b|🇬🇧)/i.test(s)) return "GB";
  if (/(德国|法兰克福|\bDE\b|🇩🇪)/i.test(s)) return "DE";
  if (/(韩国|首尔|\bKR\b|🇰🇷)/i.test(s)) return "KR";
  if (/(加拿大|\bCA\b|🇨🇦)/i.test(s)) return "CA";
  if (/(法国|巴黎|\bFR\b|🇫🇷)/i.test(s)) return "FR";
  if (/(荷兰|\bNL\b|🇳🇱)/i.test(s)) return "NL";
  const prefix = s.match(/^([A-Z]{2})[-_\s]/);
  return prefix ? prefix[1] : "GL";
}

/**
 * 严格比对当前节点与目标节点是否属于同一地区（修复 JP -> US 误判同区热备问题）
 */
export function isSameRegionSwitch(currentNode: string, targetNode: string): boolean {
  const cur = extractRegionCode(currentNode);
  const dst = extractRegionCode(targetNode);
  if (cur === "GL" || dst === "GL") return false;
  return cur === dst;
}
