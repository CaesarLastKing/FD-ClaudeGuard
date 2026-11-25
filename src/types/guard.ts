export type ThemeMode = "dark" | "light";
export type NavTab = "console" | "audit" | "nodes" | "maintain" | "config" | "logs";
export type AuditSubTab = "audit" | "logs";
export type CheckStatus = "ok" | "fail" | "warn";
export type CheckPart = "must" | "opt";

export interface WindowPos {
  x: number;
  y: number;
}

export interface AppConfig {
  theme: ThemeMode;
  showHud: boolean;
  notifyEnabled: boolean;
  bootStart: boolean;
  bootHudOnly: boolean;
  wakePreblockGuard: boolean;
  antiNakedGuard: boolean;
  autoKillSwitch: boolean;
  antiUploadFlush: boolean;
  safeExitPrompt: boolean;
  calm24h: boolean;
  hudPinned: boolean;
  hudFolded: boolean;
  hudEdgeDocked: boolean;
  hudPosition: WindowPos | null;
  lockedNodeForIp?: string | null;
  lockedLandingIp?: string | null;
  boundPrimaryOrgId?: string | null;
  killHoldSeconds?: number;
  ackedLogIds?: string[];
  telemetryToolDiagEnabled?: boolean;
  telemetryClaudeSummaryEnabled?: boolean;
}

export type AppConfigPatch = Partial<AppConfig>;

export interface PreflightItem {
  id: string;
  part: CheckPart;
  cat: string;
  icon: string;
  mode: string;
  title: string;
  status: CheckStatus;
  summary: string;
  evidence: string;
  guide: string;
  fixLabel: string | null;
  isKillItem: boolean;
  isFailover: boolean;
}

export interface PreflightReport {
  checkedAt: string;
  stage: string;
  items: PreflightItem[];
}

export interface StartupEntry {
  app: string;
  enabled: boolean;
  riskLevel: "ok" | "warn" | "neutral";
  detail: string;
}

export interface StartupAuditReport {
  entries: StartupEntry[];
  claudeAutostartRisk: boolean;
}

export interface HudEventLine {
  message: string;
  time: string;
  level: "ok" | "warn" | "danger";
  targetTab?: NavTab;
}

export interface GuardSnapshot {
  healthLevel: "ok" | "warn" | "danger";
  statusLabel: string;
  currentNode: string;
  regionCode: string;
  exitIpMasked: string;
  latencyMs: number | null;
  latencyLabel: string;
  bgClaudeProcs: number;
  killSwitchActive: boolean;
  killHoldActive?: boolean;
  killHoldRemainingSecs?: number;
  killHoldBlockedCount?: number;
  killHoldTxLocked?: boolean;
  killHoldReason?: string;
  nodeDown: boolean;
  nodeDriftWarn?: boolean;
  mustPassed: number;
  mustTotal: number;
  optPassed: number;
  optTotal: number;
  clashVersion: string;
  clashPort: number;
  clashOnline: boolean;
  anthropicStatusIndicator: string;
  anthropicStatusDesc: string;
  unreadLogAnomalies: number;
  unreadLogCritical?: number;
  unreadLogWarnings?: number;
  activeFlowAnomalies: number;
  liveFlowAnomalies?: number;
  nextFullAuditEpochMs: number;
  triggeredPlaybookIds: string[];
  hudEvents: HudEventLine[];
}

export interface NavigatePayload {
  tab: NavTab;
  subTab?: string | null;
  focusItemId?: string | null;
  openPlaybook?: boolean | null;
}

export interface PlaybookRule {
  id: string;
  code: string;
  level: "fail" | "warn" | "neutral";
  tag: string;
  title: string;
  desc: string;
  hitText: string;
}

export interface ToastAction {
  label: string;
  onClick: () => void;
  tone?: "flat" | "danger";
}

export interface ToastMessage {
  id: string;
  title: string;
  body: string;
  type: "ok" | "info" | "danger";
  badge?: string;
  action?: ToastAction;
}

export interface RouteCompare {
  fromCode: string;
  fromName: string;
  fromRole: string;
  fromDanger?: boolean;
  toCode: string;
  toName: string;
  toRole: string;
}

export interface RiskModalState {
  open: boolean;
  tone?: "ok" | "warn" | "danger";
  badge?: string;
  title: string;
  subtitle?: string;
  routeCompare?: RouteCompare;
  rows: Array<{ label: string; value: string; tone?: "normal" | "danger" | "ok" }>;
  footTip?: string;
  primaryLabel: string;
  onPrimary: () => void;
  secondaryLabel?: string;
  onSecondary?: () => void;
  dangerLabel?: string;
  onDanger?: () => void;
}

export interface FixResult {
  itemId: string;
  success: boolean;
  requiresManualStep: boolean;
  message: string;
  report: PreflightReport;
  snapshot: GuardSnapshot;
}

export interface BatchFixResult {
  fixedIds: string[];
  skippedManualId: string | null;
  summary: string;
  report: PreflightReport;
  snapshot: GuardSnapshot;
}

export interface NodeItem {
  name: string;
  regionCode: string;
  regionLabel?: string;
  nodeType: string;
  delayMs: number | null;
  jitterMs: number;
  dropRatePct: number;
  blocked: boolean;
  isCurrent: boolean;
  score: number;
  recommendation: string;
  asnPurity?: string;
  asnShort?: string;
  anthropicProbe?: string;
  cfBlocked?: boolean;
  claudeStatus?: string;
  claudeLabel?: string;
  geminiStatus?: string;
  geminiLabel?: string;
  dualAiOk?: boolean;
  driftCount24h?: number;
  riskLevel?: string;
  riskDetail?: string;
  webCfChallenge?: boolean;
}

export interface NodeReport {
  connected: boolean;
  endpoint: string;
  groupName: string;
  currentNode: string;
  totalRawNodes: number;
  filteredBlockedCount: number;
  nodes: NodeItem[];
  currentExitSummary?: string | null;
}

export interface SwitchNodeResult {
  switched: boolean;
  nodeName: string;
  message: string;
  report: PreflightReport;
  snapshot: GuardSnapshot;
}

export interface ClaudeConn {
  id: string;
  anomaly: boolean;
  acked?: boolean;
  process: string;
  host: string;
  rule: string;
  chain: string;
  action: string;
  time: string;
  bytesLabel: string;
}

export interface KillReport {
  beforeCount: number;
  afterCount: number;
  telemetryClearedBytes: number;
  message: string;
  killHoldActive?: boolean;
  killHoldRemainingSecs?: number;
}

export interface KillHoldSnapshot {
  active: boolean;
  remainingSecs: number;
  blockedCount: number;
  txLocked: boolean;
  reason: string;
}

export interface KillSwitchState {
  active: boolean;
  ruleName: string;
  targetExe: string | null;
  firewallApplied: boolean;
  claudeConnectionsClosed: number;
  killedProcesses: number;
  telemetryClearedBytes: number;
  reason: string;
  updatedAt: string;
}

export interface LogEvent {
  id: string;
  ruleId: string | null;
  anomaly: boolean;
  simulated?: boolean;
  acked?: boolean;
  level: "fail" | "warn" | "ok";
  tag: string;
  time: string;
  file: string;
  line: number;
  title: string;
  cause: string;
  context: string;
  repeatCount?: number;
  collapsedIds?: string[];
  attributionClue?: string | null;
}

export interface TelemetryFilePreview {
  fileName: string;
  sizeBytes: number;
  sizeLabel: string;
  modifiedAt: string;
  previewText: string;
}

export interface TelemetryInspection {
  telemetryDir: string;
  totalFiles: number;
  totalBytes: number;
  totalSizeLabel: string;
  explanation: string;
  files: TelemetryFilePreview[];
}

export interface NoiseCategoryCount {
  label: string;
  count: number;
}

export interface LogStats {
  totalAnomalies: number;
  criticalCount?: number;
  warningCount?: number;
  regionOrRateCount: number;
  disconnectCount: number;
  telemetryOrDeviceCount: number;
  watchingFiles: string[];
  ignoredNoiseCount?: number;
  ignoredNoiseBreakdown?: NoiseCategoryCount[];
  timezoneJumpWarning?: string | null;
}

export interface ClaudeDataRootsSummary {
  classicDetected: boolean;
  msixPackages: string[];
  telemetryExists: boolean;
}

export interface CleanupCategoryPreview {
  id: string;
  title: string;
  description: string;
  defaultSelected: boolean;
  willBackup: boolean;
  fileCount: number;
  totalBytes: number;
  sizeLabel: string;
  samplePaths: string[];
}

export interface ProtectedSummary {
  fileCount: number;
  totalBytes: number;
  sizeLabel: string;
  reasons: string[];
}

export interface CleanupPlanPreview {
  detectedInstallModes: string[];
  activeClaudeProcs: number;
  categories: CleanupCategoryPreview[];
  protected: ProtectedSummary;
  scannedMs: number;
}

export interface LogAnalysisReport {
  events: LogEvent[];
  stats: LogStats;
}

export interface BackupInfo {
  fileName: string;
  fullPath: string;
  kind: string;
  createdAt: string;
  createdTs?: number;
  sizeBytes: number;
  sizeLabel: string;
}

export interface DiagnosticBundleResult {
  zipPath: string;
  promptMarkdown: string;
  manifestMagic: number;
}

export interface FeedbackReportResult {
  ticketId: string;
  createdAt: string;
  uploadedBytes: number;
  endpointUsed: string;
  message: string;
}

export interface DeepAuditProgress {
  running: boolean;
  phase: "idle" | "running" | "done" | "cancelled" | "blocked" | string;
  currentIndex: number;
  total: number;
  currentNode: string;
  originalNode: string;
  currentNodeVerified: boolean;
  message: string;
}

export interface RollbackItemStatus {
  id: string;
  title: string;
  category: string;
  touchedByGuard: boolean;
  canRollback: boolean;
  originalSummary: string;
  currentSummary: string;
  riskNote: string;
}

export interface RollbackOverview {
  baselineExists: boolean;
  baselinePath: string;
  isElevated: boolean;
  loopbackDnsAdapters: string[];
  activeFirewallRules: boolean;
  touchedCount: number;
  items: RollbackItemStatus[];
}

export interface RollbackActionReport {
  itemId: string;
  ok: boolean;
  message: string;
  overview: RollbackOverview;
}

export interface RollbackBatchReport {
  allOk: boolean;
  revertedIds: string[];
  skippedIds: string[];
  failed: string[];
  summary: string;
  overview: RollbackOverview;
}

export interface RescueStepResult {
  step: string;
  ok: boolean;
  detail: string;
}

export interface NetworkRescueReport {
  ok: boolean;
  isElevated: boolean;
  directConnectivityOk: boolean;
  steps: RescueStepResult[];
  summary: string;
}

export type GeoConsistency =
  | "pending"
  | "match"
  | "same_continent_diff_country"
  | "cross_continent_mismatch";

export type AuditDataSource = "local_config" | "official_probe" | "offline_jsonl" | "unknown";

export interface ScoreDeductionItem {
  id: string;
  weightMax: number;
  delta: number;
  deltaLabel: string;
  tone: "danger" | "warn" | "muted" | "ok" | string;
  title: string;
  desc: string;
}

export interface ScoreResult {
  score: number;
  maxScore: number;
  level: "safe" | "watch" | "mid_high" | "critical" | string;
  levelLabel: string;
  colorToken: "green" | "amber" | "orange" | "red" | string;
  confidence: "local_only" | "stale_7d" | "full_combined" | "cloud_only" | string;
  confidenceLabel: string;
  disclaimer: string;
  blindSpotNote?: string | null;
  deductions: ScoreDeductionItem[];
}

export interface QuotaDisplaySummary {
  fiveHourPct: number | null;
  sevenDayPct: number | null;
  stampShort: string;
  stampTooltip: string;
  fiveHourOfflineNote?: string | null;
  softLocked: boolean;
  source: AuditDataSource;
}

export interface BackupAccountRecord {
  orgPrefix: string;
  emailMasked?: string | null;
  planLabel?: string | null;
  merchantChannel?: string | null;
  backupCount: number;
}

export interface CachedUsageSummary {
  fetchedAtMs?: number | null;
  fiveHourPct?: number | null;
  fiveHourResetsAt?: string | null;
  fiveHourLockedReason?: string | null;
  sevenDayPct?: number | null;
  sevenDayResetsAt?: string | null;
  sevenDayLockedReason?: string | null;
  cachedExtraUsageDisabledReason?: string | null;
}

export interface ClaudeJsonSummary {
  exists: boolean;
  parseError?: string | null;
  emailMasked?: string | null;
  orgUuidPrefix8?: string | null;
  planLabel?: string | null;
  billingType?: string | null;
  merchantChannel?: string | null;
  accountCreatedAt?: string | null;
  accountAgeDays?: number | null;
  subscriptionCreatedAt?: string | null;
  subscriptionAgeDays?: number | null;
  firstStartTime?: string | null;
  localDeviceAgeDays?: number | null;
  machineIdPrefix8?: string | null;
  userIdPrefix8?: string | null;
  cachedUsage?: CachedUsageSummary | null;
}

export interface CredentialsMetaSummary {
  exists: boolean;
  subscriptionType?: string | null;
  rateLimitTier?: string | null;
  scopes: string[];
  expiresAt?: string | null;
  isExpired?: boolean | null;
  mcpOauthProviders: string[];
}

export interface SettingsHygieneSummary {
  settingsExists: boolean;
  settingsPath?: string | null;
  privacyEnvFlags: Record<string, boolean>;
  privacyEnabledCount: number;
  privacyMissingKeys: string[];
  settingsNonOfficialEndpoint?: string | null;
  systemEnvEndpointConflicts: string[];
  telemetryFileCount: number;
  telemetryTotalBytes: number;
  scheduledTasksCount: number;
  backupFileCount: number;
  backupAccounts: BackupAccountRecord[];
}

export interface WindowBehaviorStats {
  assistantTurns: number;
  sidechainTurns: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
}

export interface OfflineBehaviorSummary {
  projectsDirExists: boolean;
  filesScanned7d: number;
  last5h: WindowBehaviorStats;
  last24h: WindowBehaviorStats;
  last7d: WindowBehaviorStats;
  subagentRatio24hPct: number;
  activeHours24h: number;
  overnightBotRhythmSuspected: boolean;
}

export interface LocalLogSample {
  id: string;
  category: string;
  time: string;
  fileRef: string;
  rawSanitized: string;
  count: number;
}

export interface DesktopLogsSummary {
  discoveredDirs: string[];
  scannedLogFiles: number;
  orgIdPrefixes: string[];
  accountBannedHits: number;
  portalVerifyHits: number;
  crossOrg404Hits: number;
  oauth403Hits: number;
  cookie403Hits: number;
  cfShield403Hits: number;
  rateLimit429Hits: number;
  planChangedHits: number;
  fiveHourSoftLockHits: number;
  maxSideSessionsSeen: number;
  highSideSessionHits: number;
  mcpErrorHits: number;
  mcpErrorStorm: boolean;
  disconnectHits: number;
  recentSamples: LocalLogSample[];
}

export interface LocalAccountAudit {
  profileId: string;
  scannedAtMs: number;
  claudeJson: ClaudeJsonSummary;
  credentials: CredentialsMetaSummary;
  hygiene: SettingsHygieneSummary;
  behavior: OfflineBehaviorSummary;
  desktop: DesktopLogsSummary;
  crossClientOrgMismatch: boolean;
  allObservedOrgPrefixes: string[];
}

export interface CloudProbeSnapshot {
  verifiedAtMs: number;
  checkedAtIso: string;
  emailMasked?: string | null;
  orgIdPrefix8?: string | null;
  plan: string;
  merchantChannel?: string | null;
  workspaceGeo?: string | null;
  edgeCountry?: string | null;
  edgeColo?: string | null;
  accountAgeDays?: number | null;
  subscriptionAgeDays?: number | null;
  subscriptionEndsAt?: string | null;
  chatAvailable: boolean;
  isBanned: boolean;
  appealsRedirectEnabled: boolean;
  hasMonitoringNotice: boolean;
  activeFlagTypes: string[];
  warningSummaryZh?: string | null;
  personaKycStatus?: string | null;
  personaKycCompletedAt?: string | null;
  personaKycAgeHours?: number | null;
  portalHold: boolean;
  portalState: string;
  fiveHourPct?: number | null;
  fiveHourResetsAt?: string | null;
  sevenDayPct?: number | null;
  sevenDayResetsAt?: string | null;
  warnings: string[];
}

export interface AuditLogFlowItem {
  id: string;
  cat: "403" | "net" | "other" | string;
  denoised: boolean;
  chipLabel: string;
  chipTone: "danger" | "warn" | "neutral" | string;
  title: string;
  desc: string;
  timeLabel: string;
  rawSanitized: string;
  count: number;
}

export interface AccountAuditReport {
  profileId: string;
  auditedAtMs: number;
  emailMasked: string;
  orgIdPrefix8?: string | null;
  plan: string;
  merchantChannel: string;
  accountAgeDays?: number | null;
  subscriptionAgeDays?: number | null;
  localDeviceAgeDays?: number | null;
  subscriptionRenewLabel: string;
  subscriptionRenewIsEstimated: boolean;

  workspaceGeo?: string | null;
  exitCountry?: string | null;
  exitColo?: string | null;
  exitIpPurity?: string | null;
  geoConsistency: GeoConsistency;

  cloudVerified: boolean;
  cloudStale: boolean;
  cloudAgeDays?: number | null;
  verifyCount: number;
  cloudSnapshot?: CloudProbeSnapshot | null;

  quota: QuotaDisplaySummary;
  scoreResult: ScoreResult;
  local: LocalAccountAudit;
  runtimeClashPort: number;
  runtimeProxyOk: boolean;
  runtimeBgProcs: number;
  runtimeKillHoldActive: boolean;
  runtimeKillHoldSecs: number;

  denoisedOauth403Count: number;
  logFlowItems: AuditLogFlowItem[];
  pendingIssueCount: number;
  hasDangerIssue: boolean;
}

export interface AccountAuditActionResult {
  ok: boolean;
  action: string;
  message: string;
  report?: AccountAuditReport | null;
}

export interface AppUpdateInfo {
  currentVersion: string;
  available: boolean;
  latestVersion?: string | null;
  publishedAt?: string | null;
  notes?: string | null;
  viaProxy: boolean;
  message: string;
}
