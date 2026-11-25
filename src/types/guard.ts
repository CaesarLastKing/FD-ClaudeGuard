export type ThemeMode = "dark" | "light";
export type NavTab = "console" | "nodes" | "logs" | "maintain" | "config";
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

export interface LicenseStatus {
  commercialFeatureEnabled: boolean;
  licensed: boolean;
  activatedAt?: string | null;
  batchId?: string | null;
  installIdShort?: string | null;
  machineFpShort?: string | null;
  apiEndpoint?: string | null;
}

export interface ActivateLicenseResult {
  licensed: boolean;
  activatedAt: string;
  batchId: string;
  message: string;
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
