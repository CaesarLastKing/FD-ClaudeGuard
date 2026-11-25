-- FD Claude Guard 商业授权与遥测 D1 SQLite 表结构
CREATE TABLE IF NOT EXISTS licenses (
  key_hash TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unused',
  activated_at TEXT,
  machine_fp_hash TEXT,
  install_id_hash TEXT
);

CREATE INDEX IF NOT EXISTS idx_licenses_batch_status ON licenses(batch_id, status);

-- T-302：客户机低频高价值匿名诊断日志与 Claude 高危归因遥测表（联合唯一去重 + received_at 索引）
CREATE TABLE IF NOT EXISTS telemetry_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  install_id_hash TEXT NOT NULL,
  app_version TEXT NOT NULL,
  category TEXT NOT NULL,        -- 'tool_diag' | 'claude_error'
  event_type TEXT NOT NULL,
  level TEXT NOT NULL,           -- 'fail' | 'error' | 'warn'
  tag TEXT NOT NULL DEFAULT '',
  signature TEXT NOT NULL DEFAULT '',
  repeat_count INTEGER NOT NULL DEFAULT 1,
  pre_ban_factors TEXT NOT NULL DEFAULT '[]',
  env_json TEXT NOT NULL DEFAULT '{}',
  client_event_id TEXT NOT NULL,
  UNIQUE(install_id_hash, client_event_id)
);

CREATE INDEX IF NOT EXISTS idx_telemetry_received_at ON telemetry_events(received_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_cat_tag ON telemetry_events(category, tag, received_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_version ON telemetry_events(app_version, received_at);

-- T-303：用户主动触发「一键匿名上报排障」单号表
CREATE TABLE IF NOT EXISTS feedback_reports (
  ticket_id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  install_id_hash TEXT NOT NULL,
  app_version TEXT NOT NULL,
  summary_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback_reports(created_at);

-- P0-7：轻量 D1 频控计数表（防刷写打爆 D1 配额与激活码穷举）
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket_key TEXT PRIMARY KEY,
  hits INTEGER NOT NULL DEFAULT 1,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_expires ON rate_limits(expires_at);
