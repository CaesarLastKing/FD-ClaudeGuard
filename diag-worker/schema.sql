-- FD Claude Guard 脱敏诊断日志与排障单号 D1 表结构
-- 隐私红线：仅接收客户端二次强脱敏后的结构体，服务端额外限制单条体积并按 14 天自动清理

CREATE TABLE IF NOT EXISTS feedback_reports (
  ticket_id TEXT PRIMARY KEY,
  install_id_hash TEXT NOT NULL,
  app_version TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  bytes_size INTEGER NOT NULL,
  client_country TEXT,
  created_at_unix INTEGER NOT NULL,
  created_at_iso TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback_reports(created_at_unix DESC);

CREATE TABLE IF NOT EXISTS telemetry_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_event_id TEXT NOT NULL,
  install_id_hash TEXT NOT NULL,
  app_version TEXT NOT NULL,
  category TEXT NOT NULL,
  event_type TEXT NOT NULL,
  level TEXT NOT NULL,
  tag TEXT,
  signature TEXT,
  event_json TEXT NOT NULL,
  created_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tel_created ON telemetry_events(created_at_unix DESC);
CREATE INDEX IF NOT EXISTS idx_tel_type ON telemetry_events(event_type, created_at_unix DESC);

-- 单 IP 简易滑动窗口限流表（防恶意刷库）
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket_key TEXT PRIMARY KEY,
  hits INTEGER NOT NULL,
  expires_at_unix INTEGER NOT NULL
);
