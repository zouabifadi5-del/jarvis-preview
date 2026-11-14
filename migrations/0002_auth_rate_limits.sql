-- JARVIS authentication rate-limit storage.
-- Bucket identifiers are HMACs; raw client IP addresses are never stored.
CREATE TABLE IF NOT EXISTS auth_rate_limits (
  bucket_hash TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  request_count INTEGER NOT NULL CHECK (request_count > 0),
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (bucket_hash, window_start)
);
CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_expiry
  ON auth_rate_limits(expires_at);
