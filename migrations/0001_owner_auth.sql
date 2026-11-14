-- JARVIS owner authentication schema.
-- D1 migration only: this file does not create or bind a Cloudflare database.
-- Apply only after the account's Free-plan and billing status are verified.

-- D1 enforces declared foreign keys by default; no PRAGMA toggle is needed.

CREATE TABLE IF NOT EXISTS jarvis_owner (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  created_at INTEGER NOT NULL,
  enrollment_closed_at INTEGER
);

CREATE TABLE IF NOT EXISTS owner_credentials (
  credential_id TEXT PRIMARY KEY,
  owner_id INTEGER NOT NULL DEFAULT 1
    REFERENCES jarvis_owner(id) ON DELETE CASCADE,
  public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  transports_json TEXT,
  device_type TEXT,
  backed_up INTEGER NOT NULL DEFAULT 0 CHECK (backed_up IN (0, 1)),
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_owner_credentials_active
  ON owner_credentials(owner_id, revoked_at);

CREATE TABLE IF NOT EXISTS auth_challenges (
  challenge_hash TEXT PRIMARY KEY,
  challenge TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK (purpose IN ('registration', 'authentication')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_auth_challenges_expiry
  ON auth_challenges(expires_at);

CREATE TABLE IF NOT EXISTS auth_sessions (
  session_hash TEXT PRIMARY KEY,
  csrf_token_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
  last_seen_at INTEGER,
  revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry
  ON auth_sessions(expires_at);

-- No user profile, conversation memory, prompts, email, or other personal content
-- belongs in this authentication database.
