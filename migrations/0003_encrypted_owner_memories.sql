-- JARVIS encrypted owner memory schema.
-- This migration is prepared for isolated development and must not be applied
-- to the account-scoped remote database until the memory release gates are approved.
-- No plaintext memory, titles, tags, or search terms are stored in this table.

CREATE TABLE IF NOT EXISTS owner_memories (
  id TEXT PRIMARY KEY CHECK (length(id) = 36),
  owner_id INTEGER NOT NULL DEFAULT 1
    REFERENCES jarvis_owner(id) ON DELETE CASCADE,
  category TEXT NOT NULL CHECK (
    category IN ('preference', 'fact', 'project', 'routine', 'temporary')
  ),
  ciphertext BLOB NOT NULL CHECK (length(ciphertext) >= 16),
  nonce BLOB NOT NULL CHECK (length(nonce) = 12),
  key_version INTEGER NOT NULL CHECK (key_version > 0),
  schema_version INTEGER NOT NULL DEFAULT 1 CHECK (schema_version = 1),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
  expires_at INTEGER,
  CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_owner_memories_updated
  ON owner_memories(owner_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_owner_memories_expiry
  ON owner_memories(owner_id, expires_at);
