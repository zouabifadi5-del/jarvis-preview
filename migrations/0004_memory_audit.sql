-- Minimal, content-free audit events for owner memory lifecycle changes.
-- Trigger writes are atomic with the underlying memory/settings mutation.
-- No record IDs, categories, plaintext, ciphertext, session IDs, or IP addresses
-- are included. Keep only the newest 200 events for the single owner.

CREATE TABLE IF NOT EXISTS owner_memory_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL DEFAULT 1
    REFERENCES jarvis_owner(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL CHECK (
    event_type IN ('created', 'updated', 'deleted', 'enabled', 'disabled')
  ),
  occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0)
);

CREATE INDEX IF NOT EXISTS idx_owner_memory_audit_recent
  ON owner_memory_audit(owner_id, id DESC);

CREATE TRIGGER IF NOT EXISTS trg_owner_memories_audit_insert
AFTER INSERT ON owner_memories
BEGIN
  INSERT INTO owner_memory_audit(owner_id, event_type, occurred_at)
  VALUES (NEW.owner_id, 'created', NEW.created_at);
  DELETE FROM owner_memory_audit
  WHERE owner_id = NEW.owner_id
    AND id NOT IN (
      SELECT id FROM owner_memory_audit
      WHERE owner_id = NEW.owner_id
      ORDER BY id DESC LIMIT 200
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_owner_memories_audit_update
AFTER UPDATE ON owner_memories
BEGIN
  INSERT INTO owner_memory_audit(owner_id, event_type, occurred_at)
  VALUES (NEW.owner_id, 'updated', NEW.updated_at);
  DELETE FROM owner_memory_audit
  WHERE owner_id = NEW.owner_id
    AND id NOT IN (
      SELECT id FROM owner_memory_audit
      WHERE owner_id = NEW.owner_id
      ORDER BY id DESC LIMIT 200
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_owner_memories_audit_delete
AFTER DELETE ON owner_memories
BEGIN
  INSERT INTO owner_memory_audit(owner_id, event_type, occurred_at)
  VALUES (OLD.owner_id, 'deleted', unixepoch());
  DELETE FROM owner_memory_audit
  WHERE owner_id = OLD.owner_id
    AND id NOT IN (
      SELECT id FROM owner_memory_audit
      WHERE owner_id = OLD.owner_id
      ORDER BY id DESC LIMIT 200
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_owner_memory_settings_audit_insert
AFTER INSERT ON owner_memory_settings
BEGIN
  INSERT INTO owner_memory_audit(owner_id, event_type, occurred_at)
  VALUES (NEW.owner_id, CASE WHEN NEW.enabled = 1 THEN 'enabled' ELSE 'disabled' END, NEW.updated_at);
  DELETE FROM owner_memory_audit
  WHERE owner_id = NEW.owner_id
    AND id NOT IN (
      SELECT id FROM owner_memory_audit
      WHERE owner_id = NEW.owner_id
      ORDER BY id DESC LIMIT 200
    );
END;

CREATE TRIGGER IF NOT EXISTS trg_owner_memory_settings_audit_update
AFTER UPDATE OF enabled ON owner_memory_settings
WHEN OLD.enabled != NEW.enabled
BEGIN
  INSERT INTO owner_memory_audit(owner_id, event_type, occurred_at)
  VALUES (NEW.owner_id, CASE WHEN NEW.enabled = 1 THEN 'enabled' ELSE 'disabled' END, NEW.updated_at);
  DELETE FROM owner_memory_audit
  WHERE owner_id = NEW.owner_id
    AND id NOT IN (
      SELECT id FROM owner_memory_audit
      WHERE owner_id = NEW.owner_id
      ORDER BY id DESC LIMIT 200
    );
END;
