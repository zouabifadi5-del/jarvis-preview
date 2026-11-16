# J.A.R.V.I.S. — Private Memory Design

**Status (16 November 2026):** Encrypted memory storage helpers, owner-only API routes (create, list, inspect, update, export, delete-one, delete-all), and explicit owner-controlled enable/disable endpoints are implemented on `jarvis-security-hardening`. The iPhone-first owner UI supports explicit save, list, inspect, edit, export, delete, explicit enable after a retention warning, one-tap disable, and a per-message memory-use checkbox that resets after every send. Active memory records are capped atomically at 100, and expired records are lazily pruned when the owner lists or saves memories. CI run #631 passed 36 local SQLite/Node checks and 57 Workers-runtime tests (93 total), including versioned-key compatibility, explicit opt-in bounded retrieval, rejection when memory is disabled, one-message UI consent, private-memory/chat-context isolation, and post-logout chat rejection. The same run reported zero production dependency vulnerabilities, passed browser JavaScript syntax and manifest/icon checks, and completed a Wrangler dry run without deploying: https://github.com/zouabifadi5-del/jarvis-preview/actions/runs/43906372888. Memory remains disabled unless the explicit D1-retention acceptance flag and a valid server-side encryption key are configured. No owner memory or chat transcript has been stored. A read-only check of the live `jarvis-owner-auth` D1 database confirmed that only migrations `0001_owner_auth.sql` and `0002_auth_rate_limits.sql` are recorded; encrypted-memory migrations `0003` and `0004` are not applied remotely, the memory tables are absent, and all owner/authentication data counts are currently zero. Chat can now retrieve up to five most recently updated, unexpired memories only when the owner explicitly sends `useMemory: true` for that individual request and persistent memory is enabled. Retrieved plaintext is capped at 4,000 UTF-8 bytes, decrypted server-side, and serialized as JSON data explicitly labeled untrusted reference data; JSON escaping prevents memory text from creating new prompt sections. Requests without that flag do not query or inject saved memories. A resumable bulk-rotation route is now implemented: an owner must reauthenticate with a passkey and explicitly confirm each request; each request rotates at most 10 records using compare-and-set checks, and reports remaining old-key versions. Old-key retirement remains a manual release gate: retain old keys until all live records are on the current version, then wait at least seven days after final rotation before removing them. Background scheduled expiry cleanup and a privacy-preserving management audit trail remain outstanding. The chat route retains no server-side transcript. The browser's recent conversation remains page-memory-only and clears on reload or sign-out; durable memory is fetched only for a request that explicitly opts in.

## Goals

- Keep durable memory private to the one passkey-authenticated owner.
- Store only information the owner explicitly asks JARVIS to remember or confirms in a save prompt.
- Let the owner inspect, correct, export, and delete every stored item.
- Keep raw memory text out of D1, logs, analytics, source control, and client-side persistent storage.
- Never let a model response or retrieved memory authorize an external action.

## Memory categories

Start with a small, owner-controlled set:

- Preferences and communication style.
- Stable facts the owner explicitly asks to remember.
- Ongoing projects and their current state.
- Routines and recurring plans.
- Temporary notes with an explicit expiry date.

Do not automatically store credentials, passkeys, recovery codes, financial account numbers, medical records, or other highly sensitive secrets. Do not infer sensitive traits. A model may suggest a memory candidate, but the server must not save it until the owner confirms the exact text and category.

## Encryption and storage

- Use AES-256-GCM through WebCrypto on the Worker. Generate a fresh 96-bit nonce for every record.
- Keep random 256-bit encryption keys only in Cloudflare Worker secrets. The legacy single-key configuration is `JARVIS_MEMORY_ENCRYPTION_KEY` with version 1. The new staged keyring configuration is the `JARVIS_MEMORY_KEYRING` secret containing a bounded JSON object such as `{"currentVersion":2,"keys":{"1":"<base64url-key-v1>","2":"<base64url-key-v2>"}}`. The keyring accepts at most eight positive key versions, requires the current version to be present, imports every key before enabling memory, and rejects noncanonical base64url encodings. New records use the current version; reads and exports can decrypt records with any retained version; editing a record re-encrypts it using the current version. Never store keys in D1, Wrangler files, browser code, Git, logs, or the model prompt. This is keyring compatibility, not a completed bulk-rotation workflow: retain every old key until a separately reviewed batch re-encryption has verified every live record and the seven-day D1 Time Travel retention window has elapsed. Do not replace/remove keys or enable memory as part of this code change.
- Version the key and ciphertext format. Bind record ID, owner ID, schema version, and key version as authenticated additional data (AAD).
- Rotate through `POST /auth/memories/rotate` with `{confirm:true,batchSize:10}` after a new key becomes current. Repeat until `remaining` is zero. Each call requires a recent passkey session and CSRF protection; each update compares the old key version, ciphertext, and nonce to avoid overwriting concurrent changes. Do not remove old keys until the seven-day D1 Time Travel window after final rotation has elapsed.
- Store ciphertext, nonce, key version, owner ID, record ID, timestamps, and non-sensitive lifecycle fields only. Avoid plaintext titles, tags, summaries, or search indexes in the first version.
- Fail closed if the encryption key is absent, malformed, or has the wrong length. Do not fall back to plaintext storage.
- Decrypt only after owner-session checks; require CSRF for writes and recent passkey authentication for creation, editing, export, and deletion. Never expose bulk decrypted memory to the browser unless the owner requests an export or inspection.

## Retrieval and prompt safety

- [x] Retrieve at most five most recently updated, unexpired records only on an explicit per-request `useMemory: true` choice while owner memory is enabled; decrypt server-side and cap aggregate content at 4,000 UTF-8 bytes.
- [x] Keep default chat requests memory-free; retrieved content is explicitly labeled untrusted reference data and cannot grant authority or override policy.
- [x] Serialize retrieved memories as a JSON data block, explicitly labeled untrusted; JSON escaping prevents embedded newlines from spoofing prompt sections.
- Continue to treat retrieved memory as data, not system instructions, policy, consent, or authorization.
- The model may use memories to tailor answers, but cannot create, edit, or delete durable memory without an explicit owner action.
- Do not give the model arbitrary SQL, filesystem, shell, or unrestricted network tools.

## Owner controls

- List memories with minimal metadata and timestamps.
- Open and inspect one memory at a time.
- Edit by decrypting, validating, and re-encrypting with a fresh nonce.
- Export a user-readable JSON file only after recent passkey confirmation; do not include encryption keys.
- Delete an individual memory or all memories only after an explicit, high-assurance confirmation. Do not claim deletion from backups until the provider's backup retention and purge behavior has been verified.
- [x] Provide a visible memory status, explicit owner-controlled enable after retention disclosure, and one-tap disable without deleting the account.

## Data lifecycle and backups

Cloudflare's current D1 documentation lists the Workers Free limits as 5 million rows read per day, 100,000 rows written per day, 5 GB total account storage, and 500 MB maximum size per database. Free-plan D1 Time Travel is always on and retains up to 7 days of point-in-time history; it can restore deleted or changed data within that window. Sources: https://developers.cloudflare.com/d1/platform/pricing/ https://developers.cloudflare.com/d1/platform/limits/ https://developers.cloudflare.com/d1/reference/time-travel/

- A live-row deletion is not immediate physical erasure: historical D1 state may be restorable for up to seven days. The product must disclose this retention window and must not promise immediate deletion from backups.
- Do not store sensitive owner memory until the owner accepts the seven-day recovery window or a separately reviewed crypto-erasure design is available.
- Define an expiry policy for temporary notes and prune expired items through bounded, authenticated maintenance.
- Do not configure additional backups or replication for memory until retention, access, and deletion semantics are understood. Cloudflare D1 Free Time Travel is always on and retains up to seven days of historical database state.
- Document that deleting a live D1 row may not immediately remove provider-managed backups. Never promise complete erasure without evidence.
- Add a privacy-preserving audit trail of memory-management events without logging memory content before enabling the feature.

## Implementation status and remaining gates

- [x] Verify D1 Free limits and mandatory seven-day Time Travel retention; explicitly gate activation on owner acceptance.
- [x] Add encrypted-record schema and test it with synthetic data/local SQLite.
- [x] Implement AES-256-GCM encryption/decryption, fresh 96-bit nonces, AAD binding, and negative tamper/key/metadata tests.
- [x] Implement owner-only CRUD, JSON export, and deletion routes with strict schemas, CSRF on writes, recent-passkey checks, and request throttles.
- [x] Test backend flows with synthetic data only.
- [x] Add an owner-facing memory UI for explicit review, edit, export, and delete actions.
- [x] Add an owner-facing one-tap memory-disable control and explicit enable confirmation; disable preserves encrypted records for inspection or deletion.
- [x] Add opt-in bounded memory retrieval to chat (five records / 4,000 UTF-8 bytes maximum), default-off per request, with untrusted-context labeling and no automatic writes.
- [x] Implement and test bounded resumable key rotation (10 records per call), requiring recent passkey authentication and explicit confirmation; compare-and-set updates prevent overwriting concurrent edits.
- [ ] Independently review key retirement and crypto-erasure; old keys must remain available for at least seven days after the final record rotation.
- [x] Add atomic, content-free SQLite/D1 triggers for create/update/delete and enable/disable events; retain only the newest 200 events, with no memory content, record ID, category, session, or IP.
- [ ] Add scheduled expiry cleanup and separately review whether read/export/retrieval events should be recorded.
- [ ] Review the full design independently before enabling memory for the owner.
- [ ] Require separate deployment and owner approval before storing any real memory.

## Current decision

Keep persistent memory disabled. Backend encryption and CRUD APIs are a tested prototype, not an enabled personal-memory feature. The existing chat remains stateless, with only temporary in-page conversation context.
