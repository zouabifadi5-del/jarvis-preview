# J.A.R.V.I.S. — Private Memory Design

**Status (16 November 2026):** Encrypted memory storage helpers and owner-only API routes (create, list, inspect, update, export, delete-one, delete-all) are implemented on `jarvis-security-hardening` with synthetic tests. Memory remains disabled unless both the explicit D1-retention acceptance flag and a valid server-side encryption key are configured. No owner memory or chat transcript has been stored. The iPhone-first owner UI supports explicit save, list, inspect, edit, export, and delete actions. Model retrieval integration, a one-tap memory-disable control, key-rotation workflow, and management audit trail are still outstanding. The stateless chat route retains only bounded recent conversation in browser page memory; it clears on reload or sign-out.

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
- Keep a random 256-bit encryption key only in a Cloudflare Worker secret named `JARVIS_MEMORY_ENCRYPTION_KEY`. Never store it in D1, Wrangler files, browser code, Git, logs, or the model prompt. The current code accepts key version 1 only; do not rotate or replace the key until a reviewed rotation/migration procedure exists.
- Version the key and ciphertext format so future key rotation can be tested. Bind record ID, owner ID, schema version, and key version as authenticated additional data (AAD).
- Store ciphertext, nonce, key version, owner ID, record ID, timestamps, and non-sensitive lifecycle fields only. Avoid plaintext titles, tags, summaries, or search indexes in the first version.
- Fail closed if the encryption key is absent, malformed, or has the wrong length. Do not fall back to plaintext storage.
- Decrypt only after owner-session checks; require CSRF for writes and recent passkey authentication for creation, editing, export, and deletion. Never expose bulk decrypted memory to the browser unless the owner requests an export or inspection.

## Retrieval and prompt safety

- Start with a small bounded set of recent memories and decrypt them server-side only for the authenticated owner.
- Treat each memory as untrusted data, not as system instructions or authorization. Clearly delimit retrieved memory in the model prompt.
- The model may use memories to tailor answers, but cannot create, edit, or delete durable memory without an explicit owner action.
- Do not give the model arbitrary SQL, filesystem, shell, or unrestricted network tools.

## Owner controls

- List memories with minimal metadata and timestamps.
- Open and inspect one memory at a time.
- Edit by decrypting, validating, and re-encrypting with a fresh nonce.
- Export a user-readable JSON file only after recent passkey confirmation; do not include encryption keys.
- Delete an individual memory or all memories only after an explicit, high-assurance confirmation. Do not claim deletion from backups until the provider's backup retention and purge behavior has been verified.
- Provide a visible memory status and a way to disable memory use without deleting the account.

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
- [ ] Add a one-tap memory-disable control.
- [ ] Add bounded memory retrieval to chat, with retrieved text treated as untrusted context and no automatic writes.
- [ ] Implement and test key rotation, crypto-erasure options, expiry pruning, and privacy-preserving management audit events.
- [ ] Review the full design independently before enabling memory for the owner.
- [ ] Require separate deployment and owner approval before storing any real memory.

## Current decision

Keep persistent memory disabled. Backend encryption and CRUD APIs are a tested prototype, not an enabled personal-memory feature. The existing chat remains stateless, with only temporary in-page conversation context.
