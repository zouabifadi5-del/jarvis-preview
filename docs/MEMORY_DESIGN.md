# J.A.R.V.I.S. — Private Memory Design

**Status (16 November 2026):** Design only. No owner memories or chat transcripts are stored. The stateless chat route retains only a bounded recent conversation in browser page memory; it is cleared on reload or sign-out.

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
- Keep a random 256-bit encryption key only in a Cloudflare Worker secret named `JARVIS_MEMORY_ENCRYPTION_KEY`. Never store it in D1, Wrangler files, browser code, Git, logs, or the model prompt.
- Version the key and ciphertext format so future key rotation can be tested. Bind record ID, owner ID, schema version, and key version as authenticated additional data (AAD).
- Store ciphertext, nonce, key version, owner ID, record ID, timestamps, and non-sensitive lifecycle fields only. Avoid plaintext titles, tags, summaries, or search indexes in the first version.
- Fail closed if the encryption key is absent, malformed, or has the wrong length. Do not fall back to plaintext storage.
- Decrypt only after owner-session and CSRF checks. Never expose bulk decrypted memory to the browser unless the owner requests an export or inspection.

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

- Define an expiry policy for temporary notes and prune expired items through bounded, authenticated maintenance.
- Do not enable backups or replication for memory until retention, access, and deletion semantics are understood.
- Document that deleting a live D1 row may not immediately remove provider-managed backups. Never promise complete erasure without evidence.
- Keep an audit trail of memory-management events without logging memory content.

## Implementation gates

1. Verify current D1 Free limits and backup/retention behavior before adding a memory table.
2. Add a migration for encrypted records only; test it with synthetic ciphertext and local SQLite.
3. Implement AES-GCM encryption/decryption and AAD validation with negative tests for tampering, nonce mismatch, wrong key version, and wrong owner ID.
4. Add owner-only CRUD, export, correction, and deletion routes with CSRF, recent-passkey checks for export/bulk deletion, strict schemas, rate limits, and audit metadata.
5. Test all flows using synthetic data; no personal data in CI.
6. Review the full design independently before enabling memory for the owner.
7. Require separate deployment and owner-enrollment approval before storing any real memory.

## Current decision

Do not implement or enable persistent memory until these gates are satisfied. The existing chat prototype remains stateless, with only temporary in-page conversation context.
