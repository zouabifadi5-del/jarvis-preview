# J.A.R.V.I.S. — Internal Security Review Notes

**Review type:** Maintainer-assisted static review and synthetic-test review; not an independent audit  
**Reviewed branch:** `jarvis-security-hardening`  
**Review baseline:** `72da0123ce8528679f56eab6e29c5c185957b757`  
**Date:** 16 November 2026

## Scope examined

- WebAuthn owner enrollment, login, recovery, challenge consumption, and credential lifecycle
- Session token hashing, cookie attributes, idle/absolute expiry, CSRF verification, and logout
- IP- and session-derived rate-limit buckets
- AES-GCM memory encryption, AAD binding, keyring parsing, memory CRUD, key rotation, and expiry cleanup
- Chat request bounds, explicit per-request memory opt-in, and untrusted-context serialization
- Synthetic D1/SQLite and Workers-runtime tests, plus CI dependency audit and Wrangler dry run

This is a code-level review of the isolated prototype. It does not prove production security, does not inspect secret values, and is not a substitute for an independent reviewer or live-device validation.

## Findings addressed

### 1. Memory key rotation lacked endpoint throttling

**Risk:** The rotation route required a recent passkey and CSRF token but was omitted from the route-specific per-session and per-IP rate-limit policies.

**Change:** Added a 10-request-per-minute per-session limit and a 30-request-per-minute per-IP limit for `POST /auth/memories/rotate`.

**Verification:** Added a regression test that exercises the authenticated-session limit. Included in CI run #661 and subsequent runs.

### 2. A stale memory edit could overwrite a concurrent key rotation

**Risk:** An edit could read a record under an old key, pause while a rotation changed the record to the current key, then update by record ID alone. That could restore ciphertext encrypted under the old key after rotation had apparently completed.

**Change:** Memory edits now use compare-and-set against the expected key version, ciphertext, and nonce. A stale write is rejected with HTTP 409 (`memory_changed_retry`), and the UI tells the owner to reopen the record before retrying.

**Verification:** Added a local SQLite regression test proving a stale edit cannot overwrite a newer encrypted record. Included in CI run #661 and subsequent runs.

## Controls observed in the reviewed code

- Single-owner enrollment is gated by a high-entropy bootstrap secret and closes after the owner record exists.
- WebAuthn verification requires user verification and binds challenges to configured origin/RP ID; challenges are short-lived and single-use.
- Session cookies are Secure, HttpOnly for the session token, SameSite=Strict, hashed at rest, and subject to idle and absolute expiry.
- Mutating authenticated routes require same-origin and CSRF checks; sensitive memory operations require recent passkey authentication, except the deliberately immediate memory-disable control.
- Recovery-code use is atomically claimed; recovery replaces credentials/codes and revokes active sessions.
- The last active passkey cannot be revoked.
- Memory payloads use AES-256-GCM with fresh nonces and authenticated metadata; keyring parsing is bounded and rejects malformed keys.
- Memory retrieval is off by default and requires an explicit per-message choice; retrieved text is treated as untrusted data.
- The chat route has bounded input/history/output and no tools or external-action capability.
- Scheduled expiry cleanup is a no-op unless the explicit retention-acceptance flag is enabled.

These are implementation observations, not guarantees against all threats. Production behavior still depends on correct runtime configuration and provider semantics.

## Open release gates

- Independent security review of authentication, recovery, memory encryption, key rotation, rate limiting, and deployment configuration.
- Real iPhone Safari passkey enrollment/login/recovery and PWA acceptance testing.
- Verify the exact production origin, RP ID, and required secret configuration without revealing secret values.
- Run controlled integration tests against the live D1 database using disposable synthetic records, after a separate deployment approval.
- Decide whether inspect, export, and retrieval events should be audited; preserve the privacy rationale.
- Complete independent review of old-key retirement and crypto-erasure. Keep old keys until every live record is on the current key and at least seven days have elapsed after final rotation.
- Obtain explicit owner acceptance of the D1 seven-day Time Travel retention window before enabling durable memory.

## Current safety boundary

No deployment or remote migration was performed by this review. Encrypted-memory migrations `0003` and `0004` remain unapplied to remote D1. Persistent memory remains disabled; no real passkey, personal memory, or chat transcript has been created. Do not treat passing CI or this internal review as production approval.
