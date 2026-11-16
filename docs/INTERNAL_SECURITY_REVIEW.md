# J.A.R.V.I.S. — Internal Security Review Notes

**Review type:** Maintainer-assisted static review and synthetic-test review; not an independent audit  
**Reviewed branch:** `jarvis-security-hardening`  
**Review baseline:** `d96dc55667a4bc01bb9653b944651817c9e1f98d`  
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

### 3. Concurrent session activity updates could move the idle timestamp backwards

**Risk:** Two overlapping requests can capture different timestamps and complete their D1 updates out of order. A slower request with an older timestamp could overwrite a newer `last_seen_at`, shortening the effective idle lifetime and causing an avoidable session expiry.

**Change:** Session activity now uses SQLite/D1 `MAX(COALESCE(last_seen_at, created_at), ?)` so a request can never move the stored activity timestamp backwards. The returned activity timestamp is also monotonic relative to the row observed by that request.

**Verification:** Added a regression test that executes a newer touch followed by an older touch and asserts the stored timestamp remains at the newer value. CI run #671 passed.

### 4. Concurrent recovery attempts using the same code

**Risk examined:** An owner may open more than one recovery challenge using the same recovery code. Both challenges can be individually valid, so the final recovery operation must enforce single-use at the recovery-code row itself rather than relying only on challenge consumption.

**Observed control:** `completeOwnerRecovery` atomically claims the recovery-code row using `used_at IS NULL` and a per-attempt claim hash. Credential replacement, deletion of unused old recovery codes, insertion of replacement codes, and session revocation are conditioned on that same claim marker within the D1 batch.

**Verification:** Added a concurrent two-attempt regression test using separate valid recovery challenges but the same underlying recovery-code hash. Exactly one recovery operation must succeed and exactly one active replacement credential must remain. CI run #674 passed.

### 5. CI actions were referenced by mutable version tags

**Risk:** Referencing GitHub Actions by tags alone permits the tag target to change without a repository code change, weakening reproducibility and supply-chain review.

**Change:** The workflow now pins checkout and setup-node to the immutable commit SHAs observed in the successful runner execution, retaining their human-readable version comments. Workflow permissions remain explicitly limited to `contents: read`.

**Verification:** The updated workflow is queued for CI validation. Independent review should still confirm the pinned commits and action provenance.

## Controls observed in the reviewed code

- Single-owner enrollment is gated by a high-entropy bootstrap secret and closes after the owner record exists.
- WebAuthn verification requires user verification and binds challenges to configured origin/RP ID; challenges are short-lived and single-use.
- Session cookies are Secure, HttpOnly for the session token, SameSite=Strict, hashed at rest, and subject to idle and absolute expiry. Concurrent activity touches are monotonic so an out-of-order request cannot shorten the idle window.
- Mutating authenticated routes require same-origin and CSRF checks; sensitive memory operations require recent passkey authentication, except the deliberately immediate memory-disable control.
- Recovery-code use is atomically claimed; recovery replaces credentials/codes and revokes active sessions. Concurrent recovery attempts using different challenges but the same code are covered by a regression test.
- The last active passkey cannot be revoked.
- Memory payloads use AES-256-GCM with fresh nonces and authenticated metadata; keyring parsing is bounded and rejects malformed keys.
- Memory retrieval is off by default and requires an explicit per-message choice; retrieved text is treated as untrusted data.
- The chat route has bounded input/history/output and no tools or external-action capability.
- The CI workflow requests only `contents: read` and pins its two GitHub-maintained actions to immutable commit SHAs.
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

## Verification update

- CI run #674 passed 38 Node/SQLite checks and 60 Workers-runtime checks (98 total), production dependency audit reported zero vulnerabilities, and Wrangler dry-run completed. It includes the monotonic session-touch and concurrent recovery-code double-spend regression tests.
- CI run #677 passed after pinning GitHub Actions to immutable commit SHAs; the 98 tests, production dependency audit, and Wrangler dry run all passed on that workflow revision.
- Earlier run #670 failed because the initial session-touch test fixture queried a non-exported helper; the fixture was corrected, and subsequent runs passed.

## Current safety boundary

No deployment or remote migration was performed by this review. Encrypted-memory migrations `0003` and `0004` remain unapplied to remote D1. Persistent memory remains disabled; no real passkey, personal memory, or chat transcript has been created. Do not treat passing CI or this internal review as production approval.
