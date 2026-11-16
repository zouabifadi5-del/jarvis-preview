# J.A.R.V.I.S. — Phase 4 Verification and Release Gate Checklist

**Status:** Preparation only; no deployment or remote mutation authorized by this checklist  
**Branch:** `jarvis-security-hardening`  
**Purpose:** Keep independent review, configuration verification, controlled integration testing, and iPhone acceptance separate from implementation CI.

## 1. Independent security review — required

A reviewer other than the implementer should inspect the exact commit proposed for release and record findings with severity, evidence, affected code, and a retest result.

- [ ] WebAuthn registration, authentication, origin/RP-ID binding, user-verification enforcement, challenge expiry, and replay handling.
- [ ] Recovery-code entropy, storage hashes, single-use behavior under concurrent requests, credential replacement, and session revocation.
- [ ] Session cookie attributes, idle and absolute expiry, CSRF validation, logout races, and credential lifecycle.
- [ ] Rate-limit atomicity, bucket derivation, IP trust boundary, retention cleanup, and daily inference budget.
- [ ] AES-GCM nonce/AAD handling, keyring parsing, rotation concurrency, stale writes, backup retention, and key retirement.
- [ ] Prompt/history/memory boundaries, output limits, provider failure handling, and absence of privileged tools.
- [ ] Worker routing, static asset headers, secret handling, D1 bindings, cron configuration, and deployment workflow.
- [ ] Dependency provenance, lockfile reproducibility, audit output, and build pipeline permissions.

**Acceptance:** No unresolved critical/high findings. Medium/low findings must have an explicit mitigation or owner-approved deferral. The reviewer must not be the author of the reviewed changes.

## 2. Configuration verification — read-only until separately approved

- [ ] Confirm account remains within the user's zero-cost constraint; do not enable billing, paid add-ons, or trials.
- [ ] Confirm the intended Worker name, environment, branch/commit, and deployment target.
- [ ] Enable branch protection for the release branch: require pull requests, require the Worker runtime CI check, block force pushes, and restrict direct pushes where available. **Current observation:** `jarvis-security-hardening` is not protected.
- [ ] Verify `AUTH_ORIGIN` is the exact HTTPS origin served by the Worker.
- [ ] Verify `WEBAUTHN_RP_ID` is the exact host corresponding to that origin.
- [ ] Verify required bootstrap and HMAC secrets are present, sufficiently random, and correctly scoped without printing or retrieving their values.
- [ ] Verify D1 binding points to the intended database; remember D1 is account-scoped, not branch-scoped.
- [ ] Confirm memory retention acceptance is absent/false and memory encryption key settings are absent until separately accepted.
- [ ] Confirm cron schedule and retention gate are correct.
- [ ] Confirm no public preview origin can call owner-authenticated routes.

Do not paste secrets, recovery codes, cookies, or private keys into review notes, chat, GitHub issues, or logs.

## 3. Controlled integration test — separate deployment approval required

Use disposable synthetic data only. Do not use personal memory or real recovery codes.

- [ ] Back up/record the current remote D1 migration state and confirm rollback path.
- [ ] Confirm the exact target database ID and current schema before any migration.
- [ ] Review migrations `0003` and `0004` independently before application.
- [ ] Deploy only the approved commit to the intended non-production Worker target.
- [ ] Verify health, static asset delivery, HTTPS, CSP/security headers, and exact origin behavior.
- [ ] Exercise one-owner registration, login, session rotation, logout, logout-all, and credential revocation.
- [ ] Exercise invalid origin/RP ID, invalid user verification, expired/replayed challenges, and recovery-code double-spend attempts.
- [ ] Exercise CSRF failures, expired/idle sessions, rate-limit boundaries, and concurrent requests.
- [ ] If memory testing is explicitly approved, use synthetic records to test encrypt/read/edit/export/delete, disable, rotation, expiry cleanup, and backup-retention disclosures.
- [ ] Verify no prompts, memory plaintext, cookies, secrets, or recovery codes appear in logs.
- [ ] Record observed results and remove synthetic data using the approved cleanup path.

No live migration or deployment is implied by completing this document.

## 4. iPhone 17 Pro Max acceptance — owner-operated

- [ ] Use Safari on the intended HTTPS origin.
- [ ] Enroll a passkey and verify Face ID/device-passcode confirmation.
- [ ] Log in, reload, close/reopen Safari, and verify session behavior.
- [ ] Test logout and logout-all from the UI.
- [ ] Test recovery using a disposable test code and confirm replacement credentials/codes.
- [ ] Add/revoke a secondary test passkey; verify the last active passkey cannot be revoked.
- [ ] Add the PWA to the Home Screen and verify viewport, safe-area, offline/error, and navigation behavior.
- [ ] Verify microphone/voice behavior only while foregrounded; iOS web apps cannot continuously listen for a custom wake word in the background.
- [ ] Do not enable persistent personal memory until retention and deletion behavior are explicitly accepted.

## 5. Rollback and incident readiness

- [ ] Identify the last known-good Worker version and exact rollback command/process.
- [ ] Preserve a migration ledger and a tested database recovery procedure.
- [ ] Define who can revoke sessions, rotate compromised secrets, and disable memory.
- [ ] Confirm secret rotation does not remove old memory decryption keys before all records and backup-retention windows are accounted for.
- [ ] Define a contact path for reporting security findings without publishing exploit details.

## Current known state

- Synthetic CI validates the isolated branch; it is not a production security certification.
- Remote D1 currently has only authentication migrations `0001` and `0002`; encrypted-memory migrations `0003` and `0004` are not applied.
- The live Worker has not been validated end-to-end with the branch authentication routes.
- No real passkey, personal memory, or real AI inference has been exercised.
- Independent review and owner-operated iPhone testing remain external gates.
