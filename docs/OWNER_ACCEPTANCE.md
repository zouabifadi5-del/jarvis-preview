# J.A.R.V.I.S. — Owner Acceptance and Simulation Checklist

**Status (16 November 2026):** Prepared for a future controlled acceptance test. Do not perform these steps against production until the deployment and owner-enrollment gates have been explicitly approved.

## Current safe simulation

The isolated `jarvis-security-hardening` branch can be validated without production access:

- Run the local SQLite/Node test suite for D1 schema and storage helpers.
- Run the Workers runtime suite with synthetic WebAuthn credentials and a mocked `env.AI.run()`.
- Check browser JavaScript syntax and Wrangler configuration with `deploy --dry-run`.
- Verify the chat route rejects missing sessions, missing/invalid CSRF tokens, malformed payloads, system-role injection, oversized context, and exhausted budgets.
- Confirm the chat response is not persisted and the client clears temporary history on reload or sign-out.

A mocked AI response proves request handling and UI wiring only. It does not prove that Cloudflare inference works or that the model's answer quality is acceptable.

## Release prerequisites

- [ ] Confirm the intended production hostname and exact Worker branch/commit.
- [ ] Confirm the account remains on a genuinely free plan; do not enable billing, Paid plans, prepaid credits, or paid add-ons.
- [ ] Review the complete dependency tree and commit a reproducible lockfile.
- [ ] Independently review the authentication and authorization implementation.
- [ ] Verify D1 migrations and disposable synthetic-data cleanup on the intended database.
- [ ] Verify required secret bindings are present without reading or logging their values.
- [ ] Verify the WebAuthn RP ID exactly matches the production hostname.
- [ ] Obtain explicit release approval before deployment or first owner enrollment.

## iPhone Safari passkey acceptance

Use the iPhone 17 Pro Max with current iOS Safari over HTTPS. Do not paste bootstrap secrets or recovery codes into screenshots, logs, support messages, or chat.

1. Open the verified JARVIS origin and confirm the certificate/hostname are correct.
2. Enroll the owner's passkey once using the approved bootstrap flow.
3. Save the one-time recovery codes offline; acknowledge the recovery-code screen only after confirming they are stored safely.
4. Sign out, reload, and sign in using the passkey. Confirm the old session cannot be reused after rotation.
5. Verify a wrong-origin request, expired challenge, replayed challenge, invalid CSRF request, and malformed request are rejected.
6. Verify session idle expiry and absolute expiry; verify logout and logout-all revoke sessions.
7. Add a second passkey only after recent passkey reauthentication. Confirm the last active credential cannot be revoked.
8. Test one recovery code with a replacement passkey. Confirm old sessions are revoked and all prior recovery codes are rotated.
9. Confirm no private content appears in public assets, URLs, browser localStorage, analytics, or application logs.
10. Confirm sign-out clears the in-page conversation and that a reload does not restore it.

## First live AI smoke test

Only after the security release gates and iPhone passkey acceptance pass:

- Obtain separate owner approval for a low-volume live inference test.
- Check current account-wide free Workers AI quota before making a request.
- Send a non-sensitive test prompt in English, French, Modern Standard Arabic, and Tunisian Arabic.
- Confirm the reply is bounded, no chat text is stored, and the usage ceiling is enforced.
- Stop if the model is unavailable or quota is exhausted. Never switch to a paid provider or enable billing.

## Current non-goals

- No always-on custom wake word in iOS background.
- No persistent personal memory until encrypted storage, owner review/edit/export/delete, backup semantics, and independent review are implemented.
- No connected personal accounts or external actions.
- No production deployment or first owner enrollment until the release prerequisites are satisfied.
