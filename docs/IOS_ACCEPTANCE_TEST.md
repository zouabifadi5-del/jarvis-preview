# J.A.R.V.I.S. — iPhone Safari Acceptance Test Plan

**Status:** Prepared for a future controlled test. Nothing in this checklist has been performed on the owner's iPhone. The security branch is not deployed, no real passkey is enrolled, and the live D1 database has not received the memory migrations.

## Hard prerequisites

Do not begin real-device testing until a separate release decision authorizes a controlled deployment.

- Confirm the exact HTTPS origin and matching WebAuthn RP ID from the live deployment; never infer them from the repository.
- Confirm the deployed commit, active Worker, D1 database ID, and current account plan.
- Keep billing disabled and verify the intended free-tier limits.
- For authentication-only testing, apply and verify only the reviewed auth migrations. Do not apply memory migrations 0003/0004 or configure memory secrets unless the owner separately accepts the retention model.
- Configure the bootstrap secret only for the one-time owner registration ceremony. Never paste it into chat, source control, screenshots, or logs.
- Use synthetic test data only. Do not store real personal memory during initial acceptance.
- Have an offline recovery-code storage method ready before enrolling a real passkey.

## Test sequence

### A. Safari and passkey enrollment

1. Open the exact HTTPS Worker origin in Safari on the iPhone.
2. Confirm the page loads with no mixed-content warnings and the expected JARVIS title.
3. Complete one-time owner registration using the server-side bootstrap process.
4. Confirm iOS presents the platform passkey / Face ID or passcode flow.
5. Confirm registration returns a session and one-time recovery codes; save the codes offline and verify they are not shown again on refresh.
6. Attempt a second registration and confirm enrollment is closed.
7. Confirm the passkey is visible in iOS Passwords / passkey management as expected.

### B. Authentication and session protections

1. Sign out, then sign in with the enrolled passkey.
2. Refresh Safari and confirm the session behaves as designed without localStorage or sessionStorage tokens.
3. Confirm a request without the CSRF token cannot perform a state-changing action.
4. Confirm a wrong-origin request is rejected.
5. Sign out and confirm authenticated endpoints reject the old session.
6. Use “sign out everywhere” and confirm all active sessions are revoked.
7. Test idle expiry and absolute expiry using a controlled test environment; do not weaken production timeouts to make this test easier.
8. Add a second passkey, verify it, and revoke it. Confirm the last active passkey cannot be revoked.
9. Test one-time recovery with a synthetic recovery code; confirm the used code cannot be replayed and old credentials/sessions are revoked.

### C. iPhone home-screen experience

1. In Safari, use Share → Add to Home Screen.
2. Launch the installed web app from the Home Screen.
3. Check portrait and landscape layouts, safe-area insets, keyboard behavior, scrolling, and button reachability.
4. Confirm passkey prompts work from both Safari and the Home Screen launch context.
5. Confirm reload and sign-out clear in-page chat history.

### D. Memory safeguards — separate approval required

Do not run this section until the owner explicitly accepts D1's provider-managed retention window and separately approves memory activation.

1. Verify migrations 0003 and 0004 are applied to the intended D1 database.
2. Configure a newly generated server-side keyring without exposing its values to the browser or logs.
3. Confirm memory remains disabled before the owner enables it.
4. Save synthetic memory, inspect it, edit it, export it, and delete it.
5. Confirm D1 stores ciphertext only and the audit table stores only event type and timestamp metadata.
6. Confirm ordinary chat does not retrieve memory.
7. Tick the one-message memory checkbox, send one message, and verify the checkbox resets even if the request fails.
8. Confirm memory retrieval fails closed when memory is disabled or a key version is missing.
9. Test key rotation in batches of at most 10; repeat until no old-version records remain. Verify the content decrypts after rotation.
10. Keep old keys for at least seven days after final rotation before considering retirement.
11. Confirm the daily 02:00 UTC cleanup is inactive unless the retention-acceptance flag is true; after approval, verify expired synthetic rows are pruned without decrypting content.

### E. Stop conditions

Stop the test and do not store personal data if any of these occur:

- Passkey prompt appears for an unexpected origin or RP ID.
- A logged-out or unauthenticated browser can access private endpoints.
- CSRF or origin checks can be bypassed.
- Recovery codes can be replayed.
- Plaintext memory, session tokens, bootstrap secrets, or encryption keys appear in logs, browser storage, or D1.
- The Worker invokes AI without the owner's authenticated request, or saved memory is injected without per-message opt-in.
- A deployment, migration, or configuration change would affect the live account outside the approved scope.

Record only pass/fail outcomes and non-sensitive diagnostics. Never capture or share passkey secrets, recovery codes, session cookies, encryption keys, or personal memory text.
