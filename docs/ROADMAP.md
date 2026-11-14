# J.A.R.V.I.S. — Delivery Roadmap

## Milestone 0 — Repository foundation
- [x] Keep the public preview separate from the private core repository.
- [x] Create the `jarvis-foundation` development branch.
- [x] Document the architecture and security boundaries.
- [ ] Owner review of the first client implementation (awaiting user review).

## Milestone 1 — Usable client
- [x] Responsive mobile-first command interface.
- [x] Clear preview / service-not-connected status.
- [x] Accessible labeled controls and keyboard submission.
- [x] No simulated AI responses or misleading online claims; test input stays local.

## Milestone 2 — Minimal service
- [x] Select Cloudflare Workers as the provisional backend candidate.
- [x] Connect the public preview repository and configure Cloudflare's production branch as `jarvis-foundation`.
- [ ] Verify the active deployment was built from `jarvis-foundation` and serves the health-only worker scaffold.
- [ ] Verify the live `/health` response and independently confirm zero-cost account/billing status.
- [x] Add zero-dependency tests for the worker health route, unknown routes, and non-GET requests; verified locally with Node.js v22.16.0 (3 passed, 0 failed).
- [ ] Keep credentials on the server only.
- [ ] Add request validation before accepting commands.
- [ ] Add rate limiting and safe error handling.

## Milestone 3 — Owner security and memory
- [x] Document a single-owner passkey, session, privacy, and command-approval design (design only; not implemented or audited).
- [ ] Select and verify a maintained WebAuthn implementation compatible with the Worker runtime.
- [ ] Owner authentication.
- [ ] Session protection and logout.
- [ ] Explicit memory review, correction, export, and deletion.
- [ ] Encrypt sensitive data at rest and in transit.

## Milestone 4 — AI and integrations
- [ ] Verify a no-cost AI path and its limitations before integration.
- [ ] Start with read-only connectors.
- [ ] Require confirmation for messages, sharing, schedule changes, and destructive actions.
- [ ] Require strong confirmation for financial and security actions.

## Non-negotiable constraints
- iPhone-first; no Mac is assumed.
- Zero-cost development; do not enable billing or paid trials.
- Never commit API keys, OAuth secrets, passwords, tokens, or private personal data.
- Do not claim a feature works until it has been tested end to end.
- iOS does not generally allow a third-party web app to continuously listen for a custom wake word in the background. Use supported Shortcuts/Siri entry points instead.
