# J.A.R.V.I.S. — Delivery Roadmap

## Milestone 0 — Repository foundation
- [x] Keep the public preview separate from the private core repository.
- [x] Create the `jarvis-foundation` development branch.
- [x] Document the architecture and security boundaries.
- [ ] Review and approve the first client implementation.

## Milestone 1 — Usable client
- [ ] Responsive mobile-first command interface.
- [ ] Clear offline / preview / service-connected status.
- [ ] Accessible controls and keyboard support.
- [ ] No fake AI responses or misleading "online" claims.

## Milestone 2 — Minimal service
- [ ] Choose a genuinely free backend/runtime.
- [ ] Keep credentials on the server only.
- [ ] Add a health endpoint and basic request validation.
- [ ] Add rate limiting and safe error handling.

## Milestone 3 — Owner security and memory
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
