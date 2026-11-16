# J.A.R.V.I.S. — Public Preview

**Just A Rather Very Intelligent System**

This repository contains the public-facing prototype and non-sensitive project documentation.

> The foundation website remains a visual preview, not a deployed AI assistant. The isolated `jarvis-security-hardening` branch contains synthetic-tested owner passkey enrollment/login, session protection, multi-device credential management, recovery, and a stateless owner-only chat route. The chat route is tested with a mocked AI binding; no real inference has been made. The branch is not deployed, no owner passkey is enrolled, and no conversation memory or account integrations are connected.

## Project documents

- [Architecture foundation](docs/ARCHITECTURE.md)
- [Delivery roadmap](docs/ROADMAP.md)
- [Owner security design](docs/SECURITY.md) (design and implementation in progress; not deployed or security-audited)
- [Authentication implementation plan](docs/AUTHENTICATION_PLAN.md) (current route implementation, storage design, flows, and remaining security gates)
- [Zero-cost AI provider plan](docs/AI_PROVIDER_PLAN.md) (Workers AI Free quota, model candidates, privacy and integration gates; no inference enabled)
- [Private memory design](docs/MEMORY_DESIGN.md) (encrypted owner-controlled memory; design only, no personal data stored)
- [Zero-cost authentication test plan](docs/AUTHENTICATION_FREE_TIER_TEST_PLAN.md) (staged local, account-eligibility, and isolated tests; no deployment authorized)
- [Worker runtime compatibility test](docs/WORKER_RUNTIME_TESTING.md) (isolated workerd test harness; verified run #428 has 51 runtime tests plus 25 local SQLite/Node tests, dependency audit, browser syntax check, and Wrangler dry run)

## Repository boundaries

- Public preview: this repository. Keep it free of credentials and private user data.
- Private development repository: `jarvis-core`. Do not copy secrets into this public repository.

## Development

The active foundation branch is `jarvis-foundation`. Changes will be developed there first and reviewed before merging into `main`. Runtime compatibility experiments, owner authentication/recovery routes, per-IP and per-session throttling, strict request-field validation, the browser interface, and Workers Static Assets configuration are isolated on `jarvis-security-hardening` and are not merged into the foundation branch or deployed.

Run the worker's zero-dependency tests with `npm test` using Node.js. They cover the health response, strict route matching, unsupported methods, hardened response headers, cache prevention, HTTPS-only HSTS behavior, and static-shell safety/configuration.

## Constraints

- iPhone-first development; no Mac is assumed.
- Zero-cost approach: no paid services, billing, or auto-renewing trials.
- Do not claim features are operational until verified.
