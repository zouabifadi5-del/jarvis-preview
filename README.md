# J.A.R.V.I.S. — Public Preview

**Just A Rather Very Intelligent System**

This repository contains the public-facing prototype and non-sensitive project documentation.

> The current website is a visual preview, not a functioning AI assistant. Initial owner-authentication routes and a first-party passkey browser client are being tested on an isolated branch; they are not deployed or connected to a real database. AI, memory, and account integrations are not connected.

## Project documents

- [Architecture foundation](docs/ARCHITECTURE.md)
- [Delivery roadmap](docs/ROADMAP.md)
- [Owner security design](docs/SECURITY.md) (design and implementation in progress; not deployed or security-audited)
- [Authentication implementation plan](docs/AUTHENTICATION_PLAN.md) (current route implementation, storage design, flows, and remaining security gates)
- [Zero-cost authentication test plan](docs/AUTHENTICATION_FREE_TIER_TEST_PLAN.md) (staged local, account-eligibility, and isolated tests; no deployment authorized)
- [Worker runtime compatibility test](docs/WORKER_RUNTIME_TESTING.md) (isolated workerd test harness; latest verified run #132 has 35 runtime tests plus 15 local SQLite/Node tests, browser syntax check, and Wrangler dry run)

## Repository boundaries

- Public preview: this repository. Keep it free of credentials and private user data.
- Private development repository: `jarvis-core`. Do not copy secrets into this public repository.

## Development

The active foundation branch is `jarvis-foundation`. Changes will be developed there first and reviewed before merging into `main`. Runtime compatibility experiments, the owner passkey interface, and Workers Static Assets configuration are isolated on `jarvis-worker-runtime-tests` and are not merged into the foundation branch or deployed.

Run the worker's zero-dependency tests with `npm test` using Node.js. They cover the health response, strict route matching, unsupported methods, hardened response headers, cache prevention, HTTPS-only HSTS behavior, and static-shell safety/configuration.

## Constraints

- iPhone-first development; no Mac is assumed.
- Zero-cost approach: no paid services, billing, or auto-renewing trials.
- Do not claim features are operational until verified.
