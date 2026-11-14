# J.A.R.V.I.S. — Public Preview

**Just A Rather Very Intelligent System**

This repository contains the public-facing prototype and non-sensitive project documentation.

> The current website is a visual preview, not a functioning AI assistant. AI, owner authentication, memory, and account integrations are not connected yet.

## Project documents

- [Architecture foundation](docs/ARCHITECTURE.md)
- [Delivery roadmap](docs/ROADMAP.md)
- [Owner security design](docs/SECURITY.md) (proposal only; no authentication is implemented)
- [Authentication implementation plan](docs/AUTHENTICATION_PLAN.md) (candidate libraries, storage, flows, and security tests)
- [Zero-cost authentication test plan](docs/AUTHENTICATION_FREE_TIER_TEST_PLAN.md) (staged local, account-eligibility, and isolated tests; no deployment authorized)
- [Worker runtime compatibility test](docs/WORKER_RUNTIME_TESTING.md) (isolated workerd test harness; execution pending)

## Repository boundaries

- Public preview: this repository. Keep it free of credentials and private user data.
- Private development repository: `jarvis-core`. Do not copy secrets into this public repository.

## Development

The active foundation branch is `jarvis-foundation`. Changes will be developed there first and reviewed before merging into `main`. Runtime compatibility experiments are isolated on `jarvis-worker-runtime-tests` and are not merged into the foundation branch.

Run the worker's zero-dependency tests with `npm test` using Node.js. The six tests cover the health response, strict route matching, unsupported methods, hardened response headers, cache prevention, and HTTPS-only HSTS behavior.

## Constraints

- iPhone-first development; no Mac is assumed.
- Zero-cost approach: no paid services, billing, or auto-renewing trials.
- Do not claim features are operational until verified.
