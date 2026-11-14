# J.A.R.V.I.S. — Worker Runtime Compatibility Test

**Status:** Harness prepared on `jarvis-worker-runtime-tests`; execution result still needs confirmation.  
**Purpose:** Test the Worker scaffold and the server-side WebAuthn library inside the Cloudflare Workers runtime without deploying to Cloudflare.  
**Cost:** Uses the standard GitHub-hosted runner for this public repository; no paid runner, Cloudflare resource, account secret, or billing change.

## Why this test exists

The existing Node.js test suite checks the Worker handler under Node.js. That is useful, but it does not prove that code and dependencies behave in Cloudflare's `workerd` runtime.

Cloudflare recommends its Workers Vitest integration for this purpose. The `@cloudflare/vitest-plugin` runs tests in the Workers runtime locally through Miniflare/workerd and can load the project's Wrangler configuration.

## Candidate versions for this compatibility experiment

- `@simplewebauthn/server@14.1.0`: current JSR release at the time of this test; its official package listing explicitly names Cloudflare Workers as a supported runtime.
- `@simplewebauthn/browser@14.0.0`: current browser package release; browser behavior still needs separate Safari/iPhone testing.
- `vitest@4.1.0`: minimum version named by Cloudflare's current first-test guide.
- `@cloudflare/vitest-plugin@1.8.2`: current npm release selected for this experiment.

These are test candidates, not production approvals. The CI job installs exact direct versions temporarily with `--no-save --package-lock=false`; no dependencies or lockfile are committed by this experiment. A production dependency lockfile is created only after successful compatibility and security review.

## Tests prepared

### Worker contract

- Health response shape and honest `aiConnected: false` state.
- Exact route matching and query-string behavior.
- Generic 404 for unknown routes.
- Rejection of non-GET methods.
- No-store and security response headers.
- No permissive CORS header.
- HSTS only for HTTPS requests.

### SimpleWebAuthn runtime smoke test

- Import `generateRegistrationOptions` and `generateAuthenticationOptions`.
- Generate both sets of options using Worker runtime cryptography.
- Check challenge encoding, relying-party ID, and required user-verification settings.
- Use synthetic test identifiers only; no real owner credential or passkey is created.

This smoke test does not prove that a real authenticator ceremony, credential verification, session handling, or iPhone Safari flow works. Those require separate tests later.

## CI safety boundaries

The workflow:
- Runs only on pushes to `jarvis-worker-runtime-tests` and pull requests targeting the listed development branches.
- Uses the standard `ubuntu-latest` runner.
- Has read-only repository permissions.
- Does not receive Cloudflare credentials or other secrets.
- Does not run Wrangler deploy, create a Durable Object, or call Cloudflare account APIs.
- Does not alter the production branch.

GitHub documents standard GitHub-hosted runners as free for public repositories. Cloudflare documents that the Workers Vitest integration runs tests in the Worker runtime. Miniflare is not a hardened sandbox, so only trusted project code should be run in it.

## Remaining gates

1. Confirm the GitHub Actions run completed successfully; the GitHub connector currently does not expose the push-triggered run listing.
2. If it fails, inspect the exact install/runtime error and correct the harness before adding authentication code.
3. After the smoke test passes, add negative tests around WebAuthn verification with synthetic fixtures.
4. Separately test the browser package and passkey ceremony in Safari on the owner's iPhone.
5. Only then consider a reviewed authentication implementation. No deployment or personal-data storage is authorized by this test.

## References

- Cloudflare Workers testing: https://developers.cloudflare.com/workers/testing/
- Cloudflare Vitest integration: https://developers.cloudflare.com/workers/testing/vitest-integration/
- Cloudflare first test guide: https://developers.cloudflare.com/workers/testing/vitest-integration/write-your-first-test/
- SimpleWebAuthn server package: https://jsr.io/@simplewebauthn/server
- SimpleWebAuthn browser package: https://jsr.io/@simplewebauthn/browser
- GitHub Actions billing: https://docs.github.com/en/actions/concepts/billing-and-usage
