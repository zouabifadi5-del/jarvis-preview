# J.A.R.V.I.S. — Zero-Cost AI Provider Plan

**Status (16 November 2026):** Provider research and a stateless owner-only chat implementation are complete on the isolated branch. No real inference request has been made; the route is tested with a mock AI binding and remains undeployed.

## Non-negotiable cost boundary

- Use Cloudflare Workers AI only while the account remains on Workers Free and the selected model is eligible for the Free plan.
- Cloudflare currently includes 10,000 Neurons per day at no charge. The daily allocation resets at 00:00 UTC. On Workers Free, requests beyond the allocation fail; they do not automatically become paid usage. Do not change the account to Workers Paid, add prepaid AI Gateway credits, or enable billing to bypass a limit.
- Some models require Workers Paid or prepaid credits. Do not use them, even if their model pages show a token price.
- Monitor the daily Neuron allocation and impose an application-side usage ceiling below the provider limit. If quota or capacity is exhausted, return a clear temporary-unavailable response; never offer an upgrade or silently switch to a paid route.
- The free allocation is shared across eligible Workers AI models for the account, not reserved exclusively for JARVIS. Check current account usage before enabling any live inference.

Official pricing: https://developers.cloudflare.com/workers-ai/platform/pricing/

## Candidate models

### Primary text-chat candidate: `@cf/zai-org/glm-4.7-flash`

Cloudflare identifies this as available on Workers Free. It supports multilingual dialogue, instruction-following, reasoning, and multi-turn function calling, with a 131,072-token context window. Cloudflare describes it as optimized for multilingual dialogue and fast inference.

Model page: https://developers.cloudflare.com/workers-ai/models/glm-4.7-flash/  
Free-plan availability: https://developers.cloudflare.com/changelog/post/2026-07-28-models-require-workers-paid/  
Model introduction: https://developers.cloudflare.com/changelog/post/2026-02-13-glm-4.7-flash-workers-ai/

### Secondary candidate for vision and broader multimodal work: `@cf/google/gemma-4-26b-a4b-it`

Cloudflare identifies this as available on Workers Free. It supports function calling, reasoning, and vision, has a 256,000-token context window, and is multilingual with out-of-the-box support for 35+ languages and pretraining across 140+ languages. Its vision capabilities may be useful later for documents, images, screenshots, and OCR.

Model page: https://developers.cloudflare.com/workers-ai/models/gemma-4-26b-a4b-it/  
Model introduction: https://developers.cloudflare.com/changelog/post/2026-04-04-gemma-4-26b-a4b-workers-ai/

The documentation does not establish reliable Tunisian Arabic dialect quality for either model. Before choosing a permanent default, test both with a small, non-sensitive evaluation set covering Tunisian Arabic, Modern Standard Arabic, French, English, code, instruction following, and tool-call accuracy. Do not submit personal records or secrets during model evaluation.

## Integration design

- Use the native Workers AI binding (`env.AI.run()`) from the Worker. No third-party provider key is required for this binding.
- A stateless `POST /auth/chat` route and an owner-only browser chat panel now exist on the isolated branch. The route requires an active owner session and CSRF token, accepts one message of at most 6,000 characters, and returns a bounded reply. It does not persist conversation text or expose tools.
- Chat calls are capped at 10 per session per minute, 30 per client IP per minute, and 50 per owner per UTC day using HMAC-derived D1 buckets. The 50-request daily cap is an application-side safety ceiling, not a guarantee of exact Neuron usage; it leaves margin below the provider's 10,000-Neuron daily allocation.
- The isolated branch's `wrangler.toml` declares `[ai] binding = "AI"` for deployment. `wrangler.test.toml` intentionally omits that binding so local workerd tests do not open a remote AI proxy or consume the account's daily quota.
- All chat routes must require a valid owner session and CSRF protection for state-changing requests. Apply per-session and per-IP limits, strict JSON schemas, input/output size caps, bounded generation tokens, and request timeouts.
- The model must never receive direct access to arbitrary shell, SQL, filesystem, or unrestricted network tools. Tool calls must be mapped to a server-side allowlist and validated independently.
- Start with stateless chat: do not persist prompts, replies, or memory until data retention, encryption, backup, export, deletion, and access controls are designed and tested.
- Model output, retrieved content, and tool-call arguments are untrusted. A model response is never authorization to send messages, share files, change schedules, spend money, or change security settings.
- Tests must stub `env.AI.run()`. Do not run real inference in local development, CI, or automated tests because Workers AI calls can reach the Cloudflare account and consume the free daily allocation.
- A successful Wrangler dry run is not proof that a live AI binding or model request works. The first live inference test must be an owner-approved, low-volume smoke test after the deployment and authentication gates are met.

Workers AI binding documentation: https://developers.cloudflare.com/workers-ai/configuration/bindings/  
Function-calling documentation: https://developers.cloudflare.com/workers-ai/features/function-calling/

## Explicit exclusions

Do not use models that Cloudflare marks as Workers Paid-only, including `@cf/moonshotai/kimi-k2.6`, `@cf/moonshotai/kimi-k2.7-code`, and `@cf/zai-org/glm-5.2`, unless the owner later changes the zero-budget constraint. Do not configure AI Gateway Unified Billing or prepaid credits for this project.

## Current implementation status

The stateless chat route, owner-only UI, HMAC-backed per-session/per-IP throttles, and 100-request UTC-day budget are implemented on `jarvis-security-hardening`. Synthetic tests use a mocked `env.AI.run()` binding; no real inference has been performed. CI run #413 passed 25 local SQLite/Node checks and 51 Workers-runtime tests (76 total), plus the dependency audit, browser syntax check, and Wrangler dry run: https://github.com/zouabifadi5-del/jarvis-preview/actions/runs/43882501898. The route is not deployed, and no owner conversation data is stored.

## Next steps

1. Keep authentication and deployment gates separate from AI feature development.
2. Add a small owner-only evaluation harness for GLM-4.7-Flash and Gemma 4; no real inference in CI.
3. Only after authentication is safely deployed and tested, request explicit approval for one live, low-volume inference smoke test.
4. Build memory only after its security and lifecycle design is approved and implemented.
