# JARVIS OpenClaw Adoption Assessment

**Status:** Architecture decision recorded; no upstream code imported, no merge, no deployment, and no paid services authorized.

## Decision

Use the upstream OpenClaw project as the primary assistant runtime candidate, subject to a staged compatibility and security review. Keep JARVIS as the owner-controlled product identity, policy layer, and private integration project. Do not rewrite OpenClaw from scratch.

Upstream:
- Repository: https://github.com/openclaw/openclaw
- License: MIT
- Upstream version observed during assessment: 2026.11.3
- Official iOS app documentation: https://docs.openclaw.ai/platforms/ios

The MIT license permits copying and modification, provided the copyright and license notice are retained in copies or substantial portions. Preserve upstream notices and clearly document JARVIS modifications.

## Why this is the lead candidate

The upstream README describes:
- A Gateway acting as the control plane for sessions, tools, events, and channels.
- Companion apps and nodes, including iOS and Android.
- Extensible tools, skills, plugins, and multiple model providers, including local models.
- State, memory, and credentials stored on the operator's own hardware by default.
- A self-hosted installation path without a mandatory hosted subscription.

The official iOS platform documentation describes an iPhone app that pairs with a Gateway over WebSocket (LAN or tailnet), supports voice/Talk and voice wake capabilities, and can invoke approved device-node actions. The documented minimum is iOS 26.2; the owner's iPhone is on a newer iOS release.

## Fit against JARVIS constraints

| Requirement | Assessment |
|---|---|
| iPhone-first | Native iOS companion app exists; verify actual wake-word and background behavior on owner's device. |
| No Mac | Mac is not required for the Gateway; a supported always-on Windows/Linux host is still needed. |
| Zero cost | Software is MIT/open source; hosting hardware and model inference must also remain free. |
| Private owner-only assistant | Must configure pairing, Gateway authentication, device permissions, and a strict single-owner policy. |
| Persistent memory | Upstream has memory facilities; assess storage, retention, export, and deletion before enabling. |
| Voice activation | iOS app documents Voice Wake/Talk; test with the owner's iPhone and actual iOS permission behavior. |
| Proactive skills/automation | Supported through skills/tools; all actions need an explicit allowlist and confirmation boundaries. |

## Critical constraints and risks

1. OpenClaw's Gateway is a Node.js application, not a Cloudflare Worker. The existing Cloudflare Worker/D1 project must remain the JARVIS identity/authentication and lightweight API layer; it cannot host the full OpenClaw runtime as-is.
2. A Gateway needs a running host. First investigate whether the owner's existing Windows gaming laptop can run it at zero additional cost. Do not assume it is always online.
3. A free local model is only practical if the host has sufficient RAM/VRAM and acceptable inference speed. Do not connect paid model APIs or trials. If local inference is too slow, report that limitation rather than silently switching to a paid provider.
4. OpenClaw's README warns that tools in the main session can run on the host. Sandboxing, tool allowlists, channel pairing, and remote exposure controls must be reviewed before granting capabilities.
5. The iOS app's capabilities do not mean iOS permits an arbitrary third-party app to run a permanently listening wake-word service under all conditions. Verify actual behavior; retain Siri/Shortcuts/manual launch as fallback if required.
6. Do not expose the Gateway directly to the public internet. Prefer LAN or a properly secured private tailnet after reviewing whether its free tier meets the owner's needs.
7. Never store secrets, passkeys, private conversations, or personal memory in this public repository.

## JARVIS integration boundaries

- Keep `jarvis-core` private and untouched unless explicitly authorized.
- Keep the existing `jarvis-preview` owner-auth work isolated on `jarvis-worker-runtime-tests`; do not merge or deploy it.
- Preserve the existing D1 database `jarvis-owner-auth` solely for owner authentication metadata and rate-limit records. Do not use it for conversations or assistant memory.
- Do not copy OpenClaw into the Cloudflare Worker. Run the Gateway as a separate process on an owner-controlled host.
- Integrate only through documented, authenticated interfaces. Treat the Gateway as a privileged component and place JARVIS owner authorization in front of any sensitive action.
- Retain the upstream MIT license and copyright notice in any copied or modified source.

## Execution sequence

1. Inspect the exact upstream release, security guide, iOS app requirements, supported Windows/Linux runtime, and dependency/license notices.
2. Inventory the owner's existing host hardware and determine whether local inference is viable without purchasing anything.
3. Create an isolated test environment on that host; do not connect personal accounts or private data during initial tests.
4. Install the official iOS companion app and pair it only with the isolated Gateway over a private connection.
5. Verify owner-only pairing, passkey/auth boundaries, Voice Wake, Talk, memory persistence, tool approval, sandboxing, and safe shutdown.
6. Select a free local model only after hardware benchmarking. Keep paid providers disabled.
7. Design the JARVIS identity and authentication bridge after the upstream behavior is proven.
8. Request separate owner approval before any public deployment, merge to a protected branch, connection to personal accounts, or access to private data.

## Current verified state

- A new working branch, `jarvis-openclaw-adoption`, has been created from `jarvis-worker-runtime-tests`.
- This assessment document is the only change on the new branch so far.
- The existing JARVIS runtime-test branch remains unchanged by this assessment.
- The most recent GitHub Actions run on the source branch completed successfully (run #320).
- The existing remote D1 database and successful migration application are recorded in the project provisioning gate; read-only schema verification and real D1 smoke tests remain outstanding.
- No Worker deployment, upstream fork, code import, account connection, or paid service has been performed.

## Upstream references

- https://github.com/openclaw/openclaw
- https://github.com/openclaw/openclaw/blob/main/LICENSE
- https://github.com/openclaw/openclaw/blob/main/docs/platforms/ios.md
- https://docs.openclaw.ai/gateway/security
- https://docs.openclaw.ai/gateway/sandboxing
- https://docs.openclaw.ai/gateway
