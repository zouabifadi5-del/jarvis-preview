import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyRegistrationResponse
} from "@simplewebauthn/server";
import {
  completeOwnerRecovery,
  consumeChallenge,
  consumeRecoveryChallenge,
  createChallenge,
  createOwnerWithCredential,
  completeOwnerRecovery,
  consumeRecoveryChallenge,
  findActiveRecoveryCode,
  createSession,
  findActiveCredential,
  findActiveRecoveryCode,
  findActiveSession,
  findOwner,
  listActiveCredentials,
  revokeAllSessions,
  revokeCredential,
  storeCredential,
  revokeSession,
  updateCredentialCounter,
  verifySessionCsrf
} from "./d1-store.js";
import { verifyStoredCredentialAuthentication } from "./webauthn.js";

const SESSION_COOKIE = "__Host-jarvis_session";
const CSRF_COOKIE = "__Host-jarvis_csrf";
const CHALLENGE_TTL_SECONDS = 5 * 60;
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const MAX_BODY_BYTES = 16 * 1024;
const encoder = new TextEncoder();

function response(request, body, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    ...extraHeaders
  });
  if (new URL(request.url).protocol === "https:") {
    headers.set("Strict-Transport-Security", "max-age=31536000");
  }
  return Response.json(body, { status, headers });
}

function fail(request, status, error) {
  return response(request, { error }, status);
}

function configuration(request, env) {
  if (!env?.DB || typeof env.DB.prepare !== "function") return null;
  if (typeof env.AUTH_ORIGIN !== "string" || typeof env.WEBAUTHN_RP_ID !== "string") return null;
  let configured;
  try {
    configured = new URL(env.AUTH_ORIGIN);
  } catch {
    return null;
  }
  if (
    configured.protocol !== "https:" ||
    configured.origin !== env.AUTH_ORIGIN ||
    configured.hostname !== env.WEBAUTHN_RP_ID ||
    new URL(request.url).origin !== env.AUTH_ORIGIN
  ) return null;
  return { db: env.DB, origin: configured.origin, rpID: env.WEBAUTHN_RP_ID };
}

function sameOrigin(request, origin) {
  return request.headers.get("Origin") === origin &&
    new URL(request.url).origin === origin;
}

function equalSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length < 32 || b.length < 32) return false;
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i += 1) difference |= left[i] ^ right[i];
  return difference === 0;
}

async function readJson(request) {
  const contentType = (request.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") return null;
  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength > MAX_BODY_BYTES) return null;
  const raw = await request.text();
  if (encoder.encode(raw).length > MAX_BODY_BYTES) return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}

function sessionCookie(token, maxAge) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function csrfCookie(token, maxAge) {
  // Deliberately readable by same-origin JavaScript so the client can recover
  // the CSRF header value after a page reload; the server stores only its hash.
  return `${CSRF_COOKIE}=${token}; Path=/; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

function clearCsrfCookie() {
  return `${CSRF_COOKIE}=; Path=/; Secure; SameSite=Strict; Max-Age=0`;
}

async function issueSession(request, db, now, additionalBody = {}) {
  // Rotate an existing browser session after every successful passkey ceremony.
  const previousToken = getCookie(request, SESSION_COOKIE);
  if (previousToken) await revokeSession(db, { sessionToken: previousToken, now });
  const session = await createSession(db, { now, ttlSeconds: SESSION_TTL_SECONDS });
  const issued = response(request, {
    authenticated: true,
    csrfToken: session.csrfToken,
    expiresAt: session.expiresAt,
    ...additionalBody
  }, 200, { "Set-Cookie": sessionCookie(session.sessionToken, SESSION_TTL_SECONDS) });
  issued.headers.append("Set-Cookie", csrfCookie(session.csrfToken, SESSION_TTL_SECONDS));
  return issued;
}

async function registrationOptions(request, env, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  if (!equalSecret(request.headers.get("X-Jarvis-Bootstrap"), env.JARVIS_BOOTSTRAP_SECRET)) {
    return fail(request, 403, "bootstrap_not_authorized");
  }
  if (await findOwner(cfg.db)) return fail(request, 409, "enrollment_closed");

  const challenge = await createChallenge(cfg.db, {
    purpose: "registration",
    now,
    ttlSeconds: CHALLENGE_TTL_SECONDS
  });
  const userID = new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    encoder.encode("JARVIS single-owner WebAuthn user handle v1")
  ));
  const options = await generateRegistrationOptions({
    rpName: "J.A.R.V.I.S.",
    rpID: cfg.rpID,
    userName: "owner",
    userDisplayName: "JARVIS Owner",
    userID,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required"
    },
    timeout: 60000
  });
  // Persist the exact server-issued challenge in the D1 single-use store.
  // The library challenge is replaced with the persisted random challenge.
  options.challenge = challenge.challenge;
  return response(request, options);
}

async function registrationVerify(request, env, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  if (!equalSecret(request.headers.get("X-Jarvis-Bootstrap"), env.JARVIS_BOOTSTRAP_SECRET)) {
    return fail(request, 403, "bootstrap_not_authorized");
  }
  if (await findOwner(cfg.db)) return fail(request, 409, "enrollment_closed");
  const body = await readJson(request);
  if (!body || typeof body.challenge !== "string" || !body.response || typeof body.response !== "object") {
    return fail(request, 400, "invalid_request");
  }
  const consumed = await consumeChallenge(cfg.db, {
    challenge: body.challenge,
    purpose: "registration",
    now
  });
  if (!consumed) return fail(request, 400, "challenge_invalid_or_expired");

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: consumed,
      expectedOrigin: cfg.origin,
      expectedRPID: cfg.rpID,
      requireUserVerification: true
    });
  } catch {
    return fail(request, 400, "registration_verification_failed");
  }
  if (!verification.verified || !verification.registrationInfo?.credential) {
    return fail(request, 400, "registration_verification_failed");
  }

  const credential = verification.registrationInfo.credential;
  let recoveryCodes;
  try {
    ({ recoveryCodes } = await createOwnerWithCredential(cfg.db, {
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports || [],
      deviceType: verification.registrationInfo.credentialDeviceType || null,
      backedUp: verification.registrationInfo.credentialBackedUp || false,
      now
    }));
  } catch {
    // The singleton owner row makes first enrollment a one-time atomic operation.
    return fail(request, 409, "enrollment_closed");
  }
  return issueSession(request, cfg.db, now, { recoveryCodes });
}


async function recoveryOptions(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  const body = await readJson(request);
  if (!body || typeof body.recoveryCode !== "string") return fail(request, 400, "invalid_request");
  const recoveryCodeHash = await findActiveRecoveryCode(cfg.db, body.recoveryCode.trim());
  if (!recoveryCodeHash) return fail(request, 401, "recovery_failed");

  const challenge = await createChallenge(cfg.db, {
    purpose: "recovery",
    recoveryCodeHash,
    now,
    ttlSeconds: CHALLENGE_TTL_SECONDS
  });
  const userID = new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    encoder.encode("JARVIS single-owner WebAuthn user handle v1")
  ));
  const options = await generateRegistrationOptions({
    rpName: "J.A.R.V.I.S.",
    rpID: cfg.rpID,
    userName: "owner",
    userDisplayName: "JARVIS Owner",
    userID,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required"
    },
    timeout: 60000
  });
  options.challenge = challenge.challenge;
  return response(request, options);
}

async function recoveryVerify(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  const body = await readJson(request);
  if (!body || typeof body.challenge !== "string" || !body.response || typeof body.response !== "object") {
    return fail(request, 400, "invalid_request");
  }
  const consumed = await consumeRecoveryChallenge(cfg.db, { challenge: body.challenge, now });
  if (!consumed) return fail(request, 400, "challenge_invalid_or_expired");

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: consumed.challenge,
      expectedOrigin: cfg.origin,
      expectedRPID: cfg.rpID,
      requireUserVerification: true
    });
  } catch {
    return fail(request, 401, "recovery_failed");
  }
  if (!verification.verified || !verification.registrationInfo?.credential) {
    return fail(request, 401, "recovery_failed");
  }

  const credential = verification.registrationInfo.credential;
  let recoveryCodes;
  try {
    ({ recoveryCodes } = await completeOwnerRecovery(cfg.db, {
      recoveryCodeHash: consumed.recoveryCodeHash,
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports || [],
      deviceType: verification.registrationInfo.credentialDeviceType || null,
      backedUp: verification.registrationInfo.credentialBackedUp || false,
      now
    }));
  } catch {
    return fail(request, 401, "recovery_failed");
  }
  return issueSession(request, cfg.db, now, { recoveryCodes });
}


async function recoveryOptions(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  const body = await readJson(request);
  if (!body || typeof body.recoveryCode !== "string") return fail(request, 400, "invalid_request");
  const recoveryCodeHash = await findActiveRecoveryCode(cfg.db, body.recoveryCode);
  if (!recoveryCodeHash || !await findOwner(cfg.db)) return fail(request, 401, "recovery_failed");

  const challenge = await createChallenge(cfg.db, {
    purpose: "recovery",
    recoveryCodeHash,
    now,
    ttlSeconds: CHALLENGE_TTL_SECONDS
  });
  const credentials = await listActiveCredentials(cfg.db);
  const userID = new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    encoder.encode("JARVIS single-owner WebAuthn user handle v1")
  ));
  const options = await generateRegistrationOptions({
    rpName: "J.A.R.V.I.S.",
    rpID: cfg.rpID,
    userName: "owner",
    userDisplayName: "JARVIS Owner",
    userID,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required"
    },
    excludeCredentials: credentials.map((item) => ({
      id: item.id,
      transports: item.transports
    })),
    timeout: 60000
  });
  options.challenge = challenge.challenge;
  return response(request, options);
}

async function recoveryVerify(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  const body = await readJson(request);
  if (!body || typeof body.challenge !== "string" || !body.response || typeof body.response !== "object") {
    return fail(request, 400, "invalid_request");
  }
  const consumed = await consumeRecoveryChallenge(cfg.db, {
    challenge: body.challenge,
    now
  });
  if (!consumed) return fail(request, 400, "recovery_failed");

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: consumed.challenge,
      expectedOrigin: cfg.origin,
      expectedRPID: cfg.rpID,
      requireUserVerification: true
    });
  } catch {
    return fail(request, 400, "recovery_failed");
  }
  if (!verification.verified || !verification.registrationInfo?.credential) {
    return fail(request, 400, "recovery_failed");
  }

  const credential = verification.registrationInfo.credential;
  let recoveryCodes;
  try {
    const recovered = await completeOwnerRecovery(cfg.db, {
      recoveryCodeHash: consumed.recoveryCodeHash,
      challengeHash: consumed.challengeHash,
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports || [],
      deviceType: verification.registrationInfo.credentialDeviceType || null,
      backedUp: verification.registrationInfo.credentialBackedUp || false,
      now
    });
    recoveryCodes = recovered.recoveryCodes;
  } catch {
    return fail(request, 401, "recovery_failed");
  }
  return issueSession(request, cfg.db, now, { recoveryCodes });
}

async function loginOptions(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  if (!await findOwner(cfg.db)) return fail(request, 401, "authentication_failed");
  const credentials = await listActiveCredentials(cfg.db);
  if (credentials.length === 0) return fail(request, 401, "authentication_failed");

  const challenge = await createChallenge(cfg.db, {
    purpose: "authentication",
    now,
    ttlSeconds: CHALLENGE_TTL_SECONDS
  });
  const options = await generateAuthenticationOptions({
    rpID: cfg.rpID,
    allowCredentials: credentials.map((credential) => ({
      id: credential.id,
      transports: credential.transports
    })),
    userVerification: "required",
    timeout: 60000
  });
  options.challenge = challenge.challenge;
  return response(request, options);
}

async function loginVerify(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  const body = await readJson(request);
  if (!body || typeof body.challenge !== "string" || !body.response || typeof body.response !== "object") {
    return fail(request, 400, "invalid_request");
  }
  const consumed = await consumeChallenge(cfg.db, {
    challenge: body.challenge,
    purpose: "authentication",
    now
  });
  if (!consumed) return fail(request, 400, "challenge_invalid_or_expired");

  const responseCredentialId = body.response.id;
  if (typeof responseCredentialId !== "string") return fail(request, 401, "authentication_failed");
  const stored = await findActiveCredential(cfg.db, responseCredentialId);
  if (!stored) return fail(request, 401, "authentication_failed");

  let verification;
  try {
    verification = await verifyStoredCredentialAuthentication({
      response: body.response,
      expectedChallenge: consumed,
      expectedOrigin: cfg.origin,
      expectedRPID: cfg.rpID,
      credential: {
        id: stored.id,
        publicKey: stored.publicKey,
        counter: stored.counter,
        transports: stored.transports
      },
      requireUserVerification: true
    });
  } catch {
    return fail(request, 401, "authentication_failed");
  }
  if (!verification.verified || !verification.authenticationInfo?.userVerified) {
    return fail(request, 401, "authentication_failed");
  }

  const counterUpdated = await updateCredentialCounter(cfg.db, {
    credentialId: stored.id,
    expectedCounter: stored.counter,
    newCounter: verification.authenticationInfo.newCounter,
    now
  });
  if (!counterUpdated) return fail(request, 409, "credential_state_changed_retry");

  return issueSession(request, cfg.db, now);
}


async function authenticatedOwner(request, cfg, now, requireCsrf = false) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const session = await findActiveSession(cfg.db, { sessionToken: token, now });
  if (!session) return null;
  if (requireCsrf) {
    const csrfToken = request.headers.get("X-CSRF-Token");
    if (!await verifySessionCsrf(cfg.db, { sessionToken: token, csrfToken, now })) return null;
  }
  return { token, session };
}

async function credentialList(request, cfg, now) {
  const auth = await authenticatedOwner(request, cfg, now);
  if (!auth) return fail(request, 401, "not_authenticated");
  const credentials = await listActiveCredentials(cfg.db);
  return response(request, {
    credentials: credentials.map((item) => ({
      id: item.id,
      transports: item.transports,
      deviceType: item.deviceType,
      backedUp: item.backedUp,
      createdAt: item.createdAt,
      lastUsedAt: item.lastUsedAt
    }))
  });
}

async function addCredentialOptions(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  const auth = await authenticatedOwner(request, cfg, now, true);
  if (!auth) return fail(request, 403, "session_or_csrf_invalid");
  if (now - auth.session.createdAt > 5 * 60) return fail(request, 403, "reauthentication_required");
  if (!await findOwner(cfg.db)) return fail(request, 401, "owner_not_enrolled");
  const credentials = await listActiveCredentials(cfg.db);
  if (credentials.length >= 10) return fail(request, 409, "credential_limit_reached");

  const challenge = await createChallenge(cfg.db, {
    purpose: "credential_add",
    now,
    ttlSeconds: CHALLENGE_TTL_SECONDS
  });
  const userID = new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    encoder.encode("JARVIS single-owner WebAuthn user handle v1")
  ));
  const options = await generateRegistrationOptions({
    rpName: "J.A.R.V.I.S.",
    rpID: cfg.rpID,
    userName: "owner",
    userDisplayName: "JARVIS Owner",
    userID,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required"
    },
    excludeCredentials: credentials.map((item) => ({
      id: item.id,
      transports: item.transports
    })),
    timeout: 60000
  });
  options.challenge = challenge.challenge;
  return response(request, options);
}

async function addCredentialVerify(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  const auth = await authenticatedOwner(request, cfg, now, true);
  if (!auth) return fail(request, 403, "session_or_csrf_invalid");
  if (now - auth.session.createdAt > 5 * 60) return fail(request, 403, "reauthentication_required");
  const body = await readJson(request);
  if (!body || typeof body.challenge !== "string" || !body.response || typeof body.response !== "object") {
    return fail(request, 400, "invalid_request");
  }
  const consumed = await consumeChallenge(cfg.db, {
    challenge: body.challenge,
    purpose: "credential_add",
    now
  });
  if (!consumed) return fail(request, 400, "challenge_invalid_or_expired");

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: consumed,
      expectedOrigin: cfg.origin,
      expectedRPID: cfg.rpID,
      requireUserVerification: true
    });
  } catch {
    return fail(request, 400, "registration_verification_failed");
  }
  if (!verification.verified || !verification.registrationInfo?.credential) {
    return fail(request, 400, "registration_verification_failed");
  }
  const credential = verification.registrationInfo.credential;
  try {
    await storeCredential(cfg.db, {
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports || [],
      deviceType: verification.registrationInfo.credentialDeviceType || null,
      backedUp: verification.registrationInfo.credentialBackedUp || false,
      now
    });
  } catch {
    return fail(request, 409, "credential_already_registered_or_invalid");
  }
  return response(request, { registered: true });
}

async function removeCredential(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  const auth = await authenticatedOwner(request, cfg, now, true);
  if (!auth) return fail(request, 403, "session_or_csrf_invalid");
  if (now - auth.session.createdAt > 5 * 60) return fail(request, 403, "reauthentication_required");
  const body = await readJson(request);
  if (!body || typeof body.credentialId !== "string") return fail(request, 400, "invalid_request");
  const credentials = await listActiveCredentials(cfg.db);
  if (credentials.length <= 1) return fail(request, 409, "cannot_revoke_last_credential");
  const revoked = await revokeCredential(cfg.db, { credentialId: body.credentialId, now });
  if (!revoked) return fail(request, 404, "credential_not_found");
  return response(request, { revoked: true });
}

async function currentSession(request, cfg, now) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return fail(request, 401, "not_authenticated");
  const session = await findActiveSession(cfg.db, { sessionToken: token, now });
  if (!session) return fail(request, 401, "not_authenticated");
  return response(request, { authenticated: true, expiresAt: session.expiresAt });
}


async function logoutAll(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  const token = getCookie(request, SESSION_COOKIE);
  const csrfToken = request.headers.get("X-CSRF-Token");
  if (!token || !await verifySessionCsrf(cfg.db, { sessionToken: token, csrfToken, now })) {
    return fail(request, 403, "csrf_check_failed");
  }
  const revokedCount = await revokeAllSessions(cfg.db, { now });
  const cleared = response(request, { authenticated: false, revokedCount }, 200, {
    "Set-Cookie": clearSessionCookie()
  });
  cleared.headers.append("Set-Cookie", clearCsrfCookie());
  return cleared;
}

async function logout(request, cfg, now) {
  if (!sameOrigin(request, cfg.origin)) return fail(request, 403, "origin_not_allowed");
  const token = getCookie(request, SESSION_COOKIE);
  const csrfToken = request.headers.get("X-CSRF-Token");
  if (!token || !await verifySessionCsrf(cfg.db, { sessionToken: token, csrfToken, now })) {
    return fail(request, 403, "csrf_check_failed");
  }
  await revokeSession(cfg.db, { sessionToken: token, now });
  const cleared = response(request, { authenticated: false }, 200, {
    "Set-Cookie": clearSessionCookie()
  });
  cleared.headers.append("Set-Cookie", clearCsrfCookie());
  return cleared;
}

export async function handleAuthRequest(request, env) {
  const cfg = configuration(request, env);
  if (!cfg) return fail(request, 503, "authentication_not_configured");
  const now = Math.floor(Date.now() / 1000);
  const { pathname } = new URL(request.url);

  try {
    if (pathname === "/auth/register/options" && request.method === "POST") {
      return await registrationOptions(request, env, cfg, now);
    }
    if (pathname === "/auth/register/verify" && request.method === "POST") {
      return await registrationVerify(request, env, cfg, now);
    }
    if (pathname === "/auth/recovery/options" && request.method === "POST") {
      return await recoveryOptions(request, cfg, now);
    }
    if (pathname === "/auth/recovery/verify" && request.method === "POST") {
      return await recoveryVerify(request, cfg, now);
    }
    if (pathname === "/auth/recovery/options" && request.method === "POST") {
      return await recoveryOptions(request, cfg, now);
    }
    if (pathname === "/auth/recovery/verify" && request.method === "POST") {
      return await recoveryVerify(request, cfg, now);
    }
    if (pathname === "/auth/login/options" && request.method === "POST") {
      return await loginOptions(request, cfg, now);
    }
    if (pathname === "/auth/login/verify" && request.method === "POST") {
      return await loginVerify(request, cfg, now);
    }
    if (pathname === "/auth/me" && request.method === "GET") {
      return await currentSession(request, cfg, now);
    }
    if (pathname === "/auth/credentials" && request.method === "GET") {
      return await credentialList(request, cfg, now);
    }
    if (pathname === "/auth/credentials/options" && request.method === "POST") {
      return await addCredentialOptions(request, cfg, now);
    }
    if (pathname === "/auth/credentials/verify" && request.method === "POST") {
      return await addCredentialVerify(request, cfg, now);
    }
    if (pathname === "/auth/credentials/revoke" && request.method === "POST") {
      return await removeCredential(request, cfg, now);
    }
    if (pathname === "/auth/logout-all" && request.method === "POST") {
      return await logoutAll(request, cfg, now);
    }
    if (pathname === "/auth/logout" && request.method === "POST") {
      return await logout(request, cfg, now);
    }
    return fail(request, 404, "not_found");
  } catch {
    return fail(request, 503, "authentication_temporarily_unavailable");
  }
}
