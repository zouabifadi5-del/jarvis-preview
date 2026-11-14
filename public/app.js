"use strict";

const statusNode = document.querySelector("#status");
const signedOut = document.querySelector("#signed-out");
const signedIn = document.querySelector("#signed-in");
const loginButton = document.querySelector("#login");
const enrollButton = document.querySelector("#enroll");
const addButton = document.querySelector("#add-credential");
const reauthButton = document.querySelector("#reauthenticate");
const logoutButton = document.querySelector("#logout");
const logoutAllButton = document.querySelector("#logout-all");
const secretInput = document.querySelector("#bootstrap-secret");
const credentialsNode = document.querySelector("#credentials");

function setStatus(message, kind = "info") {
  statusNode.textContent = message;
  statusNode.dataset.kind = kind;
}
function setBusy(busy) {
  for (const button of [loginButton, enrollButton, addButton, reauthButton, logoutButton, logoutAllButton]) if (button) button.disabled = busy;
}
function decodeBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error("The server returned invalid passkey options.");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function encodeBase64Url(value) {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function registrationOptionsFromServer(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    user: { ...options.user, id: decodeBase64Url(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((item) => ({ ...item, id: decodeBase64Url(item.id) }))
  };
}
function authenticationOptionsFromServer(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((item) => ({ ...item, id: decodeBase64Url(item.id) }))
  };
}
function serializeRegistration(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: encodeBase64Url(credential.response.attestationObject),
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      transports: typeof credential.response.getTransports === "function" ? credential.response.getTransports() : []
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}
function serializeAuthentication(credential) {
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: encodeBase64Url(credential.response.authenticatorData),
      clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
      signature: encodeBase64Url(credential.response.signature),
      userHandle: credential.response.userHandle ? encodeBase64Url(credential.response.userHandle) : null
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}
function readCookie(name) {
  const prefix = name + "=";
  for (const item of document.cookie.split(";")) {
    const value = item.trim();
    if (value.startsWith(prefix)) return decodeURIComponent(value.slice(prefix.length));
  }
  return null;
}
async function api(path, { method = "GET", body, headers = {} } = {}) {
  const requestHeaders = new Headers(headers);
  if (body !== undefined) requestHeaders.set("Content-Type", "application/json");
  if (method !== "GET" && method !== "HEAD") {
    const csrf = readCookie("__Host-jarvis_csrf");
    if (csrf && !requestHeaders.has("X-CSRF-Token")) requestHeaders.set("X-CSRF-Token", csrf);
  }
  const response = await fetch(path, {
    method, headers: requestHeaders, body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store", redirect: "error", credentials: "same-origin"
  });
  let payload = {};
  try { payload = await response.json(); } catch { /* handled below */ }
  if (!response.ok) {
    const messages = {
      enrollment_closed: "Owner enrollment is already closed. Use passkey sign-in.",
      bootstrap_not_authorized: "The bootstrap secret was not accepted.",
      challenge_invalid_or_expired: "That passkey request expired. Please try again.",
      not_authenticated: "Your session has expired. Sign in again.",
      session_or_csrf_invalid: "Your session security check failed. Refresh and sign in again.",
      reauthentication_required: "Your sign-in is too old for this change. Tap Confirm passkey for security changes, then retry."
    };
    if (response.status === 503 && payload.error === "authentication_not_configured") {
      throw new Error("The authentication service is not configured yet.");
    }
    throw new Error(messages[payload.error] || "Request failed (" + response.status + ").");
  }
  return payload;
}
function showSignedOut() { signedOut.hidden = false; signedIn.hidden = true; }
async function showSignedIn() { signedOut.hidden = true; signedIn.hidden = false; await loadCredentials(); }
async function loadCredentials() {
  credentialsNode.replaceChildren();
  const result = await api("/auth/credentials");
  const heading = document.createElement("p");
  heading.className = "muted";
  heading.textContent = result.credentials.length + " active passkey credential(s)";
  credentialsNode.append(heading);
  for (const credential of result.credentials) {
    const item = document.createElement("div");
    item.className = "credential";
    const title = document.createElement("strong");
    title.textContent = credential.deviceType === "multiDevice" ? "Synced passkey" : "Device-bound passkey";
    const details = document.createElement("div");
    details.className = "muted";
    details.textContent = "Added " + new Date(credential.createdAt * 1000).toLocaleDateString();
    item.append(title, details);
    if (result.credentials.length > 1) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "danger";
      remove.textContent = "Remove this passkey";
      remove.addEventListener("click", async () => {
        if (!window.confirm("Remove this passkey from your JARVIS owner account?")) return;
        remove.disabled = true;
        try {
          await signIn();
          await api("/auth/credentials/revoke", {
            method: "POST",
            body: { credentialId: credential.id }
          });
          await loadCredentials();
          setStatus("Passkey removed.", "success");
        } catch (error) {
          setStatus(error instanceof Error ? error.message : "Could not remove this passkey.", "error");
          remove.disabled = false;
        }
      });
      item.append(remove);
    }
    credentialsNode.append(item);
  }
}
async function requireWebAuthn() {
  if (!window.isSecureContext || !navigator.credentials || typeof navigator.credentials.create !== "function" ||
      typeof navigator.credentials.get !== "function" || !window.PublicKeyCredential) {
    throw new Error("Passkeys are not available in this browser or page context. Open the secure JARVIS address in Safari.");
  }
}
async function enrollOwner() {
  await requireWebAuthn();
  const secret = secretInput.value.trim();
  secretInput.value = "";
  if (secret.length < 32) throw new Error("Enter the one-time bootstrap secret (at least 32 characters).");
  const headers = { "X-Jarvis-Bootstrap": secret };
  const options = await api("/auth/register/options", { method: "POST", headers });
  const credential = await navigator.credentials.create({ publicKey: registrationOptionsFromServer(options) });
  if (!credential) throw new Error("Passkey creation was cancelled.");
  await api("/auth/register/verify", {
    method: "POST", headers,
    body: { challenge: options.challenge, response: serializeRegistration(credential) }
  });
  secretInput.value = "";
  await showSignedIn();
  setStatus("Owner passkey created. Enrollment is now closed.", "success");
}
async function signIn() {
  await requireWebAuthn();
  const options = await api("/auth/login/options", { method: "POST" });
  const credential = await navigator.credentials.get({ publicKey: authenticationOptionsFromServer(options) });
  if (!credential) throw new Error("Passkey sign-in was cancelled.");
  await api("/auth/login/verify", { method: "POST", body: { challenge: options.challenge, response: serializeAuthentication(credential) } });
  await showSignedIn();
  setStatus("Owner authenticated. Your private session is active.", "success");
}
async function addPasskey() {
  await signIn();
  await requireWebAuthn();
  const options = await api("/auth/credentials/options", { method: "POST" });
  const credential = await navigator.credentials.create({ publicKey: registrationOptionsFromServer(options) });
  if (!credential) throw new Error("Passkey creation was cancelled.");
  await api("/auth/credentials/verify", { method: "POST", body: { challenge: options.challenge, response: serializeRegistration(credential) } });
  await loadCredentials();
  setStatus("Additional passkey added to your owner account.", "success");
}
async function signOut() {
  await api("/auth/logout", { method: "POST", body: {} });
  showSignedOut();
  setStatus("You have signed out.", "success");
}
async function signOutEverywhere() {
  if (!window.confirm("End every active JARVIS session on all devices? You will need your passkey to sign in again.")) return;
  const result = await api("/auth/logout-all", { method: "POST", body: {} });
  showSignedOut();
  setStatus("Signed out on all devices. " + result.revokedCount + " session(s) revoked.", "success");
}

async function signOutAll() {
  if (!window.confirm("Sign out of JARVIS on every device? You will need a passkey to sign in again.")) return;
  await api("/auth/logout-all", { method: "POST", body: {} });
  showSignedOut();
  setStatus("All JARVIS sessions have been revoked.", "success");
}
async function runAction(action) {
  setBusy(true);
  try { await action(); }
  catch (error) { setStatus(error instanceof Error ? error.message : "Something went wrong. Please try again.", "error"); }
  finally { setBusy(false); }
}
loginButton.addEventListener("click", () => runAction(signIn));
enrollButton.addEventListener("click", () => runAction(enrollOwner));
addButton.addEventListener("click", () => runAction(addPasskey));
reauthButton.addEventListener("click", () => runAction(signIn));
logoutButton.addEventListener("click", () => runAction(signOut));
logoutAllButton.addEventListener("click", () => runAction(signOutEverywhere));
logoutAllButton.addEventListener("click", () => runAction(signOutAll));
async function initialize() {
  try {
    await requireWebAuthn();
    await api("/auth/me");
    await showSignedIn();
    setStatus("Owner session active.", "success");
  } catch (error) {
    showSignedOut();
    if (error instanceof Error && error.message.includes("Passkeys are not available")) {
      setStatus(error.message, "error");
      return;
    }
    if (error instanceof Error && error.message === "The authentication service is not configured yet.") {
      loginButton.hidden = true;
      enrollButton.hidden = true;
      secretInput.hidden = true;
      setStatus(error.message, "error");
      return;
    }
    setStatus("Sign in with your owner passkey, or complete the one-time setup if this is a new installation.");
  }
}
initialize();
