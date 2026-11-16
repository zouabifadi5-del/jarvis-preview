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
const recoverButton = document.querySelector("#recover");
const recoveryCodeInput = document.querySelector("#recovery-code");
const recoveryPanel = document.querySelector("#recovery-panel");
const recoveryList = document.querySelector("#recovery-list");
const copyRecoveryButton = document.querySelector("#copy-recovery");
const downloadRecoveryButton = document.querySelector("#download-recovery");
const acknowledgeRecoveryButton = document.querySelector("#acknowledge-recovery");
const secretInput = document.querySelector("#bootstrap-secret");
const credentialsNode = document.querySelector("#credentials");
const chatLog = document.querySelector("#chat-log");
const chatMessageInput = document.querySelector("#chat-message");
const sendChatButton = document.querySelector("#send-chat");
let chatHistory = [];
const memoryPanel = document.querySelector("#memory-panel");
const memoryStatus = document.querySelector("#memory-status");
const memoryControls = document.querySelector("#memory-controls");
const memoryCategory = document.querySelector("#memory-category");
const memoryContent = document.querySelector("#memory-content");
const memoryExpires = document.querySelector("#memory-expires");
const memoryListNode = document.querySelector("#memory-list");
const saveMemoryButton = document.querySelector("#save-memory");
const clearMemoryButton = document.querySelector("#clear-memory");
const exportMemoriesButton = document.querySelector("#export-memories");
const deleteAllMemoriesButton = document.querySelector("#delete-all-memories");
let selectedMemoryId = null;

function setStatus(message, kind = "info") {
  statusNode.textContent = message;
  statusNode.dataset.kind = kind;
}
function setBusy(busy) {
  for (const button of [loginButton, enrollButton, addButton, reauthButton, logoutButton, logoutAllButton, recoverButton, copyRecoveryButton, downloadRecoveryButton, acknowledgeRecoveryButton, sendChatButton]) if (button) button.disabled = busy;
  if (memoryControls) for (const control of memoryControls.querySelectorAll("button, input, select, textarea")) control.disabled = busy;
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
      recovery_failed: "That recovery code could not be used. Check it and try again, or use a different unused code.",
      reauthentication_required: "Your sign-in is too old for this change. Tap Confirm passkey for security changes, then retry.",
      ai_not_configured: "JARVIS AI is not configured yet.",
      ai_rate_limit_not_configured: "JARVIS AI safety limits are not configured, so requests are blocked.",
      ai_temporarily_unavailable: "JARVIS AI is temporarily unavailable. Your message was not saved.",
      ai_response_unavailable: "JARVIS could not produce a valid reply. Try again later.",
      daily_ai_limit_reached: "JARVIS reached its daily free-use limit. Try again after 00:00 UTC; no paid upgrade will be used.",
      rate_limit_exceeded: "Too many requests. Wait a little before trying again.",
      memory_not_enabled: "Persistent memory is disabled until the owner accepts the seven-day D1 backup window and the encryption key is configured.",
      memory_key_version_unsupported: "This memory uses an unsupported encryption-key version. Do not delete or overwrite it.",
      memory_integrity_check_failed: "This memory failed its integrity check and was not changed.",
      memory_not_found: "That memory no longer exists.",
      memory_limit_reached: "JARVIS has reached its current memory limit.",
      explicit_confirmation_required: "Confirm the exact memory action before continuing."
    };
    if (response.status === 503 && payload.error === "authentication_not_configured") {
      throw new Error("The authentication service is not configured yet.");
    }
    const error = new Error(messages[payload.error] || "Request failed (" + response.status + ").");
    error.code = payload.error;
    error.status = response.status;
    throw error;
  }
  return payload;
}
function showSignedOut() {
  signedOut.hidden = false;
  signedIn.hidden = true;
  recoveryPanel.hidden = true;
  chatLog.replaceChildren();
  chatMessageInput.value = "";
  chatHistory = [];
  memoryListNode.replaceChildren();
  memoryContent.value = "";
  memoryExpires.value = "";
  selectedMemoryId = null;
  memoryControls.hidden = true;
  memoryStatus.textContent = "Persistent memory is not available while signed out.";
}
function showRecoveryCodes(codes) {
  if (!Array.isArray(codes) || codes.length !== 10 || codes.some((code) => typeof code !== "string")) {
    throw new Error("The server did not return the expected recovery codes. Do not close this page; contact the owner support process.");
  }
  recoveryList.textContent = codes.join("\n");
  signedOut.hidden = true;
  signedIn.hidden = true;
  recoveryPanel.hidden = false;
  setStatus("Save these recovery codes before continuing.", "success");
}
async function copyRecoveryCodes() {
  if (!navigator.clipboard?.writeText) throw new Error("Clipboard access is unavailable. Use the download option instead.");
  await navigator.clipboard.writeText(recoveryList.textContent);
  setStatus("Recovery codes copied. Store them somewhere secure and offline.", "success");
}
function downloadRecoveryCodes() {
  const blob = new Blob(["JARVIS owner recovery codes\nKeep offline. Each code works once.\n\n", recoveryList.textContent, String.fromCharCode(10)], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "jarvis-recovery-codes.txt";
  link.click();
  URL.revokeObjectURL(url);
  setStatus("Recovery-code file prepared. Keep it secure and offline.", "success");
}
function acknowledgeRecoveryCodes() {
  recoveryPanel.hidden = true;
  recoveryList.textContent = "";
  signedIn.hidden = false;
  setStatus("Recovery codes acknowledged. Owner session active.", "success");
}
async function showSignedIn() { signedOut.hidden = true; signedIn.hidden = false; await loadCredentials(); await loadMemories(); }
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
function appendChatMessage(role, content) {
  const item = document.createElement("div");
  item.className = "chat-message " + role;
  const label = document.createElement("strong");
  label.textContent = role === "assistant" ? "JARVIS" : "You";
  const body = document.createElement("p");
  body.textContent = content;
  item.append(label, body);
  chatLog.append(item);
  chatLog.scrollTop = chatLog.scrollHeight;
}

async function sendChatMessage() {
  const message = chatMessageInput.value.trim();
  if (!message) {
    setStatus("Write a message first.", "error");
    return;
  }
  setStatus("JARVIS is thinking…");
  const result = await api("/auth/chat", {
    method: "POST",
    body: { message, history: chatHistory }
  });
  appendChatMessage("user", message);
  appendChatMessage("assistant", result.reply);
  chatHistory.push({ role: "user", content: message }, { role: "assistant", content: result.reply });
  if (chatHistory.length > 8) chatHistory = chatHistory.slice(-8);
  chatMessageInput.value = "";
  setStatus("Reply received. This prototype does not save chat history.", "success");
}

function memoryExpirySeconds() {
  if (!memoryExpires.value) return null;
  const date = new Date(memoryExpires.value + "T23:59:59");
  const timestamp = Math.floor(date.getTime() / 1000);
  if (!Number.isSafeInteger(timestamp)) throw new Error("Choose a valid memory expiry date.");
  return timestamp;
}

function clearMemoryEditor() {
  selectedMemoryId = null;
  memoryContent.value = "";
  memoryCategory.value = "preference";
  memoryExpires.value = "";
  saveMemoryButton.textContent = "Save memory";
}

async function openMemory(id) {
  const result = await api("/auth/memories/" + encodeURIComponent(id));
  const memory = result.memory;
  selectedMemoryId = memory.id;
  memoryCategory.value = memory.category;
  memoryContent.value = memory.content;
  memoryExpires.value = memory.expiresAt ? new Date(memory.expiresAt * 1000).toISOString().slice(0, 10) : "";
  saveMemoryButton.textContent = "Update selected memory";
  setStatus("Memory loaded for inspection. Editing requires a fresh passkey check.");
}

function renderMemoryList(memories) {
  memoryListNode.replaceChildren();
  if (!memories.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No saved memories yet.";
    memoryListNode.append(empty);
    return;
  }
  for (const memory of memories) {
    const item = document.createElement("div");
    item.className = "memory-item";
    const summary = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = memory.category.charAt(0).toUpperCase() + memory.category.slice(1);
    const date = document.createElement("p");
    date.className = "muted";
    date.textContent = "Updated " + new Date(memory.updatedAt * 1000).toLocaleString();
    summary.append(title, date);
    const actions = document.createElement("div");
    actions.className = "memory-actions";
    const view = document.createElement("button");
    view.type = "button";
    view.className = "secondary";
    view.textContent = "View / edit";
    view.addEventListener("click", () => runAction(() => openMemory(memory.id)));
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "danger";
    remove.textContent = "Delete";
    remove.addEventListener("click", () => runAction(() => deleteMemory(memory.id)));
    actions.append(view, remove);
    item.append(summary, actions);
    memoryListNode.append(item);
  }
}

async function loadMemories() {
  memoryListNode.replaceChildren();
  memoryControls.hidden = true;
  try {
    const result = await api("/auth/memories");
    memoryControls.hidden = false;
    memoryStatus.textContent = result.memories.length + " encrypted memory record(s). Content is decrypted only when you open a record.";
    renderMemoryList(result.memories);
  } catch (error) {
    if (error.code === "memory_not_enabled") {
      memoryStatus.textContent = error.message;
      return;
    }
    throw error;
  }
}

async function saveMemory() {
  const content = memoryContent.value.trim();
  const category = memoryCategory.value;
  if (!content) throw new Error("Enter the exact memory text you want to save.");
  if (!window.confirm((selectedMemoryId ? "Update" : "Save") + " this exact text in your private encrypted memory?")) return;
  const body = { content, category, expiresAt: memoryExpirySeconds() };
  // Memory writes require a recent passkey ceremony, including first-time creation.
  await signIn();
  if (selectedMemoryId) {
    await api("/auth/memories/" + encodeURIComponent(selectedMemoryId), { method: "PUT", body });
    setStatus("Memory updated and encrypted.", "success");
  } else {
    await api("/auth/memories", { method: "POST", body });
    setStatus("Memory saved and encrypted.", "success");
  }
  clearMemoryEditor();
  await loadMemories();
}

async function deleteMemory(id) {
  if (!window.confirm("Delete this memory from active storage? A restorable encrypted copy may remain in provider backups for up to seven days.")) return;
  await signIn();
  await api("/auth/memories/" + encodeURIComponent(id), {
    method: "DELETE", body: { confirm: true }
  });
  if (selectedMemoryId === id) clearMemoryEditor();
  await loadMemories();
  setStatus("Memory deleted from active storage. Backup retention may last up to seven days.", "success");
}

async function exportMemories() {
  if (!window.confirm("Export all your saved memories to a JSON file? The file will contain decrypted private text.")) return;
  await signIn();
  const result = await api("/auth/memories/export", {
    method: "POST", body: { confirm: true }
  });
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "jarvis-memory-export.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  setStatus("Memory export created. Keep the downloaded file private.", "success");
}

async function deleteAllMemories() {
  if (!window.confirm("Delete ALL saved memories from active storage? Provider backups may retain restorable encrypted copies for up to seven days.")) return;
  await signIn();
  await api("/auth/memories", { method: "DELETE", body: { confirm: true } });
  clearMemoryEditor();
  await loadMemories();
  setStatus("All memories deleted from active storage. Backup retention may last up to seven days.", "success");
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
  const result = await api("/auth/register/verify", {
    method: "POST", headers,
    body: { challenge: options.challenge, response: serializeRegistration(credential) }
  });
  secretInput.value = "";
  await showSignedIn();
  showRecoveryCodes(result.recoveryCodes);
}

async function recoverOwner() {
  await requireWebAuthn();
  const recoveryCode = recoveryCodeInput.value.trim();
  recoveryCodeInput.value = "";
  if (recoveryCode.length < 40) throw new Error("Enter one complete unused recovery code.");
  const options = await api("/auth/recovery/options", {
    method: "POST",
    body: { recoveryCode }
  });
  const credential = await navigator.credentials.create({
    publicKey: registrationOptionsFromServer(options)
  });
  if (!credential) throw new Error("Recovery passkey creation was cancelled.");
  const result = await api("/auth/recovery/verify", {
    method: "POST",
    body: { challenge: options.challenge, response: serializeRegistration(credential) }
  });
  recoveryCodeInput.value = "";
  await showSignedIn();
  showRecoveryCodes(result.recoveryCodes);
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
recoverButton.addEventListener("click", () => runAction(recoverOwner));
copyRecoveryButton.addEventListener("click", () => runAction(copyRecoveryCodes));
downloadRecoveryButton.addEventListener("click", () => runAction(downloadRecoveryCodes));
acknowledgeRecoveryButton.addEventListener("click", () => runAction(acknowledgeRecoveryCodes));
sendChatButton.addEventListener("click", () => runAction(sendChatMessage));
saveMemoryButton.addEventListener("click", () => runAction(saveMemory));
clearMemoryButton.addEventListener("click", clearMemoryEditor);
exportMemoriesButton.addEventListener("click", () => runAction(exportMemories));
deleteAllMemoriesButton.addEventListener("click", () => runAction(deleteAllMemories));

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
      recoverButton.hidden = true;
      recoveryCodeInput.hidden = true;
      setStatus(error.message, "error");
      return;
    }
    setStatus("Sign in with your owner passkey, or complete the one-time setup if this is a new installation.");
  }
}
initialize();
