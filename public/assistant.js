"use strict";
(() => {
  const panel = document.querySelector("#assistant-panel");
  const log = document.querySelector("#chat-log");
  const form = document.querySelector("#chat-form");
  const input = document.querySelector("#chat-input");
  const send = document.querySelector("#send-command");
  const speak = document.querySelector("#speak-last");
  const clear = document.querySelector("#clear-chat");
  if (!panel || !log || !form || !input || !send) return;

  let messages = [];
  let lastReply = "";

  function csrfCookie() {
    for (const part of document.cookie.split(";")) {
      const value = part.trim();
      if (value.startsWith("__Host-jarvis_csrf=")) return decodeURIComponent(value.slice("__Host-jarvis_csrf=".length));
    }
    return "";
  }

  function addMessage(role, content) {
    const node = document.createElement("div");
    node.className = "message " + (role === "user" ? "user-message" : "assistant-message");
    node.textContent = content;
    log.append(node);
    log.scrollTop = log.scrollHeight;
  }

  function setBusy(busy) {
    send.disabled = busy;
    input.disabled = busy;
    send.textContent = busy ? "Thinking…" : "Send";
  }

  async function setAuthenticated(authenticated) {
    panel.hidden = !authenticated;
    if (!authenticated) {
      messages = [];
      if (window.speechSynthesis) window.speechSynthesis.cancel();
    }
  }

  async function sendMessage(event) {
    event.preventDefault();
    const content = input.value.trim();
    if (!content || send.disabled) return;
    if (!csrfCookie()) {
      addMessage("assistant", "Your security session needs refreshing. Sign out and sign in again.");
      return;
    }
    messages.push({ role: "user", content });
    if (messages.length > 10) messages = messages.slice(-10);
    addMessage("user", content);
    input.value = "";
    setBusy(true);
    try {
      const response = await fetch("/assistant/chat", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfCookie() },
        body: JSON.stringify({ messages })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const messagesByError = {
          assistant_not_configured: "JARVIS AI is not enabled on the server yet.",
          not_authenticated: "Your owner session has expired. Sign in again.",
          session_or_csrf_invalid: "Your security check failed. Sign in again.",
          model_unavailable: "The free AI model did not return a response. Try again later.",
          assistant_temporarily_unavailable: "The AI service is temporarily unavailable or its free daily allowance may be exhausted. No paid fallback is enabled."
        };
        throw new Error(messagesByError[payload.error] || "Request failed (" + response.status + ").");
      }
      if (typeof payload.answer !== "string" || !payload.answer.trim()) throw new Error("The AI service returned an empty response.");
      lastReply = payload.answer.trim();
      messages.push({ role: "assistant", content: lastReply });
      if (messages.length > 10) messages = messages.slice(-10);
      addMessage("assistant", lastReply);
    } catch (error) {
      addMessage("assistant", error instanceof Error ? error.message : "Unable to reach JARVIS.");
    } finally {
      setBusy(false);
      input.focus();
    }
  }

  form.addEventListener("submit", sendMessage);
  clear.addEventListener("click", () => {
    messages = [];
    lastReply = "";
    log.replaceChildren();
    addMessage("assistant", "Conversation cleared from this page. No chat history was stored.");
  });
  speak.addEventListener("click", () => {
    if (!lastReply || !("speechSynthesis" in window)) {
      addMessage("assistant", "Spoken playback is unavailable in this browser or there is no reply yet.");
      return;
    }
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(lastReply);
    utterance.lang = "en-US";
    window.speechSynthesis.speak(utterance);
  });

  window.addEventListener("jarvis-auth-changed", (event) => setAuthenticated(Boolean(event.detail?.authenticated)));
  fetch("/auth/me", { credentials: "same-origin", cache: "no-store" })
    .then((response) => setAuthenticated(response.ok))
    .catch(() => setAuthenticated(false));
})();
