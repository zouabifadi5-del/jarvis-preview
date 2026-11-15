const SESSION_COOKIE = "__Host-jarvis_session";
const MAX_BODY_BYTES = 20 * 1024;
const MODEL = "@cf/google/gemma-4-26b-a4b-it";
const encoder = new TextEncoder();

function json(request, body, status = 200) {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer"
    }
  });
}

function cookie(request, name) {
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const index = part.indexOf("=");
    if (index >= 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}

async function readBody(request) {
  if ((request.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase() !== "application/json") return null;
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > MAX_BODY_BYTES) return null;
  const raw = await request.text();
  if (encoder.encode(raw).byteLength > MAX_BODY_BYTES) return null;
  try {
    const body = JSON.parse(raw);
    return body && typeof body === "object" && !Array.isArray(body) ? body : null;
  } catch {
    return null;
  }
}

export async function handleAssistantRequest(request, env) {
  const origin = typeof env?.AUTH_ORIGIN === "string" ? env.AUTH_ORIGIN : "";
  if (!env?.DB || !env?.AI || typeof env.DB.prepare !== "function") {
    return json(request, { error: "assistant_not_configured" }, 503);
  }
  if (request.method !== "POST") return json(request, { error: "method_not_allowed" }, 405);
  if (!origin || request.headers.get("Origin") !== origin || new URL(request.url).origin !== origin) {
    return json(request, { error: "origin_not_allowed" }, 403);
  }

  const token = cookie(request, SESSION_COOKIE);
  const csrfToken = request.headers.get("X-CSRF-Token");
  if (!token || !csrfToken) return json(request, { error: "not_authenticated" }, 401);

  try {
    const { findActiveSession, verifySessionCsrf } = await import("./auth/d1-store.js");
    const now = Math.floor(Date.now() / 1000);
    const session = await findActiveSession(env.DB, { sessionToken: token, now });
    if (!session || !await verifySessionCsrf(env.DB, { sessionToken: token, csrfToken, now })) {
      return json(request, { error: "session_or_csrf_invalid" }, 403);
    }

    const body = await readBody(request);
    if (!body || !Array.isArray(body.messages) || body.messages.length < 1 || body.messages.length > 12) {
      return json(request, { error: "invalid_request" }, 400);
    }
    const messages = [];
    for (const item of body.messages) {
      if (!item || !["user", "assistant"].includes(item.role) ||
          typeof item.content !== "string" || item.content.trim().length === 0 ||
          item.content.length > 4000) {
        return json(request, { error: "invalid_message" }, 400);
      }
      messages.push({ role: item.role, content: item.content.trim() });
    }
    if (messages[messages.length - 1].role !== "user") {
      return json(request, { error: "last_message_must_be_user" }, 400);
    }

    const result = await env.AI.run(MODEL, {
      messages: [{
        role: "system",
        content: "You are JARVIS, a private personal assistant for one authenticated owner. Be accurate, concise, and transparent about uncertainty. Do not claim to control the iPhone, access accounts, remember information permanently, or perform actions unless a connected and authorized tool actually did so. Never ask for passwords, passkeys, recovery codes, or secret tokens. You cannot execute device actions in this initial release."
      }, ...messages],
      max_tokens: 600,
      temperature: 0.4,
      chat_template_kwargs: { enable_thinking: false }
    });

    const answer = typeof result?.response === "string" ? result.response.trim() : "";
    if (!answer) return json(request, { error: "model_unavailable" }, 503);
    return json(request, { answer, model: MODEL, stored: false });
  } catch {
    return json(request, { error: "assistant_temporarily_unavailable" }, 503);
  }
}
