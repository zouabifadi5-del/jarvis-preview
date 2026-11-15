/**
 * J.A.R.V.I.S. Worker entry point.
 * Owner authentication and assistant requests fail closed until the required
 * D1, origin, WebAuthn, and Workers AI bindings are configured.
 */
import { handleAuthRequest } from "./auth/routes.js";
import { handleAssistantRequest } from "./assistant.js";

function jsonResponse(request, body, status = 200) {
  const headers = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  };
  if (new URL(request.url).protocol === "https:") {
    headers["Strict-Transport-Security"] = "max-age=31536000";
  }
  return Response.json(body, { status, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/health" && request.method === "GET") {
      return jsonResponse(request, {
        service: "jarvis-api",
        status: "ok",
        mode: "iphone-assistant",
        aiConfigured: Boolean(env?.AI),
        authenticationConfigured: Boolean(env?.DB && env?.AUTH_ORIGIN && env?.WEBAUTHN_RP_ID)
      });
    }

    if (url.pathname === "/assistant/chat") {
      return handleAssistantRequest(request, env);
    }

    if (url.pathname.startsWith("/auth/")) {
      return handleAuthRequest(request, env);
    }

    const isStaticAsset = url.pathname === "/" ||
      url.pathname.endsWith(".html") ||
      url.pathname.endsWith(".js") ||
      url.pathname.endsWith(".css") ||
      url.pathname.endsWith(".webmanifest") ||
      url.pathname.endsWith(".svg");
    const acceptsHtml = (request.headers.get("Accept") || "").includes("text/html");
    if (
      env?.ASSETS &&
      (request.method === "GET" || request.method === "HEAD") &&
      (isStaticAsset || acceptsHtml)
    ) {
      return env.ASSETS.fetch(request);
    }

    return jsonResponse(request, {
      error: "not_found",
      message: "This endpoint is not implemented."
    }, 404);
  }
};
