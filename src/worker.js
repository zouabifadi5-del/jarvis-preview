/**
 * J.A.R.V.I.S. Worker entry point.
 * Authentication routes fail closed until D1 and explicit origin/RP settings
 * are configured. No AI calls or personal-content storage are exposed here.
 */
import { handleAuthRequest } from "./auth/routes.js";

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
        mode: "authentication-scaffold",
        aiConnected: false
      });
    }

    if (url.pathname.startsWith("/auth/")) {
      return handleAuthRequest(request, env);
    }

    if (env?.ASSETS && (request.method === "GET" || request.method === "HEAD")) {
      return env.ASSETS.fetch(request);
    }

    return jsonResponse(request, {
      error: "not_found",
      message: "This endpoint is not implemented."
    }, 404);
  }
};
