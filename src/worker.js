/**
 * J.A.R.V.I.S. Worker entry point.
 * Authentication routes fail closed until D1 and explicit origin/RP settings
 * are configured. No AI calls or personal-content storage are exposed here.
 */
import { handleAuthRequest } from "./auth/routes.js";

function securityHeaders(request, { noStore = false } = {}) {
  const headers = new Headers({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin"
  });
  if (noStore) headers.set("Cache-Control", "no-store");
  if (new URL(request.url).protocol === "https:") {
    headers.set("Strict-Transport-Security", "max-age=31536000");
  }
  return headers;
}

function jsonResponse(request, body, status = 200) {
  return Response.json(body, { status, headers: securityHeaders(request, { noStore: true }) });
}

async function secureAssetResponse(request, assets) {
  const upstream = await assets.fetch(request);
  const headers = new Headers(upstream.headers);
  for (const [name, value] of securityHeaders(request)) headers.set(name, value);
  headers.set(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; upgrade-insecure-requests"
  );
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers
  });
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

    const isStaticAsset = url.pathname === "/" ||
      url.pathname.endsWith(".html") ||
      url.pathname.endsWith(".js") ||
      url.pathname.endsWith(".css");
    const acceptsHtml = (request.headers.get("Accept") || "").includes("text/html");
    if (
      env?.ASSETS &&
      (request.method === "GET" || request.method === "HEAD") &&
      (isStaticAsset || acceptsHtml)
    ) {
      return secureAssetResponse(request, env.ASSETS);
    }

    return jsonResponse(request, {
      error: "not_found",
      message: "This endpoint is not implemented."
    }, 404);
  }
};
