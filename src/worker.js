/**
 * J.A.R.V.I.S. minimal service scaffold.
 * Public health check only; no personal data, secrets, or AI calls.
 */

function jsonResponse(request, body, status = 200) {
  const headers = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  };

  // Advertise HTTPS-only transport only when the incoming request used HTTPS.
  if (new URL(request.url).protocol === "https:") {
    headers["Strict-Transport-Security"] = "max-age=31536000";
  }

  return Response.json(body, { status, headers });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return jsonResponse(request, {
        service: "jarvis-api",
        status: "ok",
        mode: "scaffold",
        aiConnected: false
      });
    }

    return jsonResponse(request, {
      error: "not_found",
      message: "This endpoint is not implemented."
    }, 404);
  }
};
