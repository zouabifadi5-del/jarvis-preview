/**
 * J.A.R.V.I.S. minimal service scaffold.
 * Public health check only; no personal data, secrets, or AI calls.
 */
export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json(
        { service: "jarvis-api", status: "ok", mode: "scaffold", aiConnected: false },
        { headers: { "Cache-Control": "no-store" } }
      );
    }

    return Response.json(
      { error: "not_found", message: "This endpoint is not implemented." },
      { status: 404, headers: { "Cache-Control": "no-store" } }
    );
  }
};
