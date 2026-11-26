// Client for the AI Guardrail Proxy. Every call goes to the real proxy (through the Vite
// / nginx "/api" forward); nothing here fakes a response.

async function request(baseUrl, path, { method = "GET", key, adminToken, body, headers = {} } = {}) {
  const started = performance.now();
  const init = { method, headers: { ...headers } };
  if (key) init.headers.Authorization = `Bearer ${key}`;
  if (adminToken) init.headers.Authorization = `Bearer ${adminToken}`;
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(`${baseUrl.replace(/\/$/, "")}${path}`, init);
  } catch (error) {
    return {
      ok: false, status: 0, ms: Math.round(performance.now() - started), data: null,
      error: `Could not reach the proxy at ${baseUrl}. Is it running? (${error.message})`,
    };
  }
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  return {
    ok: response.ok,
    status: response.status,
    ms: Math.round(performance.now() - started),
    data,
    action: response.headers.get("x-guardrail-action"),
    reasons: (response.headers.get("x-guardrail-reasons") || "").split(",").filter(Boolean),
    error: response.ok ? null : describeError(response.status, data),
  };
}

/** One plain sentence saying what failed and what to do about it. */
export function describeError(status, data) {
  const err = data && typeof data === "object" ? data.error || data.detail : null;
  const message = typeof err === "string" ? err : err?.message;
  const code = err && typeof err === "object" ? err.code : data?.code;
  if (status === 401) return message && message !== "Unauthorized"
    ? message : "The proxy rejected the API key. Pick another key in the tenant switcher.";
  if (status === 403 && code === "insufficient_scope") return message;
  if (status === 403 && (code === "blocked_by_policy" || data?.reasons)) return "Blocked by the guardrail policy.";
  if (status === 413) return message || "The input is longer than the project allows.";
  if (status === 429) return message || "Rate limit or monthly budget reached for this project.";
  if (status === 503) return message || "The proxy could not reach a model or a required service (Redis, database).";
  if (status === 404) return message || "Not found. The proxy may be an older version without this endpoint.";
  if (status === 422) {
    if (Array.isArray(data?.detail)) return data.detail.map((d) => d.msg).join("; ");
    return message || "The request was invalid.";
  }
  return message || `The proxy answered ${status}.`;
}

export const proxy = {
  health: (c) => request(c.baseUrl, "/health"),
  ready: (c) => request(c.baseUrl, "/ready"),
  scan: (c, key, body, session) =>
    request(c.baseUrl, "/v1/guard/scan", {
      method: "POST", key, body, headers: session ? { "x-guardrail-session": session } : {},
    }),
  generate: (c, key, prompt) => request(c.baseUrl, "/generate", { method: "POST", key, body: { prompt } }),
};

export const admin = {
  get: (c, path) => request(c.baseUrl, `/admin/v1${path}`, { adminToken: c.adminToken }),
  post: (c, path, body = {}) => request(c.baseUrl, `/admin/v1${path}`, { method: "POST", adminToken: c.adminToken, body }),
  put: (c, path, body) => request(c.baseUrl, `/admin/v1${path}`, { method: "PUT", adminToken: c.adminToken, body }),
  patch: (c, path, body) => request(c.baseUrl, `/admin/v1${path}`, { method: "PATCH", adminToken: c.adminToken, body }),
};
