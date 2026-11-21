// Thin client for the guardrail proxy. Request functions resolve to
// { ok, status, data } and never throw for HTTP errors.

function url(settings, path) {
  return `${settings.baseUrl.replace(/\/+$/, "")}${path}`;
}

function headers(settings) {
  const h = { "Content-Type": "application/json" };
  if (settings.apiKey) h["x-api-key"] = settings.apiKey;
  return h;
}

async function readJson(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return { error: text || res.statusText };
  }
}

function networkError(err) {
  return { ok: false, status: 0, data: { error: `Could not reach proxy: ${err.message}` } };
}

export async function checkHealth(settings) {
  try {
    const res = await fetch(url(settings, "/health"));
    return res.ok;
  } catch {
    return false;
  }
}

export async function fetchMetrics(settings) {
  // Trailing slash avoids the redirect from the mounted metrics app.
  const res = await fetch(url(settings, "/metrics/"));
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.text();
}

export async function generate(settings, prompt) {
  try {
    const res = await fetch(url(settings, "/generate"), {
      method: "POST",
      headers: headers(settings),
      body: JSON.stringify({ prompt }),
    });
    return { ok: res.ok, status: res.status, data: await readJson(res) };
  } catch (err) {
    return networkError(err);
  }
}

export async function chatCompletion(settings, model, messages) {
  try {
    const res = await fetch(url(settings, "/v1/chat/completions"), {
      method: "POST",
      headers: headers(settings),
      body: JSON.stringify({ model, messages, stream: false }),
    });
    return { ok: res.ok, status: res.status, data: await readJson(res) };
  } catch (err) {
    return networkError(err);
  }
}

// Yields raw SSE events (text between blank lines).
async function* sseEvents(res) {
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      yield buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
    }
  }
  if (buffer.trim()) yield buffer;
}

// An SSE event may span several "data:" lines; per the spec they are joined with "\n".
const stripData = (ev) =>
  ev
    .split("\n")
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(line.startsWith("data: ") ? 6 : 5))
    .join("\n");

/**
 * Streams from /stream, or from /v1/chat/completions when `messages` is given.
 * Calls onChunk(text) per delta. Resolves { ok, status, data } where data is the
 * final metadata (/stream) or an error body.
 */
export async function streamResponse(settings, { prompt, model, messages }, onChunk) {
  const chat = Boolean(messages);
  try {
    const res = await fetch(url(settings, chat ? "/v1/chat/completions" : "/stream"), {
      method: "POST",
      headers: headers(settings),
      body: JSON.stringify(chat ? { model, messages, stream: true } : { prompt }),
    });
    if (!res.ok) return { ok: false, status: res.status, data: await readJson(res) };

    let meta = null;
    for await (const ev of sseEvents(res)) {
      const payload = stripData(ev);
      if (chat) {
        if (payload.trim() === "[DONE]") break;
        try {
          const text = JSON.parse(payload)?.choices?.[0]?.delta?.content;
          if (text) onChunk(text);
        } catch {
          /* ignore malformed chunk */
        }
        continue;
      }
      if (payload.startsWith('{"__meta"')) {
        try {
          meta = JSON.parse(payload).__meta;
          continue;
        } catch {
          /* fall through and treat as text */
        }
      }
      onChunk(payload);
    }
    return { ok: true, status: res.status, data: meta || {} };
  } catch (err) {
    return networkError(err);
  }
}

// Parse Prometheus text exposition into [{ name, labels, value }].
export function parseMetrics(text) {
  const out = [];
  for (const line of text.split("\n")) {
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^([a-zA-Z_:][\w:]*)(?:\{([^}]*)\})?\s+(\S+)/);
    if (!m) continue;
    const labels = {};
    if (m[2]) {
      for (const p of m[2].matchAll(/(\w+)="((?:[^"\\]|\\.)*)"/g)) labels[p[1]] = p[2];
    }
    const value = Number(m[3]);
    if (!Number.isNaN(value)) out.push({ name: m[1], labels, value });
  }
  return out;
}
