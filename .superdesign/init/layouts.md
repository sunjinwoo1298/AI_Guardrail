# Layouts

Framework: React 18 + Vite 5 (SPA, no router library; views switched by state in App.jsx). No component library. Plain global CSS (`src/styles.css`) with CSS custom properties. Backend: FastAPI AI Guardrail Proxy, reached through the Vite dev proxy at `/api`.

## App shell (`frontend/src/App.jsx`)
Two-column grid: 240px left sidebar (brand, view nav, connection settings, playground settings, session stats) and a scrolling main area rendering the active view. Collapses to one column under 760px.

### `frontend/src/App.jsx`

```jsx
import { useCallback, useEffect, useState } from "react";
import { checkHealth } from "./api.js";
import { MODELS } from "./presets.js";
import Playground from "./components/Playground.jsx";
import SecurityLab from "./components/SecurityLab.jsx";
import TestCases from "./components/TestCases.jsx";
import Metrics from "./components/Metrics.jsx";

const DEFAULTS = { baseUrl: "/api", apiKey: "test-api-key", model: MODELS[0], endpoint: "generate" };
const EMPTY_STATS = { requests: 0, served: 0, cacheHits: 0, blocked: 0, tokens: 0, saved: 0 };

const VIEWS = [
  ["playground", "Playground"],
  ["lab", "Security Lab"],
  ["tests", "Test cases"],
  ["metrics", "Metrics"],
];

function loadSettings() {
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem("proxy-settings") || "{}") };
  } catch {
    return DEFAULTS;
  }
}

export default function App() {
  const [view, setView] = useState("playground");
  const [settings, setSettings] = useState(loadSettings);
  const [online, setOnline] = useState(null);
  const [stats, setStats] = useState(EMPTY_STATS);

  const update = (patch) => setSettings((s) => ({ ...s, ...patch }));

  useEffect(() => {
    try {
      localStorage.setItem("proxy-settings", JSON.stringify(settings));
    } catch {
      /* storage unavailable */
    }
  }, [settings]);

  useEffect(() => {
    let cancelled = false;
    const ping = async () => {
      const ok = await checkHealth(settings);
      if (!cancelled) setOnline(ok);
    };
    ping();
    const id = setInterval(ping, 15000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [settings.baseUrl]);

  // Called by every view after a request so the sidebar counters stay current.
  const onResult = useCallback((result) => {
    setStats((s) => ({
      requests: s.requests + 1,
      // Only responses that report cache status count toward the hit rate
      // (blocked, rate-limited, degraded and raw chat-completion replies do not).
      served: s.served + (result.ok && typeof result.data?.cache_hit === "boolean" && result.data?.status !== "degraded" ? 1 : 0),
      blocked: s.blocked + (result.status === 403 ? 1 : 0),
      cacheHits: s.cacheHits + (result.data?.cache_hit ? 1 : 0),
      tokens: s.tokens + (result.data?.total_tokens || 0),
      saved: s.saved + (result.data?.cache_saved_cost || 0),
    }));
  }, []);

  const hitRate = stats.served ? Math.round((stats.cacheHits / stats.served) * 100) : 0;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <h1>Guardrail Proxy</h1>
          <small>Console</small>
        </div>

        <nav className="nav" aria-label="Views">
          {VIEWS.map(([id, label]) => (
            <button key={id} className={view === id ? "active" : ""} onClick={() => setView(id)}>
              {label}
            </button>
          ))}
        </nav>

        <div className="section">
          <h3>Connection</h3>
          <div className="status">
            <span className={`dot ${online === null ? "" : online ? "ok" : "bad"}`} />
            {online === null ? "Checking…" : online ? "Proxy reachable" : "Proxy unreachable"}
          </div>
          <label>
            Proxy URL
            <input value={settings.baseUrl} onChange={(e) => update({ baseUrl: e.target.value })} />
          </label>
          <label>
            API key
            <input type="password" value={settings.apiKey} onChange={(e) => update({ apiKey: e.target.value })} />
          </label>
        </div>

        <div className="section">
          <h3>Playground</h3>
          <label>
            Endpoint
            <select value={settings.endpoint} onChange={(e) => update({ endpoint: e.target.value })}>
              <option value="generate">/generate</option>
              <option value="stream">/stream</option>
              <option value="chat">/v1/chat/completions</option>
            </select>
          </label>
          <label>
            Model
            <select
              value={settings.model}
              disabled={settings.endpoint !== "chat"}
              onChange={(e) => update({ model: e.target.value })}
            >
              {MODELS.map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
          </label>
          {settings.endpoint !== "chat" && <p className="hint">Model is only used by /v1/chat/completions.</p>}
        </div>

        <div className="section">
          <h3>Session</h3>
          <dl className="stats">
            <dt>Requests</dt><dd>{stats.requests}</dd>
            <dt>Cache hit rate</dt><dd>{hitRate}%</dd>
            <dt>Blocked</dt><dd>{stats.blocked}</dd>
            <dt>Tokens</dt><dd>{stats.tokens}</dd>
            <dt>Cost saved</dt><dd>${stats.saved.toFixed(6)}</dd>
          </dl>
          <button className="secondary" onClick={() => setStats(EMPTY_STATS)}>Reset</button>
        </div>
      </aside>

      <main className="main">
        {view === "playground" && <Playground settings={settings} onResult={onResult} />}
        {view === "lab" && <SecurityLab settings={settings} onResult={onResult} />}
        {view === "tests" && <TestCases settings={settings} onResult={onResult} />}
        {view === "metrics" && <Metrics settings={settings} />}
      </main>
    </div>
  );
}

```

### `frontend/src/main.jsx`

```jsx
import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import "./styles.css";

createRoot(document.getElementById("root")).render(<App />);

```
