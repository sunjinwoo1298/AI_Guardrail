import { useCallback, useEffect, useState } from "react";
import { fetchMetrics, parseMetrics } from "../api.js";

// Sum samples for a metric, grouped by one label.
function groupBy(samples, name, label) {
  const groups = {};
  for (const s of samples) {
    if (s.name !== name) continue;
    const key = s.labels[label] ?? "n/a";
    groups[key] = (groups[key] || 0) + s.value;
  }
  return Object.entries(groups).sort((a, b) => b[1] - a[1]);
}

function total(samples, name) {
  return samples.filter((s) => s.name === name).reduce((sum, s) => sum + s.value, 0);
}

function Table({ title, rows, head }) {
  return (
    <div className="panel">
      <div className="panel-head"><h3>{title}</h3></div>
      {rows.length === 0 ? (
        <div className="panel-body"><span className="hint">No data yet.</span></div>
      ) : (
        <table>
          <thead>
            <tr><th>{head}</th><th className="num">Count</th></tr>
          </thead>
          <tbody>
            {rows.map(([k, v]) => (
              <tr key={k}><td>{k}</td><td className="num">{v}</td></tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function Metrics({ settings }) {
  const [samples, setSamples] = useState([]);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState(null);

  const load = useCallback(async () => {
    try {
      setSamples(parseMetrics(await fetchMetrics(settings)));
      setError("");
      setUpdated(new Date());
    } catch (e) {
      setError(`Could not load /metrics (${e.message}).`);
    }
  }, [settings]);

  useEffect(() => { load(); }, [load]);

  const requests = groupBy(samples, "ai_proxy_http_requests_total", "status").map(([k, v]) => [`HTTP ${k}`, v]);
  const lookups = samples
    .filter((s) => s.name === "ai_proxy_cache_lookups_total")
    .map((s) => [`${s.labels.layer} / ${s.labels.result}`, s.value]);
  const blocks = groupBy(samples, "ai_proxy_security_blocks_total", "reason");
  const events = groupBy(samples, "ai_proxy_security_events_total", "event");
  const cost = total(samples, "ai_proxy_model_cost_total");
  const savedCost = total(samples, "ai_proxy_cache_saved_cost_total");
  // Hit rate over requests that were actually answered (excludes degraded fallbacks).
  const answered = samples.filter(
    (s) => s.name === "ai_proxy_model_requests_total" && s.labels.cache_type !== "degraded",
  );
  const answeredTotal = answered.reduce((sum, s) => sum + s.value, 0);
  const answeredHits = answered.filter((s) => s.labels.cache_hit === "true").reduce((sum, s) => sum + s.value, 0);
  const hitRate = answeredTotal ? `${((answeredHits / answeredTotal) * 100).toFixed(1)}%` : "n/a";
  const unpriced = total(samples, "ai_proxy_unpriced_requests_total");
  const estimated = samples
    .filter((s) => s.name === "ai_proxy_usage_source_total" && s.labels.source === "estimated")
    .reduce((sum, s) => sum + s.value, 0);

  return (
    <div className="page">
      <div className="page-head">
        <h1>Metrics</h1>
        <p>Live counters from the proxy's /metrics endpoint. For history and alerting use Grafana.</p>
      </div>

      <div className="row">
        <button className="secondary" onClick={load}>Refresh</button>
        {updated && <span className="hint">Updated {updated.toLocaleTimeString()}</span>}
        <span className="grow" />
        <a href="http://localhost:3000" target="_blank" rel="noreferrer">Grafana</a>
        <a href="http://localhost:9090" target="_blank" rel="noreferrer">Prometheus</a>
      </div>

      {error && <div className="callout danger">{error}</div>}

      <div className="panel">
        <dl className="kv panel-body">
          <dt>Total requests</dt>
          <dd>{total(samples, "ai_proxy_http_requests_total")}</dd>
          <dt>Cache hit rate</dt>
          <dd>{hitRate} ({answeredHits} of {answeredTotal} answered)</dd>
          <dt>Model cost</dt>
          <dd>${cost.toFixed(6)}{unpriced > 0 && ` · ${unpriced} request(s) used an unpriced model`}</dd>
          <dt>Cost saved by cache</dt>
          <dd>${savedCost.toFixed(6)}</dd>
          <dt>Token counts estimated</dt>
          <dd>{estimated} request(s) (provider did not report usage)</dd>
          <dt>Tokens (total)</dt>
          <dd>
            {samples
              .filter((s) => s.name === "ai_proxy_model_tokens_total" && s.labels.kind === "total")
              .reduce((sum, s) => sum + s.value, 0)}
          </dd>
        </dl>
      </div>

      <div className="cols-3">
        <Table title="Requests by status" head="Status" rows={requests} />
        <Table title="Cache lookups" head="Layer / result" rows={lookups} />
        <Table title="Security blocks" head="Reason" rows={blocks} />
      </div>
      <Table title="Security events" head="Event" rows={events} />
    </div>
  );
}
