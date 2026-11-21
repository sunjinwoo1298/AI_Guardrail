const fmtCost = (n) => `$${Number(n || 0).toFixed(6)}`;

function riskLevel(score) {
  if (score >= 0.8) return "danger";
  if (score >= 0.35) return "warn";
  return "ok";
}

export function RiskMeter({ score }) {
  const value = Math.max(0, Math.min(1, Number(score) || 0));
  return (
    <div className="row">
      <div className={`meter ${riskLevel(value)}`}>
        <div style={{ width: `${value * 100}%` }} />
      </div>
      <span className="mono">{value.toFixed(2)}</span>
    </div>
  );
}

/** Security findings. Works for both successful metadata and 403 bodies. */
export function SecurityDetails({ data, status }) {
  const blocked = status === 403 || data.blocked;
  const piiTypes = [...new Set((data.pii_detections || []).map((d) => d.type))];
  const signals = data.prompt_injection_matches || [];

  return (
    <div className="panel-body">
      {blocked && (
        <div className="callout danger">
          Blocked by security policy (HTTP 403). Risk score {Number(data.risk_score ?? 0).toFixed(2)}.
        </div>
      )}
      <dl className="kv">
        <dt>Risk score</dt>
        <dd>{data.risk_score !== undefined ? <RiskMeter score={data.risk_score} /> : "n/a"}</dd>
        <dt>PII</dt>
        <dd>
          {data.pii_detected ? (
            <span className="row">
              <span className="tag warn">Detected</span>
              {piiTypes.map((t) => (
                <span key={t} className="tag mono">{t}</span>
              ))}
            </span>
          ) : (
            <span className="tag ok">None</span>
          )}
        </dd>
        <dt>Prompt injection</dt>
        <dd>
          {data.prompt_injection_detected ? (
            <span className="row">
              <span className="tag danger">Flagged</span>
              {signals.map((s) => (
                <span key={s} className="tag mono">{s}</span>
              ))}
            </span>
          ) : (
            <span className="tag ok">None</span>
          )}
        </dd>
        {data.sanitized !== undefined && (
          <>
            <dt>Prompt modified</dt>
            <dd>{data.sanitized ? "Yes, sensitive values were masked" : "No"}</dd>
          </>
        )}
      </dl>
      {data.sanitized_prompt && data.sanitized && (
        <div>
          <p className="hint">Prompt sent to the model</p>
          <pre className="block">{data.sanitized_prompt}</pre>
        </div>
      )}
    </div>
  );
}

/** Request/response metadata from /generate or the /stream meta event. */
export function MetadataDetails({ data }) {
  if (data.total_tokens === undefined && !data.request_id) return null;
  const cache = data.cache_hit ? `Hit (${data.cache_type})` : "Miss";
  return (
    <dl className="kv panel-body">
      <dt>Status</dt>
      <dd>{data.status || "success"}{data.reason ? ` (${data.reason})` : ""}</dd>
      <dt>Model</dt>
      <dd className="mono">{data.model || "n/a"}</dd>
      <dt>Cache</dt>
      <dd>
        {cache}
        {data.similarity_distance !== undefined && ` · distance ${Number(data.similarity_distance).toFixed(3)}`}
      </dd>
      <dt>Latency</dt>
      <dd>{data.latency}s</dd>
      <dt>Tokens</dt>
      <dd>
        {data.prompt_tokens} prompt + {data.completion_tokens} completion = {data.total_tokens}
      </dd>
      <dt>Cost</dt>
      <dd>
        {fmtCost(data.estimated_cost)}
        {data.cache_saved_cost > 0 && ` · saved ${fmtCost(data.cache_saved_cost)}`}
      </dd>
      <dt>Request ID</dt>
      <dd className="mono">{data.request_id}</dd>
    </dl>
  );
}

/** Rate limit / auth / server errors. */
export function ErrorSummary({ status, data }) {
  const message = data.error?.message || data.error || data.detail || "Request failed";
  const extra =
    status === 429
      ? `${data.reason || ""} (requests ${data.rpm_used}/${data.rpm_limit}, tokens ${data.tpm_used}/${data.tpm_limit})`
      : "";
  return (
    <div className="callout danger">
      <strong>{status ? `HTTP ${status}` : "Network error"}</strong>: {typeof message === "string" ? message : JSON.stringify(message)}
      {extra && <div className="hint">{extra}</div>}
    </div>
  );
}

/** Complete result block used by Security Lab and Test Cases. */
export default function ResultPanel({ result }) {
  if (!result) return null;
  const { ok, status, data } = result;
  return (
    <div className="panel">
      <div className="panel-head">
        <h3>Result</h3>
        <span className={`tag ${ok ? "ok" : "danger"}`}>{status || "error"}</span>
      </div>
      {ok ? (
        <>
          <div className="panel-body">
            <p className="msg-body">{data.response}</p>
          </div>
          <MetadataDetails data={data} />
        </>
      ) : (
        <div className="panel-body">
          <ErrorSummary status={status} data={data} />
        </div>
      )}
      <div style={{ borderTop: "1px solid var(--border)" }}>
        <SecurityDetails data={data} status={status} />
      </div>
    </div>
  );
}
