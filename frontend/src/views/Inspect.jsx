import { useState } from "react";
import { proxy } from "../api.js";
import InspectedText, { countMasks } from "../components/InspectedText.jsx";
import Trace from "../components/Trace.jsx";
import { SCENARIOS } from "../scenarios.js";
import { useStore } from "../store.jsx";

const UNTRUSTED = { user: "user", tool: "tool result", function: "tool result" };

function messagesAsText(messages) {
  return (messages || [])
    .filter((m) => UNTRUSTED[m.role] && typeof m.content === "string")
    .map((m) => `${UNTRUSTED[m.role]}: ${m.content}`)
    .join("\n\n");
}

export function humanReason(reason) {
  const [kind, detail] = reason.split(/:(.*)/s);
  switch (kind) {
    case "prompt_injection": return "prompt injection";
    case "risk_score": return "risk score over the project's limit";
    case "pii": return `personal data (${detail.replace(/,/g, ", ")})`;
    case "deny": return `keyword rule "${detail}"`;
    case "tool_not_allowed": return `tool "${detail}" is not allowed`;
    case "tool_arguments_invalid": return `"${detail}" arguments don't match the schema`;
    case "tool_arguments_denied": return `"${detail}" arguments contain a denied pattern`;
    case "session_locked": return "session locked after repeated attacks";
    case "unscanned_media": return `unscanned ${detail}`;
    case "moderation": return `harmful content (${detail})`;
    case "moderation_unavailable": return "moderation unavailable";
    case "exfiltration": return `leaking ${detail}`;
    case "canary_leak": return "system prompt leaked";
    default: return reason.replace(/_/g, " ");
  }
}

/** Normalise a guard-scan or /generate result into what the screen shows. */
function toView(kind, res, sent, tenantLabel) {
  const d = res.data && typeof res.data === "object" ? res.data : {};
  const reasons = d.reasons || d.guardrail_reasons || res.reasons || [];
  const action = d.action || d.guardrail_action || res.action || (res.status === 403 ? "block" : res.ok ? "allow" : null);
  const piiTypes = d.detections?.pii || [...new Set((d.pii_detections || []).map((p) => p.type))];
  return {
    kind, status: res.status, ok: res.ok, error: res.error, ms: res.ms, tenantLabel,
    action, reasons, sent,
    risk: typeof d.risk_score === "number" ? d.risk_score : null,
    piiTypes,
    matches: d.detections?.prompt_injection?.matches || [],
    received: kind === "scan" ? (d.sanitized?.input ?? messagesAsText(d.sanitized?.messages)) : d.sanitized_prompt,
    answer: kind === "full" && res.ok ? d.response : null,
    model: d.model, latency: d.latency, cacheHit: d.cache_hit, cacheType: d.cache_type,
    tokens: d.total_tokens, cost: d.estimated_cost, requestId: d.request_id, policyMode: d.policy_mode,
    degraded: d.status === "degraded",
    outputRedacted: typeof d.output_redacted === "number" ? d.output_redacted : null,
  };
}

function buildTrace(v) {
  const stoppedEarly = v.status === 0 || v.status === 401 || v.status === 413 || v.status === 429 ||
    (v.status === 503 && !v.degraded);
  const skip = (name) => ({ name, verdict: "skip", pill: "not reached", detail: "The request stopped earlier." });
  const steps = [];
  if (stoppedEarly) {
    steps.push({ name: "Key and limits", verdict: "block", pill: v.status ? String(v.status) : "unreachable", detail: v.error });
    return [...steps, ...["Prompt injection", "Personal data", "Policy", "Model", "Output redaction"].map(skip)];
  }
  steps.push({ name: "Key and limits", verdict: "pass", detail: `Accepted for ${v.tenantLabel}` });

  const stopped = v.action === "block";
  const monitor = v.action === "would_block";
  const injection = v.reasons.filter((r) => r === "prompt_injection" || r === "risk_score");
  const piiBlock = v.reasons.filter((r) => r.startsWith("pii:"));
  const policy = v.reasons.filter((r) => !injection.includes(r) && !piiBlock.includes(r));
  const risk = v.risk === null ? "" : ` (risk ${v.risk.toFixed(2)})`;

  steps.push(injection.length
    ? { name: "Prompt injection", verdict: stopped ? "block" : "flag", pill: monitor ? "would block" : stopped ? "blocked" : "flagged",
        detail: v.matches.length ? `Caught "${v.matches[0]}"${risk}` : `The classifier rated it an attack${risk}` }
    : { name: "Prompt injection", verdict: "pass", detail: `No attack found${risk}` });

  if (piiBlock.length) {
    steps.push({ name: "Personal data", verdict: stopped ? "block" : "flag", pill: monitor ? "would block" : "blocked",
                 detail: `The policy blocks ${v.piiTypes.join(", ")}` });
  } else if (v.piiTypes.length) {
    steps.push({ name: "Personal data", verdict: "flag", pill: "masked", detail: v.piiTypes.join(", ") });
  } else {
    steps.push({ name: "Personal data", verdict: "pass", detail: "None found" });
  }

  const modeText = v.policyMode === "monitor" ? "Monitor mode" : "Enforce mode";
  steps.push(policy.length
    ? { name: "Policy", verdict: stopped ? "block" : "flag", pill: monitor ? "would block" : stopped ? "blocked" : "flagged",
        detail: policy.map(humanReason).join("; ") }
    : { name: "Policy", verdict: monitor ? "flag" : "pass", pill: monitor ? "monitor" : undefined,
        detail: monitor ? `${modeText}: let through, recorded as would-block` : modeText });

  if (v.kind === "scan") {
    steps.push({ name: "Model", verdict: "skip", pill: "not called", detail: "Scan only: no model call" });
    steps.push({ name: "Output redaction", verdict: "skip", pill: "not called", detail: "Runs on the model's answer" });
  } else if (stopped) {
    steps.push({ name: "Model", verdict: "skip", pill: "not called", detail: "Stopped before the model" });
    steps.push({ name: "Output redaction", verdict: "skip", pill: "not called", detail: "No answer to redact" });
  } else if (!v.ok || v.degraded) {
    steps.push({ name: "Model", verdict: "error", pill: String(v.status), detail: v.error || "No model answered" });
    steps.push({ name: "Output redaction", verdict: "skip", pill: "not reached", detail: "No answer to redact" });
  } else {
    steps.push(v.cacheHit
      ? { name: "Model", verdict: "pass", pill: "cache hit", detail: `Answered from the ${v.cacheType} cache, no model call` }
      : { name: "Model", verdict: "pass", detail: `${v.model}, ${Math.round((v.latency || 0) * 1000)} ms` });
    // The proxy reports how many values it redacted; labels the model wrote itself
    // (echoing its masked prompt) are not counted.
    const n = v.outputRedacted;
    steps.push(n
      ? { name: "Output redaction", verdict: "flag", pill: "redacted", detail: `${n} value${n > 1 ? "s" : ""} removed from the answer` }
      : { name: "Output redaction", verdict: "pass",
          detail: v.cacheHit ? "Cached answers are stored already redacted" : n === 0 ? "Nothing to redact" : "Checked" });
  }
  return steps;
}

function Headline({ v }) {
  if (v.status === 0 || (!v.ok && v.status !== 403 && !v.degraded)) return <p className="notice block">{v.error}</p>;
  if (v.degraded) return <p className="notice block">Every model was unavailable (503). The prompt passed the guardrails.</p>;
  const reasons = v.reasons.map(humanReason).join("; ");
  if (v.action === "block") return <p className="notice block"><strong>Blocked:</strong> {reasons}.</p>;
  if (v.action === "would_block") return <p className="notice flag"><strong>Monitor mode let this through.</strong> In enforce mode it would be blocked: {reasons}.</p>;
  if (v.action === "flag") return <p className="notice flag"><strong>Allowed and recorded:</strong> {reasons}.</p>;
  return <p className="notice pass"><strong>Allowed.</strong> {v.piiTypes.length ? "Personal data was masked first." : "Nothing needed changing."}</p>;
}

export default function Inspect() {
  const { conn, tenant, update, setMode } = useStore();
  const [scenarioId, setScenarioId] = useState(SCENARIOS[0].id);
  const [text, setText] = useState(SCENARIOS[0].prompt);
  const [messages, setMessages] = useState(null);
  const [mode, setModeLocal] = useState("scan");
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState(null);
  const [runId, setRunId] = useState(0);

  function pick(scenario) {
    setScenarioId(scenario.id);
    setMessages(scenario.messages || null);
    setText(scenario.prompt || messagesAsText(scenario.messages));
    setView(null);
  }

  async function send() {
    if (busy || !text.trim()) return;
    setBusy(true);
    const useScan = mode === "scan" || messages;
    const sent = messages ? messagesAsText(messages) : text;
    const res = useScan
      ? await proxy.scan(conn, tenant.key, messages ? { messages } : { input: text })
      : await proxy.generate(conn, tenant.key, text);
    const next = toView(useScan ? "scan" : "full", res, sent, tenant.label);
    if (next.policyMode) setMode(tenant.id, next.policyMode);
    update({ lastPrompt: messages ? "" : text });
    setView(next);
    setRunId((n) => n + 1);
    setBusy(false);
  }

  const blocked = view && view.action === "block";
  const masked = view ? countMasks(view.received) : 0;

  return (
    <div className="page">
      <div className="page-head">
        <h1>Inspect a request</h1>
        <p className="lede">Send a prompt through the proxy and see what every guardrail did to it.</p>
      </div>

      <div className="inspect">
        <div className="inspect-left">
          <div className="composer">
            <div className="composer-main">
              <label className="field" htmlFor="prompt">Prompt</label>
              <textarea id="prompt" className="payload" rows={6} value={text} readOnly={Boolean(messages)}
                        onChange={(e) => { setText(e.target.value); setMessages(null); setScenarioId(null); }}
                        onKeyDown={(e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) send(); }} />
              {messages && <p className="small muted">This scenario is a conversation with a tool result, so it runs as a scan.</p>}
              <div className="row">
                <div className="segmented" role="group" aria-label="How to send">
                  <button aria-pressed={mode === "scan"} onClick={() => setModeLocal("scan")}>Scan only</button>
                  <button aria-pressed={mode === "full"} disabled={Boolean(messages)} onClick={() => setModeLocal("full")}>
                    Full request to the model
                  </button>
                </div>
                <span className="grow" />
                <button className="btn primary" onClick={send} disabled={busy || !text.trim()}>
                  {busy ? "Sending…" : "Send through proxy"}
                </button>
              </div>
              <p className="small muted">
                {mode === "scan" || messages
                  ? "Scan only uses POST /v1/guard/scan: every check, no model call, no provider key needed."
                  : "Full request uses POST /generate: the guardrails, then the project's model, then output redaction."}
              </p>
            </div>
            <div>
              <h3 style={{ marginBottom: 8 }}>Try a scenario</h3>
              <ul className="scenarios">
                {SCENARIOS.map((s) => (
                  <li key={s.id}>
                    <button aria-pressed={scenarioId === s.id} onClick={() => pick(s)}>
                      <span className="scenario-name">{s.name}</span>
                      <span className="scenario-expect">Expected: {s.expect.toLowerCase()}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {view && <Headline v={view} />}

          {view && (
            <section aria-label="What you sent">
              <div className="doc-label"><h3>What you sent</h3></div>
              <div className="sheet"><InspectedText text={view.sent} strike={view.matches} /></div>
              {view.matches.length > 0 && <p className="caption">Struck through: the phrases the tripwires caught.</p>}
            </section>
          )}

          {view && view.status !== 0 && (view.ok || view.status === 403) && (
            <section aria-label="What the model received">
              <div className="doc-label">
                <h3>{view.kind === "scan" ? "What the model would receive" : "What the model received"}</h3>
              </div>
              <div className="sheet">
                {blocked
                  ? <p className="muted">Nothing. The request was stopped before the model.</p>
                  : <InspectedText key={runId} text={view.received || view.sent} animate />}
              </div>
              {!blocked && (
                <p className="caption">
                  {masked ? `${masked} value${masked > 1 ? "s" : ""} masked before the model saw ${masked > 1 ? "them" : "it"}.` : "Nothing needed masking."}
                </p>
              )}
            </section>
          )}

          {view && view.answer && (
            <section aria-label="What your app received">
              <div className="doc-label"><h3>What your app received</h3></div>
              <div className="sheet"><InspectedText text={view.answer} prose /></div>
              <p className="caption">
                {view.outputRedacted
                  ? `${view.outputRedacted} value${view.outputRedacted > 1 ? "s were" : " was"} redacted from the model's answer.`
                  : "Labels in the answer come from the masked prompt the model saw; nothing new needed redacting."}
              </p>
            </section>
          )}
        </div>

        <aside aria-label="Checkpoints">
          <h2 style={{ marginBottom: 16 }}>Checkpoints</h2>
          {view ? (
            <Trace key={runId} steps={buildTrace(view)} reveal />
          ) : (
            <p className="muted">Send a prompt to see each checkpoint's verdict here, in the order the proxy runs them.</p>
          )}
          {view && view.status !== 0 && (
            <div className="aside-block">
              <dl className="facts">
                <dt>Status</dt><dd>{view.status}</dd>
                {view.risk !== null && (<><dt>Risk score</dt><dd>{view.risk.toFixed(2)}</dd></>)}
                {view.kind === "full" && view.ok && (<><dt>Cache</dt><dd>{view.cacheHit ? `hit (${view.cacheType})` : "miss"}</dd></>)}
                {view.tokens !== undefined && view.tokens !== null && (<><dt>Tokens</dt><dd>{view.tokens}</dd></>)}
                {typeof view.cost === "number" && (<><dt>Cost</dt><dd>${view.cost.toFixed(6)}</dd></>)}
                <dt>Round trip</dt><dd>{view.ms} ms</dd>
                {view.requestId && (<><dt>Request id</dt><dd className="mono">{view.requestId}</dd></>)}
              </dl>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
