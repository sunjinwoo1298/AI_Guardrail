import { useRef, useState } from "react";
import { chatCompletion, generate, streamResponse } from "../api.js";
import { ErrorSummary, MetadataDetails, SecurityDetails } from "./ResultPanel.jsx";

export default function Playground({ settings, onResult }) {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(null);
  const bottomRef = useRef(null);

  const patchLast = (patch) =>
    setMessages((prev) => prev.map((m, i) => (i === prev.length - 1 ? { ...m, ...patch } : m)));

  async function send() {
    const prompt = input.trim();
    if (!prompt || busy) return;
    setInput("");
    setBusy(true);

    const history = [...messages.filter((m) => !m.error), { role: "user", content: prompt }];
    setMessages([...messages, { role: "user", content: prompt }, { role: "assistant", content: "", pending: true }]);

    let result;
    if (settings.endpoint === "stream") {
      let text = "";
      result = await streamResponse(settings, { prompt }, (chunk) => {
        text += chunk;
        patchLast({ content: text });
      });
    } else if (settings.endpoint === "chat") {
      result = await chatCompletion(
        settings,
        settings.model,
        history.map(({ role, content }) => ({ role, content })),
      );
      if (result.ok) {
        const reply = result.data?.choices?.[0]?.message?.content ?? "";
        const usage = result.data?.usage || {};
        result = {
          ...result,
          data: { model: result.data?.model, content: reply, total_tokens: usage.total_tokens || 0, ...usage, status: "success" },
        };
      }
    } else {
      result = await generate(settings, prompt);
    }

    onResult(result);
    const reply =
      settings.endpoint === "chat" ? result.data?.content : result.data?.response;
    if (result.ok) {
      const content = settings.endpoint === "stream" ? undefined : reply;
      patchLast({ ...(content !== undefined ? { content } : {}), pending: false, meta: result.data, status: result.status });
    } else {
      patchLast({ content: "", pending: false, error: true, meta: result.data, status: result.status });
    }
    setBusy(false);
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: "smooth" }), 50);
  }

  function onKeyDown(e) {
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) send();
  }

  return (
    <div className="page">
      <div className="page-head">
        <h1>Playground</h1>
        <p>Send prompts through the proxy and inspect what the guardrails did with them.</p>
      </div>

      <div className="chat">
        {messages.length === 0 && <p className="hint">No messages yet.</p>}
        {messages.map((m, i) => (
          <div key={i} className={`msg ${m.role} ${m.error ? "error" : ""}`}>
            <span className="msg-role">{m.role === "user" ? "You" : "Proxy"}</span>
            {m.error ? (
              <ErrorSummary status={m.status} data={m.meta || {}} />
            ) : (
              <div className="msg-body">{m.content || (m.pending ? "…" : "")}</div>
            )}
            {m.role === "assistant" && m.meta && !m.pending && (
              <div>
                <button className="secondary" onClick={() => setOpen(open === i ? null : i)}>
                  {open === i ? "Hide details" : "Details"}
                </button>
                {open === i && (
                  <div className="panel" style={{ marginTop: 8 }}>
                    {!m.error && <MetadataDetails data={m.meta} />}
                    <SecurityDetails data={m.meta} status={m.status} />
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      <div className="composer">
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Enter a prompt"
          aria-label="Prompt"
        />
        <div className="row">
          <button className="primary" onClick={send} disabled={busy || !input.trim()}>
            {busy ? "Sending…" : "Send"}
          </button>
          <button className="secondary" onClick={() => setMessages([])} disabled={busy || messages.length === 0}>
            Clear
          </button>
          <span className="hint">Ctrl+Enter to send</span>
        </div>
      </div>
    </div>
  );
}
