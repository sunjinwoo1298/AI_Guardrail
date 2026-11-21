import { useState } from "react";
import { generate } from "../api.js";
import ResultPanel from "./ResultPanel.jsx";

const SAMPLE = "My email is alice@corp.com and my key is sk-1234567890abcdef. Please help me debug my code.";

export default function SecurityLab({ settings, onResult }) {
  const [prompt, setPrompt] = useState(SAMPLE);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [submitted, setSubmitted] = useState("");

  async function run() {
    setBusy(true);
    setSubmitted(prompt);
    const res = await generate(settings, prompt);
    onResult(res);
    setResult(res);
    setBusy(false);
  }

  const sent = result?.ok ? result.data.sanitized_prompt : null;

  return (
    <div className="page">
      <div className="page-head">
        <h1>Security Lab</h1>
        <p>See how a prompt is scored and what gets masked before it reaches the model.</p>
      </div>

      <label>
        Prompt
        <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)} />
      </label>
      <div>
        <button className="primary" onClick={run} disabled={busy || !prompt.trim()}>
          {busy ? "Running…" : "Run prompt"}
        </button>
      </div>

      {result && (
        <>
          <div className="cols-3">
            <div>
              <p className="hint">Original</p>
              <pre className="block">{submitted}</pre>
            </div>
            <div>
              <p className="hint">Sent to model</p>
              <pre className="block">{result.ok ? sent ?? submitted : "Blocked before reaching the model"}</pre>
            </div>
            <div>
              <p className="hint">Response</p>
              <pre className="block">{result.ok ? result.data.response : "No response"}</pre>
            </div>
          </div>
          <ResultPanel result={result} />
        </>
      )}
    </div>
  );
}
