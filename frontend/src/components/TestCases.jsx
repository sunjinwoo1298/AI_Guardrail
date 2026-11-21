import { useState } from "react";
import { generate } from "../api.js";
import { PRESETS } from "../presets.js";
import ResultPanel from "./ResultPanel.jsx";

export default function TestCases({ settings, onResult }) {
  const [results, setResults] = useState({});
  const [running, setRunning] = useState(null);

  async function run(index, prompt) {
    setRunning(index);
    const res = await generate(settings, prompt);
    onResult(res);
    setResults((prev) => ({ ...prev, [index]: res }));
    setRunning(null);
  }

  return (
    <div className="page">
      <div className="page-head">
        <h1>Test cases</h1>
        <p>Prebuilt prompts for checking caching, PII masking and injection blocking.</p>
      </div>

      <div className="panel">
        {PRESETS.map((p, i) => (
          <div className="preset" key={p.name}>
            <div className="row">
              <div className="grow">
                <strong>{p.name}</strong> <span className="tag">{p.category}</span>
                <p className="hint">{p.description}</p>
              </div>
              <button className="secondary" onClick={() => run(i, p.prompt)} disabled={running !== null}>
                {running === i ? "Running…" : "Run"}
              </button>
            </div>
            <pre className="block">{p.prompt}</pre>
            <ResultPanel result={results[i]} />
          </div>
        ))}
      </div>
    </div>
  );
}
