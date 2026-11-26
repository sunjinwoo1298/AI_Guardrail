// Verdict pills and the numbered checkpoint trace (the one place numbering is used: the
// steps really are the order a request goes through the proxy).

const LABELS = { pass: "pass", block: "blocked", flag: "flagged", skip: "skipped", error: "error" };

export function Pill({ verdict, children }) {
  const tone = verdict === "error" ? "block" : verdict === "skip" ? "" : verdict;
  return <span className={`pill ${tone}`}>{children || LABELS[verdict] || verdict}</span>;
}

export default function Trace({ steps, reveal }) {
  return (
    <ol className={`trace${reveal ? " revealing" : ""}`} aria-label="Checkpoints in request order">
      {steps.map((step, i) => (
        <li key={step.name} className={step.verdict} style={reveal ? { animationDelay: `${i * 60}ms` } : undefined}>
          <span className="step-num" aria-hidden="true">{i + 1}</span>
          <div>
            <div className="step-head">
              <span className="step-name">{step.name}</span>
              <Pill verdict={step.verdict}>{step.pill}</Pill>
            </div>
            <p className="step-detail">{step.detail}</p>
          </div>
        </li>
      ))}
    </ol>
  );
}
