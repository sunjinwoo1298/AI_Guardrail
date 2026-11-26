// The signature element: text drawn with what the guardrails did to it.
//   [EMAIL]                -> ink redaction bar labelled with the entity type
//   [image removed: chart] -> dashed box where a leaking image was removed
//   strike phrases         -> struck through in block red (caught attack phrases)
//   mark phrases           -> marker highlight (things worth pointing at)

const TOKEN = /\[(image removed(?::[^\]]*)?|REDACTED_SYSTEM_PROMPT|[A-Z][A-Z_]{1,30})\]/g;

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function splitPhrases(text, phrases, className, keyPrefix) {
  const usable = (phrases || []).filter((p) => p && p.trim().length > 2);
  if (!usable.length) return [text];
  const pattern = new RegExp(`(${usable.map(escapeRegex).sort((a, b) => b.length - a.length).join("|")})`, "gi");
  return text.split(pattern).map((part, i) =>
    i % 2 === 1 ? <span key={`${keyPrefix}-${i}`} className={className}>{part}</span> : part,
  );
}

export default function InspectedText({ text, strike = [], mark = [], prose = false, animate = false }) {
  if (!text) return null;
  const out = [];
  let last = 0;
  let index = 0;
  for (const match of text.matchAll(TOKEN)) {
    const before = text.slice(last, match.index);
    out.push(...splitPhrases(before, strike, "struck", `s${index}`).flatMap((part, j) =>
      typeof part === "string" ? splitPhrases(part, mark, "marked", `m${index}-${j}`) : [part]));
    const label = match[1];
    if (label.startsWith("image removed")) {
      out.push(<span key={`t${index}`} className="removed">{label}</span>);
    } else {
      const name = label === "REDACTED_SYSTEM_PROMPT" ? "SYSTEM PROMPT" : label.replace(/_/g, " ");
      out.push(
        <span key={`t${index}`} className={`redact${animate ? " drawing" : ""}`}
              style={animate ? { animationDelay: `${index * 60}ms` } : undefined}
              title={`Masked ${name.toLowerCase()}`}>
          {name}
        </span>,
      );
    }
    last = match.index + match[0].length;
    index += 1;
  }
  const rest = text.slice(last);
  out.push(...splitPhrases(rest, strike, "struck", "s-end").flatMap((part, j) =>
    typeof part === "string" ? splitPhrases(part, mark, "marked", `m-end-${j}`) : [part]));
  return <div className={`doc${prose ? " prose" : ""}`}>{out}</div>;
}

export function countMasks(text) {
  return [...(text || "").matchAll(TOKEN)].filter((m) => !m[1].startsWith("image removed")).length;
}
