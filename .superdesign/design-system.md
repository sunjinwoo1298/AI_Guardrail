# Design system: Guardrail Proxy demo console

## Product context
AI Guardrail Proxy is a security gateway between a company's applications and LLM providers. Every
request is authenticated, scanned for prompt injection and personal data, checked against the
project's policy, sent to the model, and the answer is redacted on the way back. Companies use it so
they don't have to build guardrails themselves.

The console is a **live demo** shown to CTOs and security leads. Its job is to prove, one real
request at a time, that each guardrail actually fires. It calls the real proxy; when something fails
it says exactly what failed. Nothing is faked or simulated.

## Key screens (JTBD)
1. **Inspect** (live guardrails): type or pick a prompt, send it through the proxy, and see what each
   checkpoint did to that exact text: allowed, masked, flagged or blocked; risk score; cache result;
   the model's (redacted) answer. Also runs the standalone guard scan on model output.
2. **Tenants & policies**: organizations → projects → API keys; the project's versioned policy
   (enforce / monitor mode, detector actions, PII allow-list, deny rules, budget); publish a new
   version, roll back, and immediately re-run a prompt to show the change.
3. **Agent security**: tool-call policy (allowed tools, argument schema), exfiltration scrubbing of
   model output (image URLs that leak data), session lock-out after repeated attacks.

## Signature element
**The inspected document.** Prompts and answers are shown as text under inspection, and the
guardrails' actions are drawn on the text itself:
- detected-but-allowed spans: highlighter mark (marker yellow behind the text);
- masked PII: a solid ink redaction bar the length of the value, with the entity type set in small
  paper-coloured text inside it (e.g. EMAIL);
- blocked attack phrases: a 2px block-red strike-through plus a thin block-red underline rule;
- stripped exfiltration links: the link text kept, the URL replaced by a dashed outline box.
This is the one bold idea. Everything around it is quiet, flat and disciplined.

## Color
| Name | Hex | Use |
|---|---|---|
| paper | #EEF0F3 | app background |
| sheet | #FFFFFF | document surfaces (the inspected text, forms) |
| ink | #14213D | primary text, redaction bars, primary buttons |
| ink-soft | #4A5468 | secondary text |
| rule | #C9CED8 | hairlines, input borders |
| pass | #0F7B5F | allowed / healthy |
| block | #B3261E | blocked / errors |
| flag | #B7791F | flagged / monitor mode / would-block |
| marker | #FFE15A | highlight of detected spans (always behind ink text) |

No gradients. No tinted near-black: ink is a deep blue, not black. Status colors are used only for
verdicts and status, never decoration.

## Typography
- **Schibsted Grotesk** (Google Fonts) for all interface text. Weights 400 / 500 / 700 / 800.
- **JetBrains Mono** only for text that is a payload: prompts, model answers, JSON policies, keys.
  Never for labels, numbers in tables or navigation.
- Scale (px): 13 / 15 / 18 / 24 / 34 / 52. Body 15/1.55. Headings 800, tight tracking (-0.02em) at
  34 and 52. Sentence case everywhere. No all-caps labels, no tracked-out eyebrows.
- Numbers in tables and meters use tabular figures.

## Layout
- Desktop: a 64px top bar (product name, tenant switcher org / project / key, mode badge
  "Enforce" or "Monitor", connection status) and a left rail with the three screens.
- Inspect screen: two columns. Left (wide): the inspected document (the prompt as sent, with marks)
  above the answer document. Right (360px): the checkpoint trace as a vertical sequence in request
  order (Key and limits → Injection → Personal data → Policy → Model → Output redaction), each step
  with its verdict and one line of detail; below it the request facts (status, risk, cache, tokens).
- The trace IS a sequence, so it may be numbered by order; nothing else is numbered.
- Content is left-aligned. Hairline rules separate regions; few boxes. Radius: 6px on inputs and
  buttons, 0 on document sheets (they read as paper), 999px only on small status pills.
- Mobile: rail becomes a top tab row; the trace stacks below the document.

## Components
- Buttons: primary = ink fill, paper text; secondary = sheet with rule border. Labels say the action
  ("Send through proxy", "Publish version 4", "Roll back to version 2").
- Verdict pill: small, rounded, color-coded text and 1px border (pass / block / flag), never filled.
- Status line in the top bar: a 8px dot plus plain words ("Proxy reachable").
- Scenario list: plain rows (name + one-line expected outcome), not cards.

## Motion
One moment only: when a response arrives, the checkpoint trace fills top to bottom (each step's
verdict appears ~60ms after the previous), and redaction bars draw in from left to right. Respect
prefers-reduced-motion (no animation). No hover lift, no entrance fades on sections.

## Voice
Plain, specific, active. "Blocked: instruction override in message 1." "Masked 2 values before the
model saw them." Errors say what failed and how to fix it ("The proxy rejected the API key. Check
the key in the tenant switcher."). No marketing language.
