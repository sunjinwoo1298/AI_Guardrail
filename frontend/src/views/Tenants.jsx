import { useCallback, useEffect, useMemo, useState } from "react";
import { admin, proxy } from "../api.js";
import { Pill } from "../components/Trace.jsx";
import { useStore } from "../store.jsx";
import { humanReason } from "./Inspect.jsx";

const KEYWORD_RULE = "blocked-keywords";

function setPath(doc, path, value) {
  const copy = structuredClone(doc || {});
  let node = copy;
  for (const key of path.slice(0, -1)) {
    node[key] = node[key] && typeof node[key] === "object" ? node[key] : {};
    node = node[key];
  }
  const last = path[path.length - 1];
  if (value === undefined || value === "" || (Array.isArray(value) && value.length === 0)) delete node[last];
  else node[last] = value;
  return copy;
}

function ago(iso) {
  if (!iso) return "";
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} days ago`;
}

function AdminUnavailable({ result }) {
  const status = result?.status;
  let text = result?.error;
  if (status === 404) text = "The admin API is off. Start the proxy with DATABASE_URL and ADMIN_API_TOKEN set (see the README).";
  if (status === 401) text = "Enter the proxy's ADMIN_API_TOKEN (or a gpa_ admin token) under the connection status, top right.";
  if (status === 503) text = "The control plane database isn't configured. Set DATABASE_URL and restart the proxy.";
  return (
    <div className="stack">
      <p className="notice flag">{text}</p>
      <p className="muted small">The Inspect screen still works with the proxy's env key in the meantime.</p>
    </div>
  );
}

export default function Tenants() {
  const { conn, tenants, addTenant, forgetTenant, lastPrompt, setMode } = useStore();
  const [me, setMe] = useState(null);
  const [orgs, setOrgs] = useState([]);
  const [selected, setSelected] = useState(null); // project object (with org slug)
  const [keys, setKeys] = useState([]);
  const [policy, setPolicy] = useState(null);
  const [versions, setVersions] = useState([]);
  const [budget, setBudget] = useState(null);
  const [draft, setDraft] = useState({});
  const [comment, setComment] = useState("");
  const [showJson, setShowJson] = useState(false);
  const [message, setMessage] = useState(null);
  const [newProject, setNewProject] = useState("");
  const [tries, setTries] = useState([]);
  const [busy, setBusy] = useState(false);

  const say = (tone, text) => setMessage({ tone, text });

  const loadOrgs = useCallback(async () => {
    const who = await admin.get(conn, "/me");
    setMe(who);
    if (!who.ok) return;
    const list = await admin.get(conn, "/orgs");
    if (!list.ok) return say("block", list.error);
    const withProjects = await Promise.all((list.data.data || []).map(async (org) => {
      const projects = await admin.get(conn, `/orgs/${org.slug}/projects`);
      return { ...org, projects: projects.ok ? projects.data.data : [] };
    }));
    setOrgs(withProjects);
    setSelected((current) => current || withProjects.flatMap((o) => o.projects)[0] || null);
  }, [conn.baseUrl, conn.adminToken]);

  const loadProject = useCallback(async (project) => {
    if (!project) return;
    const [k, p, v, b] = await Promise.all([
      admin.get(conn, `/projects/${project.id}/keys`),
      admin.get(conn, `/projects/${project.id}/policy`),
      admin.get(conn, `/projects/${project.id}/policy/versions`),
      admin.get(conn, `/projects/${project.id}/budget`),
    ]);
    setKeys(k.ok ? k.data.data : []);
    setPolicy(p.ok ? p.data : null);
    setDraft(p.ok ? structuredClone(p.data.document || {}) : {});
    setVersions(v.ok ? v.data.data : []);
    setBudget(b.ok ? b.data : null);
    if (p.ok) setMode(project.id, p.data.document?.mode || "enforce");
  }, [conn.baseUrl, conn.adminToken]);

  useEffect(() => { loadOrgs(); }, [loadOrgs]);
  useEffect(() => { setTries([]); setMessage(null); loadProject(selected); }, [selected?.id, loadProject]);

  const storedKey = tenants.find((t) => t.projectId === selected?.id);
  const dirty = policy && JSON.stringify(draft) !== JSON.stringify(policy.document || {});
  const keywordRule = (draft.deny || []).find((r) => r.name === KEYWORD_RULE);

  async function createDemoTenant() {
    setBusy(true);
    let org = await admin.post(conn, "/orgs", { slug: "acme", name: "Acme" });
    if (!org.ok && org.status !== 409) { setBusy(false); return say("block", org.error); }
    let project = await admin.post(conn, "/orgs/acme/projects", { slug: "support-bot", name: "Support bot" });
    if (project.status === 409) {
      const list = await admin.get(conn, "/orgs/acme/projects");
      project = { ok: true, data: list.data.data.find((p) => p.slug === "support-bot") };
    }
    if (!project.ok) { setBusy(false); return say("block", project.error); }
    await issueKey(project.data);
    await loadOrgs();
    setSelected(project.data);
    setBusy(false);
    // Selecting a project clears messages; say what happened once it has loaded.
    setTimeout(() => say("pass", "Created acme / support-bot and issued a key. The console now sends requests as this project."), 0);
  }

  async function addProject(event) {
    event.preventDefault();
    const org = orgs.find((o) => o.id === selected?.org_id) || orgs[0];
    if (!org || !newProject.trim()) return;
    const result = await admin.post(conn, `/orgs/${org.slug}/projects`, { slug: newProject.trim().toLowerCase() });
    if (!result.ok) return say("block", result.error);
    setNewProject("");
    await loadOrgs();
    setSelected({ ...result.data, app_name: `${org.slug}/${result.data.slug}` });
  }

  async function issueKey(project = selected) {
    const result = await admin.post(conn, `/projects/${project.id}/keys`, { name: "console" });
    if (!result.ok) return say("block", result.error);
    addTenant({ id: project.id, projectId: project.id, key: result.data.key,
                label: (project.app_name || project.slug).replace("/", " / ") });
    say("pass", `Issued ${result.data.prefix}… and switched the console to it. The full key is shown only once and is kept in this browser.`);
    if (project.id === selected?.id) loadProject(project);
  }

  async function revoke(key) {
    const result = await admin.post(conn, `/projects/${selected.id}/keys/${key.id}/revoke`);
    if (!result.ok) return say("block", result.error);
    if (storedKey && storedKey.key.startsWith(key.prefix)) forgetTenant(storedKey.id);
    say("pass", `Revoked ${key.prefix}…. Requests with it now get 401.`);
    loadProject(selected);
  }

  async function publish() {
    const next = (policy?.version || 0) + 1;
    const result = await admin.put(conn, `/projects/${selected.id}/policy`, { document: draft, comment: comment || undefined });
    if (!result.ok) return say("block", result.error);
    setComment("");
    say("pass", `Published version ${next}. It applies to new requests within a few seconds.`);
    loadProject(selected);
  }

  async function rollback(version) {
    const result = await admin.post(conn, `/projects/${selected.id}/policy/rollback/${version}`);
    if (!result.ok) return say("block", result.error);
    say("pass", `Rolled back: version ${result.data.version} now has the rules of version ${version}.`);
    loadProject(selected);
  }

  async function tryIt() {
    if (!storedKey || !lastPrompt) return;
    const result = await proxy.scan(conn, storedKey.key, { input: lastPrompt });
    const action = result.ok ? result.data.action : "error";
    setTries((t) => [{ version: policy?.version, action, reasons: result.ok ? result.data.reasons : [result.error] }, ...t].slice(0, 5));
  }

  const json = useMemo(() => JSON.stringify(draft, null, 2), [draft]);

  if (me && !me.ok) {
    return (
      <div className="page">
        <div className="page-head"><h1>Tenants and policies</h1></div>
        <AdminUnavailable result={me} />
      </div>
    );
  }

  return (
    <div className="page">
      <div className="page-head">
        <h1>Tenants and policies</h1>
        <p className="lede">Each customer gets an organization, projects and keys. A project's policy decides what the guardrails do.</p>
      </div>
      {message && <p className={`notice ${message.tone}`} role="status">{message.text}</p>}

      {me && orgs.length === 0 && (
        <div className="stack" style={{ maxWidth: 560 }}>
          <p>No organizations yet. Create one to show multi-tenancy: an organization "acme" with a project "support-bot" and a key for it.</p>
          <div><button className="btn primary" onClick={createDemoTenant} disabled={busy}>{busy ? "Creating…" : "Create demo tenant"}</button></div>
        </div>
      )}

      {orgs.length > 0 && (
        <div className="tenants">
          <div className="stack-lg">
            <nav className="tree" aria-label="Organizations and projects">
              {orgs.map((org) => (
                <div key={org.id}>
                  <div className="tree-org">{org.slug}{org.status !== "active" && <span className="pill block" style={{ marginLeft: 8 }}>suspended</span>}</div>
                  {org.projects.map((p) => (
                    <button key={p.id} aria-current={selected?.id === p.id} onClick={() => setSelected(p)}>{p.slug}</button>
                  ))}
                </div>
              ))}
            </nav>
            <form className="row" onSubmit={addProject}>
              <input className="grow" aria-label="New project name" placeholder="new-project" value={newProject}
                     onChange={(e) => setNewProject(e.target.value)} />
              <button className="btn" type="submit" disabled={!newProject.trim()}>Add project</button>
            </form>

            {selected && (
              <div className="stack">
                <h3>API keys for {selected.slug}</h3>
                <div className="list">
                  {keys.length === 0 && <p className="muted small list-row">No keys yet.</p>}
                  {keys.map((k) => (
                    <div key={k.id} className={`list-row${k.active ? "" : " revoked"}`}>
                      <div>
                        <div className="mono">{k.prefix}…</div>
                        <div className="small muted">
                          {k.active ? `${k.name}, ${k.scopes.join(", ")}${k.last_used_at ? `, used ${ago(k.last_used_at)}` : ""}` : `Revoked ${ago(k.revoked_at)}`}
                        </div>
                      </div>
                      {k.active && <button className="btn text" onClick={() => revoke(k)}>Revoke</button>}
                    </div>
                  ))}
                </div>
                <div><button className="btn" onClick={() => issueKey()}>Issue new key</button></div>
              </div>
            )}
          </div>

          {selected && policy && (
            <div className="stack-lg">
              <div className="stack">
                <h2>Policy for {(selected.app_name || selected.slug).replace("/", " / ")}</h2>
                <p className="small muted">
                  {policy.version ? `Version ${policy.version}, published by ${policy.created_by} ${ago(policy.created_at)}` : "No policy published yet: global defaults apply"}
                </p>
              </div>
              <div className="stack">
                <div className="segmented" role="group" aria-label="Policy mode">
                  {["enforce", "monitor"].map((m) => (
                    <button key={m} aria-pressed={(draft.mode || "enforce") === m}
                            onClick={() => setDraft(setPath(draft, ["mode"], m === "enforce" ? undefined : m))}>
                      {m === "enforce" ? "Enforce" : "Monitor"}
                    </button>
                  ))}
                </div>
                <p className="small muted">Monitor lets every request through and records what would have been blocked.</p>
              </div>

              <div className="policy-form">
                <div className="policy-row">
                  <label htmlFor="p-inj">Prompt injection</label>
                  <select id="p-inj" value={draft.injection?.action || "block"}
                          onChange={(e) => setDraft(setPath(draft, ["injection", "action"], e.target.value === "block" ? undefined : e.target.value))}>
                    <option value="block">Block</option><option value="flag">Flag (allow and record)</option><option value="off">Off</option>
                  </select>
                </div>
                <div className="policy-row">
                  <label htmlFor="p-pii">Personal data</label>
                  <select id="p-pii" value={draft.pii?.action || "mask"}
                          onChange={(e) => setDraft(setPath(draft, ["pii", "action"], e.target.value === "mask" ? undefined : e.target.value))}>
                    <option value="mask">Mask</option><option value="block">Block</option><option value="flag">Flag</option><option value="off">Off</option>
                  </select>
                </div>
                <div className="policy-row">
                  <div><label htmlFor="p-allow">Allowed personal data</label><div className="hint">Sent unmasked</div></div>
                  <input id="p-allow" className="payload" placeholder="EMAIL_ADDRESS, PHONE_NUMBER"
                         value={(draft.pii?.allow_entities || []).join(", ")}
                         onChange={(e) => setDraft(setPath(draft, ["pii", "allow_entities"],
                           e.target.value.split(",").map((s) => s.trim().toUpperCase()).filter(Boolean)))} />
                </div>
                <div className="policy-row">
                  <div><label htmlFor="p-kw">Blocked keywords</label><div className="hint">Comma-separated</div></div>
                  <div className="row">
                    <input id="p-kw" className="grow" placeholder="globex, internal codename"
                           value={(keywordRule?.keywords || []).join(", ")}
                           onChange={(e) => {
                             const words = e.target.value.split(",").map((s) => s.trim()).filter(Boolean);
                             const others = (draft.deny || []).filter((r) => r.name !== KEYWORD_RULE);
                             const rules = words.length ? [...others, { name: KEYWORD_RULE, keywords: words, action: keywordRule?.action || "block" }] : others;
                             setDraft(setPath(draft, ["deny"], rules));
                           }} />
                    <select aria-label="Keyword action" style={{ width: 110 }} value={keywordRule?.action || "block"} disabled={!keywordRule}
                            onChange={(e) => setDraft(setPath(draft, ["deny"], (draft.deny || []).map((r) => r.name === KEYWORD_RULE ? { ...r, action: e.target.value } : r)))}>
                      <option value="block">Block</option><option value="flag">Flag</option>
                    </select>
                  </div>
                </div>
                <div className="policy-row">
                  <div><label htmlFor="p-budget">Monthly budget (USD)</label><div className="hint">Model calls stop at the cap</div></div>
                  <div className="stack" style={{ gap: 6 }}>
                    <input id="p-budget" type="number" min="1" placeholder="No cap" value={draft.budget?.monthly_usd ?? ""}
                           onChange={(e) => setDraft(setPath(draft, ["budget", "monthly_usd"], e.target.value ? Number(e.target.value) : undefined))} />
                    {budget && budget.monthly_usd && (
                      <>
                        <div className={`meter ${budget.exceeded.length ? "block" : budget.cost_usd / budget.monthly_usd > 0.8 ? "flag" : ""}`}>
                          <span style={{ width: `${Math.min(100, (budget.cost_usd / budget.monthly_usd) * 100)}%` }} />
                        </div>
                        <span className="small muted num">${budget.cost_usd.toFixed(4)} of ${budget.monthly_usd} used in {budget.month}</span>
                      </>
                    )}
                  </div>
                </div>
                <div className="policy-row">
                  <label htmlFor="p-rpm">Requests per minute</label>
                  <input id="p-rpm" type="number" min="1" placeholder="Global default" value={draft.rpm ?? ""}
                         onChange={(e) => setDraft(setPath(draft, ["rpm"], e.target.value ? Number(e.target.value) : undefined))} />
                </div>
              </div>

              <div className="stack">
                <button className="btn text" onClick={() => setShowJson(!showJson)} aria-expanded={showJson}>
                  {showJson ? "Hide policy JSON" : "Show policy JSON"}
                </button>
                {showJson && <pre className="sheet doc" style={{ margin: 0 }}>{json}</pre>}
              </div>

              <div className="row">
                <input className="grow" placeholder="What changed (optional)" value={comment} onChange={(e) => setComment(e.target.value)} />
                <button className="btn primary" onClick={publish} disabled={!dirty}>Publish version {(policy.version || 0) + 1}</button>
                <button className="btn" onClick={() => setDraft(structuredClone(policy.document || {}))} disabled={!dirty}>Discard changes</button>
              </div>
            </div>
          )}

          {selected && (
            <aside className="stack-lg" aria-label="Version history and test">
              <div className="stack">
                <h2>Version history</h2>
                <ul className="versions">
                  {versions.length === 0 && <li className="muted small">No versions yet.</li>}
                  {versions.map((v, i) => (
                    <li key={v.version}>
                      <div className="row"><strong>v{v.version}</strong>{i === 0 && <Pill verdict="pass">current</Pill>}</div>
                      <span className="small">{v.comment || "No description"}</span>
                      <span className="small muted">{v.created_by}, {ago(v.created_at)}</span>
                      {i > 0 && <div><button className="btn text small" onClick={() => rollback(v.version)}>Roll back to version {v.version}</button></div>}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="aside-block">
                <h3>Try it</h3>
                {!lastPrompt && <p className="small muted">Send a prompt on the Inspect screen first; it appears here.</p>}
                {lastPrompt && <div className="sheet doc" style={{ padding: "10px 12px", maxHeight: 160, overflow: "auto" }}>{lastPrompt}</div>}
                {!storedKey && <p className="small muted">Issue a key for this project to send requests as it.</p>}
                <div><button className="btn" onClick={tryIt} disabled={!storedKey || !lastPrompt}>Re-run last prompt</button></div>
                {tries.map((t, i) => (
                  <div key={i} className="row small">
                    <span className="muted">Under v{t.version || 0}:</span>
                    <Pill verdict={t.action === "allow" ? "pass" : t.action === "block" || t.action === "error" ? "block" : "flag"}>
                      {t.action === "would_block" ? "would block" : t.action === "allow" ? "allowed" : t.action === "block" ? "blocked" : t.action}
                    </Pill>
                    <span className="muted">{t.reasons.map(humanReason).join("; ")}</span>
                  </div>
                ))}
              </div>
            </aside>
          )}
        </div>
      )}
    </div>
  );
}
