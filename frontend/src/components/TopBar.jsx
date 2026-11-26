import { useEffect, useRef, useState } from "react";
import { proxy } from "../api.js";
import { useStore } from "../store.jsx";

function usePopover() {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return undefined;
    const close = (event) => {
      if (event.type === "keydown" ? event.key === "Escape" : !ref.current?.contains(event.target)) setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);
  return { open, setOpen, ref };
}

function TenantSwitcher() {
  const { tenants, tenant, update } = useStore();
  const { open, setOpen, ref } = usePopover();
  return (
    <div className="popover-wrap" ref={ref}>
      <button className="switcher" aria-expanded={open} aria-haspopup="true" onClick={() => setOpen(!open)}>
        <span>{tenant.label}</span>
        <span aria-hidden="true">▾</span>
      </button>
      {open && (
        <div className="popover left" role="dialog" aria-label="Choose the tenant to send requests as">
          <p className="small muted">Requests are sent with this key. Issue more keys under Tenants and policies.</p>
          <ul className="switcher-list">
            {tenants.map((t) => (
              <li key={t.id}>
                <button aria-pressed={t.id === tenant.id} onClick={() => { update({ activeTenantId: t.id }); setOpen(false); }}>
                  {t.label}
                  <span className="mono muted"> {t.key.slice(0, 12)}…</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function ConnectionPanel({ online }) {
  const { baseUrl, adminToken, envKey, update } = useStore();
  const { open, setOpen, ref } = usePopover();
  return (
    <div className="popover-wrap" ref={ref}>
      <button className="switcher status-line" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className={`dot ${online === null ? "" : online ? "pass" : "block"}`} />
        {online === null ? "Checking proxy" : online ? "Proxy reachable" : "Proxy unreachable"}
      </button>
      {open && (
        <div className="popover right" role="dialog" aria-label="Connection settings">
          <label className="field">
            Proxy URL
            <input value={baseUrl} onChange={(e) => update({ baseUrl: e.target.value })} />
          </label>
          <label className="field">
            Env API key (one of the proxy's API_KEYS)
            <input type="password" value={envKey} onChange={(e) => update({ envKey: e.target.value })} />
          </label>
          <label className="field">
            Admin token (for Tenants and policies)
            <input type="password" value={adminToken} placeholder="ADMIN_API_TOKEN or a gpa_ token"
                   onChange={(e) => update({ adminToken: e.target.value })} />
          </label>
          <p className="small muted">
            "/api" is forwarded to the proxy by the dev server. Stored in this browser only.
          </p>
        </div>
      )}
    </div>
  );
}

export default function TopBar() {
  const { conn, tenant, policyMode } = useStore();
  const [online, setOnline] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const ping = async () => {
      const result = await proxy.health(conn);
      if (!cancelled) setOnline(result.ok);
    };
    ping();
    const timer = setInterval(ping, 15000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [conn.baseUrl]);

  const mode = policyMode[tenant.id];
  return (
    <header className="topbar">
      <span className="wordmark">Guardrail Proxy</span>
      <TenantSwitcher />
      <div className="topbar-right">
        {mode && <span className={`pill ${mode === "monitor" ? "flag" : "pass"}`}>{mode === "monitor" ? "Monitor" : "Enforce"}</span>}
        <ConnectionPanel online={online} />
      </div>
    </header>
  );
}
