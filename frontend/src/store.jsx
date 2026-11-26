import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

// Per-viewer settings (connection, issued demo keys, the active tenant). Kept in
// localStorage only as a convenience; the console works without it.
const STORAGE_KEY = "guardrail-console";

// The proxy's env-configured key (API_KEYS) works without the control plane.
export const ENV_TENANT = { id: "env", label: "Env key (API_KEYS)", key: "test-api-key", projectId: null };

const DEFAULTS = {
  baseUrl: "/api",
  adminToken: "",
  envKey: "test-api-key",
  tenants: [ENV_TENANT],
  activeTenantId: "env",
  lastPrompt: "",
};

function load() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
    const tenants = [ENV_TENANT, ...(saved.tenants || []).filter((t) => t.id !== "env")];
    return { ...DEFAULTS, ...saved, tenants };
  } catch {
    return DEFAULTS;
  }
}

const Store = createContext(null);

export function StoreProvider({ children }) {
  const [state, setState] = useState(load);
  // Policy facts learned from the admin API or from responses, by tenant id.
  const [policyMode, setPolicyMode] = useState({});

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ ...state, tenants: state.tenants.filter((t) => t.id !== "env") }));
    } catch {
      /* storage unavailable: settings last for this visit only */
    }
  }, [state]);

  const update = useCallback((patch) => setState((s) => ({ ...s, ...patch })), []);

  /** Remember an issued key for a project and make it the active tenant. */
  const addTenant = useCallback((tenant, activate = true) => {
    setState((s) => ({
      ...s,
      tenants: [...s.tenants.filter((t) => t.id !== tenant.id), tenant],
      activeTenantId: activate ? tenant.id : s.activeTenantId,
    }));
  }, []);

  const forgetTenant = useCallback((id) => {
    setState((s) => ({
      ...s,
      tenants: s.tenants.filter((t) => t.id !== id || t.id === "env"),
      activeTenantId: s.activeTenantId === id ? "env" : s.activeTenantId,
    }));
  }, []);

  const value = useMemo(() => {
    const envTenant = { ...ENV_TENANT, key: state.envKey || ENV_TENANT.key };
    const tenants = state.tenants.map((t) => (t.id === "env" ? envTenant : t));
    const tenant = tenants.find((t) => t.id === state.activeTenantId) || envTenant;
    return {
      ...state,
      tenants,
      tenant,
      conn: { baseUrl: state.baseUrl, adminToken: state.adminToken },
      update,
      addTenant,
      forgetTenant,
      policyMode,
      setMode: (tenantId, mode) => setPolicyMode((m) => (m[tenantId] === mode ? m : { ...m, [tenantId]: mode })),
    };
  }, [state, update, addTenant, forgetTenant, policyMode]);

  return <Store.Provider value={value}>{children}</Store.Provider>;
}

export function useStore() {
  return useContext(Store);
}
