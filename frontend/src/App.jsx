import { useEffect, useState } from "react";
import TopBar from "./components/TopBar.jsx";
import { StoreProvider, useStore } from "./store.jsx";
import AgentSecurity from "./views/AgentSecurity.jsx";
import Inspect from "./views/Inspect.jsx";
import Tenants from "./views/Tenants.jsx";

const SCREENS = [
  { id: "inspect", label: "Inspect", component: Inspect },
  { id: "tenants", label: "Tenants and policies", component: Tenants },
  { id: "agents", label: "Agent security", component: AgentSecurity },
];

function currentScreen() {
  const id = window.location.hash.replace(/^#\/?/, "");
  return SCREENS.find((s) => s.id === id) || SCREENS[0];
}

function Shell() {
  const { baseUrl } = useStore();
  const [screen, setScreen] = useState(currentScreen);

  useEffect(() => {
    const onHash = () => setScreen(currentScreen());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    document.title = `${screen.label} · Guardrail Proxy`;
  }, [screen]);

  const Screen = screen.component;
  return (
    <div className="app">
      <TopBar />
      <div className="body">
        <nav className="rail" aria-label="Screens">
          {SCREENS.map((s) => (
            <a key={s.id} href={`#/${s.id}`} aria-current={s.id === screen.id ? "page" : undefined}>{s.label}</a>
          ))}
          <p className="rail-foot">Connected to {baseUrl === "/api" ? "the dev proxy (/api)" : baseUrl}</p>
        </nav>
        <main className="main" id="main">
          <Screen />
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <StoreProvider>
      <Shell />
    </StoreProvider>
  );
}
