# Pages

Framework: React 18 + Vite 5 (SPA, no router library; views switched by state in App.jsx). No component library. Plain global CSS (`src/styles.css`) with CSS custom properties. Backend: FastAPI AI Guardrail Proxy, reached through the Vite dev proxy at `/api`.

## playground
Entry: `frontend/src/components/Playground.jsx` (rendered inside `frontend/src/App.jsx`)
Dependencies:
- frontend/src/App.jsx
  - frontend/src/presets.js
- frontend/src/components/ResultPanel.jsx
- frontend/src/api.js
- frontend/src/styles.css

## lab
Entry: `frontend/src/components/SecurityLab.jsx` (rendered inside `frontend/src/App.jsx`)
Dependencies:
- frontend/src/App.jsx
  - frontend/src/presets.js
- frontend/src/components/ResultPanel.jsx
- frontend/src/api.js
- frontend/src/presets.js
- frontend/src/styles.css

## tests
Entry: `frontend/src/components/TestCases.jsx` (rendered inside `frontend/src/App.jsx`)
Dependencies:
- frontend/src/App.jsx
  - frontend/src/presets.js
- frontend/src/components/ResultPanel.jsx
- frontend/src/api.js
- frontend/src/presets.js
- frontend/src/styles.css

## metrics
Entry: `frontend/src/components/Metrics.jsx` (rendered inside `frontend/src/App.jsx`)
Dependencies:
- frontend/src/App.jsx
  - frontend/src/presets.js
- frontend/src/api.js
- frontend/src/styles.css

