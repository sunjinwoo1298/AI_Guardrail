# Guardrail Proxy Console (React)

Web UI for the AI Guardrail Proxy.

Views: Playground (chat via `/generate`, `/stream` or `/v1/chat/completions`), Security Lab, Test cases, Metrics.

## Develop

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

Requests go to `/api/*`, which Vite forwards to `http://localhost:8000` (override with `VITE_PROXY_TARGET`). No CORS configuration is needed. The API key and URL are editable in the sidebar and saved in localStorage.

## Production / Docker

`docker compose -f docker-compose.observability.yml up -d --build` builds this folder into an nginx image on http://localhost:5173. nginx forwards `/api/` to the `app` service.

If you set the sidebar Proxy URL to a different origin, the backend must allow CORS for it (it currently does not).

## Notes

- `/generate` and `/stream` ignore the model; only `/v1/chat/completions` honors the model selector.
- Metrics are read from `/metrics/` and parsed in the browser (`src/api.js`, `src/components/Metrics.jsx`).
