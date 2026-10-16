# frontend

Next.js 16 (App Router, cache components) + React 19, Tailwind v4, Framer Motion. Deployed on **Vercel** with Root Directory `frontend`.

## Run
```bash
npm install
npm run dev        # http://localhost:3000   (needs frontend/.env.local, see ../keys/frontend.env.example)
npm run lint && npx tsc --noEmit && npm run build
```

## What lives here
```
app/            pages + route handlers
  page.tsx                landing (Three.js globe hero)
  dashboard/              session-gated dashboard + settings
  pricing/, checkout/, billing/   plans, simulated checkout and portal
  api/auth/               NextAuth (Google, JWT sessions)
  api/engine/[...path]    session-checked proxy to the backend (allow-listed routes, Pro gating for bulk auto-fix)
  api/chat/               streaming AI advisor (NDJSON)
  api/checkout, api/billing, api/stripe/webhook
components/     UI (landing, dashboard, pricing, ui/AttackGraph = React Flow, ui/Globe = Three.js)
lib/            auth, engine client, plans, subscription (via backend), stripe, advisor/
  advisor/      providers: gemini (free tier), claude, mock; mcp.ts = real MCP client to the backend
```

## Talking to the backend
Server-side only, with `BACKEND_URL` and the `X-Engine-Key` header (`ENGINE_API_KEY`). The browser never calls the backend directly.

## Plans and billing
Basic (free) and Pro ($29/mo). "Auto-fix all safe" is Pro-only and enforced on the server (HTTP 402) using the plan stored in the database, never the cookie.
Billing is **simulated** unless `STRIPE_SECRET_KEY` + `STRIPE_PRICE_PRO` (+ `STRIPE_WEBHOOK_SECRET`) are set, which switches to real Stripe Checkout, Billing Portal and webhooks (the Stripe path is implemented but untested against live keys).

## AI advisor
`ADVISOR_PROVIDER=auto` uses Gemini when `GEMINI_API_KEY` is set (default model `gemini-3.6-flash`, with automatic fallback to `gemini-3.5-flash-lite` then `gemini-2.5-flash`), else Claude when `ANTHROPIC_API_KEY` is set, else a keyword mock. All providers use only the backend's read-only MCP tools.
