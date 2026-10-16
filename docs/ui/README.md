# UI remix: rules

Goal: change how the product **looks**, nothing about how it **works**.

## Branches
- `ui-remix` is the integration branch. It merges into `main` only at the end, after the checklist passes.
- Everyone works on their own branch **starting with `ui-`** (e.g. `ui-tokens`, `ui-pricing`) and opens PRs into `ui-remix`.
- Small PRs, one area each. Rebase on `ui-remix` daily.

## Protected (the `ui-guard` check fails the PR if you touch these)
`backend/`, `database/`, `keys/`, `frontend/app/api/`, `frontend/lib/`, `.github/` (except `ui-guard.yml`).
Also do not change, inside components: handlers (`onClick`, `fetch`, `signIn`, `signOut`), state/hooks, the anchor ids
`#overview #graph #scan #fix #applied`, `aria-label`s, and text that tests or error messages rely on.
Changing `package.json`, `next.config.ts` or `tsconfig.json` is allowed but flagged: say why in the PR.

## Who owns what (no overlapping files)
| Area | Files | Owner |
|---|---|---|
| Design tokens + fonts | `frontend/app/globals.css`, `frontend/app/layout.tsx` | you |
| Landing + navbar | `frontend/app/page.tsx`, `frontend/components/landing/*`, `frontend/components/layout/*` | you |
| Pricing, settings, checkout, billing | `frontend/app/pricing`, `components/pricing`, `components/dashboard/SettingsView.tsx`, `components/billing`, `app/checkout`, `app/billing` | teammate 1 |
| Copy, assets, QA runs, demo script | docs, landing copy | teammate 2 |
| Dashboard, graph, advisor | `components/dashboard/*`, `components/ui/AttackGraph.tsx` | last phase, assigned later |

## Tools
- Before/after screenshots: `cd frontend && node scripts/ui-snap.mjs ../docs/ui/after` (needs the app running locally; see the script header). Baseline (current UI) is in `docs/ui/baseline/`.
- Checks on every PR: `cd frontend && npm run lint && npm run build && npx tsc --noEmit`.
- Test checklist: `docs/ui/CHECKLIST.md`.
- Google login does not work on Vercel preview URLs (the OAuth redirect is fixed to production). Test signed-in screens locally.
