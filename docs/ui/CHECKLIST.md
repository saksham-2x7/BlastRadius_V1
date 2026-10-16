# UI checklist (run before every merge into `ui-remix`, and in full before `ui-remix` -> `main`)

Run locally with FalkorDB + backend + frontend up (`keys/setup.sh`, then see the root README). Tick each box.

## Behavior (must be identical before and after)
- [ ] 1. Landing loads, no console errors; "Sign in with Google" starts login; signed-in user lands on `/dashboard`; sign out returns home.
- [ ] 2. Dashboard shows **4 attack paths**, KEV badges (flame) on 4 findings, graph renders with a choke point on `api-gateway`.
- [ ] 3. **Approve fix** on F4 changes paths 4 -> 1; **Apply fix** works on an auto-tier finding; **Reset sample data** restores 4 paths.
- [ ] 4. Free user: **Auto-fix all safe** shows a lock and opens the pricing modal. Pro user: it applies fixes (402 vs 200 unchanged).
- [ ] 5. Pricing -> **Upgrade to Pro** -> simulated checkout -> **Pay** -> Settings shows Pro -> **Manage billing** -> **Cancel subscription** -> Basic.
- [ ] 6. Advisor (Ctrl/Cmd+K): ask "Which vulnerability should I patch first?"; tool steps appear, the answer streams, Esc closes, Stop works.
- [ ] 7. Error screens readable: backend stopped -> "Engine API is not running"; FalkorDB stopped -> "FalkorDB is unreachable"; Retry works.
- [ ] 8. Settings shows profile (name, email, Google), plan, billing; sign-out button works.

## Layout
- [ ] 9. Desktop 1440, tablet 768, mobile 375: no horizontal scroll, nothing clipped or overlapping, buttons reachable.
- [ ] 10. Keyboard: tab order sensible, visible focus ring, modals close with Esc.
- [ ] 11. Text contrast readable (body text at least 4.5:1); `prefers-reduced-motion` respected.

## Automated
- [ ] 12. `npm run lint`, `npm run build`, `npx tsc --noEmit` pass in `frontend/`.
- [ ] 13. `ui-guard` check passes (no protected files changed).
- [ ] 14. Screenshots regenerated (`scripts/ui-snap.mjs`) and compared with `docs/ui/baseline/`.
