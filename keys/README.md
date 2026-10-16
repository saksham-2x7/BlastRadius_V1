# keys

**Every environment variable in one place.** Templates (`*.env.example`) are safe to commit. Real values live only in `frontend/.env.local`, `backend/.env` (both git-ignored) and in the Vercel / Railway dashboards. **Never paste a key in chat, an issue or a screenshot.**

```bash
keys/setup.sh    # creates frontend/.env.local + backend/.env, generates NEXTAUTH_SECRET and ONE ENGINE_API_KEY written to both
keys/check.sh    # names-only report: required keys set? ENGINE_API_KEY equal? any secret about to be committed?
```

## Who needs what
| Variable | frontend | backend | database server | Where to get it |
|---|:-:|:-:|:-:|---|
| `ENGINE_API_KEY` | ✅ | ✅ | | `openssl rand -hex 24` (**must be identical** in frontend and backend) |
| `NEXTAUTH_URL` / `NEXTAUTH_SECRET` | ✅ | | | your site URL / `openssl rand -base64 32` |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | ✅ | | | Google Cloud Console → Google Auth Platform → Clients |
| `BACKEND_URL` | ✅ | | | the backend's public URL |
| `GEMINI_API_KEY` (or `ANTHROPIC_API_KEY`) | ✅ | | | aistudio.google.com/apikey (free tier) |
| `STRIPE_*` | ✅ (optional) | | | leave empty for simulated billing |
| `CORS_ORIGINS`, `MCP_ALLOWED_HOSTS` | | ✅ | | your Vercel origin / Railway domain |
| `FALKORDB_HOST/PORT/PASSWORD/USERNAME/SSL/GRAPH…` | | ✅ | | where the database is |
| `REDIS_ARGS` (password), `BROWSER` | | | ✅ | `--requirepass <openssl rand -hex 24>`; the same password is the backend's `FALKORDB_PASSWORD` |

## Rules
1. Production values are set in **Vercel** (frontend vars) and **Railway** (backend and database vars). Changing a variable needs a redeploy.
2. Rotate a key: generate a new one, update **both** places that share it (e.g. `ENGINE_API_KEY` on Vercel and Railway), redeploy both.
3. Never use a `NEXT_PUBLIC_` prefix for anything in `frontend.env.example`.
4. Run `keys/check.sh` before every push.
