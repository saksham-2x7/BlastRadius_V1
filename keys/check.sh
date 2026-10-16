#!/usr/bin/env bash
# Verifies local key setup and that no secret is about to be committed. Prints variable NAMES only, never values.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
F=frontend/.env.local; B=backend/.env; bad=0
get() { grep -m1 "^$2=" "$1" 2>/dev/null | cut -d= -f2- | sed 's/[[:space:]]*#.*$//' | sed 's/[[:space:]]*$//'; }
need() { [ -n "$(get "$1" "$2")" ] && echo "  ok   $1  $2" || { echo "  MISSING  $1  $2"; bad=1; }; }
[ -f $F ] && [ -f $B ] || { echo "Missing $F or $B. Run keys/setup.sh first."; exit 1; }
echo "frontend required:"; for k in NEXTAUTH_URL NEXTAUTH_SECRET GOOGLE_CLIENT_ID GOOGLE_CLIENT_SECRET BACKEND_URL ENGINE_API_KEY; do need $F $k; done
echo "backend required:";  for k in ENGINE_API_KEY FALKORDB_HOST FALKORDB_PORT; do need $B $k; done
[ -n "$(get $F GEMINI_API_KEY)$(get $F ANTHROPIC_API_KEY)" ] && echo "  ok   advisor key present" || echo "  note: no GEMINI_API_KEY / ANTHROPIC_API_KEY, so the advisor uses the keyword mock"
[ "$(get $F ENGINE_API_KEY)" = "$(get $B ENGINE_API_KEY)" ] && echo "  ok   ENGINE_API_KEY matches in frontend and backend" || { echo "  MISMATCH  ENGINE_API_KEY differs between $F and $B"; bad=1; }
echo "secret scan (files git would publish):"
hits="$(git ls-files -co --exclude-standard | grep -v '^keys/check.sh$' | xargs grep -lEI 'GOCSPX-|AIza[0-9A-Za-z_-]{30,}|AQ\.A[0-9A-Za-z_-]{20,}|sk-ant-|whsec_|sk_live|sk_test|(ENGINE_API_KEY|NEXTAUTH_SECRET|FALKORDB_PASSWORD)=[A-Za-z0-9+/=]{20,}' 2>/dev/null || true)"
[ -z "$hits" ] && echo "  ok   no secrets found" || { echo "  SECRET-LIKE TEXT IN:"; echo "$hits" | sed 's/^/    /'; bad=1; }
git ls-files | grep -E '(^|/)\.env($|\.)|\.local\.txt$' | sed 's/^/  TRACKED SECRET FILE: /' | grep . && bad=1
[ $bad -eq 0 ] && echo "ALL GOOD" || { echo "PROBLEMS FOUND"; exit 1; }
