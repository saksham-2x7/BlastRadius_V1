#!/usr/bin/env bash
# Creates frontend/.env.local and backend/.env from the templates (never overwrites), and fills the secrets that can be
# generated locally. ENGINE_API_KEY is generated once and written to BOTH files so they always match.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
F="$ROOT/frontend/.env.local"; B="$ROOT/backend/.env"

get() { grep -m1 "^$2=" "$1" 2>/dev/null | cut -d= -f2- | sed 's/[[:space:]]*#.*$//' || true; }
set_var() { # file key value
  local tmp; tmp="$(mktemp)"
  awk -v k="$2" -v v="$3" 'BEGIN{done=0} $0 ~ "^"k"=" && !done {print k"="v; done=1; next} {print} END{if(!done) print k"="v}' "$1" > "$tmp" && mv "$tmp" "$1"
}

[ -f "$F" ] || { cp "$ROOT/keys/frontend.env.example" "$F"; echo "created frontend/.env.local"; }
[ -f "$B" ] || { cp "$ROOT/keys/backend.env.example"  "$B"; echo "created backend/.env"; }

key="$(get "$F" ENGINE_API_KEY)"; [ -n "$key" ] || key="$(get "$B" ENGINE_API_KEY)"; [ -n "$key" ] || key="$(openssl rand -hex 24)"
set_var "$F" ENGINE_API_KEY "$key"; set_var "$B" ENGINE_API_KEY "$key"
[ -n "$(get "$F" NEXTAUTH_SECRET)" ] || { set_var "$F" NEXTAUTH_SECRET "$(openssl rand -base64 32)"; echo "generated NEXTAUTH_SECRET"; }

echo "ENGINE_API_KEY is set and identical in frontend and backend."
echo "Still to fill by hand in frontend/.env.local: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GEMINI_API_KEY (see keys/README.md)."
echo "Then run: keys/check.sh"
