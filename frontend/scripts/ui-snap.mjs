// UI screenshot tool: captures every page/state at desktop, tablet and mobile sizes with headless Chrome (no extra installs).
//
// Usage (from frontend/):   npm run build && npx next start -p 3010   (production build: no dev overlay or dev badge)
//                           BASE_URL=http://localhost:3010 node scripts/ui-snap.mjs ../docs/ui/baseline
// Needs: FalkorDB + backend running, frontend/.env.local present, Google Chrome installed.
// It mints a throwaway signed-in *test* session for a fake user ("ui-snap"), so it only ever runs against localhost.
// It resets the LOCAL sample graph first so every run starts from the same state (4 attack paths).
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { encode } from "next-auth/jwt";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";
if (!/^http:\/\/localhost(:\d+)?$/.test(BASE)) throw new Error("ui-snap only runs against http://localhost");
const OUT = path.resolve(process.argv[2] ?? "../docs/ui/baseline");
const CHROME = process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = 9333;
const VIEWPORTS = [
  { name: "desktop", w: 1440, h: 900 },
  { name: "tablet", w: 768, h: 1024 },
  { name: "mobile", w: 375, h: 812 },
];
const MAX_HEIGHT = 7000;

const env = Object.fromEntries(
  fs.readFileSync(".env.local", "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#"))
    .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).split(" #")[0].trim()]),
);
const token = await encode({ token: { name: "UI Snap", email: "ui-snap@example.com", sub: "ui-snap" }, secret: env.NEXTAUTH_SECRET, maxAge: 3600 });
const cookie = `next-auth.session-token=${token}`;

// ---- headless Chrome over the DevTools protocol
const chrome = spawn(CHROME, ["--headless=new", "--use-angle=swiftshader", "--enable-unsafe-swiftshader", "--ignore-gpu-blocklist", "--no-first-run", "--no-default-browser-check", "--hide-scrollbars",
  `--remote-debugging-port=${PORT}`, "--user-data-dir=/tmp/br-ui-snap", "about:blank"], { stdio: "ignore" });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
for (let i = 0; i < 50; i++) { try { await fetch(`http://127.0.0.1:${PORT}/json/version`); break; } catch { await sleep(200); } }
const pageInfo = (await (await fetch(`http://127.0.0.1:${PORT}/json`)).json()).find((t) => t.type === "page");
const ws = new WebSocket(pageInfo.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map();
ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); } };
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const i = ++id; pending.set(i, (d) => (d.error ? reject(new Error(`${method}: ${d.error.message}`)) : resolve(d.result))); ws.send(JSON.stringify({ id: i, method, params }));
});
await send("Page.enable"); await send("Network.enable");

const clickSelector = (sel) => `document.querySelector(${JSON.stringify(sel)})?.click()`;

// ---- state setup that needs the signed-in session
const api = (p, init = {}) => fetch(`${BASE}${p}`, { ...init, headers: { cookie, "content-type": "application/json", ...(init.headers ?? {}) } });
await api("/api/engine/reset", { method: "POST" });
const checkoutUrl = (await (await api("/api/checkout", { method: "POST" })).json()).url;

const states = [
  { id: "01-landing", path: "/", auth: false, wait: 4000, reveal: true },
  { id: "02-pricing", path: "/pricing", auth: false, wait: 1500 },
  { id: "03-dashboard", path: "/dashboard", auth: true, wait: 4500 },
  { id: "03b-dashboard-scanned", path: "/dashboard", auth: true, wait: 4500, action: `document.querySelectorAll('button').forEach((b) => { if (/run scan/i.test(b.textContent)) b.click(); })`, after: 9000, full: true },
  { id: "03c-dashboard-after-reset", path: "/dashboard", auth: true, wait: 4500, action: `(async () => { const w = (ms) => new Promise((r) => setTimeout(r, ms)); const click = (re) => [...document.querySelectorAll('button')].find((b) => re.test(b.textContent))?.click(); click(/run scan/i); await w(9000); click(/reset sample data/i); })()`, after: 15000, full: true },
  { id: "04-dashboard-advisor-open", path: "/dashboard", auth: true, wait: 4500, action: clickSelector('button[title^="Ask the advisor"]'), after: 1200 },
  { id: "05-dashboard-pricing-modal", path: "/dashboard", auth: true, wait: 4500, action: clickSelector('button[title^="Pro feature"]'), after: 1200 },
  { id: "06-settings", path: "/dashboard/settings", auth: true, wait: 2500 },
  { id: "07-checkout", path: checkoutUrl, auth: true, wait: 2000 },
  { id: "08-billing-portal", path: "/billing/mock", auth: true, wait: 2500 },
];

const ONLY = (process.env.ONLY ?? "").split(",").filter(Boolean); // e.g. ONLY=01-landing,02-pricing
let count = 0;
for (const vp of VIEWPORTS) {
  fs.mkdirSync(path.join(OUT, vp.name), { recursive: true });
  await send("Emulation.setDeviceMetricsOverride", { width: vp.w, height: vp.h, deviceScaleFactor: 1, mobile: vp.w < 500 });
  for (const phase of [false, true]) {
    await send("Network.clearBrowserCookies");
    if (phase) await send("Network.setCookie", { name: "next-auth.session-token", value: token, url: BASE });
    for (const s of states.filter((x) => x.auth === phase && (ONLY.length === 0 || ONLY.includes(x.id)))) {
      await send("Page.navigate", { url: `${BASE}${s.path}` });
      await sleep(s.wait);
      // Scroll through the page so scroll-triggered (whileInView) sections animate in before the capture, then return to top.
      await send("Runtime.evaluate", { awaitPromise: true, expression: `(async () => { const step = Math.max(300, innerHeight / 2); for (let y = 0; y < document.documentElement.scrollHeight; y += step) { scrollTo({ top: y, behavior: 'instant' }); await new Promise((r) => setTimeout(r, 260)); } scrollTo({ top: 0, behavior: 'instant' }); await new Promise((r) => setTimeout(r, 900)); })()` });
      if (s.reveal) await send("Runtime.evaluate", { expression: `document.querySelectorAll('[style]').forEach((e) => { if (e.style.opacity === '0') { e.style.opacity = '1'; e.style.transform = 'none'; } })` });
      if (s.action) { await send("Runtime.evaluate", { expression: s.action }); await sleep(s.after ?? 800); }
      if (process.env.DEBUG_TEXT) console.log((await send("Runtime.evaluate", { expression: `JSON.stringify({toast: document.body.innerText.includes('Sample workspace reset'), idle: document.body.innerText.includes('Ready to scan the'), rerun: document.body.innerText.includes('re-run'), ls: localStorage.getItem('br-scanned')})`, returnByValue: true })).result.value);
      const { cssContentSize } = await send("Page.getLayoutMetrics");
      // Overlay states (modal, side panel) are fixed-position: capture just the viewport so the backdrop covers the shot.
      const height = s.action && !s.full ? vp.h : Math.min(Math.ceil(cssContentSize.height), MAX_HEIGHT);
      const { data } = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true, clip: { x: 0, y: 0, width: vp.w, height, scale: 1 } });
      fs.writeFileSync(path.join(OUT, vp.name, `${s.id}.png`), Buffer.from(data, "base64"));
      count++; console.log(`${vp.name.padEnd(7)} ${s.id}  (${vp.w}x${height})`);
    }
  }
}
chrome.kill();
console.log(`\n${count} screenshots written to ${OUT}`);
process.exit(0);
