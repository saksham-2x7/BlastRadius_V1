"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import Lenis from "lenis";
import "./light.css";

gsap.registerPlugin(ScrollTrigger);

const STEPS = [
  { n: "01", t: "Map", d: "Hosts, network links, identities and findings become nodes and edges in a FalkorDB graph." },
  { n: "02", t: "Rank", d: "Every finding is ranked by the attack paths it sits on, then by CISA KEV and EPSS, not by CVSS alone." },
  { n: "03", t: "Simulate", d: "Preview any patch first and see how many attack paths disappear before anything changes." },
  { n: "04", t: "Fix", d: "Low-risk fixes apply themselves. High-risk ones wait for your approval, with a rollback note." },
];

const FAQ = [
  ["What is BlastRadius?", "It turns your infrastructure into a graph, finds every real route from the internet to your crown jewels, and tells you the few fixes that cut them, so you fix what matters first."],
  ["Does it scan my real systems?", "Not yet. The demo uses a synthetic workspace with real CVE ids. CISA KEV and FIRST EPSS come from live public feeds (with a built-in snapshot as fallback); CVSS values are a snapshot."],
  ["How does it decide what to fix first?", "By how many attack paths a finding sits on, then CISA KEV status and EPSS. A CVSS 10.0 on a host nobody can reach ranks below a 7.5 on the only road to your database."],
  ["Will it change my systems on its own?", "Today fixes update the graph and keep a rollback note; they don't touch real servers. Only low-risk fixes can auto-apply, and risky ones always wait for a human to approve."],
  ["What does the AI advisor do?", "It is an agent that reads your graph with FalkorDB algorithms, explains the exact route, and can apply low-risk fixes itself. The graph decides what is low-risk, never the model: high-risk fixes always wait for a human. Every decision is saved in graph memory. Answers can be wrong, so verify before acting."],
  ["What does it cost?", "Basic is free. Pro is $29 a month and unlocks Auto-fix all safe. Billing is simulated in the demo and no card is charged."],
];

const MARQUEE = ["Attack paths", "CISA KEV", "EPSS", "Choke points", "Safe autofix", "FalkorDB", "MCP tools", "Rollback notes"];

/** Wraps each word in a span so it can be animated. Works on text-only elements. */
function splitWords(el: Element) {
  const text = el.textContent ?? "";
  el.textContent = "";
  return text.split(" ").map((w, i, arr) => {
    const s = document.createElement("span");
    s.className = "word";
    s.textContent = w;
    el.appendChild(s);
    if (i < arr.length - 1) el.appendChild(document.createTextNode(" "));
    return s;
  });
}

function Frame({ src, alt, url, cursor = "View", className = "" }: { src: string; alt: string; url: string; cursor?: string; className?: string }) {
  return (
    <div className={`lp-frame ${className}`} data-cursor={cursor}>
      <div className="lp-frame-bar">
        <i />
        <i />
        <i />
        <span className="mono">{url}</span>
      </div>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src={src} alt={alt} loading="eager" />
    </div>
  );
}

export default function LightLanding() {
  const root = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState<number | null>(0);
  const [menu, setMenu] = useState(false);

  useEffect(() => {
    const el = root.current;
    if (!el) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const fine = window.matchMedia("(hover: hover) and (pointer: fine)").matches;
    document.documentElement.style.background = "#f4f2ed";

    // ---------- smooth scrolling, driven by GSAP's ticker so ScrollTrigger stays in sync
    let lenis: Lenis | null = null;
    let tick: ((t: number) => void) | null = null;
    let velocity = 0;
    if (!reduce) {
      lenis = new Lenis({ lerp: 0.085, wheelMultiplier: 0.95 });
      lenis.on("scroll", (e: { velocity: number }) => {
        velocity = e.velocity;
        ScrollTrigger.update();
      });
      tick = (t) => lenis!.raf(t * 1000);
      gsap.ticker.add(tick);
      gsap.ticker.lagSmoothing(0);
    }

    const ctx = gsap.context(() => {
      const q = (s: string) => gsap.utils.toArray<HTMLElement>(s);

      // ---------- custom cursor
      const dot = el.querySelector<HTMLElement>(".lp-cursor-dot");
      const ring = el.querySelector<HTMLElement>(".lp-cursor-ring");
      const ringLabel = ring?.querySelector("span") ?? null;
      const cleanups: Array<() => void> = [];
      if (fine && dot && ring) {
        const dx = gsap.quickTo(dot, "x", { duration: 0.08, ease: "power3" });
        const dy = gsap.quickTo(dot, "y", { duration: 0.08, ease: "power3" });
        const rx = gsap.quickTo(ring, "x", { duration: 0.45, ease: "power3" });
        const ry = gsap.quickTo(ring, "y", { duration: 0.45, ease: "power3" });
        let seen = false;
        const move = (e: MouseEvent) => {
          if (!seen) {
            seen = true;
            gsap.set([dot, ring], { x: e.clientX, y: e.clientY });
            gsap.to([dot, ring], { opacity: 1, duration: 0.3 });
          }
          dx(e.clientX);
          dy(e.clientY);
          rx(e.clientX);
          ry(e.clientY);
        };
        window.addEventListener("mousemove", move);
        cleanups.push(() => window.removeEventListener("mousemove", move));
        q("[data-cursor]").forEach((t) => {
          const enter = () => {
            if (ringLabel) ringLabel.textContent = t.dataset.cursor ?? "";
            ring.classList.add("is-label");
            gsap.to(ring, { scale: 1.9, duration: 0.35, ease: "power3.out" });
            gsap.to(dot, { scale: 0, duration: 0.2 });
          };
          const leave = () => {
            ring.classList.remove("is-label");
            gsap.to(ring, { scale: 1, duration: 0.35, ease: "power3.out" });
            gsap.to(dot, { scale: 1, duration: 0.2 });
          };
          t.addEventListener("mouseenter", enter);
          t.addEventListener("mouseleave", leave);
          cleanups.push(() => {
            t.removeEventListener("mouseenter", enter);
            t.removeEventListener("mouseleave", leave);
          });
        });
        q("a, button").forEach((t) => {
          if (t.dataset.cursor) return;
          const enter = () => gsap.to(ring, { scale: 1.6, duration: 0.3, ease: "power3.out" });
          const leave = () => gsap.to(ring, { scale: 1, duration: 0.3, ease: "power3.out" });
          t.addEventListener("mouseenter", enter);
          t.addEventListener("mouseleave", leave);
          cleanups.push(() => {
            t.removeEventListener("mouseenter", enter);
            t.removeEventListener("mouseleave", leave);
          });
        });

        // magnetic buttons
        q("[data-magnetic]").forEach((m) => {
          const mx = gsap.quickTo(m, "x", { duration: 0.6, ease: "elastic.out(1, 0.5)" });
          const my = gsap.quickTo(m, "y", { duration: 0.6, ease: "elastic.out(1, 0.5)" });
          const mv = (e: MouseEvent) => {
            const r = m.getBoundingClientRect();
            mx((e.clientX - (r.left + r.width / 2)) * 0.32);
            my((e.clientY - (r.top + r.height / 2)) * 0.4);
          };
          const lv = () => {
            mx(0);
            my(0);
          };
          m.addEventListener("mousemove", mv);
          m.addEventListener("mouseleave", lv);
          cleanups.push(() => {
            m.removeEventListener("mousemove", mv);
            m.removeEventListener("mouseleave", lv);
          });
        });

        // 3D tilt on frames
        q(".js-tilt").forEach((t) => {
          const rxT = gsap.quickTo(t, "rotationY", { duration: 0.7, ease: "power3.out" });
          const ryT = gsap.quickTo(t, "rotationX", { duration: 0.7, ease: "power3.out" });
          gsap.set(t, { transformPerspective: 1400 });
          const mv = (e: MouseEvent) => {
            const r = t.getBoundingClientRect();
            rxT(((e.clientX - r.left) / r.width - 0.5) * 8);
            ryT(-((e.clientY - r.top) / r.height - 0.5) * 6);
          };
          const lv = () => {
            rxT(0);
            ryT(0);
          };
          t.addEventListener("mousemove", mv);
          t.addEventListener("mouseleave", lv);
          cleanups.push(() => {
            t.removeEventListener("mousemove", mv);
            t.removeEventListener("mouseleave", lv);
          });
        });
      }

      if (reduce) {
        gsap.set(".lp-pre", { display: "none" });
        return () => cleanups.forEach((c) => c());
      }

      // ---------- scroll progress bar
      gsap.to(".lp-progress", {
        scaleX: 1,
        ease: "none",
        scrollTrigger: { trigger: el, start: "top top", end: "bottom bottom", scrub: 0.2 },
      });

      // ---------- nav hides on scroll down, returns on scroll up
      const nav = el.querySelector<HTMLElement>(".lp-nav");
      if (nav) {
        const showNav = gsap.to(nav, { yPercent: -160, duration: 0.45, ease: "power3.inOut", paused: true });
        ScrollTrigger.create({
          start: 0,
          end: "max",
          onUpdate: (self) => {
            if (self.scroll() < 120) return showNav.reverse();
            if (self.direction === 1) showNav.play();
            else showNav.reverse();
          },
        });
      }

      // ---------- preloader then hero intro
      const heroLines = q(".js-hero-line > span");
      gsap.set(heroLines, { yPercent: 115 });
      gsap.set([".js-hero-sub", ".js-hero-cta > *", ".js-hero-chip", ".js-hero-meta"], { opacity: 0, y: 28 });
      gsap.set(".js-hero-frame", { opacity: 0, y: 120, rotationX: 16, transformPerspective: 1400, transformOrigin: "50% 0%" });
      gsap.set(".js-rings circle", { transformOrigin: "50% 50%", scale: 0.2, opacity: 0 });

      const counter = { v: 0 };
      const intro = gsap.timeline({ defaults: { ease: "power4.out" } });
      intro
        .to(counter, {
          v: 100,
          duration: 1.5,
          ease: "power2.inOut",
          onUpdate: () => {
            const c = el.querySelector(".lp-pre-count");
            if (c) c.textContent = String(Math.round(counter.v)).padStart(3, "0");
          },
        })
        .to(".lp-pre-word", { yPercent: 0, duration: 0.6 }, 0.1)
        .to(".lp-pre-bar", { scaleX: 1, duration: 1.5, ease: "power2.inOut" }, 0)
        .to(".lp-pre-word", { yPercent: -110, duration: 0.5, ease: "power3.in" }, 1.55)
        .to(".lp-pre", { yPercent: -100, duration: 0.9, ease: "power4.inOut" }, 1.7)
        .set(".lp-pre", { display: "none" })
        .to(heroLines, { yPercent: 0, duration: 1.3, stagger: 0.12 }, 2.0)
        .to(".js-hero-sub", { opacity: 1, y: 0, duration: 1 }, 2.35)
        .to(".js-hero-cta > *", { opacity: 1, y: 0, duration: 0.9, stagger: 0.1 }, 2.5)
        .to(".js-hero-meta", { opacity: 1, y: 0, duration: 0.9 }, 2.6)
        .to(".js-hero-chip", { opacity: 1, y: 0, duration: 1, stagger: 0.12 }, 2.5)
        .to(".js-hero-frame", { opacity: 1, y: 0, rotationX: 0, duration: 1.6 }, 2.4)
        .add(() => {
          gsap.to(".js-rings circle", { scale: 1.5, opacity: 0.55, duration: 0.01 });
          gsap.fromTo(
            ".js-rings circle",
            { scale: 0.2, opacity: 0.5 },
            { scale: 1.35, opacity: 0, duration: 4.5, ease: "power1.out", stagger: { each: 0.9, repeat: -1 }, repeat: -1 }
          );
        }, 2.2);

      // hero parallax: mouse + scroll
      const depth = q("[data-depth]");
      if (fine) {
        const heroEl = el.querySelector<HTMLElement>(".js-hero");
        const mm = (e: MouseEvent) => {
          const nx = e.clientX / window.innerWidth - 0.5;
          const ny = e.clientY / window.innerHeight - 0.5;
          depth.forEach((d) => {
            const k = Number(d.dataset.depth);
            gsap.to(d, { x: nx * k * 60, y: ny * k * 40, duration: 1.2, ease: "power3.out", overwrite: "auto" });
          });
        };
        heroEl?.addEventListener("mousemove", mm);
        cleanups.push(() => heroEl?.removeEventListener("mousemove", mm));
      }
      q(".js-hero-chip").forEach((c, i) => {
        gsap.to(c, { yPercent: i % 2 ? -14 : 12, ease: "none", scrollTrigger: { trigger: ".js-hero", start: "top top", end: "bottom top", scrub: true } });
        gsap.to(c, { y: "+=10", duration: 2.4 + i * 0.4, repeat: -1, yoyo: true, ease: "sine.inOut", delay: 3 });
      });
      gsap.to(".js-hero-title", { yPercent: -18, ease: "none", scrollTrigger: { trigger: ".js-hero", start: "top top", end: "bottom top", scrub: true } });
      gsap.to(".js-rings", { scale: 1.4, ease: "none", scrollTrigger: { trigger: ".js-hero", start: "top top", end: "bottom top", scrub: true } });

      // ---------- marquee (speeds up with scroll velocity)
      q(".lp-marquee").forEach((m, i) => {
        const dir = i % 2 ? 1 : -1;
        const tween =
          dir === -1
            ? gsap.fromTo(m, { xPercent: 0 }, { xPercent: -50, ease: "none", duration: 38, repeat: -1 })
            : gsap.fromTo(m, { xPercent: -50 }, { xPercent: 0, ease: "none", duration: 38, repeat: -1 });
        gsap.ticker.add(() => {
          const v = Math.abs(velocity);
          tween.timeScale(1 + Math.min(v * 0.5, 7));
        });
      });

      // ---------- generic reveals
      q(".js-fade").forEach((t) => {
        gsap.from(t, { opacity: 0, y: 48, duration: 1.1, ease: "power3.out", scrollTrigger: { trigger: t, start: "top 88%" } });
      });
      q(".js-lines").forEach((blk) => {
        const inners = blk.querySelectorAll(".mask > span");
        gsap.from(inners, { yPercent: 115, duration: 1.2, stagger: 0.1, ease: "power4.out", scrollTrigger: { trigger: blk, start: "top 85%" } });
      });
      q(".js-stagger").forEach((g) => {
        gsap.from(g.children, { opacity: 0, y: 60, duration: 1, stagger: 0.12, ease: "power3.out", scrollTrigger: { trigger: g, start: "top 82%" } });
      });
      q(".js-parallax").forEach((p) => {
        const s = Number(p.dataset.speed ?? 0.2);
        gsap.to(p, { yPercent: -s * 100, ease: "none", scrollTrigger: { trigger: p, start: "top bottom", end: "bottom top", scrub: true } });
      });
      q(".js-imgpar").forEach((im) => {
        gsap.fromTo(im, { yPercent: -8, scale: 1.12 }, { yPercent: 8, ease: "none", scrollTrigger: { trigger: im.parentElement, start: "top bottom", end: "bottom top", scrub: true } });
      });

      // ---------- HOW IT WORKS: pinned, the graph is drawn by scroll
      const how = el.querySelector<HTMLElement>(".js-how");
      if (how) {
        const nodes = q(".js-gnode");
        const base = q(".js-gedge");
        const hot = q(".js-ghot");
        const gate = q(".js-ggate");
        const steps = q(".js-step");
        const counterEl = el.querySelector<HTMLElement>(".js-count");
        const badge = el.querySelector<HTMLElement>(".js-badge");
        const choke = el.querySelector<HTMLElement>(".js-choke");
        const paths = { v: 0 };
        [...base, ...hot].forEach((p) => {
          const len = (p as unknown as SVGPathElement).getTotalLength();
          p.dataset.len = String(len);
        });
        gsap.set(nodes, { opacity: 0, scale: 0.6, transformOrigin: "50% 50%" });
        base.forEach((p) => gsap.set(p, { strokeDasharray: p.dataset.len, strokeDashoffset: p.dataset.len }));
        gsap.set(hot, { opacity: 0 });
        gsap.set(choke, { opacity: 0, scale: 0.4, transformOrigin: "50% 50%" });
        gsap.set(badge, { opacity: 0, y: 10 });
        const setStep = (i: number) => steps.forEach((s, k) => s.setAttribute("data-active", String(k === i)));
        setStep(0);

        const tl = gsap.timeline({
          defaults: { ease: "none" },
          scrollTrigger: {
            trigger: how,
            start: "top top",
            end: "+=380%",
            pin: true,
            scrub: 0.8,
            onUpdate: (self) => setStep(Math.min(3, Math.floor(self.progress * 4 + 0.02))),
          },
        });
        // 1 map
        tl.to(nodes, { opacity: 1, scale: 1, stagger: 0.08, duration: 0.5 }, 0)
          .to(base, { strokeDashoffset: 0, stagger: 0.04, duration: 0.5 }, 0.2)
          // 2 rank
          .to(hot, { opacity: 1, stagger: 0.05, duration: 0.5 }, 1.1)
          .to(paths, { v: 4, duration: 0.5, onUpdate: () => counterEl && (counterEl.textContent = String(Math.round(paths.v))) }, 1.1)
          // 3 simulate: the choke point
          .to(choke, { opacity: 1, scale: 1, duration: 0.4 }, 2.1)
          .to(gate, { opacity: 0.12, duration: 0.5 }, 2.35)
          .to(paths, { v: 1, duration: 0.5, onUpdate: () => counterEl && (counterEl.textContent = String(Math.round(paths.v))) }, 2.35)
          // 4 fix
          .to(hot, { opacity: 0, duration: 0.5 }, 3.2)
          .to(paths, { v: 0, duration: 0.5, onUpdate: () => counterEl && (counterEl.textContent = String(Math.round(paths.v))) }, 3.2)
          .to(".js-gnode rect", { stroke: "#0f9d6b", duration: 0.5 }, 3.3)
          .to(badge, { opacity: 1, y: 0, duration: 0.4 }, 3.5)
          .to({}, { duration: 0.4 });
      }

      // ---------- WHY: scrubbed word-by-word statement, counters
      q(".js-statement").forEach((s) => {
        const words = splitWords(s);
        gsap.fromTo(words, { opacity: 0.14 }, { opacity: 1, stagger: 0.06, ease: "none", scrollTrigger: { trigger: s, start: "top 78%", end: "bottom 45%", scrub: true } });
      });
      q(".js-num").forEach((n) => {
        const to = Number(n.dataset.to);
        const o = { v: 0 };
        gsap.to(o, {
          v: to,
          duration: 1.6,
          ease: "power2.out",
          scrollTrigger: { trigger: n, start: "top 88%", once: true },
          onUpdate: () => (n.textContent = String(Math.round(o.v))),
        });
      });
      // ink section reveal: rounded top corners flatten as it arrives
      gsap.fromTo(".js-ink", { borderTopLeftRadius: 80, borderTopRightRadius: 80 }, { borderTopLeftRadius: 0, borderTopRightRadius: 0, ease: "none", scrollTrigger: { trigger: ".js-ink", start: "top 95%", end: "top 25%", scrub: true } });

      // ---------- autofix cards hover lift via CSS; sticky footer wordmark parallax
      gsap.fromTo(".js-wordmark", { yPercent: 40 }, { yPercent: 0, ease: "none", scrollTrigger: { trigger: ".js-footer", start: "top bottom", end: "bottom bottom", scrub: true } });
      gsap.to(".js-spin", { rotation: 360, duration: 14, repeat: -1, ease: "none" });

      // anchor links use Lenis
      q("a[href^='#']").forEach((a) => {
        const h = () => {
          const id = a.getAttribute("href");
          if (!id || id === "#") return;
          const target = document.querySelector<HTMLElement>(id);
          if (target) lenis?.scrollTo(target, { offset: -20, duration: 1.6 });
        };
        const click = (e: Event) => {
          e.preventDefault();
          h();
        };
        a.addEventListener("click", click);
        cleanups.push(() => a.removeEventListener("click", click));
      });

      return () => cleanups.forEach((c) => c());
    }, root);

    return () => {
      ctx.revert();
      if (tick) gsap.ticker.remove(tick);
      lenis?.destroy();
      ScrollTrigger.getAll().forEach((t) => t.kill());
      document.documentElement.style.background = "";
    };
  }, []);

  return (
    <div ref={root} className="lp">
      <div className="lp-grain" aria-hidden />
      <div className="lp-cursor-dot" aria-hidden />
      <div className="lp-cursor-ring" aria-hidden>
        <span>View</span>
      </div>
      <div className="lp-progress" style={{ position: "fixed", left: 0, top: 0, height: 3, width: "100%", background: "var(--lp-accent)", transform: "scaleX(0)", transformOrigin: "0 50%", zIndex: 95 }} />

      {/* preloader */}
      <div className="lp-pre" style={{ position: "fixed", inset: 0, zIndex: 150, background: "var(--lp-ink)", color: "#f4f2ed", display: "grid", placeItems: "center" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ overflow: "hidden" }}>
            <div className="lp-pre-word serif" style={{ fontSize: "clamp(48px,9vw,120px)", lineHeight: 1.05, transform: "translateY(110%)" }}>
              BlastRadius
            </div>
          </div>
          <div style={{ marginTop: 28, display: "flex", alignItems: "center", gap: 16, justifyContent: "center" }}>
            <div style={{ width: 200, height: 2, background: "rgba(244,242,237,.18)", overflow: "hidden" }}>
              <div className="lp-pre-bar" style={{ height: "100%", background: "var(--lp-accent)", transform: "scaleX(0)", transformOrigin: "0 50%" }} />
            </div>
            <span className="lp-pre-count mono" style={{ fontSize: 12, letterSpacing: ".15em" }}>
              000
            </span>
          </div>
        </div>
      </div>

      {/* nav */}
      <nav className="lp-nav" aria-label="Main">
        <a href="#top" className="flex items-center gap-2 font-semibold tracking-tight" data-magnetic>
          <span className="grid h-7 w-7 place-items-center rounded-full" style={{ background: "var(--lp-accent)" }}>
            <span className="block h-2 w-2 rounded-full bg-white" />
          </span>
          BlastRadius
        </a>
        <div className="ml-auto hidden items-center md:flex">
          {[["How it works", "#how"], ["Why paths", "#why"], ["Safe autofix", "#autofix"], ["Pricing", "#pricing"], ["FAQ", "#faq"]].map(([l, h]) => (
            <a key={h} href={h} className="link">
              {l}
            </a>
          ))}
        </div>
        <Link href="/login" className="lp-btn lp-btn--ink ml-auto md:ml-3" style={{ height: 42, padding: "0 20px", fontSize: 14 }} data-magnetic>
          Sign in
        </Link>
        <button className="lp-burger md:hidden" aria-label={menu ? "Close menu" : "Open menu"} aria-expanded={menu} onClick={() => setMenu((m) => !m)}>
          <span />
          <span />
        </button>
      </nav>

      {/* mobile menu */}
      <div className="lp-menu" data-open={menu} aria-hidden={!menu}>
        {[["How it works", "#how"], ["Why paths", "#why"], ["Safe autofix", "#autofix"], ["Pricing", "#pricing"], ["FAQ", "#faq"]].map(([l, h]) => (
          <a key={h} href={h} onClick={() => setMenu(false)} tabIndex={menu ? 0 : -1}>
            {l}
          </a>
        ))}
        <Link href="/login" className="lp-btn lp-btn--ink mt-4 justify-center" onClick={() => setMenu(false)} tabIndex={menu ? 0 : -1}>
          Start a scan →
        </Link>
      </div>

      <main>
      {/* HERO */}
      <header id="top" className="js-hero relative flex min-h-[100svh] flex-col justify-center px-5 pb-24 pt-36 sm:px-10">
        <svg className="js-rings pointer-events-none absolute left-1/2 top-[44%] -z-0 h-[140vmin] w-[140vmin] -translate-x-1/2 -translate-y-1/2" viewBox="-200 -200 400 400" aria-hidden>
          {[190, 150, 112, 76, 44].map((r) => (
            <circle key={r} r={r} fill="none" stroke="#ff4b2b" strokeWidth="1.2" />
          ))}
        </svg>
        <div className="pointer-events-none absolute left-1/2 top-[44%] h-3 w-3 -translate-x-1/2 -translate-y-1/2 rounded-full" style={{ background: "var(--lp-accent)", boxShadow: "0 0 0 8px rgba(255,75,43,.18), 0 0 60px 10px rgba(255,75,43,.35)" }} />

        {/* floating finding chips */}
        <div className="js-hero-chip mono absolute left-[6%] top-[30%] hidden rounded-full border px-4 py-2 text-xs shadow-xl lg:block" data-depth="0.9" style={{ background: "#fff", borderColor: "var(--lp-line)" }}>
          <span style={{ color: "var(--lp-accent)" }}>● </span>api-gateway · CHOKE POINT · 3 of 4 paths
        </div>
        <div className="js-hero-chip mono absolute right-[7%] top-[26%] hidden rounded-full border px-4 py-2 text-xs shadow-xl lg:block" data-depth="1.2" style={{ background: "#fff", borderColor: "var(--lp-line)" }}>
          <span style={{ color: "var(--lp-warn)" }}>● </span>CVE-2014-0160 · KEV · EPSS 100%
        </div>
        <div className="js-hero-chip mono absolute bottom-[22%] left-[10%] hidden rounded-full border px-4 py-2 text-xs shadow-xl lg:block" data-depth="0.6" style={{ background: "#fff", borderColor: "var(--lp-line)" }}>
          <span style={{ color: "var(--lp-ok)" }}>● </span>legacy-ftp · CVSS 10.0 · 0 paths
        </div>
        <div className="js-hero-chip mono absolute bottom-[26%] right-[9%] hidden rounded-full border px-4 py-2 text-xs shadow-xl lg:block" data-depth="1">
          <div className="rounded-full px-4 py-2" style={{ background: "var(--lp-ink)", color: "#fff", margin: "-9px -17px" }}>
            4 paths → <span style={{ color: "#ff8a73" }}>0</span> after 2 fixes
          </div>
        </div>

        <div className="relative z-10 mx-auto max-w-6xl text-center">
          <p className="js-hero-meta mono mb-7 text-[11px] uppercase tracking-[0.28em]" style={{ color: "var(--lp-muted)" }}>
            Attack-path-aware security triage
          </p>
          <h1 className="js-hero-title text-[clamp(52px,10.5vw,168px)] font-semibold leading-[0.92] tracking-[-0.045em]">
            <span className="mask js-hero-line">
              <span>See the paths.</span>
            </span>
            <span className="mask js-hero-line">
              <span>
                Fix what <span className="serif" style={{ color: "var(--lp-accent)" }}>matters.</span>
              </span>
            </span>
          </h1>
          <p className="js-hero-sub mx-auto mt-9 max-w-2xl text-lg leading-relaxed sm:text-xl" style={{ color: "var(--lp-muted)" }}>
            BlastRadius maps your infrastructure as a graph, finds every real route from the internet to your crown jewels, and fixes only the weaknesses that cut them.
          </p>
          <div className="js-hero-cta mt-10 flex flex-wrap items-center justify-center gap-3">
            <Link href="/login" className="lp-btn lp-btn--ink" data-magnetic>
              Start a scan <span aria-hidden>→</span>
            </Link>
            <a href="#how" className="lp-btn lp-btn--ghost" data-magnetic>
              See how it works
            </a>
          </div>
        </div>

        <div className="js-showcase-wrap relative z-10 mx-auto mt-20 w-full max-w-6xl" style={{ perspective: 1600 }}>
          <div className="js-hero-frame">
            <div className="js-tilt">
              <Frame src="/lp/dashboard.png" alt="The BlastRadius console after a scan: attack graph and ranked fixes" url="blastradius.app/dashboard" cursor="Live demo" />
            </div>
          </div>
        </div>
      </header>

      {/* MARQUEE */}
      <section className="overflow-hidden border-y py-6" style={{ borderColor: "var(--lp-line)" }} aria-hidden>
        <div className="lp-marquee">
          {[0, 1].map((k) => (
            <div key={k}>
              {[...MARQUEE, ...MARQUEE].map((m, i) => (
                <span key={i} className="flex items-center gap-10 px-5 text-[clamp(28px,4vw,56px)] font-semibold tracking-tight">
                  <span className={i % 2 ? "serif" : ""}>{m}</span>
                  <span style={{ color: "var(--lp-accent)" }}>✺</span>
                </span>
              ))}
            </div>
          ))}
        </div>
      </section>

      {/* SHOWCASE: how the screenshots are used */}
      <section className="mx-auto max-w-6xl px-5 py-32 sm:px-10">
        <div className="js-lines max-w-3xl">
          <p className="mono mb-5 text-[11px] uppercase tracking-[0.28em]" style={{ color: "var(--lp-muted)" }}>
            The console
          </p>
          <h2 className="text-[clamp(38px,6vw,84px)] font-semibold leading-[0.98] tracking-[-0.04em]">
            <span className="mask">
              <span>A calmer way to</span>
            </span>
            <span className="mask">
              <span>
                read <span className="serif" style={{ color: "var(--lp-accent)" }}>your risk.</span>
              </span>
            </span>
          </h2>
        </div>
        <div className="mt-16 grid gap-6 md:grid-cols-5">
          <div className="js-fade md:col-span-3">
            <div className="js-tilt">
              <Frame src="/lp/graph.png" alt="Attack graph with live attack paths highlighted in red" url="blastradius.app/dashboard#graph" />
            </div>
            <p className="mt-5 max-w-md text-[15px]" style={{ color: "var(--lp-muted)" }}>
              Paths light up the moment a scan finishes. The choke point every route passes through is marked, so the one fix that matters is obvious.
            </p>
          </div>
          <div className="js-fade md:col-span-2 md:mt-24">
            <div className="js-tilt">
              <Frame src="/lp/fixes.png" alt="The top fixes ranked by attack paths" url="blastradius.app/dashboard#fix" />
            </div>
            <p className="mt-5 max-w-sm text-[15px]" style={{ color: "var(--lp-muted)" }}>
              Three fixes first, ranked by the paths they cut. Everything else waits behind one click.
            </p>
          </div>
        </div>
      </section>

      {/* HOW IT WORKS (pinned) */}
      <section id="how" className="js-how relative flex min-h-[100svh] items-center px-5 py-24 sm:px-10">
        <div className="mx-auto grid w-full max-w-6xl items-center gap-12 lg:grid-cols-[1fr_1.15fr]">
          <div>
            <p className="mono mb-5 text-[11px] uppercase tracking-[0.28em]" style={{ color: "var(--lp-muted)" }}>
              How it works
            </p>
            <h2 className="text-[clamp(36px,5vw,72px)] font-semibold leading-[1] tracking-[-0.04em]">
              Scan. Advise. <span className="serif" style={{ color: "var(--lp-accent)" }}>Fix.</span>
            </h2>
            <ol className="mt-10 space-y-5">
              {STEPS.map((s) => (
                <li key={s.n} className="js-step group grid grid-cols-[48px_1fr] gap-3 transition-opacity duration-500 data-[active=false]:opacity-30">
                  <span className="mono pt-1 text-xs" style={{ color: "var(--lp-accent)" }}>
                    {s.n}
                  </span>
                  <div>
                    <h3 className="text-2xl font-semibold tracking-tight">{s.t}</h3>
                    <p className="mt-1 max-w-md text-[15px] leading-relaxed" style={{ color: "var(--lp-muted)" }}>
                      {s.d}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          </div>

          <div className="relative rounded-[28px] border bg-white p-4 shadow-[0_50px_100px_-50px_rgba(13,13,15,.5)]" style={{ borderColor: "var(--lp-line)" }}>
            <div className="mono flex items-center justify-between px-2 pb-3 pt-1 text-[11px]" style={{ color: "var(--lp-muted)" }}>
              <span>attack graph · sample workspace</span>
              <span>
                <span className="js-count text-xl font-semibold" style={{ color: "var(--lp-accent)" }}>
                  0
                </span>{" "}
                live paths
              </span>
            </div>
            <svg viewBox="0 0 600 400" className="h-auto w-full" role="img" aria-label="Attack graph being drawn: nodes, attack paths, the choke point, then a fix">
              {/* all edges (grey), then hot edges (red) on top */}
              <g>
                <path className="lp-edge js-gedge" d="M70 200 C130 200 140 70 200 70" />
                <path className="lp-edge js-gedge" d="M70 200 C130 200 140 160 200 160" />
                <path className="lp-edge js-gedge" d="M70 200 C130 200 140 250 200 250" />
                <path className="lp-edge js-gedge" d="M70 200 C120 220 130 340 200 340" />
                <path className="lp-edge js-gedge" d="M280 70 C330 70 340 110 390 110" />
                <path className="lp-edge js-gedge" d="M280 70 C330 70 340 230 390 230" />
                <path className="lp-edge js-gedge" d="M280 160 C330 160 340 230 390 230" />
                <path className="lp-edge js-gedge" d="M280 250 C330 250 340 230 390 230" />
                <path className="lp-edge js-gedge" d="M470 230 C520 230 510 180 530 180" />
                <path className="lp-edge js-gedge" d="M470 110 C520 110 510 170 530 180" />
              </g>
              <g>
                <path className="lp-edge hot flowing js-ghot" d="M70 200 C130 200 140 70 200 70" />
                <path className="lp-edge hot flowing js-ghot" d="M70 200 C130 200 140 160 200 160" />
                <path className="lp-edge hot flowing js-ghot" d="M70 200 C130 200 140 250 200 250" />
                <path className="lp-edge hot flowing js-ghot js-ggate" d="M280 70 C330 70 340 230 390 230" />
                <path className="lp-edge hot flowing js-ghot js-ggate" d="M280 160 C330 160 340 230 390 230" />
                <path className="lp-edge hot flowing js-ghot js-ggate" d="M280 250 C330 250 340 230 390 230" />
                <path className="lp-edge hot flowing js-ghot js-ggate" d="M470 230 C520 230 510 180 530 180" />
                <path className="lp-edge hot flowing js-ghot" d="M280 70 C330 70 340 110 390 110" />
                <path className="lp-edge hot flowing js-ghot" d="M470 110 C520 110 510 170 530 180" />
              </g>
              {/* nodes */}
              {[
                ["internet", 20, 185, "entry"],
                ["edge-apache", 200, 55, ""],
                ["edge-nginx", 200, 145, ""],
                ["edge-node", 200, 235, ""],
                ["legacy-ftp", 200, 325, ""],
                ["worker-java", 390, 95, ""],
                ["api-gateway", 390, 215, ""],
                ["db-customers", 500, 165, "crown"],
              ].map(([name, x, y, kind]) => (
                <g key={String(name)} className={`lp-node js-gnode ${kind}`} transform={`translate(${x} ${y})`}>
                  <rect width={name === "internet" ? 62 : name === "db-customers" ? 98 : 88} height="30" rx="9" />
                  <text x="10" y="19">
                    {name}
                  </text>
                </g>
              ))}
              <g className="js-choke" transform="translate(432 230)">
                <circle r="26" fill="none" stroke="#ff4b2b" strokeWidth="2" opacity=".5" />
                <circle r="38" fill="none" stroke="#ff4b2b" strokeWidth="1" opacity=".25" />
              </g>
            </svg>
            <div className="js-badge mono absolute bottom-6 right-6 rounded-full px-4 py-2 text-xs font-semibold" style={{ background: "var(--lp-ok)", color: "#fff" }}>
              ✓ 0 attack paths remain
            </div>
          </div>
        </div>
      </section>

      {/* WHY PATHS (ink) */}
      <section id="why" className="js-ink relative px-5 py-40 sm:px-10" style={{ background: "var(--lp-ink)", color: "#f4f2ed" }}>
        <div className="mx-auto max-w-6xl">
          <p className="mono mb-8 text-[11px] uppercase tracking-[0.28em]" style={{ color: "rgba(244,242,237,.55)" }}>
            Why paths
          </p>
          <p className="js-statement text-[clamp(30px,5vw,72px)] font-semibold leading-[1.05] tracking-[-0.035em]">
            The scariest bug is often the least dangerous. A CVSS 10.0 that leads nowhere can wait. A 7.5 on the only road to your database cannot.
          </p>
          <div className="js-stagger mt-24 grid gap-px overflow-hidden rounded-3xl md:grid-cols-3" style={{ background: "rgba(244,242,237,.14)" }}>
            {[
              { to: 0, suffix: "", label: "attack paths through the CVSS 10.0 finding" },
              { to: 3, suffix: " of 4", label: "attack paths run through a single CVSS 7.5" },
              { to: 2, suffix: "", label: "fixes take the demo workspace from 4 paths to 0" },
            ].map((s) => (
              <div key={s.label} className="p-10" style={{ background: "var(--lp-ink)" }}>
                <div className="text-[clamp(64px,9vw,128px)] font-semibold leading-none tracking-[-0.05em]">
                  <span className="js-num" data-to={s.to}>
                    0
                  </span>
                  <span className="serif" style={{ color: "#ff8a73", fontSize: ".5em" }}>
                    {s.suffix}
                  </span>
                </div>
                <p className="mt-5 max-w-[16rem] text-[15px]" style={{ color: "rgba(244,242,237,.65)" }}>
                  {s.label}
                </p>
              </div>
            ))}
          </div>
          <p className="mono mt-6 text-[11px]" style={{ color: "rgba(244,242,237,.4)" }}>
            In the demo workspace. Synthetic infrastructure, real CVE ids.
          </p>
        </div>
      </section>

      {/* SAFE AUTOFIX */}
      <section id="autofix" className="relative px-5 py-40 sm:px-10">
        <div className="mx-auto max-w-6xl">
          <div className="js-lines max-w-3xl">
            <p className="mono mb-5 text-[11px] uppercase tracking-[0.28em]" style={{ color: "var(--lp-muted)" }}>
              Safe autofix
            </p>
            <h2 className="text-[clamp(38px,6vw,84px)] font-semibold leading-[0.98] tracking-[-0.04em]">
              <span className="mask">
                <span>Small fixes itself.</span>
              </span>
              <span className="mask">
                <span>
                  <span className="serif" style={{ color: "var(--lp-accent)" }}>Big ones ask.</span>
                </span>
              </span>
            </h2>
            <p className="mt-6 max-w-xl text-lg" style={{ color: "var(--lp-muted)" }}>
              The graph decides the tier with fixed rules on blast radius, never a model&apos;s guess.
            </p>
          </div>
          <div className="js-stagger mt-16 grid gap-5 md:grid-cols-3">
            {[
              { tag: "AUTO", c: "var(--lp-ok)", t: "Leaf host, one path", d: "Reversible patch. Apply it in one click, or let Pro clear every safe fix at once.", step: "Applies itself" },
              { tag: "NEEDS APPROVAL", c: "var(--lp-warn)", t: "Choke point or crown-jewel neighbour", d: "High blast radius. BlastRadius drafts the fix and a rollback note, then waits for a human.", step: "Human approves" },
              { tag: "MONITOR", c: "var(--lp-muted)", t: "Not on any path", d: "A loud CVSS on a host nobody can reach. Tracked, not rushed.", step: "No action" },
            ].map((c) => (
              <div key={c.tag} className="group relative overflow-hidden rounded-[28px] border bg-white p-8 transition-transform duration-500 hover:-translate-y-2" style={{ borderColor: "var(--lp-line)" }} data-cursor="Tier">
                <span className="mono rounded-full border px-3 py-1 text-[10px] font-semibold tracking-wider" style={{ color: c.c, borderColor: c.c }}>
                  {c.tag}
                </span>
                <h3 className="mt-8 text-2xl font-semibold leading-tight tracking-tight">{c.t}</h3>
                <p className="mt-3 text-[15px] leading-relaxed" style={{ color: "var(--lp-muted)" }}>
                  {c.d}
                </p>
                <div className="mono mt-10 text-xs" style={{ color: c.c }}>
                  → {c.step}
                </div>
                <div className="pointer-events-none absolute -right-10 -top-10 h-40 w-40 rounded-full opacity-0 blur-2xl transition-opacity duration-500 group-hover:opacity-30" style={{ background: c.c }} />
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* PARALLAX IMAGE BAND */}
      <section className="relative mx-5 overflow-hidden rounded-[36px] sm:mx-10" style={{ height: "min(78vh, 720px)", background: "var(--lp-ink)" }}>
        <div className="absolute inset-0 overflow-hidden">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img className="js-imgpar absolute left-0 top-0 h-full w-full scale-110 object-cover object-top opacity-60 blur-[7px]" src="/lp/dashboard.png" alt="" />
        </div>
        <div className="absolute inset-0" style={{ background: "linear-gradient(180deg, rgba(13,13,15,.15), rgba(13,13,15,.75))" }} />
        <div className="js-parallax absolute bottom-10 left-8 right-8 text-[#f4f2ed] sm:left-14" data-speed="0.12">
          <p className="mono mb-3 text-[11px] uppercase tracking-[0.28em] opacity-70">An agent that acts, with limits</p>
          <p className="max-w-3xl text-[clamp(30px,4.6vw,64px)] font-semibold leading-[1.02] tracking-[-0.035em]">
            Ask the advisor <span className="serif" style={{ color: "#ff8a73" }}>anything</span>. It reasons over the graph, applies the safe fixes itself, and hands the risky ones to you.
          </p>
        </div>
      </section>

      {/* PRICING */}
      <section id="pricing" className="px-5 py-40 sm:px-10">
        <div className="mx-auto max-w-6xl">
          <div className="js-lines text-center">
            <p className="mono mb-5 text-[11px] uppercase tracking-[0.28em]" style={{ color: "var(--lp-muted)" }}>
              Pricing
            </p>
            <h2 className="text-[clamp(38px,6vw,84px)] font-semibold leading-[0.98] tracking-[-0.04em]">
              <span className="mask">
                <span>
                  Plans <span className="serif" style={{ color: "var(--lp-accent)" }}>that scale</span> with you.
                </span>
              </span>
            </h2>
          </div>
          <div className="js-stagger mx-auto mt-16 grid max-w-4xl items-stretch gap-5 md:grid-cols-2">
            {[
              { n: "Basic", p: "$0", per: "forever", d: "Scan, understand your paths and fix by hand.", f: ["Attack-path scan", "Findings ranked by paths", "Manual Apply / Approve", "Fix history with rollback notes"], b: "Get started", href: "/login", dark: false },
              { n: "Pro", p: "$29", per: "per month", d: "Clear every safe fix in one click.", f: ["Everything in Basic", "Auto-fix all safe", "High-risk fixes still wait for approval", "Scheduled scans (soon)"], b: "Upgrade to Pro", href: "/pricing", dark: true },
            ].map((pl) => (
              <div key={pl.n} className="relative flex flex-col rounded-[28px] border p-8" style={pl.dark ? { background: "var(--lp-ink)", color: "#f4f2ed", borderColor: "var(--lp-ink)", boxShadow: "0 50px 100px -40px rgba(13,13,15,.7)" } : { background: "#fff", borderColor: "var(--lp-line)" }}>
                {pl.dark && (
                  <span className="mono absolute -top-3 left-8 rounded-full px-3 py-1 text-[10px] font-semibold tracking-wider" style={{ background: "var(--lp-accent)", color: "#fff" }}>
                    POPULAR
                  </span>
                )}
                <h3 className="text-lg font-semibold">{pl.n}</h3>
                <div className="mt-5 flex items-baseline gap-2">
                  <span className="text-6xl font-semibold tracking-[-0.04em]">{pl.p}</span>
                  <span className="text-sm opacity-60">{pl.per}</span>
                </div>
                <p className="mt-3 text-[15px] opacity-70">{pl.d}</p>
                <ul className="mt-7 flex-1 space-y-3 text-[15px]">
                  {pl.f.map((x) => (
                    <li key={x} className="flex gap-3">
                      <span style={{ color: pl.dark ? "#ff8a73" : "var(--lp-accent)" }}>✓</span>
                      {x}
                    </li>
                  ))}
                </ul>
                <Link href={pl.href} className={`lp-btn mt-9 justify-center ${pl.dark ? "" : "lp-btn--ghost"}`} style={pl.dark ? { background: "#f4f2ed", color: "var(--lp-ink)" } : undefined} data-magnetic>
                  {pl.b}
                </Link>
              </div>
            ))}
          </div>
          <p className="mono mt-8 text-center text-[11px]" style={{ color: "var(--lp-muted)" }}>
            Demo billing is simulated. No card is charged.
          </p>
        </div>
      </section>

      {/* FAQ */}
      <section id="faq" className="px-5 pb-40 sm:px-10">
        <div className="mx-auto grid max-w-6xl gap-14 lg:grid-cols-[0.8fr_1.2fr]">
          <div className="js-lines">
            <p className="mono mb-5 text-[11px] uppercase tracking-[0.28em]" style={{ color: "var(--lp-muted)" }}>
              FAQ
            </p>
            <h2 className="text-[clamp(38px,5vw,72px)] font-semibold leading-[1] tracking-[-0.04em]">
              <span className="mask">
                <span>Honest</span>
              </span>
              <span className="mask">
                <span>
                  <span className="serif" style={{ color: "var(--lp-accent)" }}>answers.</span>
                </span>
              </span>
            </h2>
          </div>
          <div className="js-fade divide-y" style={{ borderTop: "1px solid var(--lp-line)" }}>
            {FAQ.map(([q, a], i) => (
              <div key={q} className="lp-faq-item" data-open={open === i} style={{ borderColor: "var(--lp-line)" }}>
                <button className="flex w-full items-center justify-between gap-6 py-6 text-left text-xl font-semibold tracking-tight sm:text-2xl" onClick={() => setOpen(open === i ? null : i)} aria-expanded={open === i}>
                  {q}
                  <span className="lp-plus grid h-9 w-9 shrink-0 place-items-center rounded-full border text-lg transition-all duration-300" style={{ borderColor: "var(--lp-line)" }}>
                    +
                  </span>
                </button>
                <div className="lp-faq-body">
                  <div>
                    <p className="max-w-2xl pb-6 text-[16px] leading-relaxed" style={{ color: "var(--lp-muted)" }}>
                      {a}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FINAL CTA */}
      <section className="relative overflow-hidden px-5 py-40 text-center sm:px-10" style={{ background: "var(--lp-accent)", color: "#fff" }}>
        <svg className="js-spin pointer-events-none absolute left-1/2 top-1/2 h-[120vmin] w-[120vmin] -translate-x-1/2 -translate-y-1/2 opacity-[0.12]" viewBox="-100 -100 200 200" aria-hidden>
          {[90, 70, 50, 30].map((r) => (
            <circle key={r} r={r} fill="none" stroke="#fff" strokeWidth=".4" strokeDasharray="2 3" />
          ))}
        </svg>
        <div className="js-lines relative">
          <h2 className="text-[clamp(48px,10vw,160px)] font-semibold leading-[0.92] tracking-[-0.045em]">
            <span className="mask">
              <span>Two fixes.</span>
            </span>
            <span className="mask">
              <span className="serif">Zero attack paths.</span>
            </span>
          </h2>
        </div>
        <p className="relative mx-auto mt-8 max-w-xl text-lg opacity-90">Sign in with Google and open the sample workspace to see scan, advise, fix in about a minute.</p>
        <div className="relative mt-10">
          <Link href="/login" className="lp-btn" style={{ background: "#0d0d0f", color: "#fff", height: 64, padding: "0 40px", fontSize: 17 }} data-magnetic data-cursor="Open">
            Open the live demo →
          </Link>
        </div>
      </section>

      {/* FOOTER */}
      </main>

      <footer className="js-footer relative overflow-hidden px-5 pb-0 pt-20 sm:px-10" style={{ background: "var(--lp-ink)", color: "#f4f2ed" }}>
        <div className="mx-auto flex max-w-6xl flex-wrap items-start justify-between gap-10 pb-16">
          <div>
            <p className="text-xl font-semibold">BlastRadius</p>
            <p className="mt-2 max-w-xs text-sm opacity-60">Graph-native exposure management. Built on FalkorDB, MCP-ready.</p>
          </div>
          <div className="flex gap-16 text-sm">
            <div className="space-y-3 opacity-80">
              <a className="block hover:opacity-100" href="#how">How it works</a>
              <a className="block" href="#why">Why paths</a>
              <a className="block" href="#autofix">Safe autofix</a>
            </div>
            <div className="space-y-3 opacity-80">
              <a className="block" href="#pricing">Pricing</a>
              <a className="block" href="#faq">FAQ</a>
              <Link className="block" href="/login">Sign in</Link>
            </div>
          </div>
        </div>
        <div className="js-wordmark serif select-none text-center leading-[0.8]" style={{ fontSize: "clamp(80px,21vw,340px)", letterSpacing: "-0.04em", color: "rgba(244,242,237,.95)", marginBottom: "0.04em" }} aria-hidden>
          BlastRadius
        </div>
        <div className="mono mx-auto flex max-w-6xl justify-between py-6 text-[11px] opacity-50">
          <span>© 2026 BlastRadius</span>
          <span>Synthetic topology · live CISA KEV and FIRST EPSS feeds · CVSS is a snapshot</span>
        </div>
      </footer>
    </div>
  );
}
