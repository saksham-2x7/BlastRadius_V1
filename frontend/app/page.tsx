import type { Metadata } from "next";
import LightLanding from "@/components/lp/LightLanding";

export const metadata: Metadata = {
  title: "BlastRadius: see the paths. Fix what matters.",
  description: "BlastRadius maps your infrastructure as a graph, finds every real attack path to your crown jewels, and fixes only the weaknesses that cut them.",
  alternates: { canonical: "/" },
};

export default function Home() {
  return (
    <>
      <style>{`html,body{background:#f4f2ed!important;color-scheme:light!important}`}</style>
      <LightLanding />
    </>
  );
}
