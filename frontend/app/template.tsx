"use client";

import { motion } from "framer-motion";
import type { ReactNode } from "react";

/** A template re-mounts on every navigation, so this fades each page in as you move between landing, pricing and dashboard. */
export default function Template({ children }: { children: ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
}
