"use client";

import { useEffect } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Lock, X } from "lucide-react";
import PlanCards from "./PlanCards";

export default function PricingModal({ open, onClose, mock }: { open: boolean; onClose: () => void; mock: boolean }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-[90] flex items-start justify-center overflow-y-auto bg-bg/80 p-4 backdrop-blur-md sm:items-center"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            aria-labelledby="pricing-title"
            onClick={(e) => e.stopPropagation()}
            initial={{ opacity: 0, y: 24, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 12, scale: 0.98 }}
            transition={{ duration: 0.25, ease: [0.22, 1, 0.36, 1] }}
            className="relative my-8 w-full max-w-3xl rounded-3xl border border-line bg-bg p-6 shadow-2xl sm:p-8"
          >
            <button
              onClick={onClose}
              aria-label="Close"
              className="absolute right-4 top-4 grid h-8 w-8 place-items-center rounded-lg text-muted transition hover:bg-panel hover:text-fg"
            >
              <X className="h-4 w-4" />
            </button>
            <div className="mb-6 text-center">
              <span className="mx-auto grid h-11 w-11 place-items-center rounded-xl border border-accent/30 bg-accent/10">
                <Lock className="h-5 w-5 text-accent" />
              </span>
              <h2 id="pricing-title" className="mt-4 text-2xl font-semibold tracking-tight">
                Auto-fix all safe is a Pro feature
              </h2>
              <p className="mx-auto mt-2 max-w-md text-sm text-muted">
                Clear every low-risk fix in one click. High-risk fixes still wait for your approval.
              </p>
            </div>
            <PlanCards mock={mock} compact />
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
