import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname),
      "server-only": path.resolve(__dirname, "tests/stubs/server-only.ts"), // the real package throws outside a Next server build
    },
  },
  test: { environment: "node", include: ["tests/**/*.test.ts"] },
});
