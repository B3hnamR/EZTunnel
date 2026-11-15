import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// The build goes straight into the Rust source tree, where `src/dashboard/assets.rs` embeds it.
// File names are fixed (no hashes) because that table lists them by name.
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: "../src/dashboard/ui",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    modulePreload: false,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "app-[name].js",
        assetFileNames: (info) =>
          (info.names?.[0] ?? info.name ?? "").endsWith(".css") ? "app.css" : "[name][extname]",
      },
    },
  },
  // Same Host as the page, so the dashboard's same-origin check passes through the proxy.
  server: { proxy: { "/api": { target: process.env.EZ_DEMO ?? "http://127.0.0.1:47832", changeOrigin: false } } },
});
