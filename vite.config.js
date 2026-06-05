import { defineConfig } from "vite";

export default defineConfig({
  root: "desktop/renderer",
  publicDir: false,
  server: {
    host: "0.0.0.0",
    port: 3000,
  },
});
