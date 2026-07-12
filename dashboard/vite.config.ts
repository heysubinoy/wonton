import { defineConfig } from "vite";

// The dashboard talks to a wonton-server over plain fetch() — no framework, no server-side
// rendering. `WONTON_SERVER_URL` picks which server the dev build points at; the production
// build (see README) is meant to be served *by* that same server (Part 4), so it defaults to
// same-origin ("") there.
export default defineConfig({
  envPrefix: "WONTON_",
  build: {
    target: "es2022",
  },
});
