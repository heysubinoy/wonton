/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the wonton-server to talk to. Empty string = same-origin (Part 4: served by
   * that same server). Set via `dashboard/.env` (`WONTON_SERVER_URL=...`) for local dev against
   * a server on a different port. */
  readonly WONTON_SERVER_URL: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
