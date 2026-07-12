# wonton dashboard

A read-only web viewer for wonton: browse orgs/stores/branches you have access to, see verified
commit history, and view decrypted current values — all in the browser. See the root
[README](../README.md#dashboard) for the security model (what's verified, what OAuth does and
doesn't gate, and the honest tradeoffs of browser-based key custody).

**Read-only, v1.** No `set`/`commit`/`push`/`share` from here yet — that's a real second client
(would need staging/commit logic re-implemented or shared via WASM) and a deliberately separate,
later step. Dashboard sign-up (generating a brand-new identity in the browser) isn't built either
— log in here with an identity already registered via the CLI (`wonton login`); OAuth currently
only proves you control an email before the CLI-side registration, and the dashboard's login
screen tells you that when it detects a completed OAuth redirect.

## Setup

Requires Rust with the `wasm32-unknown-unknown` target and `wasm-pack` (for building
`crates/wasm`), plus Node.js.

```console
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

cd dashboard
npm install
cp .env.example .env   # if wonton-server runs on a different origin than the dashboard dev server
npm run dev             # builds crates/wasm via wasm-pack, then starts the Vite dev server
```

`npm run dev`/`npm run build` both run `npm run wasm:build` first (a `wasm-pack build --target
web` over `../crates/wasm`, output into `src/wasm-pkg/`, gitignored — regenerate any time the
Rust crate changes; there's no file-watcher wiring this up automatically yet).

## Layout

- `src/api.ts` — thin `fetch` wrapper over `wonton-server`'s REST API (the same routes
  `wonton-sync::SyncClient` uses).
- `src/wasm.ts` — the only module that imports the generated `wasm-pkg`; everything else goes
  through its typed re-exports.
- `src/session.ts` — in-memory-only session/key state. Nothing here ever touches
  `localStorage`/IndexedDB.
- `src/browse.ts` — the read-only history walk + decrypt flow (verifies every commit via
  `wonton-wasm`'s `verify_commit`, mirroring `wonton_vcs::log`'s first-parent walk).
- `src/main.ts` — plain-DOM UI wiring. No framework; swap it out later without touching the
  modules above.

## Testing

The crypto/verification logic lives in `crates/wasm` and is tested there (`cargo test -p
wonton-wasm`, native — see that crate's module docs for why `wasm-bindgen`'s types can't be
exercised this way for every path, and `wasm-pack test --headless --chrome` for the real-browser
check of the thin `#[wasm_bindgen]` wrappers themselves). This package has no test suite of its
own yet beyond `tsc -b`'s type checking (`npm run build`) — it's a thin DOM/fetch layer over
already-tested logic.
