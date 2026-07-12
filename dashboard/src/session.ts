// In-memory-only session state. Nothing here is ever written to localStorage/IndexedDB — see
// the crate/plan docs on browser key custody: the unlocked identity and every unwrapped DEK
// live only in WASM linear memory (via the handles below) for the lifetime of this page load.
// Reloading the page loses the session; that's the deliberate, honest cost of not persisting key
// material in a browser.

import { WontonClient } from "./api";
import type { DekHandle, IdentityHandle } from "./wasm";

export interface Session {
  client: WontonClient;
  identity: IdentityHandle;
  username: string;
  userId: string;
}

let current: Session | null = null;

export function setSession(session: Session) {
  current = session;
}

export function getSession(): Session {
  if (!current) throw new Error("not logged in");
  return current;
}

export function hasSession(): boolean {
  return current !== null;
}

export function clearSession() {
  // `free()` releases the WASM-side memory immediately rather than waiting for GC — the closest
  // thing to "wipe on logout" this layer can do (mirrors `Zeroize`/`ZeroizeOnDrop` in the Rust
  // crates, though JS/WASM has no equivalent guarantee against a copy already having been made
  // elsewhere on the heap — flagged plainly, not oversold).
  current?.identity.free();
  current = null;
}

// A small per-branch cache of unwrapped DEK handles, so switching between commits on the same
// branch during one browsing session doesn't re-unwrap on every fetch. Cleared alongside the
// session (see `clearSession`).
const dekCache = new Map<string, DekHandle>();

export function cacheDek(branchKey: string, dek: DekHandle) {
  dekCache.get(branchKey)?.free();
  dekCache.set(branchKey, dek);
}

export function getCachedDek(branchKey: string): DekHandle | undefined {
  return dekCache.get(branchKey);
}

export function clearDekCache() {
  for (const dek of dekCache.values()) dek.free();
  dekCache.clear();
}
