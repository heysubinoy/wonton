// The read-only browse flow: given an unwrapped `DekHandle` for a branch and its current ref,
// walk the (first-parent) commit history — verifying each commit's signature via
// `wonton-wasm`'s `verify_commit` — and decrypt the tip's current key/value pairs. This mirrors
// `wonton_vcs::log`'s walk and `commands.rs`'s `effective_working_set`, just done here in
// TypeScript instead of Rust (see `crates/wasm/src/lib.rs`'s module docs for why the walk itself
// isn't reused directly: `wonton_vcs::log` is hard-wired to a filesystem-backed object store).

import { ApiError, type WontonClient } from "./api";
import { bytesToBase64, verifyCommit, parseTree, type DekHandle } from "./wasm";

export interface CommitInfo {
  hashHex: string;
  authorId: string;
  timestamp: number;
  message: string;
  treeHashHex: string;
  parentHashesHex: string[];
}

const signerPubkeyCache = new Map<string, string>();

async function resolveSignerPubkeyB64(client: WontonClient, authorId: string): Promise<string> {
  const cached = signerPubkeyCache.get(authorId);
  if (cached) return cached;
  const info = await client.getUserById(authorId);
  signerPubkeyCache.set(authorId, info.ed25519_pubkey);
  return info.ed25519_pubkey;
}

async function fetchAndVerifyCommit(client: WontonClient, hashHex: string): Promise<CommitInfo> {
  const bytes = await client.fetchObjectBytes(hashHex);
  if (!bytes) throw new Error(`commit ${hashHex} is not on the server (broken history?)`);
  const bytesB64 = bytesToBase64(bytes);

  // We need the author's pubkey before we can verify — but we don't know the author until we've
  // parsed the (unverified) bytes. Parse the JSON once, unverified, just to read `author_id`,
  // then call `verify_commit` (which re-parses AND checks the hash + signature) as the real,
  // trusted source of truth. The unverified peek is only ever used to look up a pubkey; nothing
  // from it is trusted or displayed until `verify_commit` succeeds.
  const unverified = JSON.parse(new TextDecoder().decode(bytes));
  const authorId: string = unverified.fields.author_id;
  const signerPubkeyB64 = await resolveSignerPubkeyB64(client, authorId);

  const verified = verifyCommit(bytesB64, hashHex, signerPubkeyB64);
  return {
    hashHex,
    authorId: verified.author_id,
    timestamp: verified.timestamp,
    message: verified.message,
    treeHashHex: verified.tree_hash_hex,
    parentHashesHex: verified.parent_hashes_hex,
  };
}

/** Walk first-parent history from `tipHex`, verifying every commit, oldest-problem-first (i.e.
 * fails closed on the first bad commit it meets — never silently skips one). Mirrors
 * `wonton_vcs::log`'s `--first-parent` semantics. */
export async function walkHistory(client: WontonClient, tipHex: string): Promise<CommitInfo[]> {
  const history: CommitInfo[] = [];
  let cursor: string | undefined = tipHex;
  while (cursor) {
    const commit = await fetchAndVerifyCommit(client, cursor);
    history.push(commit);
    cursor = commit.parentHashesHex[0];
  }
  return history;
}

/** The tip's current effective key -> plaintext-value map (no staging concept in the dashboard —
 * it only ever shows committed history, never a local working tree). */
export async function decryptCurrentValues(client: WontonClient, dek: DekHandle, tipHex: string): Promise<Map<string, string>> {
  const commit = await fetchAndVerifyCommitTrusted(client, tipHex);
  const treeBytes = await client.fetchObjectBytes(commit.treeHashHex);
  if (!treeBytes) throw new Error(`tree ${commit.treeHashHex} is not on the server`);
  const treeMap: Map<string, string> = parseTree(bytesToBase64(treeBytes), commit.treeHashHex);

  const result = new Map<string, string>();
  for (const [key, blobHashHex] of treeMap.entries()) {
    const blobBytes = await client.fetchObjectBytes(blobHashHex);
    if (!blobBytes) throw new Error(`blob ${blobHashHex} (key '${key}') is not on the server`);
    const plaintext = dek.decrypt_blob(bytesToBase64(blobBytes), blobHashHex);
    result.set(key, plaintext);
  }
  return result;
}

// `decryptCurrentValues` needs a verified commit too, but doesn't want to duplicate
// `fetchAndVerifyCommit`'s logic — small local alias so both entry points share one
// implementation.
const fetchAndVerifyCommitTrusted = fetchAndVerifyCommit;

/** `404` on a fetch during a browse action reads as "you don't have access" or "doesn't exist",
 * the same access-control-falls-out-for-free story the CLI has — surfaced here as a plain
 * message rather than a raw `ApiError`. */
export function describeBrowseError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 403) return "You don't have access to this branch.";
    if (err.status === 404) return "Not found (check the org/store/branch name).";
    return `Server error (${err.status}): ${err.message}`;
  }
  return err instanceof Error ? err.message : String(err);
}
