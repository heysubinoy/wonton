// DOM wiring for the read-only dashboard. No framework — plain TypeScript over a handful of
// `<div>`s, since the actual complexity here is the crypto/API flow (session.ts, browse.ts,
// wasm.ts, api.ts), not the UI. Swap this file for a real framework later without touching any
// of those.

import { WontonClient, type BranchSummary } from "./api";
import { describeBrowseError, decryptCurrentValues, walkHistory } from "./browse";
import { cacheDek, clearDekCache, clearSession, getCachedDek, getSession, hasSession, setSession } from "./session";
import { Argon2ParamsInput, ensureWasmReady, unlockIdentity } from "./wasm";

const SERVER_URL = import.meta.env.WONTON_SERVER_URL || ""; // "" = same-origin (Part 4: served by wonton-server itself)

const app = document.getElementById("app")!;

function render(html: string) {
  app.innerHTML = html;
}

function el<T extends HTMLElement>(selector: string): T {
  const found = app.querySelector<T>(selector);
  if (!found) throw new Error(`missing element: ${selector}`);
  return found;
}

// ---- OAuth callback landing --------------------------------------------------------------

function checkOAuthTicket(): { ticket: string; email: string } | null {
  const fragment = new URLSearchParams(location.hash.replace(/^#/, ""));
  const ticket = fragment.get("oauth_ticket");
  const email = fragment.get("email");
  if (!ticket) return null;
  history.replaceState(null, "", location.pathname); // don't leave the ticket sitting in the URL
  return { ticket, email: email ?? "" };
}

// ---- Login screen -------------------------------------------------------------------------

function renderLogin() {
  const oauth = checkOAuthTicket();
  render(`
    <div class="card">
      <h1>wonton dashboard</h1>
      ${
        oauth
          ? `<p class="note">Verified <strong>${escapeHtml(oauth.email)}</strong> with Google. Dashboard
             sign-up isn't built yet (read-only viewer, v1) — finish registering from the CLI
             (<code>wonton login &lt;username&gt; --server ${escapeHtml(SERVER_URL || location.origin)}</code>),
             then log in below with that username and passphrase.</p>`
          : ""
      }
      <form id="login-form">
        <label>Username <input id="username" autocomplete="username" required /></label>
        <label>Passphrase <input id="passphrase" type="password" autocomplete="current-password" required /></label>
        <button type="submit">Log in</button>
      </form>
      <p><a href="${SERVER_URL}/auth/oauth/google/authorize">Sign in with Google</a> (to register a new account via the CLI, per above)</p>
      <p id="login-error" class="error"></p>
    </div>
  `);

  el<HTMLFormElement>("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = el<HTMLInputElement>("#username").value.trim();
    const passphrase = el<HTMLInputElement>("#passphrase").value;
    const errorEl = el<HTMLElement>("#login-error");
    errorEl.textContent = "";
    try {
      await doLogin(username, passphrase);
      renderBrowse();
    } catch (err) {
      errorEl.textContent = describeBrowseError(err);
    }
  });
}

async function doLogin(username: string, passphrase: string): Promise<void> {
  await ensureWasmReady();
  const client = new WontonClient(SERVER_URL);
  const start = await client.loginStart(username);
  const params = new Argon2ParamsInput(start.argon2_params.salt, start.argon2_params.m_cost_kib, start.argon2_params.t_cost, start.argon2_params.p_cost);
  const identity = unlockIdentity(start.wrapped_privkey, params, passphrase);
  const signatureB64 = identity.sign(start.challenge_nonce);
  const complete = await client.loginComplete(username, start.challenge_nonce, signatureB64);
  client.setToken(complete.token);
  setSession({ client, identity, username, userId: complete.user_id });
}

// ---- Browse screen ------------------------------------------------------------------------

function renderBrowse() {
  const session = getSession();
  render(`
    <div class="card">
      <div class="topbar">
        <span>Signed in as <strong>${escapeHtml(session.username)}</strong></span>
        <button id="logout">Log out</button>
      </div>
      <form id="branch-form">
        <label>Org <input id="org" required /></label>
        <label>Store <input id="store" required /></label>
        <button type="submit">List branches</button>
      </form>
      <p id="browse-error" class="error"></p>
      <ul id="branch-list"></ul>
      <div id="branch-detail"></div>
    </div>
  `);

  el<HTMLButtonElement>("#logout").addEventListener("click", () => {
    clearDekCache();
    clearSession();
    renderLogin();
  });

  el<HTMLFormElement>("#branch-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const org = el<HTMLInputElement>("#org").value.trim();
    const store = el<HTMLInputElement>("#store").value.trim();
    const errorEl = el<HTMLElement>("#browse-error");
    const listEl = el<HTMLElement>("#branch-list");
    errorEl.textContent = "";
    listEl.innerHTML = "";
    try {
      const branches = await session.client.listBranches(org, store);
      renderBranchList(org, store, branches);
    } catch (err) {
      errorEl.textContent = describeBrowseError(err);
    }
  });
}

function renderBranchList(org: string, store: string, branches: BranchSummary[]) {
  const listEl = el<HTMLElement>("#branch-list");
  if (branches.length === 0) {
    listEl.innerHTML = "<li>(no accessible branches)</li>";
    return;
  }
  listEl.innerHTML = branches
    .map((b) => `<li><button class="link" data-branch="${escapeHtml(b.name)}">${escapeHtml(b.name)}</button> <span class="role">${b.role}</span></li>`)
    .join("");
  listEl.querySelectorAll<HTMLButtonElement>("button[data-branch]").forEach((btn) => {
    btn.addEventListener("click", () => loadBranch(org, store, btn.dataset.branch!));
  });
}

async function loadBranch(org: string, store: string, branch: string) {
  const session = getSession();
  const detailEl = el<HTMLElement>("#branch-detail");
  detailEl.innerHTML = "<p>Loading…</p>";
  try {
    const branchKey = `${org}/${store}/${branch}`;
    let dek = getCachedDek(branchKey);
    if (!dek) {
      const keys = await session.client.listKeys(org, store, branch);
      const grants = keys[session.userId];
      const grant = grants?.reduce((a, b) => (b.dek_version > a.dek_version ? b : a));
      if (!grant) throw new Error(`you don't have access to ${branchKey}`);
      dek = session.identity.unwrap_dek(grant.sealed_box);
      cacheDek(branchKey, dek);
    }

    const ref = await session.client.getRef(org, store, branch);
    if (!ref.commit_hash) {
      detailEl.innerHTML = `<p>${escapeHtml(branchKey)}: no commits yet.</p>`;
      return;
    }

    const [values, history] = await Promise.all([
      decryptCurrentValues(session.client, dek, ref.commit_hash),
      walkHistory(session.client, ref.commit_hash),
    ]);

    detailEl.innerHTML = `
      <h2>${escapeHtml(branchKey)}</h2>
      <h3>Current values</h3>
      <table>${[...values.entries()].map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`).join("")}</table>
      <h3>History (verified, first-parent)</h3>
      <ul>${history
        .map(
          (c) =>
            `<li><code>${c.hashHex.slice(0, 12)}</code> — ${escapeHtml(c.message)}
             <span class="meta">${new Date(c.timestamp * 1000).toISOString()}</span></li>`,
        )
        .join("")}</ul>
    `;
  } catch (err) {
    detailEl.innerHTML = `<p class="error">${escapeHtml(describeBrowseError(err))}</p>`;
  }
}

// ---- boot -----------------------------------------------------------------------------------

function escapeHtml(s: string): string {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

if (hasSession()) {
  renderBrowse();
} else {
  renderLogin();
}
