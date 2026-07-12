// A thin `fetch` wrapper over wonton-server's REST API — the exact same routes
// `wonton-sync::SyncClient` (the CLI's client) uses. No framework, no client-side caching layer;
// every call is a plain request. Base64/hex wire conventions match `wonton-shared`'s doc
// comments exactly (binary fields base64, content hashes hex).

export interface Argon2ParamsDto {
  salt: string;
  m_cost_kib: number;
  t_cost: number;
  p_cost: number;
}

export interface LoginStartResponse {
  wrapped_privkey: string;
  argon2_params: Argon2ParamsDto;
  challenge_nonce: string;
}

export interface LoginCompleteResponse {
  token: string;
  expires_at: number;
  user_id: string;
}

export interface BranchSummary {
  name: string;
  role: "admin" | "writer" | "reader";
}

export interface BranchDetails {
  branch_id: string;
  active_dek_version: number;
}

export interface RefResponse {
  commit_hash: string | null;
}

export interface WrappedDekEntry {
  dek_version: number;
  sealed_box: string;
}

export type KeysMap = Record<string, WrappedDekEntry[]>;

export interface UserPublicInfo {
  user_id: string;
  ed25519_pubkey: string;
  x25519_pubkey: string;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export class WontonClient {
  private token: string | null = null;

  constructor(private baseUrl: string) {}

  setToken(token: string) {
    this.token = token;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (this.token) headers["authorization"] = `Bearer ${this.token}`;
    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      let message = res.statusText;
      try {
        const parsed = await res.json();
        if (typeof parsed?.error === "string") message = parsed.error;
      } catch {
        // no JSON body; keep statusText
      }
      throw new ApiError(res.status, message);
    }
    if (res.status === 204 || res.headers.get("content-length") === "0") {
      return undefined as T;
    }
    return (await res.json()) as T;
  }

  /** Raw object bytes (`GET /objects/{hash}`) — never JSON, base64-encoded by the caller before
   * handing to `wonton-wasm` (see `src/wasm.ts`). Not found => `null`, never thrown, since a
   * "this object doesn't exist locally yet" is routine while walking history. */
  async fetchObjectBytes(hashHex: string): Promise<ArrayBuffer | null> {
    const res = await fetch(`${this.baseUrl}/objects/${hashHex}`, {
      headers: this.token ? { authorization: `Bearer ${this.token}` } : {},
    });
    if (res.status === 404) return null;
    if (!res.ok) throw new ApiError(res.status, res.statusText);
    return res.arrayBuffer();
  }

  loginStart(username: string): Promise<LoginStartResponse> {
    return this.request("POST", "/auth/login/start", { username });
  }

  loginComplete(username: string, challengeNonce: string, signatureB64: string): Promise<LoginCompleteResponse> {
    return this.request("POST", "/auth/login/complete", {
      username,
      challenge_nonce: challengeNonce,
      signature: signatureB64,
    });
  }

  listBranches(org: string, store: string): Promise<BranchSummary[]> {
    return this.request("GET", `/orgs/${encodeURIComponent(org)}/stores/${encodeURIComponent(store)}/branches`);
  }

  getBranchDetails(org: string, store: string, branch: string): Promise<BranchDetails> {
    return this.request(
      "GET",
      `/orgs/${encodeURIComponent(org)}/stores/${encodeURIComponent(store)}/branches/${encodeURIComponent(branch)}`,
    );
  }

  listKeys(org: string, store: string, branch: string): Promise<KeysMap> {
    return this.request(
      "GET",
      `/orgs/${encodeURIComponent(org)}/stores/${encodeURIComponent(store)}/branches/${encodeURIComponent(branch)}/keys`,
    );
  }

  getRef(org: string, store: string, branch: string): Promise<RefResponse> {
    return this.request(
      "GET",
      `/orgs/${encodeURIComponent(org)}/stores/${encodeURIComponent(store)}/branches/${encodeURIComponent(branch)}/ref`,
    );
  }

  getUserById(userId: string): Promise<UserPublicInfo> {
    return this.request("GET", `/users/by-id/${encodeURIComponent(userId)}`);
  }
}
