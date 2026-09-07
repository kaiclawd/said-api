/**
 * SAID Identity — minimal, zero-dependency client for partners.
 *
 * Read an agent's identity and reputation by a stable opaque id. No crypto,
 * no wallet handling, no chain knowledge required — it's just a trust lookup.
 *
 *   import { SaidIdentity } from './said-identity';
 *   const said = new SaidIdentity();
 *
 *   // Who is this agent + how trustworthy?
 *   const agent = await said.get('cmmwv5y5q01whoh482p337uhe');
 *
 *   // Gate access: only let reputable agents through.
 *   if (await said.meetsReputation(agentId, 60)) { ...allow... }
 *
 * The id can be a SAID id, and for convenience also resolves a wallet or pda
 * if that's all a partner has.
 */

export type Tier = 'unranked' | 'bronze' | 'silver' | 'gold' | 'platinum';

export interface SaidAgent {
  id: string;
  name: string | null;
  description: string | null;
  image: string | null;
  verified: boolean;
  reputation: {
    score: number; // 0–100
    tier: Tier;
    badges: string[];
    feedbackCount: number;
    scored: boolean;
  };
  capabilities: {
    serviceTypes: string[];
    skills: string[];
    a2a: string | null;
    mcp: string | null;
  };
  registeredAt: string;
  /** Present only when fetched with { onchain: true }. */
  onchain?: {
    chain: 'solana';
    wallet: string;
    pda: string;
    explorer: string;
  };
}

export class SaidIdentityError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'SaidIdentityError';
  }
}

export class SaidIdentity {
  private readonly baseUrl: string;

  constructor(opts: { baseUrl?: string } = {}) {
    this.baseUrl = (opts.baseUrl ?? 'https://api.saidprotocol.com').replace(/\/$/, '');
  }

  /**
   * Look up an agent by id (or wallet / pda). Returns null if not found.
   * Pass { onchain: true } to also get the verifiable Solana anchor.
   */
  async get(id: string, opts: { onchain?: boolean } = {}): Promise<SaidAgent | null> {
    const qs = opts.onchain ? '?include=onchain' : '';
    const res = await fetch(`${this.baseUrl}/api/identity/${encodeURIComponent(id)}${qs}`);
    if (res.status === 404) return null;
    if (!res.ok) {
      throw new SaidIdentityError(`SAID identity lookup failed (${res.status})`, res.status);
    }
    return (await res.json()) as SaidAgent;
  }

  /**
   * True if the agent exists, is verified, and its reputation score is at or
   * above `min` (0–100). The one-liner for reputation-gating access.
   */
  async meetsReputation(id: string, min: number): Promise<boolean> {
    const agent = await this.get(id);
    return !!agent && agent.verified && agent.reputation.score >= min;
  }
}
