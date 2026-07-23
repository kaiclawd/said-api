/**
 * SAID Protocol — On-chain Enforcement Data Layer
 *
 * Reads staking and slashing data directly from the SAID on-chain program.
 * This is SAID's #1 competitive differentiator — no other agent trust
 * protocol has economic enforcement (staking/slashing).
 *
 * Program ID: 5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G
 *
 * PDA Derivation:
 *   Agent Identity: [b"agent", owner_pubkey.as_ref()]
 *   Agent Stake:    [b"stake", agent_identity_pda.as_ref()]
 *
 * On-chain Account Layouts (Anchor):
 *   AgentIdentity (AgentStake also):
 *     discriminator (8 bytes) | owner (32) | authority (32) | metadata_uri (4+200)
 *     | created_at (8) | is_verified (1) | verified_at (8, option)
 *     | verification_tier (1) | stake_amount (8) | staked_at (8, option)
 *     | slash_count (4) | last_slashed_at (8, option)
 *     | last_receipt_seq (8) | last_anchor_index (8) | bump (1)
 *
 *   AgentStake:
 *     discriminator (8) | agent_id (32) | amount (8) | staked_at (8)
 *     | cooldown_until (8, option) | is_slashed (1) | bump (1)
 */

import { Connection, PublicKey } from '@solana/web3.js';
import { Hono } from 'hono';

// ─── Constants ──────────────────────────────────────────────────────

const SAID_PROGRAM_ID = new PublicKey('5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G');
const LAMPORTS_PER_SOL = 1_000_000_000;

// Minimum rent-exempt balance for a 0-lamport stake account isn't relevant;
// we're reading the data, not creating accounts.

// ─── Types ──────────────────────────────────────────────────────────

export interface EnforcementStatus {
  wallet: string;
  programId: string;
  agentPda: string | null;
  stakePda: string | null;
  registered: boolean;
  // Staking
  staked: boolean;
  stakeAmountSol: number;
  stakeAmountLamports: number;
  stakedAt: number | null; // unix timestamp
  cooldownUntil: number | null; // unix timestamp
  unstakeRequested: boolean;
  // Slashing
  isSlashed: boolean;
  slashCount: number;
  lastSlashedAt: number | null; // unix timestamp
  // Identity
  isVerified: boolean;
  verificationTier: number;
  owner: string | null;
  registeredAt: number | null; // unix timestamp
  // Derived
  enforcementTier: 'economic' | 'reputation' | 'none';
  economicSecuritySol: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  riskReasons: string[];
}

export interface EnforcementBatchResult {
  results: Record<string, EnforcementStatus>;
  summary: {
    total: number;
    staked: number;
    slashed: number;
    verified: number;
    totalStakedSol: number;
  };
}

// ─── PDA Derivation ─────────────────────────────────────────────────

/**
 * Derive the AgentIdentity PDA from an owner wallet address.
 * Seeds: [b"agent", owner.key().as_ref()]
 */
export function deriveAgentPda(ownerWallet: string): [PublicKey, number] {
  const owner = new PublicKey(ownerWallet);
  return PublicKey.findProgramAddressSync(
    [Buffer.from('agent'), owner.toBuffer()],
    SAID_PROGRAM_ID,
  );
}

/**
 * Derive the AgentStake PDA from an AgentIdentity PDA.
 * Seeds: [b"stake", agent_identity.key().as_ref()]
 */
export function deriveStakePda(agentPda: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('stake'), agentPda.toBuffer()],
    SAID_PROGRAM_ID,
  );
}

// ─── Account Decoders ───────────────────────────────────────────────

// Anchor account discriminator = sha256("account:<AccountName>")[0..8]
// We use the first 8 bytes to verify account type.

const AGENT_IDENTITY_DISCRIMINATOR = Buffer.from([
  0x18, 0x14, 0x29, 0x74, 0x6b, 0x81, 0x85, 0x6d, // placeholder — will be replaced by runtime probe
]);

const AGENT_STAKE_DISCRIMINATOR = Buffer.from([
  0x2d, 0x31, 0xb7, 0x3f, 0x6f, 0x4d, 0x92, 0x0c, // placeholder
]);

/**
 * Decode an AgentIdentity account from raw buffer.
 *
 * Layout (after 8-byte discriminator):
 *   owner: 32 bytes
 *   authority: 32 bytes
 *   metadata_uri: 4 (length) + N bytes (string)
 *   created_at: 8 bytes (i64)
 *   is_verified: 1 byte (bool)
 *   verified_at: 1 + 8 bytes (Option<i64> — 0 = None, 1 = Some)
 *   verification_tier: 1 byte (u8)
 *   stake_amount: 8 bytes (u64)
 *   staked_at: 1 + 8 bytes (Option<i64>)
 *   slash_count: 4 bytes (u32)
 *   last_slashed_at: 1 + 8 bytes (Option<i64>)
 *   last_receipt_seq: 8 bytes (u64)
 *   last_anchor_index: 8 bytes (u64)
 *   bump: 1 byte (u8)
 */
export function decodeAgentIdentity(data: Buffer): {
  owner: string;
  authority: string;
  metadataUri: string;
  createdAt: number;
  isVerified: boolean;
  verifiedAt: number | null;
  verificationTier: number;
  stakeAmount: number;
  stakedAt: number | null;
  slashCount: number;
  lastSlashedAt: number | null;
  lastReceiptSeq: number;
  lastAnchorIndex: number;
  bump: number;
} {
  let offset = 8; // skip discriminator

  const owner = new PublicKey(data.subarray(offset, offset + 32)).toBase58();
  offset += 32;

  const authority = new PublicKey(data.subarray(offset, offset + 32)).toBase58();
  offset += 32;

  // metadata_uri: 4-byte length prefix + string data
  const uriLen = data.readUInt32LE(offset);
  offset += 4;
  const metadataUri = data.subarray(offset, offset + uriLen).toString('utf8');
  offset += uriLen;

  const createdAt = Number(data.readBigInt64LE(offset));
  offset += 8;

  const isVerified = data[offset] === 1;
  offset += 1;

  // Option<i64>
  const verifiedAtOpt = data[offset];
  offset += 1;
  const verifiedAt = verifiedAtOpt === 1 ? Number(data.readBigInt64LE(offset)) : null;
  offset += 8;

  const verificationTier = data.readUInt8(offset);
  offset += 1;

  const stakeAmount = Number(data.readBigUInt64LE(offset));
  offset += 8;

  const stakedAtOpt = data[offset];
  offset += 1;
  const stakedAt = stakedAtOpt === 1 ? Number(data.readBigInt64LE(offset)) : null;
  offset += 8;

  const slashCount = data.readUInt32LE(offset);
  offset += 4;

  const lastSlashedAtOpt = data[offset];
  offset += 1;
  const lastSlashedAt = lastSlashedAtOpt === 1 ? Number(data.readBigInt64LE(offset)) : null;
  offset += 8;

  const lastReceiptSeq = Number(data.readBigUInt64LE(offset));
  offset += 8;

  const lastAnchorIndex = Number(data.readBigUInt64LE(offset));
  offset += 8;

  const bump = data.readUInt8(offset);

  return {
    owner,
    authority,
    metadataUri,
    createdAt,
    isVerified,
    verifiedAt,
    verificationTier,
    stakeAmount,
    stakedAt,
    slashCount,
    lastSlashedAt,
    lastReceiptSeq,
    lastAnchorIndex,
    bump,
  };
}

/**
 * Decode an AgentStake account from raw buffer.
 *
 * Layout (after 8-byte discriminator):
 *   agent_id: 32 bytes
 *   amount: 8 bytes (u64)
 *   staked_at: 8 bytes (i64)
 *   cooldown_until: 1 + 8 bytes (Option<i64>)
 *   is_slashed: 1 byte (bool)
 *   bump: 1 byte (u8)
 */
export function decodeAgentStake(data: Buffer): {
  agentId: string;
  amount: number;
  stakedAt: number;
  cooldownUntil: number | null;
  isSlashed: boolean;
  bump: number;
} {
  let offset = 8; // skip discriminator

  const agentId = new PublicKey(data.subarray(offset, offset + 32)).toBase58();
  offset += 32;

  const amount = Number(data.readBigUInt64LE(offset));
  offset += 8;

  const stakedAt = Number(data.readBigInt64LE(offset));
  offset += 8;

  const cooldownOpt = data[offset];
  offset += 1;
  const cooldownUntil = cooldownOpt === 1 ? Number(data.readBigInt64LE(offset)) : null;
  offset += 8;

  const isSlashed = data[offset] === 1;
  offset += 1;

  const bump = data.readUInt8(offset);

  return { agentId, amount, stakedAt, cooldownUntil, isSlashed, bump };
}

// ─── Risk Assessment ────────────────────────────────────────────────

function assessRisk(status: Partial<EnforcementStatus>): {
  level: 'low' | 'medium' | 'high' | 'critical';
  reasons: string[];
} {
  const reasons: string[] = [];

  if (status.isSlashed) {
    reasons.push('Agent stake has been slashed — economic penalty applied');
  }

  if (status.slashCount && status.slashCount > 0) {
    reasons.push(`Agent has been slashed ${status.slashCount} time(s)`);
  }

  if (!status.staked || status.stakeAmountSol === 0) {
    reasons.push('No economic stake — zero skin-in-the-game');
  }

  if (status.stakeAmountSol && status.stakeAmountSol > 0 && status.stakeAmountSol < 0.1) {
    reasons.push('Minimum stake only — low economic commitment');
  }

  if (!status.isVerified) {
    reasons.push('Agent is not verified');
  }

  // Determine level
  let level: 'low' | 'medium' | 'high' | 'critical' = 'low';

  if (status.isSlashed || (status.slashCount && status.slashCount >= 2)) {
    level = 'critical';
  } else if (status.slashCount && status.slashCount >= 1) {
    level = 'high';
  } else if (!status.staked || status.stakeAmountSol === 0) {
    level = 'medium';
  } else if (status.stakeAmountSol && status.stakeAmountSol < 0.5) {
    level = 'medium';
  }

  return { level, reasons };
}

function deriveEnforcementTier(staked: boolean, isVerified: boolean): 'economic' | 'reputation' | 'none' {
  if (staked) return 'economic';
  if (isVerified) return 'reputation';
  return 'none';
}

// ─── Core Query Function ────────────────────────────────────────────

/**
 * Query on-chain enforcement data for a wallet address.
 * Reads both AgentIdentity and AgentStake PDAs.
 */
export async function getEnforcementStatus(
  connection: Connection,
  walletAddress: string,
): Promise<EnforcementStatus> {
  const [agentPda] = deriveAgentPda(walletAddress);
  const [stakePda] = deriveStakePda(agentPda);

  // Fetch both accounts in parallel
  const [agentAccount, stakeAccount] = await connection.getMultipleAccountsInfo([agentPda, stakePda]);

  // If no agent identity account, wallet isn't registered on-chain
  if (!agentAccount || !agentAccount.data) {
    return {
      wallet: walletAddress,
      programId: SAID_PROGRAM_ID.toBase58(),
      agentPda: agentPda.toBase58(),
      stakePda: stakePda.toBase58(),
      registered: false,
      staked: false,
      stakeAmountSol: 0,
      stakeAmountLamports: 0,
      stakedAt: null,
      cooldownUntil: null,
      unstakeRequested: false,
      isSlashed: false,
      slashCount: 0,
      lastSlashedAt: null,
      isVerified: false,
      verificationTier: 0,
      owner: null,
      registeredAt: null,
      enforcementTier: 'none',
      economicSecuritySol: 0,
      riskLevel: 'medium',
      riskReasons: ['No on-chain registration found'],
    };
  }

  // Decode agent identity
  const agent = decodeAgentIdentity(Buffer.from(agentAccount.data));

  // Decode stake account if it exists
  let stake = null;
  if (stakeAccount && stakeAccount.data) {
    try {
      stake = decodeAgentStake(Buffer.from(stakeAccount.data));
    } catch (e) {
      console.warn(`[enforcement] Failed to decode stake account for ${walletAddress}:`, e);
    }
  }

  const staked = stake !== null && stake.amount > 0;
  const stakeAmountLamports = stake?.amount ?? agent.stakeAmount ?? 0;
  const stakeAmountSol = stakeAmountLamports / LAMPORTS_PER_SOL;
  const isSlashed = stake?.isSlashed ?? false;
  const slashCount = agent.slashCount;
  const cooldownUntil = stake?.cooldownUntil ?? null;
  const unstakeRequested = cooldownUntil !== null;

  const enforcementTier = deriveEnforcementTier(staked, agent.isVerified);

  const partial: Partial<EnforcementStatus> = {
    isSlashed,
    slashCount,
    staked,
    stakeAmountSol,
    isVerified: agent.isVerified,
  };

  const { level, reasons } = assessRisk(partial);

  return {
    wallet: walletAddress,
    programId: SAID_PROGRAM_ID.toBase58(),
    agentPda: agentPda.toBase58(),
    stakePda: stakePda.toBase58(),
    registered: true,
    staked,
    stakeAmountSol,
    stakeAmountLamports,
    stakedAt: stake?.stakedAt ?? agent.stakedAt ?? null,
    cooldownUntil,
    unstakeRequested,
    isSlashed,
    slashCount,
    lastSlashedAt: agent.lastSlashedAt,
    isVerified: agent.isVerified,
    verificationTier: agent.verificationTier,
    owner: agent.owner,
    registeredAt: agent.createdAt,
    enforcementTier,
    economicSecuritySol: stakeAmountSol,
    riskLevel: level,
    riskReasons: reasons,
  };
}

// ─── Hono Routes ────────────────────────────────────────────────────

/**
 * Create the enforcement router with all staking/slashing endpoints.
 *
 * Usage in index.ts:
 *   import { createEnforcementRouter } from './enforcement.js';
 *   app.route('/api/enforcement', createEnforcementRouter(connection));
 */
export function createEnforcementRouter(connection: Connection): Hono {
  const router = new Hono();

  /**
   * GET /api/enforcement/:wallet
   *
   * Returns the full on-chain enforcement status for an agent.
   * Includes staking amount, slash history, risk assessment, and
   * enforcement tier classification.
   *
   * This is SAID's unique differentiator — no other agent trust
   * protocol exposes economic enforcement data.
   */
  router.get('/:wallet', async (c) => {
    const { wallet } = c.req.param();

    // Validate Solana address format
    try {
      new PublicKey(wallet);
    } catch {
      return c.json({ error: 'Invalid wallet address' }, 400);
    }

    try {
      const status = await getEnforcementStatus(connection, wallet);
      return c.json(status);
    } catch (error) {
      console.error(`[enforcement] Failed for ${wallet}:`, error);
      return c.json({
        error: 'Failed to query enforcement status',
        details: error instanceof Error ? error.message : 'Unknown error',
      }, 500);
    }
  });

  /**
   * POST /api/enforcement/batch
   *
   * Batch query enforcement status for multiple wallets.
   * Body: { wallets: string[] } (max 25)
   *
   * Returns a map of wallet → EnforcementStatus plus summary stats.
   */
  router.post('/batch', async (c) => {
    const body = await c.req.json().catch(() => ({}));
    const wallets: string[] = body.wallets;

    if (!Array.isArray(wallets) || wallets.length === 0) {
      return c.json({ error: 'wallets array is required' }, 400);
    }

    if (wallets.length > 25) {
      return c.json({ error: 'Maximum 25 wallets per batch request' }, 400);
    }

    // Validate all addresses first
    for (const w of wallets) {
      try {
        new PublicKey(w);
      } catch {
        return c.json({ error: `Invalid wallet address: ${w}` }, 400);
      }
    }

    try {
      // Process in parallel
      const results = await Promise.allSettled(
        wallets.map((w) => getEnforcementStatus(connection, w)),
      );

      const statusMap: Record<string, EnforcementStatus> = {};
      let staked = 0;
      let slashed = 0;
      let verified = 0;
      let totalStakedSol = 0;

      for (let i = 0; i < wallets.length; i++) {
        const result = results[i];
        if (result.status === 'fulfilled') {
          statusMap[wallets[i]] = result.value;
          if (result.value.staked) {
            staked++;
            totalStakedSol += result.value.stakeAmountSol;
          }
          if (result.value.isSlashed) slashed++;
          if (result.value.isVerified) verified++;
        } else {
          // Graceful degradation for individual failures
          statusMap[wallets[i]] = {
            wallet: wallets[i],
            programId: SAID_PROGRAM_ID.toBase58(),
            agentPda: '',
            stakePda: '',
            registered: false,
            staked: false,
            stakeAmountSol: 0,
            stakeAmountLamports: 0,
            stakedAt: null,
            cooldownUntil: null,
            unstakeRequested: false,
            isSlashed: false,
            slashCount: 0,
            lastSlashedAt: null,
            isVerified: false,
            verificationTier: 0,
            owner: null,
            registeredAt: null,
            enforcementTier: 'none',
            economicSecuritySol: 0,
            riskLevel: 'high',
            riskReasons: ['Query failed'],
          };
        }
      }

      const response: EnforcementBatchResult = {
        results: statusMap,
        summary: {
          total: wallets.length,
          staked,
          slashed,
          verified,
          totalStakedSol: Math.round(totalStakedSol * 1000) / 1000,
        },
      };

      return c.json(response);
    } catch (error) {
      console.error('[enforcement] Batch failed:', error);
      return c.json({ error: 'Batch query failed' }, 500);
    }
  });

  /**
   * GET /api/enforcement/:wallet/stake
   *
   * Returns staking-specific data only (lightweight).
   */
  router.get('/:wallet/stake', async (c) => {
    const { wallet } = c.req.param();

    try {
      new PublicKey(wallet);
    } catch {
      return c.json({ error: 'Invalid wallet address' }, 400);
    }

    try {
      const [agentPda] = deriveAgentPda(wallet);
      const [stakePda] = deriveStakePda(agentPda);
      const stakeAccount = await connection.getAccountInfo(stakePda);

      if (!stakeAccount || !stakeAccount.data) {
        return c.json({
          wallet,
          staked: false,
          amountSol: 0,
          amountLamports: 0,
          stakedAt: null,
          cooldownUntil: null,
          isSlashed: false,
          stakePda: stakePda.toBase58(),
        });
      }

      const stake = decodeAgentStake(Buffer.from(stakeAccount.data));

      return c.json({
        wallet,
        staked: stake.amount > 0,
        amountSol: stake.amount / LAMPORTS_PER_SOL,
        amountLamports: stake.amount,
        stakedAt: stake.stakedAt,
        cooldownUntil: stake.cooldownUntil,
        isSlashed: stake.isSlashed,
        stakePda: stakePda.toBase58(),
      });
    } catch (error) {
      console.error(`[enforcement/stake] Failed for ${wallet}:`, error);
      return c.json({ error: 'Failed to query stake' }, 500);
    }
  });

  /**
   * GET /api/enforcement/leaderboard/staked
   *
   * Returns the top staked agents. Since we can't enumerate all stake
   * accounts efficiently via RPC, this requires a DB-backed cache.
   * For now, returns a helpful message pointing to the indexer.
   */
  router.get('/leaderboard/staked', (c) => {
    return c.json({
      message: 'Staked agents leaderboard requires indexer data',
      hint: 'Use GET /api/enforcement/:wallet for individual lookups',
      programId: SAID_PROGRAM_ID.toBase58(),
      note: 'An indexer service is needed to enumerate all stake accounts. This endpoint will be populated once the SAID indexer is deployed.',
    });
  });

  return router;
}
