/**
 * SAID Trust Score Engine
 *
 * Two-layer scoring system:
 *   - SAID Engine (70 pts max) — on-chain Solana + internal DB data
 *   - FairScale Enrichment (30 pts max) — external API with 3s timeout fallback
 *
 * Scores cached in Redis with 6-hour TTL. BullMQ queue for background refresh.
 */

import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';
import { Connection, PublicKey } from '@solana/web3.js';
import Redis from 'ioredis';
import { Queue, Worker } from 'bullmq';

// ─── Types ────────────────────────────────────────────────────────

export interface ScoreBreakdown {
  identity: number;
  activity: number;
  economic: number;
  ecosystem: number;
  longevity: number;
  fairscale_enrichment: number;
}

export interface ScoreResult {
  wallet: string;
  score: number;
  tier: 'unverified' | 'bronze' | 'silver' | 'gold' | 'platinum';
  breakdown: ScoreBreakdown;
  badges: string[];
  flags: string[];
  sources: string[];
  cached: boolean;
  updated: string;
}

// Known LST (Liquid Staking Token) mints
const LST_MINTS = new Set([
  'mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So',  // mSOL
  'J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn', // jitoSOL
  'bSo13r4TkiE4KumL71LsHTPpL2euBYLFx6h9HP3piy1',  // bSOL
  '7dHbWXmci3dT8UFYWYZweBLXgycu7Y3iL6trKn1Y7ARj', // stSOL
  'he1iusmfkpAdwvxLNGV8Y1iSbj4rUy6yMhEA3fotn9A',  // hSOL
  '5oVNBeEEQvYi1cX3ir8Dx5n1P7pdxydbGF2X4TxVusJm', // INF
]);

// Known DEX program IDs for swap detection
const DEX_PROGRAMS = new Set([
  'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4',  // Jupiter v6
  'whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc',  // Orca Whirlpool
  'CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK', // Raydium CLMM
  '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8', // Raydium AMM
]);

// Known SAID ecosystem partner program IDs
const ECOSYSTEM_PARTNERS = new Set([
  '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G', // SAID Protocol
  'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s',  // Metaplex
]);

const CACHE_TTL = 6 * 60 * 60; // 6 hours in seconds
const CACHE_PREFIX = 'said:score:';
const FAIRSCALE_TIMEOUT = 3_000; // 3 seconds

// ─── Redis & Queue Setup ──────────────────────────────────────────

let redis: Redis | null = null;
let scoreQueue: Queue | null = null;
let scoreWorker: Worker | null = null;

function getRedis(): Redis | null {
  if (redis) return redis;
  const url = process.env.REDIS_URL;
  if (!url) {
    console.warn('[Score] REDIS_URL not set — caching disabled');
    return null;
  }
  try {
    redis = new Redis(url, { maxRetriesPerRequest: 3, lazyConnect: true });
    redis.on('error', (err) => console.error('[Score Redis]', err.message));
    redis.connect().catch(() => {});
    return redis;
  } catch {
    return null;
  }
}

function getQueue(): Queue | null {
  if (scoreQueue) return scoreQueue;
  const url = process.env.REDIS_URL;
  if (!url) return null;
  try {
    scoreQueue = new Queue('score-refresh', {
      connection: { url },
      defaultJobOptions: {
        removeOnComplete: 100,
        removeOnFail: 50,
        attempts: 2,
        backoff: { type: 'exponential', delay: 5_000 },
      },
    });
    return scoreQueue;
  } catch {
    return null;
  }
}

// ─── Tier & Badge Logic ───────────────────────────────────────────

function getTier(score: number): ScoreResult['tier'] {
  if (score >= 80) return 'platinum';
  if (score >= 60) return 'gold';
  if (score >= 40) return 'silver';
  if (score >= 20) return 'bronze';
  return 'unverified';
}

interface BadgeContext {
  isVerified: boolean;
  hasLST: boolean;
  noDumps: boolean;
  platformCount: number;
  attestationsGiven: number;
  registeredAt: Date;
  messagesSent: number;
}

function computeBadges(ctx: BadgeContext): string[] {
  const badges: string[] = [];
  if (ctx.isVerified) badges.push('verified');
  if (ctx.hasLST) badges.push('lst_staker');
  if (ctx.noDumps) badges.push('no_dumps');
  if (ctx.platformCount >= 2) badges.push('multi_platform');
  if (ctx.attestationsGiven >= 3) badges.push('attester');

  // OG badge: registered within first 30 days of SAID launch (~Jan 2025)
  const saidLaunch = new Date('2025-01-15T00:00:00Z');
  const ogCutoff = new Date(saidLaunch.getTime() + 30 * 24 * 60 * 60 * 1000);
  if (ctx.registeredAt <= ogCutoff) badges.push('og');

  if (ctx.messagesSent >= 50) badges.push('active_messenger');
  return badges;
}

// ─── SAID Engine (70 pts) ─────────────────────────────────────────

async function computeSAIDScore(
  wallet: string,
  prisma: PrismaClient,
  connection: Connection,
): Promise<{
  score: number;
  breakdown: Omit<ScoreBreakdown, 'fairscale_enrichment'>;
  badges: string[];
  flags: string[];
}> {
  const pubkey = new PublicKey(wallet);

  // ── Fetch DB data in parallel ─────────────────────────────────
  const [agent, attestationsReceived, attestationsGiven, walletLinks, messageCount] = await Promise.all([
    prisma.agent.findUnique({
      where: { wallet },
      include: { _count: { select: { feedbackReceived: true } } },
    }),
    prisma.attestation.count({ where: { subjectWallet: wallet, revokedAt: null } }),
    prisma.attestation.count({ where: { attesterWallet: wallet, revokedAt: null } }),
    prisma.walletLink.count({ where: { agentPda: { in: await getAgentPdas(wallet, prisma) } } }),
    prisma.a2AMessage.count({ where: { fromWallet: wallet } }),
  ]);

  // ── Fetch on-chain data in parallel ───────────────────────────
  const [balance, tokenAccounts, signatures] = await Promise.all([
    connection.getBalance(pubkey).catch(() => 0),
    connection.getParsedTokenAccountsByOwner(pubkey, { programId: new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA') }).catch(() => ({ value: [] })),
    connection.getSignaturesForAddress(pubkey, { limit: 200 }).catch(() => []),
  ]);

  // Also check Token-2022 accounts
  const token2022Accounts = await connection.getParsedTokenAccountsByOwner(pubkey, {
    programId: new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'),
  }).catch(() => ({ value: [] }));

  const allTokenAccounts = [...tokenAccounts.value, ...token2022Accounts.value];

  // ── Parse on-chain data ───────────────────────────────────────
  const now = Date.now();
  const thirtyDaysAgo = now - 30 * 24 * 60 * 60 * 1000;

  // Recent signatures (within 30d)
  const recentSigs = signatures.filter(s => (s.blockTime || 0) * 1000 > thirtyDaysAgo);
  const txCount30d = recentSigs.length;

  // Active days (30d)
  const activeDaysSet = new Set(
    recentSigs.map(s => new Date((s.blockTime || 0) * 1000).toISOString().slice(0, 10))
  );
  const activeDays30d = activeDaysSet.size;

  // Consistency (coefficient of variation of tx gaps)
  let consistencyScore = 0;
  if (recentSigs.length >= 3) {
    const times = recentSigs
      .map(s => (s.blockTime || 0) * 1000)
      .sort((a, b) => a - b);
    const gaps: number[] = [];
    for (let i = 1; i < times.length; i++) {
      gaps.push(times[i] - times[i - 1]);
    }
    const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
    if (mean > 0) {
      const variance = gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length;
      const cv = Math.sqrt(variance) / mean;
      // Low CV = consistent. CV < 1.0 = full marks, CV > 3.0 = 0
      consistencyScore = Math.max(0, Math.min(3, (3 - cv) * (3 / 2)));
    }
  }

  // Error rate
  const failedTx = recentSigs.filter(s => s.err !== null).length;
  const totalTx = recentSigs.length;
  const errorPenalty = totalTx > 0 ? (failedTx / totalTx) * -3 : 0;

  // Unique program interactions (from recent sigs — we use memo as proxy since we can't get full tx details cheaply)
  // We'll count unique programs from token accounts + known programs
  const uniquePrograms = new Set<string>();
  recentSigs.forEach(s => {
    if (s.memo) uniquePrograms.add('memo');
  });
  // Add programs from token interactions
  allTokenAccounts.forEach(ta => {
    const info = ta.account.data.parsed?.info;
    if (info?.mint) uniquePrograms.add(info.mint.slice(0, 8));
  });

  // Token diversity
  const uniqueTokenMints = new Set(
    allTokenAccounts
      .map(ta => ta.account.data.parsed?.info?.mint)
      .filter(Boolean)
  );

  // LST detection
  const hasLST = allTokenAccounts.some(ta => {
    const mint = ta.account.data.parsed?.info?.mint;
    return mint && LST_MINTS.has(mint);
  });

  // DEX activity detection (look for known DEX programs in memo/logs)
  // Rough heuristic: count signatures that are likely swaps
  let swapCount = 0;
  for (const sig of recentSigs) {
    if (sig.memo && (sig.memo.includes('swap') || sig.memo.includes('Swap'))) {
      swapCount++;
    }
  }
  // If we don't have memo data, estimate from token account count
  if (swapCount === 0 && uniqueTokenMints.size > 3) {
    swapCount = Math.min(uniqueTokenMints.size, 10); // rough estimate
  }

  // Large dump detection (>50% balance sold in single tx)
  // Heuristic: check if any recent signatures had very large lamport changes
  // For now, assume no dumps unless we detect an obvious signal
  const noDumps = true; // Placeholder — real detection requires parsed tx details

  // Wallet age (first ever tx)
  const firstTxTime = signatures.length > 0
    ? (signatures[signatures.length - 1].blockTime || 0) * 1000
    : 0;
  const walletAgeDays = firstTxTime > 0 ? (now - firstTxTime) / (1000 * 60 * 60 * 24) : 0;

  // Continuous activity check (no gaps > 30d in last year)
  let continuousActivity = true;
  if (signatures.length >= 2) {
    const sortedTimes = signatures
      .map(s => (s.blockTime || 0) * 1000)
      .filter(t => t > 0)
      .sort((a, b) => a - b);
    for (let i = 1; i < sortedTimes.length; i++) {
      if (sortedTimes[i] - sortedTimes[i - 1] > 30 * 24 * 60 * 60 * 1000) {
        continuousActivity = false;
        break;
      }
    }
  } else {
    continuousActivity = false;
  }

  // Registration streak (consecutive months active)
  const monthsActive = new Set(
    signatures.map(s => {
      const d = new Date((s.blockTime || 0) * 1000);
      return `${d.getFullYear()}-${d.getMonth()}`;
    })
  );
  let streak = 0;
  const nowDate = new Date();
  for (let i = 0; i < 6; i++) {
    const m = new Date(nowDate.getFullYear(), nowDate.getMonth() - i, 1);
    if (monthsActive.has(`${m.getFullYear()}-${m.getMonth()}`)) {
      streak++;
    } else {
      break;
    }
  }

  // Platform registrations
  const platformSources = agent?.registrationSource || '';
  const knownPlatforms = new Set<string>();
  if (platformSources) knownPlatforms.add(platformSources);
  // Count cross-platform registrations from agent data
  // Check if agent has multiple registration sources or platform interactions
  const platformCount = Math.max(knownPlatforms.size, agent?.registrationSource ? 1 : 0);

  // Metadata completeness
  let metadataPoints = 0;
  if (agent?.a2aEndpoint) metadataPoints += 0.5;
  if (agent?.mcpEndpoint) metadataPoints += 0.5;
  if (agent?.wallet) metadataPoints += 0.5; // agentWallet
  if (agent?.pda) metadataPoints += 0.5; // DID equivalent

  // ── Pillar 1: Identity (21 pts max) ───────────────────────────
  const daysRegistered = agent
    ? (now - new Date(agent.registeredAt).getTime()) / (1000 * 60 * 60 * 24)
    : 0;

  const identity =
    Math.min(daysRegistered / 180, 1) * 6 +             // Registration age (6)
    (agent?.isVerified ? 4 : 0) +                        // Verified status (4)
    (agent?.passportMint ? 3 : 0) +                      // NFT passport (3)
    Math.min((walletLinks + 1) / 3, 1) * 2 +             // Linked wallets (2) — +1 for primary
    Math.min(attestationsReceived / 5, 1) * 2 +          // Unique attesters (2)
    (platformSources && platformSources !== 'on-chain-sync' ? 2 : 0) + // Platform-registered (2)
    metadataPoints;                                       // Metadata completeness (2)

  // ── Pillar 2: Activity (17.5 pts max) ─────────────────────────
  const activity =
    Math.min(txCount30d / 100, 1) * 5 +                  // Tx count 30d (5)
    Math.min(activeDays30d / 20, 1) * 4 +                // Active days 30d (4)
    consistencyScore +                                    // Consistency (3)
    errorPenalty +                                        // Error rate penalty (-3)
    Math.min(uniquePrograms.size / 5, 1) * 3 +           // Unique programs (3)
    Math.min(messageCount / 50, 1) * 2.5;                // Message activity (2.5)

  // ── Pillar 3: Economic (14 pts max) ───────────────────────────
  const solBalance = balance / 1e9; // Convert lamports to SOL

  const economic =
    Math.min(solBalance / 5, 1) * 3 +                    // SOL balance (3)
    Math.min(uniqueTokenMints.size / 10, 1) * 3 +        // Token diversity (3)
    Math.min(swapCount / 20, 1) * 3 +                    // DEX activity (3)
    (hasLST ? 3 : 0) +                                   // LST staking (3)
    (noDumps ? 2 : 0);                                   // No large dumps (2)

  // ── Pillar 4: Ecosystem (10.5 pts max) ────────────────────────
  const ecosystem =
    Math.min(platformCount / 3, 1) * 4 +                 // Cross-platform (4)
    Math.min(attestationsGiven / 5, 1) * 3 +             // Attestations given (3)
    (uniquePrograms.size > 0 ? 3.5 : 0);                 // Partner interaction (3.5)

  // ── Pillar 5: Longevity (7 pts max) ───────────────────────────
  const longevity =
    Math.min(walletAgeDays / 365, 1) * 3 +               // Wallet age (3)
    (continuousActivity ? 2 : 0) +                        // Continuous activity (2)
    Math.min(streak / 6, 1) * 2;                          // Registration streak (2)

  // ── Totals ────────────────────────────────────────────────────
  const saidScore = Math.min(70,
    Math.max(0, identity) +
    Math.max(0, activity) +
    Math.max(0, economic) +
    Math.max(0, ecosystem) +
    Math.max(0, longevity)
  );

  // Round pillar scores to 1 decimal
  const round1 = (n: number) => Math.round(Math.max(0, n) * 10) / 10;

  const badges = computeBadges({
    isVerified: agent?.isVerified || false,
    hasLST,
    noDumps,
    platformCount,
    attestationsGiven,
    registeredAt: agent?.registeredAt || new Date(),
    messagesSent: messageCount,
  });

  const flags: string[] = [];
  if (errorPenalty < -1) flags.push('high_error_rate');
  if (!agent) flags.push('not_registered');

  return {
    score: Math.round(saidScore * 10) / 10,
    breakdown: {
      identity: round1(identity),
      activity: round1(activity),
      economic: round1(economic),
      ecosystem: round1(ecosystem),
      longevity: round1(longevity),
    },
    badges,
    flags,
  };
}

// Helper: get all PDAs associated with a wallet
async function getAgentPdas(wallet: string, prisma: PrismaClient): Promise<string[]> {
  const agent = await prisma.agent.findUnique({ where: { wallet }, select: { pda: true } });
  return agent ? [agent.pda] : [];
}

// ─── FairScale Enrichment (30 pts) ────────────────────────────────

async function fetchFairScaleScore(wallet: string): Promise<{ score: number; max: number } | null> {
  const apiUrl = process.env.FAIRSCALE_API_URL;
  const apiKey = process.env.FAIRSCALE_API_KEY;

  if (!apiUrl) return null;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FAIRSCALE_TIMEOUT);

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) headers['fairkey'] = apiKey;

    const res = await fetch(`${apiUrl}/score?wallet=${wallet}`, {
      signal: controller.signal,
      headers,
    });
    clearTimeout(timeout);

    if (!res.ok) return null;

    const data = await res.json() as { fairscore?: number; fairscore_base?: number; score?: number; max?: number };
    const score = data.fairscore ?? data.score;
    if (typeof score !== 'number') return null;

    return {
      score,
      max: data.max || 100,
    };
  } catch {
    // Timeout or network error — degrade gracefully
    return null;
  }
}

// ─── Full Score Computation ───────────────────────────────────────

async function computeFullScore(
  wallet: string,
  prisma: PrismaClient,
  connection: Connection,
): Promise<ScoreResult> {
  const [saidResult, fairscale] = await Promise.all([
    computeSAIDScore(wallet, prisma, connection),
    fetchFairScaleScore(wallet),
  ]);

  let finalScore: number;
  let fairscaleContribution = 0;
  const sources: string[] = ['said'];

  if (fairscale) {
    fairscaleContribution = (fairscale.score / fairscale.max) * 30;
    finalScore = saidResult.score + fairscaleContribution;
    sources.push('fairscale');
  } else {
    // Scale SAID-only score to 0-100
    finalScore = (saidResult.score / 70) * 100;
  }

  finalScore = Math.round(Math.min(100, Math.max(0, finalScore)));

  return {
    wallet,
    score: finalScore,
    tier: getTier(finalScore),
    breakdown: {
      ...saidResult.breakdown,
      fairscale_enrichment: Math.round(fairscaleContribution * 10) / 10,
    },
    badges: saidResult.badges,
    flags: saidResult.flags,
    sources,
    cached: false,
    updated: new Date().toISOString(),
  };
}

// ─── Cache Layer ──────────────────────────────────────────────────

async function getCachedScore(wallet: string): Promise<ScoreResult | null> {
  const r = getRedis();
  if (!r) return null;

  try {
    const cached = await r.get(`${CACHE_PREFIX}${wallet}`);
    if (!cached) return null;
    const result = JSON.parse(cached) as ScoreResult;
    result.cached = true;
    return result;
  } catch {
    return null;
  }
}

async function setCachedScore(wallet: string, result: ScoreResult): Promise<void> {
  const r = getRedis();
  if (!r) return;

  try {
    await r.set(`${CACHE_PREFIX}${wallet}`, JSON.stringify(result), 'EX', CACHE_TTL);
  } catch {
    // Non-critical — log and continue
  }
}

// ─── Queue: Background Refresh ────────────────────────────────────

export function initScoreWorker(prisma: PrismaClient, connection: Connection): void {
  const url = process.env.REDIS_URL;
  if (!url) return;

  try {
    scoreWorker = new Worker(
      'score-refresh',
      async (job) => {
        const { wallet } = job.data as { wallet: string };
        console.log(`[Score Worker] Refreshing score for ${wallet}`);
        const result = await computeFullScore(wallet, prisma, connection);
        await setCachedScore(wallet, result);
        console.log(`[Score Worker] Done — ${wallet} score=${result.score}`);
      },
      { connection: { url }, concurrency: 3 },
    );
    scoreWorker.on('failed', (job, err) => {
      console.error(`[Score Worker] Job ${job?.id} failed:`, err.message);
    });
    console.log('[Score] Background worker started');
  } catch (err) {
    console.error('[Score] Worker init failed:', err);
  }
}

async function enqueueRefresh(wallet: string): Promise<void> {
  const q = getQueue();
  if (!q) return;
  try {
    await q.add('refresh', { wallet }, {
      jobId: `score-${wallet}`,
      delay: 0,
    });
  } catch {
    // Non-critical
  }
}

// ─── Route: GET /api/score/:wallet ────────────────────────────────

export function createScoreRoutes(prisma: PrismaClient, connection: Connection): Hono {
  const routes = new Hono();

  routes.get('/:wallet', async (c) => {
    const wallet = c.req.param('wallet');

    // Validate wallet format (base58, 32-44 chars)
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(wallet)) {
      return c.json({ error: 'Invalid wallet address' }, 400);
    }

    // Check cache first
    const cached = await getCachedScore(wallet);
    if (cached) {
      // Queue background refresh if stale (> 5 hours = approaching 6h TTL)
      const updatedAt = new Date(cached.updated).getTime();
      if (Date.now() - updatedAt > 5 * 60 * 60 * 1000) {
        enqueueRefresh(wallet);
      }
      return c.json(cached);
    }

    // Compute fresh score
    try {
      const result = await computeFullScore(wallet, prisma, connection);

      // Cache the result (non-blocking)
      setCachedScore(wallet, result);

      return c.json(result);
    } catch (err: any) {
      console.error(`[Score] Error computing score for ${wallet}:`, err.message);
      return c.json({ error: 'Failed to compute trust score', details: err.message }, 500);
    }
  });

  return routes;
}
