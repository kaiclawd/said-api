import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

/**
 * AgentDEX Integration Module for SAID Protocol
 *
 * Provides endpoints that AgentDEX (or any agent-to-agent trading platform)
 * can use to:
 *   1. Verify an agent's SAID identity and reputation before a trade
 *   2. Submit post-trade feedback that feeds into the SAID reputation system
 *
 * This bridges SAID's identity layer with AgentDEX's trading layer, so agents
 * trading on AgentDEX carry portable, verifiable reputations.
 */

const prisma = new PrismaClient();

export const agentdexRoutes = new Hono();

// ──────────────────────────────────────────────
// GET /verify/:wallet
// Returns SAID identity + reputation for AgentDEX consumption
// ──────────────────────────────────────────────

agentdexRoutes.get('/verify/:wallet', async (c) => {
  const wallet = c.req.param('wallet');

  const agent = await prisma.agent.findUnique({
    where: { wallet },
    include: {
      _count: { select: { feedbackReceived: true } },
    },
  });

  if (!agent) {
    return c.json(
      {
        verified: false,
        wallet,
        error: 'Agent not registered in SAID Protocol',
      },
      404,
    );
  }

  // Compute a simple trust tier for easy consumption
  const trustTier =
    agent.isVerified && agent.reputationScore >= 70
      ? 'high'
      : agent.isVerified || agent.reputationScore >= 40
        ? 'medium'
        : 'low';

  return c.json({
    verified: true,
    wallet: agent.wallet,
    pda: agent.pda,
    identity: {
      name: agent.name,
      description: agent.description,
      twitter: agent.twitter,
      website: agent.website,
    },
    reputation: {
      score: agent.reputationScore,
      feedbackCount: agent._count.feedbackReceived,
      isVerified: agent.isVerified,
      trustTier,
    },
    endpoints: {
      mcp: agent.mcpEndpoint ?? null,
      a2a: agent.a2aEndpoint ?? null,
      x402Wallet: agent.x402Wallet ?? null,
    },
    serviceTypes: agent.serviceTypes,
    skills: agent.skills,
    registeredAt: agent.registeredAt.toISOString(),
    profileUrl: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
    badgeUrl: `https://api.saidprotocol.com/api/badge/${wallet}.svg?style=score`,
  });
});

// ──────────────────────────────────────────────
// POST /trade-feedback
// Accepts trade completion data from AgentDEX and converts it to SAID feedback
// ──────────────────────────────────────────────

interface TradeFeedbackBody {
  /** Wallet of the agent submitting feedback (the rater) */
  fromWallet: string;
  /** Wallet of the agent being rated */
  toWallet: string;
  /** Trade ID on AgentDEX (for dedup / audit) */
  tradeId: string;
  /** Overall satisfaction score 0-100 */
  score: number;
  /** Optional comment */
  comment?: string;
  /** Trade metadata */
  trade: {
    type: string; // e.g. "swap", "otc", "service"
    amount?: number;
    token?: string;
    completedAt: string; // ISO timestamp
  };
  /** Solana wallet signature over the canonical message */
  signature: string;
  /** Timestamp (ms) used when signing */
  timestamp: number;
}

function getTradeFeedbackMessage(
  fromWallet: string,
  toWallet: string,
  tradeId: string,
  score: number,
  timestamp: number,
): string {
  return `SAID:agentdex:trade-feedback:${toWallet}:${tradeId}:${score}:${timestamp}`;
}

function verifySignature(message: string, signature: string, walletAddress: string): boolean {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = bs58.decode(signature);
    const publicKeyBytes = bs58.decode(walletAddress);
    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  } catch {
    return false;
  }
}

agentdexRoutes.post('/trade-feedback', async (c) => {
  const body = (await c.req.json()) as TradeFeedbackBody;
  const { fromWallet, toWallet, tradeId, score, comment, trade, signature, timestamp } = body;

  // ── Validate required fields ──
  if (!fromWallet || !toWallet || !tradeId || score === undefined || !signature || !timestamp || !trade) {
    return c.json(
      {
        error:
          'Missing required fields: fromWallet, toWallet, tradeId, score, signature, timestamp, trade',
      },
      400,
    );
  }

  if (score < 0 || score > 100) {
    return c.json({ error: 'Score must be between 0 and 100' }, 400);
  }

  if (fromWallet === toWallet) {
    return c.json({ error: 'Cannot rate yourself' }, 400);
  }

  // ── Timestamp freshness (5 min window) ──
  const now = Date.now();
  if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
    return c.json({ error: 'Timestamp expired. Sign a fresh message.' }, 400);
  }

  // ── Verify target agent exists ──
  const targetAgent = await prisma.agent.findUnique({ where: { wallet: toWallet } });
  if (!targetAgent) {
    return c.json({ error: 'Target agent not found in SAID registry' }, 404);
  }

  // ── Verify signature ──
  const message = getTradeFeedbackMessage(fromWallet, toWallet, tradeId, score, timestamp);
  if (!verifySignature(message, signature, fromWallet)) {
    return c.json({ error: 'Invalid signature' }, 401);
  }

  // ── Check if from-agent is verified (for weighted scoring) ──
  const fromAgent = await prisma.agent.findUnique({ where: { wallet: fromWallet } });
  const fromIsVerified = fromAgent?.isVerified ?? false;
  const weight = fromIsVerified ? 2.0 : 1.0;

  // ── Build comment with trade context ──
  const tradeContext = `[AgentDEX ${trade.type}${trade.token ? ` ${trade.token}` : ''}${trade.amount ? ` ${trade.amount}` : ''} | trade:${tradeId}]`;
  const fullComment = comment ? `${tradeContext} ${comment}` : tradeContext;

  // ── Upsert feedback (one per fromWallet→toWallet pair, same as core SAID) ──
  const feedback = await prisma.feedback.upsert({
    where: {
      fromWallet_toWallet: { fromWallet, toWallet },
    },
    create: {
      fromWallet,
      toWallet,
      score,
      comment: fullComment,
      signature,
      weight,
      fromIsVerified,
    },
    update: {
      score,
      comment: fullComment,
      signature,
      weight,
      fromIsVerified,
    },
  });

  // ── Recalculate weighted reputation ──
  const allFeedback = await prisma.feedback.findMany({
    where: { toWallet },
    select: { score: true, weight: true },
  });

  let totalWeight = 0;
  let weightedSum = 0;
  for (const fb of allFeedback) {
    weightedSum += fb.score * fb.weight;
    totalWeight += fb.weight;
  }
  const weightedScore = totalWeight > 0 ? weightedSum / totalWeight : 0;

  await prisma.agent.update({
    where: { wallet: toWallet },
    data: {
      reputationScore: weightedScore,
      feedbackCount: allFeedback.length,
    },
  });

  return c.json({
    success: true,
    feedbackId: feedback.id,
    tradeId,
    message: fromIsVerified
      ? 'Trade feedback recorded with verified agent bonus (2× weight)'
      : 'Trade feedback recorded',
  });
});

// ──────────────────────────────────────────────
// GET /trade-feedback/message
// Helper: returns the message string a client must sign
// ──────────────────────────────────────────────

agentdexRoutes.get('/trade-feedback/message', (c) => {
  const { fromWallet, toWallet, tradeId, score } = c.req.query();

  if (!fromWallet || !toWallet || !tradeId || !score) {
    return c.json(
      { error: 'Query params required: fromWallet, toWallet, tradeId, score' },
      400,
    );
  }

  const timestamp = Date.now();
  const message = getTradeFeedbackMessage(fromWallet, toWallet, tradeId, parseInt(score), timestamp);

  return c.json({
    message,
    timestamp,
    instructions:
      'Sign this exact message with the fromWallet, then POST to /api/integrations/agentdex/trade-feedback',
  });
});
