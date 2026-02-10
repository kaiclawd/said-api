import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server';
import { PrismaClient } from '@prisma/client';
import { Connection, PublicKey } from '@solana/web3.js';
import { config } from 'dotenv';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import fs from 'fs/promises';
import { Resend } from 'resend';

// Verify a Solana wallet signature
function verifySignature(message: string, signature: string, walletAddress: string): boolean {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const signatureBytes = bs58.decode(signature);
    const publicKeyBytes = bs58.decode(walletAddress);
    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  } catch (e) {
    console.error('Signature verification error:', e);
    return false;
  }
}

// Generate the message that must be signed for feedback
function getFeedbackMessage(fromWallet: string, toWallet: string, score: number, timestamp: number): string {
  return `SAID:feedback:${toWallet}:${score}:${timestamp}`;
}

config();

const prisma = new PrismaClient();
const app = new Hono();
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// SAID Program constants
const SAID_PROGRAM_ID = new PublicKey('5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G');
const AGENT_ACCOUNT_SIZE = 263;

// RPC connection
const connection = new Connection(
  process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com',
  'confirmed'
);

// CORS
app.use('/*', cors({
  origin: [
    'https://www.saidprotocol.com',
    'https://saidprotocol.com',
    'http://localhost:3000',
    'https://devoted-cooperation-production-8f30.up.railway.app'
  ],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}));

// Health check
app.get('/', (c) => c.json({ status: 'ok', service: 'said-api', version: '1.0.0' }));
app.get('/health', (c) => c.json({ status: 'healthy' }));

// ============ AGENTS ============

// List agents with search/filter
app.get('/api/agents', async (c) => {
  const { search, skill, serviceType, verified, sort, limit, offset } = c.req.query();
  
  const where: any = {};
  
  if (search) {
    where.OR = [
      { name: { contains: search, mode: 'insensitive' } },
      { wallet: { contains: search, mode: 'insensitive' } },
      { description: { contains: search, mode: 'insensitive' } },
    ];
  }
  
  if (skill) {
    where.skills = { has: skill };
  }
  
  if (serviceType) {
    where.serviceTypes = { has: serviceType };
  }
  
  if (verified === 'true') {
    where.isVerified = true;
  }
  
  const orderBy: any = sort === 'newest' 
    ? { registeredAt: 'desc' }
    : sort === 'name'
    ? { name: 'asc' }
    : { reputationScore: 'desc' };
  
  const agents = await prisma.agent.findMany({
    where,
    orderBy,
    take: Math.min(parseInt(limit || '50'), 100),
    skip: parseInt(offset || '0'),
    include: {
      _count: { select: { feedbackReceived: true } }
    }
  });
  
  const total = await prisma.agent.count({ where });
  
  return c.json({ agents, total, limit: parseInt(limit || '50'), offset: parseInt(offset || '0') });
});

// Get single agent profile
app.get('/api/agents/:wallet', async (c) => {
  const wallet = c.req.param('wallet');
  
  const agent = await prisma.agent.findUnique({
    where: { wallet },
    include: {
      feedbackReceived: {
        orderBy: { createdAt: 'desc' },
        take: 10,
      },
      _count: { select: { feedbackReceived: true } }
    }
  });
  
  if (!agent) {
    return c.json({ error: 'Agent not found' }, 404);
  }
  
  return c.json(agent);
});

// Get agent feedback
app.get('/api/agents/:wallet/feedback', async (c) => {
  const wallet = c.req.param('wallet');
  const { limit, offset } = c.req.query();
  
  const feedback = await prisma.feedback.findMany({
    where: { toWallet: wallet },
    orderBy: { createdAt: 'desc' },
    take: Math.min(parseInt(limit || '20'), 50),
    skip: parseInt(offset || '0'),
  });
  
  const total = await prisma.feedback.count({ where: { toWallet: wallet } });
  
  return c.json({ feedback, total });
});

// Submit feedback
app.post('/api/agents/:wallet/feedback', async (c) => {
  const toWallet = c.req.param('wallet');
  const body = await c.req.json();
  const { fromWallet, score, comment, signature, timestamp, source } = body;
  // source is optional - identifies the platform (e.g., "agentdex", "superrouter", "w3rt")
  
  // Validate required fields
  if (!fromWallet || score === undefined || !signature || !timestamp) {
    return c.json({ error: 'Missing required fields: fromWallet, score, signature, timestamp' }, 400);
  }
  
  if (score < 0 || score > 100) {
    return c.json({ error: 'Score must be between 0 and 100' }, 400);
  }
  
  // Timestamp must be within last 5 minutes (prevent replay attacks)
  const now = Date.now();
  if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
    return c.json({ error: 'Timestamp too old. Sign a fresh message.' }, 400);
  }
  
  // Can't rate yourself
  if (fromWallet === toWallet) {
    return c.json({ error: 'Cannot rate yourself' }, 400);
  }
  
  // Check target agent exists
  const targetAgent = await prisma.agent.findUnique({ where: { wallet: toWallet } });
  if (!targetAgent) {
    return c.json({ error: 'Target agent not found' }, 404);
  }
  
  // Verify signature
  const message = getFeedbackMessage(fromWallet, toWallet, score, timestamp);
  const isValid = verifySignature(message, signature, fromWallet);
  
  if (!isValid) {
    return c.json({ error: 'Invalid signature. Make sure you signed the correct message.' }, 401);
  }
  
  // Check if fromWallet is a verified agent (for weighted scoring)
  const fromAgent = await prisma.agent.findUnique({ where: { wallet: fromWallet } });
  const fromIsVerified = fromAgent?.isVerified || false;
  
  // Weight: verified agents count 2x
  const weight = fromIsVerified ? 2.0 : 1.0;
  
  // Build comment with source prefix if provided
  const fullComment = source 
    ? `[${source}] ${comment || ''}`.trim()
    : comment;

  // Upsert feedback (one per fromWallet->toWallet pair)
  const feedback = await prisma.feedback.upsert({
    where: {
      fromWallet_toWallet: { fromWallet, toWallet }
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
    }
  });
  
  // Recalculate weighted reputation
  const allFeedback = await prisma.feedback.findMany({
    where: { toWallet },
    select: { score: true, weight: true }
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
    }
  });
  
  return c.json({ 
    success: true, 
    feedback,
    message: fromIsVerified 
      ? 'Feedback recorded with verified agent bonus (2x weight)' 
      : 'Feedback recorded'
  });
});

// Get message to sign for feedback
app.get('/api/agents/:wallet/feedback/message', async (c) => {
  const toWallet = c.req.param('wallet');
  const { fromWallet, score } = c.req.query();
  
  if (!fromWallet || !score) {
    return c.json({ error: 'Query params required: fromWallet, score' }, 400);
  }
  
  const timestamp = Date.now();
  const message = getFeedbackMessage(fromWallet, toWallet, parseInt(score), timestamp);
  
  return c.json({ 
    message,
    timestamp,
    instructions: 'Sign this exact message with your wallet, then POST to /api/agents/:wallet/feedback with { fromWallet, score, comment?, signature, timestamp }'
  });
});

// ============ TRUSTED SOURCE FEEDBACK ============

// Trusted sources (platforms that can submit feedback without user signatures)
const TRUSTED_SOURCES: Record<string, { name: string; weight: number }> = {
  'torch_sk_live_7f8a9b2c3d4e5f6a7b8c9d0e': { name: 'torch-market', weight: 1.5 },
  'solprism_sk_live_a1b2c3d4e5f6g7h8i9j0': { name: 'solprism', weight: 1.5 },
  'agentdex_sk_live_x1y2z3a4b5c6d7e8f9g0': { name: 'agentdex', weight: 1.2 },
};

// Event type to score mapping
const EVENT_SCORES: Record<string, number> = {
  'token_launch': 15,
  'trade_complete': 5,
  'governance_vote': 10,
  'reasoning_commit': 10,
  'successful_interaction': 8,
  'positive_review': 12,
  'negative_review': -10,
};

// Trusted source feedback endpoint (API key auth, no wallet signature required)
app.post('/api/sources/feedback', async (c) => {
  const apiKey = c.req.header('X-Source-Key');
  
  if (!apiKey || !TRUSTED_SOURCES[apiKey]) {
    return c.json({ error: 'Invalid or missing X-Source-Key header' }, 401);
  }
  
  const source = TRUSTED_SOURCES[apiKey];
  const body = await c.req.json();
  const { wallet, event, outcome, metadata } = body;
  
  // Validate required fields
  if (!wallet || !event) {
    return c.json({ error: 'Missing required fields: wallet, event' }, 400);
  }
  
  // Check agent exists
  const agent = await prisma.agent.findUnique({ where: { wallet } });
  if (!agent) {
    return c.json({ error: 'Agent not found. Must be registered on SAID first.' }, 404);
  }
  
  // Calculate score based on event type and outcome
  const baseScore = EVENT_SCORES[event] || 5;
  const outcomeMultiplier = outcome === 'failure' ? -0.5 : 1;
  const score = Math.round(baseScore * outcomeMultiplier * source.weight);
  
  // Create feedback record from trusted source
  // Use SAID System wallet as the source since foreign key requires valid agent
  const SYSTEM_WALLET = '72onvrQJZkPGLAhWK5MeYc73iyM72P2ABKzDMQ4NpQBL';
  
  try {
    const feedback = await prisma.feedback.create({
      data: {
        fromWallet: SYSTEM_WALLET,
        toWallet: wallet,
        score: Math.max(-100, Math.min(100, score)),
        weight: source.weight,
        comment: `[${source.name}] ${event}${outcome ? `: ${outcome}` : ''}${metadata?.details ? ` - ${metadata.details}` : ''}`,
        signature: `trusted:${source.name}:${Date.now()}`,
        fromIsVerified: true,
      }
    });
    
    // Recalculate reputation score
    const allFeedback = await prisma.feedback.findMany({
      where: { toWallet: wallet }
    });
    
    const totalWeight = allFeedback.reduce((sum, f) => sum + (f.weight || 1), 0);
    const weightedSum = allFeedback.reduce((sum, f) => sum + f.score * (f.weight || 1), 0);
    const newScore = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
    const clampedScore = Math.max(0, Math.min(100, newScore));
    
    // Determine trust tier
    const trustTier = clampedScore >= 70 ? 'high' : clampedScore >= 30 ? 'medium' : 'low';
    
    // Update agent
    await prisma.agent.update({
      where: { wallet },
      data: {
        reputationScore: clampedScore,
        feedbackCount: allFeedback.length,
      }
    });
    
    return c.json({
      success: true,
      source: source.name,
      event,
      scoreChange: score,
      newReputationScore: clampedScore,
      trustTier,
      feedbackId: feedback.id,
    });
  } catch (err: any) {
    console.error('Feedback creation error:', err);
    return c.json({ 
      error: 'Failed to create feedback', 
      details: err.message || 'Unknown error'
    }, 500);
  }
});

// Get available event types
app.get('/api/sources/events', (c) => {
  return c.json({
    events: Object.keys(EVENT_SCORES),
    scores: EVENT_SCORES,
  });
});

// ============ LEADERBOARD ============

app.get('/api/leaderboard', async (c) => {
  const { period, limit } = c.req.query();
  
  // Calculate date filter based on period
  let dateFilter: Date | null = null;
  if (period === 'weekly' || period === 'week') {
    dateFilter = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  } else if (period === 'monthly' || period === 'month') {
    dateFilter = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  } else if (period === 'daily' || period === 'day') {
    dateFilter = new Date(Date.now() - 24 * 60 * 60 * 1000);
  }
  
  if (dateFilter) {
    // For time-filtered leaderboard, calculate reputation from recent feedback only
    const recentFeedback = await prisma.feedback.groupBy({
      by: ['toWallet'],
      where: {
        createdAt: { gte: dateFilter }
      },
      _avg: { score: true },
      _count: { score: true },
      _sum: { weight: true },
    });
    
    // Get agent details for those with recent feedback
    const wallets = recentFeedback.map(f => f.toWallet);
    const agents = await prisma.agent.findMany({
      where: { wallet: { in: wallets } },
      select: {
        wallet: true,
        pda: true,
        name: true,
        twitter: true,
        isVerified: true,
      }
    });
    
    const agentMap = new Map(agents.map(a => [a.wallet, a]));
    
    // Calculate weighted scores for the period
    const leaderboard = recentFeedback
      .map(f => {
        const agent = agentMap.get(f.toWallet);
        if (!agent) return null;
        return {
          ...agent,
          periodScore: f._avg.score || 0,
          periodFeedbackCount: f._count.score,
        };
      })
      .filter(Boolean)
      .sort((a: any, b: any) => b.periodScore - a.periodScore)
      .slice(0, Math.min(parseInt(limit || '50'), 100))
      .map((a, i) => ({ ...a, rank: i + 1 }));
    
    return c.json({ 
      leaderboard,
      period: period || 'all',
      since: dateFilter.toISOString(),
    });
  }
  
  // Default: all-time leaderboard
  const agents = await prisma.agent.findMany({
    where: {
      feedbackCount: { gt: 0 }
    },
    orderBy: { reputationScore: 'desc' },
    take: Math.min(parseInt(limit || '50'), 100),
    select: {
      wallet: true,
      pda: true,
      name: true,
      twitter: true,
      reputationScore: true,
      feedbackCount: true,
      isVerified: true,
    }
  });
  
  return c.json({ 
    leaderboard: agents.map((a, i) => ({ ...a, rank: i + 1 })),
    period: period || 'all'
  });
});

// ============ REGISTRATION HELPER ============

// Helper endpoint to generate registration instructions
app.get('/api/register', (c) => {
  return c.json({
    instructions: 'Use npx said-register or follow the manual steps below',
    npxCommand: 'npx said-register --metadata https://your-domain.com/agent.json',
    manual: {
      step1: 'Create an AgentCard JSON file with your agent metadata',
      step2: 'Host it at a public URL',
      step3: 'Call the SAID program registerAgent instruction',
    },
    agentCardSchema: {
      name: 'Your Agent Name (required)',
      description: 'What your agent does (required)',
      version: '1.0.0',
      twitter: '@youragent',
      website: 'https://youragent.com',
      capabilities: ['coding', 'research', 'chat'],
      serviceTypes: ['assistant', 'automation'],
      mcpEndpoint: 'https://youragent.com/mcp (optional)',
      a2aEndpoint: 'https://youragent.com/a2a (optional)',
      x402Wallet: 'Your payment wallet (optional)',
    },
    programId: SAID_PROGRAM_ID.toString(),
    verificationFee: '0.01 SOL (optional, for verified badge)',
    docs: 'https://www.saidprotocol.com/skill.md',
  });
});

// ============ SPONSORED REGISTRATION ============
// Free registration - we pay the rent (first 100 agents)

// Rate limiting: track registrations per IP
const registrationRateLimit = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_WINDOW = 60 * 60 * 1000; // 1 hour
const RATE_LIMIT_MAX = 3; // 3 registrations per hour per IP

// Sponsorship pool: first 100 agents get free registration
const SPONSOR_POOL_MAX = 100;

// Sponsorship wallet (loaded from env)
const SPONSOR_PRIVATE_KEY = process.env.SPONSOR_PRIVATE_KEY;

/**
 * Get current sponsorship count from database
 */
async function getSponsorshipCount(): Promise<number> {
  const count = await prisma.agent.count({
    where: { sponsored: true }
  });
  return count;
}

/**
 * Check if sponsorship slots are available
 */
async function isSponsorshipAvailable(): Promise<{ available: boolean; remaining: number; used: number }> {
  const used = await getSponsorshipCount();
  const remaining = Math.max(0, SPONSOR_POOL_MAX - used);
  return {
    available: remaining > 0,
    remaining,
    used
  };
}

// Generate message for registration signature
function getRegistrationMessage(wallet: string, name: string, timestamp: number): string {
  return `SAID:register:${wallet}:${name}:${timestamp}`;
}

/**
 * POST /api/register/sponsored
 * Free registration - we pay the rent, user just signs
 */
app.post('/api/register/sponsored', async (c) => {
  // Rate limiting
  const clientIp = c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || 'unknown';
  const now = Date.now();
  const rateData = registrationRateLimit.get(clientIp);
  
  if (rateData) {
    if (now < rateData.resetAt) {
      if (rateData.count >= RATE_LIMIT_MAX) {
        return c.json({ 
          error: 'Rate limit exceeded. Max 3 registrations per hour.',
          retryAfter: Math.ceil((rateData.resetAt - now) / 1000)
        }, 429);
      }
      rateData.count++;
    } else {
      registrationRateLimit.set(clientIp, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    }
  } else {
    registrationRateLimit.set(clientIp, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
  }

  const body = await c.req.json();
  const { wallet, name, description, signature, timestamp, twitter, website, capabilities } = body;
  
  // Validate required fields
  if (!wallet || !name) {
    return c.json({ error: 'Required: wallet, name' }, 400);
  }
  
  // Check sponsorship availability
  const sponsorship = await isSponsorshipAvailable();
  if (!sponsorship.available) {
    return c.json({
      error: 'Sponsorship pool exhausted',
      message: `All ${SPONSOR_POOL_MAX} sponsored slots have been claimed. Registration now requires 0.005 SOL.`,
      slotsUsed: sponsorship.used,
      slotsTotal: SPONSOR_POOL_MAX,
      instructions: {
        step1: 'Fund your wallet with ~0.005 SOL',
        step2: 'Run: npx said-register --keypair wallet.json'
      }
    }, 410); // 410 Gone - resource no longer available
  }
  
  // Check if already registered
  const existing = await prisma.agent.findUnique({ where: { wallet } });
  if (existing) {
    return c.json({ 
      error: 'Wallet already registered',
      pda: existing.pda,
      profile: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`
    }, 409);
  }
  
  // Verify signature if provided (optional but recommended)
  if (signature && timestamp) {
    const message = getRegistrationMessage(wallet, name, timestamp);
    const isValid = verifySignature(message, signature, wallet);
    
    if (!isValid) {
      return c.json({ error: 'Invalid signature' }, 401);
    }
    
    // Timestamp must be within 10 minutes
    if (Math.abs(Date.now() - timestamp) > 10 * 60 * 1000) {
      return c.json({ error: 'Timestamp too old. Sign a fresh message.' }, 400);
    }
  }
  
  try {
    // Step 1: Create and store the agent card
    const card = {
      name,
      description: description || `${name} - AI Agent on SAID Protocol`,
      wallet,
      twitter: twitter || undefined,
      website: website || undefined,
      capabilities: capabilities || [],
      created: new Date().toISOString().split('T')[0],
      verified: false,
    };
    
    await prisma.agentCard.upsert({
      where: { wallet },
      create: { wallet, cardJson: JSON.stringify(card) },
      update: { cardJson: JSON.stringify(card), updatedAt: new Date() }
    });
    
    const metadataUri = `https://api.saidprotocol.com/api/cards/${wallet}.json`;
    
    // Step 2: Calculate PDA
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from('agent'), new PublicKey(wallet).toBuffer()],
      SAID_PROGRAM_ID
    );
    
    // Step 3: Check if we have sponsor key configured
    if (!SPONSOR_PRIVATE_KEY) {
      // No sponsor key - return instructions for manual registration
      return c.json({
        success: false,
        sponsored: false,
        message: 'Sponsorship not available. Manual registration required.',
        wallet,
        pda: pda.toString(),
        metadataUri,
        cardStored: true,
        instructions: {
          step1: 'Fund your wallet with ~0.005 SOL',
          step2: 'Run: npx said-register --keypair your-wallet.json',
        }
      });
    }
    
    // Step 4: Build and submit sponsored transaction
    // For now, we'll just store the card and return success
    // The actual on-chain registration will be handled by a separate process
    // that monitors pending registrations and submits them
    
    // Store sponsored registration
    await prisma.agent.create({
      data: {
        wallet,
        pda: pda.toString(),
        owner: wallet,
        metadataUri,
        registeredAt: new Date(),
        isVerified: false,
        sponsored: true,  // Mark as sponsored
        name: card.name,
        description: card.description,
        twitter: card.twitter,
        website: card.website,
        skills: card.capabilities,
      }
    });
    
    // Get remaining slots for response
    const remainingSlots = SPONSOR_POOL_MAX - (sponsorship.used + 1);
    
    return c.json({
      success: true,
      sponsored: true,
      message: 'Registration successful! Welcome to SAID Protocol.',
      wallet,
      pda: pda.toString(),
      metadataUri,
      profile: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
      badge: `https://api.saidprotocol.com/api/badge/${wallet}.svg`,
      slotsRemaining: remainingSlots,
    });
    
  } catch (error: any) {
    console.error('Sponsored registration error:', error);
    return c.json({ error: 'Registration failed: ' + error.message }, 500);
  }
});

/**
 * GET /api/register/sponsored/message
 * Get the message to sign for sponsored registration
 */
app.get('/api/register/sponsored/message', (c) => {
  const { wallet, name } = c.req.query();
  
  if (!wallet || !name) {
    return c.json({ error: 'Query params required: wallet, name' }, 400);
  }
  
  const timestamp = Date.now();
  const message = getRegistrationMessage(wallet, name, timestamp);
  
  return c.json({
    message,
    timestamp,
    instructions: 'Sign this message with your wallet, then POST to /api/register/sponsored'
  });
});

/**
 * GET /api/register/sponsored/status
 * Check sponsorship availability
 */
app.get('/api/register/sponsored/status', async (c) => {
  const sponsorship = await isSponsorshipAvailable();
  const totalRegistered = await prisma.agent.count();
  
  return c.json({
    available: sponsorship.available,
    slotsTotal: SPONSOR_POOL_MAX,
    slotsUsed: sponsorship.used,
    slotsRemaining: sponsorship.remaining,
    totalRegistered,
    message: sponsorship.available 
      ? `Free registration available! ${sponsorship.remaining} slots remaining.`
      : `Sponsorship pool exhausted. Registration now requires 0.005 SOL.`,
    cost: sponsorship.available ? 'FREE (sponsored)' : '0.005 SOL',
    verificationCost: '0.01 SOL (optional, for verified badge)'
  });
});

// ============ PENDING REGISTRATION (OFF-CHAIN, FREE) ============
/**
 * POST /api/register/pending
 * Register an agent off-chain (free, instant, no SOL required)
 * Status: PENDING - can upgrade to REGISTERED (on-chain) later
 */
app.post('/api/register/pending', async (c) => {
  const body = await c.req.json();
  const { wallet, name, description, twitter, website, capabilities } = body;
  
  // Validate required fields
  if (!wallet || !name) {
    return c.json({ error: 'Required: wallet, name' }, 400);
  }
  
  // Check if already registered
  const existing = await prisma.agent.findUnique({ where: { wallet } });
  if (existing) {
    return c.json({ 
      success: true,
      message: 'Already registered',
      wallet,
      pda: existing.pda,
      status: existing.isVerified ? 'VERIFIED' : (existing.sponsored ? 'REGISTERED' : 'PENDING'),
      profile: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`
    });
  }
  
  try {
    // Compute PDA (deterministic)
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from('agent'), new PublicKey(wallet).toBuffer()],
      SAID_PROGRAM_ID
    );
    
    // Build card
    const card = {
      name,
      description: description || `${name} - AI Agent on SAID Protocol`,
      wallet,
      twitter: twitter || undefined,
      website: website || undefined,
      capabilities: capabilities || ['chat', 'assistant'],
      status: 'PENDING',
      registeredAt: new Date().toISOString(),
    };
    
    const metadataUri = `https://api.saidprotocol.com/api/cards/${wallet}.json`;
    
    // Store card in database (for /api/cards/:wallet.json endpoint)
    await prisma.agentCard.upsert({
      where: { wallet },
      create: {
        wallet,
        cardJson: JSON.stringify(card),
      },
      update: {
        cardJson: JSON.stringify(card),
      }
    });
    
    // Store in database with PENDING status (not sponsored = off-chain only)
    await prisma.agent.create({
      data: {
        wallet,
        pda: pda.toString(),
        owner: wallet,
        metadataUri,
        registeredAt: new Date(),
        isVerified: false,
        sponsored: false,  // PENDING = not on-chain yet
        name: card.name,
        description: card.description,
        twitter: card.twitter,
        website: card.website,
        skills: card.capabilities,
      }
    });
    
    return c.json({
      success: true,
      message: 'Agent registered (PENDING). Upgrade to on-chain anytime.',
      wallet,
      pda: pda.toString(),
      status: 'PENDING',
      metadataUri,
      profile: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
      badge: `https://api.saidprotocol.com/api/badge/${wallet}.svg`,
      upgrade: {
        cost: '0.005 SOL',
        instructions: 'Fund wallet and run: npx said-anchor'
      }
    });
    
  } catch (error: any) {
    console.error('Pending registration error:', error);
    return c.json({ error: 'Registration failed: ' + error.message }, 500);
  }
});

// ============ CARD HOSTING ============
// Host agent cards for agents who don't have their own hosting

// Store a card (called by CLI during registration)
app.post('/api/cards', async (c) => {
  const body = await c.req.json();
  const { wallet, name, description, twitter, website, github, capabilities } = body;
  
  if (!wallet || !name) {
    return c.json({ error: 'Required: wallet, name' }, 400);
  }
  
  // Build card
  const card = {
    name,
    description: description || `${name} - AI Agent on SAID Protocol`,
    wallet,
    twitter: twitter || undefined,
    website: website || undefined,
    github: github || undefined,
    capabilities: capabilities || [],
    created: new Date().toISOString().split('T')[0],
    verified: false,
  };
  
  // Store in database (we'll serve it from /api/cards/:wallet.json)
  await prisma.agentCard.upsert({
    where: { wallet },
    create: {
      wallet,
      cardJson: JSON.stringify(card),
    },
    update: {
      cardJson: JSON.stringify(card),
      updatedAt: new Date(),
    }
  });
  
  const cardUri = `https://api.saidprotocol.com/api/cards/${wallet}.json`;
  
  return c.json({ 
    success: true, 
    cardUri,
    card,
  });
});

// Serve hosted cards (handle both with and without .json extension)
app.get('/api/cards/:wallet', async (c) => {
  const rawWallet = c.req.param('wallet') || '';
  const wallet = rawWallet.replace(/\.json$/, '');
  console.log('[Card GET] Raw param:', rawWallet, '| Cleaned wallet:', wallet);
  
  try {
    const stored = await prisma.agentCard.findUnique({
      where: { wallet }
    });
    console.log('[Card GET] Found:', stored ? 'YES' : 'NO');
    
    if (!stored) {
      return c.json({ error: 'Card not found' }, 404);
    }
  
    const card = JSON.parse(stored.cardJson);
    
    // Check if agent is now verified and update card
    const agent = await prisma.agent.findUnique({
      where: { wallet },
      select: { isVerified: true }
    });
    
    if (agent) {
      card.verified = agent.isVerified;
    }
    
    c.header('Content-Type', 'application/json');
    c.header('Cache-Control', 'public, max-age=60');
    return c.json(card);
  } catch (e: any) {
    console.error('[Card GET] Error:', e.message);
    return c.json({ error: 'Failed to fetch card' }, 500);
  }
});

// Generate transaction for registration (returns unsigned transaction)
app.post('/api/register/prepare', async (c) => {
  const body = await c.req.json();
  const { wallet, metadataUri } = body;
  
  if (!wallet || !metadataUri) {
    return c.json({ error: 'Required: wallet, metadataUri' }, 400);
  }
  
  // Validate metadata URI is reachable
  try {
    const res = await fetch(metadataUri);
    if (!res.ok) {
      return c.json({ error: `Metadata URI not reachable: ${res.status}` }, 400);
    }
    const card = await res.json();
    if (!card.name) {
      return c.json({ error: 'AgentCard must have a name field' }, 400);
    }
  } catch (e) {
    return c.json({ error: 'Failed to fetch metadata URI. Make sure it\'s publicly accessible.' }, 400);
  }
  
  // Return PDA and instructions for client-side transaction building
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from('agent'), new PublicKey(wallet).toBuffer()],
    SAID_PROGRAM_ID
  );
  
  return c.json({
    success: true,
    pda: pda.toString(),
    instruction: {
      programId: SAID_PROGRAM_ID.toString(),
      method: 'registerAgent',
      args: { metadataUri },
      accounts: [
        { name: 'agent', pubkey: pda.toString(), isSigner: false, isWritable: true },
        { name: 'owner', pubkey: wallet, isSigner: true, isWritable: true },
        { name: 'systemProgram', pubkey: '11111111111111111111111111111111', isSigner: false, isWritable: false },
      ]
    },
    message: 'Build and sign this transaction client-side, then submit to Solana.',
  });
});

// ============ SVG BADGE ============

function generateBadgeSvg(agent: { name: string; isVerified: boolean; reputationScore: number; wallet: string }, style: string = 'default'): string {
  const name = agent.name || 'Agent';
  const score = Math.round(agent.reputationScore);
  const shortWallet = agent.wallet.slice(0, 4) + '...' + agent.wallet.slice(-4);
  
  if (style === 'minimal') {
    // Minimal shield-style badge
    return `<svg xmlns="http://www.w3.org/2000/svg" width="120" height="28" viewBox="0 0 120 28">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#1a1a1a"/>
      <stop offset="100%" style="stop-color:#2a2a2a"/>
    </linearGradient>
  </defs>
  <rect width="120" height="28" rx="4" fill="url(#bg)"/>
  <text x="8" y="18" fill="#fff" font-family="system-ui,-apple-system,sans-serif" font-size="11" font-weight="600">SAID</text>
  <rect x="42" y="0" width="1" height="28" fill="#444"/>
  <text x="50" y="18" fill="${agent.isVerified ? '#22c55e' : '#888'}" font-family="system-ui,-apple-system,sans-serif" font-size="11" font-weight="500">${agent.isVerified ? '✓ Verified' : 'Registered'}</text>
</svg>`;
  }
  
  if (style === 'score') {
    // Badge with reputation score
    const scoreColor = score >= 70 ? '#22c55e' : score >= 40 ? '#f59e0b' : '#888';
    return `<svg xmlns="http://www.w3.org/2000/svg" width="160" height="28" viewBox="0 0 160 28">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#1a1a1a"/>
      <stop offset="100%" style="stop-color:#2a2a2a"/>
    </linearGradient>
  </defs>
  <rect width="160" height="28" rx="4" fill="url(#bg)"/>
  <text x="8" y="18" fill="#fff" font-family="system-ui,-apple-system,sans-serif" font-size="11" font-weight="600">SAID</text>
  <rect x="42" y="0" width="1" height="28" fill="#444"/>
  <text x="50" y="18" fill="${agent.isVerified ? '#22c55e' : '#888'}" font-family="system-ui,-apple-system,sans-serif" font-size="11">${agent.isVerified ? '✓' : '○'}</text>
  <rect x="65" y="0" width="1" height="28" fill="#444"/>
  <text x="73" y="18" fill="${scoreColor}" font-family="system-ui,-apple-system,sans-serif" font-size="11" font-weight="600">${score}/100</text>
  <rect x="115" y="0" width="1" height="28" fill="#444"/>
  <text x="123" y="18" fill="#666" font-family="monospace" font-size="9">${shortWallet}</text>
</svg>`;
  }
  
  // Default: Full badge with name
  return `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="56" viewBox="0 0 220 56">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#1a1a1a"/>
      <stop offset="100%" style="stop-color:#0a0a0a"/>
    </linearGradient>
    <linearGradient id="accent" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:${agent.isVerified ? '#22c55e' : '#666'}"/>
      <stop offset="100%" style="stop-color:${agent.isVerified ? '#16a34a' : '#555'}"/>
    </linearGradient>
  </defs>
  <rect width="220" height="56" rx="8" fill="url(#bg)" stroke="#333" stroke-width="1"/>
  <rect x="0" y="0" width="4" height="56" rx="2" fill="url(#accent)"/>
  <text x="16" y="24" fill="#fff" font-family="system-ui,-apple-system,sans-serif" font-size="14" font-weight="700">${escapeXml(name.slice(0, 20))}</text>
  <text x="16" y="42" fill="#888" font-family="monospace" font-size="10">${shortWallet}</text>
  <g transform="translate(170, 12)">
    <rect width="40" height="18" rx="4" fill="${agent.isVerified ? '#22c55e' : '#333'}"/>
    <text x="20" y="13" fill="${agent.isVerified ? '#fff' : '#888'}" font-family="system-ui,-apple-system,sans-serif" font-size="9" font-weight="600" text-anchor="middle">${agent.isVerified ? 'VERIFIED' : 'REG'}</text>
  </g>
  <text x="170" y="46" fill="#666" font-family="system-ui,-apple-system,sans-serif" font-size="9">SAID Protocol</text>
</svg>`;
}

function escapeXml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// SVG badge endpoint
app.get('/api/badge/:wallet.svg', async (c) => {
  const wallet = (c.req.param('wallet') || '').replace('.svg', '');
  const style = c.req.query('style') || 'default';
  
  const agent = await prisma.agent.findUnique({
    where: { wallet },
    select: { name: true, wallet: true, isVerified: true, reputationScore: true }
  });
  
  if (!agent) {
    // Return a "not found" badge
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="120" height="28" viewBox="0 0 120 28">
  <rect width="120" height="28" rx="4" fill="#1a1a1a"/>
  <text x="60" y="18" fill="#666" font-family="system-ui,-apple-system,sans-serif" font-size="11" text-anchor="middle">Not Found</text>
</svg>`;
    c.header('Content-Type', 'image/svg+xml');
    c.header('Cache-Control', 'public, max-age=300');
    return c.body(svg);
  }
  
  const svg = generateBadgeSvg({
    ...agent,
    name: agent.name || 'Agent'
  }, style);
  c.header('Content-Type', 'image/svg+xml');
  c.header('Cache-Control', 'public, max-age=300');
  return c.body(svg);
});

// Badge info endpoint (for embedding instructions)
app.get('/api/badge/:wallet', async (c) => {
  const wallet = c.req.param('wallet');
  
  const agent = await prisma.agent.findUnique({
    where: { wallet },
    select: { name: true, wallet: true, pda: true, isVerified: true, reputationScore: true }
  });
  
  if (!agent) {
    return c.json({ error: 'Agent not found' }, 404);
  }
  
  const baseUrl = 'https://api.saidprotocol.com';
  const profileUrl = `https://www.saidprotocol.com/agent.html?wallet=${wallet}`;
  
  return c.json({
    agent: {
      name: agent.name,
      wallet: agent.wallet,
      isVerified: agent.isVerified,
      reputationScore: agent.reputationScore,
    },
    badges: {
      default: `${baseUrl}/api/badge/${wallet}.svg`,
      minimal: `${baseUrl}/api/badge/${wallet}.svg?style=minimal`,
      score: `${baseUrl}/api/badge/${wallet}.svg?style=score`,
    },
    embed: {
      markdown: `[![SAID ${agent.isVerified ? 'Verified' : 'Registered'}](${baseUrl}/api/badge/${wallet}.svg)](${profileUrl})`,
      html: `<a href="${profileUrl}"><img src="${baseUrl}/api/badge/${wallet}.svg" alt="SAID ${agent.isVerified ? 'Verified' : 'Registered'}"></a>`,
    },
    profileUrl,
  });
});

// ============ STATS ============

app.get('/api/stats', async (c) => {
  const [total, verified, avgReputation] = await Promise.all([
    prisma.agent.count(),
    prisma.agent.count({ where: { isVerified: true } }),
    prisma.agent.aggregate({ _avg: { reputationScore: true } }),
  ]);
  
  return c.json({
    totalAgents: total,
    verifiedAgents: verified,
    averageReputation: avgReputation._avg.reputationScore || 0,
  });
});

// ============ INTEGRATION ENDPOINTS ============
// Generic endpoints for any platform to verify agents and submit feedback

/**
 * GET /api/verify/:wallet
 * Quick verification endpoint for integrating platforms.
 * Returns identity, reputation, trust tier, and useful URLs.
 */
app.get('/api/verify/:wallet', async (c) => {
  const wallet = c.req.param('wallet');
  const include = c.req.query('include'); // ?include=payments

  const agent = await prisma.agent.findUnique({
    where: { wallet },
    include: {
      _count: { select: { feedbackReceived: true } },
    },
  });

  if (!agent) {
    return c.json({
      verified: false,
      registered: false,
      wallet,
      error: 'Agent not registered in SAID Protocol',
    }, 404);
  }

  // Compute trust tier for easy gating decisions
  const trustTier =
    agent.isVerified && agent.reputationScore >= 70
      ? 'high'
      : agent.isVerified || agent.reputationScore >= 40
        ? 'medium'
        : 'low';

  return c.json({
    registered: true,
    verified: agent.isVerified,
    wallet: agent.wallet,
    pda: agent.pda,
    identity: {
      name: agent.name,
      description: agent.description,
      twitter: agent.twitter,
      website: agent.website,
      image: agent.image,
    },
    reputation: {
      score: agent.reputationScore,
      feedbackCount: agent._count.feedbackReceived,
      trustTier,
    },
    endpoints: {
      mcp: agent.mcpEndpoint ?? null,
      a2a: agent.a2aEndpoint ?? null,
    },
    serviceTypes: agent.serviceTypes,
    skills: agent.skills,
    registeredAt: agent.registeredAt.toISOString(),
    urls: {
      profile: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
      badge: `https://api.saidprotocol.com/api/badge/${wallet}.svg`,
      badgeWithScore: `https://api.saidprotocol.com/api/badge/${wallet}.svg?style=score`,
    },
    // Include payments if requested
    ...(include === 'payments' && {
      payments: {
        x402: {
          enabled: !!agent.x402Wallet,
          solana: agent.x402Wallet || agent.wallet,
          evm: null,
        },
      },
    }),
  });
});

/**
 * GET /api/agents/:wallet/payments
 * Get payment configuration for an agent (x402, etc.)
 */
app.get('/api/agents/:wallet/payments', async (c) => {
  const wallet = c.req.param('wallet');

  const agent = await prisma.agent.findUnique({
    where: { wallet },
    select: { wallet: true, x402Wallet: true, name: true, isVerified: true },
  });

  if (!agent) {
    return c.json({ error: 'Agent not found' }, 404);
  }

  return c.json({
    wallet: agent.wallet,
    name: agent.name,
    payments: {
      x402: {
        enabled: !!agent.x402Wallet,
        solana: agent.x402Wallet || agent.wallet, // Default to main wallet if no x402 set
        evm: null, // Future: add EVM address support
      },
    },
  });
});

/**
 * GET /api/trust/:wallet
 * Minimal trust check - returns just the trust tier.
 * Use for quick gating decisions.
 */
app.get('/api/trust/:wallet', async (c) => {
  const wallet = c.req.param('wallet');

  const agent = await prisma.agent.findUnique({
    where: { wallet },
    select: { isVerified: true, reputationScore: true },
  });

  if (!agent) {
    return c.json({ wallet, trustTier: 'none', registered: false });
  }

  const trustTier =
    agent.isVerified && agent.reputationScore >= 70
      ? 'high'
      : agent.isVerified || agent.reputationScore >= 40
        ? 'medium'
        : 'low';

  return c.json({ wallet, trustTier, registered: true, verified: agent.isVerified });
});

// ============ ATTESTATIONS ============

// Generate message for attestation signature
function getAttestationMessage(attesterWallet: string, subjectWallet: string, type: string, confidence: number, timestamp: number): string {
  return `SAID:attest:${subjectWallet}:${type}:${confidence}:${timestamp}`;
}

/**
 * POST /api/attest
 * Create an attestation (agent vouching for another agent)
 */
app.post('/api/attest', async (c) => {
  const body = await c.req.json();
  const { attesterWallet, subjectWallet, type, confidence, context, skill, signature, timestamp } = body;
  
  // Validate required fields
  if (!attesterWallet || !subjectWallet) {
    return c.json({ error: 'Required: attesterWallet, subjectWallet' }, 400);
  }
  
  // Can't attest yourself
  if (attesterWallet === subjectWallet) {
    return c.json({ error: 'Cannot attest yourself' }, 400);
  }
  
  const attestationType = type || 'trust';
  const attestationConfidence = Math.min(100, Math.max(1, confidence || 50));
  
  // Check both agents exist
  const [attester, subject] = await Promise.all([
    prisma.agent.findUnique({ where: { wallet: attesterWallet } }),
    prisma.agent.findUnique({ where: { wallet: subjectWallet } }),
  ]);
  
  if (!attester) {
    return c.json({ error: 'Attester not registered in SAID' }, 404);
  }
  if (!subject) {
    return c.json({ error: 'Subject not registered in SAID' }, 404);
  }
  
  // If signature provided, verify it
  if (signature && timestamp) {
    const message = getAttestationMessage(attesterWallet, subjectWallet, attestationType, attestationConfidence, timestamp);
    const isValid = verifySignature(message, signature, attesterWallet);
    
    if (!isValid) {
      return c.json({ error: 'Invalid signature' }, 401);
    }
    
    // Timestamp must be within 5 minutes
    if (Math.abs(Date.now() - timestamp) > 5 * 60 * 1000) {
      return c.json({ error: 'Timestamp too old' }, 400);
    }
  }
  
  // Create or update attestation
  const attestation = await prisma.attestation.upsert({
    where: {
      attesterWallet_subjectWallet_type: {
        attesterWallet,
        subjectWallet,
        type: attestationType,
      }
    },
    create: {
      attesterWallet,
      subjectWallet,
      type: attestationType,
      confidence: attestationConfidence,
      context,
      skill: attestationType === 'skill' ? skill : null,
      signature,
    },
    update: {
      confidence: attestationConfidence,
      context,
      skill: attestationType === 'skill' ? skill : null,
      signature,
      revokedAt: null, // Un-revoke if previously revoked
      updatedAt: new Date(),
    }
  });
  
  // Recalculate subject's trust score based on attestations
  await recalculateTrustScore(subjectWallet);
  
  return c.json({
    success: true,
    attestation: {
      id: attestation.id,
      attester: attester.name || attesterWallet,
      subject: subject.name || subjectWallet,
      type: attestation.type,
      confidence: attestation.confidence,
      context: attestation.context,
    },
    message: `Attestation recorded: ${attester.name || 'Agent'} vouches for ${subject.name || 'Agent'}`,
  });
});

/**
 * GET /api/attestations/:wallet
 * Get attestations received by an agent
 */
app.get('/api/attestations/:wallet', async (c) => {
  const wallet = c.req.param('wallet');
  const { type, limit, offset } = c.req.query();
  
  const where: any = { 
    subjectWallet: wallet,
    revokedAt: null,
  };
  if (type) where.type = type;
  
  const attestations = await prisma.attestation.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: Math.min(parseInt(limit || '50'), 100),
    skip: parseInt(offset || '0'),
    include: {
      attester: {
        select: { wallet: true, name: true, isVerified: true, reputationScore: true }
      }
    }
  });
  
  const total = await prisma.attestation.count({ where });
  
  // Calculate trust score from attestations
  const trustFromAttestations = attestations.reduce((sum, a) => {
    const weight = a.attester.isVerified ? 2 : 1;
    const attesterRepWeight = (a.attester.reputationScore || 50) / 100;
    return sum + (a.confidence * weight * attesterRepWeight * 0.1);
  }, 0);
  
  return c.json({
    wallet,
    attestations: attestations.map(a => ({
      id: a.id,
      attester: {
        wallet: a.attester.wallet,
        name: a.attester.name,
        isVerified: a.attester.isVerified,
        reputationScore: a.attester.reputationScore,
      },
      type: a.type,
      confidence: a.confidence,
      context: a.context,
      skill: a.skill,
      createdAt: a.createdAt,
    })),
    total,
    trustFromAttestations: Math.round(trustFromAttestations),
  });
});

/**
 * GET /api/attestations/:wallet/given
 * Get attestations given by an agent
 */
app.get('/api/attestations/:wallet/given', async (c) => {
  const wallet = c.req.param('wallet');
  const { type, limit, offset } = c.req.query();
  
  const where: any = { 
    attesterWallet: wallet,
    revokedAt: null,
  };
  if (type) where.type = type;
  
  const attestations = await prisma.attestation.findMany({
    where,
    orderBy: { createdAt: 'desc' },
    take: Math.min(parseInt(limit || '50'), 100),
    skip: parseInt(offset || '0'),
    include: {
      subject: {
        select: { wallet: true, name: true, isVerified: true }
      }
    }
  });
  
  const total = await prisma.attestation.count({ where });
  
  return c.json({
    wallet,
    attestationsGiven: attestations.map(a => ({
      id: a.id,
      subject: {
        wallet: a.subject.wallet,
        name: a.subject.name,
        isVerified: a.subject.isVerified,
      },
      type: a.type,
      confidence: a.confidence,
      context: a.context,
      skill: a.skill,
      createdAt: a.createdAt,
    })),
    total,
  });
});

/**
 * DELETE /api/attestations/:id
 * Revoke an attestation (soft delete)
 */
app.delete('/api/attestations/:id', async (c) => {
  const id = c.req.param('id');
  const body = await c.req.json().catch(() => ({}));
  const { wallet, signature, timestamp } = body;
  
  const attestation = await prisma.attestation.findUnique({ where: { id } });
  
  if (!attestation) {
    return c.json({ error: 'Attestation not found' }, 404);
  }
  
  // Only attester can revoke
  if (wallet !== attestation.attesterWallet) {
    return c.json({ error: 'Only the attester can revoke' }, 403);
  }
  
  // Verify signature if provided
  if (signature && timestamp) {
    const message = `SAID:revoke:${id}:${timestamp}`;
    const isValid = verifySignature(message, signature, wallet);
    if (!isValid) {
      return c.json({ error: 'Invalid signature' }, 401);
    }
  }
  
  // Soft delete
  await prisma.attestation.update({
    where: { id },
    data: { revokedAt: new Date() }
  });
  
  // Recalculate subject's trust score
  await recalculateTrustScore(attestation.subjectWallet);
  
  return c.json({ success: true, message: 'Attestation revoked' });
});

/**
 * GET /api/trust-graph/:wallet
 * Get the web of trust around an agent
 */
app.get('/api/trust-graph/:wallet', async (c) => {
  const wallet = c.req.param('wallet');
  const depth = Math.min(parseInt(c.req.query('depth') || '1'), 2);
  
  const agent = await prisma.agent.findUnique({ 
    where: { wallet },
    select: { wallet: true, name: true, isVerified: true, reputationScore: true }
  });
  
  if (!agent) {
    return c.json({ error: 'Agent not found' }, 404);
  }
  
  // Get attestations received (who trusts this agent)
  const trustedBy = await prisma.attestation.findMany({
    where: { subjectWallet: wallet, revokedAt: null },
    include: {
      attester: {
        select: { wallet: true, name: true, isVerified: true, reputationScore: true }
      }
    }
  });
  
  // Get attestations given (who this agent trusts)
  const trusts = await prisma.attestation.findMany({
    where: { attesterWallet: wallet, revokedAt: null },
    include: {
      subject: {
        select: { wallet: true, name: true, isVerified: true, reputationScore: true }
      }
    }
  });
  
  // Build graph nodes and edges
  const nodes: any[] = [{ 
    id: wallet, 
    name: agent.name || wallet.slice(0, 8), 
    isVerified: agent.isVerified,
    reputationScore: agent.reputationScore,
    isCenter: true 
  }];
  
  const edges: any[] = [];
  const seenWallets = new Set([wallet]);
  
  for (const a of trustedBy) {
    if (!seenWallets.has(a.attester.wallet)) {
      nodes.push({
        id: a.attester.wallet,
        name: a.attester.name || a.attester.wallet.slice(0, 8),
        isVerified: a.attester.isVerified,
        reputationScore: a.attester.reputationScore,
      });
      seenWallets.add(a.attester.wallet);
    }
    edges.push({
      from: a.attester.wallet,
      to: wallet,
      type: a.type,
      confidence: a.confidence,
    });
  }
  
  for (const a of trusts) {
    if (!seenWallets.has(a.subject.wallet)) {
      nodes.push({
        id: a.subject.wallet,
        name: a.subject.name || a.subject.wallet.slice(0, 8),
        isVerified: a.subject.isVerified,
        reputationScore: a.subject.reputationScore,
      });
      seenWallets.add(a.subject.wallet);
    }
    edges.push({
      from: wallet,
      to: a.subject.wallet,
      type: a.type,
      confidence: a.confidence,
    });
  }
  
  return c.json({
    center: wallet,
    nodes,
    edges,
    stats: {
      trustedByCount: trustedBy.length,
      trustsCount: trusts.length,
    }
  });
});

/**
 * GET /api/attest/message
 * Get the message to sign for an attestation
 */
app.get('/api/attest/message', (c) => {
  const { attesterWallet, subjectWallet, type, confidence } = c.req.query();
  
  if (!attesterWallet || !subjectWallet) {
    return c.json({ error: 'Query params required: attesterWallet, subjectWallet' }, 400);
  }
  
  const timestamp = Date.now();
  const attestationType = type || 'trust';
  const attestationConfidence = parseInt(confidence || '50');
  const message = getAttestationMessage(attesterWallet, subjectWallet, attestationType, attestationConfidence, timestamp);
  
  return c.json({
    message,
    timestamp,
    instructions: 'Sign this message with your wallet, then POST to /api/attest with { attesterWallet, subjectWallet, type, confidence, context?, signature, timestamp }',
  });
});

/**
 * Recalculate trust score for an agent based on feedback + attestations
 */
async function recalculateTrustScore(wallet: string) {
  // Get feedback
  const feedback = await prisma.feedback.findMany({
    where: { toWallet: wallet },
    select: { score: true, weight: true }
  });
  
  // Get attestations
  const attestations = await prisma.attestation.findMany({
    where: { subjectWallet: wallet, revokedAt: null },
    include: {
      attester: {
        select: { isVerified: true, reputationScore: true }
      }
    }
  });
  
  // Calculate weighted feedback score
  let feedbackWeight = 0;
  let feedbackSum = 0;
  for (const f of feedback) {
    feedbackSum += f.score * (f.weight || 1);
    feedbackWeight += f.weight || 1;
  }
  
  // Calculate attestation bonus
  // Higher trust attesters and higher confidence = more weight
  let attestationBonus = 0;
  for (const a of attestations) {
    const attesterWeight = a.attester.isVerified ? 2 : 1;
    const attesterRepWeight = (a.attester.reputationScore || 50) / 100;
    attestationBonus += (a.confidence * attesterWeight * attesterRepWeight * 0.1);
  }
  
  // Combine: base from feedback + bonus from attestations
  const baseScore = feedbackWeight > 0 ? feedbackSum / feedbackWeight : 50;
  const finalScore = Math.min(100, Math.max(0, baseScore + attestationBonus));
  
  await prisma.agent.update({
    where: { wallet },
    data: {
      reputationScore: finalScore,
      feedbackCount: feedback.length,
    }
  });
  
  return finalScore;
}

// ============ AUTH ============

// Generate session token
function generateSessionToken(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Verify user session
async function verifySession(authHeader: string | undefined): Promise<any> {
  if (!authHeader?.startsWith('Bearer ')) return null;
  const token = authHeader.substring(7);
  
  const user = await prisma.user.findUnique({
    where: { sessionToken: token },
  });
  
  if (!user || !user.sessionExpiry || user.sessionExpiry < new Date()) {
    return null;
  }
  
  return user;
}

// POST /auth/login-wallet
app.post('/auth/login-wallet', async (c) => {
  try {
    const { walletAddress, signature, message } = await c.req.json();
    
    if (!walletAddress) {
      return c.json({ error: 'walletAddress required' }, 400);
    }
    
    // TODO: Verify signature (for now, trust the wallet address)
    // In production: verify the signature matches the message signed by the wallet
    
    // Find or create user
    let user = await prisma.user.findUnique({
      where: { walletAddress }
    });
    
    if (!user) {
      user = await prisma.user.create({
        data: {
          walletAddress,
          lastLoginAt: new Date(),
        }
      });
    } else {
      user = await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginAt: new Date() }
      });
    }
    
    // Generate session token (valid for 30 days)
    const sessionToken = generateSessionToken();
    const sessionExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    
    await prisma.user.update({
      where: { id: user.id },
      data: { sessionToken, sessionExpiry }
    });
    
    return c.json({
      ok: true,
      user: {
        id: user.id,
        walletAddress: user.walletAddress,
        displayName: user.displayName,
      },
      sessionToken,
      expiresAt: sessionExpiry.toISOString(),
    });
  } catch (e: any) {
    console.error('Login error:', e);
    return c.json({ error: e.message }, 500);
  }
});

// POST /auth/login-privy
app.post('/auth/login-privy', async (c) => {
  try {
    const { privyId, email, walletAddress, displayName } = await c.req.json();
    
    if (!privyId) {
      return c.json({ error: 'privyId required' }, 400);
    }
    
    // Find or create user by Privy ID
    let user = await prisma.user.findUnique({
      where: { privyId }
    });
    
    if (!user) {
      user = await prisma.user.create({
        data: {
          privyId,
          email,
          walletAddress,
          displayName,
          lastLoginAt: new Date(),
        }
      });
    } else {
      // Update user info on login
      user = await prisma.user.update({
        where: { id: user.id },
        data: { 
          email: email || user.email,
          walletAddress: walletAddress || user.walletAddress,
          displayName: displayName || user.displayName,
          lastLoginAt: new Date() 
        }
      });
    }
    
    // Generate session token (valid for 30 days)
    const sessionToken = generateSessionToken();
    const sessionExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    
    await prisma.user.update({
      where: { id: user.id },
      data: { sessionToken, sessionExpiry }
    });
    
    return c.json({
      ok: true,
      user: {
        id: user.id,
        privyId: user.privyId,
        walletAddress: user.walletAddress,
        email: user.email,
        displayName: user.displayName,
      },
      sessionToken,
      expiresAt: sessionExpiry.toISOString(),
    });
  } catch (e: any) {
    console.error('Privy login error:', e);
    return c.json({ error: e.message }, 500);
  }
});

// GET /auth/me
app.get('/auth/me', async (c) => {
  const user = await verifySession(c.req.header('Authorization'));
  
  if (!user) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  return c.json({
    ok: true,
    user: {
      id: user.id,
      walletAddress: user.walletAddress,
      email: user.email,
      displayName: user.displayName,
      createdAt: user.createdAt,
    }
  });
});

// PATCH /auth/me - Update user profile
app.patch('/auth/me', async (c) => {
  const user = await verifySession(c.req.header('Authorization'));
  
  if (!user) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  try {
    const body = await c.req.json();
    const { displayName } = body;
    
    // Update user in database
    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: {
        displayName: displayName || user.displayName,
      },
    });
    
    return c.json({
      ok: true,
      user: {
        id: updatedUser.id,
        walletAddress: updatedUser.walletAddress,
        email: updatedUser.email,
        displayName: updatedUser.displayName,
        createdAt: updatedUser.createdAt,
      }
    });
  } catch (e: any) {
    console.error('Update profile error:', e);
    return c.json({ error: e.message }, 500);
  }
});

// GET /users/me/agents
app.get('/users/me/agents', async (c) => {
  const user = await verifySession(c.req.header('Authorization'));
  
  if (!user) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  const userAgents = await prisma.userAgent.findMany({
    where: { userId: user.id },
    include: {
      agent: true,
    },
    orderBy: { createdAt: 'desc' },
  });
  
  return c.json({
    ok: true,
    agents: userAgents.map(ua => ua.agent),
  });
});

// POST /users/me/agents
app.post('/users/me/agents', async (c) => {
  const user = await verifySession(c.req.header('Authorization'));
  
  if (!user) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  
  try {
    const { agentWallet } = await c.req.json();
    
    if (!agentWallet) {
      return c.json({ error: 'agentWallet required' }, 400);
    }
    
    // Check if agent exists
    const agent = await prisma.agent.findUnique({
      where: { wallet: agentWallet }
    });
    
    if (!agent) {
      return c.json({ error: 'Agent not found' }, 404);
    }
    
    // Link agent to user (idempotent)
    await prisma.userAgent.upsert({
      where: {
        userId_agentWallet: {
          userId: user.id,
          agentWallet: agentWallet,
        }
      },
      create: {
        userId: user.id,
        agentWallet: agentWallet,
      },
      update: {}, // No-op if already linked
    });
    
    return c.json({ ok: true });
  } catch (e: any) {
    console.error('Link agent error:', e);
    return c.json({ error: e.message }, 500);
  }
});

// ============ SYNC (internal) ============

async function syncAgentsFromChain() {
  console.log('Syncing agents from chain...');
  
  try {
    const accounts = await connection.getProgramAccounts(SAID_PROGRAM_ID, {
      filters: [{ dataSize: AGENT_ACCOUNT_SIZE }]
    });
    
    for (const { pubkey, account } of accounts) {
      try {
      const data = account.data;
      
      // Parse on-chain data
      const owner = new PublicKey(data.subarray(8, 40)).toString();
      const uriLength = data.readUInt32LE(40);
      const metadataUri = data.subarray(44, 44 + uriLength).toString('utf8');
      const offset = 44 + uriLength;
      
      // Parse timestamps with validation (chain stores unix seconds)
      const rawRegisteredAt = Number(data.readBigInt64LE(offset));
      const rawVerifiedAt = Number(data.readBigInt64LE(offset + 9));
      const isVerified = data[offset + 8] === 1;
      
      // Validate timestamps are reasonable (between 2020 and 2100)
      const minTs = 1577836800; // 2020-01-01
      const maxTs = 4102444800; // 2100-01-01
      const registeredAt = (rawRegisteredAt > minTs && rawRegisteredAt < maxTs) ? rawRegisteredAt : Math.floor(Date.now() / 1000);
      const verifiedAt = (rawVerifiedAt > minTs && rawVerifiedAt < maxTs) ? rawVerifiedAt : 0;
      
      // Fetch metadata card
      let card: any = {};
      try {
        let uri = metadataUri;
        // Fix www prefix only for main site, not api subdomain
        if (uri.includes('://saidprotocol.com') || uri.includes('://www.saidprotocol.com')) {
          uri = uri.replace('://saidprotocol.com', '://www.saidprotocol.com');
        }
        // api.saidprotocol.com should remain unchanged
        const res = await fetch(uri);
        if (res.ok) {
          const text = await res.text();
          // Only parse as JSON if it looks like JSON (not HTML)
          if (text.trim().startsWith('{')) {
            card = JSON.parse(text);
          }
        }
      } catch (e) {
        console.log(`Failed to fetch card for ${owner}: ${e}`);
      }
      
      // Upsert agent
      await prisma.agent.upsert({
        where: { pda: pubkey.toString() },
        create: {
          wallet: owner,
          pda: pubkey.toString(),
          owner,
          metadataUri,
          registeredAt: new Date(registeredAt * 1000),
          isVerified,
          verifiedAt: verifiedAt > 0 ? new Date(verifiedAt * 1000) : null,
          name: card.name,
          description: card.description,
          twitter: card.twitter,
          image: card.image,
          website: card.website,
          mcpEndpoint: card.mcpEndpoint,
          a2aEndpoint: card.a2aEndpoint,
          x402Wallet: card.x402Wallet,
          serviceTypes: card.serviceTypes || [],
          skills: card.capabilities || card.skills || [],
        },
        update: {
          metadataUri,
          isVerified,
          verifiedAt: verifiedAt > 0 ? new Date(verifiedAt * 1000) : null,
          name: card.name,
          description: card.description,
          twitter: card.twitter,
          image: card.image,
          website: card.website,
          mcpEndpoint: card.mcpEndpoint,
          a2aEndpoint: card.a2aEndpoint,
          x402Wallet: card.x402Wallet,
          serviceTypes: card.serviceTypes || [],
          skills: card.capabilities || card.skills || [],
          lastSyncedAt: new Date(),
        }
      });
      } catch (e) {
        console.error(`Failed to sync agent ${pubkey.toString()}:`, e);
      }
    }
    
    console.log(`Synced ${accounts.length} agents`);
  } catch (e) {
    console.error('Sync error:', e);
  }
}

// ============ START ============

const port = parseInt(process.env.PORT || '3001');

// Sync on startup, then every 5 minutes
syncAgentsFromChain();
setInterval(syncAgentsFromChain, 5 * 60 * 1000);

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`SAID API running on http://localhost:${info.port}`);
});
// Rebuild trigger Tue Feb  3 17:46:45 UTC 2026
