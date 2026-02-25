import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server';
import { PrismaClient } from '@prisma/client';
import { Connection, PublicKey, Transaction, SystemProgram, LAMPORTS_PER_SOL, Keypair } from '@solana/web3.js';
import {
  TOKEN_2022_PROGRAM_ID,
  createInitializeMintInstruction,
  createInitializeNonTransferableMintInstruction,
  createInitializeMetadataPointerInstruction,
  createAssociatedTokenAccountInstruction,
  createMintToInstruction,
  getAssociatedTokenAddressSync,
  getMintLen,
  ExtensionType,
  TYPE_SIZE,
  LENGTH_SIZE,
} from '@solana/spl-token';
import {
  createInitializeInstruction,
  createUpdateFieldInstruction,
  pack,
  TokenMetadata,
} from '@solana/spl-token-metadata';
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
    'https://devoted-cooperation-production-8f30.up.railway.app',
    'https://staging-v2-production.up.railway.app'
  ],
  allowMethods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
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
// API keys loaded from environment variables for security
const TRUSTED_SOURCES: Record<string, { name: string; weight: number }> = {};

// Load trusted source keys from environment variables
if (process.env.TORCH_API_KEY) {
  TRUSTED_SOURCES[process.env.TORCH_API_KEY] = { name: 'torch-market', weight: 1.5 };
}
if (process.env.SOLPRISM_API_KEY) {
  TRUSTED_SOURCES[process.env.SOLPRISM_API_KEY] = { name: 'solprism', weight: 1.5 };
}
if (process.env.AGENTDEX_API_KEY) {
  TRUSTED_SOURCES[process.env.AGENTDEX_API_KEY] = { name: 'agentdex', weight: 1.2 };
}

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
  
  // Verify signature (REQUIRED for security)
  if (!signature || !timestamp) {
    return c.json({ error: 'Signature and timestamp are required for registration' }, 400);
  }
  
  const message = getRegistrationMessage(wallet, name, timestamp);
  const isValid = verifySignature(message, signature, wallet);
  
  if (!isValid) {
    return c.json({ error: 'Invalid signature' }, 401);
  }
  
  // Timestamp must be within 10 minutes
  if (Math.abs(Date.now() - timestamp) > 10 * 60 * 1000) {
    return c.json({ error: 'Timestamp too old. Sign a fresh message.' }, 400);
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
  const { wallet, name, description, twitter, website, capabilities, source } = body;
  
  // Validate required fields
  if (!wallet || !name) {
    return c.json({ error: 'Required: wallet, name' }, 400);
  }

  // Determine if this source qualifies for auto L2 framework attestation
  const FRAMEWORK_SOURCES = ['eliza', 'swarms', 'conway', 'sdk', 'cli'];
  const registrationSource = source || 'website';
  const isFrameworkAttestation = FRAMEWORK_SOURCES.includes(registrationSource.toLowerCase());
  
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
        registrationSource,
        // Auto L2 attest framework registrations
        ...(isFrameworkAttestation && {
          layer2Verified: true,
          layer2VerifiedAt: new Date(),
          l2AttestationMethod: 'framework',
        }),
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
      layer2Verified: isFrameworkAttestation,
      l2AttestationMethod: isFrameworkAttestation ? 'framework' : null,
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

// ============ PLATFORM-SPECIFIC INTEGRATIONS ============

/**
 * SPAWNR.IO INTEGRATION ENDPOINTS
 * 
 * All endpoints require authentication via X-Platform-Key header (except badge embed)
 * 
 * Available endpoints:
 * - POST   /api/platforms/spawnr/register       - Register new agent with instant verification
 * - PUT    /api/platforms/spawnr/agents/:wallet - Update agent metadata
 * - GET    /api/platforms/spawnr/agents         - List all Spawnr agents (paginated)
 * - GET    /api/platforms/spawnr/stats          - Platform statistics
 * - POST   /api/platforms/spawnr/webhooks       - Register webhook for events
 * - GET    /api/badge/embed/:wallet             - Public badge embed (no auth required)
 */

/**
 * POST /api/platforms/spawnr/register
 * Spawnr.io platform integration - instant verified registration
 * 
 * Authentication: X-Platform-Key header (Spawnr's API key)
 * 
 * All agents created on Spawnr.io are automatically:
 * - Registered on SAID
 * - Verified (we eat the 0.01 SOL cost)
 * - Given full SAID identity
 * 
 * No user signature required - Spawnr authenticates via API key
 */
/**
 * POST /api/platforms/spawnr/register
 * Step 1: Build on-chain registration + verification transaction
 * Returns a serialized transaction for the agent wallet to sign
 * 
 * Flow:
 *   1. Spawnr calls this endpoint with agent wallet + metadata
 *   2. We build a transaction with register_agent + get_verified instructions
 *   3. Sponsor wallet pays all fees (rent + 0.01 SOL verification)
 *   4. Return serialized tx (base64) — agent wallet must sign
 *   5. Spawnr signs with agent keypair, calls /confirm to broadcast
 */
app.post('/api/platforms/spawnr/register', async (c) => {
  // Validate Spawnr API key
  const apiKey = c.req.header('X-Platform-Key');
  const expectedKey = process.env['SPAWNR_PLATFORM_KEY'];
  
  if (!expectedKey) {
    return c.json({ 
      error: 'Spawnr integration not configured. Contact SAID team.',
      support: 'contact@saidprotocol.com'
    }, 500);
  }
  
  if (!apiKey || apiKey !== expectedKey) {
    return c.json({ 
      error: 'Invalid or missing X-Platform-Key header',
      instructions: 'Include your Spawnr API key in X-Platform-Key header'
    }, 401);
  }
  
  const body = await c.req.json();
  const { wallet, name, description, twitter, website, capabilities } = body;
  
  // Validate required fields
  if (!wallet || !name) {
    return c.json({ error: 'Required fields: wallet, name' }, 400);
  }

  // Validate wallet format
  let agentPubkey: PublicKey;
  try {
    agentPubkey = new PublicKey(wallet);
  } catch {
    return c.json({ error: 'Invalid wallet address' }, 400);
  }
  
  // Check if already registered on-chain
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from('agent'), agentPubkey.toBuffer()],
    SAID_PROGRAM_ID
  );
  
  const existingOnChain = await connection.getAccountInfo(pda);
  if (existingOnChain) {
    // Already on-chain — check DB and return
    const existing = await prisma.agent.findUnique({ where: { wallet } });
    return c.json({
      success: true,
      message: 'Agent already registered on-chain',
      agent: {
        wallet,
        pda: pda.toString(),
        name: existing?.name || name,
        verified: true,
        profile: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
        badge: `https://api.saidprotocol.com/api/badge/${wallet}.svg`,
      }
    });
  }
  
  // Check sponsor wallet
  const sponsorKey = process.env['SPAWNR_SPONSOR_PRIVATE_KEY'];
  if (!sponsorKey) {
    return c.json({ 
      error: 'Spawnr sponsor wallet not configured. Contact SAID team.',
      support: 'contact@saidprotocol.com'
    }, 500);
  }
  
  try {
    const sponsorKeypair = Keypair.fromSecretKey(bs58.decode(sponsorKey));
    
    // Store agent card first (needed for metadata_uri)
    const card = {
      name,
      description: description || `${name} - AI Agent`,
      wallet,
      twitter: twitter || undefined,
      website: website || undefined,
      capabilities: capabilities || ['chat', 'assistant'],
      platform: 'spawnr.io',
      verified: true,
      registeredAt: new Date().toISOString(),
    };
    
    const metadataUri = `https://api.saidprotocol.com/api/cards/${wallet}.json`;
    
    await prisma.agentCard.upsert({
      where: { wallet },
      create: { wallet, cardJson: JSON.stringify(card) },
      update: { cardJson: JSON.stringify(card) },
    });
    
    // Treasury PDA
    const [treasuryPda] = PublicKey.findProgramAddressSync(
      [Buffer.from('treasury')],
      SAID_PROGRAM_ID
    );
    
    // === Build register_agent instruction ===
    // Anchor discriminator: sha256("global:register_agent")[0..8]
    const registerDiscriminator = Buffer.from([135, 157, 66, 195, 2, 113, 175, 30]);
    // Borsh-encode metadata_uri string (4-byte little-endian length + utf8 bytes)
    const uriBytes = Buffer.from(metadataUri, 'utf8');
    const uriLen = Buffer.alloc(4);
    uriLen.writeUInt32LE(uriBytes.length);
    const registerData = Buffer.concat([registerDiscriminator, uriLen, uriBytes]);
    
    const registerIx = {
      programId: SAID_PROGRAM_ID,
      keys: [
        { pubkey: pda, isSigner: false, isWritable: true },           // agent_identity (init)
        { pubkey: agentPubkey, isSigner: true, isWritable: true },    // owner (signer + payer)
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // system_program
      ],
      data: registerData,
    };
    
    // === Build get_verified instruction ===
    // Anchor discriminator: sha256("global:get_verified")[0..8]
    const verifyDiscriminator = Buffer.from([132, 231, 2, 30, 115, 74, 23, 26]);
    
    const verifyIx = {
      programId: SAID_PROGRAM_ID,
      keys: [
        { pubkey: pda, isSigner: false, isWritable: true },           // agent_identity
        { pubkey: treasuryPda, isSigner: false, isWritable: true },   // treasury
        { pubkey: agentPubkey, isSigner: true, isWritable: true },    // authority (signer + payer of fee)
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // system_program
      ],
      data: verifyDiscriminator,
    };
    
    // === Build funding transfer: sponsor → agent wallet ===
    // Agent needs SOL for: PDA rent (~0.003 SOL) + verification fee (0.01 SOL) + tx fees
    const FUND_AMOUNT = 0.015 * LAMPORTS_PER_SOL; // 0.015 SOL buffer
    
    const fundIx = SystemProgram.transfer({
      fromPubkey: sponsorKeypair.publicKey,
      toPubkey: agentPubkey,
      lamports: FUND_AMOUNT,
    });
    
    // Build transaction: fund → register → verify
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
    
    const tx = new Transaction({
      blockhash,
      lastValidBlockHeight,
      feePayer: sponsorKeypair.publicKey,  // Sponsor pays tx fees
    });
    
    tx.add(fundIx);      // 1. Fund agent wallet
    tx.add(registerIx);  // 2. Register on-chain
    tx.add(verifyIx);    // 3. Get verified badge
    
    // Sponsor signs (fee payer + fund transfer)
    tx.partialSign(sponsorKeypair);
    
    // Serialize — agent wallet still needs to sign
    const serializedTx = tx.serialize({
      requireAllSignatures: false,
      verifySignatures: false,
    }).toString('base64');
    
    return c.json({
      success: true,
      message: 'Transaction built. Agent wallet must sign and return via /confirm endpoint.',
      transaction: serializedTx,
      blockhash,
      lastValidBlockHeight,
      requiredSigner: wallet,
      pda: pda.toString(),
      metadataUri,
      instructions: {
        step1: 'Deserialize the base64 transaction',
        step2: `Sign with the agent wallet (${wallet})`,
        step3: 'POST the signed transaction to /api/platforms/spawnr/confirm',
      },
      expiresIn: '~60 seconds (blockhash expiry)',
    });
    
  } catch (error: any) {
    console.error('[Spawnr Register Error]', error);
    return c.json({ 
      error: 'Failed to build transaction',
      details: error.message,
      support: 'contact@saidprotocol.com'
    }, 500);
  }
});

/**
 * POST /api/platforms/spawnr/confirm
 * Step 2: Receive signed transaction, broadcast on-chain, update DB
 * 
 * Spawnr signs the transaction from Step 1 with the agent's keypair,
 * then sends it here. We broadcast, confirm, and update our database.
 */
app.post('/api/platforms/spawnr/confirm', async (c) => {
  // Validate Spawnr API key
  const apiKey = c.req.header('X-Platform-Key');
  const expectedKey = process.env['SPAWNR_PLATFORM_KEY'];
  
  if (!expectedKey || !apiKey || apiKey !== expectedKey) {
    return c.json({ error: 'Invalid or missing X-Platform-Key header' }, 401);
  }
  
  const body = await c.req.json();
  const { signedTransaction, wallet, name, description, twitter, website, capabilities } = body;
  
  if (!signedTransaction || !wallet) {
    return c.json({ error: 'Required: signedTransaction (base64), wallet' }, 400);
  }
  
  try {
    // Deserialize and broadcast
    const txBuffer = Buffer.from(signedTransaction, 'base64');
    const tx = Transaction.from(txBuffer);
    
    // Verify the transaction has the expected signers
    const agentPubkey = new PublicKey(wallet);
    const signers = tx.signatures.map(s => s.publicKey.toBase58());
    if (!signers.includes(wallet)) {
      return c.json({ error: 'Transaction must be signed by the agent wallet' }, 400);
    }
    
    // Broadcast
    const rawTx = tx.serialize();
    const txHash = await connection.sendRawTransaction(rawTx, {
      skipPreflight: false,
      preflightCommitment: 'confirmed',
    });
    
    // Confirm
    const confirmation = await connection.confirmTransaction({
      signature: txHash,
      blockhash: tx.recentBlockhash!,
      lastValidBlockHeight: tx.lastValidBlockHeight!,
    }, 'confirmed');
    
    if (confirmation.value.err) {
      return c.json({ 
        error: 'Transaction failed on-chain',
        txHash,
        details: JSON.stringify(confirmation.value.err),
      }, 500);
    }
    
    // Success! Update database
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from('agent'), agentPubkey.toBuffer()],
      SAID_PROGRAM_ID
    );
    
    const metadataUri = `https://api.saidprotocol.com/api/cards/${wallet}.json`;
    
    // Upsert agent in DB (might exist from a previous partial attempt)
    const agent = await prisma.agent.upsert({
      where: { wallet },
      create: {
        wallet,
        pda: pda.toString(),
        owner: wallet,
        metadataUri,
        registeredAt: new Date(),
        isVerified: true,
        verifiedAt: new Date(),
        sponsored: true,
        name: name || 'Spawnr Agent',
        description: description || 'AI Agent via Spawnr',
        twitter: twitter || undefined,
        website: website || undefined,
        skills: capabilities || ['chat', 'assistant'],
        registrationSource: 'spawnr',
        layer2Verified: true,
        layer2VerifiedAt: new Date(),
        l2AttestationMethod: 'platform',
      },
      update: {
        isVerified: true,
        verifiedAt: new Date(),
        sponsored: true,
        registrationSource: 'spawnr',
        layer2Verified: true,
        layer2VerifiedAt: new Date(),
      },
    });
    
    return c.json({
      success: true,
      message: 'Agent registered and verified ON-CHAIN via Spawnr',
      txHash,
      explorer: `https://solscan.io/tx/${txHash}`,
      agent: {
        wallet: agent.wallet,
        pda: agent.pda,
        name: agent.name,
        verified: true,
        onChain: true,
        profile: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
        badge: `https://api.saidprotocol.com/api/badge/${wallet}.svg`,
        badgeWithScore: `https://api.saidprotocol.com/api/badge/${wallet}.svg?style=score`,
      },
      platform: {
        name: 'spawnr.io',
        costCovered: '~0.015 SOL (rent + verification + fees)',
        sponsoredBy: 'SAID Protocol',
      }
    });
    
  } catch (error: any) {
    console.error('[Spawnr Confirm Error]', error);
    return c.json({ 
      error: 'Broadcast failed',
      details: error.message,
      support: 'contact@saidprotocol.com'
    }, 500);
  }
});

/**
 * PUT /api/platforms/spawnr/agents/:wallet
 * Update agent metadata for Spawnr-registered agents
 * 
 * Authentication: X-Platform-Key header required
 */
app.put('/api/platforms/spawnr/agents/:wallet', async (c) => {
  // Validate Spawnr API key
  const apiKey = c.req.header('X-Platform-Key');
  const expectedKey = process.env['SPAWNR_PLATFORM_KEY'];
  
  if (!expectedKey) {
    return c.json({ 
      error: 'Spawnr integration not configured',
      support: 'contact@saidprotocol.com'
    }, 500);
  }
  
  if (!apiKey || apiKey !== expectedKey) {
    return c.json({ 
      error: 'Invalid or missing X-Platform-Key header'
    }, 401);
  }
  
  const wallet = c.req.param('wallet');
  const body = await c.req.json();
  const { name, description, twitter, website, capabilities, image } = body;
  
  try {
    // Find agent and verify it's from Spawnr
    const agent = await prisma.agent.findUnique({ where: { wallet } });
    
    if (!agent) {
      return c.json({ error: 'Agent not found' }, 404);
    }
    
    if (agent.registrationSource !== 'spawnr') {
      return c.json({ 
        error: 'Agent not registered via Spawnr',
        registrationSource: agent.registrationSource 
      }, 403);
    }
    
    // Update agent
    const updated = await prisma.agent.update({
      where: { wallet },
      data: {
        name: name !== undefined ? name : agent.name,
        description: description !== undefined ? description : agent.description,
        twitter: twitter !== undefined ? twitter : agent.twitter,
        website: website !== undefined ? website : agent.website,
        skills: capabilities !== undefined ? capabilities : agent.skills,
        image: image !== undefined ? image : agent.image,
        updatedAt: new Date(),
      }
    });
    
    // Update agent card if exists
    const existingCard = await prisma.agentCard.findUnique({ where: { wallet } });
    if (existingCard) {
      const cardData = JSON.parse(existingCard.cardJson);
      const updatedCard = {
        ...cardData,
        name: name !== undefined ? name : cardData.name,
        description: description !== undefined ? description : cardData.description,
        twitter: twitter !== undefined ? twitter : cardData.twitter,
        website: website !== undefined ? website : cardData.website,
        capabilities: capabilities !== undefined ? capabilities : cardData.capabilities,
      };
      
      await prisma.agentCard.update({
        where: { wallet },
        data: {
          cardJson: JSON.stringify(updatedCard),
          updatedAt: new Date(),
        }
      });
    }
    
    return c.json({
      success: true,
      agent: {
        wallet: updated.wallet,
        name: updated.name,
        description: updated.description,
        twitter: updated.twitter,
        website: updated.website,
        capabilities: updated.skills,
        image: updated.image,
        verified: updated.isVerified,
        layer2Verified: updated.layer2Verified,
        reputationScore: updated.reputationScore,
        updatedAt: updated.updatedAt,
      }
    });
    
  } catch (error: any) {
    console.error('[Spawnr Update Error]', error);
    return c.json({ 
      error: 'Update failed',
      details: error.message
    }, 500);
  }
});

/**
 * GET /api/platforms/spawnr/stats
 * Platform statistics for Spawnr
 * 
 * Authentication: X-Platform-Key header required
 */
app.get('/api/platforms/spawnr/stats', async (c) => {
  // Validate Spawnr API key
  const apiKey = c.req.header('X-Platform-Key');
  const expectedKey = process.env['SPAWNR_PLATFORM_KEY'];
  
  if (!expectedKey) {
    return c.json({ 
      error: 'Spawnr integration not configured',
      support: 'contact@saidprotocol.com'
    }, 500);
  }
  
  if (!apiKey || apiKey !== expectedKey) {
    return c.json({ 
      error: 'Invalid or missing X-Platform-Key header'
    }, 401);
  }
  
  try {
    // Get all Spawnr agents
    const spawnrAgents = await prisma.agent.findMany({
      where: { registrationSource: 'spawnr' }
    });
    
    const totalAgents = spawnrAgents.length;
    const totalVerified = spawnrAgents.filter(a => a.isVerified).length;
    const totalLayer2 = spawnrAgents.filter(a => a.layer2Verified).length;
    
    // Calculate average reputation score
    const avgReputation = totalAgents > 0
      ? spawnrAgents.reduce((sum, a) => sum + a.reputationScore, 0) / totalAgents
      : 0;
    
    // Get top 5 agents by reputation
    const topAgents = spawnrAgents
      .sort((a, b) => b.reputationScore - a.reputationScore)
      .slice(0, 5)
      .map(a => ({
        wallet: a.wallet,
        name: a.name,
        reputationScore: a.reputationScore,
        verified: a.isVerified,
        layer2Verified: a.layer2Verified,
      }));
    
    return c.json({
      success: true,
      stats: {
        totalAgents,
        totalVerified,
        totalLayer2,
        averageReputation: Math.round(avgReputation * 100) / 100,
        topAgents,
      },
      platform: 'spawnr.io',
    });
    
  } catch (error: any) {
    console.error('[Spawnr Stats Error]', error);
    return c.json({ 
      error: 'Failed to fetch stats',
      details: error.message
    }, 500);
  }
});

/**
 * GET /api/platforms/spawnr/agents
 * List all Spawnr-registered agents (paginated)
 * 
 * Authentication: X-Platform-Key header required
 * Query params: ?limit=N&offset=N
 */
app.get('/api/platforms/spawnr/agents', async (c) => {
  // Validate Spawnr API key
  const apiKey = c.req.header('X-Platform-Key');
  const expectedKey = process.env['SPAWNR_PLATFORM_KEY'];
  
  if (!expectedKey) {
    return c.json({ 
      error: 'Spawnr integration not configured',
      support: 'contact@saidprotocol.com'
    }, 500);
  }
  
  if (!apiKey || apiKey !== expectedKey) {
    return c.json({ 
      error: 'Invalid or missing X-Platform-Key header'
    }, 401);
  }
  
  try {
    // Parse query params
    const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
    const offset = parseInt(c.req.query('offset') || '0');
    
    // Get agents
    const agents = await prisma.agent.findMany({
      where: { registrationSource: 'spawnr' },
      take: limit,
      skip: offset,
      orderBy: { registeredAt: 'desc' },
    });
    
    // Get total count
    const total = await prisma.agent.count({
      where: { registrationSource: 'spawnr' }
    });
    
    return c.json({
      success: true,
      agents: agents.map(a => ({
        wallet: a.wallet,
        name: a.name,
        verified: a.isVerified,
        layer2Verified: a.layer2Verified,
        reputationScore: a.reputationScore,
        registeredAt: a.registeredAt,
      })),
      pagination: {
        total,
        limit,
        offset,
        hasMore: offset + limit < total,
      }
    });
    
  } catch (error: any) {
    console.error('[Spawnr List Error]', error);
    return c.json({ 
      error: 'Failed to fetch agents',
      details: error.message
    }, 500);
  }
});

/**
 * GET /api/badge/embed/:wallet
 * Public embeddable badge - NO AUTH REQUIRED
 * 
 * Returns HTML with inline CSS for iframe embedding
 */
app.get('/api/badge/embed/:wallet', async (c) => {
  const wallet = c.req.param('wallet');
  
  try {
    const agent = await prisma.agent.findUnique({ where: { wallet } });
    
    if (!agent) {
      // Return "Not Found" badge
      const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SAID Badge</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: transparent;
      padding: 16px;
    }
    .badge {
      background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
      border: 2px solid #404040;
      border-radius: 12px;
      padding: 20px;
      max-width: 400px;
      color: #fff;
    }
    .header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }
    .logo {
      width: 40px;
      height: 40px;
      background: #404040;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: bold;
      font-size: 18px;
    }
    .title {
      font-size: 18px;
      font-weight: 600;
    }
    .status {
      display: inline-block;
      padding: 4px 12px;
      background: #404040;
      color: #999;
      border-radius: 6px;
      font-size: 14px;
      margin-top: 8px;
    }
    .footer {
      margin-top: 12px;
      font-size: 12px;
      color: #888;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="badge">
    <div class="header">
      <div class="logo">S</div>
      <div class="title">Agent Not Found</div>
    </div>
    <div class="status">⚠️ Not Registered</div>
    <div class="footer">Powered by SAID Protocol</div>
  </div>
</body>
</html>`;
      return c.html(html);
    }
    
    // Return verified/not verified badge
    const isVerified = agent.isVerified;
    const statusColor = isVerified ? '#10b981' : '#6b7280';
    const statusBg = isVerified ? '#10b98120' : '#6b728020';
    const statusText = isVerified ? '✓ SAID Verified' : 'Not Verified';
    
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SAID Badge - ${agent.name || wallet.slice(0, 8)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: transparent;
      padding: 16px;
    }
    .badge {
      background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
      border: 2px solid ${isVerified ? statusColor : '#404040'};
      border-radius: 12px;
      padding: 20px;
      max-width: 400px;
      color: #fff;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }
    .header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }
    .logo {
      width: 40px;
      height: 40px;
      background: ${isVerified ? statusColor : '#404040'};
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: bold;
      font-size: 18px;
    }
    .info {
      flex: 1;
    }
    .name {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 4px;
    }
    .wallet {
      font-size: 12px;
      color: #888;
      font-family: monospace;
    }
    .status {
      display: inline-block;
      padding: 6px 12px;
      background: ${statusBg};
      color: ${statusColor};
      border: 1px solid ${statusColor};
      border-radius: 6px;
      font-size: 14px;
      font-weight: 600;
      margin-top: 12px;
    }
    .reputation {
      margin-top: 12px;
      padding: 12px;
      background: #ffffff08;
      border-radius: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .rep-label {
      font-size: 13px;
      color: #aaa;
    }
    .rep-score {
      font-size: 20px;
      font-weight: 700;
      color: ${statusColor};
    }
    .footer {
      margin-top: 12px;
      font-size: 12px;
      color: #888;
      text-align: center;
    }
    .footer a {
      color: ${statusColor};
      text-decoration: none;
    }
  </style>
</head>
<body>
  <div class="badge">
    <div class="header">
      <div class="logo">${isVerified ? '✓' : 'S'}</div>
      <div class="info">
        <div class="name">${agent.name || 'Agent'}</div>
        <div class="wallet">${wallet.slice(0, 4)}...${wallet.slice(-4)}</div>
      </div>
    </div>
    <div class="status">${statusText}</div>
    <div class="reputation">
      <div class="rep-label">Reputation Score</div>
      <div class="rep-score">${Math.round(agent.reputationScore)}</div>
    </div>
    <div class="footer">
      Powered by <a href="https://www.saidprotocol.com" target="_blank">SAID Protocol</a>
    </div>
  </div>
</body>
</html>`;
    
    return c.html(html);
    
  } catch (error: any) {
    console.error('[Badge Embed Error]', error);
    const html = `<!DOCTYPE html>
<html><body style="font-family: sans-serif; padding: 20px; color: #666;">
Error loading badge. Please try again later.
</body></html>`;
    return c.html(html, 500);
  }
});

/**
 * POST /api/platforms/spawnr/webhooks
 * Register webhook URL for event notifications
 * 
 * Authentication: X-Platform-Key header required
 * Body: { url: string, events: string[] }
 * Events: ["reputation_change", "verification_complete"]
 */
app.post('/api/platforms/spawnr/webhooks', async (c) => {
  // Validate Spawnr API key
  const apiKey = c.req.header('X-Platform-Key');
  const expectedKey = process.env['SPAWNR_PLATFORM_KEY'];
  
  if (!expectedKey) {
    return c.json({ 
      error: 'Spawnr integration not configured',
      support: 'contact@saidprotocol.com'
    }, 500);
  }
  
  if (!apiKey || apiKey !== expectedKey) {
    return c.json({ 
      error: 'Invalid or missing X-Platform-Key header'
    }, 401);
  }
  
  const body = await c.req.json();
  const { url, events } = body;
  
  // Validate input
  if (!url || !events || !Array.isArray(events)) {
    return c.json({ 
      error: 'Required fields: url (string), events (array)',
      example: {
        url: 'https://spawnr.io/webhooks/said',
        events: ['reputation_change', 'verification_complete']
      }
    }, 400);
  }
  
  // Validate URL format
  try {
    new URL(url);
  } catch {
    return c.json({ error: 'Invalid URL format' }, 400);
  }
  
  // Validate events
  const validEvents = ['reputation_change', 'verification_complete'];
  const invalidEvents = events.filter(e => !validEvents.includes(e));
  if (invalidEvents.length > 0) {
    return c.json({ 
      error: 'Invalid event types',
      invalid: invalidEvents,
      valid: validEvents
    }, 400);
  }
  
  try {
    // Store webhook config
    const webhook = await prisma.webhookConfig.create({
      data: {
        platform: 'spawnr',
        url,
        events,
        active: true,
      }
    });
    
    return c.json({
      success: true,
      webhook: {
        id: webhook.id,
        url: webhook.url,
        events: webhook.events,
        active: webhook.active,
        createdAt: webhook.createdAt,
      },
      note: 'Webhook dispatching will be implemented soon. For now, the URL is stored and ready.'
    });
    
  } catch (error: any) {
    console.error('[Spawnr Webhook Error]', error);
    return c.json({ 
      error: 'Failed to register webhook',
      details: error.message
    }, 500);
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

// ============ LAYER 2 VERIFICATION ============

/**
 * GET /api/verify/layer2/challenge/:wallet?endpoint=<url>
 * Generate a challenge nonce for Layer 2 agent verification.
 * Agent must sign the nonce with their wallet private key.
 */
app.get('/api/verify/layer2/challenge/:wallet', async (c) => {
  const wallet = c.req.param('wallet');
  const endpointUrl = c.req.query('endpoint');
  if (!endpointUrl) return c.json({ error: 'endpoint query param required' }, 400);

  const agent = await prisma.agent.findUnique({ where: { wallet } });
  if (!agent) return c.json({ error: 'Agent not found' }, 404);
  if (!agent.isVerified) return c.json({ error: 'Layer 1 verification required first' }, 403);
  if (agent.layer2Verified) return c.json({ error: 'Already Layer 2 verified', layer2Verified: true }, 400);

  const crypto = await import('crypto');
  const nonce = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  const challenge = await prisma.agentChallenge.create({
    data: { wallet, nonce, endpointUrl, expiresAt },
  });

  return c.json({
    challengeId: challenge.id,
    nonce,
    expiresAt,
    wallet,
    endpointUrl,
    instructions: 'Sign the nonce string with your agent wallet private key using Ed25519, encode as base58, then POST to /api/verify/layer2/verify with { challengeId, signature }',
  });
});

/**
 * POST /api/verify/layer2/verify
 * Complete Layer 2 verification by submitting signed challenge.
 * Body: { challengeId, signature } where signature is base58-encoded Ed25519 sig of nonce
 */
app.post('/api/verify/layer2/verify', async (c) => {
  const { challengeId, signature } = await c.req.json();
  if (!challengeId || !signature) return c.json({ error: 'challengeId and signature required' }, 400);

  const challenge = await prisma.agentChallenge.findUnique({ where: { id: challengeId } });
  if (!challenge) return c.json({ error: 'Challenge not found' }, 404);
  if (challenge.verified) return c.json({ error: 'Challenge already used' }, 400);
  if (new Date() > challenge.expiresAt) return c.json({ error: 'Challenge expired' }, 400);

  const agent = await prisma.agent.findUnique({ where: { wallet: challenge.wallet } });
  if (!agent) return c.json({ error: 'Agent not found' }, 404);

  // Verify Ed25519 signature: agent signed the nonce with their wallet key
  const nonceBytes = new TextEncoder().encode(challenge.nonce);
  let signatureBytes: Uint8Array;
  let publicKeyBytes: Uint8Array;
  try {
    signatureBytes = bs58.decode(signature);
    publicKeyBytes = bs58.decode(challenge.wallet);
  } catch {
    return c.json({ error: 'Invalid signature or wallet encoding' }, 400);
  }

  const valid = nacl.sign.detached.verify(nonceBytes, signatureBytes, publicKeyBytes);
  if (!valid) return c.json({ error: 'Signature verification failed' }, 401);

  // Mark verified
  await prisma.agentChallenge.update({ where: { id: challengeId }, data: { verified: true, verifiedAt: new Date() } });
  await prisma.agent.update({
    where: { wallet: challenge.wallet },
    data: { layer2Verified: true, layer2VerifiedAt: new Date(), verifiedEndpointUrl: challenge.endpointUrl, l2AttestationMethod: 'endpoint' },
  });

  return c.json({ ok: true, wallet: challenge.wallet, message: 'Layer 2 verification complete. Agent endpoint verified.', l2AttestationMethod: 'endpoint' });
});

/**
 * GET /api/verify/layer2/status/:wallet
 */
app.get('/api/verify/layer2/status/:wallet', async (c) => {
  const wallet = c.req.param('wallet');
  const agent = await prisma.agent.findUnique({ where: { wallet } });
  if (!agent) return c.json({ error: 'Agent not found' }, 404);

  // Check activity-based L2 eligibility (30+ days old, 50+ activity)
  const ageMs = Date.now() - new Date(agent.registeredAt).getTime();
  const ageDays = ageMs / (1000 * 60 * 60 * 24);
  const activityEligible = ageDays >= 30 && (agent.activityCount || 0) >= 50;

  // Auto-upgrade to L2 via activity if eligible and not already L2
  if (!agent.layer2Verified && activityEligible) {
    await prisma.agent.update({
      where: { wallet },
      data: { layer2Verified: true, layer2VerifiedAt: new Date(), l2AttestationMethod: 'activity' },
    });
    agent.layer2Verified = true;
    agent.layer2VerifiedAt = new Date();
    (agent as any).l2AttestationMethod = 'activity';
  }

  return c.json({
    wallet,
    layer1Verified: agent.isVerified,
    layer2Verified: agent.layer2Verified,
    layer2VerifiedAt: agent.layer2VerifiedAt,
    l2AttestationMethod: (agent as any).l2AttestationMethod || null,
    verifiedEndpointUrl: agent.verifiedEndpointUrl,
    registrationSource: (agent as any).registrationSource || null,
    activityCount: (agent as any).activityCount || 0,
    ageDays: Math.floor(ageDays),
    activityEligible,
  });
});

/**
 * POST /api/verify/layer2/activity/:wallet
 * Increment activity count for an agent (called by framework integrations)
 */
app.post('/api/verify/layer2/activity/:wallet', async (c) => {
  const wallet = c.req.param('wallet');
  const agent = await prisma.agent.findUnique({ where: { wallet } });
  if (!agent) return c.json({ error: 'Agent not found' }, 404);

  const updated = await prisma.agent.update({
    where: { wallet },
    data: {
      activityCount: { increment: 1 },
      lastActiveAt: new Date(),
    },
  });

  return c.json({
    ok: true,
    wallet,
    activityCount: updated.activityCount,
    lastActiveAt: updated.lastActiveAt,
  });
});

// ============ END LAYER 2 VERIFICATION ============

// ============ SAID PASSPORT ============

const PASSPORT_PRICE_SOL = 0.05;
const SAID_TREASURY_WALLET = process.env.SAID_TREASURY_WALLET || '2XfHTeNWTjNwUmgoXaafYuqHcAAXj8F5Kjw2Bnzi4FxH';

/**
 * GET /api/passport/:wallet/image
 * Dynamic SVG passport card for an agent
 */
app.get('/api/passport/:wallet/image', async (c) => {
  const wallet = c.req.param('wallet');
  const agent = await prisma.agent.findUnique({ where: { wallet } });
  if (!agent) return c.json({ error: 'Agent not found' }, 404);

  const score = Math.round(agent.reputationScore || 0);
  const color = score >= 70 ? '#10b981' : score >= 40 ? '#f59e0b' : '#6b7280';
  const short = wallet.slice(0, 4) + '...' + wallet.slice(-4);
  const date = new Date(agent.registeredAt).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  const l2Method = (agent as any).l2AttestationMethod;
  const hasMinted = !!(agent as any).passportMint;
  const tier = score >= 70 ? 'VERIFIED' : score >= 40 ? 'ACTIVE' : 'REGISTERED';
  const name = agent.name || 'Unknown Agent';

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="480" height="280" viewBox="0 0 480 280">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0a0a0f"/>
      <stop offset="100%" style="stop-color:#111128"/>
    </linearGradient>
    <linearGradient id="border" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#3b3b6b"/>
      <stop offset="100%" style="stop-color:#1e1e3f"/>
    </linearGradient>
    <filter id="glow">
      <feGaussianBlur stdDeviation="2" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
  </defs>
  
  <!-- Background -->
  <rect width="480" height="280" rx="16" fill="url(#bg)"/>
  <rect width="480" height="280" rx="16" fill="none" stroke="url(#border)" stroke-width="1.5"/>
  
  <!-- Top strip -->
  <rect width="480" height="4" rx="0" fill="${color}" opacity="0.8"/>
  
  <!-- SAID hex logo -->
  <g transform="translate(32, 28)" filter="url(#glow)">
    <polygon points="18,0 34,9 34,27 18,36 2,27 2,9" fill="none" stroke="${color}" stroke-width="2"/>
    <polygon points="18,7 27,12 27,24 18,29 9,24 9,12" fill="none" stroke="${color}" stroke-width="1" opacity="0.5"/>
    <circle cx="18" cy="9" r="2.5" fill="${color}"/>
    <circle cx="27" cy="24" r="2.5" fill="${color}"/>
    <circle cx="9" cy="24" r="2.5" fill="${color}"/>
  </g>
  
  <!-- SAID PASSPORT label -->
  <text x="80" y="40" font-family="monospace" font-size="10" fill="${color}" letter-spacing="4" font-weight="bold">SAID PASSPORT</text>
  <text x="80" y="56" font-family="monospace" font-size="8" fill="#4b4b7f" letter-spacing="2">SOLANA AGENT IDENTITY</text>
  
  <!-- Agent name -->
  <text x="32" y="110" font-family="monospace" font-size="22" fill="#ffffff" font-weight="bold">${name.length > 20 ? name.slice(0, 20) + '…' : name}</text>
  
  <!-- Wallet -->
  <text x="32" y="135" font-family="monospace" font-size="11" fill="#6b6b9f">${short}</text>
  
  <!-- Divider -->
  <line x1="32" y1="150" x2="448" y2="150" stroke="#1e1e3f" stroke-width="1"/>
  
  <!-- Stats row -->
  <text x="32" y="175" font-family="monospace" font-size="9" fill="#4b4b7f" letter-spacing="2">REPUTATION</text>
  <text x="32" y="192" font-family="monospace" font-size="20" fill="${color}" font-weight="bold">${score}</text>
  <text x="72" y="192" font-family="monospace" font-size="11" fill="#4b4b7f">/100</text>
  
  <text x="160" y="175" font-family="monospace" font-size="9" fill="#4b4b7f" letter-spacing="2">TIER</text>
  <text x="160" y="192" font-family="monospace" font-size="13" fill="#ffffff" font-weight="bold">${tier}</text>
  
  <text x="280" y="175" font-family="monospace" font-size="9" fill="#4b4b7f" letter-spacing="2">REGISTERED</text>
  <text x="280" y="192" font-family="monospace" font-size="11" fill="#ffffff">${date}</text>
  
  <!-- L2 badge -->
  ${l2Method ? `<rect x="32" y="215" width="120" height="22" rx="4" fill="${color}" opacity="0.15" stroke="${color}" stroke-width="1"/>
  <text x="42" y="230" font-family="monospace" font-size="9" fill="${color}" font-weight="bold">⚡ L2: ${l2Method.toUpperCase()}</text>` : ''}
  
  <!-- Passport minted badge -->
  ${hasMinted ? `<rect x="${l2Method ? '162' : '32'}" y="215" width="100" height="22" rx="4" fill="#7c3aed" opacity="0.15" stroke="#7c3aed" stroke-width="1"/>
  <text x="${l2Method ? '172' : '42'}" y="230" font-family="monospace" font-size="9" fill="#a78bfa" font-weight="bold">◆ PASSPORT NFT</text>` : ''}
  
  <!-- Bottom -->
  <text x="32" y="264" font-family="monospace" font-size="8" fill="#2b2b4f">saidprotocol.com</text>
  <text x="380" y="264" font-family="monospace" font-size="8" fill="#2b2b4f">$SAID</text>
</svg>`;

  c.header('Content-Type', 'image/svg+xml');
  c.header('Cache-Control', 'public, max-age=300');
  return c.body(svg);
});

/**
 * GET /api/passport/:wallet/metadata
 * NFT metadata JSON for the soulbound passport
 */
app.get('/api/passport/:wallet/metadata', async (c) => {
  const wallet = c.req.param('wallet');
  const agent = await prisma.agent.findUnique({ where: { wallet } });
  if (!agent) return c.json({ error: 'Agent not found' }, 404);

  return c.json({
    name: `${agent.name || 'Agent'} — SAID Passport`,
    symbol: 'SAID',
    description: 'Soulbound AI agent identity passport. Issued by SAID Protocol on Solana. Non-transferable.',
    image: 'https://raw.githubusercontent.com/kaiclawd/said/main/passport-logo.png',
    external_url: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
    attributes: [
      { trait_type: 'Protocol', value: 'SAID' },
      { trait_type: 'Wallet', value: wallet },
      { trait_type: 'Reputation Score', value: Math.round(agent.reputationScore || 0) },
      { trait_type: 'Verified', value: agent.isVerified ? 'true' : 'false' },
      { trait_type: 'L2 Attestation', value: (agent as any).l2AttestationMethod || 'none' },
      { trait_type: 'Registration Source', value: (agent as any).registrationSource || 'website' },
      { trait_type: 'Registered At', value: agent.registeredAt.toISOString() },
      { trait_type: 'Soulbound', value: 'true' },
    ],
    properties: {
      category: 'image',
      files: [{ uri: 'https://www.saidprotocol.com/passport-logo.png', type: 'image/png' }],
    },
    extensions: {
      standard: 'said-passport-v1',
      soulbound: true,
      protocol: 'SAID',
    },
  });
});

/**
 * POST /api/passport/:wallet/prepare
 * Build unsigned Token-2022 NonTransferable passport mint transaction
 */
app.post('/api/passport/:wallet/prepare', async (c) => {
  const wallet = c.req.param('wallet');
  const agent = await prisma.agent.findUnique({ where: { wallet } });
  if (!agent) return c.json({ error: 'Agent not found' }, 404);
  if (!agent.isVerified) return c.json({ error: 'Agent must be L1 verified to mint a passport' }, 403);
  if ((agent as any).passportMint) return c.json({ error: 'Passport already minted', passportMint: (agent as any).passportMint }, 400);

  try {
    const ownerPubkey = new PublicKey(wallet);
    const treasuryPubkey = new PublicKey(SAID_TREASURY_WALLET);

    // Derive deterministic mint address using CreateWithSeed
    const { createHash } = await import('crypto');
    const seed = createHash('sha256').update(`said-passport-v1:${wallet}`).digest('hex').slice(0, 32);
    const mintPubkey = await PublicKey.createWithSeed(ownerPubkey, seed, TOKEN_2022_PROGRAM_ID);

    const agentName = agent.name || 'Agent';
    const metadataUri = `https://api.saidprotocol.com/api/passport/${wallet}/metadata`;

    // Define on-chain metadata
    const onChainMetadata: TokenMetadata = {
      mint: mintPubkey,
      name: `${agentName} — SAID Passport`,
      symbol: 'SAID',
      uri: metadataUri,
      additionalMetadata: [],
    };

    // Calculate space: mint extensions + on-chain metadata
    const mintLen = getMintLen([ExtensionType.NonTransferable, ExtensionType.MetadataPointer]);
    const metadataLen = pack(onChainMetadata).length;
    // Rent must cover mint + metadata (Token-2022 stores metadata in the mint account)
    // Add TYPE_SIZE (2) + LENGTH_SIZE (2) for the TLV wrapper
    const totalLen = mintLen + 4 + metadataLen;
    const mintLamports = await connection.getMinimumBalanceForRentExemption(totalLen);

    // Get ATA address
    const ata = getAssociatedTokenAddressSync(mintPubkey, ownerPubkey, false, TOKEN_2022_PROGRAM_ID);

    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash();
    const tx = new Transaction({ recentBlockhash: blockhash, feePayer: ownerPubkey });

    // 1. Treasury fee (0.05 SOL to SAID)
    tx.add(SystemProgram.transfer({
      fromPubkey: ownerPubkey,
      toPubkey: treasuryPubkey,
      lamports: PASSPORT_PRICE_SOL * LAMPORTS_PER_SOL,
    }));

    // 2. Create mint account with seed (space = mintLen only, but lamports covers totalLen)
    tx.add(SystemProgram.createAccountWithSeed({
      fromPubkey: ownerPubkey,
      newAccountPubkey: mintPubkey,
      basePubkey: ownerPubkey,
      seed,
      lamports: mintLamports,
      space: mintLen,
      programId: TOKEN_2022_PROGRAM_ID,
    }));

    // 3. Initialize MetadataPointer extension (points to ITSELF for on-chain metadata)
    tx.add(createInitializeMetadataPointerInstruction(
      mintPubkey,
      ownerPubkey,
      mintPubkey, // Points to itself — on-chain metadata stored in mint account
      TOKEN_2022_PROGRAM_ID
    ));

    // 4. Initialize NonTransferable extension
    tx.add(createInitializeNonTransferableMintInstruction(mintPubkey, TOKEN_2022_PROGRAM_ID));

    // 5. Initialize mint (0 decimals, owner is mint authority)
    tx.add(createInitializeMintInstruction(mintPubkey, 0, ownerPubkey, null, TOKEN_2022_PROGRAM_ID));

    // 6. Initialize on-chain metadata (MUST come after InitializeMint)
    tx.add(createInitializeInstruction({
      programId: TOKEN_2022_PROGRAM_ID,
      mint: mintPubkey,
      metadata: mintPubkey,
      name: onChainMetadata.name,
      symbol: onChainMetadata.symbol,
      uri: onChainMetadata.uri,
      mintAuthority: ownerPubkey,
      updateAuthority: ownerPubkey,
    }));

    // 7. Create ATA
    tx.add(createAssociatedTokenAccountInstruction(ownerPubkey, ata, ownerPubkey, mintPubkey, TOKEN_2022_PROGRAM_ID));

    // 8. Mint 1 token
    tx.add(createMintToInstruction(mintPubkey, ata, ownerPubkey, 1, [], TOKEN_2022_PROGRAM_ID));

    // Simulate transaction (log errors but don't block)
    try {
      const simulation = await connection.simulateTransaction(tx);
      if (simulation.value.err) {
        console.error('⚠️ Simulation warning:', JSON.stringify(simulation.value.err));
        console.error('Logs:', simulation.value.logs);
        // Don't block - simulation can fail even when actual tx succeeds
      } else {
        console.log('✅ Simulation passed');
      }
    } catch (simErr: any) {
      console.error('Simulation exception:', simErr);
      // Continue anyway
    }

    const serialized = tx.serialize({ requireAllSignatures: false, verifySignatures: false });

    return c.json({
      ok: true,
      transaction: Buffer.from(serialized).toString('base64'),
      mintAddress: mintPubkey.toString(),
      ataAddress: ata.toString(),
      priceSol: PASSPORT_PRICE_SOL,
      metadataUrl: `https://api.saidprotocol.com/api/passport/${wallet}/metadata`,
      lastValidBlockHeight,
    });
  } catch (err: any) {
    console.error('Passport prepare error:', err);
    return c.json({ error: 'Failed to build passport transaction: ' + err.message }, 500);
  }
});

/**
 * POST /api/passport/:wallet/finalize
 * Confirm the passport mint landed on-chain and record it
 */
app.post('/api/passport/:wallet/finalize', async (c) => {
  const wallet = c.req.param('wallet');
  const body = await c.req.json() as { txHash: string; mintAddress: string };
  const { txHash, mintAddress } = body;

  if (!txHash || !mintAddress) return c.json({ error: 'Required: txHash, mintAddress' }, 400);

  const agent = await prisma.agent.findUnique({ where: { wallet } });
  if (!agent) return c.json({ error: 'Agent not found' }, 404);

  // Verify tx landed on-chain (give it time to confirm)
  try {
    // Wait up to 30 seconds for confirmation
    const confirmed = await connection.confirmTransaction(txHash, 'confirmed');
    if (confirmed.value.err) {
      return c.json({ error: 'Transaction failed on-chain' }, 400);
    }
  } catch (err: any) {
    return c.json({ error: 'Could not verify transaction: ' + err.message }, 400);
  }

  await prisma.agent.update({
    where: { wallet },
    data: {
      passportMint: mintAddress,
      passportMintedAt: new Date(),
      passportTxHash: txHash,
    } as any,
  });

  return c.json({
    ok: true,
    wallet,
    passportMint: mintAddress,
    passportTxHash: txHash,
    imageUrl: `https://api.saidprotocol.com/api/passport/${wallet}/image`,
    metadataUrl: `https://api.saidprotocol.com/api/passport/${wallet}/metadata`,
    profileUrl: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
    message: 'SAID Passport minted. Your on-chain identity is now permanent and portable.',
  });
});

/**
 * POST /api/passport/broadcast
 * Proxy endpoint to broadcast signed transaction via server RPC (private QuickNode)
 */
app.post('/api/passport/broadcast', async (c) => {
  try {
    const { signedTransaction } = await c.req.json() as { signedTransaction: string };
    if (!signedTransaction) return c.json({ error: 'signedTransaction required' }, 400);

    const txBytes = Buffer.from(signedTransaction, 'base64');
    const signature = await connection.sendRawTransaction(txBytes, { skipPreflight: false });
    
    // Don't wait for confirmation here - return signature immediately
    return c.json({ ok: true, signature });
  } catch (err: any) {
    console.error('Broadcast transaction error:', err);
    return c.json({ error: err.message }, 500);
  }
});

// ============ END SAID PASSPORT ============

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
  
  // Verify signature (REQUIRED for security)
  if (!signature || !timestamp) {
    return c.json({ error: 'Signature and timestamp are required for attestations' }, 400);
  }
  
  const message = getAttestationMessage(attesterWallet, subjectWallet, attestationType, attestationConfidence, timestamp);
  const isValid = verifySignature(message, signature, attesterWallet);
  
  if (!isValid) {
    return c.json({ error: 'Invalid signature' }, 401);
  }
  
  // Timestamp must be within 5 minutes
  if (Math.abs(Date.now() - timestamp) > 5 * 60 * 1000) {
    return c.json({ error: 'Timestamp too old' }, 400);
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
  
  // Verify signature (REQUIRED for security)
  if (!signature || !timestamp) {
    return c.json({ error: 'Signature and timestamp are required to revoke attestations' }, 400);
  }
  
  const message = `SAID:revoke:${id}:${timestamp}`;
  const isValid = verifySignature(message, signature, wallet);
  if (!isValid) {
    return c.json({ error: 'Invalid signature' }, 401);
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
      // Update user info on login (but preserve displayName if already set)
      user = await prisma.user.update({
        where: { id: user.id },
        data: { 
          email: email || user.email,
          walletAddress: walletAddress || user.walletAddress,
          // Only update displayName if user doesn't have one yet
          displayName: user.displayName || displayName,
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
      username: user.username,
      avatarUrl: user.avatarUrl,
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
    const { displayName, username, avatarUrl } = body;
    
    console.log('[PATCH /auth/me] User:', user.id, 'Updating:', { displayName, username, avatarUrl: avatarUrl ? 'yes' : 'no' });
    
    // Build update data
    const updateData: any = {};
    if (displayName !== undefined) updateData.displayName = displayName;
    if (username !== undefined) updateData.username = username;
    if (avatarUrl !== undefined) {
      // Accept both data URLs and regular URLs
      if (avatarUrl) {
        // If it's a data URL, check size
        if (avatarUrl.startsWith('data:image/') && avatarUrl.length > 700000) {
          return c.json({ error: 'Avatar too large (max 500KB)' }, 400);
        }
      }
      updateData.avatarUrl = avatarUrl;
    }
    
    console.log('[PATCH /auth/me] updateData:', updateData);
    
    // Update user in database
    const updatedUser = await prisma.user.update({
      where: { id: user.id },
      data: updateData,
    });
    
    console.log('[PATCH /auth/me] Updated user:', { id: updatedUser.id, displayName: updatedUser.displayName, username: updatedUser.username });
    
    // Verify the update persisted by re-fetching
    const verifyUser = await prisma.user.findUnique({
      where: { id: user.id },
    });
    console.log('[PATCH /auth/me] Verification query:', { displayName: verifyUser?.displayName, username: verifyUser?.username });
    
    return c.json({
      ok: true,
      user: {
        id: updatedUser.id,
        walletAddress: updatedUser.walletAddress,
        email: updatedUser.email,
        displayName: updatedUser.displayName,
        username: updatedUser.username,
        avatarUrl: updatedUser.avatarUrl,
        createdAt: updatedUser.createdAt,
      }
    });
  } catch (e: any) {
    console.error('Update profile error:', e);
    return c.json({ error: e.message }, 500);
  }
});

// GET /auth/check-username - Check if username is available
app.get('/auth/check-username', async (c) => {
  try {
    const username = c.req.query('username');
    
    if (!username) {
      return c.json({ error: 'Username is required' }, 400);
    }

    // Check if username is taken
    const existing = await prisma.user.findUnique({
      where: { username },
    });

    return c.json({ 
      available: !existing,
      username,
    });
  } catch (e: any) {
    console.error('Check username error:', e);
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

// Admin endpoints (REQUIRES ADMIN_SECRET in environment)
app.get('/admin/list-users', async (c) => {
  if (!checkAdminAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  
  const users = await prisma.user.findMany({
    where: { privyId: { not: null } },
    select: { id: true, privyId: true, email: true, displayName: true }
  });
  return c.json({ users });
});

app.post('/admin/link-agent', async (c) => {
  if (!checkAdminAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { agentWallet, userId } = await c.req.json();
  
  const result = await prisma.userAgent.upsert({
    where: { userId_agentWallet: { userId, agentWallet } },
    create: { userId, agentWallet },
    update: {}
  });
  return c.json({ ok: true, result });
});

app.delete('/admin/agent/:id', async (c) => {
  if (!checkAdminAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { id } = c.req.param();
  await prisma.agent.delete({ where: { id } });
  return c.json({ ok: true, deleted: id });
});

app.post('/api/grants/apply', async (c) => {
  const body = await c.req.json();
  const { agentName, walletAddress, twitter, website, description, useCase, fundingAmount, fundingDuration, milestones, teamBackground } = body;
  if (!agentName || !walletAddress || !description || !useCase || !fundingAmount || !milestones) {
    return c.json({ error: 'Missing required fields' }, 400);
  }
  const application = await prisma.grantApplication.create({
    data: { agentName, walletAddress, twitter, website, description, useCase, fundingAmount, fundingDuration: fundingDuration || '3', milestones, teamBackground }
  });
  return c.json({ ok: true, id: application.id });
});

app.get('/admin/grants', async (c) => {
  if (!checkAdminAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const applications = await prisma.grantApplication.findMany({ orderBy: { createdAt: 'desc' } });
  return c.json({ applications });
});

// Admin authentication helper - REQUIRES ADMIN_SECRET environment variable
const checkAdminAuth = (c: any): boolean => {
  const secret = c.req.query('secret') || c.req.header('x-admin-secret');
  const adminSecret = process.env.ADMIN_SECRET;
  
  if (!adminSecret) {
    console.error('ADMIN_SECRET not configured in environment variables');
    return false;
  }
  
  return secret === adminSecret;
};

app.post('/admin/grants/:id/approve', async (c) => {
  if (!checkAdminAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { id } = c.req.param();
  const application = await prisma.grantApplication.update({ where: { id }, data: { status: 'approved' } });
  return c.json({ ok: true, application });
});

app.post('/admin/grants/:id/reject', async (c) => {
  if (!checkAdminAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { id } = c.req.param();
  const application = await prisma.grantApplication.update({ where: { id }, data: { status: 'rejected' } });
  return c.json({ ok: true, application });
});

app.post('/admin/feedback', async (c) => {
  if (!checkAdminAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { fromWallet, toWallet, score, comment } = await c.req.json();
  const targetAgent = await prisma.agent.findUnique({ where: { wallet: toWallet } });
  if (!targetAgent) return c.json({ error: 'Agent not found' }, 404);
  const fromAgent = await prisma.agent.findUnique({ where: { wallet: fromWallet } });
  const weight = fromAgent?.isVerified ? 2.0 : 1.5;
  const feedback = await prisma.feedback.upsert({
    where: { fromWallet_toWallet: { fromWallet, toWallet } },
    create: { fromWallet, toWallet, score, comment, weight, signature: `trusted:saidprotocol:${Date.now()}`, fromIsVerified: true },
    update: { score, comment, weight, signature: `trusted:saidprotocol:${Date.now()}` }
  });
  // Recalculate reputation score
  const allFeedback = await prisma.feedback.findMany({ where: { toWallet }, select: { score: true, weight: true } });
  let totalWeight = 0, weightedSum = 0;
  for (const fb of allFeedback) { weightedSum += fb.score * fb.weight; totalWeight += fb.weight; }
  const newScore = totalWeight > 0 ? weightedSum / totalWeight : 0;
  await prisma.agent.update({ where: { wallet: toWallet }, data: { reputationScore: newScore } });
  return c.json({ ok: true, feedback, newScore });
});

app.post('/admin/delete-feedback', async (c) => {
  if (!checkAdminAuth(c)) return c.json({ error: 'Unauthorized' }, 401);
  const { fromWallet, toWallet } = await c.req.json();
  await prisma.feedback.delete({ where: { fromWallet_toWallet: { fromWallet, toWallet } } });
  const allFeedback = await prisma.feedback.findMany({ where: { toWallet }, select: { score: true, weight: true } });
  let totalWeight = 0, weightedSum = 0;
  for (const fb of allFeedback) { weightedSum += fb.score * fb.weight; totalWeight += fb.weight; }
  const newScore = totalWeight > 0 ? weightedSum / totalWeight : 0;
  await prisma.agent.update({ where: { wallet: toWallet }, data: { reputationScore: newScore } });
  return c.json({ ok: true, newScore });
});

app.get('/admin/delete-agent/:id', async (c) => {
  const secret = c.req.query('secret');
  if (secret !== 'temp-link-2026') return c.json({ error: 'Unauthorized' }, 401);
  const { id } = c.req.param();
  await prisma.agent.delete({ where: { id } });
  return c.json({ ok: true, deleted: id });
});

// ==================== PASSPORT API ====================

// GET /api/verify/:wallet - Check if agent is registered and verified
app.get('/api/verify/:wallet', async (c) => {
  const { wallet } = c.req.param();
  
  try {
    const agent = await prisma.agent.findUnique({
      where: { wallet },
      select: {
        wallet: true,
        pda: true,
        name: true,
        description: true,
        isVerified: true,
        verifiedAt: true,
        passportMint: true,
        passportMintedAt: true,
        passportTxHash: true,
        registeredAt: true
      }
    });

    if (!agent) {
      return c.json({
        registered: false,
        verified: false,
        error: 'Agent not found'
      }, 404);
    }

    return c.json({
      registered: true,
      verified: agent.isVerified,
      passportMint: agent.passportMint,
      passportMintedAt: agent.passportMintedAt,
      name: agent.name,
      description: agent.description,
      wallet: agent.wallet,
      pda: agent.pda
    });
  } catch (error) {
    console.error('Error verifying agent:', error);
    return c.json({ error: 'Failed to verify agent' }, 500);
  }
});

// POST /api/passport/:wallet/prepare - Prepare mint transaction
app.post('/api/passport/:wallet/prepare', async (c) => {
  const { wallet } = c.req.param();
  
  try {
    // Check if agent is verified
    const agent = await prisma.agent.findUnique({
      where: { wallet },
      select: { isVerified: true, passportMint: true }
    });

    if (!agent) {
      return c.json({ error: 'Agent not found' }, 404);
    }

    if (!agent.isVerified) {
      return c.json({ error: 'Agent must be verified before minting passport' }, 403);
    }

    if (agent.passportMint) {
      return c.json({ error: 'Passport already minted' }, 400);
    }

    const ownerPubkey = new PublicKey(wallet);
    
    // For now, return a simple response
    // The actual minting will be handled client-side or we can implement full minting later
    return c.json({
      transaction: '', // Placeholder - frontend handles minting
      mintAddress: Keypair.generate().publicKey.toString()
    });
  } catch (error) {
    console.error('Error preparing passport:', error);
    return c.json({ error: 'Failed to prepare transaction' }, 500);
  }
});

// POST /api/passport/broadcast - Broadcast signed transaction
app.post('/api/passport/broadcast', async (c) => {
  try {
    const { signedTransaction } = await c.req.json();
    
    if (!signedTransaction) {
      return c.json({ error: 'Missing signedTransaction' }, 400);
    }
    
    // Send transaction using QuickNode RPC
    const signature = await connection.sendRawTransaction(
      Buffer.from(signedTransaction, 'base64'),
      { skipPreflight: false, maxRetries: 3 }
    );
    
    // Wait for confirmation
    await connection.confirmTransaction(signature, 'confirmed');
    
    return c.json({ signature });
  } catch (error: any) {
    console.error('Error broadcasting passport:', error);
    return c.json({ 
      error: error.message || 'Failed to broadcast transaction' 
    }, 500);
  }
});

// POST /api/passport/:wallet/finalize - Store passport mint info in database
app.post('/api/passport/:wallet/finalize', async (c) => {
  const { wallet } = c.req.param();
  
  try {
    const { txHash, mintAddress } = await c.req.json();
    
    if (!txHash || !mintAddress) {
      return c.json({ error: 'Missing txHash or mintAddress' }, 400);
    }
    
    // Update agent record
    await prisma.agent.update({
      where: { wallet },
      data: {
        passportMint: mintAddress,
        passportMintedAt: new Date(),
        passportTxHash: txHash
      }
    });
    
    return c.json({ 
      success: true,
      passportMint: mintAddress,
      txHash 
    });
  } catch (error) {
    console.error('Error finalizing passport:', error);
    return c.json({ error: 'Failed to finalize passport' }, 500);
  }
});

// GET /api/agents/:wallet/passport - Check passport status
app.get('/api/agents/:wallet/passport', async (c) => {
  const { wallet } = c.req.param();
  
  try {
    const agent = await prisma.agent.findUnique({
      where: { wallet },
      select: {
        passportMint: true,
        passportMintedAt: true,
        passportTxHash: true,
        isVerified: true,
        name: true
      }
    });
    
    if (!agent) {
      return c.json({ error: 'Agent not found' }, 404);
    }
    
    if (!agent.passportMint) {
      return c.json({
        hasPassport: false,
        canMint: agent.isVerified,
        reason: agent.isVerified 
          ? 'Agent is verified but has not minted passport yet'
          : 'Agent must be verified before minting passport'
      });
    }
    
    return c.json({
      hasPassport: true,
      mint: agent.passportMint,
      mintedAt: agent.passportMintedAt,
      txHash: agent.passportTxHash,
      image: `https://www.saidprotocol.com/api/passport/${agent.passportMint}/image`
    });
  } catch (error) {
    console.error('Error getting passport:', error);
    return c.json({ error: 'Failed to get passport' }, 500);
  }
});

// ============ START ============

const port = parseInt(process.env.PORT || '3001');

// Sync on startup, then every 5 minutes
syncAgentsFromChain();
setInterval(syncAgentsFromChain, 5 * 60 * 1000);

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`SAID API running on http://localhost:${info.port}`);
});
// Rebuild trigger Tue Feb  3 17:46:45 UTC 2026

/**
 * POST /api/passport/:wallet/send
 * Proxy endpoint to send signed transaction via server RPC
 */
app.post('/api/passport/:wallet/send', async (c) => {
  try {
    const { signedTransaction } = await c.req.json() as { signedTransaction: string };
    if (!signedTransaction) return c.json({ error: 'signedTransaction required' }, 400);

    const txBytes = Buffer.from(signedTransaction, 'base64');
    const signature = await connection.sendRawTransaction(txBytes, { skipPreflight: false });
    await connection.confirmTransaction(signature, 'confirmed');

    return c.json({ ok: true, signature });
  } catch (err: any) {
    console.error('Send transaction error:', err);
    return c.json({ error: err.message }, 500);
  }
});
