import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server';
import { PrismaClient } from '@prisma/client';
import { Connection, PublicKey } from '@solana/web3.js';
import { config } from 'dotenv';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

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
  origin: ['https://www.saidprotocol.com', 'https://saidprotocol.com', 'http://localhost:3000'],
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
  const { fromWallet, score, comment, signature, timestamp } = body;
  
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
  
  // Upsert feedback (one per fromWallet->toWallet pair)
  const feedback = await prisma.feedback.upsert({
    where: {
      fromWallet_toWallet: { fromWallet, toWallet }
    },
    create: {
      fromWallet,
      toWallet,
      score,
      comment,
      signature,
      weight,
      fromIsVerified,
    },
    update: {
      score,
      comment,
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

// ============ LEADERBOARD ============

app.get('/api/leaderboard', async (c) => {
  const { period, limit } = c.req.query();
  
  // TODO: Add time-based filtering for weekly/monthly
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
        if (uri.includes('saidprotocol.com') && !uri.includes('www.')) {
          uri = uri.replace('saidprotocol.com', 'www.saidprotocol.com');
        }
        const res = await fetch(uri);
        if (res.ok) card = await res.json();
      } catch (e) {
        // Skip failed fetches
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
