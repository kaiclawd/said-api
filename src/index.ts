import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server';
import { PrismaClient } from '@prisma/client';
import { Connection, PublicKey } from '@solana/web3.js';
import { config } from 'dotenv';

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
  const { fromWallet, score, comment, signature } = body;
  
  // Validate
  if (!fromWallet || score === undefined || !signature) {
    return c.json({ error: 'Missing required fields: fromWallet, score, signature' }, 400);
  }
  
  if (score < 0 || score > 100) {
    return c.json({ error: 'Score must be between 0 and 100' }, 400);
  }
  
  // Check target agent exists
  const targetAgent = await prisma.agent.findUnique({ where: { wallet: toWallet } });
  if (!targetAgent) {
    return c.json({ error: 'Target agent not found' }, 404);
  }
  
  // TODO: Verify signature against message
  // const message = `SAID Feedback: ${fromWallet} rates ${toWallet} ${score}/100`;
  // const isValid = verifySignature(message, signature, fromWallet);
  
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
    },
    update: {
      score,
      comment,
      signature,
    }
  });
  
  // Recalculate reputation
  const avgResult = await prisma.feedback.aggregate({
    where: { toWallet },
    _avg: { score: true },
    _count: true,
  });
  
  await prisma.agent.update({
    where: { wallet: toWallet },
    data: {
      reputationScore: avgResult._avg.score || 0,
      feedbackCount: avgResult._count,
    }
  });
  
  return c.json({ success: true, feedback });
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
      const data = account.data;
      
      // Parse on-chain data
      const owner = new PublicKey(data.subarray(8, 40)).toString();
      const uriLength = data.readUInt32LE(40);
      const metadataUri = data.subarray(44, 44 + uriLength).toString('utf8');
      const offset = 44 + uriLength;
      const registeredAt = Number(data.readBigInt64LE(offset));
      const isVerified = data[offset + 8] === 1;
      const verifiedAt = Number(data.readBigInt64LE(offset + 9));
      
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
