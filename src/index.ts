import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server';
import { PrismaClient } from '@prisma/client';
import { Connection, PublicKey } from '@solana/web3.js';
import { config } from 'dotenv';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import { agentdexRoutes } from './integrations/agentdex';

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
  const wallet = c.req.param('wallet').replace('.svg', '');
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
  
  const svg = generateBadgeSvg(agent, style);
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

// ============ INTEGRATIONS ============

// AgentDEX integration — identity verification & trade feedback
app.route('/api/integrations/agentdex', agentdexRoutes);

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
