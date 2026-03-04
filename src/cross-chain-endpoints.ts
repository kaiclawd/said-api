import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';
import {
  resolveAgent,
  resolveERC8004ByTokenId,
  getCrossChainStats,
} from './cross-chain-resolver.js';
import {
  Chain,
  EVM_RPC,
} from './cross-chain-types.js';

const prisma = new PrismaClient();
const crossChain = new Hono();

// ═══════════════════════════════════════════════════════
// 1. UNIVERSAL AGENT RESOLUTION
// ═══════════════════════════════════════════════════════

/**
 * GET /xchain/resolve/:address
 * Resolve any wallet address to agent profiles across all chains
 * 
 * Query params:
 *   chain - specific chain to check (optional, auto-detects if omitted)
 */
crossChain.get('/resolve/:address', async (c) => {
  const { address } = c.req.param();
  const chain = c.req.query('chain');

  try {
    const agents = await resolveAgent(address, chain);

    return c.json({
      address,
      chain: chain || 'auto',
      agents,
      count: agents.length,
      resolvedAt: new Date().toISOString(),
    });
  } catch (error: any) {
    console.error('[XChain Resolve Error]', error);
    return c.json({ error: 'Resolution failed', details: error.message }, 500);
  }
});

/**
 * GET /xchain/resolve/token/:chain/:tokenId
 * Resolve an ERC-8004 agent by token ID on a specific chain
 */
crossChain.get('/resolve/token/:chain/:tokenId', async (c) => {
  const { chain, tokenId } = c.req.param();

  if (!EVM_RPC[chain]) {
    return c.json({ error: `Unsupported chain: ${chain}. Supported: ${Object.keys(EVM_RPC).join(', ')}` }, 400);
  }

  try {
    const agent = await resolveERC8004ByTokenId(parseInt(tokenId), chain);

    if (!agent) {
      return c.json({ error: `Agent #${tokenId} not found on ${chain}` }, 404);
    }

    return c.json({
      agent,
      resolvedAt: new Date().toISOString(),
    });
  } catch (error: any) {
    console.error('[XChain Token Resolve Error]', error);
    return c.json({ error: 'Resolution failed', details: error.message }, 500);
  }
});

// ═══════════════════════════════════════════════════════
// 2. CROSS-CHAIN DISCOVERY
// ═══════════════════════════════════════════════════════

/**
 * GET /xchain/discover
 * Discover agents across all chains
 * 
 * Query params:
 *   chains - comma-separated chains (default: all)
 *   capability - filter by capability
 *   verified - only verified agents
 *   limit - max results (default: 50)
 */
crossChain.get('/discover', async (c) => {
  const {
    chains: chainsParam,
    capability,
    verified,
    limit = '50',
  } = c.req.query();

  const requestedChains = chainsParam
    ? chainsParam.split(',').map(s => s.trim())
    : ['solana', ...Object.keys(EVM_RPC)];

  const maxLimit = Math.min(parseInt(limit), 100);
  const results: any[] = [];

  try {
    // SAID agents
    if (requestedChains.includes('solana')) {
      const saidAgents = await prisma.agent.findMany({
        where: {
          ...(verified === 'true' && { isVerified: true }),
          ...(capability && { skills: { has: capability } }),
        },
        orderBy: [{ isVerified: 'desc' }, { reputationScore: 'desc' }],
        take: maxLimit,
        select: {
          wallet: true,
          name: true,
          description: true,
          isVerified: true,
          reputationScore: true,
          skills: true,
          a2aEndpoint: true,
          registeredAt: true,
        },
      });

      for (const agent of saidAgents) {
        results.push({
          address: agent.wallet,
          chain: 'solana',
          source: 'said',
          name: agent.name || 'Unnamed Agent',
          description: agent.description || '',
          capabilities: agent.skills || [],
          endpoint: agent.a2aEndpoint || `https://api.saidprotocol.com/a2a/${agent.wallet}`,
          verified: agent.isVerified,
          reputationScore: agent.reputationScore,
          registeredAt: agent.registeredAt.toISOString(),
        });
      }
    }

    // Note: EVM discovery would require indexing (The Graph, etc.)
    // For now, return SAID results + info about EVM availability
    const evmChains = requestedChains.filter(c => EVM_RPC[c]);

    return c.json({
      agents: results.slice(0, maxLimit),
      count: results.length,
      query: { chains: requestedChains, capability, verified },
      evmNote: evmChains.length > 0
        ? `EVM agents on ${evmChains.join(', ')} can be resolved by address via /xchain/resolve/:address. Full EVM indexing coming soon.`
        : undefined,
    });
  } catch (error: any) {
    console.error('[XChain Discovery Error]', error);
    return c.json({ error: 'Discovery failed', details: error.message }, 500);
  }
});

// ═══════════════════════════════════════════════════════
// 3. CROSS-CHAIN MESSAGING
// ═══════════════════════════════════════════════════════

/**
 * POST /xchain/message
 * Send a message from any chain agent to any chain agent
 * 
 * Body:
 *   from: { address, chain }
 *   to: { address, chain }
 *   message: string
 *   context?: object
 *   signature?: string
 */
crossChain.post('/message', async (c) => {
  try {
    const body = await c.req.json();
    const { from, to, message, context, signature } = body;

    if (!from?.address || !from?.chain || !to?.address || !to?.chain || !message) {
      return c.json({
        error: 'Missing required fields',
        required: { from: { address: 'string', chain: 'string' }, to: { address: 'string', chain: 'string' }, message: 'string' },
      }, 400);
    }

    // Resolve both agents
    const [senderResults, recipientResults] = await Promise.all([
      resolveAgent(from.address, from.chain),
      resolveAgent(to.address, to.chain),
    ]);

    if (senderResults.length === 0) {
      return c.json({
        error: 'Sender not found',
        hint: `No agent found for ${from.address} on ${from.chain}. Agent must be registered on SAID (Solana) or ERC-8004 (EVM).`,
      }, 404);
    }

    if (recipientResults.length === 0) {
      return c.json({
        error: 'Recipient not found',
        hint: `No agent found for ${to.address} on ${to.chain}. Agent must be registered on SAID (Solana) or ERC-8004 (EVM).`,
      }, 404);
    }

    const sender = senderResults[0];
    const recipient = recipientResults[0];

    // Generate message ID
    const messageId = `xmsg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Store in DB (using A2AMessage table with cross-chain metadata)
    const stored = await prisma.a2AMessage.create({
      data: {
        fromWallet: `${from.chain}:${from.address}`,
        toWallet: `${to.chain}:${to.address}`,
        message,
        context: JSON.stringify({
          ...(context || {}),
          crossChain: true,
          fromChain: from.chain,
          toChain: to.chain,
          fromSource: sender.source,
          toSource: recipient.source,
          fromName: sender.name,
          toName: recipient.name,
        }),
        taskId: messageId,
        fromVerified: sender.verified,
        signature: signature || null,
        status: 'created',
        progress: 0,
      },
    });

    console.log(`[XChain Message] ${sender.name} (${from.chain}) → ${recipient.name} (${to.chain}): ${message.substring(0, 80)}`);

    // If recipient has an A2A endpoint, try to deliver
    let delivered = false;
    if (recipient.endpoint) {
      try {
        const deliveryRes = await fetch(recipient.endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from: {
              address: from.address,
              chain: from.chain,
              name: sender.name,
              verified: sender.verified,
              reputation: sender.reputationScore,
              source: sender.source,
            },
            message,
            context,
            messageId,
            protocol: 'said-xchain-v1',
          }),
          signal: AbortSignal.timeout(10000),
        });
        delivered = deliveryRes.ok;
      } catch (e) {
        console.warn(`[XChain] Delivery to ${recipient.endpoint} failed:`, e);
      }
    }

    // Update status
    if (delivered) {
      await prisma.a2AMessage.update({
        where: { taskId: messageId },
        data: { status: 'routed' },
      });
    }

    return c.json({
      success: true,
      messageId,
      status: delivered ? 'delivered' : 'stored',
      from: {
        address: from.address,
        chain: from.chain,
        name: sender.name,
        source: sender.source,
        verified: sender.verified,
      },
      to: {
        address: to.address,
        chain: to.chain,
        name: recipient.name,
        source: recipient.source,
        verified: recipient.verified,
      },
      inboxUrl: `/xchain/inbox/${to.chain}/${to.address}`,
    });
  } catch (error: any) {
    console.error('[XChain Message Error]', error);
    return c.json({ error: 'Message failed', details: error.message }, 500);
  }
});

/**
 * GET /xchain/inbox/:chain/:address
 * Get cross-chain messages for an agent
 */
crossChain.get('/inbox/:chain/:address', async (c) => {
  const { chain, address } = c.req.param();
  const { limit = '20' } = c.req.query();

  try {
    const walletKey = `${chain}:${address}`;
    
    // Also check plain address (for backward compat with SAID messages)
    const messages = await prisma.a2AMessage.findMany({
      where: {
        OR: [
          { toWallet: walletKey },
          { toWallet: address },
        ],
      },
      orderBy: { createdAt: 'desc' },
      take: parseInt(limit),
    });

    const formatted = messages.map((msg) => {
      const ctx = msg.context ? JSON.parse(msg.context) : {};
      return {
        messageId: msg.taskId,
        from: {
          address: msg.fromWallet.includes(':') ? msg.fromWallet.split(':')[1] : msg.fromWallet,
          chain: ctx.fromChain || 'solana',
          name: ctx.fromName || 'Unknown',
          verified: msg.fromVerified,
        },
        message: msg.message,
        status: msg.status,
        crossChain: ctx.crossChain || false,
        createdAt: msg.createdAt,
      };
    });

    return c.json({
      address,
      chain,
      messages: formatted,
      count: formatted.length,
    });
  } catch (error: any) {
    console.error('[XChain Inbox Error]', error);
    return c.json({ error: 'Failed to fetch inbox', details: error.message }, 500);
  }
});

// ═══════════════════════════════════════════════════════
// 4. CROSS-CHAIN STATS
// ═══════════════════════════════════════════════════════

/**
 * GET /xchain/stats
 * Get agent registry stats across all chains
 */
crossChain.get('/stats', async (c) => {
  try {
    const stats = await getCrossChainStats();
    
    const totalAgents = Object.values(stats).reduce((sum: number, s: any) => sum + (s.agents || 0), 0);
    const totalChains = Object.keys(stats).length;

    return c.json({
      totalAgents,
      totalChains,
      chains: stats,
      protocol: 'said-xchain-v1',
      supportedChains: ['solana', ...Object.keys(EVM_RPC)],
      timestamp: new Date().toISOString(),
    });
  } catch (error: any) {
    console.error('[XChain Stats Error]', error);
    return c.json({ error: 'Stats failed', details: error.message }, 500);
  }
});

// ═══════════════════════════════════════════════════════
// 5. SUPPORTED CHAINS
// ═══════════════════════════════════════════════════════

/**
 * GET /xchain/chains
 * List all supported chains
 */
crossChain.get('/chains', (c) => {
  const chains = [
    { id: 'solana', name: 'Solana', source: 'said', status: 'active' },
    ...Object.keys(EVM_RPC).map(chain => ({
      id: chain,
      name: chain.charAt(0).toUpperCase() + chain.slice(1),
      source: 'erc8004',
      status: 'active',
    })),
  ];

  return c.json({
    chains,
    count: chains.length,
    protocol: 'said-xchain-v1',
  });
});

export default crossChain;
