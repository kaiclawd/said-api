import { ethers } from 'ethers';
import {
  Chain,
  UnifiedAgent,
  ERC8004_IDENTITY_REGISTRY,
  ERC8004_REPUTATION_REGISTRY,
  IDENTITY_REGISTRY_ABI,
  REPUTATION_REGISTRY_ABI,
  EVM_RPC,
} from './cross-chain-types.js';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// ═══════════════════════════════════════════════════════
// EVM Provider Cache
// ═══════════════════════════════════════════════════════

const providerCache = new Map<string, ethers.JsonRpcProvider>();

function getProvider(chain: string): ethers.JsonRpcProvider {
  if (providerCache.has(chain)) return providerCache.get(chain)!;
  const rpc = EVM_RPC[chain];
  if (!rpc) throw new Error(`Unsupported EVM chain: ${chain}`);
  const provider = new ethers.JsonRpcProvider(rpc);
  providerCache.set(chain, provider);
  return provider;
}

function getIdentityRegistry(chain: string) {
  return new ethers.Contract(ERC8004_IDENTITY_REGISTRY, IDENTITY_REGISTRY_ABI, getProvider(chain));
}

function getReputationRegistry(chain: string) {
  return new ethers.Contract(ERC8004_REPUTATION_REGISTRY, REPUTATION_REGISTRY_ABI, getProvider(chain));
}

// ═══════════════════════════════════════════════════════
// ERC-8004 Resolution
// ═══════════════════════════════════════════════════════

/**
 * Resolve an EVM address to agent profiles on a given chain
 */
export async function resolveERC8004Agent(address: string, chain: string): Promise<UnifiedAgent[]> {
  const registry = getIdentityRegistry(chain);
  const agents: UnifiedAgent[] = [];

  try {
    const balance = await registry.balanceOf(address);
    const count = Number(balance);

    if (count === 0) return [];

    // ERC-8004 doesn't implement Enumerable
    // Strategy: Use Transfer events from recent blocks, with small range to stay within free RPC limits
    const provider = getProvider(chain);
    const filter = registry.filters.Transfer(null, address);
    
    let tokenIds: number[] = [];
    try {
      const currentBlock = await provider.getBlockNumber();
      // Only scan last 50k blocks (~7 days on ETH) to stay within free RPC limits
      const fromBlock = Math.max(0, currentBlock - 50000);
      const events = await registry.queryFilter(filter, fromBlock, 'latest');
      const candidates = [...new Set(events.map((e: any) => Number(e.args?.[2] || e.args?.tokenId)))];
      for (const tid of candidates) {
        try {
          const currentOwner = await registry.ownerOf(tid);
          if (currentOwner.toLowerCase() === address.toLowerCase()) {
            tokenIds.push(tid);
          }
        } catch (e) {}
      }
    } catch (e) {
      console.warn(`[ERC8004] Event query failed for ${address} on ${chain}:`, (e as any).message?.substring(0, 100));
    }

    // If we found no tokens via events but balance > 0, return a minimal agent card
    if (tokenIds.length === 0 && count > 0) {
      agents.push({
        address,
        chain: chain as Chain,
        source: 'erc8004',
        name: `ERC-8004 Agent`,
        description: `Registered agent on ${chain} with ${count} identity token(s)`,
        capabilities: [],
        verified: true,
        reputationScore: 0,
        owner: address,
      });
      return agents;
    }

    for (const tokenId of tokenIds.slice(0, 10)) {
      try {
        const tokenUri = await registry.tokenURI(tokenId);
        
        // Fetch metadata from URI
        let metadata: any = {};
        try {
          if (tokenUri.startsWith('data:')) {
            // data URI (base64 JSON)
            const json = tokenUri.includes('base64,')
              ? Buffer.from(tokenUri.split('base64,')[1], 'base64').toString()
              : decodeURIComponent(tokenUri.split(',')[1]);
            metadata = JSON.parse(json);
          } else if (tokenUri.startsWith('http') || tokenUri.startsWith('ipfs')) {
            const url = tokenUri.startsWith('ipfs://')
              ? `https://ipfs.io/ipfs/${tokenUri.slice(7)}`
              : tokenUri;
            const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
            if (res.ok) metadata = await res.json();
          }
        } catch (e) {
          console.warn(`[ERC8004] Failed to fetch metadata for token ${tokenId} on ${chain}:`, e);
        }

        // Try to get reputation
        let reputation = 0;
        try {
          const repRegistry = getReputationRegistry(chain);
          const rep = await repRegistry.getReputation(tokenId);
          reputation = Number(rep);
        } catch (e) {
          // Reputation registry might not exist on all chains
        }

        agents.push({
          address,
          chain: chain as Chain,
          source: 'erc8004',
          name: metadata.name || `Agent #${tokenId}`,
          description: metadata.description || '',
          capabilities: metadata.capabilities || metadata.skills || [],
          endpoint: metadata.endpoint || metadata.a2a_endpoint || undefined,
          metadataUri: tokenUri,
          verified: true, // Registered on-chain = verified
          reputationScore: reputation,
          tokenId: Number(tokenId),
          owner: address,
          raw: metadata,
        });
      } catch (e) {
        console.warn(`[ERC8004] Error reading token ${tokenId} for ${address} on ${chain}:`, e);
      }
    }
  } catch (e) {
    console.warn(`[ERC8004] Error resolving ${address} on ${chain}:`, e);
  }

  return agents;
}

/**
 * Resolve an ERC-8004 agent by token ID
 */
export async function resolveERC8004ByTokenId(tokenId: number, chain: string): Promise<UnifiedAgent | null> {
  const registry = getIdentityRegistry(chain);

  try {
    const owner = await registry.ownerOf(tokenId);
    const tokenUri = await registry.tokenURI(tokenId);

    let metadata: any = {};
    try {
      if (tokenUri.startsWith('data:')) {
        const json = tokenUri.includes('base64,')
          ? Buffer.from(tokenUri.split('base64,')[1], 'base64').toString()
          : decodeURIComponent(tokenUri.split(',')[1]);
        metadata = JSON.parse(json);
      } else if (tokenUri.startsWith('http') || tokenUri.startsWith('ipfs')) {
        const url = tokenUri.startsWith('ipfs://')
          ? `https://ipfs.io/ipfs/${tokenUri.slice(7)}`
          : tokenUri;
        const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
        if (res.ok) metadata = await res.json();
      }
    } catch (e) {
      // metadata fetch failed, continue with empty
    }

    let reputation = 0;
    try {
      const repRegistry = getReputationRegistry(chain);
      reputation = Number(await repRegistry.getReputation(tokenId));
    } catch (e) {}

    return {
      address: owner,
      chain: chain as Chain,
      source: 'erc8004',
      name: metadata.name || `Agent #${tokenId}`,
      description: metadata.description || '',
      capabilities: metadata.capabilities || metadata.skills || [],
      endpoint: metadata.endpoint || metadata.a2a_endpoint || undefined,
      metadataUri: tokenUri,
      verified: true,
      reputationScore: reputation,
      tokenId,
      owner,
      raw: metadata,
    };
  } catch (e) {
    return null;
  }
}

// ═══════════════════════════════════════════════════════
// SAID Resolution
// ═══════════════════════════════════════════════════════

/**
 * Resolve a Solana address against SAID Protocol
 */
export async function resolveSAIDAgent(wallet: string): Promise<UnifiedAgent | null> {
  try {
    const agent = await prisma.agent.findUnique({
      where: { wallet },
      select: {
        wallet: true,
        name: true,
        description: true,
        isVerified: true,
        reputationScore: true,
        feedbackCount: true,
        registeredAt: true,
        skills: true,
        a2aEndpoint: true,
      },
    });

    if (!agent) return null;

    return {
      address: agent.wallet,
      chain: 'solana',
      source: 'said',
      name: agent.name || 'Unnamed Agent',
      description: agent.description || '',
      capabilities: agent.skills || [],
      endpoint: agent.a2aEndpoint || `https://api.saidprotocol.com/a2a/${agent.wallet}`,
      verified: agent.isVerified,
      reputationScore: agent.reputationScore,
      saidWallet: agent.wallet,
      registeredAt: agent.registeredAt.toISOString(),
    };
  } catch (e) {
    console.warn(`[SAID] Error resolving ${wallet}:`, e);
    return null;
  }
}

// ═══════════════════════════════════════════════════════
// Universal Resolver
// ═══════════════════════════════════════════════════════

/**
 * Resolve any address across all supported chains
 */
export async function resolveAgent(address: string, chain?: string): Promise<UnifiedAgent[]> {
  const results: UnifiedAgent[] = [];

  // If chain specified, only check that chain
  if (chain) {
    if (chain === 'solana') {
      const agent = await resolveSAIDAgent(address);
      if (agent) results.push(agent);
    } else if (EVM_RPC[chain]) {
      const agents = await resolveERC8004Agent(address, chain);
      results.push(...agents);
    }
    return results;
  }

  // Auto-detect chain from address format
  const isEvmAddress = /^0x[a-fA-F0-9]{40}$/.test(address);
  const isSolanaAddress = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address);

  if (isSolanaAddress) {
    // Check SAID first
    const saidAgent = await resolveSAIDAgent(address);
    if (saidAgent) results.push(saidAgent);
  }

  if (isEvmAddress) {
    // Check major EVM chains in parallel
    const evmChains = ['ethereum', 'base', 'arbitrum', 'avalanche', 'optimism', 'polygon'];
    const evmResults = await Promise.allSettled(
      evmChains.map(c => resolveERC8004Agent(address, c))
    );
    for (const result of evmResults) {
      if (result.status === 'fulfilled') results.push(...result.value);
    }
  }

  return results;
}

// ═══════════════════════════════════════════════════════
// Cross-Chain Stats
// ═══════════════════════════════════════════════════════

export async function getERC8004Stats(chain: string): Promise<{ totalSupply: number } | null> {
  try {
    // ERC-8004 doesn't have totalSupply, estimate from recent Transfer events
    const provider = getProvider(chain);
    const registry = getIdentityRegistry(chain);
    const currentBlock = await provider.getBlockNumber();
    // Check for any mint events (from address(0)) in last 100k blocks
    const filter = registry.filters.Transfer('0x0000000000000000000000000000000000000000');
    const events = await registry.queryFilter(filter, Math.max(0, currentBlock - 100000), 'latest');
    // Rough estimate: highest token ID seen
    const maxTokenId = events.reduce((max: number, e: any) => {
      const tid = Number(e.args?.[2] || 0);
      return tid > max ? tid : max;
    }, 0);
    return { totalSupply: maxTokenId };
  } catch (e) {
    return null;
  }
}

export async function getCrossChainStats(): Promise<Record<string, any>> {
  const chains = Object.keys(EVM_RPC);
  const stats: Record<string, any> = {};

  // SAID stats
  const saidCount = await prisma.agent.count();
  stats.solana = { source: 'said', agents: saidCount };

  // EVM stats in parallel
  const evmResults = await Promise.allSettled(
    chains.map(async (chain) => {
      const s = await getERC8004Stats(chain);
      return { chain, ...s };
    })
  );

  for (const result of evmResults) {
    if (result.status === 'fulfilled' && result.value.totalSupply !== undefined) {
      stats[result.value.chain] = {
        source: 'erc8004',
        agents: result.value.totalSupply,
      };
    }
  }

  return stats;
}
