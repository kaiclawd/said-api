// x402 Payment Gate for SAID Cross-Chain Messaging
// Powered by Coinbase x402 SDK + PayAI Facilitator
// Supports: Solana + EVM chains (Base, Polygon, Avalanche, Sei, IoTeX, Peaq, XLayer)

import { paymentMiddleware, paymentMiddlewareFromHTTPServer, x402ResourceServer, x402HTTPResourceServer } from '@x402/hono';
import { ExactSvmScheme } from '@x402/svm/exact/server';
import { ExactEvmScheme } from '@x402/evm/exact/server';
import { HTTPFacilitatorClient } from '@x402/core/server';
import type { Context, Next } from 'hono';

// ── Config ──────────────────────────────────────────────────────────────────

// SAID Protocol treasury wallet (Solana)
export const SAID_TREASURY = process.env.SAID_TREASURY_WALLET || 'EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas';

// EVM treasury wallet (receives USDC on EVM chains)
export const SAID_EVM_TREASURY = process.env.SAID_EVM_TREASURY || '';

// Price per message
export const MESSAGE_PRICE = '$0.01';
const MESSAGE_PRICE_USDC = '0.01';

// CAIP-2 network identifiers
const CHAINS = {
  solana: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' as const,
  base: 'eip155:8453' as const,
  polygon: 'eip155:137' as const,
  avalanche: 'eip155:43114' as const,
  sei: 'eip155:1329' as const,
  iotex: 'eip155:4689' as const,
  peaq: 'eip155:3338' as const,
  xlayer: 'eip155:196' as const,
};

// PayAI facilitator
const PAYAI_FACILITATOR_URL = 'https://facilitator.payai.network';

// ── Free Tier ───────────────────────────────────────────────────────────────

const FREE_MESSAGES_PER_DAY = 10;

// In-memory rate limit counter: { "address:date" → count }
const freeTierUsage = new Map<string, number>();

// Cleanup daily counters every hour
setInterval(() => {
  const today = new Date().toISOString().slice(0, 10);
  for (const key of freeTierUsage.keys()) {
    if (!key.endsWith(today)) {
      freeTierUsage.delete(key);
    }
  }
}, 3600000);

function getFreeTierKey(address: string): string {
  const today = new Date().toISOString().slice(0, 10);
  return `${address}:${today}`;
}

function hasFreeTierRemaining(address: string): boolean {
  const key = getFreeTierKey(address);
  const used = freeTierUsage.get(key) || 0;
  return used < FREE_MESSAGES_PER_DAY;
}

function consumeFreeTier(address: string): void {
  const key = getFreeTierKey(address);
  freeTierUsage.set(key, (freeTierUsage.get(key) || 0) + 1);
}

function getFreeTierInfo(address: string): { used: number; remaining: number; limit: number } {
  const key = getFreeTierKey(address);
  const used = freeTierUsage.get(key) || 0;
  return { used, remaining: Math.max(0, FREE_MESSAGES_PER_DAY - used), limit: FREE_MESSAGES_PER_DAY };
}

// ── Custom x402 Middleware with Free Tier ────────────────────────────────────

/**
 * Create x402 payment middleware with integrated free tier.
 * 
 * Flow:
 *   1. Check if sender has free messages remaining → grant access
 *   2. If no free tier left → require x402 USDC payment
 *   3. Supports Solana + EVM chains via PayAI facilitator
 */
export function createX402Middleware() {
  const facilitator = new HTTPFacilitatorClient({
    url: PAYAI_FACILITATOR_URL,
  });

  // Build payment options
  const solanaOption = {
    scheme: 'exact' as const,
    network: CHAINS.solana,
    price: MESSAGE_PRICE_USDC,
    payTo: SAID_TREASURY,
  };

  const acceptOptions: Array<{ scheme: 'exact'; network: `${string}:${string}`; price: string; payTo: string }> = [solanaOption];

  // Add EVM chains if treasury is configured
  if (SAID_EVM_TREASURY && !SAID_EVM_TREASURY.startsWith('0x000000000')) {
    const evmChains = Object.entries(CHAINS).filter(([name]) => name !== 'solana');
    for (const [_, network] of evmChains) {
      acceptOptions.push({
        scheme: 'exact' as const,
        network,
        price: MESSAGE_PRICE_USDC,
        payTo: SAID_EVM_TREASURY,
      });
    }
    console.log(`✅ EVM payment chains enabled: ${evmChains.map(([n]) => n).join(', ')}`);
  } else {
    console.log('ℹ️  EVM payment chains disabled (set SAID_EVM_TREASURY to enable)');
  }

  const routes = {
    'POST /xchain/message': {
      accepts: acceptOptions,
      description: 'Cross-chain agent message via SAID Protocol',
    },
  };

  // Create the resource server manually so we can add the free tier hook
  const resourceServer = new x402ResourceServer([facilitator]);
  resourceServer.register('solana:*' as any, new ExactSvmScheme());
  resourceServer.register('eip155:*' as any, new ExactEvmScheme());

  const httpServer = new x402HTTPResourceServer(resourceServer, routes);

  // Free tier hook: grant access if sender has remaining free messages
  httpServer.onProtectedRequest(async (context) => {
    try {
      const body = await context.adapter.getBody?.() as any;
      const senderAddress = body?.from?.address;

      if (senderAddress && hasFreeTierRemaining(senderAddress)) {
        consumeFreeTier(senderAddress);
        const info = getFreeTierInfo(senderAddress);
        console.log(`🆓 Free tier: ${senderAddress} (${info.remaining} left today)`);
        return { grantAccess: true };
      }
    } catch {
      // Can't parse body — require payment
    }
    return undefined; // Continue to x402 payment check
  });

  return paymentMiddlewareFromHTTPServer(httpServer);
}

// ── Exports ─────────────────────────────────────────────────────────────────

export { getFreeTierInfo, CHAINS, FREE_MESSAGES_PER_DAY };
