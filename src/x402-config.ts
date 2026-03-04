// x402 Payment Configuration for SAID Cross-Chain Messaging
import { paymentMiddlewareFromConfig } from '@x402/hono';
import { ExactSvmScheme } from '@x402/svm/exact/server';

// SAID Protocol treasury wallet — receives all x402 payments
const SAID_TREASURY = process.env.SAID_TREASURY_WALLET || 'EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas';

// Price: $0.01 per message (1 cent)
const MESSAGE_PRICE = '$0.01';

// Route configuration for x402-protected endpoints
export const x402Routes = {
  'POST /xchain/message': {
    accepts: {
      scheme: 'exact',
      payTo: SAID_TREASURY,
      price: MESSAGE_PRICE,
      network: 'solana:mainnet' as const,
    },
    description: 'Send a cross-chain agent message via SAID Protocol',
    resource: 'Cross-chain agent message relay',
  },
} as const;

// Create the x402 middleware for Hono
export function createX402Middleware() {
  return paymentMiddlewareFromConfig(
    x402Routes as any,
    undefined, // Use default facilitator (x402.org)
    [
      {
        network: 'solana:mainnet' as any,
        server: new ExactSvmScheme(),
      },
    ],
    {
      appName: 'SAID Protocol — Cross-Chain Agent Communication',
    },
    undefined, // no custom paywall provider
    false, // don't sync with facilitator on start
  );
}

export { SAID_TREASURY, MESSAGE_PRICE };
