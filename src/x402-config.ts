// x402 Payment Gate for SAID Cross-Chain Messaging
// Powered by Coinbase x402 SDK + PayAI Facilitator (Solana)

import { paymentMiddlewareFromConfig } from '@x402/hono';
import { ExactSvmScheme } from '@x402/svm/exact/server';
import { HTTPFacilitatorClient } from '@x402/core/server';

// SAID Protocol treasury wallet
export const SAID_TREASURY = process.env.SAID_TREASURY_WALLET || 'EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas';

// Price per message
export const MESSAGE_PRICE = '$0.01';
const MESSAGE_PRICE_USDC = '0.01'; // Human-readable for SDK

// CAIP-2 network identifier for Solana mainnet
const SOLANA_MAINNET = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' as const;

// PayAI facilitator (supports Solana x402 verification + settlement)
const PAYAI_FACILITATOR_URL = 'https://facilitator.payai.network';

/**
 * Create x402 payment middleware using Coinbase SDK + PayAI facilitator.
 * 
 * Returns Hono middleware that gates POST /xchain/message with $0.01 USDC payment.
 * Payment flow:
 *   1. Client sends request without payment → gets 402 + payment requirements
 *   2. Client signs USDC transfer, encodes as PAYMENT-SIGNATURE header
 *   3. PayAI facilitator verifies + settles the payment
 *   4. Request proceeds to handler
 */
export function createX402Middleware() {
  const facilitator = new HTTPFacilitatorClient({
    url: PAYAI_FACILITATOR_URL,
  });

  const routes = {
    'POST /xchain/message': {
      accepts: {
        scheme: 'exact',
        network: SOLANA_MAINNET,
        price: MESSAGE_PRICE_USDC,
        payTo: SAID_TREASURY,
      },
      description: 'Cross-chain agent message via SAID Protocol',
    },
  };

  const schemes = [
    { network: 'solana:*' as const, server: new ExactSvmScheme() },
  ];

  return paymentMiddlewareFromConfig(
    routes,
    [facilitator],
    schemes,
  );
}
