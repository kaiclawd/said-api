// Custom x402 Payment Handler for SAID Cross-Chain Messaging
// Instead of using the @x402/hono SDK (which has runtime issues),
// we implement the x402 flow directly: return 402 with payment instructions,
// then verify the Solana USDC transfer before allowing the message.

import type { Context, Next } from 'hono';
import { Connection, PublicKey } from '@solana/web3.js';

// SAID Protocol treasury wallet — receives all x402 payments
export const SAID_TREASURY = process.env.SAID_TREASURY_WALLET || 'EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas';

// USDC mint on Solana mainnet
const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';

// Price per message in USDC (raw units, 6 decimals)
const MESSAGE_PRICE_USDC = 10000; // 0.01 USDC = 10000 raw units
export const MESSAGE_PRICE = '$0.01';

// Solana RPC
const RPC_URL = process.env.QUICKNODE_RPC || process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
const connection = new Connection(RPC_URL, 'confirmed');

// Cache of verified payment signatures to prevent replay
const verifiedPayments = new Set<string>();

// Cleanup old payments every hour (keep last 10k)
setInterval(() => {
  if (verifiedPayments.size > 10000) {
    const arr = [...verifiedPayments];
    verifiedPayments.clear();
    arr.slice(-5000).forEach(s => verifiedPayments.add(s));
  }
}, 3600000);

/**
 * Verify a Solana transaction is a valid USDC payment to our treasury
 */
async function verifyPayment(signature: string, expectedSender?: string): Promise<{ valid: boolean; sender?: string; error?: string }> {
  // Check for replay
  if (verifiedPayments.has(signature)) {
    return { valid: false, error: 'Payment signature already used' };
  }

  try {
    const tx = await connection.getParsedTransaction(signature, {
      maxSupportedTransactionVersion: 0,
      commitment: 'confirmed',
    });

    if (!tx) {
      return { valid: false, error: 'Transaction not found. It may not be confirmed yet.' };
    }

    if (tx.meta?.err) {
      return { valid: false, error: 'Transaction failed on-chain' };
    }

    // Check transaction age (must be within last 5 minutes)
    const txTime = tx.blockTime;
    if (txTime && Date.now() / 1000 - txTime > 300) {
      return { valid: false, error: 'Transaction too old (>5 minutes)' };
    }

    // Look for a USDC transfer to our treasury in the inner instructions or token transfers
    const preBalances = tx.meta?.preTokenBalances || [];
    const postBalances = tx.meta?.postTokenBalances || [];

    // Find treasury's USDC balance change
    let treasuryReceived = 0;
    let senderAddress: string | undefined;

    for (const post of postBalances) {
      if (post.mint === USDC_MINT && post.owner === SAID_TREASURY) {
        const pre = preBalances.find(
          p => p.accountIndex === post.accountIndex && p.mint === USDC_MINT
        );
        const preAmount = pre ? Number(pre.uiTokenAmount.amount) : 0;
        const postAmount = Number(post.uiTokenAmount.amount);
        treasuryReceived = postAmount - preAmount;
      }
    }

    // Find sender (first signer)
    const signers = tx.transaction.message.accountKeys.filter(k => k.signer);
    if (signers.length > 0) {
      senderAddress = signers[0].pubkey.toString();
    }

    if (treasuryReceived < MESSAGE_PRICE_USDC) {
      return {
        valid: false,
        error: `Insufficient payment. Expected ${MESSAGE_PRICE_USDC} USDC units (${MESSAGE_PRICE}), received ${treasuryReceived}`,
      };
    }

    // Verify sender matches if specified
    if (expectedSender && senderAddress && senderAddress !== expectedSender) {
      return {
        valid: false,
        error: `Payment sender (${senderAddress}) does not match message sender (${expectedSender})`,
        sender: senderAddress,
      };
    }

    // Mark as used
    verifiedPayments.add(signature);

    return { valid: true, sender: senderAddress };
  } catch (e: any) {
    return { valid: false, error: `Verification failed: ${e.message}` };
  }
}

/**
 * x402 middleware for Hono
 * 
 * Flow:
 * 1. Check for X-PAYMENT header (contains payment signature)
 * 2. If missing → return 402 Payment Required with instructions
 * 3. If present → verify the Solana USDC transfer
 * 4. If valid → allow request through
 * 5. If invalid → return 402 with error
 */
export function x402PaymentMiddleware() {
  return async (c: Context, next: Next) => {
    const paymentHeader = c.req.header('X-PAYMENT') || c.req.header('x-payment');

    if (!paymentHeader) {
      // Return 402 Payment Required
      return c.json({
        status: 402,
        protocol: 'x402',
        version: 1,
        error: 'Payment Required',
        paymentInstructions: {
          chain: 'solana',
          network: 'mainnet-beta',
          token: 'USDC',
          tokenMint: USDC_MINT,
          recipient: SAID_TREASURY,
          amount: MESSAGE_PRICE_USDC,
          amountReadable: MESSAGE_PRICE,
          description: 'Cross-chain agent message via SAID Protocol',
          steps: [
            `1. Send ${MESSAGE_PRICE} USDC to ${SAID_TREASURY} on Solana mainnet`,
            '2. Include the transaction signature in the X-PAYMENT header',
            '3. Retry your request with the X-PAYMENT header',
          ],
          note: 'The transaction signer must match the from.address in your message for Solana senders.',
        },
      }, 402);
    }

    // Verify payment
    // Note: Don't read body here — Hono only allows one json() read
    // Sender verification happens post-hoc if needed
    const result = await verifyPayment(paymentHeader);

    if (!result.valid) {
      return c.json({
        status: 402,
        protocol: 'x402',
        error: 'Payment verification failed',
        details: result.error,
        paymentInstructions: {
          chain: 'solana',
          network: 'mainnet-beta',
          token: 'USDC',
          tokenMint: USDC_MINT,
          recipient: SAID_TREASURY,
          amount: MESSAGE_PRICE_USDC,
          amountReadable: MESSAGE_PRICE,
        },
      }, 402);
    }

    // Payment verified — attach sender info to context and continue
    c.set('x402_sender' as any, result.sender);
    c.set('x402_payment' as any, paymentHeader);

    await next();
  };
}
