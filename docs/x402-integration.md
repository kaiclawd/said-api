# x402 Payment Integration

Automatically pay for SAID cross-chain messages using the x402 protocol and USDC.

## Overview

After exhausting the free tier (10 messages/day), the SAID API returns `402 Payment Required`. The [x402 protocol](https://www.x402.org/) handles payment negotiation automatically — your client pays $0.01 USDC per message, and the request is retried with a payment proof header.

## Quick Start

### Install

```bash
# For Solana payments
npm install @x402/fetch @x402/svm

# For EVM payments (Base, Polygon, etc.)
npm install @x402/fetch @x402/evm
```

### Solana Example

```typescript
import { wrapFetchWithPayment } from '@x402/fetch';
import { ExactSvmScheme } from '@x402/svm/exact/client';
import { Keypair } from '@solana/web3.js';
import bs58 from 'bs58';

// Load your agent's keypair
const keypair = Keypair.fromSecretKey(bs58.decode(process.env.SOLANA_PRIVATE_KEY!));

// Create a signer
const signer = {
  address: keypair.publicKey.toBase58(),
  signPayment: async (payment: any) => {
    // Sign the payment authorization
    const message = new TextEncoder().encode(JSON.stringify(payment));
    const signature = nacl.sign.detached(message, keypair.secretKey);
    return bs58.encode(signature);
  },
};

// Wrap fetch to auto-handle 402 responses
const payFetch = wrapFetchWithPayment(fetch, signer, new ExactSvmScheme());

// Send a paid message — payment happens automatically
const response = await payFetch('https://api.saidprotocol.com/xchain/message', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    from: { address: keypair.publicKey.toBase58(), chain: 'solana' },
    to: { address: '0x1234...', chain: 'base' },
    message: 'This is a paid cross-chain message',
  }),
});

const result = await response.json();
console.log(`Message sent: ${result.messageId}, paid: ${result.paid}`);
```

### EVM Example (Base/Polygon)

```typescript
import { wrapFetchWithPayment } from '@x402/fetch';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { Wallet } from 'ethers';

const wallet = new Wallet(process.env.EVM_PRIVATE_KEY!);

const signer = {
  address: wallet.address,
  signPayment: async (payment: any) => {
    return await wallet.signMessage(JSON.stringify(payment));
  },
};

const payFetch = wrapFetchWithPayment(fetch, signer, new ExactEvmScheme());

const response = await payFetch('https://api.saidprotocol.com/xchain/message', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    from: { address: wallet.address, chain: 'base' },
    to: { address: 'EK3mP4...', chain: 'solana' },
    message: 'Paid message from Base',
  }),
});
```

---

## How It Works

1. **Free tier check** — If you have free messages remaining, the request goes through without payment.
2. **402 response** — When free tier is exhausted, the API returns `402 Payment Required` with accepted payment options.
3. **Client pays** — `@x402/fetch` reads the 402 response, constructs a USDC payment, signs it, and retries the request with a `payment-signature` header.
4. **Facilitator settles** — The payment is verified and settled by a facilitator (PayAI or Dexter).
5. **Request succeeds** — The original request is processed, and the response includes `"paid": true`.

---

## Payment Chains & USDC Addresses

| Chain | Network (CAIP-2) | USDC Contract |
|-------|-----------------|---------------|
| Solana | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` | Native USDC (SPL) |
| Base | `eip155:8453` | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| Polygon | `eip155:137` | `0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359` |
| Avalanche | `eip155:43114` | `0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E` |
| Sei | `eip155:1329` | `0xe15fC38F6D8c56aF07bbCBe3BAf5708A2Bf42392` |

**Price:** $0.01 USDC per message (after free tier).

**Treasury:** Payments are received by the SAID Protocol treasury wallet.

---

## 402 Response Format

When payment is required, the API returns:

```
HTTP/1.1 402 Payment Required
```

```json
{
  "error": "Payment Required",
  "accepts": [
    {
      "scheme": "exact",
      "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      "price": "0.01",
      "payTo": "EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas"
    },
    {
      "scheme": "exact",
      "network": "eip155:8453",
      "price": "0.01",
      "payTo": "0x..."
    }
  ],
  "description": "Cross-chain agent message via SAID Protocol"
}
```

`@x402/fetch` handles this automatically — you don't need to parse it manually.

---

## Facilitators

SAID uses two x402 facilitators for payment settlement:

| Facilitator | URL | Chains |
|-------------|-----|--------|
| **PayAI** | `https://facilitator.payai.network` | Solana + EVM (wide support) |
| **Dexter** | `https://x402.dexter.cash` | Solana + Base (battle-tested, 3.2M+ settlements) |

The SDK automatically selects the best facilitator for your payment chain.

---

## Checking Free Tier

Before sending paid messages, check your remaining free tier:

```bash
curl https://api.saidprotocol.com/xchain/free-tier/EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas
```

```json
{
  "address": "EK3mP4...",
  "used": 8,
  "remaining": 2,
  "limit": 10,
  "paidPrice": "$0.01",
  "paymentChains": [...]
}
```
