# SAID Vault — SeekerClaw Integration Guide

## Base URL
```
https://api.saidprotocol.com
```

## Authentication
All requests require:
```
X-Platform-Key: <your-api-key>
```

---

## Endpoints

### 1. Provision Agent
**`POST /api/platforms/seekerclaw/provision`**

Creates a custodial wallet, registers SAID identity on-chain, verifies it, and mints an identity NFT — all in one call.

**Request:**
```json
{
  "agent_name": "MyAgent-001",
  "metadata": {
    "device_id": "seeker-device-abc123",
    "capabilities": ["payments", "x402"]
  }
}
```

**Response:**
```json
{
  "success": true,
  "agent": {
    "id": "cmnm77rlm...",
    "wallet": "FSWQ...",
    "pda": "CoNa...",
    "name": "MyAgent-001",
    "status": "verified",
    "nft_address": "aRmx...",
    "profile": "https://www.saidprotocol.com/agent.html?wallet=...",
    "badge": "https://api.saidprotocol.com/api/badge/....svg"
  },
  "privy_wallet": {
    "public_key": "FSWQ...",
    "provider": "privy"
  },
  "on_chain": {
    "register_tx": "2ysX...",
    "explorer": "https://solscan.io/tx/...",
    "verification_fee_paid": "0.01 SOL"
  },
  "cost": {
    "total_sol": 0.019,
    "breakdown": {
      "pda_rent": "~0.005 SOL",
      "verification_fee": "0.01 SOL (→ SAID treasury)",
      "nft_mint_rent": "~0.004 SOL",
      "tx_fees": "~0.00002 SOL"
    }
  }
}
```

**Notes:**
- Idempotent: same `device_id` returns existing agent with `"already_provisioned": true`
- Cost: ~0.019 SOL per agent (funded from SAID sponsor wallet)
- Each agent receives: Solana wallet, on-chain SAID identity (PDA), Metaplex NFT, profile page, SVG badge

---

### 2. Sign Transaction
**`POST /api/platforms/seekerclaw/sign`**

Send an unsigned base64-encoded Solana transaction. We sign it with the agent's custodial wallet and return the signed transaction. You broadcast it to any Solana RPC.

**Request:**
```json
{
  "agent_id": "cmnm77rlm...",
  "transaction": "<base64-encoded-unsigned-tx>",
  "description": "Swap 0.1 SOL for USDC"
}
```

**Response:**
```json
{
  "success": true,
  "signed_transaction": "<base64-signed-tx>",
  "signature": "5vec...",
  "fee_charged_sol": 0,
  "agent_signatures_this_month": 3,
  "agent_free_remaining": 7,
  "platform_signatures_this_month": 14,
  "submitted": false
}
```

**Notes:**
- `fee_charged_sol` is always returned: `0` when within free tier, `0.0001+` when paid
- `submitted: false` — you broadcast the `signed_transaction` yourself via `sendTransaction`
- When a signing fee applies, it's appended as an additional instruction to the transaction before signing (atomic — guaranteed collection)
- If agent has insufficient balance for the fee: returns `402` with `INSUFFICIENT_FUNDS`

---

### 3. Get Single Agent
**`GET /api/platforms/seekerclaw/agents/:agent_id`**

Returns agent status, on-chain wallet balance, and monthly signature usage.

**Response:**
```json
{
  "agent_id": "cmnm77rlm...",
  "wallet": "FSWQ...",
  "pda": "CoNa...",
  "name": "MyAgent-001",
  "status": "verified",
  "nft_address": "aRmx...",
  "balance_sol": 0.002,
  "created_at": "2026-04-05T20:12:59.387Z",
  "usage": {
    "month": "2026-04",
    "signatures": 11,
    "free_remaining": 0,
    "fees_paid_sol": 0.0001
  },
  "profile": "https://www.saidprotocol.com/agent.html?wallet=...",
  "badge": "https://api.saidprotocol.com/api/badge/....svg"
}
```

---

### 4. List Agents
**`GET /api/platforms/seekerclaw/agents`**

Query params: `?limit=50&offset=0&status=verified`

Returns paginated list of all provisioned SeekerClaw agents.

---

### 5. Check Balance & Usage
**`GET /api/platforms/seekerclaw/balance`**

Returns sponsor wallet capacity, agents created, platform-wide signature count, fees collected, and current volume pricing tier.

---

## Pricing

| Item | Cost |
|------|------|
| Agent provisioning | ~0.019 SOL per agent |
| Signing — first 10 per agent per month | Free |
| Signing — up to 100K/month (platform total) | 0.0001 SOL/sig (~$0.015) |
| Signing — 100K–1M/month | 0.00008 SOL/sig |
| Signing — 1M+/month | 0.00005 SOL/sig |

**Free tier:** 10 signatures per agent per month. Enough to test basic functionality (a few transfers, balance checks). Active agents generating even 1 tx/day will be in the paid tier.

**Volume discounts** are based on total platform-wide signatures per month, not per-agent.

**Fee collection** is atomic: the signing fee is appended as a `SystemProgram.transfer` instruction to the transaction before the custodial wallet signs it. No separate billing, no invoices — guaranteed on-chain collection.

---

## What Each Agent Gets

| Feature | Detail |
|---------|--------|
| Solana wallet | Privy custodial — no seed phrase, server-side signing |
| SAID identity | On-chain PDA — verified, discoverable via SAID directory |
| Metaplex NFT | Owned by agent's wallet — proof of identity |
| Profile page | `saidprotocol.com/agent.html?wallet=...` |
| SVG badge | `api.saidprotocol.com/api/badge/....svg` |

---

## Integration Flow

```
1. PROVISION (once per device)
   SeekerClaw → POST /provision → Agent created (wallet + identity + NFT)

2. SIGN (every transaction)
   SeekerClaw builds unsigned tx → POST /sign → Signed tx returned
   SeekerClaw broadcasts signed tx → Solana RPC

3. MONITOR (as needed)
   GET /agents/:agent_id → Balance, usage, status
   GET /balance → Platform-wide stats
```

---

## Error Codes

| Code | HTTP | Meaning |
|------|------|---------|
| `INVALID_TRANSACTION` | 400 | Transaction failed to deserialize |
| `INSUFFICIENT_FUNDS` | 402 | Agent wallet can't cover signing fee |
| `AGENT_NOT_FOUND` | 404 | Agent ID doesn't exist or isn't SeekerClaw |
| `WALLET_NOT_FOUND` | 404 | Agent has no wallet configured |

---

## Support

- Website: https://www.saidprotocol.com
- API Status: https://api.saidprotocol.com/api/stats
- Twitter: @saidinfra
