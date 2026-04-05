# SeekerClaw × SAID Protocol — Integration Guide

## What You Get

One API call. Your agent gets:

- **On-chain SAID identity** (Solana, verified)
- **Metaplex Core NFT** (in SAID agent collection)
- **Custodial wallet** (Privy enclave — private key never exposed)
- **API key** for autonomous transactions
- **Spending policy** (per-tx, daily, monthly limits)
- **Trust score** (reputation, on-chain activity)

---

## Architecture

```
SeekerClaw Device                    SAID Infrastructure
┌──────────────┐                    ┌─────────────────────┐
│              │                    │                     │
│  Agent       │  API key           │  SAID API           │
│  (Node.js)   │ ──────────────►   │  (Railway)          │
│              │                    │                     │
│  Decides to  │  POST /v1/tx/req   │  1. Validate policy │
│  pay 0.01    │ ──────────────►   │  2. Check limits    │
│  SOL         │                    │  3. Sign via Privy  │
│              │  ◄──────────────   │  4. Broadcast       │
│              │  { signature }     │                     │
│              │                    └─────────────────────┘
│  Never sees  │
│  private key │                    ┌─────────────────────┐
│              │                    │  Privy Enclave      │
└──────────────┘                    │  (private key held  │
                                    │   in secure HSM)    │
                                    └─────────────────────┘
```

---

## Setup (One-Time)

### Step 1: Register Agent

When a SeekerClaw device provisions a new agent:

```bash
POST https://api.saidprotocol.com/v1/wallet/create
Authorization: Bearer said_ak_<partner_key>
Content-Type: application/json

{
  "agentId": "<said-agent-id>",
  "name": "SeekerBot-001",
  "description": "SeekerClaw autonomous agent",
  "capabilities": ["x402", "a2a", "payments"]
}
```

**Response:**
```json
{
  "wallet": {
    "publicKey": "4pQzR8b...",
    "provider": "privy"
  },
  "apiKey": "said_ak_...",
  "identity": {
    "pda": "5bjzVh...",
    "verified": true,
    "nftAsset": "ASEgVU...",
    "collection": "2aJH9B...",
    "profile": "https://www.saidprotocol.com/agent.html?wallet=4pQzR8b..."
  },
  "policy": {
    "maxPerTransaction": 0.01,
    "dailyLimit": 0.1,
    "monthlyLimit": 1.0,
    "allowedTokens": ["SOL"]
  }
}
```

The agent stores only `publicKey` and `apiKey`. No private key ever touches the device.

### Step 2: Fund Wallet

User funds the agent wallet from their Phantom/main wallet:

```
SOL transfer → 4pQzR8b... (agent's Privy wallet)
```

Standard Solana transfer. No special flow needed.

### Step 3: Set Spending Limits

```bash
PUT https://api.saidprotocol.com/v1/policy/<agentId>
Authorization: Bearer said_ak_<partner_key>
Content-Type: application/json

{
  "maxPerTransaction": 0.01,
  "dailyLimit": 0.1,
  "monthlyLimit": 1.0,
  "allowedTokens": ["SOL", "USDC"],
  "allowedPrograms": ["*"],
  "telegramConfirm": true
}
```

---

## Runtime (Autonomous)

### Agent Pays (x402, A2A, etc.)

```bash
POST https://api.saidprotocol.com/v1/transaction/request
Authorization: Bearer said_ak_<agent_key>
Content-Type: application/json

{
  "agentId": "<agent-id>",
  "to": "<recipient-address>",
  "amount": 1000000,
  "token": "SOL",
  "memo": "x402 payment for API access",
  "idempotencyKey": "tx-unique-id-12345"
}
```

**SAID does:**
1. Validates API key
2. Checks spending policy (per-tx limit, daily limit, monthly limit)
3. Signs transaction via Privy enclave
4. Broadcasts to Solana
5. Returns signature

**Response:**
```json
{
  "requestId": "req-uuid",
  "status": "completed",
  "signature": "5d6Jx...",
  "transactionHash": "5d6Jx..."
}
```

### Check Balance

```bash
GET https://api.saidprotocol.com/v1/wallet/<agentId>
Authorization: Bearer said_ak_<agent_key>
```

**Response:**
```json
{
  "publicKey": "4pQzR8b...",
  "balance": {
    "sol": 0.48,
    "usdc": 0
  },
  "spending": {
    "today": 0.02,
    "thisMonth": 0.15,
    "dailyLimit": 0.1,
    "monthlyLimit": 1.0
  }
}
```

---

## Mapping to SeekerClaw Architecture

| SeekerClaw Concept | SAID Equivalent | Notes |
|---|---|---|
| Core NFT (identity) | Metaplex Core NFT + SAID PDA | Auto-minted on registration |
| PDA wallet | Privy embedded wallet | Same "prepaid card" model |
| Executive Keypair | SAID API key (`said_ak_...`) | Revocable, rotatable |
| Android Keystore | Privy HSM enclave | More secure — not on device |
| App-side limits | Server-side TransactionPolicy | Can't be bypassed by prompt injection |
| MWA approve (setup) | One API call | No wallet adapter needed |
| MWA approve (fund) | Standard SOL transfer | Same UX |
| Kill switch (revoke) | `POST /v1/apikey/revoke` | Instant, server-side |
| Key rotation | `POST /v1/apikey/generate` + revoke old | No MWA tap needed |

---

## Security Model

### What's at risk if API key is compromised?

| Asset | At Risk? | Why |
|---|---|---|
| Agent wallet balance | YES — but capped by policy | Attacker limited to spending limits |
| User's main wallet | No | SAID has no access |
| Agent identity (NFT) | No | API key can't transfer NFTs |
| Reputation / history | No | On-chain, immutable |

### Defense layers

| Layer | Description |
|---|---|
| Spending limits | Server-enforced per-tx, daily, monthly caps |
| API key rotation | Generate new key, revoke old — instant |
| Kill switch | Revoke API key → agent can't spend |
| Privy enclave | Private key in HSM, never exposed |
| Idempotency keys | Prevents replay attacks / double-spend |
| Rate limiting | Per-key request throttling |
| Telegram confirm | Optional: notify user before large payments |

---

## Device Change / Reinstall

Agent identity and wallet survive. Only the API key needs regenerating.

1. Install SeekerClaw
2. Connect same user account
3. Agent identity auto-detected (on-chain NFT + SAID PDA)
4. Generate NEW API key via SAID
5. Old key automatically revoked
6. Wallet balance, identity, reputation — all intact

---

## Endpoints Reference

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| POST | `/v1/wallet/create` | Partner key | Provision wallet for agent |
| GET | `/v1/wallet/:agentId` | Agent key | Get wallet + balance |
| POST | `/v1/wallet/upgrade` | Session | Add wallet to existing agent |
| POST | `/v1/transaction/request` | Agent key | Request transaction signing |
| GET | `/v1/transaction/status/:id` | Agent key | Check tx status |
| POST | `/v1/transaction/cancel` | Agent key | Cancel pending tx |
| GET | `/v1/policy/:agentId` | Agent key | Get spending policy |
| PUT | `/v1/policy/:agentId` | Partner key | Update spending limits |
| POST | `/v1/apikey/generate` | Session | Generate new API key |
| POST | `/v1/apikey/revoke` | Session | Revoke API key |

---

## Getting Started

1. **Contact SAID team** → receive partner API key
2. **Register first agent** → `POST /v1/wallet/create`
3. **Fund wallet** → standard SOL transfer
4. **Set policy** → `PUT /v1/policy/:agentId`
5. **Start transacting** → `POST /v1/transaction/request`

**API Base:** `https://api.saidprotocol.com`
**Support:** contact@saidprotocol.com
**Docs:** https://docs.saidprotocol.com
