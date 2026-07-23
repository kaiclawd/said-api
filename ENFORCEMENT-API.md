# SAID Protocol — Enforcement API

> **SAID's #1 competitive differentiator:** On-chain economic enforcement (staking/slashing) for AI agents. No other agent trust protocol has this.

## Overview

The Enforcement API exposes staking and slashing data directly from the SAID on-chain program (`5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G`). This data is SAID's unique moat — while competitors like AstraSync, RNWY, and ChainAware provide scoring, NONE provide economic enforcement.

**The pitch:** *"Experian tells you an agent is untrustworthy. SAID makes the agent pay for being untrustworthy."*

## Endpoints

### `GET /api/enforcement/:wallet`

Returns the full on-chain enforcement status for an agent.

**Response:**
```json
{
  "wallet": "EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas",
  "programId": "5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G",
  "agentPda": "7xKp...",
  "stakePda": "3jWm...",
  "registered": true,
  "staked": true,
  "stakeAmountSol": 1.5,
  "stakeAmountLamports": 1500000000,
  "stakedAt": 1721443200,
  "cooldownUntil": null,
  "unstakeRequested": false,
  "isSlashed": false,
  "slashCount": 0,
  "lastSlashedAt": null,
  "isVerified": true,
  "verificationTier": 1,
  "owner": "EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas",
  "registeredAt": 1721443200,
  "enforcementTier": "economic",
  "economicSecuritySol": 1.5,
  "riskLevel": "low",
  "riskReasons": []
}
```

### `POST /api/enforcement/batch`

Batch query up to 25 wallets. Returns summary stats.

**Request:**
```json
{ "wallets": ["wallet1...", "wallet2...", "wallet3..."] }
```

**Response:**
```json
{
  "results": { "wallet1...": { ... }, "wallet2...": { ... } },
  "summary": {
    "total": 3,
    "staked": 2,
    "slashed": 0,
    "verified": 3,
    "totalStakedSol": 4.5
  }
}
```

### `GET /api/enforcement/:wallet/stake`

Lightweight staking data only.

## Enforcement Tiers

| Tier | Description | Criteria |
|------|-------------|----------|
| `economic` | Highest trust — agent has skin in the game | Staked ≥ 0.1 SOL |
| `reputation` | Medium trust — verified but no stake | IsVerified, no stake |
| `none` | Unverified, unstaked | Neither |

## Risk Levels

| Level | Criteria |
|-------|----------|
| `low` | Staked ≥ 0.5 SOL, no slashes, verified |
| `medium` | Min stake only, or unverified |
| `high` | Has been slashed once |
| `critical` | Currently slashed, or slashed ≥ 2 times |

## Integration Examples

### Pre-transaction trust check
```typescript
const response = await fetch(`https://api.saidprotocol.com/api/enforcement/${wallet}`);
const enforcement = await response.json();

if (enforcement.riskLevel === 'critical') {
  throw new Error('Agent has been slashed — refuse transaction');
}
if (enforcement.stakeAmountSol < minStake) {
  // Require escrow for low-stake agents
  escrowPercent = 100;
}
```

### Batch screening for marketplaces
```typescript
const response = await fetch('https://api.saidprotocol.com/api/enforcement/batch', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ wallets: agentWallets }),
});
const { results, summary } = await response.json();
// Filter out slashed agents
const safe = Object.entries(results).filter(([_, s]) => !s.isSlashed);
```

## On-Chain Account Structure

PDA derivation:
- **Agent Identity:** `[b"agent", owner_pubkey.as_ref()]`
- **Agent Stake:** `[b"stake", agent_identity_pda.as_ref()]`

The enforcement module reads these accounts directly via Solana RPC — no indexer or database required. Data is always real-time.
