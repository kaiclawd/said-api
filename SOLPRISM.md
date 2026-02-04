# SOLPRISM × SAID Protocol Integration

**Verifiable AI Reasoning for Agent Identity & Reputation**

## What This Adds

[SOLPRISM](https://github.com/basedmereum/axiom-protocol) is a commit-reveal protocol for verifiable AI reasoning on Solana. This integration adds **reasoning commitments** to key SAID Protocol actions, answering not just _"who is this agent?"_ but _"why did this agent act?"_.

### The Synergy

| SAID Protocol | SOLPRISM | Together |
|--------------|----------|----------|
| **Who** is this agent? | **Why** did the agent act? | Full trust profile |
| Identity verification | Reasoning verification | Complete accountability |
| Reputation scores | Decision audit trails | Trustworthy AI agents |

## How It Works

1. **Before** a key action (feedback, trust check, source event), SOLPRISM creates a reasoning trace documenting the decision logic
2. The trace is hashed (SHA-256) and committed — this is the **pre-commitment**
3. The action executes normally (zero changes to existing SAID logic)
4. The hash can be verified later against the full reasoning trace

```
Agent submits feedback → SOLPRISM commits reasoning hash → SAID processes feedback → Hash verifiable forever
```

## Setup

### 1. Environment Variables

Add to your `.env`:

```bash
# Enable SOLPRISM reasoning commitments
SOLPRISM_ENABLED=true
SOLPRISM_AGENT_NAME=said-api

# Optional: keypair for onchain commits (hash-only mode works without this)
# SOLPRISM_KEYPAIR_PATH=/path/to/solana-keypair.json
```

### 2. No Code Changes Required

The integration initializes automatically when `SOLPRISM_ENABLED=true` is set. If not set, everything works exactly as before — SOLPRISM is a pure opt-in addition.

## What Gets Committed

| SAID Action | SOLPRISM Trace | Why |
|-------------|----------------|-----|
| Feedback submission | Score, weight, verification status | Prove reputation updates are legitimate |
| Trust verification | Trust tier calculation logic | Show how trust was determined |
| Source feedback | Event type, score change, source | Audit platform-submitted reputation data |

## API Response Enhancement

When SOLPRISM is enabled, relevant API responses include a `solprism` field:

```json
{
  "success": true,
  "feedback": { ... },
  "solprism": {
    "hash": "a1b2c3d4...",
    "timestamp": 1706000000000,
    "actionType": "feedback"
  }
}
```

## Verification

Anyone can verify a SOLPRISM commitment:

```typescript
import { hashTrace } from './src/solprism';

// Given the original reasoning trace and the committed hash:
const computedHash = hashTrace(trace);
const isValid = computedHash === committedHash;
// true = the reasoning was NOT tampered with
```

## Architecture

```
┌─────────────────────────────────────────────┐
│                SAID API (Hono)              │
│                                             │
│  ┌─────────┐   ┌──────────┐   ┌─────────┐  │
│  │Feedback │   │  Trust   │   │ Source  │  │
│  │Endpoint │   │  Check   │   │Feedback │  │
│  └────┬────┘   └────┬─────┘   └────┬────┘  │
│       │              │              │        │
│       ▼              ▼              ▼        │
│  ┌──────────────────────────────────────┐   │
│  │     SolprismIntegration (optional)   │   │
│  │  - Creates reasoning traces          │   │
│  │  - Hashes & commits pre-action       │   │
│  │  - Zero impact if disabled           │   │
│  └──────────────────────────────────────┘   │
│                     │                        │
└─────────────────────┼────────────────────────┘
                      │
                      ▼
          ┌──────────────────────┐
          │  SOLPRISM Program    │
          │  (Solana Devnet)     │
          │  CZcvor...QeBu      │
          └──────────────────────┘
```

## Links

- **SOLPRISM SDK**: [`@solprism/sdk@0.1.0`](https://github.com/basedmereum/axiom-protocol/tree/main/sdk)
- **SOLPRISM Program**: `CZcvoryaQNrtZ3qb3gC1h9opcYpzEP1D9Mu1RVwFQeBu`
- **Integration Source**: `src/solprism.ts`

## Zero Risk

- ✅ No changes to existing SAID business logic
- ✅ Graceful no-op when disabled
- ✅ No new runtime dependencies required
- ✅ Uses crypto module already available in Node.js
- ✅ No breaking changes to any API contract
