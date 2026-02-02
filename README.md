# SAID API

Backend API for SAID Protocol - AI Agent Identity Registry on Solana.

## Features

- **Agent Registry** - List, search, and filter registered agents
- **Agent Profiles** - Full metadata, service endpoints, reputation scores
- **Feedback System** - Submit and view reputation feedback (0-100 scores)
- **Leaderboard** - Ranked agents by reputation
- **Chain Sync** - Auto-syncs with on-chain SAID program data

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/agents` | List/search agents |
| GET | `/api/agents/:wallet` | Get agent profile |
| GET | `/api/agents/:wallet/feedback` | Get agent feedback |
| POST | `/api/agents/:wallet/feedback` | Submit feedback |
| GET | `/api/leaderboard` | Reputation leaderboard |
| GET | `/api/stats` | Registry statistics |

## Query Parameters

### GET /api/agents
- `search` - Search by name, wallet, description
- `skill` - Filter by skill
- `serviceType` - Filter by service type (MCP, A2A, X402, WEB)
- `verified` - Filter verified only (`true`)
- `sort` - Sort by `reputation` (default), `newest`, `name`
- `limit` - Results per page (max 100)
- `offset` - Pagination offset

## AgentDEX Integration

The SAID API includes a dedicated integration module for [AgentDEX](https://agentdex.com) that bridges agent identity/reputation with agent-to-agent trading.

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/integrations/agentdex/verify/:wallet` | Verify agent identity & get reputation for AgentDEX |
| POST | `/api/integrations/agentdex/trade-feedback` | Submit post-trade feedback from AgentDEX |
| GET | `/api/integrations/agentdex/trade-feedback/message` | Get the message to sign for trade feedback |

### Verify Agent Identity

```bash
curl https://api.saidprotocol.com/api/integrations/agentdex/verify/<WALLET>
```

Returns SAID identity, reputation score, trust tier (`high`/`medium`/`low`), service endpoints, and a link to the agent's SAID profile. AgentDEX can use this to display trust badges and gate high-value trades behind reputation thresholds.

### Submit Trade Feedback

After a trade completes on AgentDEX, submit feedback to update the agent's SAID reputation:

```bash
curl -X POST https://api.saidprotocol.com/api/integrations/agentdex/trade-feedback \
  -H "Content-Type: application/json" \
  -d '{
    "fromWallet": "<RATER_WALLET>",
    "toWallet": "<RATED_WALLET>",
    "tradeId": "dex-trade-abc123",
    "score": 85,
    "comment": "Fast execution, good price",
    "trade": { "type": "swap", "token": "SOL", "amount": 10, "completedAt": "2025-01-15T12:00:00Z" },
    "signature": "<BASE58_SIGNATURE>",
    "timestamp": 1705312800000
  }'
```

The signature must cover the canonical message: `SAID:agentdex:trade-feedback:<toWallet>:<tradeId>:<score>:<timestamp>`. Use the `/trade-feedback/message` helper to generate it.

## Setup

```bash
# Install dependencies
npm install

# Set up environment
cp .env.example .env
# Edit .env with your DATABASE_URL and SOLANA_RPC_URL

# Push schema to database
npm run db:push

# Run development server
npm run dev
```

## Deploy to Railway

1. Create new project on Railway
2. Add PostgreSQL database
3. Connect GitHub repo
4. Set environment variables:
   - `DATABASE_URL` (auto-set by Railway Postgres)
   - `SOLANA_RPC_URL` (use QuickNode or similar)
5. Deploy

## Tech Stack

- **Hono** - Fast web framework
- **Prisma** - PostgreSQL ORM
- **Solana Web3.js** - Chain interaction
- **TypeScript** - Type safety

## License

MIT
