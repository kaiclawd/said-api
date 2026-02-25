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
# Force rebuild
