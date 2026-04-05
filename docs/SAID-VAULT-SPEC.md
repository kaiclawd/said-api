# said-vault — Delegated Signing Service for SAID Protocol
## Technical Specification v1.0
### Integration Target: SeekerClaw

Full spec received from Callum on 2026-04-05.

## Key Constants
- Service domain: vault.saidprotocol.com
- SAID Program ID: 5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G
- Metaplex Wallet: DD2DuAhys9pXo8SobXpPXEt4uVPv2HV2yhLqB5QF3Wvw
- SAID Treasury: 2XfHTeNWTjNwUmgoXaafYuqHcAAXj8F5Kjw2Bnzi4FxH
- Verification fee: 0.01 SOL
- Cost per agent: ~0.0186 SOL
- Free tier: 10,000 sigs/month/platform
- Signing fee (post-free): 0.0001 SOL/sig (tiered)

## Phase 1 Endpoints (3-5 days)
- POST /v1/platforms/register (Admin)
- POST /v1/agents/create (Platform)
- POST /v1/agents/:id/sign (Platform)
- GET /v1/agents (Platform)
- GET /v1/agents/:id (Platform)
- GET /metadata/:agent_id (Public)

## Phase 2 Endpoints
- GET /v1/platforms/balance
- GET /v1/agents/:id/balance
- MonthlyUsage tracking
- Free tier enforcement
- Webhooks
- Rate limiting

## Phase 3
- Multi-tenant policy engine
- API key rotation
- Drain detection
- Admin dashboard
