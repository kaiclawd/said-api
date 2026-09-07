# SAID Identity — partner integration

Read an AI agent's **identity** and **reputation** by a stable, opaque id.
No wallet handling, no chain knowledge required — it's a trust lookup. The
crypto (Solana wallet/pda) is the verifiable anchor underneath, exposed only
when you ask for it.

## REST

```bash
# By SAID id (or wallet / pda — whatever you have)
curl https://api.saidprotocol.com/api/identity/cmmwv5y5q01whoh482p337uhe

# Opt into the verifiable on-chain anchor
curl "https://api.saidprotocol.com/api/identity/cmmwv5y5q01whoh482p337uhe?include=onchain"
```

Default response (note: no wallet, no chain):

```json
{
  "id": "cmmwv5y5q01whoh482p337uhe",
  "name": "MEME Factory",
  "description": "Creative AI agent",
  "image": "https://…",
  "verified": true,
  "reputation": { "score": 62.3, "tier": "bronze", "badges": ["verified","trusted"], "feedbackCount": 26, "scored": true },
  "capabilities": { "serviceTypes": [], "skills": [], "a2a": null, "mcp": null },
  "registeredAt": "2026-03-19T02:37:43.000Z"
}
```

## TypeScript SDK

```ts
import { SaidIdentity } from './said-identity';
const said = new SaidIdentity();

const agent = await said.get(agentId);              // identity + reputation
const ok = await said.meetsReputation(agentId, 60); // reputation-gate in one line
```

## MCP

`said-identity-mcp.ts` exposes two tools — `said_lookup_identity` and
`said_check_reputation` — for MCP-native agents. `npm i @modelcontextprotocol/sdk`
then run it and add to your `mcpServers`.

## Why id, not wallet

- **No crypto tell** — `cmmwv5y5q…` reads like any SaaS id.
- **No data leak** — a raw wallet exposes the agent's full on-chain balance and
  history on a block explorer. The id exposes nothing.
- **Survives key rotation** — identity is stable even if the underlying wallet
  changes. Verifiability stays available via `?include=onchain`.
