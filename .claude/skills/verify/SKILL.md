---
name: verify
description: Verify said-api changes end-to-end against a scratch Postgres — boot the real server locally and drive routes with curl.
---

# Verifying said-api changes

## Handle

Local Postgres 16 runs via Homebrew (`brew services list`). Boot the real
server against a scratch DB — never against the `.env` DATABASE_URL (prod
Supabase), and never run `npm run start` locally (it runs
`prisma db push --accept-data-loss` against whatever DATABASE_URL points at).

```bash
createdb said_verify_scratch
DATABASE_URL="postgresql://callum@localhost:5432/said_verify_scratch" npx prisma db push --skip-generate
DATABASE_URL="postgresql://callum@localhost:5432/said_verify_scratch" ADMIN_SECRET=vk PORT=3999 npx tsx src/index.ts
# ready ~1s: curl localhost:3999/api/leaderboard → 200
# cleanup: pkill -f "tsx src/index.ts"; dropdb said_verify_scratch
```

Env vars set in the shell win over `.env` (dotenv doesn't overwrite).
Partner keys for the outcome doors: `PARTNER_SOURCE_KEYS="name:key:weight"`.

## Gotchas

- Boot kicks off an anchor-sync that pulls the real on-chain registry into
  the scratch DB (chain reads only — harmless, takes a minute, populates
  real agents).
- Feedback.fromWallet has an FK to Agent.wallet — seed writers as agents.
  The system wallet `72onvrQJZkPGLAhWK5MeYc73iyM72P2ABKzDMQ4NpQBL` must
  exist for the partner doors. Agent inserts need `updatedAt`.
- Signed peer feedback: message is `SAID:feedback:<toWallet>:<score>:<timestamp>`,
  nacl-sign with a generated Keypair, bs58 signature, timestamp within 5 min.
- Admin routes: `x-admin-secret` header; wrong secret returns 404 by design.
- The reputation scorer lives on `feat/reputation-v0.8` (deployed by cron
  box) — schema changes to shared tables must land on BOTH branches, since
  both deploys run `db push --accept-data-loss`.
