# SAID Protocol — Dune dashboard

Query pack for a public Dune dashboard on the **on-chain SAID program itself**, not the
API's off-chain view. Program: [`5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G`](https://solscan.io/account/5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G).

## How the decode works

The SAID program is **not decoded on Dune** (nobody has submitted the IDL), so there are
no `said_solana.*` tables. Every query filters `solana.instruction_calls` on
`executing_account` and identifies the instruction by its Anchor discriminator — the
first 8 bytes of `sha256("global:<name>")`:

| Instruction | Discriminator (hex) | Source |
|---|---|---|
| `register_agent` | `879d42c30271af1e` | [src/index.ts:1882](../src/index.ts#L1882) |
| `get_verified` | `84e7021e734a171a` | [src/index.ts:1901](../src/index.ts#L1901) |
| `link_wallet` | `c849eeafa57d9907` | [src/index.ts:8428](../src/index.ts#L8428) |
| `unlink_wallet` | `de9d78e092ddbfc6` | [src/index.ts:8529](../src/index.ts#L8529) |
| `transfer_authority` | `65f5b3b2e6c64ca3` | [src/index.ts:8628](../src/index.ts#L8628) |
| `withdraw_fees` | `c6d4ab6d90d7ae59` | [withdraw-treasury.cjs:41](../withdraw-treasury.cjs#L41) |
| `initialize` | `afaf6d1f0d989bed` | standard Anchor constant |

Account positions used (1-indexed, as Trino arrays are):

- `register_agent` → `[agent_identity_pda, owner (signer+payer), system_program]`
- `get_verified` → `[agent_identity_pda, treasury, authority, system_program]`

The identity PDA (`account_arguments[1]`) is the join key across instructions — it is
seeded `[b"agent", owner]`, so it is stable and unique per agent.

Treasury PDA (seeds `[b"treasury"]`): `2XfHTeNWTjNwUmgoXaafYuqHcAAXj8F5Kjw2Bnzi4FxH`.

## Run order

**Run `01_instruction_census.sql` first.** It groups every call the program has ever
received by discriminator. Any row labelled `unmapped` is an instruction the decode
layer doesn't know about yet — staking, slashing, and `update_agent` are the likely
candidates, since those are read via RPC in [src/enforcement.ts](../src/enforcement.ts)
rather than built here, so their discriminators aren't in the codebase. Take the hex,
work out the name, and add it to the `CASE` in `00` and anywhere else it belongs.

Then save `00_base_decoded_instructions.sql` and reference it from the others as
`query_<ID>` if you'd rather not repeat the `CASE` block — each query below is currently
self-contained so it can be pasted and run in isolation.

## Panels

| # | Query | Viz | What it answers |
|---|---|---|---|
| 02 | `headline_scorecard` | 6 counters | Agents registered, verified, verification rate, 7d adds, distinct payers, treasury SOL |
| 03 | `growth_daily` | bars + cumulative line | Registration and verification curve, 7d smoothed |
| 04 | `sponsored_vs_self_serve` | stacked area | Platform-sponsored vs self-serve onboarding over time |
| 05 | `top_integrators` | table | Leaderboard of fee payers, with their agents' verification rate |
| 06 | `verification_funnel` | bars | Time from register to verify, incl. atomic same-tx onboarding |
| 07 | `treasury_revenue` | bars + cumulative line | Verification-fee revenue in SOL and USD, and withdrawals |
| 08 | `onboarding_cost` | line + bars | Real SOL cost per agent onboarded (rent + fee + funding) |
| 09 | `wallet_link_graph` | bars | WalletLink activity and authority transfers per week |
| 10 | `integrator_cohorts` | stacked area | Top 8 payers vs everyone else, over time |
| 11 | `concentration_check` | counters | Top-1 / top-10 payer share of all registrations |

Panels 04, 05, 10 and 11 are the ones worth leading with. Registration counts are the
easy metric and every registry has them; what nobody publishes is *who paid* and *how
concentrated it is* — and that's exactly the test SAID applies to
[ERC-8004](https://docs.dune.com/data-catalog/solana/overview) in its own positioning
(top-10 wallets own ~51% there). Publishing it first, with the number stated plainly,
is stronger than being asked for it later.

## Two caveats before this goes public

1. **On-chain count will be lower than `/api/stats`.** The API reports ~5.6k agents; the
   chain only knows about agents whose `register_agent` actually landed. Anything
   DB-only or pending anchoring won't appear. Decide which number is the public one, and
   don't let the dashboard quietly contradict the README badge.
2. **Panels 07 and 08 publish protocol revenue and unit costs.** That's fine and even
   useful, but it is a permanent public number. The 20/80 treasury split wallets are
   deliberately **not** in any query here.

## Wiring up the Dune MCP

Not connected in this session — it needs a browser OAuth round-trip, so run it from an
interactive shell:

```bash
claude mcp add --scope user --transport http dune https://api.dune.com/mcp/v1
```

Then, in an interactive session, `/mcp` to complete the sign-in. After that these
queries can be created and executed directly, and the dashboard assembled, without
leaving the terminal. Until then they're paste-ready in the Dune query editor.
