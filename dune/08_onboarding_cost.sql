-- SAID Protocol — what it costs to put an agent on chain
-- Viz: line chart (avg_sol_per_agent) + bar (total_sol_spent)
--
-- Sums the actual SOL debited from the fee payer on every transaction that contains a
-- register_agent: PDA rent + the 0.01 SOL verification fee (when bundled) + network fee
-- + any funding transfer to the agent wallet. This is the real unit economics of
-- onboarding, and for sponsored registrations it is the integrator's cost, not the
-- agent's.

WITH reg_tx AS (
    SELECT
        block_date,
        tx_id,
        tx_signer,
        COUNT(DISTINCT account_arguments[1]) AS agents_in_tx
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
      AND bytearray_substring(data, 1, 8) = 0x879d42c30271af1e
    GROUP BY 1, 2, 3
),

payer_spend AS (
    SELECT
        t.block_date,
        t.tx_id,
        t.agents_in_tx,
        -aa.balance_change / 1e9 AS sol_spent
    FROM reg_tx t
    JOIN solana.account_activity aa
      ON aa.tx_id = t.tx_id
     AND aa.block_date = t.block_date
     AND aa.address = t.tx_signer
     AND aa.token_mint_address IS NULL
)

SELECT
    block_date,
    SUM(agents_in_tx)                                        AS agents_onboarded,
    ROUND(SUM(sol_spent), 4)                                 AS total_sol_spent,
    ROUND(SUM(sol_spent) / NULLIF(SUM(agents_in_tx), 0), 5)   AS avg_sol_per_agent,
    ROUND(APPROX_PERCENTILE(sol_spent, 0.5), 5)              AS median_sol_per_tx
FROM payer_spend
GROUP BY 1
ORDER BY 1
