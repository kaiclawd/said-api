-- SAID Protocol — headline scorecard
-- Viz: 6 x Counter widgets, all reading from this one query
--
-- Registration is idempotent per owner (the identity PDA is seeded [b"agent", owner]),
-- so distinct agent PDAs == distinct agents.

WITH said AS (
    SELECT
        block_date,
        block_time,
        tx_id,
        tx_signer,
        account_arguments[1] AS agent_pda,
        CASE bytearray_substring(data, 1, 8)
            WHEN 0x879d42c30271af1e THEN 'register_agent'
            WHEN 0x84e7021e734a171a THEN 'get_verified'
            ELSE 'other'
        END AS ix_name
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
),

treasury AS (
    SELECT
        SUM(IF(balance_change > 0, balance_change, 0)) / 1e9 AS sol_collected,
        SUM(IF(balance_change < 0, -balance_change, 0)) / 1e9 AS sol_withdrawn
    FROM solana.account_activity
    WHERE address = '2XfHTeNWTjNwUmgoXaafYuqHcAAXj8F5Kjw2Bnzi4FxH'  -- treasury PDA, seeds [b"treasury"]
      AND tx_success
      AND token_mint_address IS NULL
)

SELECT
    COUNT(DISTINCT IF(ix_name = 'register_agent', agent_pda)) AS agents_registered,
    COUNT(DISTINCT IF(ix_name = 'get_verified',   agent_pda)) AS agents_verified,
    ROUND(
        100.0 * COUNT(DISTINCT IF(ix_name = 'get_verified', agent_pda))
              / NULLIF(COUNT(DISTINCT IF(ix_name = 'register_agent', agent_pda)), 0)
    , 1) AS verification_rate_pct,
    COUNT(DISTINCT IF(ix_name = 'register_agent' AND block_time > NOW() - INTERVAL '7' DAY, agent_pda))
        AS agents_registered_7d,
    COUNT(DISTINCT IF(ix_name = 'register_agent', tx_signer)) AS distinct_registration_payers,
    ROUND(MAX(t.sol_collected), 3) AS treasury_sol_collected,
    ROUND(MAX(t.sol_collected) - MAX(t.sol_withdrawn), 3) AS treasury_sol_balance
FROM said
CROSS JOIN treasury t
