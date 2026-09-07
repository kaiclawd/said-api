-- SAID Protocol — register → verify funnel and time-to-verify
-- Viz: bar chart on bucket, ordered by sort_order
--
-- Agents are joined on the identity PDA (account 1 on both instructions), which is
-- stable across the two instructions and across authority transfers.
-- Expect the "same transaction" bucket to be large: the sponsored onboarding flows in
-- said-api build register_agent + get_verified into a single transaction.

WITH reg AS (
    SELECT
        account_arguments[1] AS agent_pda,
        MIN(block_time)      AS registered_at,
        ARBITRARY(tx_id)     AS reg_tx
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
      AND bytearray_substring(data, 1, 8) = 0x879d42c30271af1e
    GROUP BY 1
),

ver AS (
    SELECT
        account_arguments[1] AS agent_pda,
        MIN(block_time)      AS verified_at,
        ARBITRARY(tx_id)     AS ver_tx
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
      AND bytearray_substring(data, 1, 8) = 0x84e7021e734a171a
    GROUP BY 1
),

joined AS (
    SELECT
        r.agent_pda,
        r.registered_at,
        v.verified_at,
        r.reg_tx = v.ver_tx AS same_tx,
        date_diff('minute', r.registered_at, v.verified_at) AS mins_to_verify
    FROM reg r
    LEFT JOIN ver v ON v.agent_pda = r.agent_pda
)

SELECT
    CASE
        WHEN verified_at IS NULL          THEN 'never verified'
        WHEN same_tx                      THEN 'same transaction (atomic onboarding)'
        WHEN mins_to_verify < 60          THEN 'within 1 hour'
        WHEN mins_to_verify < 60 * 24     THEN 'within 1 day'
        WHEN mins_to_verify < 60 * 24 * 7 THEN 'within 1 week'
        ELSE 'more than a week'
    END AS bucket,
    CASE
        WHEN verified_at IS NULL          THEN 6
        WHEN same_tx                      THEN 1
        WHEN mins_to_verify < 60          THEN 2
        WHEN mins_to_verify < 60 * 24     THEN 3
        WHEN mins_to_verify < 60 * 24 * 7 THEN 4
        ELSE 5
    END AS sort_order,
    COUNT(*) AS agents,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) AS pct_of_all_agents
FROM joined
GROUP BY 1, 2
ORDER BY sort_order
