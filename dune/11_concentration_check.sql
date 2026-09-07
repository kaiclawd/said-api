-- SAID Protocol — concentration check (the number a sceptic will ask for)
-- Viz: table / counters
--
-- ERC-8004's credibility problem is that its top 10 wallets own ~51% of registrations.
-- Run the same test on SAID and know the answer before someone else computes it.

WITH reg AS (
    SELECT
        tx_signer,
        account_arguments[1] AS agent_pda,
        account_arguments[2] AS owner
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
      AND bytearray_substring(data, 1, 8) = 0x879d42c30271af1e
      AND cardinality(account_arguments) >= 3
),

by_payer AS (
    SELECT
        tx_signer,
        COUNT(DISTINCT agent_pda) AS agents
    FROM reg
    GROUP BY 1
),

ranked AS (
    SELECT
        tx_signer,
        agents,
        ROW_NUMBER() OVER (ORDER BY agents DESC) AS rnk,
        SUM(agents) OVER () AS total_agents
    FROM by_payer
)

SELECT
    MAX(total_agents) AS total_agents,
    COUNT(*)          AS distinct_payers,
    ROUND(100.0 * SUM(IF(rnk = 1,  agents, 0)) / MAX(total_agents), 1) AS top_1_payer_pct,
    ROUND(100.0 * SUM(IF(rnk <= 10, agents, 0)) / MAX(total_agents), 1) AS top_10_payer_pct,
    COUNT_IF(agents = 1) AS payers_with_one_agent,
    ROUND(100.0 * COUNT_IF(agents = 1) / COUNT(*), 1) AS pct_payers_with_one_agent
FROM ranked
