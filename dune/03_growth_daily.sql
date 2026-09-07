-- SAID Protocol — registrations & verifications per day, with cumulative agent count
-- Viz: bar chart (registrations, verifications) + line on right axis (cumulative_agents)

WITH said AS (
    SELECT
        block_date,
        account_arguments[1] AS agent_pda,
        CASE bytearray_substring(data, 1, 8)
            WHEN 0x879d42c30271af1e THEN 'register_agent'
            WHEN 0x84e7021e734a171a THEN 'get_verified'
            WHEN 0xc849eeafa57d9907 THEN 'link_wallet'
            ELSE 'other'
        END AS ix_name
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
),

daily AS (
    SELECT
        block_date,
        COUNT(DISTINCT IF(ix_name = 'register_agent', agent_pda)) AS registrations,
        COUNT(DISTINCT IF(ix_name = 'get_verified',   agent_pda)) AS verifications,
        COUNT_IF(ix_name = 'link_wallet')                         AS wallet_links
    FROM said
    GROUP BY 1
)

SELECT
    block_date,
    registrations,
    verifications,
    wallet_links,
    SUM(registrations) OVER (ORDER BY block_date) AS cumulative_agents,
    SUM(verifications) OVER (ORDER BY block_date) AS cumulative_verifications,
    -- 7-day trailing average smooths the platform-batch spikes
    ROUND(AVG(registrations) OVER (ORDER BY block_date ROWS BETWEEN 6 PRECEDING AND CURRENT ROW), 1)
        AS registrations_7d_avg
FROM daily
ORDER BY block_date
