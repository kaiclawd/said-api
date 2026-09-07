-- SAID Protocol — multi-wallet linking and authority movement
-- Viz: bar chart per week + counter on net_links_outstanding
--
-- WalletLink is how an external agent wallet gets tied to a SAID identity without
-- handing over keys (both wallets sign). transfer_authority is a key-rotation /
-- custody-handover event and is worth watching on its own — a spike there is either
-- a platform migration or something going wrong.

WITH said AS (
    SELECT
        DATE_TRUNC('week', block_date) AS week,
        account_arguments[1] AS agent_pda,
        CASE bytearray_substring(data, 1, 8)
            WHEN 0xc849eeafa57d9907 THEN 'link_wallet'
            WHEN 0xde9d78e092ddbfc6 THEN 'unlink_wallet'
            WHEN 0x65f5b3b2e6c64ca3 THEN 'transfer_authority'
            ELSE 'other'
        END AS ix_name
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
      AND bytearray_substring(data, 1, 8) IN (
            0xc849eeafa57d9907, 0xde9d78e092ddbfc6, 0x65f5b3b2e6c64ca3
          )
),

weekly AS (
    SELECT
        week,
        COUNT_IF(ix_name = 'link_wallet')        AS links,
        COUNT_IF(ix_name = 'unlink_wallet')      AS unlinks,
        COUNT_IF(ix_name = 'transfer_authority') AS authority_transfers,
        COUNT(DISTINCT IF(ix_name = 'link_wallet', agent_pda)) AS agents_linking
    FROM said
    GROUP BY 1
)

SELECT
    week,
    links,
    unlinks,
    authority_transfers,
    agents_linking,
    SUM(links - unlinks) OVER (ORDER BY week) AS net_links_outstanding
FROM weekly
ORDER BY week
