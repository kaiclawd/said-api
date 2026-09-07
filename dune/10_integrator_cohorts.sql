-- SAID Protocol — is distribution broadening, or is it one integrator?
-- Viz: stacked area on agents_onboarded by payer_label
--
-- Concentration is the honest question for a registry: 5k agents from one sponsor is a
-- single customer, not a network. This pins the top 8 payers by name and folds the rest
-- into "other", so the shape of the dependency is visible over time.

WITH reg AS (
    SELECT
        block_date,
        IF(tx_signer = account_arguments[2], 'self-serve', tx_signer) AS payer,
        account_arguments[1] AS agent_pda
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
      AND bytearray_substring(data, 1, 8) = 0x879d42c30271af1e
      AND cardinality(account_arguments) >= 3
),

top_payers AS (
    SELECT payer
    FROM reg
    GROUP BY payer
    ORDER BY COUNT(DISTINCT agent_pda) DESC
    LIMIT 8
)

SELECT
    DATE_TRUNC('week', r.block_date) AS week,
    IF(t.payer IS NULL, 'other', r.payer) AS payer_label,
    COUNT(DISTINCT r.agent_pda) AS agents_onboarded
FROM reg r
LEFT JOIN top_payers t ON t.payer = r.payer
GROUP BY 1, 2
ORDER BY 1, 3 DESC
