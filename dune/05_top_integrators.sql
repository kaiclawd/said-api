-- SAID Protocol — integrator leaderboard (who is actually driving registrations)
-- Viz: table, with a solscan link column
--
-- One row per fee payer that has ever paid for a registration. Self-registrations
-- (payer == owner) collapse into a single "self-serve (long tail)" row so the
-- platform payers stand out.

WITH reg AS (
    SELECT
        block_time,
        tx_signer,
        account_arguments[1] AS agent_pda,
        account_arguments[2] AS owner
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
      AND bytearray_substring(data, 1, 8) = 0x879d42c30271af1e
      AND cardinality(account_arguments) >= 3
),

ver AS (
    SELECT DISTINCT account_arguments[1] AS agent_pda
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
      AND bytearray_substring(data, 1, 8) = 0x84e7021e734a171a
),

labelled AS (
    SELECT
        IF(r.tx_signer = r.owner, 'self-serve (long tail)', r.tx_signer) AS payer,
        r.agent_pda,
        r.block_time,
        v.agent_pda IS NOT NULL AS is_verified
    FROM reg r
    LEFT JOIN ver v ON v.agent_pda = r.agent_pda
)

SELECT
    payer,
    COUNT(DISTINCT agent_pda) AS agents_onboarded,
    COUNT_IF(is_verified)     AS of_which_verified,
    ROUND(100.0 * COUNT_IF(is_verified) / COUNT(*), 1) AS verified_pct,
    COUNT_IF(block_time > NOW() - INTERVAL '30' DAY)   AS onboarded_30d,
    MIN(block_time) AS first_registration,
    MAX(block_time) AS last_registration,
    IF(payer = 'self-serve (long tail)', NULL,
       'https://solscan.io/account/' || payer) AS solscan
FROM labelled
GROUP BY payer
ORDER BY agents_onboarded DESC
LIMIT 100
