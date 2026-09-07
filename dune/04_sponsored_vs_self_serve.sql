-- SAID Protocol — who pays to onboard an agent?
-- Viz: stacked area (normalized to 100% is also worth a second panel)
--
-- register_agent accounts: [agent_identity, owner (signer + payer), system_program].
-- The owner signs, but the FEE PAYER is the first signer of the transaction. When a
-- platform onboards agents it funds and pays for them, so tx_signer != owner.
-- This is the cleanest on-chain read of "distribution via integrators" vs "self-serve".

WITH reg AS (
    SELECT
        block_date,
        tx_signer,
        account_arguments[1] AS agent_pda,
        account_arguments[2] AS owner
    FROM solana.instruction_calls
    WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
      AND tx_success
      AND bytearray_substring(data, 1, 8) = 0x879d42c30271af1e
      AND cardinality(account_arguments) >= 3
)

SELECT
    block_date,
    COUNT_IF(tx_signer = owner)  AS self_serve,
    COUNT_IF(tx_signer <> owner) AS platform_sponsored,
    ROUND(100.0 * COUNT_IF(tx_signer <> owner) / COUNT(*), 1) AS sponsored_pct
FROM reg
GROUP BY 1
ORDER BY 1
