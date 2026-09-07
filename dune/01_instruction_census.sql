-- SAID Protocol — instruction census (run this SECOND, before trusting anything else)
-- Viz: table
--
-- Purpose: ground-truth every discriminator the program has ever seen. Any row that
-- comes back as 'unmapped' is an instruction the decode layer in 00 doesn't know about
-- (staking/slashing/update_agent are the likely candidates) — take its hex, work out
-- the name, and add it to the CASE in 00.
-- Deliberately does NOT filter tx_success: failure rate per instruction is a signal.

SELECT
    to_hex(bytearray_substring(data, 1, 8)) AS discriminator,
    CASE bytearray_substring(data, 1, 8)
        WHEN 0x879d42c30271af1e THEN 'register_agent'
        WHEN 0x84e7021e734a171a THEN 'get_verified'
        WHEN 0xc849eeafa57d9907 THEN 'link_wallet'
        WHEN 0xde9d78e092ddbfc6 THEN 'unlink_wallet'
        WHEN 0x65f5b3b2e6c64ca3 THEN 'transfer_authority'
        WHEN 0xc6d4ab6d90d7ae59 THEN 'withdraw_fees'
        WHEN 0xafaf6d1f0d989bed THEN 'initialize'
        ELSE 'unmapped'
    END AS ix_name,
    COUNT(*)                                              AS calls,
    COUNT_IF(NOT tx_success)                              AS failed_calls,
    ROUND(100.0 * COUNT_IF(NOT tx_success) / COUNT(*), 2) AS failure_rate_pct,
    COUNT(DISTINCT tx_signer)                             AS distinct_fee_payers,
    COUNT(DISTINCT account_arguments[1])                  AS distinct_agent_pdas,
    MIN(block_time)                                       AS first_seen,
    MAX(block_time)                                       AS last_seen,
    ARBITRARY(length(data))                               AS sample_data_bytes
FROM solana.instruction_calls
WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
GROUP BY 1, 2
ORDER BY calls DESC
