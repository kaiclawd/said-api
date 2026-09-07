-- SAID Protocol — base decode layer
-- Save this query FIRST, then reference it from the others as `query_<ID>`
-- (Dune "query as a view"), or paste the SELECT inline as a CTE.
--
-- Program: 5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G  (Solana mainnet)
-- The SAID program is NOT decoded on Dune, so we decode by Anchor discriminator:
--   discriminator = first 8 bytes of sha256("global:<instruction_name>")
-- Values below are lifted from the tx builders in said-api/src/index.ts.

SELECT
    block_time,
    block_date,
    block_slot,
    tx_id,
    tx_signer,
    tx_success,
    is_inner,
    account_arguments,
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
    -- account 1 is the agent_identity PDA on every agent-scoped instruction
    account_arguments[1] AS agent_pda,
    -- register_agent accounts: [agent_identity, owner (signer + payer), system_program]
    -- get_verified accounts:   [agent_identity, treasury, authority (pays 0.01 SOL), system_program]
    IF(cardinality(account_arguments) >= 3, account_arguments[2]) AS account_2,
    IF(cardinality(account_arguments) >= 3, account_arguments[3]) AS account_3
FROM solana.instruction_calls
WHERE executing_account = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G'
