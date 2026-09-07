-- SAID Protocol — treasury revenue (verification fees) in SOL and USD
-- Viz: bar chart on usd_in + line on cumulative_usd_in
--
-- get_verified charges 0.01 SOL into the treasury PDA (seeds [b"treasury"]).
-- Every credit to that PDA is protocol revenue; debits are authority withdrawals
-- (withdraw_fees, discriminator c6d4ab6d90d7ae59).
--
-- SOL price: prices.day stores contract_address as varbinary, so Solana mints must be
-- passed through from_base58(). So1111...112 is wrapped SOL, which Dune prices as SOL.

WITH flows AS (
    SELECT
        block_date,
        SUM(IF(balance_change > 0,  balance_change, 0)) / 1e9 AS sol_in,
        SUM(IF(balance_change < 0, -balance_change, 0)) / 1e9 AS sol_out
    FROM solana.account_activity
    WHERE address = '2XfHTeNWTjNwUmgoXaafYuqHcAAXj8F5Kjw2Bnzi4FxH'
      AND tx_success
      AND token_mint_address IS NULL
      AND balance_change <> 0
    GROUP BY 1
),

sol_price AS (
    SELECT CAST(timestamp AS DATE) AS block_date, price
    FROM prices.day
    WHERE blockchain = 'solana'
      AND contract_address = from_base58('So11111111111111111111111111111111111111112')
)

SELECT
    f.block_date,
    f.sol_in,
    f.sol_out,
    ROUND(f.sol_in * p.price, 2)  AS usd_in,
    ROUND(f.sol_out * p.price, 2) AS usd_out,
    SUM(f.sol_in)                   OVER (ORDER BY f.block_date) AS cumulative_sol_in,
    ROUND(SUM(f.sol_in * p.price)   OVER (ORDER BY f.block_date), 2) AS cumulative_usd_in,
    -- verification fee is 0.01 SOL, so this is a cross-check on query 03
    ROUND(f.sol_in / 0.01, 0) AS implied_verifications
FROM flows f
LEFT JOIN sol_price p ON p.block_date = f.block_date
ORDER BY f.block_date
