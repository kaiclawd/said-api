# Claw Pump Integration - Setup Complete ✅

## What Was Added

Two new endpoints in `/Users/callum/said-api/src/index.ts`:

1. **POST /api/platforms/clawpump/register**
   - Line 1423+
   - Builds sponsored registration transaction
   - Same flow as Spawnr integration

2. **POST /api/platforms/clawpump/confirm**
   - Receives signed transaction from Claw Pump
   - Broadcasts to Solana
   - Updates database with `registrationSource: 'clawpump'`

## Environment Variables Required

Add to your said-api `.env` or Railway environment:

```bash
CLAWPUMP_API_KEY=<generate-this-and-send-to-Bunny>
```

**Reuses existing:**
- `SPONSOR_PRIVATE_KEY` - Same sponsor wallet as Spawnr (already configured)

## How It Works

### Step 1: Claw Pump calls `/register`

```bash
POST https://api.saidprotocol.com/api/platforms/clawpump/register
Headers:
  X-Platform-Key: <CLAWPUMP_API_KEY>
  Content-Type: application/json

Body:
{
  "wallet": "agent_wallet_pubkey",
  "name": "Agent Name",
  "description": "Agent description (optional)",
  "twitter": "@handle (optional)",
  "website": "https://... (optional)",
  "capabilities": ["chat", "trading"] (optional)
}
```

**Response:**
```json
{
  "success": true,
  "transaction": "base64_encoded_transaction",
  "blockhash": "...",
  "lastValidBlockHeight": 123456,
  "requiredSigner": "agent_wallet_pubkey",
  "pda": "...",
  "instructions": {
    "step1": "Deserialize the base64 transaction",
    "step2": "Sign with the agent wallet",
    "step3": "POST the signed transaction to /api/platforms/clawpump/confirm"
  }
}
```

### Step 2: Claw Pump signs + calls `/confirm`

```bash
POST https://api.saidprotocol.com/api/platforms/clawpump/confirm
Headers:
  X-Platform-Key: <CLAWPUMP_API_KEY>
  Content-Type: application/json

Body:
{
  "signedTransaction": "base64_signed_transaction",
  "wallet": "agent_wallet_pubkey",
  "name": "Agent Name",
  ...other metadata
}
```

**Response:**
```json
{
  "success": true,
  "message": "Agent registered and verified ON-CHAIN via Claw Pump",
  "txHash": "...",
  "explorer": "https://solscan.io/tx/...",
  "agent": {
    "wallet": "...",
    "pda": "...",
    "name": "...",
    "verified": true,
    "onChain": true,
    "profile": "https://www.saidprotocol.com/agent.html?wallet=...",
    "badge": "https://api.saidprotocol.com/api/badge/...svg"
  },
  "platform": {
    "name": "claw.pump",
    "costCovered": "~0.015 SOL",
    "sponsoredBy": "SAID Protocol"
  }
}
```

## Database Tracking

All Claw Pump agents are tagged in the database:
- `registrationSource: 'clawpump'`
- `sponsored: true`
- `layer2Verified: true`
- `l2AttestationMethod: 'platform'`

**To query Claw Pump agents:**
```sql
SELECT * FROM agents WHERE registrationSource = 'clawpump';
```

**To compare platforms:**
```sql
SELECT 
  registrationSource, 
  COUNT(*) as total_agents,
  SUM(CASE WHEN isVerified THEN 1 ELSE 0 END) as verified_agents
FROM agents
WHERE registrationSource IN ('spawnr', 'clawpump')
GROUP BY registrationSource;
```

## Cost Analysis

**Per agent:**
- Registration rent: ~0.003 SOL
- Verification fee: 0.01 SOL
- Transaction fees: ~0.002 SOL
- **Total: ~0.015 SOL** (~$2.40 at $160 SOL)

**Projected volume:**
- If Claw Pump launches 50 agents/month: 0.75 SOL/month (~$120)
- If Claw Pump launches 100 agents/month: 1.5 SOL/month (~$240)

## Monitoring

**Check Claw Pump usage:**
```bash
# Count agents from Claw Pump
curl https://api.saidprotocol.com/api/agents | jq '[.[] | select(.registrationSource == "clawpump")] | length'

# Get all Claw Pump agents
curl https://api.saidprotocol.com/api/agents | jq '[.[] | select(.registrationSource == "clawpump")]'
```

## Next Steps

1. **Generate API key for Bunny:**
   ```bash
   openssl rand -hex 32
   ```

2. **Add to Railway env vars:**
   ```
   CLAWPUMP_API_KEY=<generated-key>
   ```

3. **Redeploy said-api**

4. **Send to Bunny:**
   - API key
   - Integration docs (see below)

5. **Test integration:**
   - Have Bunny test with 1 agent
   - Verify it appears on saidprotocol.com
   - Verify `registrationSource` is set correctly in DB

## Integration Docs for Bunny

```markdown
# Claw Pump → SAID Integration

Base URL: https://api.saidprotocol.com
API Key: [SEND THIS SECURELY]

## Verify an Agent (2-step process)

### Step 1: Build Transaction

POST /api/platforms/clawpump/register
Headers:
  X-Platform-Key: [YOUR_API_KEY]
  Content-Type: application/json

Body:
{
  "wallet": "agent_wallet_address",
  "name": "Agent Name",
  "description": "Description (optional)",
  "twitter": "@handle (optional)",
  "website": "https://... (optional)",
  "capabilities": ["chat", "trading"] (optional)
}

Returns: Partially-signed transaction (base64)

### Step 2: Sign + Confirm

1. Deserialize the transaction from Step 1
2. Sign with the agent's private key
3. Serialize the signed transaction to base64

POST /api/platforms/clawpump/confirm
Headers:
  X-Platform-Key: [YOUR_API_KEY]
  Content-Type: application/json

Body:
{
  "signedTransaction": "base64_signed_tx",
  "wallet": "agent_wallet_address",
  "name": "Agent Name"
}

Returns: Success + on-chain transaction hash + agent profile URL

## Display Verification Badge

Use the badge URL returned in the response:

HTML:
<img src="https://api.saidprotocol.com/api/badge/{wallet}.svg" alt="SAID Verified" />

Or fetch agent data:
GET https://api.saidprotocol.com/api/agents/{wallet}

Response includes:
- isVerified: true/false
- verified badge URLs
- profile link
- reputation data
```

## Backup

Original file backed up to: `/Users/callum/said-api/src/index.ts.backup`

If anything breaks, restore with:
```bash
cd /Users/callum/said-api/src
cp index.ts.backup index.ts
```

## Testing

**Test locally:**
```bash
cd /Users/callum/said-api
npm run dev
```

**Test endpoints:**
```bash
# Register (should fail without API key)
curl -X POST http://localhost:3001/api/platforms/clawpump/register \
  -H "Content-Type: application/json" \
  -d '{"wallet": "test", "name": "Test"}

# With API key (generate first)
export API_KEY="your_generated_key"
curl -X POST http://localhost:3001/api/platforms/clawpump/register \
  -H "X-Platform-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"wallet": "valid_solana_pubkey", "name": "Test Agent"}'
```

## Questions?

Contact: kaiclawd@outlook.com or via WhatsApp
