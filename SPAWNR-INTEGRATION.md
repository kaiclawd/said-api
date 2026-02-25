# Spawnr.io Integration Guide

**Instant verified agent registration for all Spawnr-created agents**

---

## Overview

Spawnr.io has full platform integration with SAID Protocol. Every agent created on Spawnr automatically:

✅ Gets registered on SAID  
✅ Receives instant verification (normally 0.01 SOL)  
✅ Gets full SAID identity (profile, badge, reputation tracking)  
✅ Layer 2 verified (platform attestation)  

**Zero user friction. Zero cost. One API call.**

---

## Authentication

**API Key:** `spawnr_e00b63db4ea8b896ac6e72ca5d9e0960686b33e2fd1acda30eb3e139286fe02b`

**Header:** `X-Platform-Key: <your API key>`

**Security:** Keep this key secret. Anyone with this key can create verified SAID agents under the Spawnr platform.

---

## Endpoint

### POST /api/platforms/spawnr/register

**URL:** `https://api.saidprotocol.com/api/platforms/spawnr/register`

**Authentication:** Required (see above)

**Rate Limit:** None (unlimited for Spawnr)

**Cost:** FREE (SAID covers the 0.01 SOL verification fee)

---

## Request

### Headers

```
Content-Type: application/json
X-Platform-Key: spawnr_e00b63db4ea8b896ac6e72ca5d9e0960686b33e2fd1acda30eb3e139286fe02b
```

### Body

```json
{
  "wallet": "agent_solana_wallet_address",
  "name": "Agent Name",
  "description": "What this agent does",
  "twitter": "@agent_handle",
  "website": "https://agent-website.com",
  "capabilities": ["chat", "trading", "research"],
  "metadata": {
    "any": "custom",
    "fields": "you want to track"
  }
}
```

**Required fields:**
- `wallet` (string) - Solana wallet address
- `name` (string) - Agent name

**Optional fields:**
- `description` (string) - What the agent does
- `twitter` (string) - Twitter handle (with or without @)
- `website` (string) - Agent website URL
- `capabilities` (array) - What the agent can do
- `metadata` (object) - Any custom data you want to track

---

## Response

### Success (200)

```json
{
  "success": true,
  "message": "Agent registered and verified via Spawnr integration",
  "agent": {
    "wallet": "DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKK",
    "pda": "7Z9QGWuQ3BHLoMUe7YUEm9BJfPTi5uGVFqUVRaU6pump",
    "name": "TradeBot Alpha",
    "description": "Automated trading agent for Solana",
    "verified": true,
    "layer2Verified": true,
    "registeredAt": "2026-02-24T21:30:00.000Z",
    "profile": "https://www.saidprotocol.com/agent.html?wallet=DYw8...",
    "badge": "https://api.saidprotocol.com/api/badge/DYw8....svg",
    "badgeWithScore": "https://api.saidprotocol.com/api/badge/DYw8....svg?style=score",
    "metadataUri": "https://api.saidprotocol.com/api/cards/DYw8....json"
  },
  "platform": {
    "name": "spawnr.io",
    "costCovered": "0.01 SOL verification fee"
  }
}
```

### Already Exists (200)

If the agent is already registered, we automatically upgrade them to verified:

```json
{
  "success": true,
  "message": "Agent already verified",
  "agent": {
    "wallet": "...",
    "pda": "...",
    "name": "...",
    "verified": true,
    "profile": "...",
    "badge": "..."
  }
}
```

### Error (401)

Invalid or missing API key:

```json
{
  "error": "Invalid or missing X-Platform-Key header",
  "instructions": "Include your Spawnr API key in X-Platform-Key header"
}
```

### Error (400)

Missing required fields:

```json
{
  "error": "Required fields: wallet, name"
}
```

### Error (500)

Server error:

```json
{
  "error": "Registration failed",
  "details": "...",
  "support": "contact@saidprotocol.com"
}
```

---

## Usage Examples

### Node.js / TypeScript

```typescript
const registerAgent = async (wallet: string, name: string, description?: string) => {
  const response = await fetch('https://api.saidprotocol.com/api/platforms/spawnr/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Platform-Key': 'spawnr_e00b63db4ea8b896ac6e72ca5d9e0960686b33e2fd1acda30eb3e139286fe02b',
    },
    body: JSON.stringify({
      wallet,
      name,
      description,
      capabilities: ['chat', 'assistant'],
    }),
  });
  
  const data = await response.json();
  
  if (!data.success) {
    throw new Error(data.error || 'Registration failed');
  }
  
  console.log('✅ Agent verified:', data.agent.name);
  console.log('📍 Profile:', data.agent.profile);
  console.log('🔰 Badge:', data.agent.badge);
  
  return data.agent;
};

// Example usage
const agent = await registerAgent(
  'DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKK',
  'TradeBot Alpha',
  'Automated trading agent for Solana'
);
```

### Python

```python
import requests

def register_agent(wallet: str, name: str, description: str = None):
    url = 'https://api.saidprotocol.com/api/platforms/spawnr/register'
    headers = {
        'Content-Type': 'application/json',
        'X-Platform-Key': 'spawnr_e00b63db4ea8b896ac6e72ca5d9e0960686b33e2fd1acda30eb3e139286fe02b',
    }
    payload = {
        'wallet': wallet,
        'name': name,
        'description': description,
        'capabilities': ['chat', 'assistant'],
    }
    
    response = requests.post(url, json=payload, headers=headers)
    data = response.json()
    
    if not data.get('success'):
        raise Exception(data.get('error', 'Registration failed'))
    
    print(f"✅ Agent verified: {data['agent']['name']}")
    print(f"📍 Profile: {data['agent']['profile']}")
    print(f"🔰 Badge: {data['agent']['badge']}")
    
    return data['agent']

# Example usage
agent = register_agent(
    wallet='DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKK',
    name='TradeBot Alpha',
    description='Automated trading agent for Solana'
)
```

### cURL

```bash
curl -X POST https://api.saidprotocol.com/api/platforms/spawnr/register \
  -H "Content-Type: application/json" \
  -H "X-Platform-Key: spawnr_e00b63db4ea8b896ac6e72ca5d9e0960686b33e2fd1acda30eb3e139286fe02b" \
  -d '{
    "wallet": "DYw8jCTfwHNRJhhmFcbXvVDTqWMEVFBX6ZKUmG5CNSKK",
    "name": "TradeBot Alpha",
    "description": "Automated trading agent for Solana",
    "capabilities": ["chat", "trading"]
  }'
```

---

## Integration Flow

**When a user creates an agent on Spawnr:**

1. User completes agent creation on Spawnr.io
2. Spawnr backend calls SAID API with agent details
3. SAID instantly registers + verifies the agent
4. SAID returns agent profile/badge URLs
5. Spawnr shows user their verified SAID identity

**User experience:** Seamless. They don't even know SAID is involved. They just get a verified agent automatically.

---

## What You Get

For every agent registered via this endpoint:

✅ **Verified identity** (normally costs 0.01 SOL)  
✅ **SAID profile page** (`saidprotocol.com/agent/...`)  
✅ **Embeddable badge** (SVG, multiple styles)  
✅ **Reputation tracking** (agents can receive feedback from platforms)  
✅ **Layer 2 verified** (platform attestation - extra trust signal)  
✅ **Discovery** (agents appear in SAID directory/search)  
✅ **Portable identity** (works across all SAID-integrated platforms)

---

## Reputation & Feedback

Once an agent is registered, Spawnr (and other platforms) can submit reputation feedback:

**Endpoint:** `POST /api/sources/feedback`  
**Authentication:** Same API key  
**Use case:** Track agent performance, update reputation scores

See main SAID API docs for feedback endpoint details.

---

## Support

**Questions?** 
- Email: contact@saidprotocol.com
- Discord: discord.gg/saidprotocol
- Twitter: @saidinfra

**Issues?**
- Check API key is correct
- Verify wallet address is valid Solana address
- Ensure Content-Type header is set

---

## Cost Structure

**For Spawnr:** FREE  
**For Users:** FREE  
**For SAID:** 0.01 SOL per agent (we cover this)

We're investing in the Spawnr ecosystem. This integration helps grow the SAID network while making Spawnr agents instantly trustworthy.

---

## Changelog

**2026-02-24** - Initial Spawnr integration
- Instant verified registration
- API key authentication
- Auto Layer 2 verification
- Unlimited agent creation

---

**Built for Spawnr.io by SAID Protocol**  
**Let's build the trusted agent economy together.**
