# SAID Multi-Wallet API Reference

## Overview
SAID Protocol now supports multiple wallets per agent identity. One agent can have:
- **1 primary wallet** (permanent, used in PDA seeds)
- **Multiple linked wallets** (can be added/removed)
- **1 authority wallet** (can be the primary or any linked wallet)

## Endpoints

### 1. Link a Wallet
```http
POST /api/wallet/link
Content-Type: application/json

{
  "agentWallet": "PRIMARY_WALLET_ADDRESS",
  "newWallet": "WALLET_TO_LINK"
}
```

**Response:**
```json
{
  "success": true,
  "transaction": "BASE64_ENCODED_TX",
  "blockhash": "...",
  "lastValidBlockHeight": 123456,
  "requiredSigners": ["PRIMARY_WALLET", "NEW_WALLET"],
  "walletLinkPda": "PDA_ADDRESS",
  "expiresIn": "~60 seconds"
}
```

**Usage:**
```typescript
const response = await fetch('/api/wallet/link', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ agentWallet, newWallet })
});

const { transaction, requiredSigners } = await response.json();
const tx = Transaction.from(Buffer.from(transaction, 'base64'));

// BOTH wallets must sign
tx.sign(primaryWallet, newWallet);

const sig = await connection.sendRawTransaction(tx.serialize());
await connection.confirmTransaction(sig);
```

---

### 2. Unlink a Wallet
```http
DELETE /api/wallet/link
Content-Type: application/json

{
  "agentWallet": "PRIMARY_WALLET_ADDRESS",
  "walletToRemove": "LINKED_WALLET_TO_REMOVE"
}
```

**Response:**
```json
{
  "success": true,
  "transaction": "BASE64_ENCODED_TX",
  "blockhash": "...",
  "lastValidBlockHeight": 123456,
  "requiredSigner": "PRIMARY_WALLET",
  "expiresIn": "~60 seconds"
}
```

**Note:** Only the authority wallet needs to sign (not the wallet being removed).

---

### 3. Transfer Authority
```http
POST /api/wallet/transfer-authority
Content-Type: application/json

{
  "agentWallet": "PRIMARY_WALLET_ADDRESS",
  "linkedWallet": "LINKED_WALLET_TO_BECOME_AUTHORITY"
}
```

**Response:**
```json
{
  "success": true,
  "transaction": "BASE64_ENCODED_TX",
  "blockhash": "...",
  "lastValidBlockHeight": 123456,
  "requiredSigner": "LINKED_WALLET",
  "warning": "This will transfer authority! The linked wallet becomes the new admin.",
  "expiresIn": "~60 seconds"
}
```

**⚠️ Warning:** This is a recovery mechanism. The linked wallet becomes the new authority and can manage the agent identity.

---

### 4. Resolve Wallet to Agent ⭐
```http
GET /api/agent/resolve/:wallet
```

**Purpose:** Given ANY wallet address, find the agent identity it belongs to.

**Response (if primary wallet):**
```json
{
  "resolved": true,
  "type": "primary",
  "wallet": "WALLET_ADDRESS",
  "agent": {
    "wallet": "PRIMARY_WALLET",
    "pda": "AGENT_PDA",
    "name": "Agent Name",
    "description": "...",
    "reputationScore": 85,
    "isVerified": true,
    "profile": "https://www.saidprotocol.com/agent.html?wallet=...",
    "badge": "https://api.saidprotocol.com/api/badge/WALLET.svg"
  }
}
```

**Response (if linked wallet):**
```json
{
  "resolved": true,
  "type": "linked",
  "wallet": "LINKED_WALLET",
  "linkedTo": "PRIMARY_WALLET",
  "agent": { ... }
}
```

**Response (if not found):**
```json
{
  "resolved": false,
  "wallet": "WALLET_ADDRESS",
  "message": "Wallet is not registered as an agent or linked to any agent"
}
```

**Use Case:** Integrators can lookup any wallet and discover the agent behind it.

---

### 5. List Agent Wallets
```http
GET /api/agent/:wallet/wallets
```

**Response:**
```json
{
  "agent": {
    "wallet": "PRIMARY_WALLET",
    "pda": "AGENT_PDA",
    "name": "Agent Name",
    "profile": "https://www.saidprotocol.com/agent.html?wallet=..."
  },
  "wallets": {
    "primary": {
      "wallet": "PRIMARY_WALLET",
      "type": "primary",
      "isPermanent": true,
      "isAuthority": true
    },
    "linked": [
      {
        "wallet": "LINKED_WALLET_1",
        "pda": "WALLET_LINK_PDA_1",
        "type": "linked",
        "linkedAt": "2026-03-03T12:00:00Z",
        "isAuthority": false
      },
      {
        "wallet": "LINKED_WALLET_2",
        "pda": "WALLET_LINK_PDA_2",
        "type": "linked",
        "linkedAt": "2026-03-03T13:00:00Z",
        "isAuthority": false
      }
    ]
  },
  "totalWallets": 3
}
```

---

## On-Chain Details

### Program ID
```
5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G
```

### PDA Seeds
- **AgentIdentity:** `[b"agent", owner.key()]` (owner = primary wallet)
- **WalletLink:** `[b"wallet", linked_wallet.key()]`

### Instruction Discriminators
- **link_wallet:** `[200, 73, 238, 175, 165, 125, 153, 7]`
- **unlink_wallet:** `[222, 157, 120, 224, 146, 221, 191, 198]`
- **transfer_authority:** `[101, 245, 179, 178, 230, 198, 76, 163]`

---

## Common Workflows

### Adding a Recovery Wallet
```typescript
// 1. Link the recovery wallet
const linkRes = await fetch('/api/wallet/link', {
  method: 'POST',
  body: JSON.stringify({
    agentWallet: primaryWallet.publicKey.toString(),
    newWallet: recoveryWallet.publicKey.toString()
  })
});

const { transaction } = await linkRes.json();
const tx = Transaction.from(Buffer.from(transaction, 'base64'));
tx.sign(primaryWallet, recoveryWallet);
await connection.sendRawTransaction(tx.serialize());

// Now the recovery wallet can be used for authority transfer if primary is lost
```

### Recovering Lost Primary Wallet
```typescript
// If primary wallet is lost, use a linked wallet to become authority
const transferRes = await fetch('/api/wallet/transfer-authority', {
  method: 'POST',
  body: JSON.stringify({
    agentWallet: lostPrimaryWallet,
    linkedWallet: recoveryWallet.publicKey.toString()
  })
});

const { transaction } = await transferRes.json();
const tx = Transaction.from(Buffer.from(transaction, 'base64'));
tx.sign(recoveryWallet); // Only recovery wallet signs
await connection.sendRawTransaction(tx.serialize());

// Recovery wallet is now the authority
```

### Platform Integration (Multi-Platform Agent)
```typescript
// Agent exists on multiple platforms (Twitter, Discord, Telegram)
// Link all wallets to the same SAID identity

// Link Twitter wallet
await linkWallet(primaryWallet, twitterWallet);

// Link Discord wallet
await linkWallet(primaryWallet, discordWallet);

// Link Telegram wallet
await linkWallet(primaryWallet, telegramWallet);

// Now all wallets resolve to the same agent identity
const twitterAgent = await fetch(`/api/agent/resolve/${twitterWallet}`);
const discordAgent = await fetch(`/api/agent/resolve/${discordWallet}`);
// Both return the same agent data!
```

---

## Security Notes

1. **Link wallet requires TWO signatures:**
   - Primary wallet (authority) approves the link
   - New wallet proves they control it

2. **Unlink only requires authority:**
   - Authority can remove any linked wallet
   - OR the linked wallet can remove itself

3. **Transfer authority is permanent:**
   - Can only transfer to a wallet that's already linked
   - New authority gains full control
   - Use carefully! This is the recovery mechanism.

4. **Primary wallet is permanent:**
   - Used in PDA seeds (can't change on-chain)
   - But authority can be transferred to a linked wallet

---

## Error Codes

- **400:** Invalid input (bad wallet address, missing fields)
- **404:** Agent or wallet not found
- **409:** Wallet already linked to an agent
- **500:** Server error or transaction build failure

---

## Testing Checklist

- [ ] Link a wallet (both sign)
- [ ] List wallets (shows primary + linked)
- [ ] Resolve primary wallet
- [ ] Resolve linked wallet
- [ ] Transfer authority
- [ ] Unlink a wallet
- [ ] Try linking already-linked wallet (should fail)
- [ ] Try unlinking non-linked wallet (should fail)
- [ ] Try transfer authority to non-linked wallet (should fail)

---

## Next Steps

1. Run database migration: `npx prisma db push`
2. Add on-chain sync function
3. Test on staging environment
4. Deploy to Railway
5. Update frontend UI
6. Write integration docs for platforms
