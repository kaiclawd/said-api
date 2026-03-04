# Multi-Wallet Management

Link multiple wallets to a single agent identity on SAID Protocol.

## Overview

An agent registered on SAID can link additional wallets to its identity. This enables:

- **Multi-chain presence** — one identity, multiple wallets
- **Key rotation** — transfer authority to a new wallet without re-registering
- **Wallet resolution** — given any linked wallet, find the agent it belongs to

All wallet operations are **on-chain** via the SAID Program. The API returns serialized transactions that must be signed by the appropriate wallets and broadcast to Solana.

## Base URL

```
https://api.saidprotocol.com/api
```

---

## Endpoints

### Link a Wallet

```
POST /api/wallet/link
```

Build a transaction to link a new wallet to an existing agent identity. **Both wallets must sign** — this is bidirectional verification proving the new wallet consents to being linked.

**Request Body:**

```json
{
  "agentWallet": "EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas",
  "newWallet": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
}
```

**Response:**

```json
{
  "success": true,
  "transaction": "<base64-serialized-transaction>",
  "blockhash": "...",
  "lastValidBlockHeight": 123456789,
  "requiredSigners": [
    "EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas",
    "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
  ],
  "walletLinkPda": "...",
  "instructions": {
    "step1": "Deserialize the transaction",
    "step2": "Sign with BOTH wallets (agentWallet and newWallet)",
    "step3": "Broadcast to the network"
  },
  "expiresIn": "~60 seconds"
}
```

#### curl

```bash
curl -X POST https://api.saidprotocol.com/api/wallet/link \
  -H "Content-Type: application/json" \
  -d '{
    "agentWallet": "EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas",
    "newWallet": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
  }'
```

#### TypeScript

```typescript
import { Connection, Transaction, Keypair } from '@solana/web3.js';

// 1. Get the unsigned transaction
const res = await fetch('https://api.saidprotocol.com/api/wallet/link', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    agentWallet: agentKeypair.publicKey.toBase58(),
    newWallet: newKeypair.publicKey.toBase58(),
  }),
});
const { transaction: txBase64 } = await res.json();

// 2. Deserialize and sign with BOTH wallets
const tx = Transaction.from(Buffer.from(txBase64, 'base64'));
tx.partialSign(agentKeypair);
tx.partialSign(newKeypair);

// 3. Broadcast
const connection = new Connection('https://api.mainnet-beta.solana.com');
const sig = await connection.sendRawTransaction(tx.serialize());
await connection.confirmTransaction(sig);
console.log('Wallet linked:', sig);
```

---

### Unlink a Wallet

```
DELETE /api/wallet/link
```

Build a transaction to remove a linked wallet. Only the agent's authority wallet needs to sign.

**Request Body:**

```json
{
  "agentWallet": "EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas",
  "walletToRemove": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
}
```

**Response:**

```json
{
  "success": true,
  "transaction": "<base64-serialized-transaction>",
  "requiredSigner": "EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas",
  "expiresIn": "~60 seconds"
}
```

#### curl

```bash
curl -X DELETE https://api.saidprotocol.com/api/wallet/link \
  -H "Content-Type: application/json" \
  -d '{
    "agentWallet": "EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas",
    "walletToRemove": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
  }'
```

---

### Transfer Authority

```
POST /api/wallet/transfer-authority
```

Transfer admin control of an agent identity to a linked wallet. **⚠️ This is irreversible** — the linked wallet becomes the new authority.

**Request Body:**

```json
{
  "agentWallet": "EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas",
  "linkedWallet": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
}
```

**Response:**

```json
{
  "success": true,
  "transaction": "<base64-serialized-transaction>",
  "requiredSigner": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
  "warning": "This will transfer authority! The linked wallet becomes the new admin."
}
```

The **linked wallet** (new authority) must sign this transaction.

---

### Resolve a Wallet

```
GET /api/agent/resolve/:wallet
```

Given any wallet address, find the agent identity it belongs to — whether it's a primary owner or a linked wallet.

**Response (primary wallet):**

```json
{
  "resolved": true,
  "type": "primary",
  "wallet": "EK3mP4...",
  "agent": { "wallet": "EK3mP4...", "name": "My Agent", "pda": "...", "isVerified": true }
}
```

**Response (linked wallet):**

```json
{
  "resolved": true,
  "type": "linked",
  "wallet": "7xKXtg...",
  "linkedTo": "EK3mP4...",
  "agent": { "wallet": "EK3mP4...", "name": "My Agent" }
}
```

#### curl

```bash
curl https://api.saidprotocol.com/api/agent/resolve/7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU
```

---

### List All Wallets

```
GET /api/agent/:wallet/wallets
```

List the primary wallet and all linked wallets for an agent.

**Response:**

```json
{
  "agent": {
    "wallet": "EK3mP4...",
    "pda": "...",
    "name": "My Agent"
  },
  "wallets": {
    "primary": {
      "wallet": "EK3mP4...",
      "type": "primary",
      "isPermanent": true,
      "isAuthority": true
    },
    "linked": [
      {
        "wallet": "7xKXtg...",
        "pda": "...",
        "type": "linked",
        "linkedAt": "2026-03-01T12:00:00.000Z",
        "isAuthority": false
      }
    ]
  },
  "totalWallets": 2
}
```

#### curl

```bash
curl https://api.saidprotocol.com/api/agent/EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas/wallets
```

---

## Bidirectional Signature Verification

When linking a wallet, the SAID Program requires **both wallets to sign** the transaction:

1. **Agent wallet** (authority) — proves the agent owner approves the link
2. **New wallet** — proves the new wallet owner consents to being linked

This prevents anyone from claiming ownership of wallets they don't control.

```
agent_identity (PDA) ← authority signs
wallet_link (PDA)    ← new_wallet signs
```

The `link_wallet` instruction on the SAID Program enforces both signatures at the program level.
