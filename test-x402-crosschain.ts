/**
 * SAID Protocol — Cross-Chain x402 Payment Test (Solana → Ethereum)
 * 
 * Usage: KEYPAIR_PATH=./test-keypair.json npx tsx test-x402-crosschain.ts
 */

import { wrapFetchWithPayment, x402Client } from '@x402/fetch';
import { registerExactSvmScheme } from '@x402/svm/exact/client';
import { createKeyPairSignerFromBytes } from '@solana/kit';
import { readFileSync } from 'fs';

const API_URL = process.env.API_URL || 'https://api.saidprotocol.com';

async function main() {
  const bytes = JSON.parse(readFileSync(process.env.KEYPAIR_PATH!, 'utf8'));
  const signer = await createKeyPairSignerFromBytes(new Uint8Array(bytes));
  console.log(`🔑 Wallet: ${signer.address}`);

  const client = new x402Client();
  registerExactSvmScheme(client, { signer });
  const x402Fetch = wrapFetchWithPayment(fetch, client);

  // Solana agent (Kai) → Ethereum agent (Minara AI)
  const messageBody = {
    from: { address: '42xhLbEm5ttwzxW6YMJ2UZStX7M8ytTz7s7bsyrdPxMD', chain: 'solana' },
    to: { address: '0xB27AfB1741AA9BE0B924d99b26EbF5577054A138', chain: 'ethereum' },
    message: `Cross-chain test: Solana → Ethereum via SAID Protocol x402. Sent at ${new Date().toISOString()}`,
  };

  console.log(`\n📤 Cross-chain message: Solana → Ethereum`);
  console.log(`   From: Kai (SAID, Solana)`);
  console.log(`   To: Minara AI (ERC-8004, Ethereum)`);

  const response = await x402Fetch(`${API_URL}/xchain/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(messageBody),
  });

  const data = await response.json();
  if (response.ok) {
    console.log('\n✅ CROSS-CHAIN MESSAGE DELIVERED!');
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(`\n❌ Failed (HTTP ${response.status})`);
    console.log(JSON.stringify(data, null, 2));
  }
}

main().catch(e => console.error('❌', e.message || e));
