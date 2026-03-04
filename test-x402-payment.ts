/**
 * SAID Protocol — x402 End-to-End Payment Test
 * 
 * Usage:
 *   KEYPAIR_PATH=./test-keypair.json npx tsx test-x402-payment.ts
 */

import { wrapFetchWithPayment, x402Client } from '@x402/fetch';
import { registerExactSvmScheme } from '@x402/svm/exact/client';
import { createKeyPairSignerFromBytes } from '@solana/kit';
import { readFileSync } from 'fs';

const API_URL = process.env.API_URL || 'https://api.saidprotocol.com';
const SENDER = '42xhLbEm5ttwzxW6YMJ2UZStX7M8ytTz7s7bsyrdPxMD'; // Kai

async function main() {
  // Load keypair
  if (!process.env.KEYPAIR_PATH) throw new Error('Set KEYPAIR_PATH');
  const bytes = JSON.parse(readFileSync(process.env.KEYPAIR_PATH, 'utf8'));
  const signer = await createKeyPairSignerFromBytes(new Uint8Array(bytes));
  console.log(`🔑 Wallet: ${signer.address}`);

  // Create x402 client
  const client = new x402Client();
  registerExactSvmScheme(client, { signer });

  // Wrap fetch with x402 payment handling
  const x402Fetch = wrapFetchWithPayment(fetch, client);

  const messageBody = {
    from: { address: SENDER, chain: 'solana' },
    to: { address: SENDER, chain: 'solana' },
    message: `x402 PAID message test — ${new Date().toISOString()}`,
  };

  console.log(`\n📤 Sending paid message...`);
  console.log(`   ${messageBody.message}`);

  const response = await x402Fetch(`${API_URL}/xchain/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(messageBody),
  });

  const data = await response.json();

  if (response.ok) {
    console.log('\n✅ SUCCESS! Paid message delivered');
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(`\n❌ Failed (HTTP ${response.status})`);
    console.log(JSON.stringify(data, null, 2));
  }

  // Check settlement
  const settlement = response.headers.get('PAYMENT-RESPONSE');
  if (settlement) {
    console.log('\n💰 Settlement:', Buffer.from(settlement, 'base64').toString());
  }
}

main().catch(e => console.error('❌ Error:', e.message || e));
