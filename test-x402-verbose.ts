import { wrapFetchWithPayment, x402Client } from '@x402/fetch';
import { registerExactSvmScheme } from '@x402/svm/exact/client';
import { createKeyPairSignerFromBytes } from '@solana/kit';
import { readFileSync } from 'fs';

async function main() {
  const bytes = JSON.parse(readFileSync('./test-keypair.json', 'utf8'));
  const signer = await createKeyPairSignerFromBytes(new Uint8Array(bytes));

  const client = new x402Client();
  registerExactSvmScheme(client, { signer });
  const x402Fetch = wrapFetchWithPayment(fetch, client);

  const res = await x402Fetch('https://api.saidprotocol.com/xchain/message', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: { address: '42xhLbEm5ttwzxW6YMJ2UZStX7M8ytTz7s7bsyrdPxMD', chain: 'solana' },
      to: { address: '42xhLbEm5ttwzxW6YMJ2UZStX7M8ytTz7s7bsyrdPxMD', chain: 'solana' },
      message: `tx hash test — ${new Date().toISOString()}`,
    }),
  });

  console.log('Status:', res.status);
  console.log('\n--- ALL HEADERS ---');
  res.headers.forEach((v, k) => console.log(`${k}: ${v}`));
  
  const body = await res.json();
  console.log('\n--- BODY ---');
  console.log(JSON.stringify(body, null, 2));
}
main().catch(e => console.error(e));
