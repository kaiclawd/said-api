const { Connection, PublicKey, Transaction, SystemProgram, Keypair, LAMPORTS_PER_SOL } = require('@solana/web3.js');
const fs = require('fs');

const RPC_URL = 'https://api.mainnet-beta.solana.com';
const SAID_PROGRAM_ID = new PublicKey('5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G');
const TREASURY_PDA = new PublicKey('2XfHTeNWTjNwUmgoXaafYuqHcAAXj8F5Kjw2Bnzi4FxH');
const SPLIT_20_WALLET = new PublicKey('GFqYiHVb9XGuKavUBin5qzcsq1okjLFDV4ZCZNx5tupV');
const SPLIT_80_WALLET = new PublicKey('VFsaUZrpxVewhv9ZhWaTRzywD32KwLxvQZQKL4Vsaid');

async function main() {
  console.log('Loading treasury authority wallet...');
  
  const keyfilePath = process.env.HOME + '/.config/solana/treasury-authority.json';
  const keyfileData = JSON.parse(fs.readFileSync(keyfilePath, 'utf-8'));
  const authorityKeypair = Keypair.fromSecretKey(Uint8Array.from(keyfileData));
  
  console.log(`Wallet: ${authorityKeypair.publicKey.toBase58()}`);
  
  const expectedAuthority = 'H8nKbwHTTmnjgnsvqxRDpoEcTkU6uoqs4DcLm4kY55Wp';
  if (authorityKeypair.publicKey.toBase58() !== expectedAuthority) {
    console.error(`Wrong wallet! Expected ${expectedAuthority}`);
    process.exit(1);
  }
  
  const connection = new Connection(RPC_URL, 'confirmed');
  
  console.log('Checking treasury balance...');
  const treasuryAccount = await connection.getAccountInfo(TREASURY_PDA);
  const treasuryBalance = treasuryAccount.lamports;
  console.log(`Treasury: ${(treasuryBalance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);

  const rentExemptMin = await connection.getMinimumBalanceForRentExemption(treasuryAccount.data.length);
  const withdrawAmountLamports = treasuryBalance - rentExemptMin;
  if (withdrawAmountLamports <= 0) {
    console.error('Nothing to withdraw above the rent-exempt minimum!');
    process.exit(1);
  }
  const withdrawSOL = withdrawAmountLamports / LAMPORTS_PER_SOL;

  console.log(`\nBuilding withdrawal for ${withdrawSOL.toFixed(4)} SOL (keeping ${(rentExemptMin / LAMPORTS_PER_SOL).toFixed(6)} SOL rent minimum)...`);
  const withdrawDiscriminator = Buffer.from([0xc6, 0xd4, 0xab, 0x6d, 0x90, 0xd7, 0xae, 0x59]);
  const amountBuffer = Buffer.alloc(8);
  amountBuffer.writeBigUInt64LE(BigInt(withdrawAmountLamports));
  const instructionData = Buffer.concat([withdrawDiscriminator, amountBuffer]);
  
  const withdrawIx = {
    programId: SAID_PROGRAM_ID,
    keys: [
      { pubkey: TREASURY_PDA, isSigner: false, isWritable: true },
      { pubkey: authorityKeypair.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: instructionData,
  };
  
  const split20Lamports = Math.round(withdrawAmountLamports * 0.2);
  const split80Lamports = withdrawAmountLamports - split20Lamports;

  const transfer20Ix = SystemProgram.transfer({
    fromPubkey: authorityKeypair.publicKey,
    toPubkey: SPLIT_20_WALLET,
    lamports: split20Lamports,
  });
  const transfer80Ix = SystemProgram.transfer({
    fromPubkey: authorityKeypair.publicKey,
    toPubkey: SPLIT_80_WALLET,
    lamports: split80Lamports,
  });

  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
  const tx = new Transaction({ blockhash, lastValidBlockHeight, feePayer: authorityKeypair.publicKey });
  tx.add(withdrawIx, transfer20Ix, transfer80Ix);
  tx.sign(authorityKeypair);
  
  console.log('Simulating...');
  const simulation = await connection.simulateTransaction(tx);
  if (simulation.value.err) {
    console.error('Simulation failed:', simulation.value.err);
    console.error('Logs:', simulation.value.logs);
    process.exit(1);
  }
  console.log('✓ Simulation OK');
  
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`Withdrawing ${withdrawSOL.toFixed(4)} SOL from treasury via ${authorityKeypair.publicKey.toBase58()}`);
  console.log(`  20% (${(split20Lamports / LAMPORTS_PER_SOL).toFixed(4)} SOL) → ${SPLIT_20_WALLET.toBase58()}`);
  console.log(`  80% (${(split80Lamports / LAMPORTS_PER_SOL).toFixed(4)} SOL) → ${SPLIT_80_WALLET.toBase58()}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  console.log('Sending transaction...');
  const signature = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: false });
  
  console.log(`Transaction: ${signature}`);
  console.log(`Explorer: https://solscan.io/tx/${signature}`);
  console.log('\nWaiting for confirmation...');
  
  await connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, 'confirmed');
  
  const newBalance = await connection.getBalance(TREASURY_PDA);
  console.log(`\n✅ SUCCESS!`);
  console.log(`Withdrawn: ${withdrawSOL.toFixed(4)} SOL`);
  console.log(`  20% → ${SPLIT_20_WALLET.toBase58()}`);
  console.log(`  80% → ${SPLIT_80_WALLET.toBase58()}`);
  console.log(`Treasury remaining: ${(newBalance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);
}

main().catch(console.error);
