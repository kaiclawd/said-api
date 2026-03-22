const { Connection, PublicKey, Transaction, SystemProgram, Keypair, LAMPORTS_PER_SOL } = require('@solana/web3.js');
const fs = require('fs');

const RPC_URL = 'https://newest-restless-mansion.solana-mainnet.quiknode.pro/af7d979a4ef8558eb0da3166819eac8af0d3dd2b';
const SAID_PROGRAM_ID = new PublicKey('5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G');
const TREASURY_PDA = new PublicKey('2XfHTeNWTjNwUmgoXaafYuqHcAAXj8F5Kjw2Bnzi4FxH');
const WITHDRAW_AMOUNT = 10;

async function main() {
  console.log('Loading treasury authority wallet...');
  
  const keyfilePath = process.env.HOME + '/.keys/said-authority.json';
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
  const treasuryBalance = await connection.getBalance(TREASURY_PDA);
  const treasurySOL = treasuryBalance / LAMPORTS_PER_SOL;
  console.log(`Treasury: ${treasurySOL.toFixed(4)} SOL`);
  
  if (treasurySOL < WITHDRAW_AMOUNT) {
    console.error(`Insufficient balance!`);
    process.exit(1);
  }
  
  console.log(`\nBuilding withdrawal for ${WITHDRAW_AMOUNT} SOL...`);
  
  const withdrawAmountLamports = WITHDRAW_AMOUNT * LAMPORTS_PER_SOL;
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
  
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
  const tx = new Transaction({ blockhash, lastValidBlockHeight, feePayer: authorityKeypair.publicKey });
  tx.add(withdrawIx);
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
  console.log(`Withdrawing ${WITHDRAW_AMOUNT} SOL`);
  console.log(`From treasury → ${authorityKeypair.publicKey.toBase58()}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  
  console.log('Sending transaction...');
  const signature = await connection.sendRawTransaction(tx.serialize(), { skipPreflight: false });
  
  console.log(`Transaction: ${signature}`);
  console.log(`Explorer: https://solscan.io/tx/${signature}`);
  console.log('\nWaiting for confirmation...');
  
  await connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, 'confirmed');
  
  const newBalance = await connection.getBalance(TREASURY_PDA);
  console.log(`\n✅ SUCCESS!`);
  console.log(`Withdrawn: ${WITHDRAW_AMOUNT} SOL`);
  console.log(`Treasury remaining: ${(newBalance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);
}

main().catch(console.error);
