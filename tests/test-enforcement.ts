/**
 * Quick smoke test for the enforcement module.
 * Queries a known SAID agent wallet on mainnet.
 *
 * Run: npx tsx tests/test-enforcement.ts
 */

import { Connection, PublicKey } from '@solana/web3.js';
import {
  deriveAgentPda,
  deriveStakePda,
  getEnforcementStatus,
  decodeAgentIdentity,
  decodeAgentStake,
} from '../src/enforcement.js';

const RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
const PROGRAM_ID = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G';

// Known SAID agents from the registry (verified on-chain)
const TEST_WALLETS = [
  'EK3mP45iwgDEEts2cEDfhAs2i4PrH63NMG7vHg2d6fas', // Callum's wallet
  'H8nKbwHTTmnjgnsvqxRDpoEcTkU6uoqs4DcLm4kY55Wp', // Treasury
];

async function main() {
  const connection = new Connection(RPC_URL, 'confirmed');
  console.log(`\n🛡️  SAID Enforcement Module Test`);
  console.log(`   RPC: ${RPC_URL}`);
  console.log(`   Program: ${PROGRAM_ID}\n`);

  for (const wallet of TEST_WALLETS) {
    console.log(`\n${'─'.repeat(60)}`);
    console.log(`Wallet: ${wallet}`);

    // Show PDA derivation
    const [agentPda] = deriveAgentPda(wallet);
    const [stakePda] = deriveStakePda(agentPda);
    console.log(`Agent PDA: ${agentPda.toBase58()}`);
    console.log(`Stake PDA:  ${stakePda.toBase58()}`);

    // Fetch raw accounts for debugging
    const [agentAccount, stakeAccount] = await connection.getMultipleAccountsInfo([agentPda, stakePda]);
    console.log(`Agent account exists: ${!!agentAccount}`);
    console.log(`Stake account exists:  ${!!stakeAccount}`);

    if (agentAccount) {
      console.log(`Agent data length: ${agentAccount.data.length} bytes`);
      console.log(`Agent lamports: ${agentAccount.lamports}`);
    }

    if (stakeAccount) {
      console.log(`Stake data length: ${stakeAccount.data.length} bytes`);
      console.log(`Stake lamports: ${stakeAccount.lamports}`);
    }

    // Full enforcement status
    try {
      const status = await getEnforcementStatus(connection, wallet);
      console.log(`\n📊 Enforcement Status:`);
      console.log(`   Registered: ${status.registered}`);
      console.log(`   Verified: ${status.isVerified} (tier ${status.verificationTier})`);
      console.log(`   Staked: ${status.staked} (${status.stakeAmountSol} SOL)`);
      console.log(`   Slashed: ${status.isSlashed} (count: ${status.slashCount})`);
      console.log(`   Enforcement tier: ${status.enforcementTier}`);
      console.log(`   Risk level: ${status.riskLevel}`);
      if (status.riskReasons.length > 0) {
        console.log(`   Risk reasons:`);
        for (const r of status.riskReasons) {
          console.log(`     • ${r}`);
        }
      }
    } catch (e) {
      console.log(`   ❌ Error: ${e instanceof Error ? e.message : e}`);
    }
  }

  // Test batch
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`Testing batch query...`);
  try {
    // We'll just call individually since we're testing the module directly
    const results = await Promise.all(
      TEST_WALLETS.map(w => getEnforcementStatus(connection, w).catch(e => ({
        wallet: w,
        error: e instanceof Error ? e.message : String(e),
      }))),
    );
    console.log(`Batch results: ${results.length} wallets queried`);
    const staked = results.filter(r => 'staked' in r && r.staked).length;
    const slashed = results.filter(r => 'isSlashed' in r && r.isSlashed).length;
    console.log(`  Staked: ${staked}, Slashed: ${slashed}`);
  } catch (e) {
    console.log(`Batch error: ${e}`);
  }

  console.log(`\n✅ Enforcement module test complete\n`);
}

main().catch(console.error);
