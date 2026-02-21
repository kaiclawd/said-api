// Passport API Endpoints
// Add these to index.ts before the "START" section

import { Context } from 'hono';
import { Connection, PublicKey, Transaction, Keypair, SystemProgram, sendAndConfirmTransaction } from '@solana/web3.js';
import { createCreateMetadataAccountV3Instruction, PROGRAM_ID as TOKEN_METADATA_PROGRAM_ID } from '@metaplex-foundation/mpl-token-metadata';
import { 
  TOKEN_2022_PROGRAM_ID,
  createInitializeMintInstruction,
  createInitializeNonTransferableMintInstruction,
  getMintLen,
  ExtensionType,
  createAssociatedTokenAccountInstruction,
  getAssociatedTokenAddressSync,
  createMintToInstruction
} from '@solana/spl-token';

// GET /api/verify/:wallet - Check if agent is registered and verified
export async function handleVerifyAgent(c: Context, prisma: any) {
  const { wallet } = c.req.param();
  
  try {
    const agent = await prisma.agent.findUnique({
      where: { wallet },
      select: {
        wallet: true,
        pda: true,
        name: true,
        description: true,
        isVerified: true,
        verifiedAt: true,
        passportMint: true,
        passportMintedAt: true,
        passportTxHash: true,
        registeredAt: true
      }
    });

    if (!agent) {
      return c.json({
        registered: false,
        verified: false,
        error: 'Agent not found'
      }, 404);
    }

    return c.json({
      registered: true,
      verified: agent.isVerified,
      passportMint: agent.passportMint,
      passportMintedAt: agent.passportMintedAt,
      name: agent.name,
      description: agent.description,
      wallet: agent.wallet,
      pda: agent.pda
    });
  } catch (error) {
    console.error('Error verifying agent:', error);
    return c.json({ error: 'Failed to verify agent' }, 500);
  }
}

// POST /api/passport/:wallet/prepare - Prepare mint transaction
export async function handlePreparePassport(c: Context, connection: Connection) {
  const { wallet } = c.req.param();
  
  try {
    const ownerPubkey = new PublicKey(wallet);
    
    // Generate new mint keypair
    const mintKeypair = Keypair.generate();
    const mintPubkey = mintKeypair.publicKey;
    
    // Get associated token account
    const ata = getAssociatedTokenAddressSync(
      mintPubkey,
      ownerPubkey,
      false,
      TOKEN_2022_PROGRAM_ID
    );
    
    // Calculate rent
    const extensions = [ExtensionType.NonTransferable];
    const mintLen = getMintLen(extensions);
    const lamports = await connection.getMinimumBalanceForRentExemption(mintLen);
    
    // Build transaction
    const tx = new Transaction();
    
    // 1. Create mint account
    tx.add(
      SystemProgram.createAccount({
        fromPubkey: ownerPubkey,
        newAccountPubkey: mintPubkey,
        space: mintLen,
        lamports,
        programId: TOKEN_2022_PROGRAM_ID
      })
    );
    
    // 2. Initialize non-transferable extension
    tx.add(
      createInitializeNonTransferableMintInstruction(
        mintPubkey,
        TOKEN_2022_PROGRAM_ID
      )
    );
    
    // 3. Initialize mint
    tx.add(
      createInitializeMintInstruction(
        mintPubkey,
        0, // decimals
        ownerPubkey, // mint authority
        null, // freeze authority
        TOKEN_2022_PROGRAM_ID
      )
    );
    
    // 4. Create associated token account
    tx.add(
      createAssociatedTokenAccountInstruction(
        ownerPubkey,
        ata,
        ownerPubkey,
        mintPubkey,
        TOKEN_2022_PROGRAM_ID
      )
    );
    
    // 5. Mint 1 token to owner
    tx.add(
      createMintToInstruction(
        mintPubkey,
        ata,
        ownerPubkey,
        1,
        [],
        TOKEN_2022_PROGRAM_ID
      )
    );
    
    // Set recent blockhash and fee payer
    const { blockhash } = await connection.getLatestBlockhash('finalized');
    tx.recentBlockhash = blockhash;
    tx.feePayer = ownerPubkey;
    
    // Partially sign with mint keypair
    tx.partialSign(mintKeypair);
    
    // Serialize transaction
    const serializedTx = tx.serialize({
      requireAllSignatures: false,
      verifySignatures: false
    });
    
    return c.json({
      transaction: Buffer.from(serializedTx).toString('base64'),
      mintAddress: mintPubkey.toString()
    });
  } catch (error) {
    console.error('Error preparing passport:', error);
    return c.json({ error: 'Failed to prepare transaction' }, 500);
  }
}

// POST /api/passport/broadcast - Broadcast signed transaction
export async function handleBroadcastPassport(c: Context, connection: Connection) {
  try {
    const { signedTransaction } = await c.req.json();
    
    if (!signedTransaction) {
      return c.json({ error: 'Missing signedTransaction' }, 400);
    }
    
    // Decode transaction
    const txBuffer = Buffer.from(signedTransaction, 'base64');
    const tx = Transaction.from(txBuffer);
    
    // Send transaction
    const signature = await connection.sendRawTransaction(tx.serialize(), {
      skipPreflight: false,
      maxRetries: 3
    });
    
    // Wait for confirmation
    await connection.confirmTransaction(signature, 'confirmed');
    
    return c.json({ signature });
  } catch (error: any) {
    console.error('Error broadcasting passport:', error);
    return c.json({ 
      error: error.message || 'Failed to broadcast transaction' 
    }, 500);
  }
}

// POST /api/passport/:wallet/finalize - Store passport mint info in database
export async function handleFinalizePassport(c: Context, prisma: any) {
  const { wallet } = c.req.param();
  
  try {
    const { txHash, mintAddress } = await c.req.json();
    
    if (!txHash || !mintAddress) {
      return c.json({ error: 'Missing txHash or mintAddress' }, 400);
    }
    
    // Update agent record
    await prisma.agent.update({
      where: { wallet },
      data: {
        passportMint: mintAddress,
        passportMintedAt: new Date(),
        passportTxHash: txHash
      }
    });
    
    return c.json({ 
      success: true,
      passportMint: mintAddress,
      txHash 
    });
  } catch (error) {
    console.error('Error finalizing passport:', error);
    return c.json({ error: 'Failed to finalize passport' }, 500);
  }
}

// GET /api/agents/:wallet/passport - Check passport status
export async function handleGetPassport(c: Context, prisma: any) {
  const { wallet } = c.req.param();
  
  try {
    const agent = await prisma.agent.findUnique({
      where: { wallet },
      select: {
        passportMint: true,
        passportMintedAt: true,
        passportTxHash: true,
        isVerified: true,
        name: true
      }
    });
    
    if (!agent) {
      return c.json({ error: 'Agent not found' }, 404);
    }
    
    if (!agent.passportMint) {
      return c.json({
        hasPassport: false,
        canMint: agent.isVerified,
        reason: agent.isVerified 
          ? 'Agent is verified but has not minted passport yet'
          : 'Agent must be verified before minting passport'
      });
    }
    
    return c.json({
      hasPassport: true,
      mint: agent.passportMint,
      mintedAt: agent.passportMintedAt,
      txHash: agent.passportTxHash,
      image: `https://www.saidprotocol.com/api/passport/${agent.passportMint}/image`
    });
  } catch (error) {
    console.error('Error getting passport:', error);
    return c.json({ error: 'Failed to get passport' }, 500);
  }
}
