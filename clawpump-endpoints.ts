// ============ CLAW PUMP PLATFORM INTEGRATION ============

/**
 * POST /api/platforms/clawpump/register
 * Step 1: Build a transaction that registers + verifies an agent on SAID
 * 
 * SAID sponsors the costs (rent + verification fee + tx fees).
 * Claw Pump provides agent wallet + metadata.
 * Returns a partially-signed transaction that Claw Pump must complete + broadcast.
 */
app.post('/api/platforms/clawpump/register', async (c) => {
  // Validate Claw Pump API key
  const apiKey = c.req.header('X-Platform-Key');
  const expectedKey = process.env.CLAWPUMP_API_KEY;
  
  console.log('[DEBUG] Claw Pump Auth check:', { 
    hasApiKey: !!apiKey, 
    hasExpectedKey: !!expectedKey,
    match: apiKey === expectedKey 
  });
  
  if (!expectedKey || !apiKey || apiKey !== expectedKey) {
    return c.json({ error: 'Invalid API key' }, 401);
  }
  
  const body = await c.req.json();
  const { wallet, name, description, twitter, website, capabilities } = body;
  
  // Validate required fields
  if (!wallet || !name) {
    return c.json({ error: 'Required fields: wallet, name' }, 400);
  }

  // Validate wallet format
  let agentPubkey: PublicKey;
  try {
    agentPubkey = new PublicKey(wallet);
  } catch {
    return c.json({ error: 'Invalid wallet address' }, 400);
  }
  
  // Check if already registered on-chain
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from('agent'), agentPubkey.toBuffer()],
    SAID_PROGRAM_ID
  );
  
  const existingOnChain = await connection.getAccountInfo(pda);
  if (existingOnChain) {
    // Already on-chain — ensure DB is tagged as Claw Pump and return
    const existing = await prisma.agent.upsert({
      where: { wallet },
      create: {
        wallet,
        pda: pda.toString(),
        owner: wallet,
        metadataUri: `https://api.saidprotocol.com/api/cards/${wallet}.json`,
        registeredAt: new Date(),
        isVerified: true,
        verifiedAt: new Date(),
        sponsored: true,
        name: name || 'Claw Pump Agent',
        description: description || 'AI Agent via Claw Pump',
        twitter: twitter || undefined,
        website: website || undefined,
        skills: capabilities || ['chat', 'assistant'],
        registrationSource: 'clawpump',
        layer2Verified: true,
        layer2VerifiedAt: new Date(),
        l2AttestationMethod: 'platform',
      },
      update: {
        registrationSource: 'clawpump',
        layer2Verified: true,
        layer2VerifiedAt: new Date(),
        l2AttestationMethod: 'platform',
        sponsored: true,
        isVerified: true,
        verifiedAt: new Date(),
      },
    });
    
    emitAgentEvent('agent:registered', { wallet, name: existing.name, source: 'clawpump' });
    
    return c.json({
      success: true,
      message: 'Agent already registered on-chain',
      agent: {
        wallet,
        pda: pda.toString(),
        name: existing.name || name,
        verified: true,
        profile: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
        badge: `https://api.saidprotocol.com/api/badge/${wallet}.svg`,
      }
    });
  }
  
  // Check sponsor wallet (reuse same sponsor key as Spawnr)
  const sponsorKey = process.env['SPONSOR_PRIVATE_KEY'];
  if (!sponsorKey) {
    return c.json({ 
      error: 'Sponsor wallet not configured. Contact SAID team.',
      support: 'contact@saidprotocol.com'
    }, 500);
  }
  
  try {
    const sponsorKeypair = Keypair.fromSecretKey(bs58.decode(sponsorKey));
    
    // Store agent card first (needed for metadata_uri)
    const card = {
      name,
      description: description || `${name} - AI Agent`,
      wallet,
      twitter: twitter || undefined,
      website: website || undefined,
      capabilities: capabilities || ['chat', 'assistant'],
      platform: 'claw.pump',
      verified: true,
      registeredAt: new Date().toISOString(),
    };
    
    const metadataUri = `https://api.saidprotocol.com/api/cards/${wallet}.json`;
    
    await prisma.agentCard.upsert({
      where: { wallet },
      create: { wallet, cardJson: JSON.stringify(card) },
      update: { cardJson: JSON.stringify(card) },
    });
    
    // Treasury PDA
    const [treasuryPda] = PublicKey.findProgramAddressSync(
      [Buffer.from('treasury')],
      SAID_PROGRAM_ID
    );
    
    // === Build register_agent instruction ===
    // Anchor discriminator: sha256("global:register_agent")[0..8]
    const registerDiscriminator = Buffer.from([135, 157, 66, 195, 2, 113, 175, 30]);
    // Borsh-encode metadata_uri string (4-byte little-endian length + utf8 bytes)
    const uriBytes = Buffer.from(metadataUri, 'utf8');
    const uriLen = Buffer.alloc(4);
    uriLen.writeUInt32LE(uriBytes.length);
    const registerData = Buffer.concat([registerDiscriminator, uriLen, uriBytes]);
    
    const registerIx = {
      programId: SAID_PROGRAM_ID,
      keys: [
        { pubkey: pda, isSigner: false, isWritable: true },           // agent_identity (init)
        { pubkey: agentPubkey, isSigner: true, isWritable: true },    // owner (signer + payer)
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // system_program
      ],
      data: registerData,
    };
    
    // === Build get_verified instruction ===
    // Anchor discriminator: sha256("global:get_verified")[0..8]
    const verifyDiscriminator = Buffer.from([132, 231, 2, 30, 115, 74, 23, 26]);
    
    const verifyIx = {
      programId: SAID_PROGRAM_ID,
      keys: [
        { pubkey: pda, isSigner: false, isWritable: true },           // agent_identity
        { pubkey: treasuryPda, isSigner: false, isWritable: true },   // treasury
        { pubkey: agentPubkey, isSigner: true, isWritable: true },    // authority (signer + payer of fee)
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // system_program
      ],
      data: verifyDiscriminator,
    };
    
    // === Build funding transfer: sponsor → agent wallet ===
    // Agent needs SOL for: PDA rent (~0.003 SOL) + verification fee (0.01 SOL) + tx fees
    const FUND_AMOUNT = 0.015 * LAMPORTS_PER_SOL; // 0.015 SOL buffer
    
    const fundIx = SystemProgram.transfer({
      fromPubkey: sponsorKeypair.publicKey,
      toPubkey: agentPubkey,
      lamports: FUND_AMOUNT,
    });
    
    // Build transaction: fund → register → verify
    const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
    
    const tx = new Transaction({
      blockhash,
      lastValidBlockHeight,
      feePayer: sponsorKeypair.publicKey,  // Sponsor pays tx fees
    });
    
    tx.add(fundIx);      // 1. Fund agent wallet
    tx.add(registerIx);  // 2. Register on-chain
    tx.add(verifyIx);    // 3. Get verified badge
    
    // Sponsor signs (fee payer + fund transfer)
    tx.partialSign(sponsorKeypair);
    
    // Serialize — agent wallet still needs to sign
    const serializedTx = tx.serialize({
      requireAllSignatures: false,
      verifySignatures: false,
    }).toString('base64');
    
    return c.json({
      success: true,
      message: 'Transaction built. Agent wallet must sign and return via /confirm endpoint.',
      transaction: serializedTx,
      blockhash,
      lastValidBlockHeight,
      requiredSigner: wallet,
      pda: pda.toString(),
      metadataUri,
      instructions: {
        step1: 'Deserialize the base64 transaction',
        step2: `Sign with the agent wallet (${wallet})`,
        step3: 'POST the signed transaction to /api/platforms/clawpump/confirm',
      },
      expiresIn: '~60 seconds (blockhash expiry)',
    });
    
  } catch (error: any) {
    console.error('[Claw Pump Register Error]', error);
    return c.json({ 
      error: 'Failed to build transaction',
      details: error.message,
      support: 'contact@saidprotocol.com'
    }, 500);
  }
});

/**
 * POST /api/platforms/clawpump/confirm
 * Step 2: Receive signed transaction, broadcast on-chain, update DB
 * 
 * Claw Pump signs the transaction from Step 1 with the agent's keypair,
 * then sends it here. We broadcast, confirm, and update our database.
 */
app.post('/api/platforms/clawpump/confirm', async (c) => {
  // Validate Claw Pump API key
  const apiKey = c.req.header('X-Platform-Key');
  const expectedKey = process.env.CLAWPUMP_API_KEY;
  
  if (!expectedKey || !apiKey || apiKey !== expectedKey) {
    return c.json({ error: "Invalid or missing X-Platform-Key header" }, 401);
  }
  
  const body = await c.req.json();
  const { signedTransaction, wallet, name, description, twitter, website, capabilities } = body;
  
  if (!signedTransaction || !wallet) {
    return c.json({ error: 'Required: signedTransaction (base64), wallet' }, 400);
  }
  
  try {
    // Deserialize and broadcast
    const txBuffer = Buffer.from(signedTransaction, 'base64');
    const tx = Transaction.from(txBuffer);
    
    // Verify the transaction has the expected signers
    const agentPubkey = new PublicKey(wallet);
    const signers = tx.signatures.map(s => s.publicKey.toBase58());
    if (!signers.includes(wallet)) {
      return c.json({ error: 'Transaction must be signed by the agent wallet' }, 400);
    }
    
    // Broadcast
    const rawTx = tx.serialize();
    const txHash = await connection.sendRawTransaction(rawTx, {
      skipPreflight: false,
      preflightCommitment: 'confirmed',
    });
    
    // Confirm
    const confirmation = await connection.confirmTransaction({
      signature: txHash,
      blockhash: tx.recentBlockhash!,
      lastValidBlockHeight: tx.lastValidBlockHeight!,
    }, 'confirmed');
    
    if (confirmation.value.err) {
      return c.json({ 
        error: 'Transaction failed on-chain',
        txHash,
        details: JSON.stringify(confirmation.value.err),
      }, 500);
    }
    
    // Success! Update database
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from('agent'), agentPubkey.toBuffer()],
      SAID_PROGRAM_ID
    );
    
    const metadataUri = `https://api.saidprotocol.com/api/cards/${wallet}.json`;
    
    // Upsert agent in DB (might exist from a previous partial attempt)
    const agent = await prisma.agent.upsert({
      where: { wallet },
      create: {
        wallet,
        pda: pda.toString(),
        owner: wallet,
        metadataUri,
        registeredAt: new Date(),
        isVerified: true,
        verifiedAt: new Date(),
        sponsored: true,
        name: name || 'Claw Pump Agent',
        description: description || 'AI Agent via Claw Pump',
        twitter: twitter || undefined,
        website: website || undefined,
        skills: capabilities || ['chat', 'assistant'],
        registrationSource: 'clawpump',
        layer2Verified: true,
        layer2VerifiedAt: new Date(),
        l2AttestationMethod: 'platform',
      },
      update: {
        isVerified: true,
        verifiedAt: new Date(),
        sponsored: true,
        registrationSource: 'clawpump',
        layer2Verified: true,
        layer2VerifiedAt: new Date(),
        l2AttestationMethod: 'platform',
      },
    });
    
    // Emit SSE event for real-time frontend updates
    emitAgentEvent('agent:registered', { wallet: agent.wallet, name: agent.name, source: 'clawpump', txHash });
    
    return c.json({
      success: true,
      message: 'Agent registered and verified ON-CHAIN via Claw Pump',
      txHash,
      explorer: `https://solscan.io/tx/${txHash}`,
      agent: {
        wallet: agent.wallet,
        pda: agent.pda,
        name: agent.name,
        verified: true,
        onChain: true,
        profile: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
        badge: `https://api.saidprotocol.com/api/badge/${wallet}.svg`,
        badgeWithScore: `https://api.saidprotocol.com/api/badge/${wallet}.svg?style=score`,
      },
      platform: {
        name: 'claw.pump',
        costCovered: '~0.015 SOL (rent + verification + fees)',
        sponsoredBy: 'SAID Protocol',
      }
    });
    
  } catch (error: any) {
    console.error('[Claw Pump Confirm Error]', error.message);
    
    // Recovery: if broadcast failed but agent exists on-chain, sync DB anyway
    // This handles: expired blockhash retries, "already initialized" errors
    try {
      const agentPubkey = new PublicKey(wallet);
      const [pda] = PublicKey.findProgramAddressSync(
        [Buffer.from('agent'), agentPubkey.toBuffer()],
        SAID_PROGRAM_ID
      );
      
      const accountInfo = await connection.getAccountInfo(pda);
      if (accountInfo) {
        console.log('[Claw Pump Recovery] Agent PDA exists on-chain, syncing DB...');
        const metadataUri = `https://api.saidprotocol.com/api/cards/${wallet}.json`;
        
        const agent = await prisma.agent.upsert({
          where: { wallet },
          create: {
            wallet,
            pda: pda.toString(),
            owner: wallet,
            metadataUri,
            registeredAt: new Date(),
            isVerified: true,
            verifiedAt: new Date(),
            sponsored: true,
            name: name || 'Claw Pump Agent',
            description: description || 'AI Agent via Claw Pump',
            twitter: twitter || undefined,
            website: website || undefined,
            skills: capabilities || ['chat', 'assistant'],
            registrationSource: 'clawpump',
            layer2Verified: true,
            layer2VerifiedAt: new Date(),
            l2AttestationMethod: 'platform',
          },
          update: {
            isVerified: true,
            verifiedAt: new Date(),
            sponsored: true,
            registrationSource: 'clawpump',
            layer2Verified: true,
            layer2VerifiedAt: new Date(),
            l2AttestationMethod: 'platform',
          },
        });
        
        emitAgentEvent('agent:registered', { wallet: agent.wallet, name: agent.name, source: 'clawpump', recovered: true });
        
        return c.json({
          success: true,
          message: 'Agent already registered on-chain. Database synced.',
          recovered: true,
          agent: {
            wallet: agent.wallet,
            pda: agent.pda,
            name: agent.name,
            verified: true,
            onChain: true,
            profile: `https://www.saidprotocol.com/agent.html?wallet=${wallet}`,
            badge: `https://api.saidprotocol.com/api/badge/${wallet}.svg`,
          },
        });
      }
    } catch (recoveryError: any) {
      console.error('[Claw Pump Recovery Failed]', recoveryError.message);
    }
    
    return c.json({ 
      error: 'Broadcast failed',
      details: error.message,
      support: 'contact@saidprotocol.com'
    }, 500);
  }
});
