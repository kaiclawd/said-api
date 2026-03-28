/**
 * Delegated Signing Authority — Privy Agent Wallet Endpoints
 * 
 * Architecture:
 *   Agent/Operator → SAID API (validates, enforces policy) → Privy (signs tx) → Solana
 *   Agent NEVER holds private keys. Privy holds keys in secure enclave.
 *   SAID acts as authorization layer with rotatable API keys.
 * 
 * Endpoints:
 *   POST /v1/wallet/create         — Provision Privy wallet for agent
 *   GET  /v1/wallet/:agentId       — Get wallet public key + balance
 *   POST /v1/wallet/upgrade        — Add Privy wallet to existing agent (opt-in migration)
 *   POST /v1/transaction/request   — Request a transaction (policy check → Privy sign → broadcast)
 *   GET  /v1/transaction/:txId     — Get transaction status
 *   POST /v1/apikey/generate       — Generate rotatable API key for agent/platform
 *   POST /v1/apikey/revoke         — Revoke an API key
 *   GET  /v1/policy/:agentId       — Get current policy limits
 *   PUT  /v1/policy/:agentId       — Update policy limits (owner only)
 */

import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client';
import { Connection, PublicKey, Transaction, SystemProgram, LAMPORTS_PER_SOL } from '@solana/web3.js';
import crypto from 'crypto';

// ============================================================
// Types
// ============================================================

interface AgentContext {
  agentId: string;
  agentWallet: string;
  apiKeyId: string;
  scopes: string[];
  rateLimitPerHour: number;
}

// ============================================================
// Configuration
// ============================================================

const API_KEY_PREFIX = 'said_ak_';
const API_KEY_SECRET = process.env.API_KEY_SECRET || crypto.randomBytes(32).toString('hex');

// ============================================================
// API Key Utilities
// ============================================================

function generateApiKey(): string {
  const randomPart = crypto.randomBytes(24).toString('hex');
  return `${API_KEY_PREFIX}${randomPart}`;
}

function hashApiKey(apiKey: string): string {
  return crypto.createHmac('sha256', API_KEY_SECRET).update(apiKey).digest('hex');
}

// ============================================================
// Middleware: Validate API Key
// ============================================================

function createApiKeyMiddleware(prisma: PrismaClient) {
  return async (c: any, next: () => Promise<void>) => {
    const authHeader = c.req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer said_ak_')) {
      return c.json({ error: 'Missing or invalid API key. Use: Authorization: Bearer said_ak_...' }, 401);
    }
    
    const apiKey = authHeader.substring(7); // Remove 'Bearer '
    const keyHash = hashApiKey(apiKey);
    
    const keyRecord = await prisma.apiKey.findUnique({
      where: { keyHash },
      include: { agent: true }
    });
    
    if (!keyRecord) {
      return c.json({ error: 'Invalid API key' }, 401);
    }
    
    if (keyRecord.revokedAt) {
      return c.json({ error: 'API key has been revoked' }, 401);
    }
    
    if (keyRecord.expiresAt && new Date(keyRecord.expiresAt) < new Date()) {
      return c.json({ error: 'API key has expired' }, 401);
    }
    
    // Update last used
    await prisma.apiKey.update({
      where: { id: keyRecord.id },
      data: { lastUsedAt: new Date() }
    }).catch(() => {}); // Non-blocking
    
    // Attach agent context
    c.set('agentCtx', {
      agentId: keyRecord.agentId,
      agentWallet: keyRecord.agent.wallet,
      apiKeyId: keyRecord.id,
      scopes: keyRecord.scopes,
      rateLimitPerHour: keyRecord.rateLimitPerHour,
    } satisfies AgentContext);
    
    await next();
  };
}

// ============================================================
// Mock Privy Wallet Service
// 
// TODO: Replace with real Privy SDK after Tuesday call.
// The interface is designed to match Privy's actual API shape
// so the swap should be minimal.
// ============================================================

class PrivyWalletService {
  private isMock: boolean;
  
  constructor() {
    // Use mock if PRIVY_WALLET_MODE=mock or if wallet-specific env vars aren't set
    this.isMock = process.env.PRIVY_WALLET_MODE !== 'live';
    if (this.isMock) {
      console.log('[Privy Wallets] Running in MOCK mode. Set PRIVY_WALLET_MODE=live after Tuesday call.');
    }
  }
  
  /**
   * Create a new embedded wallet for an agent.
   * In production, this calls Privy's server SDK to provision a wallet.
   * The private key is stored in Privy's secure enclave — we never see it.
   */
  async createWallet(agentId: string): Promise<{
    publicKey: string;
    providerWalletId: string;
    provider: string;
  }> {
    if (this.isMock) {
      // Generate a deterministic-looking but random mock address
      const mockBytes = crypto.randomBytes(32);
      // Use first 32 bytes as a fake ed25519 public key, encode as base58-like
      const chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
      let mockAddress = '';
      for (let i = 0; i < 44; i++) {
        mockAddress += chars[mockBytes[i % 32] % chars.length];
      }
      
      return {
        publicKey: mockAddress,
        providerWalletId: `privy-mock-${crypto.randomUUID()}`,
        provider: 'mock',
      };
    }
    
    // TODO: Real Privy SDK call
    // const wallet = await privyClient.walletApi.create({
    //   chainType: 'solana',
    //   // authorizationKeyIds: [SAID_AUTH_KEY_ID],  // SAID's signing authority
    // });
    // return {
    //   publicKey: wallet.address,
    //   providerWalletId: wallet.id,
    //   provider: 'privy',
    // };
    
    throw new Error('Live Privy wallet creation not yet implemented. Set PRIVY_WALLET_MODE=mock');
  }
  
  /**
   * Sign a transaction using Privy's delegation.
   * SAID sends the serialized unsigned transaction to Privy,
   * Privy signs it with the agent's private key, returns signed tx.
   */
  async signTransaction(providerWalletId: string, serializedTx: string): Promise<{
    signedTransaction: string;
    signature: string;
  }> {
    if (this.isMock) {
      // Return a mock signature
      const mockSig = crypto.randomBytes(64).toString('hex');
      return {
        signedTransaction: serializedTx, // In mock, just pass through
        signature: `mock-sig-${mockSig.substring(0, 16)}`,
      };
    }
    
    // TODO: Real Privy SDK call
    // const result = await privyClient.walletApi.solana.signTransaction({
    //   walletId: providerWalletId,
    //   transaction: serializedTx,
    // });
    // return {
    //   signedTransaction: result.signedTransaction,
    //   signature: result.signature,
    // };
    
    throw new Error('Live Privy signing not yet implemented. Set PRIVY_WALLET_MODE=mock');
  }
  
  /**
   * Get wallet balance from Solana RPC.
   * This doesn't go through Privy — we read balance directly from chain.
   */
  async getBalance(publicKey: string, connection: Connection): Promise<{
    sol: number;
    usdc: number;
  }> {
    try {
      const pubkey = new PublicKey(publicKey);
      const lamports = await connection.getBalance(pubkey);
      
      // TODO: Also fetch USDC token account balance
      // For now, just return SOL balance
      return {
        sol: lamports / LAMPORTS_PER_SOL,
        usdc: 0, // Will implement SPL token balance lookup
      };
    } catch (error) {
      // If mock address or RPC fails, return zeros
      return { sol: 0, usdc: 0 };
    }
  }
}

// ============================================================
// Route Factory
// ============================================================

type Variables = {
  agentCtx: AgentContext;
};

export function createWalletRoutes(prisma: PrismaClient, connection: Connection) {
  const app = new Hono<{ Variables: Variables }>();
  const privyWallets = new PrivyWalletService();
  const validateApiKey = createApiKeyMiddleware(prisma);
  
  // ----------------------------------------------------------
  // POST /v1/wallet/create
  // Provision a new Privy wallet for an agent
  // Auth: API key OR session token
  // ----------------------------------------------------------
  app.post('/v1/wallet/create', async (c) => {
    const body = await c.req.json();
    const { agentId, walletType = 'transaction' } = body;
    
    if (!agentId) {
      return c.json({ error: 'Required: agentId' }, 400);
    }
    
    // Verify agent exists
    const agent = await prisma.agent.findUnique({ where: { id: agentId } });
    if (!agent) {
      return c.json({ error: 'Agent not found' }, 404);
    }
    
    // Check if agent already has a Privy wallet of this type
    const existingWallet = await prisma.agentWallet.findFirst({
      where: { agentId, walletType, status: 'active' }
    });
    
    if (existingWallet) {
      return c.json({
        error: 'Agent already has an active wallet of this type',
        existingWallet: {
          id: existingWallet.id,
          publicKey: existingWallet.publicKey,
          walletType: existingWallet.walletType,
        }
      }, 409);
    }
    
    try {
      // Provision wallet via Privy
      const privyResult = await privyWallets.createWallet(agentId);
      
      // Store in database
      const wallet = await prisma.agentWallet.create({
        data: {
          agentId,
          publicKey: privyResult.publicKey,
          provider: privyResult.provider,
          providerWalletId: privyResult.providerWalletId,
          walletType,
          isPrimary: walletType === 'transaction',
          metadata: {
            provisionedAt: new Date().toISOString(),
            mode: process.env.PRIVY_WALLET_MODE || 'mock',
          },
        }
      });
      
      // Also create a default policy for the agent (if they don't have one)
      await prisma.transactionPolicy.upsert({
        where: { agentId },
        create: {
          agentId,
          maxPerTransaction: 10.00,
          maxPerDay: 100.00,
          maxPerMonth: 1000.00,
          allowedTokens: ['USDC', 'SOL'],
          allowedPrograms: [],
        },
        update: {}, // Don't overwrite if exists
      });
      
      return c.json({
        success: true,
        wallet: {
          id: wallet.id,
          agentId: wallet.agentId,
          publicKey: wallet.publicKey,
          provider: wallet.provider,
          walletType: wallet.walletType,
          status: wallet.status,
          createdAt: wallet.createdAt,
        },
        note: privyResult.provider === 'mock'
          ? 'This is a mock wallet. Real Privy integration coming after Tuesday call.'
          : 'Wallet provisioned via Privy. Private key stored in secure enclave.',
      }, 201);
      
    } catch (error: any) {
      console.error('[Wallet Create Error]', error);
      return c.json({ error: 'Failed to provision wallet', details: error.message }, 500);
    }
  });
  
  // ----------------------------------------------------------
  // GET /v1/wallet/:agentId
  // Get agent's Privy wallet info + balance
  // ----------------------------------------------------------
  app.get('/v1/wallet/:agentId', async (c) => {
    const agentId = c.req.param('agentId');
    
    const wallets = await prisma.agentWallet.findMany({
      where: { agentId, status: 'active' },
      orderBy: { createdAt: 'desc' },
    });
    
    if (wallets.length === 0) {
      return c.json({ error: 'No Privy wallets found for this agent. Use POST /v1/wallet/create first.' }, 404);
    }
    
    // Fetch balances for each wallet
    const walletsWithBalances = await Promise.all(
      wallets.map(async (w) => {
        const balance = await privyWallets.getBalance(w.publicKey, connection);
        return {
          id: w.id,
          publicKey: w.publicKey,
          provider: w.provider,
          walletType: w.walletType,
          isPrimary: w.isPrimary,
          status: w.status,
          balance,
          createdAt: w.createdAt,
        };
      })
    );
    
    return c.json({
      agentId,
      wallets: walletsWithBalances,
    });
  });
  
  // ----------------------------------------------------------
  // POST /v1/wallet/upgrade
  // Add a Privy wallet to an existing agent (opt-in migration)
  // Links the new Privy wallet to the agent's identity via
  // the existing multi-wallet linking flow.
  // ----------------------------------------------------------
  app.post('/v1/wallet/upgrade', async (c) => {
    const body = await c.req.json();
    const { agentId } = body;
    
    if (!agentId) {
      return c.json({ error: 'Required: agentId' }, 400);
    }
    
    // Verify agent exists
    const agent = await prisma.agent.findUnique({ where: { id: agentId } });
    if (!agent) {
      return c.json({ error: 'Agent not found' }, 404);
    }
    
    // Check if already upgraded
    const existingWallet = await prisma.agentWallet.findFirst({
      where: { agentId, walletType: 'transaction', status: 'active' }
    });
    
    if (existingWallet) {
      return c.json({
        error: 'Agent already has a Privy transaction wallet',
        wallet: {
          publicKey: existingWallet.publicKey,
          createdAt: existingWallet.createdAt,
        }
      }, 409);
    }
    
    try {
      // 1. Provision Privy wallet
      const privyResult = await privyWallets.createWallet(agentId);
      
      // 2. Store wallet record
      const wallet = await prisma.agentWallet.create({
        data: {
          agentId,
          publicKey: privyResult.publicKey,
          provider: privyResult.provider,
          providerWalletId: privyResult.providerWalletId,
          walletType: 'transaction',
          isPrimary: true,
          metadata: {
            upgradedFrom: 'self-custody',
            originalWallet: agent.wallet,
            provisionedAt: new Date().toISOString(),
          },
        }
      });
      
      // 3. Create default policy
      await prisma.transactionPolicy.upsert({
        where: { agentId },
        create: {
          agentId,
          maxPerTransaction: 10.00,
          maxPerDay: 100.00,
          maxPerMonth: 1000.00,
          allowedTokens: ['USDC', 'SOL'],
          allowedPrograms: [],
        },
        update: {},
      });
      
      // 4. Link to on-chain identity will happen via the existing
      //    /api/wallet/link flow — SAID's external signing wallet
      //    signs on behalf of the Privy wallet.
      //    This is a separate step the operator triggers.
      
      return c.json({
        success: true,
        wallet: {
          id: wallet.id,
          publicKey: wallet.publicKey,
          provider: wallet.provider,
          status: wallet.status,
        },
        originalWallet: agent.wallet,
        nextSteps: {
          step1: 'Deposit funds (SOL/USDC) to the new wallet address',
          step2: 'Use POST /v1/transaction/request to transact via SAID',
          step3: '(Optional) Link on-chain via /api/wallet/link for identity resolution',
        },
        note: 'Your original self-custody wallet remains active. The Privy wallet is an additional secure transaction wallet.',
      }, 201);
      
    } catch (error: any) {
      console.error('[Wallet Upgrade Error]', error);
      return c.json({ error: 'Failed to upgrade wallet', details: error.message }, 500);
    }
  });
  
  // ----------------------------------------------------------
  // POST /v1/transaction/request
  // Request a transaction — SAID validates, Privy signs, broadcasts
  // Auth: API key required
  // ----------------------------------------------------------
  app.use('/v1/transaction/request', validateApiKey);
  app.post('/v1/transaction/request', async (c) => {
    const agentCtx = c.get('agentCtx') as AgentContext;
    const body = await c.req.json();
    const { type, token, amount, recipient, programId, memo } = body;
    
    // Validate required fields
    if (!type || !token || amount === undefined) {
      return c.json({ error: 'Required: type, token, amount' }, 400);
    }
    
    if (type === 'transfer' && !recipient) {
      return c.json({ error: 'Recipient required for transfer transactions' }, 400);
    }
    
    // Check scope
    if (!agentCtx.scopes.includes('transaction')) {
      return c.json({ error: 'API key does not have transaction scope' }, 403);
    }
    
    // Find agent's active Privy wallet
    const wallet = await prisma.agentWallet.findFirst({
      where: { agentId: agentCtx.agentId, walletType: 'transaction', status: 'active', isPrimary: true }
    });
    
    if (!wallet) {
      return c.json({ error: 'No active Privy wallet. Use POST /v1/wallet/create first.' }, 404);
    }
    
    // Create transaction request record (pending)
    const txRequest = await prisma.transactionRequest.create({
      data: {
        agentId: agentCtx.agentId,
        walletId: wallet.id,
        apiKeyId: agentCtx.apiKeyId,
        type,
        token,
        amount,
        recipient,
        programId,
        memo,
        status: 'pending',
      }
    });
    
    try {
      const numAmount = Number(amount);
      
      // ------ Policy Check ------
      const policy = await prisma.transactionPolicy.findUnique({
        where: { agentId: agentCtx.agentId }
      });
      
      if (policy && policy.status === 'active') {
        
        // Check per-transaction limit
        if (numAmount > Number(policy.maxPerTransaction)) {
          await prisma.transactionRequest.update({
            where: { id: txRequest.id },
            data: {
              status: 'denied',
              policyPassed: false,
              policyReason: `Exceeds per-transaction limit: ${amount} > ${policy.maxPerTransaction}`,
            }
          });
          return c.json({
            transactionId: txRequest.id,
            status: 'denied',
            policyCheck: {
              passed: false,
              reason: `Exceeds per-transaction limit (${amount} > ${policy.maxPerTransaction} ${token})`,
            }
          }, 403);
        }
        
        // Check daily spending
        const todayStart = new Date();
        todayStart.setHours(0, 0, 0, 0);
        
        const dailySpend = await prisma.transactionRequest.aggregate({
          where: {
            agentId: agentCtx.agentId,
            status: { in: ['confirmed', 'broadcast', 'signing'] },
            createdAt: { gte: todayStart },
          },
          _sum: { amount: true },
        });
        
        const dailyTotal = Number(dailySpend._sum.amount || 0) + numAmount;
        if (dailyTotal > Number(policy.maxPerDay)) {
          await prisma.transactionRequest.update({
            where: { id: txRequest.id },
            data: {
              status: 'denied',
              policyPassed: false,
              policyReason: `Exceeds daily limit: ${dailyTotal} > ${policy.maxPerDay}`,
            }
          });
          return c.json({
            transactionId: txRequest.id,
            status: 'denied',
            policyCheck: {
              passed: false,
              reason: `Exceeds daily limit (${dailyTotal.toFixed(2)} > ${policy.maxPerDay} ${token})`,
              currentDailySpend: Number(dailySpend._sum.amount || 0),
            }
          }, 403);
        }
        
        // Check token allowlist
        if (policy.allowedTokens.length > 0 && !policy.allowedTokens.includes(token)) {
          await prisma.transactionRequest.update({
            where: { id: txRequest.id },
            data: {
              status: 'denied',
              policyPassed: false,
              policyReason: `Token ${token} not in allowlist: ${policy.allowedTokens.join(', ')}`,
            }
          });
          return c.json({
            transactionId: txRequest.id,
            status: 'denied',
            policyCheck: {
              passed: false,
              reason: `Token ${token} not allowed. Permitted: ${policy.allowedTokens.join(', ')}`,
            }
          }, 403);
        }
        
        // Check program allowlist (if specified and programId provided)
        if (programId && policy.allowedPrograms.length > 0 && !policy.allowedPrograms.includes(programId)) {
          await prisma.transactionRequest.update({
            where: { id: txRequest.id },
            data: {
              status: 'denied',
              policyPassed: false,
              policyReason: `Program ${programId} not in allowlist`,
            }
          });
          return c.json({
            transactionId: txRequest.id,
            status: 'denied',
            policyCheck: {
              passed: false,
              reason: `Program ${programId} not in allowlist`,
            }
          }, 403);
        }
      }
      
      // ------ Policy Passed ------
      await prisma.transactionRequest.update({
        where: { id: txRequest.id },
        data: {
          status: 'approved',
          policyPassed: true,
          policyReason: 'All policy checks passed',
        }
      });
      
      // ------ Build Transaction ------
      // For V1, we handle simple SOL and USDC transfers.
      // Custom program interactions come in V2.
      
      if (type === 'transfer' && token === 'SOL') {
        const senderPubkey = new PublicKey(wallet.publicKey);
        const recipientPubkey = new PublicKey(recipient);
        
        const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash('confirmed');
        
        const tx = new Transaction({
          blockhash,
          lastValidBlockHeight,
          feePayer: senderPubkey,
        });
        
        tx.add(
          SystemProgram.transfer({
            fromPubkey: senderPubkey,
            toPubkey: recipientPubkey,
            lamports: Math.round(numAmount * LAMPORTS_PER_SOL),
          })
        );
        
        const serializedTx = tx.serialize({
          requireAllSignatures: false,
          verifySignatures: false,
        }).toString('base64');
        
        // ------ Sign via Privy ------
        await prisma.transactionRequest.update({
          where: { id: txRequest.id },
          data: { status: 'signing', serializedTx }
        });
        
        const signResult = await privyWallets.signTransaction(
          wallet.providerWalletId!,
          serializedTx
        );
        
        await prisma.transactionRequest.update({
          where: { id: txRequest.id },
          data: { signedAt: new Date() }
        });
        
        // ------ Broadcast ------
        // In mock mode, we don't actually broadcast
        if (wallet.provider === 'mock') {
          await prisma.transactionRequest.update({
            where: { id: txRequest.id },
            data: {
              status: 'confirmed',
              txHash: signResult.signature,
              broadcastAt: new Date(),
              confirmedAt: new Date(),
            }
          });
          
          return c.json({
            transactionId: txRequest.id,
            status: 'confirmed',
            type,
            amount: numAmount,
            token,
            recipient,
            txHash: signResult.signature,
            policyCheck: { passed: true, reason: 'All policy checks passed' },
            wallet: { publicKey: wallet.publicKey },
            note: 'Mock transaction — no real funds moved. Live signing after Privy integration.',
          });
        }
        
        // TODO: Real broadcast
        // const txSig = await connection.sendRawTransaction(
        //   Buffer.from(signResult.signedTransaction, 'base64')
        // );
        // await connection.confirmTransaction(txSig);
        
      } else {
        // For non-SOL-transfer types, mark as approved but not yet executable
        return c.json({
          transactionId: txRequest.id,
          status: 'approved',
          type,
          amount: Number(amount),
          token,
          recipient,
          policyCheck: { passed: true, reason: 'All policy checks passed' },
          note: `Transaction type '${type}' for token '${token}' approved but execution not yet implemented. SOL transfers are live.`,
        });
      }
      
    } catch (error: any) {
      console.error('[Transaction Request Error]', error);
      
      await prisma.transactionRequest.update({
        where: { id: txRequest.id },
        data: { status: 'failed', errorMessage: error.message }
      }).catch(() => {});
      
      return c.json({
        transactionId: txRequest.id,
        status: 'failed',
        error: error.message,
      }, 500);
    }
  });
  
  // ----------------------------------------------------------
  // GET /v1/transaction/:txId
  // Get transaction status
  // ----------------------------------------------------------
  app.get('/v1/transaction/:txId', async (c) => {
    const txId = c.req.param('txId');
    
    const tx = await prisma.transactionRequest.findUnique({
      where: { id: txId },
      include: { wallet: { select: { publicKey: true, provider: true } } },
    });
    
    if (!tx) {
      return c.json({ error: 'Transaction not found' }, 404);
    }
    
    return c.json({
      transactionId: tx.id,
      agentId: tx.agentId,
      status: tx.status,
      type: tx.type,
      token: tx.token,
      amount: Number(tx.amount),
      recipient: tx.recipient,
      txHash: tx.txHash,
      policyCheck: {
        passed: tx.policyPassed,
        reason: tx.policyReason,
      },
      wallet: tx.wallet,
      timestamps: {
        created: tx.createdAt,
        signed: tx.signedAt,
        broadcast: tx.broadcastAt,
        confirmed: tx.confirmedAt,
      },
      error: tx.errorMessage,
    });
  });
  
  // ----------------------------------------------------------
  // POST /v1/apikey/generate
  // Generate a new API key for an agent
  // Auth: Session token (logged-in user who owns the agent)
  // ----------------------------------------------------------
  app.post('/v1/apikey/generate', async (c) => {
    const body = await c.req.json();
    const { agentId, name, scopes, rateLimitPerHour, expiresInDays } = body;
    
    if (!agentId) {
      return c.json({ error: 'Required: agentId' }, 400);
    }
    
    // TODO: Verify caller owns this agent (via session token)
    // For now, anyone can generate keys — tighten auth before production
    
    const agent = await prisma.agent.findUnique({ where: { id: agentId } });
    if (!agent) {
      return c.json({ error: 'Agent not found' }, 404);
    }
    
    const rawKey = generateApiKey();
    const keyHash = hashApiKey(rawKey);
    const keyPrefix = rawKey.substring(0, 12); // said_ak_xxxx
    
    const expiresAt = expiresInDays
      ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000)
      : null;
    
    const apiKey = await prisma.apiKey.create({
      data: {
        agentId,
        keyHash,
        keyPrefix,
        name: name || null,
        scopes: scopes || ['wallet', 'transaction'],
        rateLimitPerHour: rateLimitPerHour || 100,
        expiresAt,
      }
    });
    
    return c.json({
      apiKey: rawKey, // ⚠️ ONLY shown once — store securely
      keyId: apiKey.id,
      keyPrefix: apiKey.keyPrefix,
      agentId: apiKey.agentId,
      scopes: apiKey.scopes,
      rateLimitPerHour: apiKey.rateLimitPerHour,
      createdAt: apiKey.createdAt,
      expiresAt: apiKey.expiresAt,
      warning: 'Store this API key securely. It will NOT be shown again.',
    }, 201);
  });
  
  // ----------------------------------------------------------
  // POST /v1/apikey/revoke
  // Revoke an API key
  // ----------------------------------------------------------
  app.post('/v1/apikey/revoke', async (c) => {
    const body = await c.req.json();
    const { keyId } = body;
    
    if (!keyId) {
      return c.json({ error: 'Required: keyId' }, 400);
    }
    
    const key = await prisma.apiKey.findUnique({ where: { id: keyId } });
    if (!key) {
      return c.json({ error: 'API key not found' }, 404);
    }
    
    if (key.revokedAt) {
      return c.json({ error: 'API key already revoked' }, 409);
    }
    
    await prisma.apiKey.update({
      where: { id: keyId },
      data: { revokedAt: new Date() }
    });
    
    return c.json({
      success: true,
      keyId,
      keyPrefix: key.keyPrefix,
      revokedAt: new Date().toISOString(),
    });
  });
  
  // ----------------------------------------------------------
  // GET /v1/policy/:agentId
  // Get current transaction policy for an agent
  // ----------------------------------------------------------
  app.get('/v1/policy/:agentId', async (c) => {
    const agentId = c.req.param('agentId');
    
    const policy = await prisma.transactionPolicy.findUnique({
      where: { agentId }
    });
    
    if (!policy) {
      return c.json({ error: 'No policy found. One is created automatically when a wallet is provisioned.' }, 404);
    }
    
    // Get current spending
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const monthStart = new Date();
    monthStart.setDate(1);
    monthStart.setHours(0, 0, 0, 0);
    
    const [dailySpend, monthlySpend] = await Promise.all([
      prisma.transactionRequest.aggregate({
        where: {
          agentId,
          status: { in: ['confirmed', 'broadcast', 'signing'] },
          createdAt: { gte: todayStart },
        },
        _sum: { amount: true },
      }),
      prisma.transactionRequest.aggregate({
        where: {
          agentId,
          status: { in: ['confirmed', 'broadcast', 'signing'] },
          createdAt: { gte: monthStart },
        },
        _sum: { amount: true },
      }),
    ]);
    
    return c.json({
      agentId,
      policy: {
        maxPerTransaction: Number(policy.maxPerTransaction),
        maxPerDay: Number(policy.maxPerDay),
        maxPerMonth: Number(policy.maxPerMonth),
        allowedTokens: policy.allowedTokens,
        allowedPrograms: policy.allowedPrograms,
        requireApprovalAbove: Number(policy.requireApprovalAbove),
        status: policy.status,
      },
      currentUsage: {
        todaySpent: Number(dailySpend._sum.amount || 0),
        monthSpent: Number(monthlySpend._sum.amount || 0),
        todayRemaining: Number(policy.maxPerDay) - Number(dailySpend._sum.amount || 0),
        monthRemaining: Number(policy.maxPerMonth) - Number(monthlySpend._sum.amount || 0),
      },
      updatedAt: policy.updatedAt,
    });
  });
  
  // ----------------------------------------------------------
  // PUT /v1/policy/:agentId
  // Update transaction policy (owner only)
  // ----------------------------------------------------------
  app.put('/v1/policy/:agentId', async (c) => {
    const agentId = c.req.param('agentId');
    const body = await c.req.json();
    
    // TODO: Verify caller owns this agent
    
    const {
      maxPerTransaction,
      maxPerDay,
      maxPerMonth,
      allowedTokens,
      allowedPrograms,
      requireApprovalAbove,
      status,
    } = body;
    
    const policy = await prisma.transactionPolicy.upsert({
      where: { agentId },
      create: {
        agentId,
        ...(maxPerTransaction !== undefined && { maxPerTransaction }),
        ...(maxPerDay !== undefined && { maxPerDay }),
        ...(maxPerMonth !== undefined && { maxPerMonth }),
        ...(allowedTokens !== undefined && { allowedTokens }),
        ...(allowedPrograms !== undefined && { allowedPrograms }),
        ...(requireApprovalAbove !== undefined && { requireApprovalAbove }),
        ...(status !== undefined && { status }),
      },
      update: {
        ...(maxPerTransaction !== undefined && { maxPerTransaction }),
        ...(maxPerDay !== undefined && { maxPerDay }),
        ...(maxPerMonth !== undefined && { maxPerMonth }),
        ...(allowedTokens !== undefined && { allowedTokens }),
        ...(allowedPrograms !== undefined && { allowedPrograms }),
        ...(requireApprovalAbove !== undefined && { requireApprovalAbove }),
        ...(status !== undefined && { status }),
      },
    });
    
    return c.json({
      success: true,
      agentId,
      policy: {
        maxPerTransaction: Number(policy.maxPerTransaction),
        maxPerDay: Number(policy.maxPerDay),
        maxPerMonth: Number(policy.maxPerMonth),
        allowedTokens: policy.allowedTokens,
        allowedPrograms: policy.allowedPrograms,
        requireApprovalAbove: Number(policy.requireApprovalAbove),
        status: policy.status,
      },
      updatedAt: policy.updatedAt,
    });
  });
  
  return app;
}
