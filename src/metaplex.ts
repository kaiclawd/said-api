/**
 * Metaplex Agent Registry Integration for SAID Protocol
 * 
 * Every verified SAID agent gets a Metaplex Core NFT with:
 * - ERC-8004 compatible registration document
 * - A2A service endpoint
 * - PDA for on-chain discovery
 * - Lifecycle hooks (Transfer, Update, Execute)
 */

import { createUmi } from '@metaplex-foundation/umi-bundle-defaults';
import { mplCore, create as createAsset, fetchCollection } from '@metaplex-foundation/mpl-core';
import { mplAgentIdentity } from '@metaplex-foundation/mpl-agent-registry';
import { registerIdentityV1 } from '@metaplex-foundation/mpl-agent-registry/dist/src/generated/identity/instructions/index.js';
import { generateSigner, keypairIdentity, publicKey as umiPublicKey } from '@metaplex-foundation/umi';
import { Keypair } from '@solana/web3.js';
import bs58 from 'bs58';

const SOLANA_RPC_URL = process.env.SOLANA_RPC || process.env.SOLANA_RPC_URL ||
  'https://newest-restless-mansion.solana-mainnet.quiknode.pro/af7d979a4ef8558eb0da3166819eac8af0d3dd2b';

const AGENT_COLLECTION_ADDRESS = process.env.METAPLEX_AGENT_COLLECTION;
const SAID_WEBSITE = 'https://www.saidprotocol.com';
const SAID_API = 'https://api.saidprotocol.com';
const SAID_PROGRAM_ID = '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G';

export interface MetaplexResult {
  success: boolean;
  assetAddress?: string;
  registrationUri?: string;
  signature?: string;
  error?: string;
}

export interface AgentInfo {
  wallet: string;
  name: string;
  description?: string;
  twitter?: string;
  website?: string;
  capabilities?: string[];
  mcpEndpoint?: string;
  a2aEndpoint?: string;
}

/**
 * Build ERC-8004 compatible agent registration document
 */
function buildRegistrationDocument(agent: AgentInfo): Record<string, unknown> {
  const services: Record<string, unknown>[] = [
    {
      name: 'web',
      endpoint: `${SAID_WEBSITE}/agents/${agent.wallet}`,
    },
    {
      name: 'A2A',
      endpoint: agent.a2aEndpoint || `${SAID_API}/api/a2a/agents/${agent.wallet}`,
      version: '1.2.0',
    },
  ];

  if (agent.mcpEndpoint) {
    services.push({
      name: 'MCP',
      endpoint: agent.mcpEndpoint,
      version: '2025-06-18',
    });
  }

  return {
    type: 'agent-registration-v1',
    name: agent.name,
    description: agent.description || `${agent.name} - AI Agent on SAID Protocol`,
    image: `${SAID_API}/api/agents/${agent.wallet}/avatar`,
    services,
    active: true,
    registrations: [
      {
        agentId: agent.wallet,
        agentRegistry: `solana:mainnet:${SAID_PROGRAM_ID}`,
      },
    ],
    supportedTrust: ['reputation', 'crypto-economic'],
    metadata: {
      capabilities: agent.capabilities || [],
      protocol: 'said-protocol',
      twitter: agent.twitter,
      website: agent.website,
    },
  };
}

/**
 * Get UMI instance with platform keypair for minting
 */
function getUmi() {
  // Use the same sponsor/platform key that signs registrations
  const encoded = process.env.SPONSOR_PRIVATE_KEY || process.env.PLATFORM_WALLET_KEYPAIR;
  if (!encoded) {
    throw new Error('SPONSOR_PRIVATE_KEY or PLATFORM_WALLET_KEYPAIR required for Metaplex minting');
  }

  const keypair = Keypair.fromSecretKey(bs58.decode(encoded));
  const umi = createUmi(SOLANA_RPC_URL)
    .use(mplCore())
    .use(mplAgentIdentity());

  const umiKeypair = umi.eddsa.createKeypairFromSecretKey(keypair.secretKey);
  umi.use(keypairIdentity(umiKeypair));

  return umi;
}

/**
 * Mint a Metaplex Core NFT and register agent identity.
 * Called after SAID verification succeeds.
 * 
 * Non-blocking — failure here should not break registration.
 */
export async function mintAgentNFT(agent: AgentInfo): Promise<MetaplexResult> {
  try {
    const umi = getUmi();

    const registrationDoc = buildRegistrationDocument(agent);
    // For now, registration doc is hosted at SAID API
    // TODO: Upload to Arweave for permanence
    const registrationUri = `${SAID_API}/api/cards/${agent.wallet}.json`;

    // Create MPL Core asset (NFT)
    const asset = generateSigner(umi);

    const createParams: Parameters<typeof createAsset>[1] = {
      asset,
      name: agent.name,
      uri: registrationUri,
    };

    if (AGENT_COLLECTION_ADDRESS) {
      try {
        await fetchCollection(umi, umiPublicKey(AGENT_COLLECTION_ADDRESS));
        (createParams as Record<string, unknown>).collection = umiPublicKey(AGENT_COLLECTION_ADDRESS);
      } catch (e) {
        console.warn('[metaplex] Collection not found, creating without collection');
      }
    }

    await createAsset(umi, createParams).sendAndConfirm(umi);
    console.log(`[metaplex] Created NFT asset: ${asset.publicKey} for ${agent.name}`);

    // Register identity on Metaplex Agent Registry
    const registerParams: Parameters<typeof registerIdentityV1>[1] = {
      asset: asset.publicKey,
      agentRegistrationUri: registrationUri,
    };

    if (AGENT_COLLECTION_ADDRESS) {
      (registerParams as Record<string, unknown>).collection = umiPublicKey(AGENT_COLLECTION_ADDRESS);
    }

    const result = await registerIdentityV1(umi, registerParams).sendAndConfirm(umi);
    console.log(`[metaplex] Registered identity for ${agent.name} (${asset.publicKey})`);

    return {
      success: true,
      assetAddress: asset.publicKey.toString(),
      registrationUri,
      signature: bs58.encode(result.signature),
    };
  } catch (error) {
    console.error('[metaplex] NFT mint failed:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Metaplex mint failed',
    };
  }
}

/**
 * Check if Metaplex minting is configured and available
 */
export function isMetaplexEnabled(): boolean {
  return !!(process.env.SPONSOR_PRIVATE_KEY || process.env.PLATFORM_WALLET_KEYPAIR);
}
