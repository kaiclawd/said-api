// Cross-Chain Agent Communication Types

export type Chain = 'solana' | 'ethereum' | 'base' | 'arbitrum' | 'avalanche' | 'tron' | 'optimism' | 'polygon' | 'celo' | 'gnosis' | 'bnb';

export type RegistrySource = 'said' | 'erc8004' | 'solana-registry';

export interface UnifiedAgent {
  // Universal identity
  address: string;
  chain: Chain;
  source: RegistrySource;
  
  // Profile
  name: string;
  description: string;
  capabilities: string[];
  endpoint?: string;
  metadataUri?: string;
  
  // Trust
  verified: boolean;
  reputationScore: number;
  
  // Registry-specific
  tokenId?: number;       // ERC-8004 NFT ID
  saidWallet?: string;    // SAID Protocol wallet
  
  // Metadata
  registeredAt?: string;
  owner?: string;
  raw?: Record<string, any>;  // Original registry data
}

export interface CrossChainMessage {
  id: string;
  from: {
    address: string;
    chain: Chain;
  };
  to: {
    address: string;
    chain: Chain;
  };
  message: string;
  context?: Record<string, any>;
  signature?: string;
  status: 'created' | 'routed' | 'delivered' | 'failed';
  createdAt: string;
}

export interface CrossChainDiscoveryQuery {
  chains?: Chain[];
  capability?: string;
  verified?: boolean;
  minReputation?: number;
  name?: string;
  limit?: number;
}

// ERC-8004 contract addresses (same on all EVM chains via CREATE2)
export const ERC8004_IDENTITY_REGISTRY = '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';
export const ERC8004_REPUTATION_REGISTRY = '0x8004BAa17C55a88189AE136b182e5fdA19dE9b63';

// EVM chain RPC endpoints (public, free tier)
export const EVM_RPC: Record<string, string> = {
  ethereum: process.env.ETH_RPC_URL || 'https://eth.llamarpc.com',
  base: process.env.BASE_RPC_URL || 'https://mainnet.base.org',
  arbitrum: process.env.ARBITRUM_RPC_URL || 'https://arb1.arbitrum.io/rpc',
  avalanche: process.env.AVALANCHE_RPC_URL || 'https://api.avax.network/ext/bc/C/rpc',
  optimism: process.env.OPTIMISM_RPC_URL || 'https://mainnet.optimism.io',
  polygon: process.env.POLYGON_RPC_URL || 'https://polygon-rpc.com',
  celo: process.env.CELO_RPC_URL || 'https://forno.celo.org',
  gnosis: process.env.GNOSIS_RPC_URL || 'https://rpc.gnosischain.com',
  bnb: process.env.BNB_RPC_URL || 'https://bsc-dataseed1.binance.org',
};

// Minimal ERC-8004 Identity Registry ABI
export const IDENTITY_REGISTRY_ABI = [
  'function totalSupply() view returns (uint256)',
  'function tokenURI(uint256 tokenId) view returns (string)',
  'function ownerOf(uint256 tokenId) view returns (address)',
  'function balanceOf(address owner) view returns (uint256)',
  'function tokenOfOwnerByIndex(address owner, uint256 index) view returns (uint256)',
  'function tokenByIndex(uint256 index) view returns (uint256)',
  'event Transfer(address indexed from, address indexed to, uint256 indexed tokenId)',
];

// Minimal ERC-8004 Reputation Registry ABI
export const REPUTATION_REGISTRY_ABI = [
  'function getReputation(uint256 agentId) view returns (int256)',
  'function getFeedbackCount(uint256 agentId) view returns (uint256)',
];
