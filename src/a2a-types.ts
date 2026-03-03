// A2A Protocol Types
// Based on Agent2Agent specification v0.3.0

export interface AgentCard {
  name: string;
  description: string;
  capabilities: string[];
  endpoint: string;
  version: string;
  said?: {
    verified: boolean;
    wallet: string;
    reputationScore: number;
    registeredAt: string;
    feedbackCount?: number;
  };
  authentication?: {
    methods: string[];
    required: boolean;
  };
}

export interface A2AMessage {
  from: string;
  to: string;
  message: string;
  context?: Record<string, any>;
  timestamp: string;
}

export interface A2ATask {
  id: string;
  from: string;
  to: string;
  message: string;
  context?: Record<string, any>;
  status: 'created' | 'working' | 'complete' | 'failed';
  progress?: number;
  result?: any;
  createdAt: string;
  updatedAt: string;
}

export interface DiscoveryQuery {
  capability?: string;
  verified?: boolean;
  chain?: 'solana' | 'ethereum' | 'all';
  minReputation?: number;
  limit?: number;
}
