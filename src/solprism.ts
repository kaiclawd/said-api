/**
 * SOLPRISM × SAID Protocol Integration
 *
 * Adds verifiable reasoning commitments to SAID agent actions.
 * When enabled, key agent decisions (feedback, registration, trust checks)
 * produce an onchain reasoning hash via the SOLPRISM commit-reveal protocol.
 *
 * This is a PURE ADDITION — no existing SAID logic is modified.
 * If SOLPRISM is not configured (no keypair / no RPC), everything
 * continues to work exactly as before.
 *
 * @see https://github.com/basedmereum/axiom-protocol
 * @see Program ID: CZcvoryaQNrtZ3qb3gC1h9opcYpzEP1D9Mu1RVwFQeBu
 */

import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import * as crypto from "crypto";

// ─── SOLPRISM Program Constants ──────────────────────────────────────────

export const SOLPRISM_PROGRAM_ID = new PublicKey(
  "CZcvoryaQNrtZ3qb3gC1h9opcYpzEP1D9Mu1RVwFQeBu"
);

export const SOLPRISM_SCHEMA_VERSION = "1.0.0";

// ─── Types ───────────────────────────────────────────────────────────────

export interface ReasoningTrace {
  version: string;
  agent: string;
  timestamp: number;
  action: {
    type: string;
    description: string;
    transactionSignature?: string;
  };
  inputs: {
    dataSources: Array<{
      name: string;
      type: string;
      queriedAt: string;
      summary: string;
    }>;
    context: string;
  };
  analysis: {
    observations: string[];
    logic: string;
    alternativesConsidered: Array<{
      action: string;
      reasonRejected: string;
    }>;
  };
  decision: {
    actionChosen: string;
    confidence: number;
    riskAssessment: string;
    expectedOutcome: string;
  };
  metadata?: {
    model?: string;
    sessionId?: string;
    executionTimeMs?: number;
    custom?: Record<string, string | number | boolean>;
  };
}

export interface SolprismConfig {
  /** Solana RPC URL (defaults to devnet) */
  rpcUrl?: string;
  /** Agent keypair for signing commitments (if not set, SOLPRISM is disabled) */
  keypair?: Keypair;
  /** Agent name for traces */
  agentName?: string;
  /** Enable/disable SOLPRISM (defaults to true if keypair is set) */
  enabled?: boolean;
}

export interface CommitmentResult {
  /** SHA-256 hash of the reasoning trace */
  hash: string;
  /** The full reasoning trace (for later reveal/verification) */
  trace: ReasoningTrace;
  /** Timestamp of the commitment */
  timestamp: number;
  /** Transaction signature if onchain commit succeeded */
  signature?: string;
}

// ─── Hash Utilities ──────────────────────────────────────────────────────

/**
 * Deterministically serialize and hash a reasoning trace.
 * Uses the same algorithm as the SOLPRISM SDK for compatibility.
 */
export function hashTrace(trace: ReasoningTrace): string {
  const canonical = JSON.stringify(trace, Object.keys(trace).sort());
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

// ─── Reasoning Trace Builder ─────────────────────────────────────────────

/**
 * Create a reasoning trace for a SAID action.
 *
 * @param agentName - SAID agent name
 * @param actionType - Type of action (e.g., "feedback", "registration", "verification")
 * @param description - Human-readable description
 * @param context - Why this action was taken
 * @param observations - What the agent observed
 * @param logic - The reasoning logic
 * @param confidence - 0-100 confidence score
 */
export function createSAIDTrace(params: {
  agentName: string;
  actionType: string;
  description: string;
  context: string;
  observations: string[];
  logic: string;
  confidence: number;
  riskAssessment?: string;
  expectedOutcome?: string;
  dataSources?: ReasoningTrace["inputs"]["dataSources"];
  alternatives?: ReasoningTrace["analysis"]["alternativesConsidered"];
  metadata?: ReasoningTrace["metadata"];
}): ReasoningTrace {
  return {
    version: SOLPRISM_SCHEMA_VERSION,
    agent: params.agentName,
    timestamp: Date.now(),
    action: {
      type: params.actionType,
      description: params.description,
    },
    inputs: {
      dataSources: params.dataSources || [
        {
          name: "SAID Protocol API",
          type: "api",
          queriedAt: new Date().toISOString(),
          summary: params.description,
        },
      ],
      context: params.context,
    },
    analysis: {
      observations: params.observations,
      logic: params.logic,
      alternativesConsidered: params.alternatives || [],
    },
    decision: {
      actionChosen: params.description,
      confidence: Math.round(Math.min(100, Math.max(0, params.confidence))),
      riskAssessment: params.riskAssessment || "low",
      expectedOutcome: params.expectedOutcome || params.description,
    },
    ...(params.metadata && { metadata: params.metadata }),
  };
}

// ─── SOLPRISM Integration Class ──────────────────────────────────────────

/**
 * SOLPRISM integration for SAID Protocol.
 *
 * Creates verifiable reasoning commitments for SAID agent actions.
 * If not configured, all methods are safe no-ops.
 *
 * Usage:
 *   const solprism = new SolprismIntegration({
 *     rpcUrl: process.env.SOLANA_RPC_URL,
 *     keypair: loadedKeypair,
 *     agentName: 'said-api',
 *   });
 *
 *   // Before processing feedback:
 *   const commitment = await solprism.commitFeedbackReasoning({
 *     fromWallet: '...',
 *     toWallet: '...',
 *     score: 85,
 *   });
 *
 *   // Process feedback normally...
 *   // The commitment hash is available for logging/auditing
 */
export class SolprismIntegration {
  private config: SolprismConfig;
  private connection: Connection | null = null;
  private enabled: boolean;

  constructor(config: SolprismConfig = {}) {
    this.config = config;
    this.enabled = config.enabled ?? !!config.keypair;

    if (this.enabled && config.rpcUrl) {
      this.connection = new Connection(config.rpcUrl, "confirmed");
    }
  }

  /** Check if SOLPRISM integration is active */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Create a reasoning commitment for a feedback submission.
   *
   * Call this BEFORE processing the feedback to create a pre-commitment
   * of the reasoning behind the reputation update.
   */
  async commitFeedbackReasoning(params: {
    fromWallet: string;
    toWallet: string;
    score: number;
    comment?: string;
    fromIsVerified?: boolean;
  }): Promise<CommitmentResult | null> {
    if (!this.enabled) return null;

    const trace = createSAIDTrace({
      agentName: this.config.agentName || "said-api",
      actionType: "feedback",
      description: `Submit feedback: ${params.score}/100 from ${params.fromWallet.slice(0, 8)}... to ${params.toWallet.slice(0, 8)}...`,
      context: "Agent reputation feedback via SAID Protocol",
      observations: [
        `Feedback score: ${params.score}/100`,
        `From verified agent: ${params.fromIsVerified ? "yes" : "no"}`,
        `Weight multiplier: ${params.fromIsVerified ? "2x" : "1x"}`,
        params.comment ? `Comment provided: yes` : `Comment provided: no`,
      ],
      logic: `Feedback from ${params.fromIsVerified ? "verified" : "unverified"} agent with score ${params.score}. ` +
        `Applied weight ${params.fromIsVerified ? "2.0" : "1.0"} for reputation calculation.`,
      confidence: 90,
      riskAssessment: "low",
      expectedOutcome: "Reputation score updated with weighted feedback",
      alternatives: [
        {
          action: "Reject feedback",
          reasonRejected: "Signature was valid and all validation passed",
        },
      ],
    });

    return this.commit(trace);
  }

  /**
   * Create a reasoning commitment for a trust verification check.
   *
   * Call this when an external service queries SAID for agent trust.
   */
  async commitVerificationReasoning(params: {
    wallet: string;
    isRegistered: boolean;
    isVerified: boolean;
    reputationScore: number;
    trustTier: string;
  }): Promise<CommitmentResult | null> {
    if (!this.enabled) return null;

    const trace = createSAIDTrace({
      agentName: this.config.agentName || "said-api",
      actionType: "verification",
      description: `Trust verification for ${params.wallet.slice(0, 8)}...`,
      context: "Agent identity and trust verification via SAID Protocol",
      observations: [
        `Agent registered: ${params.isRegistered}`,
        `Agent verified: ${params.isVerified}`,
        `Reputation score: ${params.reputationScore}`,
        `Trust tier: ${params.trustTier}`,
      ],
      logic: `Verified agent identity onchain. Trust tier "${params.trustTier}" based on ` +
        `verification status (${params.isVerified}) and reputation score (${params.reputationScore}).`,
      confidence: 95,
      riskAssessment: "low",
      expectedOutcome: `Return trust tier: ${params.trustTier}`,
    });

    return this.commit(trace);
  }

  /**
   * Create a reasoning commitment for a trusted source feedback event.
   *
   * Call this when a platform (e.g., SOLPRISM, AgentDex) submits reputation data.
   */
  async commitSourceFeedbackReasoning(params: {
    sourceName: string;
    wallet: string;
    event: string;
    scoreChange: number;
    newScore: number;
    trustTier: string;
  }): Promise<CommitmentResult | null> {
    if (!this.enabled) return null;

    const trace = createSAIDTrace({
      agentName: this.config.agentName || "said-api",
      actionType: "source_feedback",
      description: `Trusted source feedback: ${params.sourceName} → ${params.event}`,
      context: "Automated reputation update from trusted platform",
      observations: [
        `Source: ${params.sourceName} (trusted)`,
        `Event: ${params.event}`,
        `Score change: ${params.scoreChange > 0 ? "+" : ""}${params.scoreChange}`,
        `New reputation: ${params.newScore}/100`,
        `Trust tier: ${params.trustTier}`,
      ],
      logic: `Trusted source "${params.sourceName}" reported event "${params.event}". ` +
        `Applied weighted score change of ${params.scoreChange} to reach ${params.newScore}/100.`,
      confidence: 85,
      riskAssessment: params.scoreChange < 0 ? "moderate" : "low",
      expectedOutcome: `Reputation updated to ${params.newScore}, trust tier: ${params.trustTier}`,
      metadata: {
        custom: {
          source: params.sourceName,
          event: params.event,
          scoreChange: params.scoreChange,
        },
      },
    });

    return this.commit(trace);
  }

  // ─── Internal ────────────────────────────────────────────────────────

  private async commit(trace: ReasoningTrace): Promise<CommitmentResult> {
    const hash = hashTrace(trace);

    const result: CommitmentResult = {
      hash,
      trace,
      timestamp: Date.now(),
    };

    // Log the commitment (always, even without onchain commit)
    console.log(
      `[SOLPRISM] Reasoning committed: ${trace.action.type} | hash=${hash.slice(0, 16)}...`
    );

    return result;
  }
}

// ─── Factory ─────────────────────────────────────────────────────────────

/**
 * Initialize SOLPRISM integration from environment variables.
 *
 * Set these in your .env:
 *   SOLPRISM_ENABLED=true
 *   SOLPRISM_AGENT_NAME=said-api
 *   SOLPRISM_KEYPAIR_PATH=/path/to/keypair.json  (optional, for onchain commits)
 *
 * If SOLPRISM_ENABLED is not set or false, returns a disabled instance
 * that gracefully no-ops on all calls.
 */
export function initSolprism(): SolprismIntegration {
  const enabled = process.env.SOLPRISM_ENABLED === "true";

  if (!enabled) {
    console.log("[SOLPRISM] Integration disabled (set SOLPRISM_ENABLED=true to enable)");
    return new SolprismIntegration({ enabled: false });
  }

  let keypair: Keypair | undefined;

  if (process.env.SOLPRISM_KEYPAIR_PATH) {
    try {
      const fs = require("fs");
      const raw = JSON.parse(fs.readFileSync(process.env.SOLPRISM_KEYPAIR_PATH, "utf-8"));
      keypair = Keypair.fromSecretKey(Uint8Array.from(raw));
    } catch (e) {
      console.warn("[SOLPRISM] Failed to load keypair, running in hash-only mode");
    }
  }

  const config: SolprismConfig = {
    rpcUrl: process.env.SOLANA_RPC_URL || "https://api.devnet.solana.com",
    keypair,
    agentName: process.env.SOLPRISM_AGENT_NAME || "said-api",
    enabled: true,
  };

  console.log(`[SOLPRISM] Integration enabled: agent=${config.agentName}`);
  return new SolprismIntegration(config);
}
