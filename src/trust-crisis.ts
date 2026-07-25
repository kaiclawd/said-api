/**
 * SAID Protocol — Trust Crisis Endpoint
 *
 * Empirically-grounded trust assessment that exposes the gap between
 * ERC-8004 reputation scores and economically-backed trust.
 *
 * Based on peer-reviewed research:
 *   "Can Trustless Agents Be Trusted? An Empirical Study of the ERC-8004
 *    Decentralized AI Agent Ecosystem" (arXiv, July 8, 2026)
 *
 * Key findings that this endpoint encodes:
 *   - 73.5% of ERC-8004 reviewers on Ethereum show coordinated Sybil behavior
 *   - After Sybil removal, 86.8% of rated agents on BSC and 77.9% on Base
 *     have ZERO valid feedback
 *   - Only 3-15% of registered agents expose live service endpoints
 *   - Reputation scores are not commensurable across reviewers
 *   - Peer review manipulation costs $0.003-$0.055 per attack
 *
 * SAID's alternative: economic skin-in-the-game (staking/slashing).
 * Staking requires real capital commitment. Slashing creates real consequences.
 * This cannot be Sybil-attacked without proportional capital.
 *
 * This endpoint returns a programmatic comparison for any wallet.
 */

import { Hono } from 'hono';
import { Connection, PublicKey } from '@solana/web3.js';
import { getEnforcementStatus, type EnforcementStatus } from './enforcement.js';

// ─── Types ──────────────────────────────────────────────────────────

export interface TrustCrisisReport {
  wallet: string;
  timestamp: string;

  /** SAID's economic enforcement data */
  economicTrust: EnforcementStatus;

  /** Reputation signals (from SAID API, if agent is registered) */
  reputationSignals: {
    feedbackCount: number;
    reputationScore: number | null;
    bayesianScore: number | null;
    trustScore: number | null;
    /** Whether these scores are vulnerable to Sybil manipulation */
    sybilVulnerable: boolean;
    sybilRiskNote: string;
  };

  /** ERC-8004 ecosystem context */
  erc8004Context: {
    /** The academic finding: reputation registries are gameable */
    reputationRegistryReliable: boolean;
    /** Percentage of ERC-8004 reviewers with Sybil behavior (by chain) */
    sybilRateEth: number;
    sybilRateBsc: number;
    sybilRateBase: number;
    /** Percentage of agents with zero valid feedback after Sybil removal */
    invalidatedAfterSybilRemovalBsc: number;
    invalidatedAfterSybilRemovalBase: number;
    /** Only 3-15% of registered agents have live endpoints */
    liveServiceEndpointRate: string;
    /** Cost to manipulate reputation scores */
    manipulationCostUsd: string;
    citation: string;
  };

  /** The verdict: which trust signal should you actually use? */
  trustVerdict: {
    /** The one number that ISN'T gameable */
    economicSecuritySol: number;
    /** Is this agent economically backed? */
    hasEconomicCommitment: boolean;
    /** How much skin in the game? */
    skinInGameLevel: 'none' | 'minimal' | 'moderate' | 'strong' | 'whale';
    /** Has this agent faced real consequences? */
    hasBeenSlashed: boolean;
    /** Final recommendation */
    recommendation: 'trusted' | 'caution' | 'review' | 'deny' | 'unknown';
    recommendationReason: string;
    /** Key insight for integrators */
    insight: string;
  };
}

// ─── Constants from the arXiv study ─────────────────────────────────

const SYBIL_RATE_ETH = 0.735;     // 73.5% of reviewers show Sybil behavior
const SYBIL_RATE_BSC = 0.592;     // 59.2%
const SYBIL_RATE_BASE = 0.906;    // 90.6%

const INVALIDATED_BSC = 0.868;    // 86.8% lose all feedback after Sybil removal
const INVALIDATED_BASE = 0.779;   // 77.9%

const LIVE_ENDPOINT_RANGE = '3-15%';
const MANIPULATION_COST = '$0.003-$0.055';
const CITATION = 'arXiv:2607.08084 — "Can Trustless Agents Be Trusted?" (July 8, 2026)';

// ─── Helper: classify stake level ───────────────────────────────────

function classifyStake(sol: number): 'none' | 'minimal' | 'moderate' | 'strong' | 'whale' {
  if (sol === 0) return 'none';
  if (sol < 0.5) return 'minimal';
  if (sol < 5) return 'moderate';
  if (sol < 50) return 'strong';
  return 'whale';
}

// ─── Helper: derive recommendation ──────────────────────────────────

function deriveRecommendation(
  enforcement: EnforcementStatus,
  feedbackCount: number,
): { recommendation: TrustCrisisReport['trustVerdict']['recommendation']; reason: string; insight: string } {
  // Slashed agents are high risk
  if (enforcement.slashCount >= 2) {
    return {
      recommendation: 'deny',
      reason: `Agent has been slashed ${enforcement.slashCount} times — economic penalties applied for bad behavior.`,
      insight: 'This agent has demonstrably faced real consequences. Slashing is irreversible and on-chain. The stake loss is the strongest trust signal available.',
    };
  }

  if (enforcement.slashCount === 1) {
    return {
      recommendation: 'review',
      reason: 'Agent has been slashed once. Investigate the incident before trusting.',
      insight: 'A single slashing event is a strong signal — this agent was caught doing something wrong and paid for it. Unlike a bad review, slashing means real SOL was destroyed.',
    };
  }

  // Strong economic commitment
  if (enforcement.stakeAmountSol >= 5 && !enforcement.isSlashed) {
    return {
      recommendation: 'trusted',
      reason: `Agent has ${enforcement.stakeAmountSol} SOL staked with zero slashing events — strong economic commitment.`,
      insight: 'This agent has real capital at risk. Any malicious behavior would result in slashing — loss of staked SOL. This is a stronger trust signal than any reputation score, which can be gamed for pennies.',
    };
  }

  // Moderate economic commitment
  if (enforcement.stakeAmountSol >= 0.5 && !enforcement.isSlashed) {
    return {
      recommendation: 'trusted',
      reason: `Agent has ${enforcement.stakeAmountSol} SOL staked with clean record.`,
      insight: 'Moderate economic skin-in-the-game. While reputation scores can be manipulated for $0.003-$0.055, this stake represents real financial commitment that would be lost through bad behavior.',
    };
  }

  // Minimal stake
  if (enforcement.stakeAmountSol > 0 && enforcement.stakeAmountSol < 0.5) {
    return {
      recommendation: 'caution',
      reason: `Agent has minimal stake (${enforcement.stakeAmountSol} SOL). Economic commitment is low.`,
      insight: 'While any stake is better than none, this amount is low enough that a bad actor could treat it as a cost of doing business. Request higher staking for high-value transactions.',
    };
  }

  // No stake, but has reputation
  if (feedbackCount > 0) {
    return {
      recommendation: 'review',
      reason: 'Agent has reputation scores but ZERO economic backing. Reputation is vulnerable to Sybil manipulation.',
      insight: 'This agent relies on reputation scores that academic research has proven are gameable. 73.5% of ERC-8004 reviewers show coordinated Sybil behavior. Without staking, there is no economic penalty for going rogue.',
    };
  }

  // Unknown agent
  return {
    recommendation: 'unknown',
    reason: 'Agent has no economic stake and no reputation data. Insufficient evidence.',
    insight: 'This wallet has neither economic backing nor reputation history. The "unknown ≠ zero" principle applies — this agent is not necessarily untrustworthy, but there is no signal to evaluate.',
  };
}

// ─── Hono Router ────────────────────────────────────────────────────

export function createTrustCrisisRouter(
  connection: Connection,
  fetchAgentData: (wallet: string) => Promise<{
    feedbackCount: number;
    reputationScore: number | null;
    bayesianScore: number | null;
    trustScore: number | null;
  }>,
): Hono {
  const router = new Hono();

  /**
   * GET /api/trust-crisis/:wallet
   *
   * Returns a trust crisis report comparing economic enforcement data
   * against reputation signals, with ERC-8004 context.
   *
   * This endpoint encodes findings from:
   *   arXiv:2607.08084 (July 8, 2026)
   *
   * Use this when deciding whether to trust an agent. The economicSecuritySol
   * field is the one number that cannot be faked.
   */
  router.get('/:wallet', async (c) => {
    const { wallet } = c.req.param();

    // Validate address
    try {
      new PublicKey(wallet);
    } catch {
      return c.json({ error: 'Invalid wallet address' }, 400);
    }

    try {
      // Parallel: enforcement data + reputation data
      const [enforcement, reputation] = await Promise.all([
        getEnforcementStatus(connection, wallet),
        fetchAgentData(wallet).catch(() => ({
          feedbackCount: 0,
          reputationScore: null,
          bayesianScore: null,
          trustScore: null,
        })),
      ]);

      const { recommendation, reason: recommendationReason, insight } = deriveRecommendation(
        enforcement,
        reputation.feedbackCount,
      );

      const skinInGameLevel = classifyStake(enforcement.stakeAmountSol);

      const report: TrustCrisisReport = {
        wallet,
        timestamp: new Date().toISOString(),
        economicTrust: enforcement,
        reputationSignals: {
          feedbackCount: reputation.feedbackCount,
          reputationScore: reputation.reputationScore,
          bayesianScore: reputation.bayesianScore,
          trustScore: reputation.trustScore,
          sybilVulnerable: reputation.feedbackCount > 0 && enforcement.stakeAmountSol === 0,
          sybilRiskNote:
            reputation.feedbackCount > 0 && enforcement.stakeAmountSol === 0
              ? 'This agent\'s reputation has NO economic backing. Academic research shows 73.5% of ERC-8004 reviewers exhibit Sybil behavior. These scores may be manipulated.'
              : reputation.feedbackCount > 0
                ? 'Reputation exists alongside economic stake — lower Sybil risk.'
                : 'No reputation data to manipulate.',
        },
        erc8004Context: {
          reputationRegistryReliable: false,
          sybilRateEth: SYBIL_RATE_ETH,
          sybilRateBsc: SYBIL_RATE_BSC,
          sybilRateBase: SYBIL_RATE_BASE,
          invalidatedAfterSybilRemovalBsc: INVALIDATED_BSC,
          invalidatedAfterSybilRemovalBase: INVALIDATED_BASE,
          liveServiceEndpointRate: LIVE_ENDPOINT_RANGE,
          manipulationCostUsd: MANIPULATION_COST,
          citation: CITATION,
        },
        trustVerdict: {
          economicSecuritySol: enforcement.economicSecuritySol,
          hasEconomicCommitment: enforcement.stakeAmountSol > 0,
          skinInGameLevel,
          hasBeenSlashed: enforcement.slashCount > 0,
          recommendation,
          recommendationReason,
          insight,
        },
      };

      return c.json(report);
    } catch (error) {
      console.error(`[trust-crisis] Failed for ${wallet}:`, error);
      return c.json({
        error: 'Failed to generate trust crisis report',
        details: error instanceof Error ? error.message : 'Unknown error',
      }, 500);
    }
  });

  /**
   * GET /api/trust-crisis
   *
   * Returns the research context without a specific wallet lookup.
   * Useful for educational/integration purposes.
   */
  router.get('/', (c) => {
    return c.json({
      title: 'The ERC-8004 Trust Crisis',
      subtitle: 'Why reputation scores are broken — and how economic enforcement fixes it',
      citation: CITATION,
      findings: {
        sybilBehaviorRates: {
          ethereum: `${(SYBIL_RATE_ETH * 100).toFixed(1)}% of reviewers`,
          bsc: `${(SYBIL_RATE_BSC * 100).toFixed(1)}% of reviewers`,
          base: `${(SYBIL_RATE_BASE * 100).toFixed(1)}% of reviewers`,
        },
        agentsWithNoValidFeedback: {
          bsc: `${(INVALIDATED_BSC * 100).toFixed(1)}% lose all feedback after Sybil removal`,
          base: `${(INVALIDATED_BASE * 100).toFixed(1)}% lose all feedback after Sybil removal`,
        },
        liveServiceEndpoints: `Only ${LIVE_ENDPOINT_RANGE} of registered agents have live endpoints`,
        manipulationCost: `Reputation manipulation costs ${MANIPULATION_COST} per attack`,
      },
      saidAlternative: {
        mechanism: 'Staking + Slashing (economic skin-in-the-game)',
        advantage: 'Requires real capital commitment that cannot be faked for pennies',
        programId: '5dpw6KEQPn248pnkkaYyWfHwu2nfb3LUMbTucb6LaA8G',
        endpoints: {
          enforcement: 'GET /api/enforcement/:wallet',
          trustCrisis: 'GET /api/trust-crisis/:wallet',
        },
      },
      integrationGuide: {
        step1: 'Query GET /api/trust-crisis/:wallet for any agent',
        step2: 'Check trustVerdict.recommendation (trusted/caution/review/deny/unknown)',
        step3: 'Use trustVerdict.economicSecuritySol as the primary trust metric',
        step4: 'Cross-reference reputationSignals for secondary signal only',
      },
    });
  });

  return router;
}
