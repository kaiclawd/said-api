/**
 * Trust-screen logic for GET /api/screen — "should my agent pay this counterparty?"
 *
 * Kept separate from the route handler in index.ts so it's unit-testable without
 * booting the whole server. Reads SAID's computed v0.8 reputation and maps it to
 * an allow/review/caution verdict for an agent about to pay this wallet.
 *
 * Verdicts use *positive-evidence* reputation only — we assert "allow" on an
 * established track record and never fabricate a "block" we have no fraud data
 * for, so "no reputation" maps to "review", not "block".
 *
 * Operator-continuity gate: reputation binds to the agent *identity* (the PDA /
 * wallet), but authority over that identity can transfer to a new controller via
 * the on-chain `transfer_authority` instruction. A track record earned under a
 * prior operator should not be vouched for at full strength once the identity has
 * changed hands — that's the reputation-laundering vector (acquire a high-rep
 * agent, inherit its trust, behave differently). We surface continuity explicitly
 * and soft-downgrade an `allow` to `review` when the identity has transferred. We
 * never block on it — transfers can be benign (key rotation, custody migration).
 */
import type { PrismaClient } from '@prisma/client';
import { getV8Reputation } from './reputation-v0.8/read.js';

export interface OperatorIntegrity {
  // Is the historical reputation continuous with whoever controls the identity now?
  continuity: 'continuous' | 'transferred' | 'unknown';
  authorityTransfers: number; // count of transfer_authority instructions seen
  walletLinkChurn: number; // link+unlink events — secondary instability signal (informational)
  flags: string[];
  note: string;
}

export interface ScreenResult {
  wallet: string;
  verdict: 'allow' | 'review' | 'caution';
  score: number | null; // 0–100 composite, null if unscored
  tier: string;
  registered: boolean;
  verified: boolean;
  scored: boolean;
  confidence: 'high' | 'medium' | 'low';
  reason: string;
  axes: Record<string, { score: number; confidenceFloor: number; signals: number }>;
  eigentrust: number | null;
  integrity: OperatorIntegrity;
  computedAt: Date | null;
  source: string;
}

// Minimal slice of AgentSaidEngagement the integrity assessment reads.
export interface EngagementInput {
  transferAuthorityCount: number;
  linkWalletCount: number;
  unlinkWalletCount: number;
}

/**
 * Classify operator continuity from on-chain engagement counters. Pure — no DB —
 * so the laundering logic is unit-testable in isolation.
 *
 * `null` engagement (wallet has no scanned SAID-instruction record) maps to
 * `unknown`, not `transferred`: on a positive-evidence screen we don't penalize
 * absent data, we just mark continuity unverified.
 */
export function assessOperatorIntegrity(eng: EngagementInput | null): OperatorIntegrity {
  if (!eng) {
    return {
      continuity: 'unknown',
      authorityTransfers: 0,
      walletLinkChurn: 0,
      flags: [],
      note: 'No on-chain operator-engagement record — identity continuity unverified.',
    };
  }

  const authorityTransfers = eng.transferAuthorityCount ?? 0;
  const walletLinkChurn = (eng.linkWalletCount ?? 0) + (eng.unlinkWalletCount ?? 0);
  const flags: string[] = [];
  if (authorityTransfers > 0) flags.push(`authority_transferred_x${authorityTransfers}`);
  if (walletLinkChurn >= 4) flags.push('high_wallet_link_churn');

  if (authorityTransfers > 0) {
    return {
      continuity: 'transferred',
      authorityTransfers,
      walletLinkChurn,
      flags,
      note: `Authority over this identity has transferred ${authorityTransfers}× — historical reputation may have been earned by a prior controller (reputation-laundering risk).`,
    };
  }

  return {
    continuity: 'continuous',
    authorityTransfers,
    walletLinkChurn,
    flags,
    note: 'Authority over this identity has not transferred; reputation is continuous with the current controller.',
  };
}

const SOURCE_SCORED =
  'SAID Protocol reputation v0.8 — computed Bayesian per-axis posteriors + EigenTrust over 5,600+ Solana agents';

export async function buildScreenResult(prisma: PrismaClient, wallet: string): Promise<ScreenResult> {
  const agent = await prisma.agent.findUnique({
    where: { wallet },
    select: { isVerified: true },
  });

  // Unknown wallet: not a registered SAID agent → no identity to vouch for.
  if (!agent) {
    return {
      wallet,
      verdict: 'review',
      score: null,
      tier: 'unranked',
      registered: false,
      verified: false,
      scored: false,
      confidence: 'low',
      reason:
        'Not a registered SAID agent — no verifiable identity or reputation on record. Verify out-of-band before paying.',
      axes: {},
      eigentrust: null,
      integrity: assessOperatorIntegrity(null),
      computedAt: null,
      source: 'SAID Protocol reputation v0.8',
    };
  }

  // Reputation + operator-engagement read in parallel — the latter drives the
  // continuity gate below.
  const [rep, engagement] = await Promise.all([
    getV8Reputation(prisma, wallet).catch((err) => {
      console.error('[/api/screen] v8 reputation read failed', wallet, err);
      return null;
    }),
    prisma.agentSaidEngagement
      .findUnique({
        where: { wallet },
        select: { transferAuthorityCount: true, linkWalletCount: true, unlinkWalletCount: true },
      })
      .catch((err) => {
        console.error('[/api/screen] engagement read failed', wallet, err);
        return null;
      }),
  ]);
  const integrity = assessOperatorIntegrity(engagement);

  const scored = !!rep?.found;
  const tier = scored ? rep!.tier : 'unranked';
  const composite = scored ? rep!.compositeScore : 0;
  const samples = rep?.totalSamples ?? 0;
  const score = scored ? Math.round(composite * 100) : null;
  const confidence = samples >= 30 ? 'high' : samples >= 10 ? 'medium' : 'low';

  let verdict: 'allow' | 'review' | 'caution';
  let reason: string;
  if (!scored) {
    verdict = 'review';
    reason = agent.isVerified
      ? 'Verified SAID identity but no reputation evidence yet (no track record to score). Proceed with caution on a first interaction.'
      : 'Registered but unverified, with no reputation evidence yet. Verify out-of-band before paying.';
  } else if (tier === 'platinum' || tier === 'gold') {
    verdict = 'allow';
    reason = `Established ${tier} reputation (composite ${score}/100) across ${samples} signals. Safe to transact.`;
  } else if (tier === 'silver') {
    verdict = 'review';
    reason = `Moderate reputation (silver, ${score}/100, ${samples} signals). Reasonable, but review for high-value transactions.`;
  } else {
    verdict = 'caution';
    reason = `Low reputation (${tier}, ${score}/100, ${samples} signals). Limited or weak track record — caution advised.`;
  }

  // Operator-continuity gate. We will not vouch ("allow") for a reputation that
  // may belong to a prior controller: if authority over the identity has
  // transferred, soft-downgrade allow → review. Lower verdicts are already
  // cautious, so we leave them and just attach the integrity note.
  if (integrity.continuity === 'transferred' && verdict === 'allow') {
    verdict = 'review';
    reason = `Established ${tier} reputation (composite ${score}/100, ${samples} signals), BUT authority over this identity has transferred ${integrity.authorityTransfers}× — the track record may have been earned by a prior controller. Re-verify the current operator before paying.`;
  }

  // Per-axis breakdown — SAID's differentiator vs a flat feedback average.
  const axes = scored
    ? Object.fromEntries(
        Object.entries(rep!.axes).map(([axis, v]) => [
          axis,
          {
            score: Math.round(v!.posteriorMean * 100),
            confidenceFloor: Math.round(v!.lowerBound95 * 100),
            signals: v!.sampleSize,
          },
        ]),
      )
    : {};

  return {
    wallet,
    verdict,
    score,
    tier,
    registered: true,
    verified: agent.isVerified,
    scored,
    confidence,
    reason,
    axes,
    eigentrust: scored ? Number(rep!.eigentrustScore.toFixed(4)) : null,
    integrity,
    computedAt: rep?.computedAt ?? null,
    source: SOURCE_SCORED,
  };
}
