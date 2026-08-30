/**
 * Disqualifiers for reputation v0.8.
 *
 * WHY THIS EXISTS (read before adding a rule).
 *
 * The composite is a weighted blend of Beta posteriors — it answers
 * "how much good has this agent demonstrably done?". That is an ADDITIVE
 * question, and it structurally cannot answer a different one:
 * "should this agent be trusted at all?".
 *
 * Disqualification is a VETO, not a summand. This was measured, not
 * assumed: delivery is only 30% of the composite, so even a −40 penalty
 * on the delivery axis floors a diversified bad actor at ~0.52 — still
 * silver, still ranked. The remaining 70% (identity / payments / economic)
 * holds it up. No amount of negative evidence on one axis can express
 * "disqualified".
 *
 * So disqualifiers apply AFTER the blend, as a cap on the published
 * composite. Keep the two layers separate:
 *   - evidence layer  (posteriors.ts) — how much good, additively
 *   - policy layer    (this file)     — is the agent disqualified, as a veto
 *
 * Rules must key off facts that are cheap, already-collected, and hard to
 * fake. Every rule returns a human-readable `reason` — a trust layer that
 * demotes silently is indistinguishable from one that has no data, and an
 * unexplained demotion is not defensible to the agent it demotes.
 *
 * A rule states a verifiable FACT ("25 launches, 0 surviving"), never an
 * inference about intent ("rugger"). We publish what we measured.
 */

/** Parse an env var as a finite number, or null when unset/blank/invalid. */
function envNum(name: string): number | null {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

/**
 * Tuning. Magnitudes live in code (they are meaningless without the mcap
 * bars in economics-env.ts, which stay in env), but each is overridable so
 * a rule can be tightened in prod without a deploy.
 */
export const SERIAL_FAILURE_MIN_LAUNCHES = envNum('DISQUALIFY_MIN_LAUNCHES') ?? 5;
export const SERIAL_FAILURE_MAX_SURVIVAL_RATE = envNum('DISQUALIFY_MAX_SURVIVAL_RATE') ?? 0.15;
export const DISQUALIFY_COMPOSITE_CAP = envNum('DISQUALIFY_COMPOSITE_CAP') ?? 0.25;

export interface LaunchPortfolio {
  /** Total tokens this wallet has launched. */
  total: number;
  /** How many currently clear the survival bar (mcap + age gates). */
  survivors: number;
}

export interface Disqualification {
  /** Stable machine-readable code. */
  code: 'serial_launch_failure';
  /** Verifiable fact, safe to publish. Never an accusation. */
  reason: string;
  /** The composite ceiling this disqualification imposes. */
  cap: number;
}

/**
 * Serial launch failure: many launches, almost none survive.
 *
 * This measures a TRACK RECORD rather than forensically proving malice on
 * any single token, which is why it is both cheap (no RPC — DexScreener
 * data is already stored) and robust (it does not need to distinguish a
 * rug from an organic death; at this volume the distinction stops
 * mattering).
 *
 * Calibration, from the live top-100 as of 2026-08-30: 23 agents have
 * exactly 1 launch, one has 2, and one has 25. A threshold of 5 separates
 * the serial launcher from every honest builder with room to spare.
 *
 * Known evasion: splitting launches across wallets defeats any per-wallet
 * threshold. Closing that needs cross-wallet aggregation over the on-chain
 * WalletLink graph, which the scorer does not yet do.
 */
export function checkSerialLaunchFailure(p: LaunchPortfolio): Disqualification | null {
  if (p.total < SERIAL_FAILURE_MIN_LAUNCHES) return null;
  const survivalRate = p.survivors / p.total;
  if (survivalRate >= SERIAL_FAILURE_MAX_SURVIVAL_RATE) return null;
  return {
    code: 'serial_launch_failure',
    reason:
      `${p.total} tokens launched, ${p.survivors} still above the survival floor ` +
      `(${(survivalRate * 100).toFixed(0)}% survival)`,
    cap: DISQUALIFY_COMPOSITE_CAP,
  };
}

/**
 * Evaluate every disqualifier for one agent. Returns the STRONGEST
 * (lowest-cap) disqualification, or null if the agent is clear.
 */
export function evaluateDisqualifiers(input: {
  launches?: LaunchPortfolio;
}): Disqualification | null {
  const found: Disqualification[] = [];
  if (input.launches) {
    const d = checkSerialLaunchFailure(input.launches);
    if (d) found.push(d);
  }
  if (found.length === 0) return null;
  return found.reduce((worst, d) => (d.cap < worst.cap ? d : worst));
}

/** Apply a disqualification to a composite score. Pure. */
export function applyDisqualification(
  composite: number,
  d: Disqualification | null,
): number {
  return d ? Math.min(composite, d.cap) : composite;
}
