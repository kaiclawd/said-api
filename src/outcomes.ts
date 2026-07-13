/**
 * Partner outcomes logic for POST /api/outcomes/batch — the write-back door
 * for platforms that execute agent work (EarnFi, Squire, Virtuals ACP, …) and
 * report how it went. Every accepted outcome becomes one Feedback row, which
 * the v0.8 backfill cron turns into a reputation event.
 *
 * Kept separate from the route handler in index.ts so the mapping and
 * validation logic is unit-testable without booting the server.
 *
 * POLARITY CONTRACT with the v0.8 scorer: the backfill classifies each
 * Feedback row with `score >= 50 → feedback_pos, else feedback_neg`
 * (scripts/v8-backfill-events.ts on feat/reputation-v0.8). So outcome scores
 * MUST land on the correct side of 50 — a "success" stored as a small delta
 * like 8 reads as strongly negative. This exact bug is why the legacy
 * /api/sources/feedback door marked partner successes as negative.
 *
 * IDEMPOTENCY: partners retry. Each outcome carries a partner-scoped
 * externalId (their job/transaction id — e.g. an ACP jobId); we derive
 * sourceKey = `src:<partner>:<externalId>`, unique in the DB, so replays
 * dedupe instead of double-counting.
 */

export interface PartnerSource {
  name: string;
  weight: number;
}

// Single source of truth for partner write-back credentials. Keys live in
// env vars; a partner with no key set simply doesn't exist as a caller.
// Legacy named vars are kept for existing deployments; NEW partners are added
// via PARTNER_SOURCE_KEYS ("name:key:weight,name:key:weight") so the public
// code never carries a partner roster.
const PARTNER_ENV_TABLE: Array<{ env: string; name: string; weight: number }> = [
  { env: 'TORCH_API_KEY', name: 'torch-market', weight: 1.5 },
  { env: 'SOLPRISM_API_KEY', name: 'solprism', weight: 1.5 },
  { env: 'AGENTDEX_API_KEY', name: 'agentdex', weight: 1.2 },
];

export function loadPartnerSources(env: NodeJS.ProcessEnv): Record<string, PartnerSource> {
  const sources: Record<string, PartnerSource> = {};
  for (const row of PARTNER_ENV_TABLE) {
    const key = env[row.env];
    if (key) sources[key] = { name: row.name, weight: row.weight };
  }
  for (const entry of (env.PARTNER_SOURCE_KEYS ?? '').split(',')) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const [name, key, weightRaw] = trimmed.split(':');
    const weight = Number(weightRaw);
    if (!name || !key || !Number.isFinite(weight) || weight <= 0 || weight > 3) {
      console.error(`[outcomes] skipping malformed PARTNER_SOURCE_KEYS entry for "${name || trimmed}"`);
      continue;
    }
    sources[key] = { name, weight };
  }
  return sources;
}

// Accepted outcome vocabulary. Polarity comes from the outcome, never from
// the event name — partners use their own event vocab ("trade_executed",
// "inference_served", …) and we don't gatekeep it.
const POSITIVE_OUTCOMES = new Set(['success', 'completed', 'positive']);
const NEGATIVE_OUTCOMES = new Set(['failure', 'failed', 'negative']);

export const OUTCOME_SCORE_POSITIVE = 80;
export const OUTCOME_SCORE_NEGATIVE = 20;

export function outcomeToScore(outcome: string): number | null {
  if (POSITIVE_OUTCOMES.has(outcome)) return OUTCOME_SCORE_POSITIVE;
  if (NEGATIVE_OUTCOMES.has(outcome)) return OUTCOME_SCORE_NEGATIVE;
  return null; // unknown outcome — rejected per-item, not silently skipped
}

export interface OutcomeItem {
  wallet: string; // SAID-registered agent that did the work
  event: string; // partner's own event name
  outcome: string; // success|completed|positive|failure|failed|negative
  externalId: string; // partner-scoped idempotency key (job id, tx id, …)
  occurredAt?: string; // ISO timestamp of the outcome; defaults to now
  details?: string; // free-text context, stored in the comment
}

export const MAX_BATCH_SIZE = 500;

// Clock skew we tolerate on occurredAt before calling it "in the future".
const FUTURE_TOLERANCE_MS = 5 * 60 * 1000;

export interface ItemValidation {
  ok: boolean;
  error?: string;
  score?: number; // set when ok
  occurredAt?: Date; // parsed, set when ok and provided
}

export function validateOutcomeItem(item: unknown, now: Date): ItemValidation {
  if (item === null || typeof item !== 'object') {
    return { ok: false, error: 'Item must be an object' };
  }
  const o = item as Record<string, unknown>;

  if (typeof o.wallet !== 'string' || o.wallet.length < 32 || o.wallet.length > 64) {
    return { ok: false, error: 'wallet must be a base58 wallet address string' };
  }
  if (typeof o.event !== 'string' || o.event.length === 0 || o.event.length > 64) {
    return { ok: false, error: 'event must be a non-empty string (max 64 chars)' };
  }
  if (typeof o.outcome !== 'string') {
    return { ok: false, error: 'outcome is required' };
  }
  const score = outcomeToScore(o.outcome);
  if (score === null) {
    return { ok: false, error: `Unknown outcome "${o.outcome}" — use success|failure` };
  }
  if (typeof o.externalId !== 'string' || o.externalId.length === 0 || o.externalId.length > 128) {
    return { ok: false, error: 'externalId is required (partner-scoped idempotency key, max 128 chars)' };
  }
  if (o.details !== undefined && (typeof o.details !== 'string' || o.details.length > 500)) {
    return { ok: false, error: 'details must be a string (max 500 chars)' };
  }

  let occurredAt: Date | undefined;
  if (o.occurredAt !== undefined) {
    if (typeof o.occurredAt !== 'string') {
      return { ok: false, error: 'occurredAt must be an ISO timestamp string' };
    }
    const parsed = new Date(o.occurredAt);
    if (Number.isNaN(parsed.getTime())) {
      return { ok: false, error: 'occurredAt is not a valid timestamp' };
    }
    if (parsed.getTime() > now.getTime() + FUTURE_TOLERANCE_MS) {
      return { ok: false, error: 'occurredAt is in the future' };
    }
    occurredAt = parsed;
  }

  return { ok: true, score, occurredAt };
}

export function buildSourceKey(partnerName: string, externalId: string): string {
  return `src:${partnerName}:${externalId}`;
}

export function buildOutcomeComment(
  partnerName: string,
  event: string,
  outcome: string,
  details?: string
): string {
  return `[${partnerName}] ${event}: ${outcome}${details ? ` — ${details}` : ''}`;
}
