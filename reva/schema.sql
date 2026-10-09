-- Reva calibration memory. Idempotent: safe to run on every start.
-- Database name is `reva` here; reva/analytics.py rewrites the prefix when REVA_CLICKHOUSE_DATABASE differs.

CREATE DATABASE IF NOT EXISTS reva;

-- One row per screening. ReplacingMergeTree because the verified outcome arrives after the row:
-- the writer re-inserts the same row with `outcome` filled and a higher `version`.
-- ORDER BY leads with the hot-path predicate (sink_kind, guarded) so the prior query prunes granules.
CREATE TABLE IF NOT EXISTS reva.screenings
(
    screening_id  UUID,
    ts            DateTime64(3),
    repo          LowCardinality(String),
    file          String,
    function      String,
    sink_kind     LowCardinality(String),           -- '' when the gate found no flow at all
    guarded       UInt8,
    guards        Array(LowCardinality(String)),
    semgrep_rules Array(LowCardinality(String)),
    p_llm         Float32,                          -- -1 when no LLM call was made
    confidence    Float32,
    escalated     UInt8,
    prior_rate    Float32,                          -- -1 when no prior was applied
    prior_n       UInt32,
    gate_ms       Float32,
    prior_ms      Float32,
    semgrep_ms    Float32,
    llm_ms        Float32,
    total_ms      Float32,
    outcome       LowCardinality(String),           -- '' until the sandbox proof lands
    finding_id    String,
    version       UInt64,
    INDEX idx_rules semgrep_rules TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(ts)
ORDER BY (sink_kind, guarded, screening_id);

-- One row per sandbox proof, append-only. The screening's shape is denormalised onto it so the
-- rollup below needs no join: a verdict carries its own (sink_kind, guarded, semgrep_rules).
CREATE TABLE IF NOT EXISTS reva.verdicts
(
    ts            DateTime64(3),
    screening_id  UUID,
    finding_id    String,
    repo          LowCardinality(String),
    sink_kind     LowCardinality(String),
    guarded       UInt8,
    semgrep_rules Array(LowCardinality(String)),
    outcome       LowCardinality(String),           -- confirmed | rejected | suspected
    confidence    Float32,
    validate_ms   Float32
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (sink_kind, guarded, ts);

-- The prior, pre-aggregated. One row per (sink_kind, guarded, rule); `rule = ''` is the
-- unconditional bucket. At most a few hundred rows ever, so the hot-path lookup is a point read
-- whose cost does not grow with the corpus.
CREATE TABLE IF NOT EXISTS reva.prior_rollup
(
    sink_kind LowCardinality(String),
    guarded   UInt8,
    rule      LowCardinality(String),
    confirmed UInt64,
    total     UInt64
)
ENGINE = SummingMergeTree
ORDER BY (sink_kind, guarded, rule);

-- Only *proven* labels become priors: 'suspected' means the probe could not decide, which says
-- nothing about the code. ARRAY JOIN emits one row per firing rule plus the '' bucket, so
-- `rule = 'x'` has exactly the semantics of `has(semgrep_rules, 'x')`.
CREATE MATERIALIZED VIEW IF NOT EXISTS reva.prior_mv TO reva.prior_rollup AS
SELECT
    sink_kind,
    guarded,
    rule,
    toUInt64(outcome = 'confirmed') AS confirmed,
    toUInt64(1)                     AS total
FROM reva.verdicts
ARRAY JOIN arrayConcat([''], semgrep_rules) AS rule
WHERE outcome IN ('confirmed', 'rejected');
