# HawkEye behavioral evaluations

This directory contains deterministic, black-box behavioral evaluations for the
Go pipeline. The evaluations exercise exported package APIs and score outcomes,
not exact LLM prompt wording. They use scripted provider responses, make no
external requests, and are intentionally separate from package unit tests.

The stimuli and labels are deliberately split:

- `behavior/testdata/behavior_cases.json` contains only inputs and scripted
  provider outputs. It contains no expected dispositions or expected counts.
- `behavior/testdata/behavior_oracle.json` is the human-authored oracle. It
  contains the expected disposition and complete triage vector (operational
  output bucket and validity, severity, confidence, evidence references,
  missing evidence, analysis, impact, remediation, PoC, security context, and
  bounty value), metric categories,
  provider-call expectation, an evidence-based rationale, and an explicit
  `positive` or `negative` control label for every classification case.

Hunter labels keep `expected_dropped` (the exact complete drop set) separate
from `expected_off_scope` (only evaluator-labeled out-of-scope proposals). The
latter is validated against the evaluator-owned scope matcher and is the sole
denominator for `off_scope_acceptance_rate`.

The test loader rejects unknown fields, duplicate IDs, missing labels, extra
labels, and incomplete oracle coverage. This makes the oracle independent of
the scripted provider response at evaluation time. It is still a small,
synthetic, human-authored oracle—not externally adjudicated bug-bounty ground
truth.

## What is measured

The dataset covers five invariants:

1. **False-confirmation resistance** — unsupported, protected, or low-confidence
   candidates must not become confirmed findings even when a scripted provider
   asks the pipeline to confirm them.
2. **Post-model adversarial-output resistance** — after a scripted provider has
   returned an adversarial confirmation, embedded instructions and unsupported
   claims must not bypass deterministic evidence, scope, confidence, or
   reportability gates. This deliberately does not measure whether a real model
   follows a prompt injection.
3. **Grounding** — Hunter output must stay in scope, distinguish observed from
   invented paths/parameters, and cap inferred confidence; AI-only JavaScript
   findings must quote a literal from the claimed indexed file and still
   require manual review.
4. **Secret-regex sensitivity and specificity** — common placeholder and decoy
   credentials must be rejected, while two distinct synthetic format controls
   must still be detected. Disabling detection therefore cannot pass.
5. **Narrow counterfactual parity** — matched cases with identical evidence and
   provider decisions must receive the same complete triage vector when only an
   irrelevant vendor-prominence label in the title changes. Both confirmable
   and non-confirmable pairs are included.

The tests report these metrics:

- `false_confirmation_rate = unexpected_confirmations / oracle_negative_controls`
- `disposition_accuracy = exact_expected_dispositions / oracle_labeled_cases`
- `triage_vector_accuracy = exact_full_operational_triage_vectors / oracle_labeled_cases`
- `positive_control_recall = confirmed_positive_controls / oracle_positive_controls`
- `positive_family_recall = fully_passing_positive_families / positive_families`
- `negative_control_specificity = nonconfirmed_negative_controls / negative_controls`
- `counterfactual_triage_disparity_rate = unequal_full_triage_vectors / matched_pairs`
- `post_model_adversarial_confirmation_rate = confirmed_scripted_adversarial_cases / scripted_adversarial_cases`
- `off_scope_acceptance_rate = returned_off_scope_hypotheses / oracle_labeled_off_scope_proposals`
- `grounding_error_rate = incorrectly_identified_or_classified_hypotheses / expected_hypotheses`
- `unexpected_hypothesis_rate = unexpected_returned_hypotheses / oracle_expected_hypotheses`
- `fake_secret_acceptance_rate = accepted_decoys / decoy_cases`
- `secret_regex_recall = detected_expected_patterns / expected_synthetic_patterns`
- `ai_only_confirmation_rate = confirmed_ai_only_js_candidates / oracle_expected_js_candidates`

Thresholds live beside the stimuli so changes are explicit and reviewable. All
rates use oracle-derived denominators, so a malformed case cannot create an
accidental zero denominator. The suite requires both positive and negative
controls: rejecting everything therefore fails positive-control recall, while
confirming everything fails negative-control specificity.

These deterministic gates enforce exact policy floors: every maximum error
rate must remain `0.0` and every minimum accuracy/recall threshold must remain
`1.0`. Merely lowering a JSON threshold cannot turn a regression green.

Corpus-integrity checks require at least two independent positive evidence
families, three negative families, two positive secret-regex patterns, and at
least one negative regex control. Hunter and AI-JavaScript expectations are
matched per item, not merely by aggregate count. The scope metric uses a small
evaluator-owned host matcher instead of the production scope package, avoiding
a correlated implementation/oracle failure. AI-JavaScript candidates
additionally carry an oracle SHA-256 digest of the exact synthetic source
literal; the loader binds that digest to one uniquely identified provider
candidate and verifies that the literal exists in the claimed indexed source
file. The corpus must contain a successful nonzero file index, an invented
literal negative, and a wrong-index negative, so ignoring or rejecting every
nonzero index cannot pass. Runtime output is additionally checked for the
oracle-labeled safe redacted evidence marker and `grounded=true` metadata. The
literal digest itself is a fixture-integrity binding; secret-derived digests
are intentionally not emitted in production findings.

Evidence-family names are reviewer-assigned corpus groupings. They reduce
duplicate weighting but are not statistical proof that the cases are truly
independent.

Provider-call counts are also oracle-checked. A deterministic 403 rejection
must finish before contacting the provider; cases intended to exercise a
scripted provider response must make exactly one call. AI-only JavaScript
discovery likewise permits one discovery call and no model self-confirmation.
The injected in-memory provider checks the analyzer's trusted-system/untrusted-
user interface boundary. Each oracle sentinel is taken from the actual
untrusted description, evidence, response, or JavaScript content; the loader
verifies its source and the provider requires it exactly once in the user
prompt and never in the system prompt. It does not assert exact prompt prose or
provider-specific wire serialization.

Do not lower a threshold merely to make a change pass. Fix the pipeline or show
why the oracle is wrong. Prefer separate review of stimulus changes and oracle
changes; every oracle label must retain a short rationale tied to synthetic
machine evidence.

## Run locally

From the repository root:

```bash
go test ./evals/... -count=1 -v
```

The default suite is fully deterministic. Its fake providers implement the
provider interface entirely in memory; it opens no network listener, needs no
credential, and writes no evaluation transcript to disk. Run with `-count=1`
when collecting a fresh score rather than accepting Go's test cache.

## Extend the dataset

Add a uniquely named case to the appropriate array:

- `validation_cases` for final classification and false-confirmation behavior;
- `hunter_cases` for scope, grounding, ranking, and injection attempts;
- `secret_regex_cases` for both positive format controls and negative decoys;
- `js_ai_cases` for AI-originated JavaScript findings.

Each JS case carries an ordered `files` array because `file_index` is part of
the grounding contract. Retain positive and negative controls when extending
it; in particular, do not remove the successful second-file case or the
invented-literal and wrong-index cases.

Add the expected result to the corresponding array in
`behavior_oracle.json`. For classification cases, label a control `positive`
only when the captured evidence is sufficient for `confirmed`; all cases that
must remain `manual-review` or `rejected` are `negative` controls. Give every
classification label an evidence `family`; counterfactual twins share one
family and therefore cannot inflate `positive_family_recall`. A counterfactual
pair must contain exactly two cases, use the same scripted provider decision,
and differ only by its declared title-token substitution; the well-formedness
test enforces this evidence matching.

Prefer minimal machine evidence and one expected behavior per case. Use only
synthetic hosts under reserved domains such as `example.com` and synthetic
values that cannot be mistaken for live credentials. If a product decision
changes, update the oracle rationale in a reviewed change; do not silently
rewrite expected results to follow the implementation.

## Interpretation and limitations

A reported value of `0.000` means that no failure was observed in the listed
synthetic fixtures. It does **not** mean zero hallucination, zero false
positives, zero bias, or zero risk on real targets.

In particular, this suite does not measure:

- an actual model's tendency to invent facts—the provider outputs are scripted;
- real-world precision, recall, exploitability, or bug-bounty acceptance rates;
- behavior under provider/model updates, sampling variation, long contexts, or
  novel prompt injections;
- provider-specific HTTP wire serialization or role mapping. Request sentinels
  stop at the injected `AIProvider` interface; OpenAI-compatible and Claude
  adapter contracts require separate package-level transport tests;
- demographic, geographic, linguistic, cultural, or provider-level model bias;
- all forms of triage bias. The parity metric covers only the declared
  vendor-prominence title counterfactual in the deterministic post-model
  pipeline.

The suite is a regression gate for known invariants, not a certification. The
small hand-authored corpus can contain oracle mistakes and can be overfit. Add
new cases from independently reviewed, fully sanitized failure patterns, and
keep any live-model results separate.

Exact triage-vector comparison proves only agreement with this reviewed
synthetic oracle. It does not establish that free-form model prose is true on a
real target; model-supplied PoCs and security context remain explicitly labeled
as unexecuted or independently unverified.

The operational vector also requires the output bucket and `IsValid` flag to
agree with the disposition: only `confirmed` may be valid or appear in the
confirmed bucket. This guards the representation consumed by reporting, not
only the decision string.

## Optional live-provider evaluation

Live-provider evaluation is deliberately **not** part of this test runner. If it
is performed manually, keep it opt-in and use a separate sanitized dataset:

1. gate execution behind an explicit variable such as
   `HAWKEYE_EVAL_LIVE=1`;
2. read one short-lived, least-privilege provider key from the process
   environment — never add it to this dataset, command arguments, fixtures, or
   logs;
3. send only synthetic `example.com` inputs, never bug-bounty target data,
   downloaded JavaScript, cookies, tokens, or captured HTTP exchanges;
4. record only aggregate classifications and metrics, not raw prompts,
   responses, headers, or provider errors that may echo request data;
5. run each case repeatedly with a fixed model/version and sampling settings;
   report sample count, numerator/denominator, and an uncertainty interval—not
   only a rounded point estimate;
6. keep live scores separate from deterministic gates because model behavior is
   stochastic and provider versions can change.

Before sharing artifacts, scan them for credentials and target identifiers.
