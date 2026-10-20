# Novelty Assessment Report

## Methodology
- Generate a fresh signature catalogue from reference sessions only; held-out sessions are excluded from all signature statistics and evidence.
- Compare each session against each signature using only compatible numerical features in the session `features` dict and the signature `feature_profile.selected_features` summary.
- For each compatible feature, normalize absolute deviation from the signature mean by standard deviation; if unavailable or zero, use the signature range, then `max(abs(mean), 1)` as the fallback scale. Cap normalized deviation at 10, convert it to similarity `max(0, 1 - min(d / 3, 1))`, then average available feature similarities.
- Use command-category Jaccard similarity when both the session and signature expose comparable command classes.
- Use authentication success-rate similarity only when `auth_success` and the stored signature authentication profile are available.
- Overall score is `0.70 * feature similarity + 0.20 * command Jaccard similarity + 0.10 * authentication similarity`; unavailable evidence is not imputed and contributes no similarity. Reported distance is `1 - score`.
- Treat unknown or incompatible feature sets as `Insufficient Evidence` rather than silently substituting values.
- `Known-like` requires the known threshold and a top-to-runner-up margin at least as large as the ambiguous margin; `Ambiguous` requires a score at least the borderline threshold with a smaller margin; otherwise comparable evidence below the known threshold is `Potentially Novel`.

## Evaluation design
- Evaluation mode: held-out-reference-signatures
- Reference sessions: 43
- Held-out sessions: 11
- Signatures generated from reference sessions: 3
- Split ratio: 0.2
- Split seed: 42
- Split manifest: `C:\AMRITA\Final_Year_Project_zero_day_27\adaptive-zero-day-honeypot\reports\novelty_assessment\held_out\session_split.json`
- Split method: sorted session IDs shuffled with Python random.Random(seed); held-out count is round(N * ratio), constrained to leave at least one session in each partition

## Thresholds
- Known-like threshold: 0.70
- Ambiguous margin: 0.05
- Minimum compatible feature comparisons: 1
- Borderline score: 0.60

## Category counts
- Known-like: 11
- Potentially Novel: 0
- Insufficient Evidence: 0
- Ambiguous: 0

## Closest matches
- a4c62363d8d6 -> sig-a9ba70ab199a9fc1 (score=0.845505, category=Known-like)
- 76bbeca4b01a -> sig-80f49f344b21151c (score=0.799103, category=Known-like)
- a38c819b1e32 -> sig-80f49f344b21151c (score=0.795594, category=Known-like)
- 9a4ec106110f -> sig-80f49f344b21151c (score=0.795187, category=Known-like)
- 61c8acc77ac0 -> sig-80f49f344b21151c (score=0.792669, category=Known-like)

## Data quality and limitations
- No join exclusions or data-quality warnings were found in the evaluated inputs.
- Signatures, feature statistics, command evidence, and authentication profiles were derived exclusively from the reference session IDs.
- Held-out numeric features were taken from the same existing dec_results.csv rows used to compute reference statistics; the DEC model and preprocessing were not retrained or changed.
- Existing DEC assignments are reused. If the DEC model or scaler was trained using these held-out sessions, this is a signature-level holdout conditional on the existing model, not an independent end-to-end model evaluation.
- The dataset has no suitable ground-truth novelty labels; category counts are descriptive and do not establish zero-day detection accuracy.
- This is a behavioural novelty assessment, not an attack classification or zero-day detection claim.
- No attack labels or ground-truth novelty labels were used; accuracy, precision, and recall are not reported.

