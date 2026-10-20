# Novelty Assessment Report

## Methodology
- Load the project's behavioural signatures from the stored `behaviour_signatures.json` artifact.
- Compare each session against each signature using only compatible numerical features in the session `features` dict and the signature `feature_profile.selected_features` summary.
- For each compatible feature, normalize absolute deviation from the signature mean by standard deviation; if unavailable or zero, use the signature range, then `max(abs(mean), 1)` as the fallback scale. Cap normalized deviation at 10, convert it to similarity `max(0, 1 - min(d / 3, 1))`, then average available feature similarities.
- Use command-category Jaccard similarity when both the session and signature expose comparable command classes.
- Use authentication success-rate similarity only when `auth_success` and the stored signature authentication profile are available.
- Overall score is `0.70 * feature similarity + 0.20 * command Jaccard similarity + 0.10 * authentication similarity`; unavailable evidence is not imputed and contributes no similarity. Reported distance is `1 - score`.
- Treat unknown or incompatible feature sets as `Insufficient Evidence` rather than silently substituting values.
- `Known-like` requires the known threshold, a top-to-runner-up margin at least as large as the ambiguous margin, and no direct contradiction in available command-category or authentication evidence; `Ambiguous` requires a score at least the borderline threshold with a smaller margin; otherwise comparable evidence below the known threshold is `Potentially Novel`.

## Reference independence
- Evaluation mode: independent
- Reference catalogue session IDs: 43
- Assessed sessions overlapping the reference catalogue: 0

## Thresholds
- Known-like threshold: 0.70
- Ambiguous margin: 0.05
- Minimum compatible feature comparisons: 1
- Borderline score: 0.60

## Category counts
- Known-like: 5
- Potentially Novel: 0
- Insufficient Evidence: 0
- Ambiguous: 0

## Closest matches
- e22808051703 -> sig-47521826f16efd4b (score=0.836283, category=Known-like)
- 68c0f1a58402 -> sig-47521826f16efd4b (score=0.819806, category=Known-like)
- 458003a74c58 -> sig-47521826f16efd4b (score=0.798658, category=Known-like)
- 50ce19c43b81 -> sig-47521826f16efd4b (score=0.78442, category=Known-like)
- 860e0bc4a018 -> sig-47521826f16efd4b (score=0.728341, category=Known-like)

