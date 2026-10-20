# Novelty Assessment Report

## Methodology
- Load the project's behavioural signatures from the stored `behaviour_signatures.json` artifact.
- Compare each session against each signature using only compatible numerical features in the session `features` dict and the signature `feature_profile.selected_features` summary.
- Use command-category Jaccard similarity when both the session and signature expose comparable command classes.
- Use authentication success-rate similarity only when `auth_success` and the stored signature authentication profile are available.
- Treat unknown or incompatible feature sets as `Insufficient Evidence` rather than silently substituting values.
- Use the configured thresholds for `Known-like`, `Potentially Novel`, `Ambiguous`, and `Insufficient Evidence` decisions.

## Thresholds
- Known-like threshold: 0.70
- Ambiguous margin: 0.05
- Borderline score: 0.60

## Category counts
- Known-like: 54
- Potentially Novel: 0
- Insufficient Evidence: 0
- Ambiguous: 0

## Closest matches
- 4f8484ce537b -> sig-b1feaa1697ecd1bb (score=1.0, category=Known-like)
- e6aae1f4915d -> sig-7a800a68707bfcfd (score=0.892869, category=Known-like)
- ca8bbbfd6366 -> sig-7a800a68707bfcfd (score=0.889478, category=Known-like)
- a6c3b1926d4e -> sig-7a800a68707bfcfd (score=0.886399, category=Known-like)
- 1f53fe8bd0ff -> sig-7a800a68707bfcfd (score=0.881271, category=Known-like)

