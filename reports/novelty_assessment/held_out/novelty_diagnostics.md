# Held-out Novelty Diagnostics

This report diagnoses the saved held-out results produced by the original alphabetical feature-profile selection. The saved assessment artifacts are preserved; threshold sensitivity evaluates the candidate grid using the current decision rules. This is a diagnostic of signature-level matching, not an attack-detection performance report.

## Score distribution
- Sessions: 11
- Minimum: 0.712500
- Maximum: 0.845505
- Mean: 0.787685
- Median: 0.790621
- Standard deviation (population): 0.029318
- Standard deviation (sample): 0.030749

## Per-session scores
| Session | Closest signature | Best | Second | Margin | Features (best) | Category |
|---|---|---:|---:|---:|---:|---|
| 4d2398ddaebd | sig-80f49f344b21151c | 0.785760 | 0.650799 | 0.134961 | 8 | Known-like |
| 51fb60d24936 | sig-80f49f344b21151c | 0.779610 | 0.650946 | 0.128664 | 8 | Known-like |
| 61c8acc77ac0 | sig-80f49f344b21151c | 0.792669 | 0.650828 | 0.141841 | 8 | Known-like |
| 735512cb6ad6 | sig-80f49f344b21151c | 0.790621 | 0.650820 | 0.139801 | 8 | Known-like |
| 76bbeca4b01a | sig-80f49f344b21151c | 0.799103 | 0.650856 | 0.148247 | 8 | Known-like |
| 9a4ec106110f | sig-80f49f344b21151c | 0.795187 | 0.650880 | 0.144307 | 8 | Known-like |
| a38c819b1e32 | sig-80f49f344b21151c | 0.795594 | 0.650878 | 0.144716 | 8 | Known-like |
| a4c62363d8d6 | sig-a9ba70ab199a9fc1 | 0.845505 | 0.664782 | 0.180723 | 8 | Known-like |
| bdf3eea00cb2 | sig-80f49f344b21151c | 0.777651 | 0.650765 | 0.126886 | 8 | Known-like |
| ccba58b29c45 | sig-80f49f344b21151c | 0.712500 | 0.651451 | 0.061049 | 8 | Known-like |
| e422abb51310 | sig-80f49f344b21151c | 0.790332 | 0.650818 | 0.139514 | 8 | Known-like |

Detailed components and feature-level comparisons are in `score_diagnostics.csv`.

## Why sessions matched
- Signature match counts: {'sig-80f49f344b21151c': 10, 'sig-a9ba70ab199a9fc1': 1}.
- The saved result schema did not persist component scores. This diagnostic reconstructs them by rerunning the existing comparison function with the saved signatures and the same DEC feature rows; the score formula and production defaults are unchanged.
- Each matched signature's feature similarity is averaged across that signature's selected features and then receives 70% of the total score. Command-category Jaccard receives 20%; authentication similarity receives 10%. Unavailable categorical values contribute zero without renormalizing the weights.
- Ten of eleven sessions matched the failed-authentication cluster profile with no command categories on either side: command evidence is unavailable, not contradictory. Their authentication outcome matches the signature's 0% success rate. Their selected numeric features are very similar, but the selected profile has mostly constant dimensions.
- The remaining session matched the mixed-behaviour profile; its command-category Jaccard similarity and authentication similarity both contribute positively.
- Compare the per-feature values and weighted contributions in the CSV. Largest contributors are explicitly ranked per session; do not interpret constant dimensions as discriminative evidence merely because the value agrees.

## Reference signature feature ranges and variability
- **sig-804cd308f8da0466** (cluster 0, n=1): 8/8 selected features have no estimated variability. Command categories: ['file_system']; authentication success rate: 100.0%.
  - `ackdat` mean=0.561605, std=None, range=[0.561605, 0.561605]; `ct_dst_ltm` mean=54.0, std=None, range=[54.0, 54.0]; `ct_src_ltm` mean=54.0, std=None, range=[54.0, 54.0]; `ct_srv_dst` mean=54.0, std=None, range=[54.0, 54.0]; `ct_srv_src` mean=54.0, std=None, range=[54.0, 54.0]; `ct_state_ttl` mean=1.0, std=None, range=[1.0, 1.0]; `dbytes` mean=337.0, std=None, range=[337.0, 337.0]; `dinpkt` mean=0.131427, std=None, range=[0.131427, 0.131427]
- **sig-a9ba70ab199a9fc1** (cluster 1, n=6): 5/8 selected features have no estimated variability. Command categories: ['reconnaissance', 'file_system', 'privilege_escalation', 'credential_attack', 'file_transfer', 'networking']; authentication success rate: 100.0%.
  - `ackdat` mean=0.57558517, std=0.03516113, range=[0.558807, 0.647275]; `ct_dst_ltm` mean=54.0, std=0.0, range=[54.0, 54.0]; `ct_src_ltm` mean=54.0, std=0.0, range=[54.0, 54.0]; `ct_srv_dst` mean=54.0, std=0.0, range=[54.0, 54.0]; `ct_srv_src` mean=54.0, std=0.0, range=[54.0, 54.0]; `ct_state_ttl` mean=1.0, std=0.0, range=[1.0, 1.0]; `dbytes` mean=1670.66666667, std=133.08894269, range=[1399.0, 1725.0]; `dinpkt` mean=2.5278065, std=0.86322803, range=[2.05265, 4.277884]
- **sig-80f49f344b21151c** (cluster 2, n=36): 7/8 selected features have no estimated variability. Command categories: none; authentication success rate: 0.0%.
  - `ackdat` mean=0.0, std=0.0, range=[0.0, 0.0]; `ct_dst_ltm` mean=54.0, std=0.0, range=[54.0, 54.0]; `ct_src_ltm` mean=54.0, std=0.0, range=[54.0, 54.0]; `ct_srv_dst` mean=54.0, std=0.0, range=[54.0, 54.0]; `ct_srv_src` mean=54.0, std=0.0, range=[54.0, 54.0]; `ct_state_ttl` mean=1.0, std=0.0, range=[1.0, 1.0]; `dbytes` mean=0.0, std=0.0, range=[0.0, 0.0]; `dinpkt` mean=0.00820908, std=0.00422978, range=[0.0, 0.027396]

## Comparison-method audit
- A single compatible feature can satisfy `min_compatible_features=1`; because component weights are fixed, that one feature can contribute as much as 0.70, with matching authentication adding 0.10 and matching commands up to 0.20. The default is therefore permissive in principle. The current held-out records each had eight compatible features in the best signature, so the observed labels were not caused by a single feature. No empirical labelled calibration supports changing this default here.
- Legacy `comparable_feature_count` summed the same feature dimensions across all three signatures (24); it should describe the closest signature, which has 8 here. Classification now uses the closest signature's comparable count. This corrects the evidence count/minimum-feature guard without changing scores or the current threshold.
- Missing command/authentication data contributes zero without renormalizing weights; diagnostics distinguish missing evidence from observed conflict. A confirmed defect was that contradictory command or authentication evidence could be masked by numerical similarity. The revised decision rule prevents a Known-like classification when either available categorical signal directly conflicts; it does not change the similarity score or configured threshold.
- The saved profiles selected the first eight features alphabetically, not the most variable dimensions. This made profiles broad and weakly discriminative: the matched credential signature has 7/8 zero-variance dimensions, while the mixed signature has 5/8; the singleton signature has no estimable within-signature variance. Signature generation now selects non-constant dimensions ranked by relative variability when available; existing saved signatures and baseline outputs remain unchanged.
- The thresholds are configuration choices, not empirically justified values; there are no suitable ground-truth novelty labels in the dataset.

## Threshold sensitivity
- Grid: known threshold 0.70–0.90, margin 0.05–0.20, borderline score 0.60–0.70, and minimum comparable features 1/4/8/9. Full combinations are in `threshold_sensitivity.csv`; threshold values are exploratory and not calibrated.
- The table below shows minimum-feature=1 representative cases. These are sensitivity counts on this fixed, unlabeled holdout; they are not a threshold-selection criterion.
| Known | Margin | Borderline | Min features | Known-like | Potentially Novel | Ambiguous | Insufficient |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.70 | 0.05 | 0.60 | 1 | 11 | 0 | 0 | 0 |
| 0.70 | 0.05 | 0.70 | 1 | 11 | 0 | 0 | 0 |
| 0.70 | 0.10 | 0.60 | 1 | 10 | 0 | 1 | 0 |
| 0.70 | 0.10 | 0.70 | 1 | 10 | 0 | 1 | 0 |
| 0.70 | 0.15 | 0.60 | 1 | 1 | 0 | 10 | 0 |
| 0.70 | 0.15 | 0.70 | 1 | 1 | 0 | 10 | 0 |
| 0.70 | 0.20 | 0.60 | 1 | 0 | 0 | 11 | 0 |
| 0.70 | 0.20 | 0.70 | 1 | 0 | 0 | 11 | 0 |
| 0.75 | 0.05 | 0.60 | 1 | 10 | 1 | 0 | 0 |
| 0.75 | 0.05 | 0.70 | 1 | 10 | 1 | 0 | 0 |
| 0.75 | 0.10 | 0.60 | 1 | 10 | 0 | 1 | 0 |
| 0.75 | 0.10 | 0.70 | 1 | 10 | 0 | 1 | 0 |
| 0.75 | 0.15 | 0.60 | 1 | 1 | 0 | 10 | 0 |
| 0.75 | 0.15 | 0.70 | 1 | 1 | 0 | 10 | 0 |
| 0.75 | 0.20 | 0.60 | 1 | 0 | 0 | 11 | 0 |
| 0.75 | 0.20 | 0.70 | 1 | 0 | 0 | 11 | 0 |
| 0.80 | 0.05 | 0.60 | 1 | 1 | 10 | 0 | 0 |
| 0.80 | 0.05 | 0.70 | 1 | 1 | 10 | 0 | 0 |
| 0.80 | 0.10 | 0.60 | 1 | 1 | 9 | 1 | 0 |
| 0.80 | 0.10 | 0.70 | 1 | 1 | 9 | 1 | 0 |
| 0.80 | 0.15 | 0.60 | 1 | 1 | 0 | 10 | 0 |
| 0.80 | 0.15 | 0.70 | 1 | 1 | 0 | 10 | 0 |
| 0.80 | 0.20 | 0.60 | 1 | 0 | 0 | 11 | 0 |
| 0.80 | 0.20 | 0.70 | 1 | 0 | 0 | 11 | 0 |
| 0.85 | 0.05 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.85 | 0.05 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.85 | 0.10 | 0.60 | 1 | 0 | 10 | 1 | 0 |
| 0.85 | 0.10 | 0.70 | 1 | 0 | 10 | 1 | 0 |
| 0.85 | 0.15 | 0.60 | 1 | 0 | 1 | 10 | 0 |
| 0.85 | 0.15 | 0.70 | 1 | 0 | 1 | 10 | 0 |
| 0.85 | 0.20 | 0.60 | 1 | 0 | 0 | 11 | 0 |
| 0.85 | 0.20 | 0.70 | 1 | 0 | 0 | 11 | 0 |
| 0.90 | 0.05 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.90 | 0.05 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.90 | 0.10 | 0.60 | 1 | 0 | 10 | 1 | 0 |
| 0.90 | 0.10 | 0.70 | 1 | 0 | 10 | 1 | 0 |
| 0.90 | 0.15 | 0.60 | 1 | 0 | 1 | 10 | 0 |
| 0.90 | 0.15 | 0.70 | 1 | 0 | 1 | 10 | 0 |
| 0.90 | 0.20 | 0.60 | 1 | 0 | 0 | 11 | 0 |
| 0.90 | 0.20 | 0.70 | 1 | 0 | 0 | 11 | 0 |

## Validity and limitations
- This is a session-level signature holdout only. The existing DEC model and scaler may have been fitted using records in the holdout, and the available artifacts do not establish otherwise. This is not independent end-to-end generalization.
- No attack labels or ground-truth novelty labels were used. Do not interpret Known-like or Potentially Novel counts as accuracy, recall, precision, or zero-day detection.
- Three signatures are generated from a small dataset; one has a single supporting session, and the dominant profile has limited variability in its currently selected fields.

## Revised evaluation after the demonstrated fixes
- The original held-out result artifacts above remain preserved: 43 reference sessions, 11 held-out sessions, 3 signatures, and 11 `Known-like` outcomes using the old alphabetical feature selection.
- A separate rerun is stored under `revised/`; it used the same seed (42), the identical disjoint 43/11 session split, and 3 signatures generated from reference sessions only. The numerical profiles now use variable reference features only, and signatures without estimable feature variability do not claim numerical matches.
- With the configured thresholds unchanged (known 0.70, ambiguous margin 0.05, borderline 0.60, minimum features 1), the revised run produced 1 `Known-like`, 10 `Potentially Novel`, 0 `Ambiguous`, and 0 `Insufficient Evidence` outcomes. This is a descriptive result of the revised matching method, not evidence of attack novelty or detector accuracy.
- The revised run's own session-level results, component/feature diagnostics, and summary are in `revised/`; the `score_diagnostics.csv` and `threshold_sensitivity.csv` beside this report continue to describe the preserved original score baseline.
- The previous in-sample evaluation remains separate under `../novelty_assessment_summary.json`; it was not overwritten.
