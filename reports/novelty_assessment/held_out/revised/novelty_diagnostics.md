# Held-out Novelty Diagnostics

This report diagnoses the saved held-out results using relative-variability feature-profile selection. It is a diagnostic of signature-level matching, not an attack-detection performance report.

## Score distribution
- Sessions: 11
- Minimum: 0.515124
- Maximum: 0.724454
- Mean: 0.654026
- Median: 0.675336
- Standard deviation (population): 0.056046
- Standard deviation (sample): 0.058782

## Per-session scores
| Session | Closest signature | Best | Second | Margin | Features (best) | Category |
|---|---|---:|---:|---:|---:|---|
| 4d2398ddaebd | sig-861aae17eb99f9be | 0.677447 | 0.222435 | 0.455012 | 6 | Potentially Novel |
| 51fb60d24936 | sig-861aae17eb99f9be | 0.688508 | 0.273330 | 0.415178 | 6 | Potentially Novel |
| 61c8acc77ac0 | sig-861aae17eb99f9be | 0.695098 | 0.230629 | 0.464469 | 6 | Potentially Novel |
| 735512cb6ad6 | sig-861aae17eb99f9be | 0.648069 | 0.217815 | 0.430254 | 6 | Potentially Novel |
| 76bbeca4b01a | sig-861aae17eb99f9be | 0.670248 | 0.226813 | 0.443435 | 6 | Potentially Novel |
| 9a4ec106110f | sig-861aae17eb99f9be | 0.675336 | 0.278879 | 0.396457 | 6 | Potentially Novel |
| a38c819b1e32 | sig-861aae17eb99f9be | 0.724454 | 0.249223 | 0.475231 | 6 | Known-like |
| a4c62363d8d6 | sig-47521826f16efd4b | 0.606402 | 0.200481 | 0.405921 | 8 | Potentially Novel |
| bdf3eea00cb2 | sig-861aae17eb99f9be | 0.603502 | 0.139606 | 0.463896 | 6 | Potentially Novel |
| ccba58b29c45 | sig-861aae17eb99f9be | 0.515124 | 0.192249 | 0.322875 | 6 | Potentially Novel |
| e422abb51310 | sig-861aae17eb99f9be | 0.690095 | 0.220668 | 0.469427 | 6 | Potentially Novel |

Detailed components and feature-level comparisons are in `score_diagnostics.csv`.

## Why sessions matched
- Signature match counts: {'sig-861aae17eb99f9be': 10, 'sig-47521826f16efd4b': 1}.
- The saved result schema did not persist component scores. This diagnostic reconstructs them by rerunning the existing comparison function with the saved signatures and the same DEC feature rows; the score formula and production defaults are unchanged.
- Each matched signature's numerical similarity averages its 6–8 compatible selected features and contributes 70% of the total score. Command-category Jaccard contributes 20%; authentication similarity contributes 10%. Unavailable categorical evidence contributes zero without renormalizing the weights.
- Command evidence statuses: {'session_categories_missing': 10, 'comparable': 1}. Authentication evidence statuses: {'comparable': 11}. These distinguish missing evidence from an observed conflict; missing command categories are not counted as disagreement.
- 10 of 11 sessions selected sig-861aae17eb99f9be as their closest signature. Consult each session's feature details below and in the CSV to see whether the match is carried by multiple variable dimensions or weak/broad evidence.
- Compare the per-feature values and weighted contributions in the CSV. Largest contributors are explicitly ranked per session; do not interpret constant dimensions as discriminative evidence merely because the value agrees.

## Reference signature feature ranges and variability
- **sig-fb54a34cea2a64b7** (cluster 0, n=1): no numerical features selected because within-cluster variability is not estimable. Command categories: ['file_system']; authentication success rate: 100.0%.
  - No numerical feature ranges are available.
- **sig-47521826f16efd4b** (cluster 1, n=6): 0/8 selected features have no estimated variability. Command categories: ['reconnaissance', 'file_system', 'privilege_escalation', 'credential_attack', 'file_transfer', 'networking']; authentication success rate: 100.0%.
  - `sjit` mean=1.266957, std=1.59417053, range=[0.4598, 4.504347]; `sbytes` mean=55.0, std=31.84336666, range=[42.0, 120.0]; `tcprtt` mean=0.00873367, std=0.00342774, range=[0.005093, 0.014574]; `synack` mean=0.00393017, std=0.00154235, range=[0.002292, 0.006558]; `djit` mean=5.60410183, std=1.93565643, range=[4.550861, 9.527777]; `dinpkt` mean=2.5278065, std=0.86322803, range=[2.05265, 4.277884]; `dur` mean=13.14082783, std=4.31807467, range=[10.762586, 21.895156]; `dload` mean=1096.76156667, std=291.54165881, range=[511.1633, 1282.2197]
- **sig-861aae17eb99f9be** (cluster 2, n=36): 0/6 selected features have no estimated variability. Command categories: none; authentication success rate: 0.0%.
  - `djit` mean=0.00774547, std=0.00589833, range=[0.0, 0.037342]; `synack` mean=0.00499528, std=0.00342664, range=[0.0, 0.011765]; `tcprtt` mean=0.0111005, std=0.00761462, range=[0.0, 0.026144]; `dur` mean=2.94875183, std=1.72899874, range=[0.012576, 5.046908]; `dinpkt` mean=0.00820908, std=0.00422978, range=[0.0, 0.027396]; `dpkts` mean=2.91666667, std=0.5, range=[0.0, 3.0]

## Comparison-method audit
- A single compatible feature can satisfy `min_compatible_features=1`; because component weights are fixed, that one feature can contribute as much as 0.70, with matching authentication adding 0.10 and matching commands up to 0.20. The default is permissive in principle. In this saved run, the closest-signature feature count ranged from 6 to 8; this does not justify changing the default without labelled calibration.
- The diagnostic reports comparable features for the closest signature; the prior aggregate count summed matching dimensions across all signatures and overstated evidence (24 instead of 8 for the baseline example). The corrected count does not change the similarity score.
- Missing command/authentication data contributes zero without renormalizing weights; diagnostics distinguish missing evidence from observed conflict. A confirmed defect was that contradictory command or authentication evidence could be masked by numerical similarity. The revised decision rule prevents a Known-like classification when either available categorical signal directly conflicts; it does not change the similarity score or configured threshold.
- The saved signature profiles use non-constant features ranked by relative variability where such estimates exist; the singleton signature has no estimable numerical variability and therefore has no selected numerical features.
- The thresholds are configuration choices, not empirically justified values; there are no suitable ground-truth novelty labels in the dataset.

## Threshold sensitivity
- Grid: known threshold 0.70–0.90, margin 0.05–0.20, borderline score 0.60–0.70, and minimum comparable features 1/4/8/9. Full combinations are in `threshold_sensitivity.csv`; threshold values are exploratory and not calibrated.
- The table below shows minimum-feature=1 representative cases. These are sensitivity counts on this fixed, unlabeled holdout; they are not a threshold-selection criterion.
| Known | Margin | Borderline | Min features | Known-like | Potentially Novel | Ambiguous | Insufficient |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.70 | 0.05 | 0.60 | 1 | 1 | 10 | 0 | 0 |
| 0.70 | 0.05 | 0.70 | 1 | 1 | 10 | 0 | 0 |
| 0.70 | 0.10 | 0.60 | 1 | 1 | 10 | 0 | 0 |
| 0.70 | 0.10 | 0.70 | 1 | 1 | 10 | 0 | 0 |
| 0.70 | 0.15 | 0.60 | 1 | 1 | 10 | 0 | 0 |
| 0.70 | 0.15 | 0.70 | 1 | 1 | 10 | 0 | 0 |
| 0.70 | 0.20 | 0.60 | 1 | 1 | 10 | 0 | 0 |
| 0.70 | 0.20 | 0.70 | 1 | 1 | 10 | 0 | 0 |
| 0.75 | 0.05 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.75 | 0.05 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.75 | 0.10 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.75 | 0.10 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.75 | 0.15 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.75 | 0.15 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.75 | 0.20 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.75 | 0.20 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.80 | 0.05 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.80 | 0.05 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.80 | 0.10 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.80 | 0.10 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.80 | 0.15 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.80 | 0.15 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.80 | 0.20 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.80 | 0.20 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.85 | 0.05 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.85 | 0.05 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.85 | 0.10 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.85 | 0.10 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.85 | 0.15 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.85 | 0.15 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.85 | 0.20 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.85 | 0.20 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.90 | 0.05 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.90 | 0.05 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.90 | 0.10 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.90 | 0.10 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.90 | 0.15 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.90 | 0.15 | 0.70 | 1 | 0 | 11 | 0 | 0 |
| 0.90 | 0.20 | 0.60 | 1 | 0 | 11 | 0 | 0 |
| 0.90 | 0.20 | 0.70 | 1 | 0 | 11 | 0 | 0 |

## Validity and limitations
- This is a session-level signature holdout only. The existing DEC model and scaler may have been fitted using records in the holdout, and the available artifacts do not establish otherwise. This is not independent end-to-end generalization.
- No attack labels or ground-truth novelty labels were used. Do not interpret Known-like or Potentially Novel counts as accuracy, recall, precision, or zero-day detection.
- Three signatures are generated from a small dataset; one has a single supporting session, and the dominant profile has limited variability in its currently selected fields.
