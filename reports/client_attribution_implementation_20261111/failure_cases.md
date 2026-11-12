# Failure cases

Every failure leaves the session unattributed with an explicit reason. No failure produces a proposal.

## A. Captured demo data, modified in memory (`correlation_tests.csv`, `run_attribution.py`)
The captured inputs are never modified on disk. Baseline: S1 `published_listener`; S2–S5 `attributable_via_proxy_mapping` (4 attributed).

| Variant | Verification | Effect | Attributed |
|---|---|---|---|
| client_ip in S4 open record changed .3 → .4 | record_hash mismatch | all sessions `mapping_untrusted` | 0 |
| S4 open record deleted | sequence gap | all `mapping_untrusted` | 0 |
| two records reordered | sequence gap | all `mapping_untrusted` | 0 |
| signature removed | missing fields | all `mapping_untrusted` | 0 |
| log truncated mid-record | malformed JSON | all `mapping_untrusted` | 0 |
| verified with an unpinned public key | key not pinned | all `mapping_untrusted` | 0 |
| mapping log unavailable | — | all `mapping_unavailable` | 0 |
| evaluated 25 h later (max age 24 h) | verifies | all `mapping_expired` | 0 |
| key validity ended before the records | outside validity | all `mapping_untrusted` | 0 |
| test client removed from registry | verifies | S2, S4 `unregistered_peer` | 2 |
| demo listener not configured | verifies | all `published_listener` | 0 |
| S4 Cowrie `src_port` altered | verifies | S4 `mapping_missing` | 3 |
| S4 connect shifted +5 s (skew 2 s) | verifies | S4 `mapping_missing` | 3 |
| S4 Cowrie close shifted +10 s | verifies | S4 `close_inconsistent` | 3 |
| S4 close events relabelled with S5's session ID | verifies | S5 `close_inconsistent` (two closes) | 3 |
| S4 duplicated `session.connect` | verifies | S4 `close_inconsistent` | 3 |
| S4 session registered as diagnostic | verifies | S4 `excluded_diagnostic` | 3 |

One case needs explaining: when S4's close events are relabelled as S5's, S4 becomes `attributable … session_open`. Its own relay close record exists, but Cowrie no longer shows a close for it, which the rules treat as a still-open session. S5, which now has two closes, is rejected. This is the intended behaviour: a missing Cowrie close is not evidence against the mapping.

## B. Assessment side, on the real S4 evidence record (`assessment_integration_tests.csv`)

| Case | Attribution | Tier | Failed gates |
|---|---|---|---|
| verified mapping | attributable_via_proxy_mapping | propose (dry-run, subject 10.250.25.3) | — |
| no mapping supplied | unattributed:mapping_unavailable | review | 5 |
| mapping produced under another config digest | unattributed:mapping_unavailable | review | 5, 7 |
| mapping from a tampered log | unattributed:mapping_untrusted | review | 5 |
| mapping evaluated after expiry | unattributed:mapping_expired | review | 5 |

The S5 control client is `enforcement_excluded`, giving tier review with gates 5 and 6 failed. The S3 control banner is also `enforcement_excluded`.

## C. Unit tests (`tests/test_client_attribution.py`, 52 tests with an ephemeral key, synthetic events)

**Missing mappings**
- no record
- wrong port
- outside the time window
- relay accept after the Cowrie connect
- missing `src_port`
- log unavailable

**Ambiguity and duplicates**
- two records with the same tuple inside the window (ambiguous)
- tuple reuse outside the window (correctly disambiguated)
- duplicated `connection_id`
- duplicated close record

**Expiry**
- record older than the maximum age (expired)

**Tampering** (7 kinds)
- modified field
- deleted record
- reordered records
- truncated signature
- unsigned record
- appended garbage
- inserted record that links correctly but is signed with a non-pinned key

**Key problems**
- records signed by another key
- unpinned public key supplied
- unusable key
- record written outside the key validity window

**Listener and peer checks**
- published listener
- accepted local address ≠ listener
- unregistered peer

**Close checks**
- close time disagreement
- Cowrie closed but relay did not
- close matched by session ID, not by tuple
- multiple connect events

**Session scope**
- not via the relay
- both diagnostic sessions excluded
- historical session before any record (no retroactive attribution)
- correlation is pure and deterministic

**Config validation**
- v2 config requires the mapping and the exclusions
- mapping relays must be configured relays
- v1 rejects a mapping
- repository configs cross-verify
- no private-key code in the assessment packages

**Assessment integration**
- test client proposes with the client as subject
- control client is excluded
- findings are identical with and without the mapping
- no mapping → unattributed
- unverified mapping never proposes
- foreign digest fails gate 7
- mapping supplied with a v1 config → abstain
- mapped protected client → protected
- forwarded-for fields never change the subject
- inputs are not modified
- v1 direct-source behaviour is unchanged
