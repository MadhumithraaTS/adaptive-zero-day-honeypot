# Dataset V2 extractor: output schema

**Produced by:** `scripts/extract_features_v2.py --input <cowrie.json> [--input …] --output-dir <dir> [--allow-malformed]`.

**Encoding:** all files are UTF-8; the CSVs use `\n` line endings. Missing values are the literal `NaN`.

## `model_features.csv`: the model feature matrix

- **Columns:** exactly the 13 model features, in specification order, and nothing else. No identifier, label, status or descriptive field.
- **Rows:** one per session, **in the same order as `session_metadata.csv`** (row *i* here is `row = i` there).

| Column | Type | Unit | Missing | Status (group) |
|---|---|---|---|---|
| `login_success` | int8 | indicator | never | core |
| `login_failed_count` | int32 | attempts | never | conditional (C1) |
| `session_duration_s` | float64 | seconds | NaN if no `session.closed` | conditional (C3) |
| `input_line_count` | int32 | lines | never | core |
| `input_bytes_total` | int64 | bytes | never | core |
| `input_line_max_bytes` | float64 | bytes | NaN if no recorded line | core |
| `unique_command_names` | int32 | commands | never | core |
| `shell_operator_lines` | int32 | lines | never | conditional (C4) |
| `download_command_lines` | int32 | lines | never | conditional (C4) |
| `time_to_first_input_s` | float64 | seconds | NaN if no login or no recorded line (or a missing timestamp) | conditional (C2) |
| `inter_input_mean_s` | float64 | seconds | NaN if < 2 recorded lines (or a missing timestamp) | conditional (C2) |
| `inter_input_std_s` | float64 | seconds | NaN if < 3 recorded lines (or a missing timestamp) | conditional (C2) |
| `tty_output_bytes` | float64 | bytes | 0 if no login; NaN if logged in without `log.closed` | core |

**Use:** conditional features are always present. Whether they are used is decided by leakage validation, not by the extractor.

## `session_metadata.csv`: audit and descriptive table

| Column | Meaning |
|---|---|
| `row` | Row number linking to `model_features.csv` |
| `session_ref` | Cowrie session id (audit only; **never a model input**) |
| `feature_spec_version` | `2.0.0-draft.3` |
| `extraction_status` | `ok` or `ok_with_warnings` |
| `warnings` | `;`-separated session warnings (`docs/extractor_v2_design.md`) |
| `unknown_command_events`, `url_download_events`, `download_failed_events`, `redirect_write_events`, `scp_stdin_events`, `event_count`, `session_closed_observed`, `timestamp_order_mismatch` | The 8 descriptive fields (integers, never missing) |

## `extraction_summary.json`

| Key | Meaning |
|---|---|
| `extractor`, `feature_spec_version`, `spec_sha256` | What produced the output |
| `inputs` | Each input file's path, SHA-256 and size |
| `events_read`, `sessions`, `sessions_with_warnings`, `duplicate_records_removed` | Counts |
| `file_level_warnings` | `[{where: "file:line", warning, detail}]`: skipped malformed lines (only with `--allow-malformed`) and events without a session id |
| `session_warning_counts` | Sessions per warning type |
| `nan_counts` | NaN cells per model feature |
| `model_feature_dtypes`, `model_feature_status` | From the specification |
| `missing_value_encoding`, `outputs` | Format notes |

**Reading example:**

```python
X = pd.read_csv("model_features.csv")       # 13 columns; 'NaN' parsed as NaN
meta = pd.read_csv("session_metadata.csv")  # same row order
```
