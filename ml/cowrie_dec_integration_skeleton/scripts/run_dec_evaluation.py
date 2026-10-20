import sys
import os
import argparse
import pandas as pd
import numpy as np
# Add the repository root (containing the top‑level 'ml' package) to PYTHONPATH
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.append(REPO_ROOT)
print(f"[DEBUG] REPO_ROOT: {REPO_ROOT}")
print(f"[DEBUG] sys.path[0:5]: {sys.path[:5]}")

from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.inference import predict
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score


parser = argparse.ArgumentParser(description="Run offline Cowrie DEC clustering")
parser.add_argument(
    "input",
    nargs="?",
    default="behavior_features.csv",
    help="Path to the behavior-features CSV"
)
parser.add_argument(
    "--output",
    default="dec_results.csv",
    help="Path to save cluster assignments and confidence scores"
)
parser.add_argument(
    "--labels-verified",
    action="store_true",
    help="Report ARI/NMI against the 'label' column. Only use when labels are verified ground truth; "
         "Cowrie feature extraction fills unlabeled sessions with label=0."
)
args = parser.parse_args()

# Keep session IDs as the exact text from the CSV (no numeric or NA coercion).
df = pd.read_csv(args.input, converters={"session_id": str})

clusters, confidence, probabilities = predict(df)

print("\n======================================")
print("COWRIE DEC OFFLINE SANITY CHECK")
print("======================================")

print("Samples:", len(df))
print("Clusters:", sorted(np.unique(clusters).tolist()))

print("\nCluster distribution:")
unique, counts = np.unique(clusters, return_counts=True)

for c, n in zip(unique, counts):
    print(
        f"Cluster {c}: {n} "
        f"({100*n/len(clusters):.2f}%)"
    )

print("\nConfidence:")
print("Mean:", float(np.mean(confidence)))
print("Min :", float(np.min(confidence)))
print("Max :", float(np.max(confidence)))

if not args.labels_verified:
    print("\nARI/NMI: omitted (labels not verified; pass --labels-verified to report them)")
elif "label" not in df.columns:
    print("\nARI/NMI: omitted (--labels-verified given but no 'label' column)")
elif df["label"].nunique(dropna=True) < 2:
    print("\nARI/NMI: omitted (verified labels contain fewer than two classes)")
else:
    print("\nARI:", adjusted_rand_score(df["label"], clusters))
    print("NMI:", normalized_mutual_info_score(df["label"], clusters))

out = df.copy()
out["dec_cluster"] = clusters
out["dec_confidence"] = confidence

for i in range(probabilities.shape[1]):
    out[f"cluster_{i}_prob"] = probabilities[:, i]

os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
out.to_csv(args.output, index=False)

print(f"\nSaved: {args.output}")
