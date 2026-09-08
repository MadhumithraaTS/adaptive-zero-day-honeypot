import sys
import os
import pandas as pd
import numpy as np
from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
# Add the repository root (containing the top‑level 'ml' package) to PYTHONPATH
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.append(REPO_ROOT)
print(f"[DEBUG] REPO_ROOT: {REPO_ROOT}")
print(f"[DEBUG] sys.path[0:5]: {sys.path[:5]}")

from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.inference import predict


CSV_PATH = (
    sys.argv[1]
    if len(sys.argv) > 1
    else "behavior_features.csv"
)

df = pd.read_csv(CSV_PATH)

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

if "label" in df.columns:
    print("\nARI:", adjusted_rand_score(df["label"], clusters))
    print("NMI:", normalized_mutual_info_score(df["label"], clusters))

out = df.copy()
out["dec_cluster"] = clusters
out["dec_confidence"] = confidence

for i in range(probabilities.shape[1]):
    out[f"cluster_{i}_prob"] = probabilities[:, i]

out.to_csv("dec_results.csv", index=False)

print("\nSaved: dec_results.csv")
