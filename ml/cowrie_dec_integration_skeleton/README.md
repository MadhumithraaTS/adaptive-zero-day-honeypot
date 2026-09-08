# Cowrie DEC Integration

## Expected artifact directory

Place the four saved artifacts here:

ml/cowrie_dec/artifacts/
    cowrie_dec.weights.h5
    scaler.joblib
    medians.joblib
    config.json

## Run the offline check

From the project root:

python scripts/run_dec_evaluation.py path/to/behavior_features.csv

Or, if behavior_features.csv is in the project root:

python scripts/run_dec_evaluation.py

## Important preprocessing rule

Inference must reproduce the training pipeline exactly:

raw Cowrie features
-> saved categorical mappings (if categorical encoding was used)
-> saved medians
-> log1p
-> saved StandardScaler
-> DEC

Do NOT fit a new LabelEncoder during inference. A newly fitted encoder can assign different integers
to categories and therefore invalidate the saved scaler/model.

## Important model rule

The architecture in model.py must match the architecture used to create the weights file.
If the original training notebook used a different ClusteringLayer implementation or layer names,
copy that exact implementation into model.py before loading the weights.

## Live integration

The existing Cowrie feature extractor should produce a one-row DataFrame containing the 17 features.
Then:

from ml.cowrie_dec.inference import predict

clusters, confidence, probabilities = predict(session_df)

The response engine can consume cluster + confidence without using attack_cat.
