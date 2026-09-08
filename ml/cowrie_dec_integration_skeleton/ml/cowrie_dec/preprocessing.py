import json
import os
import joblib
import numpy as np
import pandas as pd


def load_artifacts(model_dir):
    """Load the saved preprocessing/model configuration artifacts."""
    config_path = os.path.join(model_dir, "config.json")
    scaler_path = os.path.join(model_dir, "scaler.joblib")
    medians_path = os.path.join(model_dir, "medians.joblib")

    for path in [config_path, scaler_path, medians_path]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Missing artifact: {path}")

    with open(config_path, "r") as f:
        config = json.load(f)

    scaler = joblib.load(scaler_path)
    medians = joblib.load(medians_path)

    return config, scaler, medians


def _encode_categorical_consistently(X, config):
    """
    Encode categorical columns only if the saved configuration says
    that encoding is required.

    IMPORTANT:
    Fitting a new encoder at inference time is NOT safe if the scaler/model
    was trained with a different category-to-integer mapping. If your
    training pipeline used LabelEncoder, save those encoders and list their
    mappings in config.json.
    """
    categorical = config.get("categorical_features", [])

    mappings = config.get("categorical_mappings", {})

    for col in categorical:
        if col not in X.columns:
            continue

        if col not in mappings:
            raise ValueError(
                f"No saved categorical mapping for '{col}'. "
                "Do not fit a new LabelEncoder on live inference data."
            )

        mapping = mappings[col]
        X[col] = X[col].map(mapping)

        if X[col].isna().any():
            unknown = X.loc[X[col].isna(), col].unique()
            raise ValueError(
                f"Unknown category encountered in '{col}'. "
                f"Saved mapping must be extended/retrained. Values: {unknown}"
            )

    return X


def preprocess(df, config, scaler, medians):
    """
    Raw DataFrame -> exact feature matrix expected by the saved DEC model.

    Order:
      1. select saved feature order
      2. categorical encoding using SAVED mappings (if configured)
      3. fill missing values using saved medians
      4. log1p designated features
      5. apply saved StandardScaler
    """
    if not isinstance(df, pd.DataFrame):
        raise TypeError("preprocess() expects a pandas DataFrame")

    features = config["features"]
    log_features = config.get("log_features", [])

    missing = [f for f in features if f not in df.columns]
    if missing:
        raise ValueError(f"Missing required features: {missing}")

    X = df[features].copy()

    X = _encode_categorical_consistently(X, config)

    # Fill missing values using the exact medians saved at training time.
    for feature in features:
        if feature in medians:
            X[feature] = X[feature].fillna(medians[feature])

    # Convert to numeric after categorical mapping.
    for feature in features:
        X[feature] = pd.to_numeric(X[feature], errors="coerce")

    if X.isna().any().any():
        bad = X.columns[X.isna().any()].tolist()
        raise ValueError(
            f"Non-numeric or unresolved missing values remain in: {bad}"
        )

    # Log1p is only valid for non-negative values.
    for feature in log_features:
        if feature in X.columns:
            if (X[feature] < 0).any():
                raise ValueError(
                    f"Negative values found in log1p feature '{feature}'."
                )
            X[feature] = np.log1p(X[feature])

    X_scaled = scaler.transform(X[features])
    return np.asarray(X_scaled, dtype=np.float32)
