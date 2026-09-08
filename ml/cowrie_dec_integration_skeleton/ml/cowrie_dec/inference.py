import os
import numpy as np
import pandas as pd

from .model import build_dec, load_weights
from .preprocessing import load_artifacts, preprocess


DEFAULT_MODEL_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "artifacts"
    )
)


class CowrieDEC:
    """Loaded final Cowrie DEC model and its preprocessing artifacts."""

    def __init__(self, model_dir=DEFAULT_MODEL_DIR):
        self.model_dir = os.path.abspath(model_dir)

        self.config, self.scaler, self.medians = load_artifacts(
            self.model_dir
        )

        self.model, self.encoder = build_dec(
            input_dim=self.config["input_dim"],
            latent_dim=self.config["latent_dim"],
            n_clusters=self.config["n_clusters"],
            alpha=self.config.get("alpha", 1.0)
        )

        load_weights(self.model, self.model_dir)

    def predict(self, df):
        X_scaled = preprocess(
            df,
            self.config,
            self.scaler,
            self.medians
        )

        soft_assignments = self.model.predict(
            X_scaled,
            verbose=0
        )

        clusters = np.argmax(
            soft_assignments,
            axis=1
        )

        confidence = np.max(
            soft_assignments,
            axis=1
        )

        return clusters, confidence, soft_assignments


_model = None


def get_model(model_dir=DEFAULT_MODEL_DIR):
    global _model

    if _model is None:
        _model = CowrieDEC(model_dir)

    return _model


def predict(df_or_path, model_dir=DEFAULT_MODEL_DIR):
    """
    Accept a DataFrame or CSV path.

    Returns:
        clusters: shape (n,)
        confidence: shape (n,)
        soft_assignments: shape (n, n_clusters)
    """
    if isinstance(df_or_path, (str, os.PathLike)):
        df = pd.read_csv(df_or_path)
    elif isinstance(df_or_path, pd.DataFrame):
        df = df_or_path
    else:
        raise TypeError(
            "predict() expects a pandas DataFrame or CSV path."
        )

    return get_model(model_dir).predict(df)
