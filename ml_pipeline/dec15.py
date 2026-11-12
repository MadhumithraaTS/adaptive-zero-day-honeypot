"""Training and evaluation helpers for the 15-feature DEC experiment.

Training reproduces the original procedure in model_selection/cowrie_tuned.ipynb (cells 3-8) with a
15-feature input. The network is built with the inference package's own build_dec(), so the saved
weights load into ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.inference.CowrieDEC unchanged;
a decoder is attached only for autoencoder pre-training. TensorFlow determinism is enabled (the
original did not), so a second run with the same seed reproduces the weights.
"""
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.model import build_dec  # noqa: E402
from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.preprocessing import preprocess  # noqa: E402

WORK = HERE / "work"
PREP_DIR = WORK / "preprocess"
SEED = 42
# Original final-model hyperparameters (cowrie_tuned.ipynb cells 3-7).
HYPERPARAMETERS = {
    "latent_dim": 4, "n_clusters": 3, "alpha": 1.0,
    "encoder": [32, 16], "decoder": [16, 32], "activation": "relu",
    "ae_optimizer": "Adam", "ae_learning_rate": 0.001, "ae_loss": "mse",
    "ae_epochs": 20, "ae_batch_size": 256, "ae_validation_split": 0.1,
    "kmeans_n_init": 20, "kmeans_random_state": SEED,
    "dec_optimizer": "Adam", "dec_learning_rate": 0.001, "dec_loss": "kld",
    "dec_maxiter": 500, "dec_update_interval": 50, "dec_tol": 0.001, "predict_batch_size": 256,
    "seed": SEED, "tf_op_determinism": True,
}


def load_split(name):
    return pd.read_pickle(WORK / f"{name}.pkl")


def load_preprocessing():
    config = json.loads((PREP_DIR / "config.json").read_text())
    return config, joblib.load(PREP_DIR / "scaler.joblib"), joblib.load(PREP_DIR / "medians.joblib")


def target_distribution(q):
    """DEC auxiliary target, exactly as in the original notebook."""
    weight = q ** 2 / (np.sum(q, axis=0) + 1e-10)
    return weight / (np.sum(weight, axis=1, keepdims=True) + 1e-10)


def _seed_everything(seed):
    import tensorflow as tf
    tf.keras.utils.set_random_seed(seed)
    tf.config.experimental.enable_op_determinism()


def kmeans_threads(single_thread):
    """Context for K-Means calls: one native thread when single_thread (scikit-learn 1.9 has no n_jobs)."""
    import contextlib
    from threadpoolctl import threadpool_limits
    return threadpool_limits(limits=1) if single_thread else contextlib.nullcontext()


def train_dec(X, hp=HYPERPARAMETERS, verbose=False, X_eval=None, kmeans_single_thread=False):
    """Pre-train the autoencoder, initialise centres with K-Means, refine with DEC.

    Returns (dec_model, encoder, log). `log` holds losses, convergence and the K-Means
    initialisation (the autoencoder + K-Means baseline). If X_eval is given, it is embedded with the
    pre-trained encoder before DEC refinement changes it, so that baseline can be scored on held-out rows.
    kmeans_single_thread runs only the K-Means calls under a one-thread limit; multithreaded K-Means is
    not bit-reproducible (dec_15_feature_v1/verification_addendum.json).
    """
    import tensorflow as tf
    from sklearn.cluster import KMeans
    from tensorflow.keras import Model
    from tensorflow.keras.layers import Dense
    from tensorflow.keras.optimizers import Adam

    tf.keras.backend.clear_session()
    _seed_everything(hp["seed"])
    started = time.time()
    dec_model, encoder = build_dec(input_dim=X.shape[1], latent_dim=hp["latent_dim"],
                                   n_clusters=hp["n_clusters"], alpha=hp["alpha"])
    x = encoder.output
    for units in hp["decoder"]:
        x = Dense(units, activation=hp["activation"])(x)
    reconstruction = Dense(X.shape[1], activation="linear", name="reconstruction")(x)
    autoencoder = Model(encoder.input, reconstruction, name="cowrie_autoencoder")
    autoencoder.compile(optimizer=Adam(learning_rate=hp["ae_learning_rate"]), loss=hp["ae_loss"])
    history = autoencoder.fit(X, X, epochs=hp["ae_epochs"], batch_size=hp["ae_batch_size"],
                              validation_split=hp["ae_validation_split"], verbose=int(verbose))
    ae_seconds = time.time() - started

    latent = encoder.predict(X, batch_size=hp["predict_batch_size"], verbose=0)
    kmeans = KMeans(n_clusters=hp["n_clusters"], random_state=hp["kmeans_random_state"], n_init=hp["kmeans_n_init"])
    with kmeans_threads(kmeans_single_thread):
        init_labels = kmeans.fit_predict(latent)
    eval_latent_init = encoder.predict(X_eval, batch_size=hp["predict_batch_size"], verbose=0) if X_eval is not None else None
    with kmeans_threads(kmeans_single_thread):
        eval_init_labels = kmeans.predict(eval_latent_init) if eval_latent_init is not None else None
    dec_model.get_layer("clustering").set_weights([kmeans.cluster_centers_.astype(np.float32)])
    dec_model.compile(optimizer=Adam(learning_rate=hp["dec_learning_rate"]), loss=hp["dec_loss"])

    q = dec_model.predict(X, batch_size=hp["predict_batch_size"], verbose=0)
    p = target_distribution(q)
    y_last = q.argmax(1)
    deltas, losses, iterations, converged = [], [], 0, False
    for ite in range(hp["dec_maxiter"]):
        if ite % hp["dec_update_interval"] == 0:
            q = dec_model.predict(X, batch_size=hp["predict_batch_size"], verbose=0)
            p = target_distribution(q)
            y_pred = q.argmax(1)
            if ite > 0:
                delta = float(np.mean(y_pred != y_last))
                deltas.append({"iteration": ite, "label_change": delta})
                if delta < hp["dec_tol"]:
                    converged, iterations = True, ite
                    break
            y_last = y_pred.copy()
        loss = dec_model.train_on_batch(X, p)
        losses.append(float(loss if np.isscalar(loss) else np.asarray(loss).ravel()[0]))
        iterations = ite + 1

    log = {
        "ae_loss_per_epoch": [float(v) for v in history.history["loss"]],
        "ae_val_loss_per_epoch": [float(v) for v in history.history.get("val_loss", [])],
        "ae_seconds": round(ae_seconds, 2),
        "kmeans_init_inertia": float(kmeans.inertia_),
        "kmeans_init_labels": init_labels,
        "kmeans_init_centers": kmeans.cluster_centers_,
        "eval_latent_init": eval_latent_init,
        "eval_init_labels": eval_init_labels,
        "dec_iterations": iterations,
        "dec_converged": converged,
        "dec_label_change_checks": deltas,
        "dec_loss_first": losses[0] if losses else None,
        "dec_loss_last": losses[-1] if losses else None,
        "dec_loss_per_iteration": losses,
        "total_seconds": round(time.time() - started, 2),
    }
    return dec_model, encoder, log


def soft_assign(dec_model, X, batch_size=256):
    return dec_model.predict(X, batch_size=batch_size, verbose=0)


def cluster_metrics(space, labels):
    """Internal metrics; None when fewer than two clusters are occupied."""
    from sklearn.metrics import calinski_harabasz_score, davies_bouldin_score, silhouette_score
    occupied = int(len(np.unique(labels)))
    if occupied < 2:
        return {"occupied_clusters": occupied, "silhouette": None, "davies_bouldin": None, "calinski_harabasz": None}
    return {"occupied_clusters": occupied,
            "silhouette": float(silhouette_score(space, labels)),
            "davies_bouldin": float(davies_bouldin_score(space, labels)),
            "calinski_harabasz": float(calinski_harabasz_score(space, labels))}


def reference_agreement(labels, reference):
    """Descriptive agreement with the generator category (never used for selection)."""
    from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
    return {"ari_vs_attack_cat": float(adjusted_rand_score(reference, labels)),
            "nmi_vs_attack_cat": float(normalized_mutual_info_score(reference, labels))}


def align_clusters(labels_a, labels_b, k=3):
    """Best one-to-one mapping of B's cluster IDs onto A's (Hungarian on the contingency table)."""
    from scipy.optimize import linear_sum_assignment
    table = np.zeros((k, k), dtype=int)
    for a, b in zip(labels_a, labels_b):
        table[a, b] += 1
    rows, cols = linear_sum_assignment(-table)
    mapping = {int(b): int(a) for a, b in zip(rows, cols)}
    aligned = np.array([mapping[int(b)] for b in labels_b])
    return mapping, float(np.mean(aligned == np.asarray(labels_a))), table


def transform(frame, config, scaler, medians):
    return preprocess(frame, config, scaler, medians)
