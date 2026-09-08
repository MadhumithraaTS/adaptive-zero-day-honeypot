import pandas as pd

from .inference import predict


def response_for_cluster(cluster, confidence):
    """
    Example policy layer.

    IMPORTANT:
    These are behavioral policies, not attack-category predictions.
    Replace the placeholder actions with your actual Cowrie response logic.
    """
    if confidence < 0.80:
        return "NORMAL_HONEYPOT"

    if cluster == 0:
        return "HIGH_INTENSITY_DECEPTION"

    if cluster == 1:
        return "HIGH_INTERACTION_RECON_DECEPTION"

    if cluster == 2:
        return "AUTHENTICATION_DECEPTION"

    return "NORMAL_HONEYPOT"


def handle_session(df):
    """
    df must contain the same raw behavioral features produced by the
    existing Cowrie feature extractor.
    """
    clusters, confidence, probabilities = predict(df)

    results = []

    for c, conf, probs in zip(
        clusters,
        confidence,
        probabilities
    ):
        results.append({
            "cluster": int(c),
            "confidence": float(conf),
            "probabilities": probs.tolist(),
            "response": response_for_cluster(
                int(c),
                float(conf)
            )
        })

    return results
