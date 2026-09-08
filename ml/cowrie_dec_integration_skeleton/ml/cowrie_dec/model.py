import os
import tensorflow as tf
from tensorflow.keras import Model
from tensorflow.keras.layers import Input, Dense, Layer


class ClusteringLayer(Layer):
    """DEC Student-t soft-assignment layer."""

    def __init__(self, n_clusters, weights=None, alpha=1.0, **kwargs):
        super().__init__(**kwargs)
        self.n_clusters = n_clusters
        self.alpha = alpha
        self.initial_weights = weights

    def build(self, input_shape):
        input_dim = int(input_shape[1])

        self.clusters = self.add_weight(
            shape=(self.n_clusters, input_dim),
            initializer="glorot_uniform",
            name="clusters"
        )

        if self.initial_weights is not None:
            self.set_weights([self.initial_weights])
            self.initial_weights = None

        super().build(input_shape)

    def call(self, inputs):
        q = 1.0 / (
            1.0
            + tf.reduce_sum(
                tf.square(
                    tf.expand_dims(inputs, axis=1) - self.clusters
                ),
                axis=2
            ) / self.alpha
        )

        q = tf.pow(q, (self.alpha + 1.0) / 2.0)
        q = q / tf.reduce_sum(q, axis=1, keepdims=True)
        return q

    def get_config(self):
        config = super().get_config()
        config.update({
            "n_clusters": self.n_clusters,
            "alpha": self.alpha
        })
        return config


def build_encoder(input_dim, latent_dim=4):
    """Recreate the final Cowrie encoder: input -> 32 -> 16 -> latent."""
    inputs = Input(shape=(input_dim,), name="input")
    x = Dense(32, activation="relu", name="encoder_dense_32")(inputs)
    x = Dense(16, activation="relu", name="encoder_dense_16")(x)
    latent = Dense(
        latent_dim,
        activation="linear",
        name="latent"
    )(x)
    return Model(inputs, latent, name="cowrie_encoder")


def build_dec(input_dim, latent_dim=4, n_clusters=3, alpha=1.0):
    """Build the inference DEC model used by the final Cowrie pipeline."""
    encoder = build_encoder(input_dim, latent_dim)

    cluster_output = ClusteringLayer(
        n_clusters=n_clusters,
        alpha=alpha,
        name="clustering"
    )(encoder.output)

    dec_model = Model(
        inputs=encoder.input,
        outputs=cluster_output,
        name="cowrie_dec"
    )
    return dec_model, encoder


def load_weights(model, model_dir):
    weights_path = os.path.join(
        model_dir,
        "cowrie_dec.weights.h5"
    )
    if not os.path.exists(weights_path):
        raise FileNotFoundError(
            f"DEC weights not found: {weights_path}"
        )

    model.load_weights(weights_path)
    return model
