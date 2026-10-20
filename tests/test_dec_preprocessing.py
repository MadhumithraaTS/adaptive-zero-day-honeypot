import numpy as np
import pandas as pd
import pytest

from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.preprocessing import preprocess


# The saved DEC artifacts are pickled with newer pandas/scikit-learn than the
# main test environment, so preprocessing logic is tested with stand-ins here.
# Real-artifact behaviour is validated with the DEC interpreter separately.
CONFIG = {"features": ["dur", "sbytes", "ct_srv_src"], "log_features": ["dur", "sbytes"]}
MEDIANS = pd.Series({"dur": 2.0, "sbytes": 40.0, "ct_srv_src": 100.0})


class IdentityScaler:
    def transform(self, X):
        return X.to_numpy(dtype=float)


def _rows():
    return pd.DataFrame({
        "session_id": ["a", "b", "c"],
        "dur": [1.0, 3.0, 5.0],
        "sbytes": [10.0, 20.0, 30.0],
        "ct_srv_src": [50.0, 60.0, 70.0],
    })


@pytest.mark.parametrize("bad_value", [np.inf, -np.inf, "inf", "-inf"])
def test_infinite_values_are_imputed_with_saved_median_like_training(bad_value):
    with_inf = _rows()
    with_inf["dur"] = with_inf["dur"].astype(object)
    with_inf.loc[0, "dur"] = bad_value
    with_median = _rows()
    with_median.loc[0, "dur"] = MEDIANS["dur"]

    actual = preprocess(with_inf, CONFIG, IdentityScaler(), MEDIANS)
    expected = preprocess(with_median, CONFIG, IdentityScaler(), MEDIANS)

    assert np.isfinite(actual).all()
    np.testing.assert_array_equal(actual, expected)
    assert actual[0, 0] == pytest.approx(np.log1p(2.0))


def test_infinite_value_in_non_log_feature_is_imputed():
    rows = _rows()
    rows.loc[2, "ct_srv_src"] = -np.inf
    result = preprocess(rows, CONFIG, IdentityScaler(), MEDIANS)
    assert result[2, 2] == 100.0


def test_nan_is_still_imputed_with_saved_median():
    rows = _rows()
    rows.loc[1, "sbytes"] = np.nan
    result = preprocess(rows, CONFIG, IdentityScaler(), MEDIANS)
    assert result[1, 1] == pytest.approx(np.log1p(40.0))


@pytest.mark.parametrize(
    "bad_value, message",
    [(np.inf, "unresolved missing"), ("inf", "Infinite values without a saved median")],
)
def test_infinite_value_without_saved_median_is_rejected(bad_value, message):
    rows = _rows()
    rows["ct_srv_src"] = rows["ct_srv_src"].astype(object)
    rows.loc[0, "ct_srv_src"] = bad_value
    with pytest.raises(ValueError, match=message):
        preprocess(rows, CONFIG, IdentityScaler(), MEDIANS.drop("ct_srv_src"))


def test_non_numeric_text_is_still_rejected():
    rows = _rows()
    rows["dur"] = rows["dur"].astype(object)
    rows.loc[0, "dur"] = "not-a-number"
    with pytest.raises(ValueError, match="Non-numeric"):
        preprocess(rows, CONFIG, IdentityScaler(), MEDIANS)


def test_finite_rows_are_unchanged_by_infinity_handling():
    rows = _rows()
    expected = np.column_stack([np.log1p(rows["dur"]), np.log1p(rows["sbytes"]), rows["ct_srv_src"]]).astype(np.float32)
    np.testing.assert_array_equal(preprocess(rows, CONFIG, IdentityScaler(), MEDIANS), expected)
