"""
Loads the resurrected phishing-detection RandomForestClassifier
(app/dumped_models/phishing/rf.joblib) and scores a URL with it.

This is the "real" ML half of phishing detection, matching how
sqlprediction/views.py already uses its own pca/mp models -- see
PredictPhishing in views.py for how this is combined with the heuristic
detector in detector.py.

Where this model came from: it's a RandomForestClassifier trained on the
public Vrbancic/Fister/Podgorelec phishing-URL dataset (111 lexical +
network features -- see vrbancic_features.py), supplied as a pretrained
.joblib file. The original pickle predates the scikit-learn version this
project is pinned to and can't be unpickled directly (a binary layout
change in the Cython Tree extension type, not just a missing-attribute
issue like the SQL-injection models in dumped_models/load_models.py) --
it was migrated by extracting its raw per-tree arrays under a
version-matched scikit-learn and reconstructing fresh Tree/
DecisionTreeClassifier/RandomForestClassifier objects under the current
version. The reconstruction was verified to produce bit-for-bit identical
predict()/predict_proba() output to the original across a 3,000-row
sample of the training data before being adopted.
"""
import logging
import os

import joblib

from .vrbancic_features import extract_all_features, to_feature_vector

logger = logging.getLogger(__name__)

_MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'dumped_models', 'phishing', 'rf.joblib')

# Loaded once at import time (same pattern sqlprediction/views.py uses for
# pca/mp) rather than per-request -- a RandomForestClassifier of this size
# takes a noticeable moment to unpickle.
_model = None
_model_load_error = None


def _get_model():
    global _model, _model_load_error
    if _model is None and _model_load_error is None:
        try:
            _model = joblib.load(os.path.normpath(_MODEL_PATH))
        except Exception as e:  # pragma: no cover - exercised via load-failure tests with a patched path
            logger.error("Failed to load phishing model from %s: %s", _MODEL_PATH, e)
            _model_load_error = e
    return _model


def model_available():
    return _get_model() is not None


def predict(url, include_network=True):
    """
    Scores a URL with the trained model.

    Returns a dict:
      {'available': True, 'is_phishing': bool, 'score': float in [0, 1],
       'features': {...}}
    or, if the model failed to load,
      {'available': False}
    Callers (PredictPhishing.post) are expected to fall back to the
    heuristic detector when 'available' is False.
    """
    model = _get_model()
    if model is None:
        return {'available': False}

    features = extract_all_features(url, include_network=include_network)
    vector = to_feature_vector(features)

    proba = model.predict_proba([vector])[0]
    classes = list(model.classes_)
    phishing_index = classes.index('Phishing')
    score = float(proba[phishing_index])

    return {
        'available': True,
        'is_phishing': score >= 0.5,
        'score': round(score, 4),
        'features': features,
    }
