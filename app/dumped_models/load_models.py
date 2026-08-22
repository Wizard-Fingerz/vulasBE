import joblib
import os


def _patch_legacy_sklearn_estimator(estimator):
    """
    These .joblib files were pickled years ago under old scikit-learn
    versions (the InconsistentVersionWarning at load time says as much —
    e.g. the shipped PCA was fitted under 0.24.2). requirements.txt pins
    scikit-learn==1.6.0, and newer scikit-learn's internal machinery
    (`__sklearn_tags__`, used by `check_is_fitted`) reads instance
    attributes — like PCA's `power_iteration_normalizer` — that didn't
    exist as constructor parameters back when these objects were fitted,
    so they were never set on the pickled instance.

    Concretely: calling `pca.transform(...)` with exactly the pinned
    scikit-learn version raises
        AttributeError: 'PCA' object has no attribute 'power_iteration_normalizer'
    on every request to /predict-sql-injection/ — this isn't a warning,
    it's a hard crash, since pca/model are constructed once at import
    time and reused for every request.

    Retraining/re-pickling from the original dataset would be the real
    fix, but that dataset isn't in this repo. Backfilling the small set of
    newer attributes with their current scikit-learn defaults is a
    pragmatic, low-risk compatibility shim: it only ever *adds* an
    attribute that's missing, never changes existing fitted behaviour.
    """
    defaults_by_missing_attr = {
        'power_iteration_normalizer': 'auto',
    }
    for attr, default in defaults_by_missing_attr.items():
        if not hasattr(estimator, attr):
            setattr(estimator, attr, default)
    return estimator


def load_model(model_name):  # Load models without extensions
    """
    Load a machine learning model from the dumped_models directory.

    :param model_name: The name of the model file (without extension).
    :return: The loaded model.
    """
    model_name = f"dumped.{model_name}"  # Update to include 'dumped.' prefix
    possible_extensions = ['.joblib', '']  # Check for .joblib and no extension
    for ext in possible_extensions:
        model_path = os.path.join(os.path.dirname(__file__), f"{model_name}{ext}")
        if os.path.exists(model_path):
            return _patch_legacy_sklearn_estimator(joblib.load(model_path))
    raise FileNotFoundError(f"Model {model_name} not found in dumped_models.")


def load_joblib(model_name):  # Load models with .joblib extension
    """
    Load a joblib model from the dumped_models directory.

    :param model_name: The name of the joblib model file (without extension).
    :return: The loaded model.
    """
    model_path = os.path.join(os.path.dirname(__file__), f"{model_name}.joblib")
    if os.path.exists(model_path):
        return _patch_legacy_sklearn_estimator(joblib.load(model_path))
    raise FileNotFoundError(f"Joblib model {model_name} not found in dumped_models.")
