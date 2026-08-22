"""
Tests for model.py — the resurrected RandomForestClassifier wrapper.

Uses include_network=False everywhere so these stay deterministic and
fast: network-dependent feature computation is vrbancic_features.py's
job and is covered by manual/live testing (see model.py's module
docstring for how the model itself was validated), not something to
re-exercise here on every test run against real DNS/HTTP/RDAP calls.
"""
from django.test import SimpleTestCase

from . import model as phishing_model


class ModelLoadTests(SimpleTestCase):
    def test_model_is_available(self):
        # app/dumped_models/phishing/rf.joblib is the reconstructed model;
        # this just confirms it loads cleanly under the current
        # scikit-learn/numpy versions pinned in requirements.txt.
        self.assertTrue(phishing_model.model_available())

    def test_predict_reports_unavailable_when_model_fails_to_load(self):
        # Simulate a missing/corrupt model file without touching the real
        # one on disk: reset the module's lazily-loaded singleton and make
        # the next load attempt fail.
        original_model = phishing_model._model
        original_error = phishing_model._model_load_error
        try:
            phishing_model._model = None
            phishing_model._model_load_error = None
            with self.settings():
                import unittest.mock as mock
                with mock.patch.object(phishing_model.joblib, 'load', side_effect=OSError('missing file')):
                    result = phishing_model.predict('https://example.com', include_network=False)
            self.assertEqual(result, {'available': False})
            self.assertFalse(phishing_model.model_available())
        finally:
            phishing_model._model = original_model
            phishing_model._model_load_error = original_error


class ModelPredictTests(SimpleTestCase):
    def test_predict_returns_expected_shape(self):
        result = phishing_model.predict('https://example.com/login', include_network=False)
        self.assertTrue(result['available'])
        self.assertIn('is_phishing', result)
        self.assertIn('score', result)
        self.assertIn('features', result)
        self.assertIsInstance(result['is_phishing'], bool)

    def test_score_is_bounded_between_zero_and_one(self):
        for url in ['https://example.com', 'http://192.168.1.5/login.php?x=1']:
            result = phishing_model.predict(url, include_network=False)
            self.assertGreaterEqual(result['score'], 0.0)
            self.assertLessEqual(result['score'], 1.0)

    def test_is_phishing_matches_score_threshold(self):
        result = phishing_model.predict('https://example.com', include_network=False)
        self.assertEqual(result['is_phishing'], result['score'] >= 0.5)

    def test_feature_vector_has_111_entries(self):
        result = phishing_model.predict('https://example.com', include_network=False)
        self.assertEqual(len(result['features']), 111)
