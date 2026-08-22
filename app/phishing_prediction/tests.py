from unittest.mock import patch

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .detector import analyze_url


class DetectorHeuristicTests(APITestCase):
    """
    Unit tests for the heuristic phishing detector itself (no HTTP layer).
    """

    def test_legitimate_urls_are_not_flagged(self):
        for url in [
            'https://www.google.com',
            'https://github.com/anthropics',
            'https://www.apple.com/uk/shop',
            'https://en.wikipedia.org/wiki/Phishing',
        ]:
            result = analyze_url(url)
            self.assertFalse(result['is_phishing'], f'{url} should not be flagged, got {result}')

    def test_ip_literal_host_with_login_path_is_flagged(self):
        result = analyze_url('http://192.168.1.5/login.php')
        self.assertTrue(result['is_phishing'])
        self.assertTrue(any('IP address' in reason for reason in result['reasons']))

    def test_brand_typosquat_is_flagged(self):
        result = analyze_url('https://www.paypa1.com/login')
        self.assertTrue(result['is_phishing'])
        self.assertTrue(any('paypal' in reason for reason in result['reasons']))

    def test_brand_name_stuffed_into_unrelated_domain_is_flagged(self):
        result = analyze_url('https://accounts.google.com.verify-user-login.ru/signin')
        self.assertTrue(result['is_phishing'])
        self.assertTrue(any('google' in reason for reason in result['reasons']))

    def test_punycode_host_is_flagged(self):
        result = analyze_url('http://xn--pypal-4ve.com/account/verify')
        self.assertTrue(result['is_phishing'])
        self.assertTrue(any('punycode' in reason for reason in result['reasons']))

    def test_url_shortener_alone_raises_score_but_is_not_automatically_phishing(self):
        result = analyze_url('http://bit.ly/3xJd9Kf')
        self.assertGreater(result['score'], 0)
        self.assertTrue(any('shorten' in reason for reason in result['reasons']))

    def test_own_brand_domain_is_not_flagged_as_its_own_lookalike(self):
        result = analyze_url('https://www.paypal.com/signin')
        self.assertFalse(result['is_phishing'])

    def test_unparseable_url_does_not_crash(self):
        result = analyze_url('not a url at all')
        self.assertIn('is_phishing', result)
        self.assertIn('score', result)

    def test_score_is_bounded_between_zero_and_one(self):
        # Deliberately pile on as many heuristics as possible.
        url = 'http://xn--pypal-4ve.com-secure-login-verify-account.com/login/verify//redirect?x=1' * 1
        result = analyze_url(url)
        self.assertGreaterEqual(result['score'], 0.0)
        self.assertLessEqual(result['score'], 1.0)


class PredictPhishingViewTests(APITestCase):
    """
    Covers the new POST /predict-phishing/ endpoint. This replaces the old
    app/phishing_prediction/views.py, which was a verbatim copy of the
    SQL-injection view (same SQL-keyword vectorizer, same model class) and
    was never even wired into app/urls.py — it couldn't have detected
    phishing, and nothing could reach it anyway.

    The endpoint's live behaviour is "trained model decides, heuristics
    supply the human-readable reasons and act as fallback" (see
    PredictPhishing.post) — model.predict() is mocked in most tests here
    so results are deterministic and don't depend on real DNS/HTTP/RDAP
    calls succeeding from wherever the test suite happens to run.
    """

    def setUp(self):
        self.url = reverse('api:predict_phishing')

    def test_endpoint_is_public(self):
        response = self.client.post(self.url, {'url': 'https://example.com'}, format='json')
        self.assertNotEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_missing_url_returns_400(self):
        response = self.client.post(self.url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('app.phishing_prediction.views.phishing_model.predict')
    def test_model_verdict_is_used_when_model_available(self, mock_predict):
        mock_predict.return_value = {'available': True, 'is_phishing': False, 'score': 0.12, 'features': {}}

        response = self.client.post(self.url, {'url': 'https://example.com'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertFalse(response.data['is_phishing'])
        self.assertEqual(response.data['score'], 0.12)
        self.assertEqual(response.data['source'], 'model')
        self.assertIn('reasons', response.data)
        self.assertIn('heuristic', response.data)

    @patch('app.phishing_prediction.views.phishing_model.predict')
    def test_model_flags_phishing_when_score_is_high(self, mock_predict):
        mock_predict.return_value = {'available': True, 'is_phishing': True, 'score': 0.91, 'features': {}}

        response = self.client.post(self.url, {'url': 'http://paypal-secure-login.com/verify-account'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['is_phishing'])
        self.assertEqual(response.data['source'], 'model')
        self.assertGreater(len(response.data['reasons']), 0)

    @patch('app.phishing_prediction.views.phishing_model.predict')
    def test_falls_back_to_heuristic_when_model_unavailable(self, mock_predict):
        mock_predict.return_value = {'available': False}

        response = self.client.post(self.url, {'url': 'http://paypal-secure-login.com/verify-account'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['source'], 'heuristic')
        self.assertTrue(response.data['is_phishing'])
        self.assertGreater(len(response.data['reasons']), 0)
        self.assertNotIn('heuristic', response.data)

    @patch('app.phishing_prediction.views.phishing_model.predict')
    def test_falls_back_to_heuristic_when_model_raises(self, mock_predict):
        mock_predict.side_effect = RuntimeError('feature vector shape mismatch')

        response = self.client.post(self.url, {'url': 'https://example.com'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['source'], 'heuristic')

    def test_real_model_end_to_end_smoke_test(self):
        # One unmocked pass through the actual endpoint (real model,
        # real heuristics), just to confirm nothing throws and the
        # response has the documented shape. include_network is on
        # inside the view, so this does real DNS/HTTP lookups for
        # whatever host is in the URL below -- kept on a domain that
        # doesn't need to resolve to anything real for the response
        # shape to be valid either way.
        response = self.client.post(self.url, {'url': 'https://example.com'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('is_phishing', response.data)
        self.assertIn('score', response.data)
        self.assertIn('reasons', response.data)
        self.assertIn(response.data['source'], ('model', 'heuristic'))
