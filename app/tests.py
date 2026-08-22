from datetime import timedelta
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

User = get_user_model()


@override_settings(FLUTTERWAVE_SECRET_KEY='test-secret-key')
class PaymentViewTests(APITestCase):
    """
    Covers POST /payment/.

    PaymentView used to crash on every single call: it did
    `from datetime import time, timedelta, timezone` at the top of
    app/views.py, which shadows the `time` *module* with datetime's `time`
    *class* — so `int(time.time())` raised
    `AttributeError: type object 'datetime.time' has no attribute 'time'`
    before the Flutterwave request was ever made. See app/views.py for the
    fix (a real `import time` plus `from django.utils import timezone`).
    These tests would fail again if that regressed.
    """

    def setUp(self):
        self.user = User.objects.create_user(username='payer', email='payer@example.com', password='Str0ng!Passw0rd-2026')
        self.client.force_authenticate(user=self.user)
        self.url = reverse('api:payment')

    def test_requires_authentication(self):
        self.client.force_authenticate(user=None)
        response = self.client.post(self.url, {'subscription_type': 'individual'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_invalid_subscription_type_returns_400(self):
        response = self.client.post(self.url, {'subscription_type': 'gold'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('app.views.requests.post')
    def test_successful_charge_redirects_to_flutterwave_link(self, mock_post):
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {'data': {'link': 'https://checkout.flutterwave.com/pay/abc123'}},
        )

        response = self.client.post(self.url, {'subscription_type': 'cooperate', 'phone_number': '08000000000'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_302_FOUND)
        self.assertEqual(response.url, 'https://checkout.flutterwave.com/pay/abc123')

        # The right amount for the plan, and the right auth header, were sent.
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs['json']['amount'], 5000)
        self.assertEqual(kwargs['json']['email'], 'payer@example.com')
        self.assertEqual(kwargs['headers']['Authorization'], 'Bearer test-secret-key')

    @patch('app.views.requests.post')
    def test_failed_charge_returns_400(self, mock_post):
        mock_post.return_value = Mock(status_code=400, json=lambda: {})

        response = self.client.post(self.url, {'subscription_type': 'individual'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class PaymentConfirmationViewTests(APITestCase):
    """
    Covers POST /payment/confirm/, the Flutterwave callback target. Same
    'inherited IsAuthenticated by omission' bug as the original LoginView —
    see app/views.py::PaymentConfirmationView for the fix — plus the
    `timezone.now()` call here used to be datetime.timezone.now(), which
    doesn't exist (datetime.timezone has no .now()); that regressed
    alongside the PaymentView bug above and is fixed by the same import
    cleanup.
    """

    def setUp(self):
        self.user = User.objects.create_user(username='confirmee', email='confirmee@example.com', password='Str0ng!Passw0rd-2026')
        self.url = reverse('api:payment-confirmation')

    def test_does_not_require_authentication(self):
        response = self.client.post(self.url, {'status': 'failed', 'email': 'confirmee@example.com'}, format='json')
        self.assertNotEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_unsuccessful_status_returns_400(self):
        response = self.client.post(self.url, {'status': 'failed', 'email': 'confirmee@example.com'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_unknown_email_returns_400_instead_of_500(self):
        response = self.client.post(self.url, {'status': 'successful', 'email': 'nobody@example.com'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_successful_status_issues_private_key_and_emails_it(self):
        before = timezone.now()

        response = self.client.post(self.url, {'status': 'successful', 'email': 'confirmee@example.com'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.private_key)
        self.assertGreater(self.user.private_key_expiration, before + timedelta(days=364))

        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(self.user.private_key, mail.outbox[0].body)
        self.assertEqual(mail.outbox[0].to, ['confirmee@example.com'])
