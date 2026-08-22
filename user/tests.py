from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

from .models import Device, User


class RegisterViewTests(APITestCase):
    """
    Covers the public POST /register/ endpoint. This endpoint didn't exist
    at all before — the browser extension's registration form posts here
    and was getting a 404.
    """

    def setUp(self):
        self.url = reverse('api:register')
        self.valid_payload = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'phone_number': '+2348012345678',
            'password': 'Str0ng!Passw0rd-2026',
        }

    def test_register_creates_user_and_returns_token(self):
        response = self.client.post(self.url, self.valid_payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('token', response.data)
        self.assertEqual(response.data['username'], 'newuser')

        user = User.objects.get(username='newuser')
        self.assertEqual(user.email, 'newuser@example.com')
        self.assertEqual(user.phone_number, '+2348012345678')
        self.assertTrue(user.check_password('Str0ng!Passw0rd-2026'))

        # The post_save signal on User should have already minted a token,
        # and it should be the same one returned in the response.
        token = Token.objects.get(user=user)
        self.assertEqual(token.key, response.data['token'])

    def test_register_rejects_duplicate_username(self):
        User.objects.create_user(username='newuser', email='other@example.com', password='Str0ng!Passw0rd-2026')

        response = self.client.post(self.url, self.valid_payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)

    def test_register_rejects_duplicate_email(self):
        User.objects.create_user(username='someoneelse', email='newuser@example.com', password='Str0ng!Passw0rd-2026')

        response = self.client.post(self.url, self.valid_payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_register_rejects_weak_password(self):
        payload = dict(self.valid_payload, username='anotheruser', email='another@example.com', password='password')

        response = self.client.post(self.url, payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)
        self.assertFalse(User.objects.filter(username='anotheruser').exists())

    def test_register_requires_email(self):
        payload = dict(self.valid_payload)
        payload.pop('email')

        response = self.client.post(self.url, payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class LoginViewTests(APITestCase):
    def setUp(self):
        self.url = reverse('api:login')
        self.user = User.objects.create_user(
            username='loginuser',
            password='Str0ng!Passw0rd-2026',
            subscription_type='individual',
        )
        self.user.private_key = 'PRIVATEKEY12345'
        self.user.private_key_expiration = timezone.now() + timezone.timedelta(days=365)
        self.user.save()

    def test_login_with_correct_credentials_and_private_key(self):
        response = self.client.post(self.url, {
            'username': 'loginuser',
            'password': 'Str0ng!Passw0rd-2026',
            'private_key': 'PRIVATEKEY12345',
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'loginuser')
        self.assertEqual(response.data['subscription_type'], 'individual')
        token = Token.objects.get(user=self.user)
        self.assertEqual(response.data['token'], token.key)

    def test_login_with_wrong_password_is_rejected(self):
        response = self.client.post(self.url, {
            'username': 'loginuser',
            'password': 'wrong-password',
            'private_key': 'PRIVATEKEY12345',
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_with_wrong_private_key_is_rejected(self):
        response = self.client.post(self.url, {
            'username': 'loginuser',
            'password': 'Str0ng!Passw0rd-2026',
            'private_key': 'NOT-THE-RIGHT-KEY',
        }, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class RefreshPrivateKeyViewTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='refreshuser', password='Str0ng!Passw0rd-2026')
        self.user.private_key = 'OLDKEY123456789'
        self.user.save()
        self.url = reverse('api:refresh-private-key')

    def test_requires_authentication(self):
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authenticated_user_gets_a_new_private_key(self):
        self.client.force_authenticate(user=self.user)

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        new_key = response.data['new_private_key']
        self.assertNotEqual(new_key, 'OLDKEY123456789')

        self.user.refresh_from_db()
        self.assertEqual(self.user.private_key, new_key)


class UserViewSetSubscriptionTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='subuser', password='Str0ng!Passw0rd-2026')
        self.url = reverse('api:user-list')
        self.client.force_authenticate(user=self.user)

    def test_valid_subscription_type_sets_plan_and_private_key(self):
        response = self.client.post(self.url, {'subscription_type': 'cooperate'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.user.refresh_from_db()
        self.assertEqual(self.user.subscription_type, 'cooperate')
        self.assertIsNotNone(self.user.private_key)
        self.assertIsNotNone(self.user.private_key_expiration)

    def test_invalid_subscription_type_is_rejected(self):
        response = self.client.post(self.url, {'subscription_type': 'gold-plan'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_requires_authentication(self):
        self.client.force_authenticate(user=None)
        response = self.client.post(self.url, {'subscription_type': 'individual'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class DeviceViewSetPlanLimitTests(APITestCase):
    def setUp(self):
        self.url = reverse('api:device-list')

    def _make_user(self, username, subscription_type):
        user = User.objects.create_user(username=username, password='Str0ng!Passw0rd-2026')
        user.subscription_type = subscription_type
        user.save()
        return user

    def test_individual_plan_allows_exactly_one_device(self):
        user = self._make_user('individual_user', 'individual')
        self.client.force_authenticate(user=user)

        first = self.client.post(self.url, {'device_id': 'device-1'}, format='json')
        self.assertEqual(first.status_code, status.HTTP_201_CREATED)

        second = self.client.post(self.url, {'device_id': 'device-2'}, format='json')
        self.assertEqual(second.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Device.objects.filter(user=user).count(), 1)

    def test_cooperate_plan_allows_up_to_twenty_devices(self):
        user = self._make_user('cooperate_user', 'cooperate')
        self.client.force_authenticate(user=user)

        # Fill 19 via the ORM directly (fast), then confirm the API allows
        # exactly one more and blocks the one after that.
        Device.objects.bulk_create([
            Device(user=user, device_id=f'device-{i}') for i in range(19)
        ])

        twentieth = self.client.post(self.url, {'device_id': 'device-20'}, format='json')
        self.assertEqual(twentieth.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Device.objects.filter(user=user).count(), 20)

        twenty_first = self.client.post(self.url, {'device_id': 'device-21'}, format='json')
        self.assertEqual(twenty_first.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(Device.objects.filter(user=user).count(), 20)

    def test_enterprise_plan_has_no_device_limit(self):
        user = self._make_user('enterprise_user', 'enterprise')
        self.client.force_authenticate(user=user)

        Device.objects.bulk_create([
            Device(user=user, device_id=f'device-{i}') for i in range(25)
        ])

        response = self.client.post(self.url, {'device_id': 'device-26'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Device.objects.filter(user=user).count(), 26)

    def test_requires_authentication(self):
        response = self.client.post(self.url, {'device_id': 'device-x'}, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
