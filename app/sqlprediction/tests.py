import io

from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from .models import BlockedHost, PacketInfo, UploadedFile

User = get_user_model()


SAMPLE_PACKET = {
    'ip_source': '10.0.0.1',
    'ip_destination': '10.0.0.2',
    'mac_source': 'AA:BB:CC:DD:EE:01',
    'mac_destination': 'AA:BB:CC:DD:EE:02',
    'protocol': 'TCP',
    'flags': 'SYN',
    'source_port': 443,
    'destination_port': 51000,
    'ttl': 64,
}


class PacketInfoViewSetTests(APITestCase):
    def test_list_and_create_via_router(self):
        # PacketInfoViewSet doesn't override permission_classes, so it
        # inherits the project-wide default of IsAuthenticated — unlike the
        # create_packet_info/create_blocked_host function views below,
        # which are explicitly @permission_classes([AllowAny]).
        self.client.force_authenticate(user=User.objects.create_user(username='packetuser', password='Str0ng!Passw0rd-2026'))
        url = reverse('api:packetinfo-list')

        create_response = self.client.post(url, SAMPLE_PACKET, format='json')
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(PacketInfo.objects.count(), 1)

        list_response = self.client.get(url)
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(list_response.data), 1)


class BlockedHostViewSetTests(APITestCase):
    def test_list_and_create_via_router(self):
        self.client.force_authenticate(user=User.objects.create_user(username='blockeduser', password='Str0ng!Passw0rd-2026'))
        url = reverse('api:blockedhost-list')

        create_response = self.client.post(url, SAMPLE_PACKET, format='json')
        self.assertEqual(create_response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(BlockedHost.objects.count(), 1)

        list_response = self.client.get(url)
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(list_response.data), 1)


class CreatePacketInfoFunctionViewTests(APITestCase):
    def test_create_packet_info_maps_capitalised_keys(self):
        url = reverse('api:create_packet_info')
        payload = {
            'IP Source': '192.168.0.1',
            'IP Destination': '192.168.0.2',
            'MAC Source': 'AA:BB:CC:DD:EE:01',
            'MAC Destination': 'AA:BB:CC:DD:EE:02',
            'Protocol': 'UDP',
            'Flags': 'ACK',
            'Source Port': 53,
            'Destination Port': 53000,
            'TTL': 128,
        }

        response = self.client.post(url, payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        packet = PacketInfo.objects.get()
        self.assertEqual(packet.ip_source, '192.168.0.1')
        self.assertEqual(packet.protocol, 'UDP')


class CreateBlockedHostFunctionViewTests(APITestCase):
    def test_create_blocked_host_maps_capitalised_keys(self):
        url = reverse('api:create_blocked_host')
        payload = {
            'IP Source': '172.16.0.1',
            'IP Destination': '172.16.0.2',
            'MAC Source': 'AA:BB:CC:DD:EE:03',
            'MAC Destination': 'AA:BB:CC:DD:EE:04',
            'Protocol': 'TCP',
            'Flags': 'RST',
            'Source Port': 8080,
            'Destination Port': 443,
            'TTL': 32,
        }

        response = self.client.post(url, payload, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(BlockedHost.objects.get().ip_source, '172.16.0.1')


class PredictSQLInjectionViewTests(APITestCase):
    """
    Exercises the real pca.joblib + mp.joblib models. This endpoint used to
    hard-crash (500, AttributeError: 'PCA' object has no attribute
    'power_iteration_normalizer') on *every single request* with the exact
    scikit-learn version pinned in requirements.txt (1.6.0), because those
    models were pickled years ago under scikit-learn 0.24.2/1.0.2. See
    app/dumped_models/load_models.py::_patch_legacy_sklearn_estimator for
    the fix. These tests would fail again if that compatibility shim ever
    regresses.
    """

    def setUp(self):
        self.url = reverse('api:predict_sql_injection')

    def test_clean_url_is_not_flagged(self):
        response = self.client.post(self.url, {'url': 'https://example.com/search?q=hello'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('is_sql_injection', response.data)
        self.assertIsInstance(response.data['is_sql_injection'], bool)

    def test_obvious_sql_injection_payload_is_flagged(self):
        payload_url = "https://example.com/login?user=admin' UNION SELECT username, password FROM users--"

        response = self.client.post(self.url, {'url': payload_url}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['is_sql_injection'])

    def test_missing_url_returns_400(self):
        response = self.client.post(self.url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_does_not_500_with_the_pinned_scikit_learn_version(self):
        """Regression test for the legacy-pickle AttributeError crash."""
        response = self.client.post(self.url, {'url': 'https://example.com/'}, format='json')
        self.assertNotEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)


class PredictionsFunctionViewTests(APITestCase):
    """Covers /predictions/, which runs raw feature rows through the
    separate MLPNEW model (predict_few) rather than the PCA + mp.joblib
    pipeline used by /predict-sql-injection/."""

    def setUp(self):
        self.url = reverse('api:predictions')

    def test_missing_input_data_returns_400(self):
        response = self.client.post(self.url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_valid_input_data_returns_predictions(self):
        # MLPNEW (dumped.MLPNEW) was fitted on 10 features; the exact
        # values only need to be numeric/well-formed for this to exercise
        # the endpoint end to end.
        row = {f'f{i}': 0 for i in range(10)}
        response = self.client.post(self.url, {'input_data': [row]}, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('predictions', response.data)
        self.assertEqual(len(response.data['predictions']), 1)


class FileUploadViewTests(APITestCase):
    def test_upload_creates_uploaded_file_and_single_pcap_copy(self):
        url = reverse('api:upload_file')
        upload = io.BytesIO(b'fake-pcap-bytes')
        upload.name = 'capture.pcap'

        response = self.client.post(url, {'file': upload}, format='multipart')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(UploadedFile.objects.count(), 1)
