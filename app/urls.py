
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from app.sqlprediction.views import PacketInfoViewSet, BlockedHostViewSet, UploadedFileViewSet, FileUploadView, PredictSQLInjection, create_blocked_host, create_packet_info, download_last_uploaded_file, download_media, predictions
from app.phishing_prediction.views import PredictPhishing
from .views import PaymentView, PaymentConfirmationView


router = DefaultRouter()
router.register(r'packet-info', PacketInfoViewSet)
router.register(r'blocked-host', BlockedHostViewSet)
router.register(r'uploaded-file', UploadedFileViewSet)


# NOTE on ordering: Django/DRF match URL patterns top-to-bottom and use the
# first match. The router's detail route for e.g. 'packet-info' is
# ^packet-info/(?P<pk>[^/.]+)/$ — which happily matches
# packet-info/create-packet-info/ too, treating "create-packet-info" as a
# pk. With `include(router.urls)` listed first (as it originally was here),
# every one of the custom endpoints below (create_packet_info,
# create_blocked_host, upload_file, download_media,
# download_last_uploaded_file) was being silently swallowed by the
# corresponding ViewSet's detail route and was completely unreachable —
# confirmed via `resolve('/packet-info/create-packet-info/')` resolving to
# PacketInfoViewSet with pk='create-packet-info', not create_packet_info.
# Listing the specific literal paths before the router include fixes that.
urlpatterns = [
    path('payment/', PaymentView.as_view(), name='payment'),
    path('payment/confirm/', PaymentConfirmationView.as_view(), name='payment-confirmation'),
    path('predictions/', predictions, name='predictions'),
    path('predict-sql-injection/', PredictSQLInjection.as_view(), name='predict_sql_injection'),
    path('predict-phishing/', PredictPhishing.as_view(), name='predict_phishing'),
    path('packet-info/create-packet-info/', create_packet_info, name='create_packet_info'),
    path('blocked-host/create-blocked-host/', create_blocked_host, name='create_blocked_host'),
    path('uploaded-file/upload-file/', FileUploadView.as_view(), name='upload_file'),
    path('uploaded-file/download-media/', download_media, name='download_media'),
    path('uploaded-file/download-last-uploaded-file/', download_last_uploaded_file, name='download_last_uploaded_file'),
    path('', include(router.urls)),
]