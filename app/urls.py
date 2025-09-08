
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from app.sqlprediction.views import PacketInfoViewSet, BlockedHostViewSet, UploadedFileViewSet, FileUploadView, PredictSQLInjection, create_blocked_host, create_packet_info, download_last_uploaded_file, download_media, predictions
from .views import PaymentView, PaymentConfirmationView


router = DefaultRouter()
router.register(r'packet-info', PacketInfoViewSet)
router.register(r'blocked-host', BlockedHostViewSet)
router.register(r'uploaded-file', UploadedFileViewSet)


urlpatterns = [
    path('', include(router.urls)),
    path('payment/', PaymentView.as_view(), name='payment'),
    path('payment/confirm/', PaymentConfirmationView.as_view(), name='payment-confirmation'),
    path('predictions/', predictions, name='predictions'),
    path('predict-sql-injection/', PredictSQLInjection.as_view(), name='predict_sql_injection'),
    path('packet-info/create-packet-info/', create_packet_info, name='create_packet_info'),
    path('blocked-host/create-blocked-host/', create_blocked_host, name='create_blocked_host'),
    path('uploaded-file/upload-file/', FileUploadView.as_view(), name='upload_file'),
    path('uploaded-file/download-media/', download_media, name='download_media'),
    path('uploaded-file/download-last-uploaded-file/', download_last_uploaded_file, name='download_last_uploaded_file'),

]