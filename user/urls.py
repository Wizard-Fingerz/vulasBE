from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import LoginView, RefreshPrivateKeyView, UserViewSet, DeviceViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'devices', DeviceViewSet)

urlpatterns = [
    path('', include(router.urls)),
     path('login/', LoginView.as_view(), name='login'),
     path('refresh-private-key/', RefreshPrivateKeyView.as_view(), name='refresh-private-key'),
 
]