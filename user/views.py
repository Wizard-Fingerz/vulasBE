from django.shortcuts import render

# Create your views here.
from rest_framework import viewsets, permissions
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from user.utils import generate_private_key
from .models import User, Device
from .serializers import UserSerializer, DeviceSerializer, RegisterSerializer
from django.utils import timezone
from datetime import timedelta
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from .serializers import LoginSerializer


class RegisterView(generics.CreateAPIView):
    """
    Public account creation. This is the endpoint the browser extension's
    register.js already calls (POST /register/) — it previously 404'd
    because nothing implemented it; UserViewSet.create() is a different,
    authenticated action (setting a subscription plan on an existing user).
    """
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token, _ = Token.objects.get_or_create(user=user)

        return Response({
            'token': token.key,
            'user_id': user.id,
            'username': user.username,
        }, status=status.HTTP_201_CREATED)


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        subscription_type = request.data.get('subscription_type')
        user = request.user

        if subscription_type not in ['individual', 'cooperate', 'enterprise']:
            return Response({"error": "Invalid subscription type."}, status=status.HTTP_400_BAD_REQUEST)

        user.subscription_type = subscription_type
        user.private_key = generate_private_key()
        user.private_key_expiration = timezone.now(
        ) + timedelta(days=365)  # 1 year expiration
        user.save()

        serializer = self.get_serializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class DeviceViewSet(viewsets.ModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        user = request.user
        device_id = request.data.get('device_id')

        if user.subscription_type == 'individual':
            if Device.objects.filter(user=user).count() < 1:
                Device.objects.create(user=user, device_id=device_id)
                return Response({"message": "Device added successfully."}, status=status.HTTP_201_CREATED)
            else:
                return Response({"error": "Individual plan allows only one device."}, status=status.HTTP_400_BAD_REQUEST)

        elif user.subscription_type == 'cooperate':
            if Device.objects.filter(user=user).count() < 20:
                Device.objects.create(user=user, device_id=device_id)
                return Response({"message": "Device added successfully."}, status=status.HTTP_201_CREATED)
            else:
                return Response({"error": "Cooperate plan allows up to 20 devices."}, status=status.HTTP_400_BAD_REQUEST)

        elif user.subscription_type == 'enterprise':
            Device.objects.create(user=user, device_id=device_id)
            return Response({"message": "Device added successfully."}, status=status.HTTP_201_CREATED)

        return Response({"error": "Invalid subscription type."}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    # Without this, LoginView inherited the project-wide default of
    # IsAuthenticated (see REST_FRAMEWORK in settings.py), which meant you
    # had to already be authenticated to be allowed to log in — every
    # request here 403'd before the serializer even ran.
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        # Create or get the token for the user
        token, created = Token.objects.get_or_create(user=user)

        return Response({
            'token': token.key,
            'user_id': user.id,
            'username': user.username,
            'subscription_type': user.subscription_type,
            'private_key_expiration': user.private_key_expiration
        }, status=status.HTTP_200_OK)


class RefreshPrivateKeyView(APIView):
    def post(self, request):
        user = request.user  # Get the currently authenticated user

        # Generate a new private key
        new_private_key = generate_private_key()

        # Update the user's private key
        user.private_key = new_private_key
        user.save()

        return Response({"message": "Private key refreshed successfully.", "new_private_key": new_private_key}, status=status.HTTP_200_OK)