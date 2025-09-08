from django.core.mail import send_mail
from datetime import time, timedelta, timezone
from django.shortcuts import render

# Create your views here.
import requests
from django.conf import settings
from django.shortcuts import redirect
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from user.models import User
from user.utils import generate_private_key


class PaymentView(APIView):
    def post(self, request):
        user = request.user
        subscription_type = request.data.get('subscription_type')
        amount = self.get_subscription_amount(subscription_type)

        if amount is None:
            return Response({"error": "Invalid subscription type."}, status=status.HTTP_400_BAD_REQUEST)

        # Prepare the payment request
        payment_data = {
            "tx_ref": f"tx-{user.id}-{int(time.time())}",
            "amount": amount,
            "currency": "NGN",  # Change to your currency
            "payment_type": "card",
            "email": user.email,
            "phone_number": request.data.get('phone_number'),
            # URL to redirect after payment
            "redirect_url": "http://yourdomain.com/payment/confirm/",
        }

        headers = {
            "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        response = requests.post(
            "https://api.flutterwave.com/v3/charges?type=mobilemoneyghana", json=payment_data, headers=headers)

        if response.status_code == 200:
            payment_response = response.json()
            # Redirect to Flutterwave payment page
            return redirect(payment_response['data']['link'])
        else:
            return Response({"error": "Payment initiation failed."}, status=status.HTTP_400_BAD_REQUEST)

    def get_subscription_amount(self, subscription_type):
        # Define subscription amounts based on type
        amounts = {
            'individual': 1000,  # Example amount
            'cooperate': 5000,
            'enterprise': 10000,
        }
        return amounts.get(subscription_type)


class PaymentConfirmationView(APIView):
    def post(self, request):
        payment_data = request.data

        # Check if the payment was successful
        if payment_data['status'] == 'successful':
            user = User.objects.get(
                email=payment_data['email'])  # Get user by email
            user.private_key = generate_private_key()  # Generate a private key
            user.private_key_expiration = timezone.now() + timedelta(days=365)  # Set expiration
            user.save()

            # Send the private key via email
            send_mail(
                'Your Private Key',
                f'Your private key is: {user.private_key}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            return Response({"message": "Payment successful, private key sent to your email."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Payment not successful."}, status=status.HTTP_400_BAD_REQUEST)
