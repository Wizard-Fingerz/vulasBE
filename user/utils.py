

from datetime import timedelta
from django.utils import timezone


import random
import string

def generate_private_key(length=15):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))



def is_private_key_valid(user, private_key):
    return (user.private_key == private_key and 
            user.private_key_expiration > timezone.now())


def subscribe_user(user, subscription_type):
    user.subscription_type = subscription_type
    user.private_key = generate_private_key()
    user.private_key_expiration = timezone.now() + timedelta(days=365)  # 1 year expiration
    user.save()