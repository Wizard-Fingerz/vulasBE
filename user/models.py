from datetime import timezone
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.dispatch import receiver
from rest_framework.authtoken.models import Token

# Create your models here.
class User(AbstractUser):
    is_admin = models.BooleanField(default=False, verbose_name='Admin')
    is_individual = models.BooleanField(default=False, verbose_name='Individual')
    is_cooperate = models.BooleanField(default=False, verbose_name='Cooperate')
    is_educational = models.BooleanField(default=False, verbose_name='Educational')
    is_enterprise = models.BooleanField(default=False, verbose_name='Enterprise')
    private_key = models.CharField(max_length=15, unique=True,blank = True,null = True)
    subscription_type = models.CharField(max_length=20, choices=[('individual', 'Individual'), ('cooperate', 'Cooperate'), ('enterprise', 'Enterprise')])
    private_key_expiration = models.DateTimeField(null=True, blank=True)


    class Meta:
        swappable = 'AUTH_USER_MODEL'

    def __str__(self):
        return str(self.username) or ''

@receiver(post_save, sender=User)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    """
    Signal handler to create a token for the user when a new user is created.
    """
    if created:
        Token.objects.create(user=instance)

class Device(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    device_id = models.CharField(max_length=100)  # Unique identifier for the device
    created_at = models.DateTimeField(auto_now_add=True)

def add_device(user, device_id):
    if user.subscription_type == 'individual':
        if Device.objects.filter(user=user).count() < 1:
            Device.objects.create(user=user, device_id=device_id)
        else:
            raise Exception("Individual plan allows only one device.")
    elif user.subscription_type == 'cooperate':
        if Device.objects.filter(user=user).count() < 20:
            Device.objects.create(user=user, device_id=device_id)
        else:
            raise Exception("Cooperate plan allows up to 20 devices.")
    elif user.subscription_type == 'enterprise':
        Device.objects.create(user=user, device_id=device_id)  # No limit for enterprise