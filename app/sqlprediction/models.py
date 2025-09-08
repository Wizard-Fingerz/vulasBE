from django.db import models
import numpy as np
import joblib
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework.views import APIView
from app.dumped_models.load_models import load_model
from rest_framework import status


# Load the models from the model files using joblib.load
dumped = "MLPNEW"  # This is the name of the model file

# Load the model
model_few = load_model(dumped)
# model_all = joblib.load(model_path_all)

def predict_few(input_data):
    input_data = np.array(input_data)  # Ensure input_data is a numpy array
    predictions = model_few.predict(input_data)
    return predictions.tolist()

# def predict_all(input_data):
#     input_data = np.array(input_data)  # Ensure input_data is a numpy array
#     predictions = model_all.predict(input_data)
#     return predictions.tolist()


class PacketInfo(models.Model):
    ip_source = models.CharField(max_length=15, blank=True, null = True)
    ip_destination = models.CharField(max_length=15, blank=True, null = True)
    mac_source = models.CharField(max_length=17, blank=True, null = True)
    mac_destination = models.CharField(max_length=17, blank=True, null = True)
    protocol = models.CharField(max_length=10, blank=True, null = True)
    flags = models.CharField(max_length=10, blank=True, null = True)
    source_port = models.IntegerField(blank=True, null = True)
    destination_port = models.IntegerField(blank=True, null = True)
    ttl = models.IntegerField(blank=True, null = True)


    def __str__(self):
        return self.ip_source

class BlockedHost(models.Model):
    ip_source = models.CharField(max_length=15, blank=True, null = True)
    ip_destination = models.CharField(max_length=15, blank=True, null = True)
    mac_source = models.CharField(max_length=17, blank=True, null = True)
    mac_destination = models.CharField(max_length=17, blank=True, null = True)
    protocol = models.CharField(max_length=10, blank=True, null = True)
    flags = models.CharField(max_length=10, blank=True, null = True)
    source_port = models.IntegerField(blank=True, null = True)
    destination_port = models.IntegerField(blank=True, null = True)
    ttl = models.IntegerField(blank=True, null = True)


class UploadedFile(models.Model):
    file = models.FileField(upload_to='uploads/')
