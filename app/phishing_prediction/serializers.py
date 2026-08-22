from rest_framework import serializers


class PredictPhishingSerializer(serializers.Serializer):
    url = serializers.CharField(
        max_length=2000,
        required=True,
        help_text="The URL to be checked for phishing indicators.",
    )
