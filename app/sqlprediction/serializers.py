from rest_framework import serializers

from app.sqlprediction.models import BlockedHost, PacketInfo, UploadedFile


class PredictionSerializer(serializers.Serializer):
    input_data = serializers.ListField(child=serializers.FloatField())


class PacketInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = PacketInfo
        fields = '__all__'


class BlockedHostSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlockedHost
        fields = '__all__'


class UploadedFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UploadedFile
        fields = ('file', )
        
class PredictSQLInjectionSerializer(serializers.Serializer):
    url = serializers.CharField(
        max_length=2000,  # Adjust the max_length as needed
        required=True,
        help_text="The URL to be checked for SQL injection."
    )