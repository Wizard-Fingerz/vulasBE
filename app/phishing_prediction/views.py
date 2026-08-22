import logging

from drf_yasg.utils import swagger_auto_schema
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from . import model as phishing_model
from .detector import analyze_url
from .serializers import PredictPhishingSerializer

logger = logging.getLogger(__name__)


class PredictPhishing(APIView):
    """
    Checks a URL for phishing characteristics using the trained
    RandomForestClassifier (model.py, app/dumped_models/phishing/rf.joblib)
    as the primary classifier, with the rule-based heuristic detector
    (detector.py) supplying human-readable "reasons" alongside it and
    acting as the sole verdict if the model can't be loaded.

    This intentionally replaces the original implementation, which was a
    copy-paste of the SQL-injection detector (same SQL-keyword vectorizer,
    same model class) pointed at an unrelated pickled model — it never
    actually evaluated anything phishing-specific, and wasn't even wired
    into app/urls.py.
    """
    permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(request_body=PredictPhishingSerializer)
    def post(self, request, format=None):
        serializer = PredictPhishingSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        url = serializer.validated_data["url"]

        try:
            heuristic_result = analyze_url(url)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            model_result = phishing_model.predict(url)
        except Exception as e:
            logger.error("Phishing model prediction failed for %r: %s", url, e)
            model_result = {'available': False}

        if model_result.get('available'):
            response = {
                'is_phishing': model_result['is_phishing'],
                'score': model_result['score'],
                'source': 'model',
                'reasons': heuristic_result['reasons'],
                'heuristic': {
                    'is_phishing': heuristic_result['is_phishing'],
                    'score': heuristic_result['score'],
                },
            }
        else:
            # The trained model failed to load (missing/corrupt joblib
            # file, incompatible scikit-learn version, etc.) -- fall back
            # to the heuristic detector alone rather than erroring out.
            response = {
                'is_phishing': heuristic_result['is_phishing'],
                'score': heuristic_result['score'],
                'source': 'heuristic',
                'reasons': heuristic_result['reasons'],
            }

        return Response(response, status=status.HTTP_200_OK)
