from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from ..sqlprediction.serializers import *
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.permissions import *
from rest_framework.decorators import *
from django.views.decorators.csrf import csrf_exempt
from ..sqlprediction.models import predict_few
from rest_framework import status, permissions
from rest_framework.response import Response
from django.http import JsonResponse
import numpy as np
import joblib
from rest_framework import generics
from ..sqlprediction.models import *
from ..sqlprediction.serializers import PacketInfoSerializer
from django.http import HttpResponse
from django.conf import settings
from scapy.all import *
import os
from django.views.static import serve
import glob
import shutil
# Create your views here.


@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def predictions(request):
    if request.method == 'POST':
        print(request.data)  # Print the received data for debugging
        input_data = request.data.get('input_data')

        # Check if 'input_data' is present in the request data
        if input_data is None:
            return Response({'error': 'Input data is missing.'}, status=400)

        input_array = []  # Create an array to hold the input data

        for input_dict in input_data:
            input_values = list(input_dict.values())
            input_array.append(input_values)

        # Use the array in your prediction function
        predictions = predict_few(input_array)
        return Response({'predictions': predictions})

    return Response({'error': 'Invalid request method.'}, status=405)

def vectorize_url(url):
    # Define your SQLIA signatures as per the provided mapping
    sqlia_signatures = [
        "'", "OR", "=", "LIKE", "SELECT", "CONVERT", "INT", "CHAR", "VARCHAR", "NVARCHAR",
        "&&", "AND", "ORDER BY", "EXEC", "UNION", "UNION SELECT", "SHUTDOWN", "EXEC",
        "XP_CMDSHELL()", "SP_EXECWEBTASK()", "IF", "ELSE", "WAITFOR", "--", "ASCII()",
        "BIN()", "HEX()", "UNHEX()", "BASE64()", "DEC()", "ROT13()", "*", "<", ">",
        "VERSION", "V$VERSION", "INFORMATION_SCHEMA.TABLES", "INFORMATION_SCHEMA.COLUMNS",
        "ALL_TABLES", "SUBSTRING", "SUBSTR", "CASE", "DECLARE", "MASTER..XP_DIRTREE", "@P",
        "SLEEP", "LOAD_FILE", "||", "~", "CURRENT_USER()", "CONCAT", "DATABASE()", "+",
        "VERSION()", "UNION SELECT", "ADMIN", "/*", "\\", "BYPASS", "BLACKLISTING", "DROP", ")", "(",
        "COOKIE", "%S%S", "_", "*\\", "MYSQL SPECIAL SQL", "/**", "!", ".", "TRUE", "FALSE",
        "DBMS_LOCK.SLEEP", "END", "COLLATE", "MD5", "HAVING", "GROUP BY", "NULL", "1/0",
        "INSERT", "PING", "TABLE_SCHEMA", "SYSOBJECTS", "SYSCOLUMNS", "TMP_SYS_TMP", "}",
        "{", "BENCHMARK", "PG_SLEEP", "INJECTION", "MYSQL.USER", "SHA1", "USER()",
        "LOCKWORKSTATION()", "CREATE", "EXITPROCESS()", "PASSWORD()", "ENCODE()",
        "COMPRESS()", "ROW_COUNT()", "SCHEMA()", "ROWCOUNT()", "…", "BULK", "OPENROWSET",
        "OUTFILE", "SA", "“", "`", "all_tab_columns"
    ]

    # Initialize a vector of zeros with the same length as the number of signatures
    vector = [0] * len(sqlia_signatures)

    # For each signature, check if it is in the URL and set the corresponding vector index to 1
    for i, signature in enumerate(sqlia_signatures):
        if signature in url:
            vector[i] = 1

    return np.array(vector)

# Load your trained PCA and MLPClassifier model
import os

# Dynamically set the paths using os.path for better portability and flexibility
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

pca_path = os.path.join(BASE_DIR, '..', 'dumped_models', 'pca.joblib')
model_path = os.path.join(BASE_DIR, '..', 'dumped_models', 'phishing', 'rf.joblib')

pca = joblib.load(os.path.abspath(pca_path))
model = joblib.load(os.path.abspath(model_path))

class PredictSQLInjection(APIView):
    permission_classes = [permissions.AllowAny,]

    def post(self, request, format=None):
        url = request.data.get('url', None)
        if url is None:
            return Response({'error': 'URL not provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Vectorize the URL
            vectorized_url = vectorize_url(url)

            # Ensure the vector has the same number of features as the training data
            if len(vectorized_url) != 112:
                return Response({'error': 'Invalid number of features in URL vector'}, status=status.HTTP_400_BAD_REQUEST)

            # Apply PCA transformation to reduce the features to 10 principal components
            vectorized_url_pca = pca.transform([vectorized_url])

            # Make sure the transformed vector has 10 features
            if vectorized_url_pca.shape[1] != 10:
                return Response({'error': 'PCA transformation did not result in 10 features'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Make a prediction with the MLPClassifier
            prediction = model.predict(vectorized_url_pca)

            # Convert the prediction to a human-readable form
            is_sql_injection = bool(prediction[0])

            return Response({'is_sql_injection': is_sql_injection}, status=status.HTTP_200_OK)
        except Exception as e:
            # In a real-world scenario, you'd want to log this exception.
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




@api_view(['POST'])
@permission_classes([AllowAny])
def create_packet_info(request):
    if request.method == 'POST':
        data = request.data  # Get the request data
        print(data)
        # Create an instance of the PacketInfo model and set its attributes
        packet_info = PacketInfo(
            ip_source=data.get('IP Source'),
            ip_destination=data.get('IP Destination'),
            mac_source=data.get('MAC Source'),
            mac_destination=data.get('MAC Destination'),
            protocol=data.get('Protocol'),
            flags=data.get('Flags'),
            source_port=data.get('Source Port'),
            destination_port=data.get('Destination Port'),
            ttl=data.get('TTL')
        )

        # Save the instance to the database
        packet_info.save()

        # Return a response indicating success
        return Response({'message': 'PacketInfo created successfully'}, status=status.HTTP_201_CREATED)

    # Handle other HTTP methods if needed
    return Response({'error': 'Invalid request method'}, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
@permission_classes([AllowAny])
def create_blocked_host(request):
    if request.method == 'POST':
        data = request.data  # Get the request data
        print(data)
        # Create an instance of the PacketInfo model and set its attributes
        blocked_host = BlockedHost(
            ip_source=data.get('IP Source'),
            ip_destination=data.get('IP Destination'),
            mac_source=data.get('MAC Source'),
            mac_destination=data.get('MAC Destination'),
            protocol=data.get('Protocol'),
            flags=data.get('Flags'),
            source_port=data.get('Source Port'),
            destination_port=data.get('Destination Port'),
            ttl=data.get('TTL')
        )

        # Save the instance to the database
        blocked_host.save()

        # Return a response indicating success
        return Response({'message': 'Blocked Host created successfully'}, status=status.HTTP_201_CREATED)

    # Handle other HTTP methods if needed
    return Response({'error': 'Invalid request method'}, status=status.HTTP_400_BAD_REQUEST)


class FileUploadView(APIView):
    permission_classes = [permissions.AllowAny,]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, *args, **kwargs):
        serializer = UploadedFileSerializer(data=request.data)

        if serializer.is_valid():
            uploaded_file = serializer.save()

            # Assuming 'uploaded_file' has a 'file' field representing the uploaded file
            uploaded_file_path = uploaded_file.file.path

            # Specify the path of the single pcap file where you want to append the content
            media_folder = 'media'
            uploads_folder = 'uploads'
            single_pcap_filename = 'single_file.pcap'

            # Ensure the 'uploads' folder exists within the 'media' folder
            uploads_folder_path = os.path.join(media_folder, uploads_folder)
            os.makedirs(uploads_folder_path, exist_ok=True)

            # Full path to the single pcap file
            single_pcap_path = os.path.join(uploads_folder_path, single_pcap_filename)

            try:
                # Delete files in 'uploads' folder, keeping only the latest 5
                files = sorted(os.listdir(uploads_folder_path), key=lambda x: os.path.getmtime(os.path.join(uploads_folder_path, x)))
                files_to_delete = files[:-5]  # Exclude the latest 5 files

                for filename in files_to_delete:
                    file_path = os.path.join(uploads_folder_path, filename)
                    try:
                        if os.path.isfile(file_path) and filename != single_pcap_filename:
                            os.unlink(file_path)
                    except Exception as e:
                        return Response({"error": f"Error deleting file: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                # Save the recent file
                with open(single_pcap_path, 'ab') as single_pcap:
                    with open(uploaded_file_path, 'rb') as uploaded_pcap:
                        single_pcap.write(uploaded_pcap.read())

                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"error": f"Internal Server Error: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def download_media(request):
    # Set the path to your media folder
    media_root = settings.MEDIA_ROOT

    # Create a zip file containing the media folder
    zip_filename = 'media_folder.zip'
    zip_filepath = os.path.join(settings.BASE_DIR, zip_filename)

    # Create a zip file
    import shutil
    shutil.make_archive(zip_filepath[:-4], 'zip', media_root)

    # Open the zip file and create a response with the file
    with open(zip_filepath, 'rb') as zip_file:
        response = HttpResponse(zip_file.read(), content_type='application/zip')
        response['Content-Disposition'] = f'attachment; filename={zip_filename}'

    # Delete the temporary zip file
    os.remove(zip_filepath)

    return response


def download_last_uploaded_file(request):
    # Set the path to your media folder
    media_root = settings.MEDIA_ROOT

    # Get a list of all files (including those in subdirectories) in the media folder
    all_files = [f for f in glob.glob(os.path.join(media_root, '**', '*'), recursive=True) if os.path.isfile(f)]

    # Sort the files by modification time in descending order
    sorted_files = sorted(all_files, key=os.path.getmtime, reverse=True)

    if sorted_files:
        # Get the path of the last uploaded file
        last_uploaded_file = sorted_files[0]

        # Open the file and create a response with its content
        with open(last_uploaded_file, 'rb') as file:
            response = HttpResponse(file.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename={os.path.relpath(last_uploaded_file, media_root)}'

        return response
    else:
        return HttpResponse("No files found in the media folder.")