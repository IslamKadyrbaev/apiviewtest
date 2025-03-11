from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from .serializers import UserSerializer, LoginSerializer
from django.contrib.auth import authenticate
import jwt
from datetime import datetime, timedelta
from django.conf import settings

class RegisterView(APIView):
    permission_classes = [AllowAny] 
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            if user:
                payload = {
                    'id': user.id,
                    'exp': datetime.utcnow() + timedelta(days=1),
                    'iat': datetime.utcnow()
                }
                token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
                return Response({'token': token}, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProtectedView(APIView):
    def get(self, request):
        return Response({'message': 'This is a protected endpoint', 'user': request.user.username})