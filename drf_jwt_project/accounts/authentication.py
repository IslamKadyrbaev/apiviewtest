from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import jwt
from django.conf import settings
from .models import CustomUser

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return None
        
        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = CustomUser.objects.get(id=payload['id'])
            return (user, token)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except (jwt.InvalidTokenError, CustomUser.DoesNotExist):
            raise AuthenticationFailed('Invalid token')