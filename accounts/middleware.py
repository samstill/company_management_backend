# middleware.py
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from user_agents import parse 
from .models import UserDevice
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone


import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import login


class RoleBasedAccessMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only check JWT tokens on protected endpoints
        if '/admin/' in request.path:
            try:
                # Authenticate the user using JWT
                jwt_authenticator = JWTAuthentication()
                user, validated_token = jwt_authenticator.authenticate(request)
                
                # Check the user's role from the token
                if validated_token.get('role') != 'admin':
                    return JsonResponse({'error': 'Forbidden: Insufficient role'}, status=403)
            except (InvalidToken, TokenError) as e:
                return JsonResponse({'error': 'Invalid or missing token'}, status=401)

        response = self.get_response(request)
        return response

class DeviceManagementMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if request.user.is_authenticated:
            user_agent = parse(request.META['HTTP_USER_AGENT'])
            device_name = user_agent.device.family
            device_type = 'Mobile' if user_agent.is_mobile else 'PC'
            browser = user_agent.browser.family
            operating_system = user_agent.os.family
            ip_address = request.META.get('REMOTE_ADDR')

            # Check if this device is already registered for the user
            user_device, created = UserDevice.objects.get_or_create(
                user=request.user,
                device_name=device_name,
                browser=browser,
                operating_system=operating_system,
                ip_address=ip_address
            )
            user_device.last_active = timezone.now()
            user_device.save()

class AdminJWTAuthMiddleware(MiddlewareMixin):
    """
    Middleware that authenticates users in the admin panel using JWT tokens.
    """
    def process_request(self, request):
        if request.path.startswith('/admin/'):

            # Get the JWT token from the Authorization header or cookies
            token = request.COOKIES.get('access') or request.META.get('HTTP_AUTHORIZATION', None)

            if token:
                if token.startswith('Bearer '):
                    token = token.split(' ')[1]

                try:
                    # Decode and verify the token
                    access_token = AccessToken(token)
                    user_id = access_token['user_id']

                    # Get the user and log them in
                    user = User.objects.get(id=user_id)
                    if user.is_active:
                        login(request, user)
                except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist, TokenError, InvalidToken):
                    pass  # Token is invalid, continue without login