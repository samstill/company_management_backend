# middleware.py
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from user_agents import parse 
from .models import UserDevice
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone


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