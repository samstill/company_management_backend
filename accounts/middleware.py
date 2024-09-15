# middleware.py
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

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
