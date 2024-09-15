# decorators.py
from functools import wraps
from django.http import JsonResponse
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

def role_required(required_role):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            try:
                jwt_authenticator = JWTAuthentication()
                user, validated_token = jwt_authenticator.authenticate(request)
                if validated_token.get('role') != required_role:
                    return JsonResponse({'error': 'Forbidden: Insufficient role'}, status=403)
            except (InvalidToken, TokenError):
                return JsonResponse({'error': 'Invalid or missing token'}, status=401)

            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
