from rest_framework import generics, permissions
from .serializers import UserRegistrationSerializer, CustomTokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response
from .permissions import IsAdmin
from django.shortcuts import render, redirect
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.contrib import messages
from .models import CustomUser
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status
from .serializers import CustomUserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .decorators import role_required
from rest_framework_simplejwt.authentication import JWTAuthentication






# User registration view
class UserRegistrationView(generics.CreateAPIView):
    permission_classes= [permissions.AllowAny]
    queryset = CustomUser.objects.all()
    serializer_class = UserRegistrationSerializer
   

# Custom token view to include role in the token
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer  # Use the custom serializer for token generation
    http_method_names = ['post', 'options']




# View accessible only by admin users
class AdminOnlyView(APIView):
    permission_classes = [IsAdmin, IsAuthenticated] # Only admin users can access this
    role_required = 'admin'

    def get(self, request):
        data = {"message": "Hello, Admin!"}
        return Response(data)
    
# Email Verification View
def verify_email(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    token_generator = PasswordResetTokenGenerator()

    if user is not None and token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Your email has been verified!")
        return redirect('login')
    else:
        messages.error(request, "The verification link is invalid!")
        return redirect('home')
    
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    refresh['role'] = user.role

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify_token_view(request):
    try:
        jwt_authenticator = JWTAuthentication()
        user, validated_token = jwt_authenticator.authenticate(request)
        return JsonResponse({'user': user.email, 'role': user.role})
    except Exception:
        return JsonResponse({'error': 'Invalid token or not authenticated'}, status=401)

@api_view(['POST'])
def login_view(request):
    email = request.data.get('email')
    password = request.data.get('password')
    user = authenticate(request, email=email, password=password)

    if user is not None:
        tokens = get_tokens_for_user(user)
        response = JsonResponse({"message": "Login successful."})
        # Set HTTP-only cookies
        response.set_cookie('access', tokens['access'], httponly=True, secure=True, samesite='Strict')
        response.set_cookie('refresh', tokens['refresh'], httponly=True, secure=True, samesite='Strict')
        return Response(tokens, status=status.HTTP_200_OK)
    return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def logout_view(request):
    logout(request)
    return Response({'status': 'success', 'message': 'Logged out successfully'})

@api_view(['GET'])

def user_view(request):
    if request.user.is_authenticated:
        user = request.user
        serializer = CustomUserSerializer(user)
        return Response(serializer.data)
    return Response({'status': 'error', 'message': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['GET'])
def refresh_token_view(request):
    refresh_token = request.COOKIES.get('refresh')
    if not refresh_token:
        return Response({'detail': 'No refresh token included'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token = RefreshToken(refresh_token)
        user = CustomUser.objects.get(id=token['user_id'])
    except Exception as e:
        return Response({'detail': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

    if not token.token['role'] == user.role:
        return Response({'detail': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)

    new_tokens = get_tokens_for_user(user)
    response = JsonResponse({"message": "Token refreshed."})
    response.set_cookie('access', new_tokens['access'], httponly=True, secure=True, samesite='Strict')
    response.set_cookie('refresh', new_tokens['refresh'], httponly=True, secure=True, samesite='Strict')
    return response

