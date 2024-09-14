from rest_framework import generics, permissions
from .serializers import UserRegistrationSerializer, CustomTokenObtainPairSerializer
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response
from .permissions import IsAdmin
from django.shortcuts import render, redirect
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from django.contrib import messages


User = get_user_model()

# User registration view
class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

# Custom token view to include role in the token
class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer  # Use the custom serializer for token generation
    http_method_names = ['post', 'options']

# View accessible only by admin users
class AdminOnlyView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        data = {"message": "Hello, Admin!"}
        return Response(data)
    
# Email Verification View
def verify_email(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
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