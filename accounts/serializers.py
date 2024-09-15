from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


# Serializer for user registration
class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    role = serializers.ChoiceField(choices=CustomUser.ROLE_CHOICES)

    class Meta:
        model = CustomUser
        fields = ( 'email','password', 'first_name', 'last_name', 'role')
    
    def create(self, validated_data):
        # Get the request user from the context (request is passed in context in views)
        request_user = self.context['request'].user

        # Check if the request user is an admin or manager
        if request_user.is_authenticated and (request_user.is_admin() or request_user.is_manager()):
            # Allow setting the role if the request user is an admin or manager
            role = validated_data.get('role', CustomUser.CUSTOMER)
        else:
            # Default to 'customer' role for non-admin/manager users
            role = CustomUser.CUSTOMER
 
  
            user = CustomUser.objects.create_user(
                email=validated_data.get('email', ''),
                password=validated_data['password'],
                first_name=validated_data.get('first_name', ''),
                last_name=validated_data.get('last_name', ''),
                role=role,
        )
        return user

# Serializer for general user details


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'first_name', 'last_name', 'role']


# Custom TokenObtainPairSerializer to include role in the JWT token payload
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['role'] = user.role
        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        # Add extra responses here
        data['role'] = self.user.role
        return data
