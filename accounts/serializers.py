from rest_framework import serializers
from .models import CustomUser, UserDevice
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


# Serializer for user registration
class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    role = serializers.ChoiceField(choices=CustomUser.ROLE_CHOICES)

    class Meta:
        model = CustomUser
        fields = ( 'email', 'phone_number' ,'password', 'first_name', 'last_name', 'role')
    
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
    profile_photo = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = ['id', 'email','phone_number' ,'profile_photo', 'first_name', 'last_name', 'role']
        extra_kwargs = {
            'profile_photo': {'required': False},  # Make it optional
        }

    def get_profile_photo(self, obj):
        request = self.context.get('request')  # Get the request from the context
        if obj.profile_photo:
            # Manually construct the correct URL for the profile photo
            return request.build_absolute_uri(f'/api/accounts{obj.profile_photo.url}')
        return None  # If no photo, return None

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims (role)
        token['role'] = user.role if hasattr(user, 'role') else 'user'  # Default role to 'user' if not set
        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        # Add role in the response payload as well
        data['role'] = self.user.role if hasattr(self.user, 'role') else 'user'
        return data

class UserDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDevice
        fields = ['id', 'device_name', 'device_type', 'browser', 'operating_system', 'ip_address', 'login_time', 'last_active']