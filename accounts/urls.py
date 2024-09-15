from django.urls import path
from .views import AdminOnlyView, UserRegistrationView, verify_email
from .views import CustomTokenObtainPairView
from rest_framework_simplejwt.views import TokenRefreshView

app_name = 'accounts'

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('admin-only/', AdminOnlyView.as_view(), name='admin_only'),
    path('verify-email/<uidb64>/<token>/', verify_email, name='verify-email'),


]
