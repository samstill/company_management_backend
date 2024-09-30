from django.urls import path, include
from .views import (
    AdminOnlyView, UserRegistrationView, verify_email, CustomTokenObtainPairView,
    verify_token_view, user_view, UserListView, DeleteUsersView, SearchUsersView,
    user_count, UserDetailView, LinkedDevicesView, LogoutDeviceView, user_trends,
    LoggedInUserView, UpdateLoggedInUserView, DeleteLoggedInUserView, TwoFactorSetupView
)
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.routers import DefaultRouter
from django.conf import settings
from django.conf.urls.static import static

# Import custom two_factor URLs from accounts/two_factor_urls.py
from .two_factor_urls import urlpatterns as two_factor_custom_urls

app_name = 'accounts'

router = DefaultRouter()
router.register(r'users', UserListView, basename='user-list')

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('admin-only/', AdminOnlyView.as_view(), name='admin_only'),
    path('verify-email/<uidb64>/<token>/', verify_email, name='verify-email'),
    path('verify-token/', verify_token_view, name='verify_token'),
    path('users/delete/', DeleteUsersView.as_view(), name='delete_users'),
    path('users/search/', SearchUsersView.as_view(), name='search_users'),
    path('users/<int:pk>/', UserDetailView.as_view(), name='fetch_user_details'),
    path('user/', LoggedInUserView.as_view(), name='logged_in_user'),
    path('user/update/', UpdateLoggedInUserView.as_view(), name='update_logged_in_user'),
    path('user/delete/', DeleteLoggedInUserView.as_view(), name='delete_logged_in_user'),
    path('user/count/', user_count, name='user_count'),
    path('user/trends/', user_trends, name='user_trends'),
    path('', include(router.urls)),
    path('devices/', LinkedDevicesView.as_view(), name='linked_devices_api'),
    path('devices/logout/<int:device_id>/', LogoutDeviceView.as_view(), name='logout_device_api'),

    # Include custom two-factor authentication URLs
    path('2fa/setup/', TwoFactorSetupView.as_view(), name='two_factor_setup'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
