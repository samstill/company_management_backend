from django.urls import path, include
from .views import AdminOnlyView, UserRegistrationView, verify_email
from .views import CustomTokenObtainPairView, verify_token_view
from rest_framework_simplejwt.views import TokenRefreshView
from .views import user_view, UserListView, DeleteUsersView, SearchUsersView
from .views import user_count
from .views import user_trends
from rest_framework.routers import DefaultRouter

app_name = 'accounts'

router = DefaultRouter()
router.register(r'users', UserListView , basename='user-list')


urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('admin-only/', AdminOnlyView.as_view(), name='admin_only'),
    path('verify-email/<uidb64>/<token>/', verify_email, name='verify-email'),
    path('verify-token/', verify_token_view, name='verify_token'),
    path('users/delete/', DeleteUsersView.as_view(), name='delete_users'),
    path('users/search/', SearchUsersView.as_view(), name='search_users'),


    path('user/count/', user_count, name='user_count'),
    path('user/', user_view, name='user_view'),
    path('user/trends/', user_trends, name='user_trends'),
    path('', include(router.urls)),


]
