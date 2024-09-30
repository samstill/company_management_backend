from django.urls import path
from two_factor.views import LoginView, SetupView, QRGeneratorView, BackupTokensView, ProfileView, DisableView

app_name = 'two_factor'  # Add this line

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('setup/', SetupView.as_view(), name='setup'),
    path('qrcode/', QRGeneratorView.as_view(), name='qr'),
    path('setup/complete/', SetupView.as_view(), name='setup_complete'),
    path('backup/tokens/', BackupTokensView.as_view(), name='backup_tokens'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('disable/', DisableView.as_view(), name='disable'),
]
