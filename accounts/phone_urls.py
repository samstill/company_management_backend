# accounts/phone_urls.py

from django.urls import path, include
from two_factor.plugins.phonenumber import urls as phone_default_urls

app_name = 'phone'

urlpatterns = [
    # Include the default phone URLs
    path('', include(phone_default_urls)),
]
