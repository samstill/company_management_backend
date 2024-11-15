from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import RoomViewSet, BookingViewSet, ReviewViewSet, PaymentViewSet, create_booking, get_available_rooms

router = DefaultRouter()
router.register(r'rooms', RoomViewSet, basename='room')
router.register(r'bookings', BookingViewSet, basename='booking')
router.register(r'reviews', ReviewViewSet, basename='review')
router.register(r'payments', PaymentViewSet, basename='payment')

urlpatterns = [
    path('', include(router.urls)),
    path('booking/create/', create_booking, name='create_booking'),
    path('get-available-rooms/', get_available_rooms, name='get_available_rooms'),
]
