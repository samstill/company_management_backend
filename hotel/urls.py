# hotel/urls.py

from django.urls import path
from .views import RoomAvailabilitySearchView, BookingCreateView, BookingCancelView, BookingHistoryView, ReviewCreateView, PaymentCreateView

urlpatterns = [
    path('rooms/', RoomAvailabilitySearchView.as_view(), name='room-availability'),
    path('bookings/', BookingCreateView.as_view(), name='booking-create'),
    path('bookings/history/', BookingHistoryView.as_view(), name='booking-history'),
    path('bookings/cancel/<int:pk>/', BookingCancelView.as_view(), name='booking-cancel'),
    path('reviews/', ReviewCreateView.as_view(), name='review-create'),
    path('payments/', PaymentCreateView.as_view(), name='payment-create'),
]
