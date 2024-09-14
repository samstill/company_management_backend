# hotel/admin.py

from django.contrib import admin
from .models import Room, Booking, Review, Payment, Coupon

@admin.register(Room)
class RoomAdmin(admin.ModelAdmin):
    list_display = ['room_number', 'room_type', 'price_per_night', 'is_available', 'is_under_maintenance', 'capacity']
    list_filter = ['room_type', 'is_available', 'is_under_maintenance']
    search_fields = ['room_number', 'description']


@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = ['customer', 'room', 'check_in_date', 'check_out_date', 'status']
    list_filter = ['status', 'room__room_type']
    search_fields = ['customer__username', 'room__room_number']


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ['customer', 'room', 'rating', 'created_at']
    search_fields = ['customer__username', 'room__room_number']


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['booking', 'amount', 'status', 'transaction_id', 'created_at']
    list_filter = ['status']
    search_fields = ['transaction_id']


@admin.register(Coupon)
class CouponAdmin(admin.ModelAdmin):
    list_display = ['code', 'discount_percent', 'expiration_date', 'is_active']
    search_fields = ['code']
