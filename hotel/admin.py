# hotel/admin.py

from django.contrib import admin
from .models import Room, Booking, Review, Payment, Coupon, Amenity

@admin.register(Room)
class RoomAdmin(admin.ModelAdmin):
    list_display = ['room_number', 'room_type', 'price_per_night', 'is_available', 'is_under_maintenance', 'capacity']
    list_filter = ['room_type', 'is_available', 'is_under_maintenance']
    search_fields = ['room_number', 'description']
    list_editable = ['is_available', 'is_under_maintenance', 'price_per_night']
    ordering = ['room_number']
    filter_horizontal = ('amenities',)  # Makes it easier to select multiple amenities


@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = ['id', 'customer', 'room', 'check_in_date', 'check_out_date', 'status']
    list_filter = ['status', 'room__room_type', 'check_in_date', 'check_out_date']
    search_fields = ['customer__username', 'room__room_number']
    readonly_fields = ['created_at']
    date_hierarchy = 'check_in_date'
    ordering = ['-check_in_date']


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ['customer', 'room', 'rating', 'created_at', 'review_snippet']
    list_filter = ['rating', 'created_at']
    search_fields = ['customer__username', 'room__room_number', 'comment']
    readonly_fields = ['created_at']
    ordering = ['-created_at']

    def review_snippet(self, obj):
        return obj.comment[:50] + '...' if len(obj.comment) > 50 else obj.comment
    review_snippet.short_description = 'Comment Preview'


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['booking', 'amount', 'status', 'transaction_id', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['transaction_id', 'booking__id']
    readonly_fields = ['transaction_id', 'created_at']
    ordering = ['-created_at']
    date_hierarchy = 'created_at'


@admin.register(Coupon)
class CouponAdmin(admin.ModelAdmin):
    list_display = ['code', 'discount_percent', 'expiration_date', 'is_active']
    list_filter = ['is_active', 'expiration_date']
    search_fields = ['code', 'description']
    list_editable = ['is_active', 'discount_percent']
    ordering = ['-expiration_date']

@admin.register(Amenity)
class AmenityAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_active', 'icon')
    list_filter = ('is_active',)
    search_fields = ('name', 'description')
