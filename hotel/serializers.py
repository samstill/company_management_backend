# hotel/serializers.py

from rest_framework import serializers
from .models import Booking, Room, Review, Payment

class RoomSerializer(serializers.ModelSerializer):
    class Meta:
        model = Room
        fields = ['room_number', 'room_type', 'price_per_night', 'is_available', 'capacity', 'description', 'amenities', 'photos']


class BookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = ['customer', 'room', 'check_in_date', 'check_out_date', 'status', 'special_requests', 'dynamic_price']
        read_only_fields = ['customer', 'status']


class ReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Review
        fields = ['customer', 'room', 'rating', 'review_text', 'created_at']
        read_only_fields = ['customer', 'room', 'created_at']


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['booking', 'amount', 'status', 'transaction_id', 'created_at']
        read_only_fields = ['status', 'transaction_id', 'created_at']
