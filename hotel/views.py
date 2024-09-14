# hotel/views.py

from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from .models import Room, Booking, Review, Payment, Coupon
from .serializers import RoomSerializer, BookingSerializer, ReviewSerializer, PaymentSerializer

# Room Views
class RoomAvailabilitySearchView(generics.ListAPIView):
    queryset = Room.objects.filter(is_available=True)
    serializer_class = RoomSerializer

    def get_queryset(self):
        room_type = self.request.query_params.get('room_type')
        check_in = self.request.query_params.get('check_in_date')
        check_out = self.request.query_params.get('check_out_date')
        queryset = Room.objects.filter(is_available=True)

        if room_type:
            queryset = queryset.filter(room_type=room_type)
        
        if check_in and check_out:
            queryset = queryset.exclude(
                booking__check_in_date__lte=check_out,
                booking__check_out_date__gte=check_in,
                booking__status='confirmed'
            )
        return queryset


# Booking Views
class BookingCreateView(generics.CreateAPIView):
    queryset = Booking.objects.all()
    serializer_class = BookingSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        room = serializer.validated_data['room']
        if room.is_available:
            room.mark_as_unavailable()
            booking = serializer.save(customer=self.request.user)

            # Apply coupon if valid
            coupon_code = self.request.data.get('coupon_code')
            if coupon_code:
                try:
                    coupon = Coupon.objects.get(code=coupon_code, is_active=True)
                    booking.dynamic_price = booking.room.price_per_night * (1 - (coupon.discount_percent / 100))
                    booking.save()
                except Coupon.DoesNotExist:
                    pass


class BookingCancelView(generics.UpdateAPIView):
    queryset = Booking.objects.all()
    serializer_class = BookingSerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        booking = self.get_object()
        booking.cancel()


class BookingHistoryView(generics.ListAPIView):
    serializer_class = BookingSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Booking.objects.filter(customer=self.request.user).order_by('-created_at')


# Review Views
class ReviewCreateView(generics.CreateAPIView):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(customer=self.request.user)


# Payment Views
class PaymentCreateView(generics.CreateAPIView):
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        booking = serializer.validated_data['booking']
        amount = serializer.validated_data['amount']
        # Process payment with third-party payment gateway and get transaction ID
        transaction_id = "12345ABC"  # Dummy transaction ID
        payment = serializer.save(transaction_id=transaction_id)
        payment.complete_payment(transaction_id)
