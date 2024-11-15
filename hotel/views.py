from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import Room, Booking, Review, Payment, Coupon
from .serializers import RoomSerializer, BookingSerializer, ReviewSerializer, PaymentSerializer
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from .forms import BookingForm


# Room ViewSet
class RoomViewSet(viewsets.ModelViewSet):
    queryset = Room.objects.filter(is_available=True)
    serializer_class = RoomSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=False, methods=['get'])
    def search_availability(self, request):
        room_type = request.query_params.get('room_type')
        check_in = request.query_params.get('check_in_date')
        check_out = request.query_params.get('check_out_date')
        queryset = Room.objects.filter(is_available=True)

        if room_type:
            queryset = queryset.filter(room_type=room_type)
        
        if check_in and check_out:
            queryset = queryset.exclude(
                booking__check_in_date__lte=check_out,
                booking__check_out_date__gte=check_in,
                booking__status='confirmed'
            )
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


# Booking ViewSet
class BookingViewSet(viewsets.ModelViewSet):
    queryset = Booking.objects.all()
    serializer_class = BookingSerializer
    permission_classes = [IsAuthenticated]

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        booking = self.get_object()
        booking.cancel()
        return Response({'status': 'Booking cancelled'}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'])
    def history(self, request):
        queryset = Booking.objects.filter(customer=request.user).order_by('-created_at')
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

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


# Review ViewSet
class ReviewViewSet(viewsets.ModelViewSet):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(customer=self.request.user)


# Payment ViewSet
class PaymentViewSet(viewsets.ModelViewSet):
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


def create_booking(request):
    if request.method == 'POST':
        form = BookingForm(request.POST)
        if form.is_valid():
            booking = form.save(commit=False)
            booking.customer = request.user
            booking.status = 'pending'
            
            try:
                booking.save()
                messages.success(request, 'Booking created successfully!')
                return redirect('booking_detail', pk=booking.pk)
            except ValueError as e:
                messages.error(request, str(e))
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = BookingForm()
    
    return render(request, 'hotel/booking_form.html', {'form': form})

def get_available_rooms(request):
    """AJAX view to get available rooms for selected dates"""
    check_in = request.GET.get('check_in')
    check_out = request.GET.get('check_out')
    
    if not check_in or not check_out:
        return JsonResponse({'error': 'Both dates are required'}, status=400)
    
    try:
        form = BookingForm(initial={
            'check_in_date': check_in,
            'check_out_date': check_out
        })
        rooms = form.get_available_rooms(check_in, check_out)
        
        room_data = [{
            'id': room.id,
            'number': room.room_number,
            'type': room.get_room_type_display(),
            'price': str(room.price_per_night)
        } for room in rooms]
        
        return JsonResponse({'rooms': room_data})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)
