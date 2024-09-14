# hotel/models.py

from django.db import models
from accounts.models import CustomUser
from django.utils.timezone import now

class Room(models.Model):
    ROOM_TYPES = [
        ('single', 'Single'),
        ('double', 'Double'),
        ('suite', 'Suite'),
    ]
    
    AMENITIES = [
        ('wifi', 'Wi-Fi'),
        ('ac', 'Air Conditioning'),
        ('tv', 'Television'),
        ('room_service', 'Room Service'),
    ]
    
    room_number = models.CharField(max_length=10, unique=True)
    room_type = models.CharField(max_length=20, choices=ROOM_TYPES)
    price_per_night = models.DecimalField(max_digits=10, decimal_places=2)
    is_available = models.BooleanField(default=True)
    is_under_maintenance = models.BooleanField(default=False)
    capacity = models.IntegerField()
    description = models.TextField(blank=True, null=True)
    amenities = models.JSONField(default=list)  # Stores amenities in JSON format
    photos = models.ImageField(upload_to='room_photos/', blank=True, null=True)

    def __str__(self):
        return f'Room {self.room_number} ({self.room_type})'

    def mark_as_unavailable(self):
        self.is_available = False
        self.save()

    def mark_as_available(self):
        self.is_available = True
        self.save()

    def mark_as_under_maintenance(self):
        self.is_under_maintenance = True
        self.is_available = False
        self.save()

    def mark_as_maintenance_completed(self):
        self.is_under_maintenance = False
        self.is_available = True
        self.save()


class Booking(models.Model):
    BOOKING_STATUS = [
        ('confirmed', 'Confirmed'),
        ('cancelled', 'Cancelled'),
    ]

    customer = models.ForeignKey(CustomUser, on_delete=models.CASCADE, limit_choices_to={'role': 'customer'})
    room = models.ForeignKey(Room, on_delete=models.CASCADE)
    check_in_date = models.DateField()
    check_out_date = models.DateField()
    status = models.CharField(max_length=10, choices=BOOKING_STATUS, default='confirmed')
    special_requests = models.TextField(blank=True, null=True)
    dynamic_price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def cancel(self):
        self.status = 'cancelled'
        self.room.is_available = True
        self.save()

    def __str__(self):
        return f'Booking {self.id} by {self.customer.username} for Room {self.room.room_number}'


class Review(models.Model):
    customer = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    room = models.ForeignKey(Room, on_delete=models.CASCADE)
    rating = models.IntegerField()  # Rating between 1-5
    review_text = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Review by {self.customer.username} for Room {self.room.room_number}'


class Payment(models.Model):
    PAYMENT_STATUS = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    booking = models.OneToOneField(Booking, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=10, choices=PAYMENT_STATUS, default='pending')
    transaction_id = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def complete_payment(self, transaction_id):
        self.status = 'completed'
        self.transaction_id = transaction_id
        self.save()


class Coupon(models.Model):
    code = models.CharField(max_length=50, unique=True)
    discount_percent = models.DecimalField(max_digits=5, decimal_places=2)
    expiration_date = models.DateField()
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f'Coupon {self.code} ({self.discount_percent}%)'
