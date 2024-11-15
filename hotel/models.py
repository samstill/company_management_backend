# hotel/models.py

from django.db import models
from accounts.models import CustomUser
from django.utils.timezone import now

class Amenity(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True, null=True)
    icon = models.CharField(max_length=50, blank=True, null=True)  # For storing FontAwesome or similar icon names
    is_active = models.BooleanField(default=True)
    
    class Meta:
        verbose_name_plural = "Amenities"
        ordering = ['name']
    
    def __str__(self):
        return self.name

class Room(models.Model):
    ROOM_TYPES = [
        ('single', 'Single'),
        ('double', 'Double'),
        ('suite', 'Suite'),
    ]
    
    room_number = models.CharField(max_length=10, unique=True)
    room_type = models.CharField(max_length=20, choices=ROOM_TYPES)
    price_per_night = models.DecimalField(max_digits=10, decimal_places=2)
    is_available = models.BooleanField(default=True)
    is_under_maintenance = models.BooleanField(default=False)
    capacity = models.IntegerField()
    description = models.TextField(blank=True, null=True)
    amenities = models.ManyToManyField(Amenity, related_name='rooms')  # Changed from JSONField to M2M
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

    def check_availability(self, check_in_date, check_out_date):
        """Check if room is available for given dates"""
        overlapping_bookings = self.booking_set.filter(
            status='confirmed',
            check_in_date__lt=check_out_date,
            check_out_date__gt=check_in_date
        )
        return not overlapping_bookings.exists() and not self.is_under_maintenance

    def update_availability_status(self):
        """Update room availability based on current bookings"""
        current_date = now().date()
        has_active_booking = self.booking_set.filter(
            status='confirmed',
            check_in_date__lte=current_date,
            check_out_date__gt=current_date
        ).exists()
        
        self.is_available = not (has_active_booking or self.is_under_maintenance)
        self.save()


class Booking(models.Model):
    BOOKING_STATUS = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('cancelled', 'Cancelled'),
        ('completed', 'Completed')  # Added new status
    ]

    customer = models.ForeignKey(CustomUser, on_delete=models.CASCADE, limit_choices_to={'role': 'customer'})
    room = models.ForeignKey(Room, on_delete=models.CASCADE)
    check_in_date = models.DateField()
    check_out_date = models.DateField()
    status = models.CharField(max_length=10, choices=BOOKING_STATUS, default='pending')
    special_requests = models.TextField(blank=True, null=True)
    dynamic_price = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        """Override save to handle room availability"""
        if self.pk is None:  # New booking
            if self.status == 'confirmed':
                if not self.room.check_availability(self.check_in_date, self.check_out_date):
                    raise ValueError("Room is not available for these dates")
        
        super().save(*args, **kwargs)
        self.room.update_availability_status()

    def cancel(self):
        """Enhanced cancellation method"""
        if self.status == 'confirmed':
            self.status = 'cancelled'
            self.save()
            
            # Update room availability
            self.room.update_availability_status()
            
            # Handle related payment if exists
            try:
                payment = self.payment
                if payment.status == 'completed':
                    # Here you might want to handle refund logic
                    pass
            except Payment.DoesNotExist:
                pass

    def complete_booking(self):
        """Mark booking as completed after checkout"""
        if self.status == 'confirmed':
            self.status = 'completed'
            self.save()
            self.room.update_availability_status()


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
