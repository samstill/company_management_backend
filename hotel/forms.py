from django import forms
from .models import Booking, Room
from django.utils.timezone import now

class BookingForm(forms.ModelForm):
    class Meta:
        model = Booking
        fields = ['room', 'check_in_date', 'check_out_date', 'special_requests']
        widgets = {
            'check_in_date': forms.DateInput(attrs={'type': 'date'}),
            'check_out_date': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Initially hide the room field until dates are selected
        self.fields['room'].queryset = Room.objects.none()
        
        # If we have initial dates, filter rooms
        if 'initial' in kwargs:
            initial = kwargs['initial']
            if 'check_in_date' in initial and 'check_out_date' in initial:
                self.fields['room'].queryset = self.get_available_rooms(
                    initial['check_in_date'],
                    initial['check_out_date']
                )

    def get_available_rooms(self, check_in_date, check_out_date):
        """Get all available rooms for given dates"""
        unavailable_rooms = Booking.objects.filter(
            status='confirmed',
            check_in_date__lt=check_out_date,
            check_out_date__gt=check_in_date
        ).values_list('room', flat=True)

        return Room.objects.exclude(
            id__in=unavailable_rooms
        ).exclude(
            is_under_maintenance=True
        ).filter(
            is_available=True
        )

    def clean(self):
        cleaned_data = super().clean()
        check_in_date = cleaned_data.get('check_in_date')
        check_out_date = cleaned_data.get('check_out_date')
        room = cleaned_data.get('room')

        if check_in_date and check_out_date:
            if check_in_date < now().date():
                raise forms.ValidationError("Check-in date cannot be in the past")
            
            if check_in_date >= check_out_date:
                raise forms.ValidationError("Check-out date must be after check-in date")

            if room:
                # Check if room is available for these dates
                if not room.check_availability(check_in_date, check_out_date):
                    raise forms.ValidationError(
                        f"Room {room.room_number} is not available for the selected dates"
                    )

        return cleaned_data
