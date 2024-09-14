from django import forms
from .models import Employee
from accounts.models import CustomUser

class EmployeeForm(forms.ModelForm):
    class Meta:
        model = Employee
        fields = ['user', 'company', 'position', 'department', 'date_of_joining', 'is_manager']

    def __init__(self, *args, **kwargs):
        super(EmployeeForm, self).__init__(*args, **kwargs)

