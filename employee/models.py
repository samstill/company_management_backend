# employee/models.py

from django.utils import timezone
from django.db import models
from django.conf import settings  # Import settings to access the CustomUser model
from company.models import Company, Department
from accounts.models import CustomUser  # Import Company and Department models


class Employee(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='employee_profile')
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, related_name='department_employees')
    position = models.CharField(max_length=100)
    date_of_joining = models.DateField()
    company = models.ForeignKey('company.Company', on_delete=models.CASCADE, related_name='company_employees') 
    is_manager = models.BooleanField(default=False)

  
        
    

#Validation for Executive Director role
    def save(self, *args, **kwargs):
        # Check if the employee is being created for the first time
        if not self.pk:  # This means the employee is being created, not updated
            # Set the user role to 'employee'
            if self.user.role != 'employee':
                self.user.role = 'employee'
                self.user.save()
        if self.position == 'Executive Director' and self.user.role != CustomUser.EXECUTIVE_DIRECTOR:
            raise ValueError('User must have the Executive Director role to be in this position.')
        super().save(*args, **kwargs)

    def __str__(self):
        return f'{self.user.first_name} {self.user.last_name} - {self.position} at {self.company.name if self.company else "All Companies"}'


class EmployeePerformance(models.Model):
    employee = models.ForeignKey(Employee, on_delete=models.CASCADE, related_name='performances')
    date = models.DateField( default=timezone.now)
    employee_rating = models.IntegerField(null=False, blank=False)
    review = models.TextField()

    def __str__(self):
        return f'Performance Review of {self.employee.user.username} on {self.date}'
