# employee/admin.py

from django.contrib import admin
from .models import Employee, EmployeePerformance
from .forms import EmployeeForm

@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    form = EmployeeForm

    # list_display = ['user', 'company', 'department', 'position', 'is_manager', 'date_of_joining']
    list_filter = ['company', 'department', 'is_manager']
    search_fields = ['user__email', 'position', 'company__name']

   

@admin.register(EmployeePerformance)
class EmployeePerformanceAdmin(admin.ModelAdmin):
    list_display = ['employee', 'date', 'employee_rating' ,'review']
    search_fields = ['employee__user__email']
