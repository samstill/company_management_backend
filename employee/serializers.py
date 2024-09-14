# employee/serializers.py

from rest_framework import serializers
from .models import Employee, EmployeePerformance

class EmployeeSerializer(serializers.ModelSerializer):
    company = serializers.StringRelatedField()
    department = serializers.StringRelatedField()

    class Meta:
        model = Employee
        fields = ['id', 'user', 'company', 'department', 'position', 'date_of_joining', 'is_manager']


class EmployeePerformanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmployeePerformance
        fields = ['id', 'employee', 'date', 'review']
