# employee/serializers.py

from rest_framework import serializers
from .models import Employee, EmployeePerformance
from company.serializers import CompanySerializer, DepartmentSerializer
from accounts.serializers import CustomUserSerializer


class EmployeeSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)
    company = CompanySerializer(read_only=True)
    department = DepartmentSerializer(read_only=True)
    performance_rating = serializers.SerializerMethodField()

    class Meta:
        model = Employee
        fields = [
            'id',
            'user',
            'company',
            'department',
            'position',
            'date_of_joining',
            'is_manager',
            'performance_rating',
        ]

    def get_performance_rating(self, obj):
        performances = obj.performances.all()
        if performances.exists():
            total_rating = sum(perf.employee_rating for perf in performances)
            average_rating = total_rating / performances.count()
            return round(average_rating, 2)
        return None


class EmployeePerformanceSerializer(serializers.ModelSerializer):
    employee = EmployeeSerializer(read_only=True)

    class Meta:
        model = EmployeePerformance
        fields = [
            'id',
            'employee',
            'date',
            'employee_rating',
            'review',
        ]
